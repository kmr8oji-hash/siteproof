"""Local notification outbox: events become app notices (and, when a sink is configured, one message to that sink). No external sending exists here.

* One notice per EVENT, never per observation: a failure that goes on is not announced again (transition events only), a recovery is its
  own event, a TLS warning is announced once per certificate and level, an image change once when it appears (not on every inspection).
* A notice is deduplicated by its key across restarts and between processes (<site>/notifications.jsonl is append-only, `add` runs under the
  OS lock <site>/notifications.lock). Ids of notices moved away by the explicit archive stay known through <site>/notification-keys.txt.
* delivery: `app` = the notice was recorded for the screen. `sink` = the message was handed to the sink ("SENT") or the hand-over failed
  ("FAILED:<error type>"); never anything that says it ARRIVED. `received` is always UNKNOWN: a successful send is not a receipt.
* Sinks are plain callables `sink(subject, body)`. Only MockFileSink (a local file, for rehearsals) exists; mail / webhook sinks are a later step
  that needs credentials and the USER's approval. The message texts reuse the AWS-B notification wording (src/aws_b/notify.py).
  E-mail is a separate, signed and default-off channel (smtp_notify.py / notify_dispatch.py) that reads these notices and never changes them.
"""
import hashlib
import json
import os
from pathlib import Path
import threading

from src.aws_b.notify import format_message, transition_event
from src.noxiworks import filelock

TLS_LEVELS = ((0, 'EXPIRED', '期限切れ'), (3, 'CRITICAL', '期限まで3日以内'), (14, 'WARN', '期限まで14日以内'))
_LOCK = threading.Lock()
KEYS_FILE = 'notification-keys.txt'  # one notice id (sha256[:16] of the key) per line: notices archived away stay "already announced"
LOCK_WAIT_SECONDS = 15
_SEEN = {}  # notifications.jsonl path -> [file id, bytes read, set of notice ids]: only the new bytes are read on the next add
_KEYS = {}  # notification-keys.txt path -> [(size, mtime_ns), set of ids]
SEVERITY = {'FAILURE': 'critical', 'RECOVERY': 'info', 'CONFIRMED': 'info', 'UNKNOWN': 'warn', 'TLS_WARN': 'warn', 'TLS_CRITICAL': 'critical',
            'TLS_EXPIRED': 'critical', 'IMAGE_CHANGED': 'warn', 'IMAGE_UNKNOWN': 'warn', 'IMAGE_FAILED': 'critical'}
KIND_LABELS = {'FAILURE': 'サイト障害', 'RECOVERY': 'サイト復旧', 'CONFIRMED': '正常を確認', 'UNKNOWN': '判定不能', 'TLS_WARN': 'TLS証明書の期限が近い',
               'TLS_CRITICAL': 'TLS証明書の期限が3日以内', 'TLS_EXPIRED': 'TLS証明書の期限切れ', 'IMAGE_CHANGED': '画像の変更を検知',
               'IMAGE_UNKNOWN': '画像の判定不能', 'IMAGE_FAILED': '画像の検査に失敗'}


def notice_id(key):
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def append_jsonl(path, record, sync=False):
    """Append one line. A torn last line (no newline) is closed first so it can never swallow this record. sync: fsync before returning."""
    path = Path(path)
    prefix = b''
    if path.is_file() and path.stat().st_size:
        with path.open('rb') as f:
            f.seek(-1, os.SEEK_END)
            prefix = b'' if f.read(1) == b'\n' else b'\n'
    with path.open('ab') as f:
        f.write(prefix + (json.dumps(record, ensure_ascii=False) + '\n').encode('utf-8'))
        if sync:
            f.flush()
            os.fsync(f.fileno())


class MockFileSink:
    """A stand-in destination: appends the message to a local file. Proves the hand-over path, never a delivery."""

    def __init__(self, path):
        self.path = Path(path)

    def __call__(self, subject, body):
        with self.path.open('a', encoding='utf-8') as f:
            f.write(json.dumps({'subject': subject, 'body': body}, ensure_ascii=False) + '\n')


class Outbox:
    def __init__(self, root, sink=None):
        self.root = Path(root)
        self.path = self.root / 'notifications.jsonl'
        self.sink = sink

    def all(self):
        if not self.path.is_file():
            return []
        out = []
        for line in self.path.read_text('utf-8').splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue  # a torn line is skipped, never repaired
        return out

    def recent(self, limit=20):
        return list(reversed(self.all()[-limit:]))

    def _known(self):
        """Ids of every announced notice: the file (read incrementally) plus the archived ids."""
        known = set()
        if self.path.is_file():
            st = self.path.stat()
            seen = _SEEN.get(str(self.path))
            if seen is None or seen[0] != (st.st_ino, st.st_dev) or st.st_size < seen[1]:
                seen = _SEEN[str(self.path)] = [(st.st_ino, st.st_dev), 0, set()]
            with self.path.open('rb') as f:
                f.seek(seen[1])
                chunk = f.read()
            end = chunk.rfind(b'\n') + 1  # a torn last line is left for the next time
            for line in chunk[:end].splitlines():
                try:
                    n = json.loads(line)
                    seen[2].add(notice_id(n['key']))
                except (ValueError, KeyError, TypeError, AttributeError):
                    continue
            seen[1] += end
            known |= seen[2]
        keys = self.root / KEYS_FILE
        if keys.is_file():
            st = keys.stat()
            stamp = (st.st_size, st.st_mtime_ns)
            cached = _KEYS.get(str(keys))
            if cached is None or cached[0] != stamp:
                cached = _KEYS[str(keys)] = [stamp, {x.strip() for x in keys.read_text('utf-8').splitlines() if x.strip()}]
            known |= cached[1]
        return known

    def add(self, key, kind, at, title, body, source, subject=None):
        """-> the new notice, or None when this event was already announced."""
        with _LOCK, filelock.held(self.root / 'notifications.lock', LOCK_WAIT_SECONDS):
            if notice_id(key) in self._known():
                return None
            sink = None
            if self.sink is not None:
                try:
                    self.sink(subject or '[SiteProof] ' + title, body)
                    sink = 'SENT'
                except Exception as exc:  # recorded, never retried here: the next event is a new notice
                    sink = 'FAILED:' + type(exc).__name__
            notice = {'id': notice_id(key), 'key': key, 'kind': kind, 'severity': SEVERITY.get(kind, 'info'), 'at': at,
                      'title': title, 'body': body, 'source': source, 'subject': subject or '[SiteProof] ' + title,
                      'delivery': {'app': 'RECORDED', 'sink': sink, 'received': 'UNKNOWN'}}
            append_jsonl(self.path, notice)
            return notice


def tls_level(days_left):
    """-> (level, label) for a certificate with this many whole days left, or None when it is not near its end."""
    if days_left is None:
        return None
    if days_left < 0:
        return 'EXPIRED', '期限切れ'
    for limit, level, label in TLS_LEVELS[1:]:  # (3, CRITICAL), (14, WARN): the nearest end first
        if days_left <= limit:
            return level, label
    return None


def http_events(outbox, previous, obs, *, target_id, hostname, path):
    """One HTTP observation -> notices for what CHANGED: failure / recovery / undecided, and a TLS expiry warning per certificate and level.
    `previous` is the outcome of the observation before this one (None for the first). -> the new notices."""
    made = []
    from src.noxiworks.http_monitor import reason_label  # (http_monitor imports this module)
    code = obs.get('reason') or ''
    event = transition_event(previous, obs['outcome'], target_id=target_id, slot=obs['at'], reason=f'{reason_label(code)}（{code}）' if code and reason_label(code) != code else code,
                             http_status=obs.get('http_status'), at=obs['at'])
    if event:
        subject, body = format_message(event, hostname, path)
        made.append(outbox.add('http:%s:%s:%s' % (event['kind'], previous, obs['at']), event['kind'], obs['at'], KIND_LABELS[event['kind']] + '：' + hostname, body,
                               'http', subject))
    level = tls_level(obs.get('tls_days_left'))
    if level:
        name, label = level
        body = '\n'.join(['SiteProof 監視: TLS証明書の期限に注意してください', '', f'対象 : https://{hostname}{path}', f'証明書の期限: {obs.get("tls_not_after")}（UTC）',
                          f'状態 : {label}（残り {obs["tls_days_left"]} 日）', '', '※ 証明書ごと・段階ごとに1回だけ通知します（更新されるまで繰り返しません）。'])
        made.append(outbox.add('tls:%s:%s' % (obs.get('tls_not_after'), name), 'TLS_' + name, obs['at'], KIND_LABELS['TLS_' + name] + '：' + hostname, body, 'tls',
                               '[SiteProof] TLS %s %s' % (name, target_id)))
    return [n for n in made if n]


def image_event(outbox, entry, previous_outcome, *, target_id, label):
    """One finished image inspection (a monitor-log entry) -> a notice when the result BECAME a change / undecided / failed (not while it stays so)."""
    outcome = entry.get('outcome')
    kind = {'CHANGED': 'IMAGE_CHANGED', 'UNKNOWN': 'IMAGE_UNKNOWN', 'FAILED': 'IMAGE_FAILED'}.get(outcome)
    if kind is None or outcome == previous_outcome:
        return None
    text = {'CHANGED': 'Baselineと比べて、画像に変更を検知しました。REVIEWで内容を確認してください（Baselineは自動では変わりません）。',
            'UNKNOWN': '画像を比較できませんでした（判定不能）。理由はREVIEW・ACTIVITYで確認してください。',
            'FAILED': '画像の検査に失敗しました。ACTIVITYで理由を確認してください。'}[outcome]
    body = '\n'.join(['SiteProof 画像監視: ' + KIND_LABELS[kind], '', f'対象 : {label} ({target_id})', f'検査 : {entry.get("run_id") or "（記録なし）"} / {entry.get("finished_at") or entry.get("started_at")}',
                      text, '', '※ 同じ結果が続く間は、通知を繰り返しません。'])
    return outbox.add('image:%s:%s' % (outcome, entry.get('run_id') or entry.get('started_at')), kind, entry.get('finished_at') or entry.get('started_at') or '',
                      KIND_LABELS[kind] + '：' + label, body, 'image', '[SiteProof] IMAGE %s %s' % (outcome, target_id))
