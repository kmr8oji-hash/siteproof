"""Long-term operation helpers: bounded history, explicit tidy-up (archive), disk usage, gaps in observation, stop reasons and expiry notices. Pure and offline.

Guarantees
  * Nothing here ever deletes, truncates or overwrites a record. A full history says FULL and stops growing; the only way to make room is `archive`, an explicit
    action (confirmed=True) that MOVES the file to <site>/history-archive/ under a new name and writes <site>/maintenance-log.jsonl.
  * Archiving notices never causes an old event to be announced again: the ids of the moved notices go to <site>/notification-keys.txt (which Outbox.add consults) first.
    It is refused while a notice younger than 24 hours exists (it might still be waiting to be mailed) or while a mail dispatch is running.
  * HttpHistory is NOT locked by itself: the caller holds the HTTP monitor's lock (the one that serialises a check) around append and archive.
Not guaranteed: sizes are read from the file system as it is at that moment (cheap scans, not snapshots); the record count of a history is exact only for complete lines.
"""
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil

from src.aws_b.model import format_utc, parse_utc
from src.noxiworks import filelock, notifications, sites

HISTORY_MAX_BYTES = 20 * 1024 * 1024
HISTORY_MAX_RECORDS = 200_000
WARN_RATIO = 0.8
NOTICE_WARN_BYTES = 5 * 1024 * 1024
NOTICE_WARN_RECORDS = 5000
CHUNK = 1024 * 1024
TAIL_STEP = 64 * 1024
EXPIRE = timedelta(hours=24)
GAP_FACTOR = 2


class ArchiveRefused(ValueError):
    pass


def _stamp(now):
    return now.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ')


def count_lines(path):
    """Lines in a file (the last one counted even when it has no newline). 0 for a missing file."""
    path = Path(path)
    if not path.is_file():
        return 0
    n, last = 0, b'\n'
    with path.open('rb') as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            n += chunk.count(b'\n')
            last = chunk[-1:]
    return n + (0 if last == b'\n' else 1)


def _archive_file(src, folder, prefix, now, actor, confirmed, log_path, action):
    """MOVE src to folder/<prefix>-<UTC>.jsonl (a new name, never an existing file) and log it. -> the log record, or {'archived': False} when there is nothing."""
    if confirmed is not True:
        raise ArchiveRefused('整理（アーカイブ）には、明示的な確認が必要です')
    src = Path(src)
    if not src.is_file() or src.stat().st_size == 0:
        return {'archived': False, 'reason': 'EMPTY'}
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    dst, n = folder / f'{prefix}-{_stamp(now)}.jsonl', 1
    while dst.exists():
        n += 1
        dst = folder / f'{prefix}-{_stamp(now)}-{n}.jsonl'
    size, records = src.stat().st_size, count_lines(src)
    os.replace(src, dst)  # a move inside the same folder tree: nothing is deleted
    record = {'at': format_utc(now), 'action': action, 'actor': str(actor)[:80], 'from': src.name, 'to': dst.relative_to(Path(log_path).parent).as_posix(), 'bytes': size,
              'records': records}
    notifications.append_jsonl(log_path, record, sync=True)
    return {'archived': True, **record}


class HttpHistory:
    """An append-only jsonl with a limit. Never deletes or truncates: FULL is reported, the file stays as it is."""

    def __init__(self, path, max_bytes=HISTORY_MAX_BYTES, max_records=HISTORY_MAX_RECORDS):
        self.path, self.max_bytes, self.max_records = Path(path), max_bytes, max_records
        self._seen = None  # (file id, bytes counted, newlines counted, last byte): only the new bytes are read next time

    def _measure(self):
        """-> (bytes, records, last byte). Incremental for a growing file."""
        if not self.path.is_file():
            self._seen = None
            return 0, 0, b'\n'
        st = self.path.stat()
        seen = self._seen
        if seen is None or seen[0] != (st.st_ino, st.st_dev) or st.st_size < seen[1]:
            seen = [(st.st_ino, st.st_dev), 0, 0, b'\n']
        offset, lines, last = seen[1], seen[2], seen[3]
        with self.path.open('rb') as f:
            f.seek(offset)
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                lines += chunk.count(b'\n')
                last = chunk[-1:]
                offset += len(chunk)
        self._seen = [seen[0], offset, lines, last]
        return offset, lines + (0 if last == b'\n' else 1), last

    def usage(self):
        size, records, _ = self._measure()
        full = size >= self.max_bytes or records >= self.max_records
        return {'records': records, 'bytes': size, 'limit_bytes': self.max_bytes, 'limit_records': self.max_records, 'full': full,
                'warn': full or size >= self.max_bytes * WARN_RATIO or records >= self.max_records * WARN_RATIO}

    def append(self, record):
        """-> {'ok': True, ...usage} or {'ok': False, 'full': True, 'reason': 'HISTORY_FULL'}: the record is NOT written when it would pass the limit."""
        size, records, last = self._measure()
        line = (json.dumps(record, ensure_ascii=False) + '\n').encode('utf-8')
        prefix = b'' if last == b'\n' else b'\n'  # a torn last line is closed first so it cannot swallow this record
        if size + len(prefix) + len(line) > self.max_bytes or records + 1 > self.max_records:
            return {'ok': False, 'full': True, 'reason': 'HISTORY_FULL', 'records': records, 'bytes': size}
        with self.path.open('ab') as f:
            f.write(prefix + line)
        return {'ok': True, 'full': False, **self.usage()}

    def tail(self, limit=1000):
        """The last `limit` readable records, oldest first. Reads from the end of the file (not the whole file); torn / foreign lines are skipped."""
        if limit <= 0 or not self.path.is_file():
            return []
        with self.path.open('rb') as f:
            pos = f.seek(0, os.SEEK_END)
            buf = b''
            while pos > 0 and buf.count(b'\n') <= limit + 2:  # a little slack for torn lines
                step = min(TAIL_STEP, pos)
                pos -= step
                f.seek(pos)
                buf = f.read(step) + buf
        lines = buf.split(b'\n')
        if pos > 0:
            lines = lines[1:]  # the first piece is cut in the middle of a line
        out = []
        for raw in lines:
            try:
                rec = json.loads(raw.decode('utf-8'))
            except (ValueError, UnicodeDecodeError):
                continue
            if isinstance(rec, dict):
                out.append(rec)
        return out[-limit:]

    def archive(self, now, actor, confirmed):
        """The explicit tidy-up: move the whole file to <site>/history-archive/http-history-<UTC>.jsonl. The caller holds the HTTP lock."""
        site = self.path.parent
        result = _archive_file(self.path, site / 'history-archive', 'http-history', now, actor, confirmed, site / 'maintenance-log.jsonl', 'ARCHIVE_HTTP_HISTORY')
        self._seen = None
        return result


# ---- notices and deliveries
def notification_usage(site_root):
    root = Path(site_root)
    out = {}
    for name, file in (('notifications', 'notifications.jsonl'), ('deliveries', 'deliveries.jsonl')):
        f = root / file
        size, n = (f.stat().st_size, count_lines(f)) if f.is_file() else (0, 0)
        out[name] = {'count': n, 'bytes': size, 'warn': size >= NOTICE_WARN_BYTES or n >= NOTICE_WARN_RECORDS}
    return out


def archive_notifications(site_root, now, actor, confirmed):
    """Move notifications.jsonl and deliveries.jsonl away. The ids of the notices stay known (notification-keys.txt), so nothing old is announced again.
    -> {'notifications': record, 'deliveries': record}. Refused while a notice younger than 24 hours exists or a dispatch is running."""
    if confirmed is not True:
        raise ArchiveRefused('整理（アーカイブ）には、明示的な確認が必要です')
    root = Path(site_root)
    with ExitStack() as stack:
        dispatch = sites.data_of(root) / 'notify' / 'dispatch.lock'
        if dispatch.parent.is_dir():
            try:
                stack.enter_context(filelock.held(dispatch, 0))
            except filelock.LockBusy:
                raise ArchiveRefused('メールの送信処理が動いています。少し待ってからやり直してください') from None
        stack.enter_context(filelock.held(root / 'notifications.lock', notifications.LOCK_WAIT_SECONDS))
        notices = notifications.Outbox(root).all()
        for n in notices:
            at = parse_utc(n.get('at') or '')
            if at is not None and now - at <= EXPIRE:
                raise ArchiveRefused('24時間以内の通知があります（まだ送信待ちの可能性があるため、整理できません）')
        keys = root / notifications.KEYS_FILE
        text = keys.read_text('utf-8') if keys.is_file() else ''
        fresh = sorted({notifications.notice_id(n['key']) for n in notices if isinstance(n.get('key'), str)} - set(text.split()))
        if fresh:
            with keys.open('a', encoding='utf-8') as f:
                f.write(('\n' if text and not text.endswith('\n') else '') + ''.join(x + '\n' for x in fresh))
                f.flush()
                os.fsync(f.fileno())
        folder, log = root / 'history-archive', root / 'maintenance-log.jsonl'
        return {'notifications': _archive_file(root / 'notifications.jsonl', folder, 'notifications', now, actor, True, log, 'ARCHIVE_NOTIFICATIONS'),
                'deliveries': _archive_file(root / 'deliveries.jsonl', folder, 'deliveries', now, actor, True, log, 'ARCHIVE_DELIVERIES')}


# ---- disk usage
def tree_bytes(path):
    """Bytes of a file or folder (symlinks / junctions are not followed). 0 when missing."""
    path = Path(path)
    try:
        if path.is_symlink():
            return 0
        if path.is_file():
            return path.stat().st_size
    except OSError:
        return 0
    total, stack = 0, [str(path)]
    while stack:
        try:
            with os.scandir(stack.pop()) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            total += e.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total


SITE_AREAS = (('runs', '撮影の記録（runs）', ('runs',)), ('real', '実サイトの撮影データ（real）', ('real',)), ('workspace', '作業領域（workspace）', ('workspace',)),
              ('ui', '画面用の生成物（ui）', ('ui',)), ('http', 'HTTP監視の履歴・アーカイブ', ('http-history.jsonl', 'history-archive')),
              ('notifications', '通知・送信の記録', ('notifications.jsonl', 'deliveries.jsonl', 'notification-keys.txt')),
              ('pages', 'このサイトの追加ページ（pages）', ('pages',)))  # a site folder holds its further pages; a page folder has none
DATA_AREAS = (('trust', '信頼設定・許可の記録（trust）', ('trust',)), ('notify', 'メール通知の設定（notify）', ('notify',)), ('background', 'バックグラウンド実行の記録', ('background',)),
              ('ui', '画面用の生成物（ui）', ('ui',)), ('backups', 'バックアップ', ('backups',)))


def _split(sizes, areas):
    """Take the named entries out of `sizes` (name -> bytes) area by area; what is left over is the caller's 'other'."""
    areas = [{'key': key, 'label': label, 'bytes': sum(sizes.pop(n, 0) for n in names)} for key, label, names in areas]
    return areas, sum(sizes.values())


def _sizes(root, skip=()):
    return {e.name: tree_bytes(e.path) for e in os.scandir(root) if e.name not in skip} if Path(root).is_dir() else {}


def disk_usage(site_root):
    """Bytes per area of one site folder. -> {'areas': [{key, label, bytes}], 'total'}."""
    areas, rest = _split(_sizes(site_root), SITE_AREAS)
    areas.append({'key': 'other', 'label': 'その他（設定・許可など）', 'bytes': rest})
    return {'areas': areas, 'total': sum(a['bytes'] for a in areas)}


def data_usage(data_root):
    """Bytes per area of the data folder, the sites listed one by one. -> {'areas', 'sites': [{site_id, bytes}], 'total', 'free_bytes'}."""
    root = Path(data_root)
    sizes = _sizes(root, skip=('sites',))
    sizes['backups'] = sizes.get('backups', 0) + sum(sizes.pop(n) for n in [n for n in sizes if n.startswith('siteproof-backup-')])
    sites = [{'site_id': e.name, 'bytes': tree_bytes(e.path)} for e in sorted(os.scandir(root / 'sites'), key=lambda e: e.name) if e.is_dir(follow_symlinks=False)]         if (root / 'sites').is_dir() else []
    areas, rest = _split(sizes, DATA_AREAS)
    areas = [{'key': 'sites', 'label': 'サイトのデータ（sites）', 'bytes': sum(s['bytes'] for s in sites)}] + areas + [{'key': 'other', 'label': 'その他', 'bytes': rest}]
    try:
        free = shutil.disk_usage(root).free
    except OSError:
        free = None
    return {'areas': areas, 'sites': sites, 'total': sum(a['bytes'] for a in areas), 'free_bytes': free}


# ---- time: gaps and days without observation
def observation_gaps(observations, now, interval):
    """Periods without an observation longer than 2 intervals (each record's own 'interval_seconds' when it has one, else `interval`).
    -> [{from, to, seconds, missed, open}] oldest first; `missed` is approximate (whole intervals that did not happen); a trailing gap up to `now` has open=True."""
    points = []
    for o in observations or ():
        at = parse_utc(o.get('at') or '') if isinstance(o, dict) else None
        if at:
            every = o.get('interval_seconds') if type(o.get('interval_seconds')) is int and o['interval_seconds'] > 0 else interval
            points.append((at, every))
    points.sort()
    gaps = []
    for (a, every), (b, _) in zip(points, points[1:]):
        gaps_seconds = int((b - a).total_seconds())
        if gaps_seconds > GAP_FACTOR * every:
            gaps.append({'from': format_utc(a), 'to': format_utc(b), 'seconds': gaps_seconds, 'missed': max(0, gaps_seconds // every - 1), 'open': False})
    if points:
        a, every = points[-1]
        seconds = int((now - a).total_seconds())
        if seconds > GAP_FACTOR * every:
            gaps.append({'from': format_utc(a), 'to': format_utc(now), 'seconds': seconds, 'missed': max(0, seconds // every - 1), 'open': True})
    return gaps


def days_unobserved(last_at, now):
    """Whole days since the last observation (text or datetime), or None when there is none."""
    at = last_at if isinstance(last_at, datetime) else parse_utc(last_at or '')
    return None if at is None else max(0, (now - at).days)


# ---- words for the screen
CHANNEL_NAMES = {'HTTP': 'HTTP監視', 'IMAGE': '画像監視', 'EMAIL': 'メール通知'}
RENEWAL = {'HTTP': 'tools/http_grant.py で許可を作り直して（署名して）', 'IMAGE': '「監視設定を更新」から許可を更新して', 'EMAIL': 'tools/notify_grant.py で許可を作り直して（署名して）'}


def stop_reason_text(settings_like, channel):
    """paused_reason (and enabled) of a monitor / channel -> one Japanese sentence that says what happened and what to do next."""
    s = settings_like if isinstance(settings_like, dict) else {}
    name, renew = CHANNEL_NAMES.get(channel, str(channel)), RENEWAL.get(channel, '許可を更新して')
    reason = s.get('paused_reason')
    if reason is None:
        if s.get('enabled'):
            return f'{name}は動作中です。'
        return f'{name}は停止中です。あなたが止めたか、まだ開始していません。必要なら開始してください。' if s.get('ever_enabled') else f'{name}はまだ開始していません。'
    code, _, detail = str(reason).partition(':')
    texts = {
        'BLOCKED': f'{name}は、許可の確認で止まりました。許可の有効期間・対象・外部通信の設定を確認し、必要なら{renew}から再開してください。',
        'COMPLETE': f'{name}は、決めた回数または期間を終えて完了しました。続けるなら{renew}、開始してください。',
        'DISK_FULL': f'{name}は、ディスクの空きが足りず止まりました。不要なファイルの整理やバックアップの移動で空きを作ってから再開してください（自動では何も消しません）。',
        'ON_HOLD': f'{name}は保留中です。内容を確認し、問題がなければ再開してください。',
        'ANOMALY': f'{name}は、異常を検知して止まりました（{detail or "詳細なし"}）。ACTIVITYで内容を確認し、原因を解消してから再開してください。',
        'DECISION': f'{name}は、あなたの判断が必要で止まりました（{detail or "詳細なし"}）。REVIEWで内容を確認して判断してください。',
        'HISTORY_FULL': f'{name}は、履歴が上限に達して止まりました。「履歴を整理（アーカイブ）」を実行してから再開してください（古い履歴は消えず、アーカイブに移ります）。',
        'GRANT_EXPIRED': f'{name}は、許可の期限が切れて止まりました。{renew}、再開してください。',
        'GRANT_EXHAUSTED': f'{name}は、許可された回数を使い切って止まりました。{renew}、再開してください。',
        'BOUNDARY': f'{name}は、外部通信の安全境界が確認できず止まりました。確認とUSERの承認が済むまで再開できません。',
        'USER': f'{name}は、あなたの操作で止めています。必要なときに再開してください。',
        'RESTORED': f'{name}は、バックアップから復元したコピーのため、停止した状態で始まりました。元のデータフォルダと同時に使わないでください（許可の回数や履歴がずれます）。'
                    '内容を確認してから、必要なものだけ開始してください。'}
    return texts.get(code) or f'{name}は停止しています（理由コード: {str(reason)[:40]}）。ACTIVITYで内容を確認してください。'


EXPIRY_WHAT = {'permit': ('監視許可（画像撮影）', '「監視設定を更新」から許可を更新してください'),
               'http_grant': ('HTTP監視の許可', 'tools/http_grant.py で許可を作り直して（署名して）ください'),
               'notify_grant': ('メール通知の許可', 'tools/notify_grant.py で許可を作り直して（署名して）ください')}
WARN_DAYS = 7
WARN_RUNS = 5
WARN_RATIO_LEFT = 0.05


def expiry_notice(valid_until, remaining, now, what, total=None):
    """-> None, or {'level': 'warn' | 'error', 'text'} for a permit / grant that is near its end (<= 7 days, <= 5 runs left or <= 5 % of `total` left)
    or already over (expired / used up)."""
    label, how = EXPIRY_WHAT.get(what, (str(what), '許可を更新してください'))
    end = valid_until if isinstance(valid_until, datetime) else parse_utc(valid_until or '')
    if end is not None and now >= end:
        return {'level': 'error', 'text': f'{label}の期限が切れています。この間、対象の動作は止まっています。{how}。'}
    if remaining is not None and remaining <= 0:
        return {'level': 'error', 'text': f'{label}の回数を使い切りました。この間、対象の動作は止まっています。{how}。'}
    parts = []
    if end is not None and end - now <= timedelta(days=WARN_DAYS):
        parts.append(f'期限まであと{max(0, (end - now).days)}日')
    if remaining is not None and (remaining <= WARN_RUNS or (total and remaining / total <= WARN_RATIO_LEFT)):
        parts.append(f'残りあと{remaining}回')
    return {'level': 'warn', 'text': f'{label}は、' + '・'.join(parts) + f'です。止まる前に、{how}。'} if parts else None
