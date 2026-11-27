"""E-mail dispatch of a site's notices (the second step after notifications.Outbox): decides WHAT may be sent, records every attempt, sends through a provider.

Guarantees
  * Off by default, twice: the data-wide channel <data>/notify/email.json and the per-site switch <site>/email-notify.json must both be on, and a freshly verified
    signed grant (smtp_notify.verify_grant) must exist before every message. Neither file holds a password or a user name.
  * Turning it on never mails the backlog: only notices at or after BOTH enabled_at moments are eligible, and none older than 24 hours (those are recorded as EXPIRED, not sent).
  * <site>/deliveries.jsonl is append-only: an ATTEMPT line is written (fsync) BEFORE sending, then one result line. An ATTEMPT without a result (a crash) is UNCERTAIN
    and is never sent again. ACCEPTED / PARTIAL / REJECTED / UNCERTAIN are final; TEMPORARY is retried after 5 min, then 30 min, at most 3 attempts, then GAVE_UP.
    A REFUSED attempt (nothing was sent) does not use up an attempt of the notice, but pauses the dispatch (5 minutes, 1 hour after an authentication failure).
  * At most 10 messages per run; one run at a time per data folder (OS lock <data>/notify/dispatch.lock, not waited for: 'busy'), so the app and the scheduler cannot send twice.
  * A send success is a server acceptance, never a receipt: nothing here says "received". A recovery whose failure was never mailed is mailed like any other event.
Not guaranteed: delivery, ordering across restarts of the provider, or protection against someone editing these files by hand.
"""
from datetime import datetime, timedelta
import json
import os
from pathlib import Path

from src.aws_b.model import format_utc, parse_utc
from src.noxiworks import filelock, notifications, sites
from src.noxiworks import smtp_notify as smtp

SCHEMA = 'siteproof.email-notify.v1'
GROUPS = {'FAILURE': ('FAILURE',), 'RECOVERY': ('RECOVERY', 'CONFIRMED'), 'UNKNOWN': ('UNKNOWN',), 'TLS': ('TLS_WARN', 'TLS_CRITICAL', 'TLS_EXPIRED'),
          'IMAGE': ('IMAGE_CHANGED', 'IMAGE_UNKNOWN', 'IMAGE_FAILED')}
GROUP_LABELS = {'FAILURE': '障害', 'RECOVERY': '復旧・正常確認', 'UNKNOWN': '判定不能', 'TLS': 'TLS証明書の期限', 'IMAGE': '画像の変更・失敗'}
KIND_GROUP = {kind: group for group, kinds in GROUPS.items() for kind in kinds}
RESULT_LABELS = {'ACCEPTED': '送信受付済み（受信は未確認）', 'PARTIAL': '一部の宛先のみ受付済み（再送しません）', 'REJECTED': 'サーバーに拒否されました（再送しません）',
                 'TEMPORARY': '一時的に送れませんでした（再試行します）', 'UNCERTAIN': '送信結果不明（再送しません）', 'REFUSED': '送信を見合わせました（送信していません）',
                 'EXPIRED': '24時間を過ぎたため送りません', 'GAVE_UP': '再試行の上限に達したため送りません', 'ATTEMPT': '送信中'}
FINAL = ('ACCEPTED', 'PARTIAL', 'REJECTED', 'UNCERTAIN', 'EXPIRED', 'GAVE_UP')
SENT_RESULTS = ('ACCEPTED', 'PARTIAL', 'REJECTED', 'TEMPORARY', 'UNCERTAIN')  # the server may have seen it: counts as an attempt of the notice
EXPIRE = timedelta(hours=24)
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = (300, 1800)  # wait after the 1st attempt, after the 2nd
MAX_PER_RUN = 10
TEST_INTERVAL_SECONDS = 60
REFUSED_WAIT_SECONDS = 300
AUTH_WAIT_SECONDS = 3600
RECENT = 20
EXTERNAL_BLOCK = 'メール通知の外部通信は、安全境界の実測とUSERの承認が済むまで無効です'


def mask_address(value):
    return smtp.mask_address(value)


class Dispatcher:
    def __init__(self, site, provider=None, grant=None):
        """provider: injected (tests / rehearsals), else the real SmtpProvider (behind its kill switch). grant: optional callable now -> (grant dict or None, problems)
        replacing the signed-file check (tests); the real check is never cached when sending."""
        self.root = Path(site.root)
        self.data = sites.data_of(self.root)
        self.site_id = site.info['site_id']
        self.provider = provider or smtp.SmtpProvider()
        self._grant = grant
        self.dir = self.data / 'notify'
        self.channel_path, self.site_path = self.dir / 'email.json', sites.site_root_of(self.root) / 'email-notify.json'  # one switch per site, its pages included
        self.deliveries_path = self.root / 'deliveries.jsonl'
        self.outbox = notifications.Outbox(self.root)

    # ---- settings (atomic writes under an OS lock; a damaged file means OFF)
    @staticmethod
    def _read(path, defaults):
        try:
            value = json.loads(Path(path).read_text('utf-8'))
            return {**defaults, **value} if isinstance(value, dict) and value.get('enabled') in (True, False) else dict(defaults)
        except (OSError, ValueError):
            return dict(defaults)

    def channel(self):
        return self._read(self.channel_path, {'schema': SCHEMA, 'enabled': False, 'enabled_at': None, 'stopped_reason': None, 'kinds': list(GROUPS)})

    def site_config(self):
        return self._read(self.site_path, {'schema': SCHEMA, 'enabled': False, 'enabled_at': None})

    def _update(self, path, defaults, **changes):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with filelock.held(path.with_suffix('.lock'), 10):
            value = {**self._read(path, defaults), **changes}
            tmp = path.with_suffix('.json.tmp')
            tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            os.replace(tmp, path)
        return value

    # ---- the grant and what may be switched on
    def _grant_now(self, now):
        return self._grant(now) if self._grant else smtp.verify_grant(self.data, now)

    def _grant_shown(self, now):
        return self._grant(now) if self._grant else smtp.cached_grant_view(self.data, now)

    def can_send(self):
        return self.provider.can_send()

    def _grant_block(self, grant, problems, now):
        if grant is None:
            return '／'.join(problems)
        try:
            smtp.ledger_usage(self.data, grant, now)
        except smtp.LedgerRefused as exc:
            return '送信回数の記録が読めません（' + exc.reason + '）'
        return None

    def enable_block(self, now):
        """Why the channel / a site cannot be turned on now, or None (fresh verification: this is an action, not a display)."""
        grant, problems = self._grant_now(now)
        return self._grant_block(grant, problems, now) or (None if self.can_send() else EXTERNAL_BLOCK)

    def set_channel(self, enabled, now):
        if enabled is not True:
            return self._update(self.channel_path, {'schema': SCHEMA, 'enabled': False, 'enabled_at': None, 'stopped_reason': None, 'kinds': list(GROUPS)},
                                enabled=False, stopped_reason='USER')
        block = self.enable_block(now)
        if block:
            raise ValueError('メール通知を有効にできません：' + block)
        current = self.channel()
        if current['enabled']:
            return current
        return self._update(self.channel_path, current, enabled=True, enabled_at=format_utc(now), stopped_reason=None)

    def set_site(self, enabled, now):
        if enabled is not True:
            return self._update(self.site_path, {'schema': SCHEMA, 'enabled': False, 'enabled_at': None}, enabled=False)
        block = self.enable_block(now)
        if block:
            raise ValueError('このサイトのメール通知を有効にできません：' + block)
        current = self.site_config()
        if current['enabled']:
            return current
        return self._update(self.site_path, current, enabled=True, enabled_at=format_utc(now))

    def set_kinds(self, kinds, now):
        if not isinstance(kinds, (list, tuple)) or any(k not in GROUPS for k in kinds):
            raise ValueError('通知する種類は ' + '・'.join(GROUPS) + ' から選んでください')
        return self._update(self.channel_path, self.channel(), kinds=[k for k in GROUPS if k in kinds])

    # ---- the delivery log (append-only) and what it says about each notice
    def _lines(self):
        out = []
        if self.deliveries_path.is_file():
            for line in self.deliveries_path.read_text('utf-8', errors='replace').splitlines():
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue  # a torn line is skipped, never repaired
                if isinstance(rec, dict) and isinstance(rec.get('notice_id'), str):
                    out.append(rec)
        return out

    def _append(self, record):
        notifications.append_jsonl(self.deliveries_path, record, sync=True)

    def _states(self, lines):
        """notice_id -> {'attempts', 'last_at', 'final'}. A leftover ATTEMPT (no result line after it) is UNCERTAIN: it may have been sent."""
        states = {}
        for rec in lines:
            s = states.setdefault(rec['notice_id'], {'attempts': 0, 'last_at': None, 'final': None, 'open': False})
            result = rec.get('result')
            if result == 'ATTEMPT':
                s['open'] = True
                continue
            s['open'] = False
            if result in SENT_RESULTS:
                s['attempts'] += 1
                s['last_at'] = parse_utc(rec.get('at') or '')
            if result in FINAL:
                s['final'] = result
        for s in states.values():
            if s['open'] and s['final'] is None:
                s['final'] = 'UNCERTAIN'
        return states

    def entries(self):
        """One entry per attempt (and per EXPIRED / GAVE_UP), oldest first; an attempt without a result shows as UNCERTAIN."""
        titles = {n.get('id'): n.get('title') for n in self.outbox.all()}
        out, opened = [], {}
        for rec in self._lines():
            key = (rec['notice_id'], rec.get('attempt'))
            if rec.get('result') == 'ATTEMPT':
                entry = opened[key] = {**rec, 'result': 'UNCERTAIN', 'reason': 'NO_RESULT_RECORDED'}
                out.append(entry)
            elif key in opened and rec.get('result') not in ('EXPIRED', 'GAVE_UP'):
                opened.pop(key).update(rec)
            else:
                out.append(dict(rec))
        for e in out:
            e['label'] = RESULT_LABELS.get(e.get('result'), '不明')
            e['title'] = 'テスト送信' if e.get('test') else titles.get(e['notice_id'])
        return out

    def _since(self):
        a, b = parse_utc(self.channel().get('enabled_at') or ''), parse_utc(self.site_config().get('enabled_at') or '')
        return max(a, b) if a and b else None

    def _scan(self, now):
        """-> (candidates, expired). Read only. candidate = (notice, attempts, last_at); expired = [(notice, reason)]."""
        since, kinds = self._since(), set(self.channel().get('kinds') or ())
        if since is None:
            return [], []
        states = self._states(self._lines())
        candidates, expired = [], []
        for n in self.outbox.all():
            nid = n.get('id')
            if not isinstance(nid, str) or KIND_GROUP.get(n.get('kind')) not in kinds:
                continue
            s = states.get(nid, {'attempts': 0, 'last_at': None, 'final': None})
            if s['final']:
                continue
            at = parse_utc(n.get('at') or '')
            if at is None:
                expired.append((n, 'AT_UNREADABLE'))
            elif at < since:
                continue  # before the switch was turned on: never announced late
            elif now - at > EXPIRE:
                expired.append((n, 'OLDER_THAN_24H'))
            elif s['attempts'] >= MAX_ATTEMPTS:
                expired.append((n, 'GAVE_UP'))
            else:
                candidates.append((n, s['attempts'], s['last_at']))
        return candidates, expired

    # ---- sending
    def _deliver(self, grant, nid, subject, body, now, *, attempt, extra=None):
        base = {'notice_id': nid, 'attempt': attempt, 'at': format_utc(now), 'channel': 'EMAIL', 'grant_id': grant['grant_id'], **(extra or {})}
        self._append({**base, 'result': 'ATTEMPT', 'reason': ''})  # before anything can leave: a crash from here on is UNCERTAIN
        try:
            message = smtp.build_message(grant, notice_id=nid, site_id=self.site_id, subject=subject, body=body, now=now)
        except (ValueError, KeyError, TypeError):
            result = smtp.SendResult('REFUSED', 'MESSAGE_INVALID')
        else:
            try:
                result = self.provider.send(grant, self.data, message, now)
            except smtp.ExternalDisabled:
                result = smtp.SendResult('REFUSED', 'EXTERNAL_DISABLED')
            except Exception:  # unknown: the message may be on its way, so it is never sent again
                result = smtp.SendResult('UNCERTAIN', 'PROVIDER_ERROR')
        if getattr(result, 'result', None) not in ('ACCEPTED', 'PARTIAL', 'REJECTED', 'TEMPORARY', 'UNCERTAIN', 'REFUSED'):
            result = smtp.SendResult('UNCERTAIN', 'RESULT_INVALID')
        self._append({**base, 'result': result.result, 'reason': str(result.reason)[:80]})
        return result

    def _paused(self, now):
        """Did the last (non-test) attempt get REFUSED a moment ago? Then wait: the same refusal would only repeat."""
        for rec in reversed(self._lines()):
            if rec.get('test') or rec.get('result') in ('EXPIRED', 'GAVE_UP'):
                continue
            if rec.get('result') != 'REFUSED':
                return False
            at = parse_utc(rec.get('at') or '')
            wait = AUTH_WAIT_SECONDS if str(rec.get('reason')).startswith('AUTH') else REFUSED_WAIT_SECONDS
            return bool(at and now - at < timedelta(seconds=wait))
        return False

    def run(self, now):
        """Send what is pending for this site. -> 'busy' when another run holds the lock, else {'status', 'sent', 'results'}."""
        ch, st = self.channel(), self.site_config()
        if not ch['enabled']:
            return {'status': 'off', 'sent': 0, 'results': []}
        if not st['enabled']:
            return {'status': 'site-off', 'sent': 0, 'results': []}
        if not self.can_send():
            return {'status': 'disabled', 'sent': 0, 'results': []}
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            with filelock.held(self.dir / 'dispatch.lock', 0):
                return self._run(now)
        except filelock.LockBusy:
            return 'busy'

    def _run(self, now):
        out = {'status': 'ok', 'sent': 0, 'results': []}
        candidates, expired = self._scan(now)
        for n, reason in expired:  # recorded once (the next scan sees the final line)
            self._append({'notice_id': n['id'], 'attempt': 0 if reason != 'GAVE_UP' else MAX_ATTEMPTS, 'at': format_utc(now), 'result': 'GAVE_UP' if reason == 'GAVE_UP' else 'EXPIRED',
                          'reason': reason, 'channel': 'EMAIL', 'grant_id': None})
        if self._paused(now):
            return {**out, 'status': 'waiting'}
        for n, attempts, last_at in candidates:
            if out['sent'] >= MAX_PER_RUN:
                break
            if attempts and (last_at is None or now - last_at < timedelta(seconds=BACKOFF_SECONDS[attempts - 1])):
                continue  # backoff: not yet
            grant, problems = self._grant_now(now)  # fresh, before EVERY message
            if grant is None:
                return {**out, 'status': 'no-grant', 'problems': problems}
            result = self._deliver(grant, n['id'], n.get('subject') or '[SiteProof] ' + str(n.get('title') or ''), n.get('body') or '', now, attempt=attempts + 1)
            out['results'].append((n['id'], result.result, result.reason))
            if result.result == 'REFUSED':
                return {**out, 'status': 'refused', 'reason': result.reason}
            out['sent'] += 1
        return out

    def send_test(self, now, actor):
        """An explicit user action: one test message through the same grant / ledger / kill switch. Not retried, at most one per minute.
        Works before the channel is turned on (that is what a test is for). -> {'ok', 'result', 'reason', 'label'}."""
        def refuse(code, text):
            return {'ok': False, 'result': code, 'reason': text, 'label': RESULT_LABELS.get(code, text)}
        grant, problems = self._grant_now(now)
        if grant is None:
            return refuse('REFUSED', '／'.join(problems))
        if not self.can_send():
            return refuse('REFUSED', EXTERNAL_BLOCK)
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            with filelock.held(self.dir / 'dispatch.lock', 0):
                for rec in reversed(self._lines()):
                    last = parse_utc(rec.get('at') or '')
                    if rec.get('test') and rec.get('result') == 'ATTEMPT' and last and now - last < timedelta(seconds=TEST_INTERVAL_SECONDS):
                        return refuse('RATE_LIMITED', 'テスト送信は1分に1回までです')
                nid = 'test-' + format_utc(now).replace(':', '').replace('-', '')
                body = '\n'.join(['SiteProof メール通知のテスト送信です。', '', f'送信元 : SiteProof（このPCのアプリ） / サイト {self.site_id}', f'操作した人: {actor}',
                                  '', 'このメールが届いたことを、受信箱で確認してください。届かなくても、アプリには「受信」とは表示されません。'])
                result = self._deliver(grant, nid, '[SiteProof] テスト送信', body, now, attempt=1, extra={'test': True, 'actor': str(actor)[:80]})
        except filelock.LockBusy:
            return refuse('BUSY', '別の送信処理が動いています')
        return {'ok': result.result == 'ACCEPTED', 'result': result.result, 'reason': result.reason, 'label': RESULT_LABELS[result.result]}

    # ---- the screen
    def status(self, now):
        ch, st = self.channel(), self.site_config()
        grant, problems = self._grant_shown(now)
        view = {'valid': grant is not None, 'problems': list(problems), 'valid_until': None, 'days_left': None, 'host': None, 'port': None, 'security': None,
                'recipients': [], 'remaining_total': None, 'remaining_today': None}
        if grant is not None:
            end = parse_utc(grant['valid_until'])
            view.update(valid_until=grant['valid_until'], days_left=(end - now).days, host=grant['smtp']['host'], port=grant['smtp']['port'],
                        security=grant['smtp']['security'], recipients=[mask_address(r) for r in grant['recipients']])
            try:
                usage = smtp.ledger_usage(self.data, grant, now)
                view.update(remaining_total=usage['remaining_total'], remaining_today=usage['remaining_today'])
                if usage['remaining_total'] == 0 or usage['remaining_today'] == 0:
                    view['problems'].append('送信回数の上限に達しています')
            except smtp.LedgerRefused as exc:
                view.update(valid=False)
                view['problems'].append('送信回数の記録が読めません（' + exc.reason + '）')
        external = self.can_send()
        block = '／'.join(view['problems']) if view['problems'] else (None if external else EXTERNAL_BLOCK)
        entries = self.entries()
        candidates, _ = self._scan(now)
        return {'configured': self.channel_path.is_file(), 'enabled': ch['enabled'], 'site_enabled': st['enabled'], 'external_enabled': external,
                'enabled_at': ch.get('enabled_at'), 'stopped_reason': ch.get('stopped_reason'), 'kinds': ch.get('kinds'), 'kind_labels': GROUP_LABELS, 'grant': view,
                'active': bool(ch['enabled'] and st['enabled'] and external and view['valid'] and not view['problems']),
                'pending': len(candidates), 'last_result': entries[-1] if entries else None, 'recent': list(reversed(entries[-RECENT:])),
                'can_enable': block is None, 'block_reason': block}
