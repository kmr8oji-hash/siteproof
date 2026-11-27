"""Local HTTP(S) availability monitoring of a registered site: one HTTPS request, its status, response time and TLS certificate expiry.

Provider: one isolated, one-shot container run per check (src/noxiworks/http_isolation.py): the network rules, Grant Broker, reaper and CONNECT proxy of
the capture boundary, unchanged, with a tiny Worker that uses the AWS-B probe's TLS / status-line parts: one approved IPv4 address:443 opened by the OS
rules, peer compared with it, no redirect following, no retry, certificate + hostname verification on, status line only (the body is never read, 16 KiB
cap), a hard deadline. No browser. Docker Desktop must already be running; it is never started for an HTTP check, and without it nothing is checked.

Separate from image monitoring on purpose: own settings (<site>/http-monitor.json), own interval (5 / 15 / 30 / 60 min), own locks, own history
(<site>/http-history.jsonl), own signed grant (<site>/http-grant.json + .sig). The image permit is NEVER a grant for HTTP checks (different schema,
different fields) and stopping one channel never starts the other. Everything is OFF by default.

External communication is OFF twice over: (1) the grant must verify, bind this site / host / path / period / ownership evidence, and have a request
left in its ledger (src/noxiworks/http_authority.py; counted for manual checks too), and (2) HTTP_EXTERNAL_ENABLED must be True in the source -- it
is False until the boundary has been measured and the USER has approved it. The isolated run decides both again for itself, right before its window. With a
probe injected (tests, rehearsals) no network is touched and no request is counted. The container boundary is NOT MEASURED for HTTP yet (docs/HTTP_BOUNDARY.md).

One check at a time per site, whoever starts it (app, Windows task, manual): an OS lock on <site>/http-monitor.lock, with "is it still due / still
enabled" decided again while it is held. Settings change under their own lock, so a stop is never overwritten by a check that was running: what the
USER stopped never restarts by itself. Missed checks (PC off) are not made up for: one check when due, the gap stays visible as a gap.

States: OK 正常 / DOWN 障害 / UNKNOWN 判定不能 / NOT_MONITORED 未監視 / STALE 長期間未観測 / STOPPED 停止中. The last result is never shown as the current
state once it is older than two intervals; a stopped monitor shows its last observation only as "before it was stopped". Only observations made
by this module (source LOCAL) are shown here; AWS-B archive data stays in its own view.
"""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import ssl

from src.aws_b.model import format_utc, parse_utc
from src.noxiworks import filelock, http_authority, notifications, retention, sites
from src.noxiworks.http_authority import GRANT_SCHEMA  # noqa: F401 (the one schema a grant may have)

HTTP_EXTERNAL_ENABLED = False  # the kill switch: no real request leaves this PC until it is turned on, deliberately, after the boundary is measured
SCHEMA = 'siteproof.http-monitor.v1'
INTERVALS = {300: '5分ごと', 900: '15分ごと', 1800: '30分ごと', 3600: '1時間ごと'}
DEFAULT_INTERVAL = 900
STALE_INTERVALS = 2
CHECK_LOCK_WAIT, SETTINGS_LOCK_WAIT = 0.5, 10.0
STATE_LABELS = {'OK': '正常', 'DOWN': '障害', 'UNKNOWN': '判定不能', 'NOT_MONITORED': '未監視', 'STALE': '長期間未観測', 'STOPPED': '停止中'}
OUTCOME_STATE = {'PASS': 'OK', 'FAIL': 'DOWN', 'UNKNOWN': 'UNKNOWN'}
EVENT_LABELS = {'DOWN': '障害を検知', 'RECOVERED': '復旧', 'UNKNOWN': '判定不能', 'OK': '正常を確認'}
DISABLED_TEXT = 'HTTP監視の外部通信は、実サイトでの試験とUSERの承認が済むまで無効です'
HISTORY_FULL_TEXT = 'HTTP監視の履歴が保存の上限に達しました。「履歴を整理」で古い履歴を別ファイルへ移してから開始してください（削除はしません）'
HISTORY_READ = 1000
NOT_RUN_CODES, NOT_RUN_RETRY = ('ENGINE_UNAVAILABLE', 'IMAGE_UNAVAILABLE', 'BUSY', 'SETUP_FAILED'), 300
HISTORY_RESERVE = 64 * 1024  # stop before the limit, so that the result of a request that was made can always be written
_GRANT_CACHE = {}


class Busy(Exception):
    pass


class ExternalDisabled(RuntimeError):
    pass


def default_settings():
    return {'schema': SCHEMA, 'enabled': False, 'ever_enabled': False, 'interval_seconds': DEFAULT_INTERVAL, 'next_due_at': None, 'last': None, 'paused_reason': None}


def live_probe(site_root, trigger, interval):
    """The real request, in an isolated container run. Refused here already while HTTP_EXTERNAL_ENABLED is False (and again in the run)."""
    if HTTP_EXTERNAL_ENABLED is not True:
        raise ExternalDisabled('HTTP監視の外部通信は無効です')
    from src.noxiworks import http_isolation
    return http_isolation.launch(site_root, trigger, interval)


REASON_LABELS = {
    'CONNECT_TIMEOUT': 'サイトが接続に応答しませんでした（時間切れ）', 'CONNECT_FAILED': 'サイトに接続できませんでした（接続の拒否・到達不能）',
    'HTTP_TIMEOUT': 'サイトの応答が時間内に届きませんでした', 'HTTP_IO_ERROR': '通信が途中で切れました', 'TLS_FAILED': 'TLS（証明書）の確認に失敗しました',
    'HTTP_INCOMPLETE': '応答が途中で終わりました', 'HTTP_MALFORMED': '応答の形式が正しくありません', 'HTTP_EXCHANGE_ERROR': '応答を読み取れませんでした',
    'HTTP_STATUS_INVALID': '応答のステータスが正しくありません', 'PROBE_RESULT_INVALID': '検査結果の形式が正しくありません',
    'ISOLATION_VIOLATION': '検査が許可された通信の範囲を外れようとしたため、結果を使わずに停止しました',
    'DESTINATION_FIRST_ADDRESS_NOT_IPV4': 'サイトのアドレスがIPv6だけのため検査できません（IPv4だけに対応）'}
REASON_PREFIXES = (('ISOLATION_SETUP_FAILED', '隔離環境を準備できなかったため、検査していません'), ('ISOLATION_INCOMPLETE', '隔離環境の処理が最後まで終わらなかったため、結果を使いません'),
                   ('PROBE_ERROR', '検査の処理でエラーが起きました'), ('DESTINATION_DNS', 'サイトの名前を解決できませんでした（DNS）'), ('DNS_', 'サイトの名前を解決できませんでした（DNS）'),
                   ('DESTINATION_', 'サイトのアドレスが検査できない種類です（内部・特殊なアドレス）'), ('PROXY_', '隔離環境の通信の中継が終わりませんでした'))


def reason_label(code):
    """The observation's reason code -> Japanese for the screen and the notices (the code itself stays the record). Unknown codes are shown as they are."""
    code = str(code or '')
    if code in REASON_LABELS:
        return REASON_LABELS[code]
    status = re.fullmatch(r'HTTP_(\d{3})(_UNRESOLVED)?', code)
    if status:
        n = int(status.group(1))
        return (f'転送の応答です（HTTP {n}・転送先は確認しません）' if status.group(2) else f'正常な応答（HTTP {n}）' if 200 <= n <= 299
                else f'エラーの応答（HTTP {n}）')
    return next((text for prefix, text in REASON_PREFIXES if code.startswith(prefix)), code)


def tls_expiry(value):
    """A certificate notAfter in OpenSSL text ("Jan  5 12:00:00 2027 GMT") or the app's UTC text -> datetime (UTC) or None."""
    if not isinstance(value, str):
        return None
    moment = parse_utc(value)
    if moment:
        return moment
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), timezone.utc)
    except (ValueError, OverflowError):
        return None


class HttpMonitor:
    def __init__(self, site, probe=None, grant=None, sink=None):
        """probe: injected (tests / rehearsals) callable (host, path, timeout), else live_probe. grant: injected callable (now, interval) -> list of
        problems, else the signed file."""
        self.site, self.root, self.info = site, Path(site.root), site.info
        self.probe, self._grant = probe, grant
        self.path = self.root / 'http-monitor.json'
        self.history_path = self.root / 'http-history.jsonl'
        self.store = retention.HttpHistory(self.history_path)  # append-only, bounded: FULL stops the monitor, nothing is ever dropped
        self.lock_path = self.root / 'http-monitor.lock'
        self.settings_lock = self.root / 'http-settings.lock'
        self.outbox = notifications.Outbox(self.root, sink)

    # ---- the target: derived from the registered site, never from a request
    def target(self):
        return http_authority.target(self.info)

    def target_problems(self):
        return http_authority.target_problems(self.info)

    # ---- settings (written atomically; every change under one lock between processes)
    def configured(self):
        return self.path.is_file()

    def load(self):
        if not self.path.is_file():
            return default_settings()
        s = json.loads(self.path.read_text('utf-8'))
        return {**default_settings(), **s}

    def save(self, settings):
        tmp = self.path.with_suffix('.json.tmp')
        tmp.write_text(json.dumps(settings, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        os.replace(tmp, self.path)

    def change(self, update):
        """load -> update(settings) -> save, never interleaved with another process. -> the saved settings."""
        try:
            with filelock.held(self.settings_lock, wait=SETTINGS_LOCK_WAIT):
                s = self.load()
                update(s)
                self.save(s)
                return s
        except filelock.LockBusy:
            raise Busy('settings are being changed') from None

    # ---- the independent grant (signed by the USER's key; verification only)
    def signed_grant(self, now, interval):
        """-> (grant or None, [(code, problem)]). For the screen and the start decision: verified at most once a minute per file state. The request
        itself never relies on this: http_authority.authorize verifies again, fresh, right before the window of the isolated run."""
        trust = http_authority.trust_file(self.root)
        stamp = tuple(f.stat().st_mtime_ns if f.is_file() else None
                      for f in (self.root / 'http-grant.json', self.root / 'http-grant.json.sig', trust,
                                sites.site_root_of(self.root) / 'real' / 'ownership-evidence.json', sites.site_root_of(self.root) / 'real' / 'ownership-revoked.json'))
        key = (str(self.root), stamp, interval, int(now.timestamp() // 60))
        if key not in _GRANT_CACHE:
            if len(_GRANT_CACHE) > 64:
                _GRANT_CACHE.clear()
            grant, why = http_authority.read_grant(self.root)
            _GRANT_CACHE[key] = ((None, [('GRANT_INVALID', why)]) if grant is None
                                 else (grant, http_authority.grant_problems(grant, self.info, self.root, now, interval)))
        grant, problems = _GRANT_CACHE[key]
        return grant, list(problems)

    def grant_problems(self, now, interval):
        if self._grant is not None:
            return list(self._grant(now, interval))
        grant, problems = self.signed_grant(now, interval)
        if grant is not None and not problems:
            used = http_authority.usage(self.root, grant)
            if used['used'] is None:
                return ['HTTP監視の回数の記録を読み取れません（trust/http-ledger）。安全のため通信しません']
            if used['remaining'] <= 0:
                return [f"許可された回数を使い切りました（{used['used']} / {grant['max_requests']}回）"]
        return [m for _, m in problems]

    def grant_view(self, now, interval):
        """What the screen shows about the grant; never an authorisation."""
        problems = self.grant_problems(now, interval)
        view = {'valid': not problems, 'problems': problems, 'state': 'VALID' if not problems else 'INVALID'}
        if self._grant is not None:
            return view
        grant, found = self.signed_grant(now, interval)
        if not isinstance(grant, dict) or grant.get('schema') != GRANT_SCHEMA:
            return view if (self.root / 'http-grant.json').is_file() or not problems else {**view, 'state': 'MISSING'}
        used = http_authority.usage(self.root, grant)
        until = parse_utc(grant['valid_until']) if isinstance(grant.get('valid_until'), str) else None
        if problems and 'GRANT_EXPIRED' in {c for c, _ in found}:
            view['state'] = 'EXPIRED'
        elif problems and not found and used['used'] is not None and used['remaining'] <= 0:
            view['state'] = 'EXHAUSTED'
        return {**view, 'purpose': grant.get('purpose'), 'valid_until': grant.get('valid_until'),
                'days_left': round((until - now).total_seconds() / 86400, 1) if until else None, 'max_requests': grant.get('max_requests'),
                'min_interval_seconds': grant.get('min_interval_seconds'), **used}

    def can_probe(self):
        return self.probe is not None or HTTP_EXTERNAL_ENABLED is True

    def start_block(self, now, interval=None):
        """Why monitoring cannot be started now, or None."""
        settings = self.load()
        interval = interval or settings['interval_seconds']
        problems = self.target_problems() + self.grant_problems(now, interval)
        if problems:
            return '／'.join(problems)
        if not self.can_probe():
            return DISABLED_TEXT
        if self.history_usage()['full']:
            return HISTORY_FULL_TEXT
        return None

    def history_usage(self):
        """Size against the limit (a stat, cheap enough for the screen)."""
        size = self.history_path.stat().st_size if self.history_path.is_file() else 0
        limit = retention.HISTORY_MAX_BYTES
        return {'bytes': size, 'limit_bytes': limit, 'warn': size >= limit * retention.WARN_RATIO, 'full': size >= limit - HISTORY_RESERVE}

    def archive_history(self, now, actor, confirmed):
        """The USER's explicit tidy-up: the whole history MOVES to history-archive/ (nothing is deleted); never while a check is running."""
        try:
            with filelock.held(self.lock_path, wait=CHECK_LOCK_WAIT):
                return self.store.archive(now, actor, confirmed)
        except filelock.LockBusy:
            raise Busy('another HTTP check is running') from None

    # ---- control (GUI)
    def start(self, now):
        block = self.start_block(now)
        if block:
            raise ValueError('HTTP監視を開始できません：' + block)
        return self.change(lambda s: s.update(enabled=True, ever_enabled=True, paused_reason=None, paused_detail=None, next_due_at=format_utc(now)))

    def stop(self, now):
        return self.change(lambda s: s.update(enabled=False, next_due_at=None, paused_reason='USER', paused_detail=None))

    def _pause(self, reason, detail):
        return self.change(lambda s: s.update(enabled=False, next_due_at=None, paused_reason=reason, paused_detail=str(detail)[:300]))

    def set_interval(self, seconds, now):
        if seconds not in INTERVALS:
            raise ValueError('HTTP監視の間隔は 5分・15分・30分・1時間 から選んでください')

        def update(s):
            s['interval_seconds'] = seconds
            last = parse_utc((s.get('last') or {}).get('at') or '')
            if s['enabled']:
                s['next_due_at'] = format_utc(max(now, last + timedelta(seconds=seconds)) if last else now)
        return self.change(update)

    # ---- one check, serialised by its own lock (never the image monitor's)
    def running(self):
        return filelock.is_held(self.lock_path)

    def is_due(self, now):
        if not self.configured():
            return False
        s = self.load()
        due = parse_utc(s.get('next_due_at') or '')
        return bool(s['enabled'] and due and now >= due)

    def run_if_due(self, now, clock=None):
        if not self.is_due(now):
            return None
        return self.run(now, 'SCHEDULE', clock, only_if_due=True)

    def check_now(self, now, clock=None):
        """The USER's manual check: the same grant, ledger and lock as a scheduled one. It neither starts nor stops monitoring."""
        block = self.start_block(now)
        if block:
            raise ValueError('HTTPの検査を実行できません：' + block)
        return self.run(now, 'MANUAL', clock)

    def run(self, now, trigger='MANUAL', clock=None, only_if_due=False):
        """One request, one observation. No retry. -> the observation, {'blocked': reason} when nothing may be requested (nothing is observed), or
        None when (only_if_due) another process has just made the check or the USER has stopped monitoring."""
        try:
            with filelock.held(self.lock_path, wait=CHECK_LOCK_WAIT):
                if only_if_due and not self.is_due(now):  # decided again while the lock is held
                    return None
                return self._run(now, trigger, clock)
        except filelock.LockBusy:
            raise Busy('another HTTP check is running') from None

    def _blocked(self, trigger, reason, detail, code=None):
        if trigger == 'SCHEDULE':  # the grant ended / is not valid / the boundary is not approved: stop, request nothing
            self._pause(reason, detail)
        return {'blocked': detail, 'code': code or reason}

    def _run(self, now, trigger, clock):
        s = self.load()
        block = self.start_block(now, s['interval_seconds'])
        if block:
            return self._blocked(trigger, 'HISTORY_FULL' if block == HISTORY_FULL_TEXT else 'BLOCKED', block)
        host, path = self.target()
        try:
            raw = self.probe(host, path, 8) if self.probe is not None else live_probe(self.root, trigger, s['interval_seconds'])
        except ExternalDisabled:
            return self._blocked(trigger, 'BLOCKED', 'HTTP監視の外部通信は無効です')
        except Exception as exc:  # a probe that raises is "not decided", never "up" and never retried
            raw = {'outcome': 'UNKNOWN', 'reason': 'PROBE_ERROR:' + type(exc).__name__}
        if isinstance(raw, dict) and raw.get('refused'):  # decided in the isolated run: nothing was requested
            return self._refused(raw, now, trigger, s['interval_seconds'])
        finished = (clock or (lambda: now))()
        obs = self._observation(raw, now, finished, trigger, s['interval_seconds'])
        previous = self._previous_outcome()
        self.store.append(obs)
        started = parse_utc(raw['reserved_at']) if isinstance(raw, dict) and isinstance(raw.get('reserved_at'), str) else None

        def update(c):  # the GUI may have stopped / changed the interval meanwhile
            c['last'], c['not_run'] = obs, None
            c['next_due_at'] = format_utc(max((started or now) + timedelta(seconds=c['interval_seconds']), finished)) if c['enabled'] else None
            if obs['reason'] == 'ISOLATION_VIOLATION':  # something tried to leave the boundary: stop until the USER has looked at it
                c.update(enabled=False, next_due_at=None, paused_reason='BOUNDARY', paused_detail='検査の処理が許可された通信の範囲を外れようとしたため、拒否して停止しました')
        self.change(update)
        try:
            notifications.http_events(self.outbox, previous, obs, target_id=self.info['page_id'], hostname=host, path=path)
        except Exception:  # a notification problem never loses the observation
            pass
        return obs

    def _refused(self, raw, now, trigger, interval):
        code, message = str(raw['refused'])[:40], str(raw.get('message') or '')[:300]
        if code in NOT_RUN_CODES:  # Docker is not there / busy: not a check and no reason to stop -- but it shows as not observed, never as "normal"
            self.change(lambda c: c.update(next_due_at=format_utc(now + timedelta(seconds=min(interval, NOT_RUN_RETRY))), not_run={'at': format_utc(now), 'code': code, 'message': message})
                        if c['enabled'] else c.update(not_run={'at': format_utc(now), 'code': code, 'message': message}))
            return {'blocked': message, 'code': code}
        if code == 'RATE_LIMITED':  # too soon is not a reason to stop: the next check waits until it is allowed
            later = parse_utc(raw['not_before']) if isinstance(raw.get('not_before'), str) else None
            later = max(later or now + timedelta(seconds=interval), now)

            def postpone(c):  # only ever later: a manual check pressed too early must not pull the scheduled one forward
                due = parse_utc(c.get('next_due_at') or '')
                c['next_due_at'] = format_utc(max(later, due) if due else later)
            self.change(lambda c: postpone(c) if c['enabled'] else None)
            return {'blocked': message, 'code': code}
        return self._blocked(trigger, code if code in ('GRANT_EXPIRED', 'GRANT_EXHAUSTED') else 'BLOCKED', message, code)

    @staticmethod
    def _observation(raw, started, finished, trigger, interval):
        raw = raw if isinstance(raw, dict) else {}
        outcome = raw.get('outcome') if raw.get('outcome') in OUTCOME_STATE else 'UNKNOWN'
        reason = raw.get('reason') if outcome == raw.get('outcome') else 'PROBE_RESULT_INVALID'
        expiry = tls_expiry(raw.get('tls_not_after'))
        status = raw.get('http_status')
        elapsed = raw.get('elapsed_ms')
        return {'at': format_utc(finished), 'started_at': format_utc(started), 'trigger': trigger, 'source': 'LOCAL', 'outcome': outcome, 'state': OUTCOME_STATE[outcome],
                'reason': str(reason or '')[:80], 'http_status': status if type(status) is int and 100 <= status <= 599 else None,
                'elapsed_ms': elapsed if type(elapsed) is int and elapsed >= 0 else None, 'selected_ip': raw.get('selected_ip') if isinstance(raw.get('selected_ip'), str) else None,
                'tls_not_after': format_utc(expiry) if expiry else None, 'tls_days_left': (expiry - finished).days if expiry else None,
                'interval_seconds': interval, 'grant_id': raw.get('grant_id') if isinstance(raw.get('grant_id'), str) else None}

    # ---- history and views (read-only)
    def history(self, limit=HISTORY_READ):
        return [o for o in self.store.tail(limit) if o.get('outcome') in OUTCOME_STATE and isinstance(o.get('at'), str)]

    def _previous_outcome(self):
        """From the settings, not from the history file: tidying the history away never announces an old failure again."""
        return (self.load().get('last') or {}).get('outcome')

    def events(self, limit=20):
        """State changes from the saved observations: 障害 / 復旧 / 判定不能 (the same result repeated is no new event). Newest first."""
        events, prev = [], None
        for o in self.history():
            kind = None
            if prev is None:
                kind = {'FAIL': 'DOWN', 'UNKNOWN': 'UNKNOWN', 'PASS': 'OK'}[o['outcome']]
            elif o['outcome'] != prev:
                kind = {'FAIL': 'DOWN', 'UNKNOWN': 'UNKNOWN', 'PASS': 'RECOVERED' if prev == 'FAIL' else 'OK'}[o['outcome']]
            if kind:
                events.append({'at': o['at'], 'type': kind, 'label': EVENT_LABELS[kind], 'reason': o['reason'], 'reason_label': reason_label(o['reason']), 'http_status': o['http_status']})
            prev = o['outcome']
        return list(reversed(events))[:limit]

    def gaps(self, now, s, limit=10):
        """Periods longer than two intervals without any observation (PC off, stopped, held up), newest first. Missed checks are never made up for."""
        found = retention.observation_gaps(self.history(), now, s['interval_seconds'])
        if not s['enabled']:
            found = [g for g in found if not g['open']]  # a stopped monitor is shown as stopped
        return list(reversed(found))[:limit]

    def status(self, now):
        """The view the screens show. Never "正常" from an old result: STALE after two intervals, STOPPED / NOT_MONITORED without a running monitor."""
        s = self.load()
        interval = s['interval_seconds']
        last = s.get('last')
        last_at = parse_utc((last or {}).get('at') or '')
        if not s['enabled']:
            state = 'STOPPED' if s['ever_enabled'] else 'NOT_MONITORED'
        elif last is None:
            state = 'NOT_MONITORED'  # started, nothing observed yet
        elif last_at is None or now - last_at > timedelta(seconds=interval * STALE_INTERVALS):
            state = 'STALE'
        else:
            state = last['state']
        expiry = tls_expiry((last or {}).get('tls_not_after'))
        days = (expiry - now).days if expiry else None
        level = notifications.tls_level(days)
        block = self.start_block(now, interval) if not s['enabled'] else None
        grant = self.grant_view(now, interval)
        return {'configured': self.configured(), 'enabled': s['enabled'], 'state': state, 'state_label': STATE_LABELS[state], 'interval_seconds': interval,
                'interval_label': INTERVALS.get(interval), 'intervals': INTERVALS, 'next_due_at': s['next_due_at'] if s['enabled'] else None,
                'last': {**last, 'reason_label': reason_label(last.get('reason'))} if last else last, 'last_at': (last or {}).get('at'), 'last_is_current': state in ('OK', 'DOWN', 'UNKNOWN'),
                'http_status': (last or {}).get('http_status'), 'elapsed_ms': (last or {}).get('elapsed_ms'),
                'tls': {'not_after': format_utc(expiry) if expiry else None, 'days_left': days, 'level': level[0] if level else ('OK' if days is not None else 'UNKNOWN'),
                        'label': level[1] if level else None},
                'paused_reason': s.get('paused_reason'), 'paused_detail': s.get('paused_detail'), 'external_enabled': self.can_probe(), 'grant': grant,
                'stop_text': retention.stop_reason_text(s, 'HTTP'), 'history_usage': self.history_usage(), 'notification_usage': retention.notification_usage(self.root),
                'grant_notice': retention.expiry_notice(grant.get('valid_until'), grant.get('remaining'), now, 'http_grant', grant.get('max_requests')) if grant.get('valid_until') else None,
                'days_unobserved': retention.days_unobserved((last or {}).get('at'), now), 'gaps': self.gaps(now, s),
                'not_run': s.get('not_run'), 'boundary': {'mode': 'DOCKER_NETNS', 'measured': False, 'fixture_measured': True},  # 18/18 on the fixture network (.local/http-iso-run-04); a real site: not yet
                'can_start': block is None if not s['enabled'] else False, 'start_block': block, 'source': 'LOCAL（このPCの観測）',
                'events': self.events(), 'notifications': self.outbox.recent(), 'running': self.running()}


def main(argv=None):
    """One pass for an OS scheduler or a rehearsal: check the HTTP of every page of every registered site that is due (or --site only). Never starts a
    browser; one broken page or site never stops the others."""
    import argparse
    from src.noxiworks.site_workflow import Site
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--site', help='one site id (default: every registered site)')
    args = parser.parse_args(argv)
    try:
        roots = [sites.resolve(args.data, args.site)] if args.site else sites.folders(args.data)
    except sites.SiteUnknown as exc:
        parser.error(str(exc))
    if not roots:
        print('no registered site')
    for root in [unit for root in roots for unit in sites.units(root)]:
        try:
            obs = HttpMonitor(Site(root)).run_if_due(datetime.now(timezone.utc).replace(microsecond=0))
            text = 'not due' if obs is None else obs.get('blocked') and 'blocked: ' + obs['blocked'] or f"{obs['state']} {obs['reason']}"
        except Busy:
            text = 'busy'
        except Exception as exc:  # one site never takes the others down
            text = 'error: ' + type(exc).__name__
        print(root.name, text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
