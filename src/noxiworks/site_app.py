"""One registered site inside the local app: its pages, its monitors, its settings and its actions (src/noxiworks/app.py holds one per site).

Everything a SiteApp reads or writes lies in its own folder <data>/sites/<site id>/ (plus the shared, read-only trust file of the USER): settings,
permits, grants, Baselines, runs, history and notifications of two sites never meet. Pages are generated with SITEPROOF_TARGETS / SITEPROOF_CAPTURE_PLAN
pointing at the site's own files, so a page shows one site only. An action reaches a SiteApp only when the request named its site id (or it is
the only site). What several sites share is serialised by the app: page generation and inspections run one at a time.
A further page of a site is a SiteApp of its own (`parent` = the first page's SiteApp, `pages` on the parent) over its own unit folder <site>/pages/<page id>:
the same code, the same files, nothing shared but what the site's folder holds for the whole host (ownership evidence, e-mail switch).
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import time

from src.noxiworks import sites
from src.noxiworks.http_monitor import STATE_LABELS
from src.noxiworks.uiview import explain_failure, monitor_view

ROOT = Path(__file__).resolve().parents[2]
RENEW_WARNING_DAYS, RENEW_WARNING_RUNS = 7, 5  # HOME suggests "監視設定を更新" from here on
OVERVIEW_SECONDS = 5


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


class SiteApp:
    def __init__(self, app, site, parent=None):
        self.app, self.site, self.parent = app, site, parent  # parent: the SiteApp of the site's first page, for a further page
        self.pages = {}  # page id -> SiteApp of a further page (the first page is this one)
        self.ui = self.shown = self.rendered = self.archive = self.error = None
        self.http_error = self.http_thread = self.notify_error = None
        self._disk, self._background, self._overview = None, {}, None

    @property
    def site_id(self):
        return self.site.info['site_id']

    @property
    def unit(self):
        """The folder name of this page: the site id for the first page, else the page id."""
        return self.site.root.name

    def units(self):
        """Every page of the site, the first one first (a further page lists itself and its siblings through its parent)."""
        first = self.parent or self
        return [first, *first.pages.values()]

    # ---- pages
    def rebuild(self):
        """The site's pages: the unchanged CLI pointed at the site's own targets / capture plan (only that site is shown)."""
        from src.aws_b.model import format_utc
        from src.noxiworks.monitoring import SCHEDULE_SCHEMA
        site = self.site
        env = {'SITEPROOF_TARGETS': str(site.root / 'targets.json'), 'SITEPROOF_CAPTURE_PLAN': str(site.root / 'capture_plan.json')}
        display = self.display_targets(site)
        if display:
            env['SITEPROOF_DISPLAY_TARGETS'] = str(display)
        try:
            # The pages' own schedule view (監視の状態) gets the monitor's real state: its interval and a provider record for the image
            # channel. HTTP is not monitored by the app, so it stays "Provider管理・未確認".
            settings = self.monitor().load() if (site.root / 'monitor.json').is_file() else None
            if settings:
                targets = json.loads((site.root / 'targets.json').read_text('utf-8'))
                targets['capture_interval_seconds'] = self.app.interval_override or settings['interval_seconds']
                (site.root / 'targets.json').write_text(json.dumps(targets, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
                last = settings['last'] or {}
                record = [{'schema': SCHEDULE_SCHEMA, 'target_id': site.page_id, 'channel': 'capture', 'enabled': settings['enabled'],
                           'last_finished_at': last.get('finished_at'), 'last_outcome': ('FAILED' if last.get('outcome') == 'FAILED' else 'COMPLETED') if last else None,
                           'next_due_at': settings['next_due_at'] if settings['enabled'] else None, 'observed_at': format_utc(utc_now()),
                           'source': 'SiteProofアプリの自動監視（このPC）'}]
                (site.root / 'schedule.json').write_text(json.dumps(record, ensure_ascii=False) + '\n', encoding='utf-8')
            real = site.mode() == 'REAL'  # real captures are shown alone; the offline fixture runs stay on disk, unshown
            runs = site.real_runs() if real else site.runs()
            self.rendered = (settings['enabled'], settings['interval_seconds']) if settings else None
            self.archive = self.archive_signature()
            self.ui = self.app.generate(site.root / 'ui', runs, site.real_registry() if real else site.registry(), env,
                                        schedule=site.root / 'schedule.json' if settings else None,
                                        archive=site.root / 'aws-archive' if self.archive else None,
                                        older=site.baseline_history_dirs() if real else ())
            self.shown = [r.name for r in runs]
            self.error = None
        except RuntimeError as exc:  # keep serving the last good pages; the panel shows why
            self.error = str(exc)
            if self.ui is None:
                raise
        return self.ui

    @staticmethod
    def display_targets(site):
        """The AWS-B pages of the site's imported archive that are NOT the registered site's pages, as a DISPLAY-ONLY targets file next to (never inside)
        the signed targets.json. Derived each time from the archive's own list and the repo's known pages; None when there is nothing to add."""
        manifest = site.root / 'aws-archive' / 'public' / 'MANIFEST.json'
        try:
            archived = set(json.loads(manifest.read_text('utf-8')).get('targets', {}))
            known = json.loads((site.root / 'targets.json').read_text('utf-8'))
            have = {p['target_id'] for p in known['pages']}
            repo = json.loads((ROOT / 'src' / 'noxiworks' / 'targets.json').read_text('utf-8'))
        except (OSError, ValueError, KeyError):
            return None
        pages = [p for p in repo['pages'] if p['target_id'] in archived and p['target_id'] not in have]
        if not pages:
            return None
        sites = [s for s in repo['sites'] if s['site_id'] in {p['site_id'] for p in pages}]
        out = site.root / 'aws-display-targets.json'
        out.write_text(json.dumps({**{k: v for k, v in repo.items() if k not in ('pages', 'sites')}, 'sites': sites, 'pages': pages}, ensure_ascii=False, indent=2) + chr(10), encoding='utf-8')
        return out

    def archive_signature(self):
        """Changes whenever the user imports AWS-B results into <site>/aws-archive (None = nothing imported)."""
        root = self.site.root / 'aws-archive'
        manifest = root / 'public' / 'MANIFEST.json'
        return (root / 'managed.json').is_file() and manifest.is_file() and manifest.stat().st_mtime_ns or None

    # ---- image monitoring (site_monitor). The GUI only pauses / resumes, confirms, approves.
    def monitor(self):
        from src.noxiworks.site_monitor import Monitor
        app = self.app
        return Monitor(self.site, docker_found=app.docker_found, real_runner=app.real_runner, fixture_capture=app.fixture_capture)

    def disk(self, monitor):
        """Disk usage of the site folder, rescanned at most every 30 s (HOME polls every few seconds)."""
        if self._disk is None or time.monotonic() - self._disk[0] > 30:
            self._disk = (time.monotonic(), monitor.disk())
        return self._disk[1]

    def settings_action(self, action, body):
        """Settings and the confirmation record only: allowed while an inspection runs (no page regeneration needed)."""
        from src.noxiworks.site_workflow import FIXTURES as SITE_FIXTURES
        if action == 'confirm':
            return self.site.confirm_baseline(utc_now())
        changes = {k: body[k] for k in ('enabled', 'interval_seconds', 'offline_fixture') if k in body}
        if 'offline_fixture' in changes and changes['offline_fixture'] not in SITE_FIXTURES:
            raise ValueError('不明な撮影画像です')
        if changes.get('enabled') is True and not self.monitor().load()['enabled']:
            monitor = self.monitor()
            view = self.monitor_view(monitor, monitor.load(), monitor.real().readiness(utc_now()), self.permit_info(monitor.real(), utc_now()), self.setup_status())
            if not view['can_start']:  # the same answer the screen used to disable the button: the server does not rely on the browser
                raise ValueError('監視を開始できません：' + (view['start_block'] or view['reason']))
        return self.monitor().update(utc_now(), self.app.interval_override, **changes)

    def baseline_action(self, action, body, now):
        """The USER's explicit decisions about the Baseline (never taken from a schedule or an inspection). The caller holds the app lock."""
        from src.noxiworks.site_monitor import Busy
        from src.noxiworks.site_workflow import ACTOR
        if action == 'baseline-update':  # "新しい基準にする"
            versions = body.get('expected_versions')
            if (body.get('confirmed') is not True or not isinstance(body.get('run_id'), str) or not isinstance(versions, dict)
                    or not all(type(v) is int for v in versions.values())):
                raise ValueError('新しい基準にする操作の内容が正しくありません')
            try:
                done = self.monitor().update_baseline(body['run_id'], versions, now, ACTOR)
            except Busy as exc:
                raise ValueError(str(exc)) from None
            return {'versions': {b['kind']: b['version'] for b in done['baselines']}, 'recovered': done.get('recovered') is True}
        expected = body.get('expected')  # formal approval of the current Baseline
        if (body.get('confirmed') is not True or not isinstance(expected, dict) or not expected
                or not all(isinstance(v, dict) for v in expected.values())):
            raise ValueError('正式承認の操作の内容が正しくありません')
        try:
            self.monitor().approve_baseline(expected, now, ACTOR)
        except Busy as exc:
            raise ValueError(str(exc)) from None
        return {'state': self.site.baseline_state()['state']}

    def inspect_now(self, now):
        """Auxiliary: inspect now, outside the schedule. The caller holds the app lock."""
        from src.noxiworks.site_monitor import Busy
        try:
            return self.monitor().run(now, 'MANUAL', self.app.interval_override, utc_now)
        except Busy:
            raise BlockingIOError('busy') from None

    def tick(self):
        """Show inspections a background worker saved, and run the next inspection when it is due. The caller holds the app lock."""
        from src.noxiworks.site_monitor import Busy
        entry = None
        try:
            entry = self.monitor().run_if_due(utc_now(), self.app.interval_override, utc_now)
        except Busy:
            pass  # the OS-scheduled worker is inspecting right now (this site, or another one for real)
        shown = [r.name for r in (self.site.real_runs() if self.site.mode() == 'REAL' else self.site.runs())]
        settings = self.monitor().load()
        if (entry is not None or shown != self.shown or (settings['enabled'], settings['interval_seconds']) != self.rendered
                or self.archive_signature() != self.archive):
            self.rebuild()
        return entry

    def next_due(self):
        try:
            return self.monitor().load().get('next_due_at') or '9'
        except (OSError, ValueError):
            return '9'

    # ---- HTTP (死活) monitoring: its own settings / grant / interval, apart from the image monitor (src/noxiworks/http_monitor.py)
    def http_monitor(self):
        from src.noxiworks.http_monitor import HttpMonitor
        return HttpMonitor(self.site, probe=self.app.http_probe)

    def http_action(self, body):
        """start / stop / interval / one manual check. Refused (with the reason) without a valid signed grant or while external communication is off."""
        from src.noxiworks.http_monitor import Busy
        monitor, now = self.http_monitor(), utc_now()
        what = body.get('what')
        try:
            if what == 'start':
                monitor.start(now)
            elif what == 'stop':
                monitor.stop(now)
            elif what == 'interval':
                monitor.set_interval(body.get('interval_seconds'), now)
            elif what == 'check':
                done = monitor.check_now(now, utc_now)
                if done.get('blocked'):
                    raise ValueError('HTTPの検査を実行しませんでした：' + done['blocked'])
            else:
                raise ValueError('unknown http action')
        except Busy:
            raise BlockingIOError('busy') from None
        return {'state': monitor.status(utc_now())['state']}

    def http_tick(self):
        """One scheduled HTTP check when due; never raises (the panel shows the error)."""
        from src.noxiworks.http_monitor import Busy
        try:
            if (self.site.root / 'http-monitor.json').is_file():
                self.http_monitor().run_if_due(utc_now(), utc_now)
        except Busy:
            pass
        except Exception as exc:
            self.http_error = 'http: ' + type(exc).__name__ + ': ' + str(exc)[:200]

    def http_status(self):
        try:
            return self.http_monitor().status(utc_now())
        except Exception as exc:  # the panel shows the error; the rest of HOME keeps working
            return {'error': type(exc).__name__ + ': ' + str(exc)[:200]}

    # ---- e-mail (notify_dispatch): its own grant, switches and ledger, apart from what may be monitored
    def dispatcher(self):
        from src.noxiworks.notify_dispatch import Dispatcher
        return Dispatcher(self.site, provider=self.app.notify_provider)

    def notify_action(self, body):
        """Switches and one explicit test message. Turning anything on is refused without a valid signed notify grant or while sending is off."""
        from src.noxiworks.filelock import LockBusy
        d, now, what, on = self.dispatcher(), utc_now(), body.get('what'), body.get('enabled')
        try:
            if what in ('channel', 'site'):
                if type(on) is not bool:
                    raise ValueError('通知の設定の内容が正しくありません')
                (d.set_channel if what == 'channel' else d.set_site)(on, now)
            elif what == 'kinds':
                d.set_kinds(body.get('kinds'), now)
            elif what == 'test':
                done = d.send_test(now, 'ローカル利用者（SiteProofアプリの画面）')
                if not done['ok']:
                    raise ValueError('テスト通知：' + done['label'] + '（' + str(done['reason']) + '）')
                return {'label': done['label']}
            else:
                raise ValueError('unknown notify action')
        except LockBusy:
            raise BlockingIOError('busy') from None
        return {'enabled': d.channel()['enabled'], 'site_enabled': d.site_config()['enabled']}

    def notify_tick(self):
        """Send what is pending for this site, if e-mail is on; never raises."""
        try:
            self.dispatcher().run(utc_now())
            self.notify_error = None
        except Exception as exc:
            self.notify_error = 'notify: ' + type(exc).__name__

    def notify_status(self):
        try:
            return self.dispatcher().status(utc_now())
        except Exception as exc:
            return {'error': type(exc).__name__ + ': ' + str(exc)[:200]}

    # ---- long-term operation: the USER's explicit tidy-up (moves, never deletes)
    def maintenance_action(self, body):
        from src.noxiworks import retention
        from src.noxiworks.filelock import LockBusy
        from src.noxiworks.http_monitor import Busy
        what, now, actor = body.get('what'), utc_now(), 'ローカル利用者（SiteProofアプリの画面）'
        if body.get('confirmed') is not True:
            raise ValueError('整理の内容を確認してから実行してください')
        try:
            if what == 'archive-http':
                done = self.http_monitor().archive_history(now, actor, True)
            elif what == 'archive-notifications':
                done = retention.archive_notifications(self.site.root, now, actor, True)
            else:
                raise ValueError('unknown maintenance action')
        except (Busy, LockBusy):
            raise BlockingIOError('busy') from None
        self._overview = self._disk = None
        return done

    # ---- first-time setup, delegated (the app holds no key and never signs)
    def setup_step(self, body):
        """One GUI button of the setup. Each starts an existing tool as a separate process, for THIS site only, and returns at once:
          setup            tools/setup_monitoring.py in its OWN console window: the USER sees the permit, confirms it there and signs with
                           their own key (ssh-keygen asks for the passphrase there). The app passes no key, no answer and no --yes.
          http-grant       tools/http_grant.py in its own console window (the HTTP grant of this page; the same rule: the USER signs there)
          dns-issue        issues the DNS TXT challenge in-process (a file in the site folder; no DNS question is asked)
          dns-check        tools/dns_ownership.py check in its own console window (a DNS query of its own, started by the USER, off until approved)
          docker           Docker Desktop (`docker desktop start`)
          background       tools/background_monitor.py install (a Windows task for this site's image monitoring)
          background-http  the same for this site's HTTP monitoring (no Docker, no browser)
        The result shows up in the readiness checks once the tool has finished."""
        step, launcher = body.get('step'), self.app.launcher
        if self.parent is not None and isinstance(step, str) and (step in ('setup', 'dns-issue', 'dns-check', 'docker') or step.startswith('background')):
            if step == 'setup':  # what is about the whole site (ownership, Docker, Windows tasks) is done on the site; the image permit is the first page's
                raise ValueError('画像撮影の許可は、サイトの最初のページ（トップページ）の設定です。このページでは設定できません')
            return self.parent.setup_step(body)
        host = self.site.info['url'].split('/')[2]
        workers_dev = re.fullmatch(r'[a-z0-9-]+\.[a-z0-9-]+\.workers\.dev', host) is not None
        where = ['--data', str(self.app.data.resolve()), '--site', self.site_id]
        evidence = (self.site.root / 'real' / 'ownership-evidence.json').is_file()
        if step == 'dns-issue':  # the challenge is made here (a file in this site's folder); nothing is asked of DNS
            from src.noxiworks import domain_ownership
            try:
                c = domain_ownership.issue(self.site.root, utc_now())
            except domain_ownership.OwnershipRefused as exc:
                raise ValueError(str(exc)) from None
            return {'record_name': c['record_name'], 'record_value': c['record_value'], 'expires_at': c['expires_at'],
                    'note': 'DNSにこのTXTレコードを登録してください。登録しただけでは確認済みになりません。'}
        if step == 'dns-check':  # the USER's own DNS question, in its own window; it is off until approved (tools/dns_ownership.py says so there)
            from tools import dns_ownership
            try:
                launcher([sys.executable, '-B', 'tools/dns_ownership.py', 'check', *where, '--pause'], console=True)
            except OSError:
                raise ValueError('確認の画面を開けませんでした') from None
            return {'launched': 'dns-check', 'enabled': dns_ownership.OWNERSHIP_DNS_ENABLED,
                    'note': ('別のウィンドウで、DNSのTXTレコードを照会して確認します（監視とは別の1回限りの通信です）。' if dns_ownership.OWNERSHIP_DNS_ENABLED
                             else '別のウィンドウが開きますが、DNSの照会は承認されるまで無効です。何も問い合わせません。')}
        if step == 'setup':  # first setup and renewal ("監視設定を更新") are the same tool
            from src.noxiworks import domain_ownership
            dns_ok = domain_ownership.state(self.site.root, utc_now())
            dns_ok = dns_ok['method'] == 'DNS_TXT_CHALLENGE' and dns_ok['status'] == 'VERIFIED'
            ownership = body.get('ownership') or ('cloudflare' if workers_dev else 'dns' if dns_ok else None)
            if ownership == 'reuse' and not evidence:
                raise ValueError('再利用できる所有権の確認記録がありません。確認方法を選んでください')
            from src.noxiworks.real_capture import UNSUPPORTED_OWNERSHIP, UNSUPPORTED_OWNERSHIP_MESSAGE
            if ownership in UNSUPPORTED_OWNERSHIP:  # refused before any window opens: such a permit could never capture
                raise ValueError(UNSUPPORTED_OWNERSHIP_MESSAGE)
            if ownership == 'dns' and not dns_ok:
                raise ValueError('有効なDNSの所有権確認の記録がありません。先に「DNSで所有権を確認」を行ってください')
            if ownership not in ('reuse', 'cloudflare', 'dns') or (ownership == 'cloudflare' and not workers_dev):
                raise ValueError('このサイトで使える所有権の確認記録はまだありません。DNSのTXTレコードで所有権を確認するか（どのサイトでも可）、'
                                 'workers.devのサイトではCloudflareアカウント確認を選んでください')
            args = [sys.executable, '-B', 'tools/setup_monitoring.py', *where, '--pause']
            if ownership != 'reuse':  # reuse: the tool takes the evidence that is already there (it re-checks it)
                args += ['--ownership', ownership]
            self.write_setup_status('LAUNCHED', 'セットアップの画面を開きました')
            try:
                launcher(args, console=True)
            except OSError as exc:
                self.write_setup_status('FAILED', 'セットアップの画面を開けませんでした：' + str(exc)[:200])
                raise ValueError('セットアップの画面を開けませんでした') from None
            return {'launched': 'setup', 'ownership': ownership,
                    'note': '別のウィンドウで、許可の内容を確認して署名してください。完了すると、この画面の準備が自動で更新されます。'}
        if step == 'http-grant':
            if not (sites.site_root_of(self.site.root) / 'real' / 'ownership-evidence.json').is_file():  # the evidence is the site's, also for a page
                raise ValueError('先に所有権の確認（DNSのTXTレコード、またはworkers.devのCloudflare確認）を済ませてください')
            try:
                launcher([sys.executable, '-B', 'tools/http_grant.py', *where, *(['--page', self.unit] if self.parent is not None else []), '--pause'], console=True)
            except OSError:
                raise ValueError('署名の画面を開けませんでした') from None
            return {'launched': 'http-grant', 'note': '別のウィンドウで、HTTP監視の許可の内容を確認して署名してください。署名しても監視は始まりません。'}
        if step == 'docker':
            launcher(['docker', 'desktop', 'start'], console=False)
            return {'launched': 'docker', 'note': 'Docker Desktopを起動しています（1〜2分かかることがあります）。'}
        channel = {'background': 'image', 'background-remove': 'image', 'background-http': 'http', 'background-http-remove': 'http'}.get(step)
        if channel:
            remove = step.endswith('-remove')
            launcher([sys.executable, '-B', 'tools/background_monitor.py', 'remove' if remove else 'install', *where, '--channel', channel], console=False)
            self._background = {}  # ask again on the next screen update
            what = '画像監視' if channel == 'image' else 'HTTP監視'
            return {'launched': step, 'note': f'アプリを閉じている間の{what}を解除しました（アプリを開いている間は、これまでどおり監視します）。' if remove
                    else f'アプリを閉じても{what}を続けるタスクを登録しました（{"15" if channel == "image" else "5"}分ごとに確認）。'}
        raise ValueError('unknown setup step')

    def write_setup_status(self, state, message):
        from src.aws_b.model import format_utc
        (self.site.root / 'setup-status.json').write_text(json.dumps({'state': state, 'message': message, 'at': format_utc(utc_now())},
                                                                     ensure_ascii=False) + '\n', encoding='utf-8')

    def setup_status(self):
        """What the setup window last reported (LAUNCHED / RUNNING / DONE / NOT_READY / FAILED), or None."""
        f = self.site.root / 'setup-status.json'
        try:
            value = json.loads(f.read_text('utf-8'))
        except (OSError, ValueError):
            return None
        return {k: str(value.get(k) or '')[:300] for k in ('state', 'message', 'at')} if isinstance(value, dict) else None

    def background_state(self, channel='image'):
        """True / False / None (unknown), asked at most once a minute (the screen polls every few seconds)."""
        at, value = self._background.get(channel, (0.0, None))
        if time.monotonic() - at > 60 or at == 0.0:
            try:
                value = self.app.background_query(self.app.data, self.site_id, channel)
            except Exception:
                value = None
            self._background[channel] = (time.monotonic(), value)
        return value

    def permit_info(self, real, now):
        """The verified permit's period and runs, for the HOME summary and the renewal warning. None without a valid signature."""
        from src.aws_b.model import parse_utc
        permit, _ = real.permit()
        if not permit:
            return None
        until = parse_utc(permit.get('valid_until') or '')
        remaining = max(0, int(permit.get('max_runs') or 0) - real.used(permit)) if type(permit.get('max_runs')) is int else 0
        days = (until - now).total_seconds() / 86400 if until else None
        # `state` tells the reasons apart for display only; `expired` keeps its meaning (either reason) and every capture refusal is
        # decided elsewhere (permit.check_scope / the harness preflight), never from this summary.
        state = 'EXPIRED' if days is None or days <= 0 else 'EXHAUSTED' if remaining == 0 else 'ACTIVE'
        return {'state': state, 'permit_id': permit.get('permit_id'), 'valid_until': permit.get('valid_until'), 'remaining_runs': remaining,
                'days_left': None if days is None else round(days, 1),
                'warning': days is not None and (days <= RENEW_WARNING_DAYS or remaining <= RENEW_WARNING_RUNS),
                'expired': days is None or days <= 0 or remaining == 0}

    # ---- what the screens show
    def status(self):
        from src.noxiworks import retention
        from src.noxiworks.site_monitor import INTERVALS, OUTCOME_LABELS
        from src.noxiworks.site_workflow import FIXTURES as SITE_FIXTURES
        app, site = self.app, self.site
        monitor = self.monitor()
        settings = monitor.load()
        real = monitor.real()
        readiness = real.readiness(utc_now())
        last = settings['last'] or {}
        # One headline state for HOME. A registered site that cannot be captured for real is "preparing" -- never shown as monitored.
        # OFFLINE_DEMO exists only for engine tests that turned synthetic captures on (fixture_capture).
        setup = self.setup_status()
        permit = self.permit_info(real, utc_now())
        if setup and setup['state'] in ('LAUNCHED', 'RUNNING'):
            display = 'SETUP_RUNNING'
        elif not settings['enabled']:
            display = 'PAUSED'
        elif last.get('outcome') == 'FAILED':
            display = 'FAILED'
        elif all(c['ok'] for c in readiness):
            display = 'REAL_MONITORING'
        elif app.fixture_capture and site.mode() != 'REAL':
            display = 'OFFLINE_DEMO'
        elif permit and permit['expired']:
            display = 'EXPIRED'  # set up once, the permit ran out (period or runs): "監視設定を更新"
        elif not (site.root / 'real' / 'permit.json').is_file():
            display = 'SETUP_NEEDED'
        else:
            display = 'REAL_PENDING'
        runs = site.runs() + site.real_runs()
        view = self.monitor_view(monitor, settings, readiness, permit, setup)
        http, notify = self.http_status(), self.notify_status()
        log = [{**entry, 'explained': explain_failure(entry.get('error')) if entry.get('outcome') == 'FAILED' else None} for entry in monitor.log(8)]
        return {**{k: site.info[k] for k in ('site_id', 'page_id', 'name', 'url', 'label', 'kinds', 'registered_at', 'owner', 'capture_mode')},
                'monitor': {'enabled': settings['enabled'], 'interval_seconds': app.interval_override or settings['interval_seconds'],
                            'interval_label': INTERVALS.get(settings['interval_seconds']), 'override': app.interval_override,
                            'next_due_at': settings['next_due_at'] if settings['enabled'] else None, 'last': settings['last'],
                            'running': monitor.running(), 'offline_fixture': settings['offline_fixture']},
                'baseline': site.baseline_state(), 'baseline_update': real.baseline_update_state(), 'baseline_history': site.baseline_history(),
                'monitor_view': view, 'runs': len(runs), 'log': log,
                'readiness': readiness, 'real_capture_available': all(c['ok'] for c in readiness), 'mode': site.mode(),
                'http': http, 'http_error': self.http_error, 'notify': notify, 'notify_error': self.notify_error, 'notice_history': self.notice_history(http, notify),
                'usage': retention.disk_usage(site.root), 'stop_text': retention.stop_reason_text({**settings, 'ever_enabled': True}, 'IMAGE'),
                'permit_notice': retention.expiry_notice(permit['valid_until'], permit['remaining_runs'], utc_now(), 'permit') if permit else None,
                'setup': setup, 'permit': permit, 'background': self.background_state(),
                'background_http': self.background_state('http'), 'ownership_evidence': (sites.site_root_of(site.root) / 'real' / 'ownership-evidence.json').is_file(),
                'unit': self.unit, 'unit_label': site.info['label'], 'pages': self.page_list(), 'max_pages': sites.MAX_PAGES,
                'ownership': self.ownership_state(),
                'display': display, 'permit_present': (site.root / 'real' / 'permit.json').is_file(), 'disk': self.disk(monitor),
                'paused_reason': settings.get('paused_reason'),
                'fixtures': SITE_FIXTURES, 'fixture_capture': app.fixture_capture, 'intervals': INTERVALS, 'outcomes': OUTCOME_LABELS,
                'error': self.error}

    @staticmethod
    def notice_history(http, notify, limit=30):
        """The last notices of this page for the screen (newest first): kind, severity and the delivery as ONE sentence made here, so the screen invents no wording.
        A hand-over to a sink or a mail server is never called a receipt; the e-mail part comes from the delivery log (the latest record of that notice)."""
        from src.noxiworks.notifications import KIND_LABELS
        mail = {}
        for entry in (notify or {}).get('recent') or []:  # newest first: the first record of a notice wins
            mail.setdefault(entry.get('notice_id'), entry)
        out = []
        for n in (http or {}).get('notifications') or []:
            sink = str((n.get('delivery') or {}).get('sink') or '')
            parts = ['画面に記録']
            if sink == 'SENT':
                parts.append('送信先へ引き渡し済み（受信は未確認）')
            elif sink.startswith('FAILED'):
                parts.append('送信先への引き渡しに失敗')
            if n.get('id') in mail and mail[n['id']].get('label'):
                parts.append('メール：' + str(mail[n['id']]['label']))
            out.append({'id': n.get('id'), 'kind': n.get('kind'), 'kind_label': KIND_LABELS.get(n.get('kind'), str(n.get('kind'))), 'severity': n.get('severity'), 'at': n.get('at'),
                        'title': n.get('title'), 'delivery_label': '・'.join(parts)})
        return out[:limit]

    def ownership_state(self):
        """The ownership of the site's host, for the screen (the site's own evidence, also on a further page), and whether the DNS check may be started at all."""
        from src.noxiworks import domain_ownership
        try:
            from tools import dns_ownership
            enabled = dns_ownership.OWNERSHIP_DNS_ENABLED is True
        except ImportError:
            enabled = False
        return {**domain_ownership.state(sites.site_root_of(self.site.root), utc_now()), 'dns_check_enabled': enabled}

    def monitor_view(self, monitor, settings, readiness, permit, setup):
        """The monitoring state HOME shows (src/noxiworks/uiview.py), and the one the server enforces when asked to start monitoring."""
        policy = settings.get('stop_policy')
        hold = monitor._hold(policy) if policy else None
        return monitor_view(enabled=settings['enabled'], running=monitor.running(), paused_reason=settings.get('paused_reason'), last=settings.get('last'),
                            readiness=readiness, permit=permit, setup=setup, hold=hold, fixture_engine=self.app.fixture_capture)

    def href(self):
        return f'/site/{self.site_id}/' if self.parent is None else f'/site/{self.site_id}/page/{self.unit}/'

    def page_list(self):
        """The pages of this unit's site, the first one first: what the page switcher shows."""
        return [{'unit': u.unit, 'label': u.site.info['label'], 'url': u.site.info['url'], 'href': u.href(), 'current': u is self} for u in self.units()]

    def stop_site(self, body):
        """Stop image AND HTTP monitoring of every page of this site (there is no start-all). One page that cannot be stopped never keeps the others running."""
        from src.noxiworks.http_monitor import Busy as HttpBusy
        from src.noxiworks.site_monitor import Busy
        if body.get('confirmed') is not True:
            raise ValueError('サイトの監視をすべて停止する操作の確認が必要です')
        now, stopped, failed = utc_now(), [], []
        for u in self.units():
            def image(u=u):
                if u.monitor().load()['enabled']:
                    u.monitor().update(now, self.app.interval_override, enabled=False)

            def http(u=u):
                m = u.http_monitor()
                if m.configured() and m.load()['enabled']:
                    m.stop(now)
            before = len(failed)
            for what, stop in (('画像監視', image), ('HTTP監視', http)):  # one channel that cannot be stopped never keeps the other running
                try:
                    stop()
                except (Busy, HttpBusy, OSError, ValueError, KeyError) as exc:
                    failed.append(f'{u.site.info["label"]}の{what}（{type(exc).__name__}）')
            if len(failed) == before:
                stopped.append(u.unit)
            u._overview = u._disk = None
        if failed:
            raise ValueError('停止できなかったページがあります：' + '、'.join(failed) + '。もう一度お試しください（停止できたページ：' + str(len(stopped)) + '）')
        return {'stopped': stopped}

    def overview(self):
        """One line of the all-sites list (HOME with several sites): the first page's line, plus `pages` (every page's line, the first included) and the
        site's `aggregate` (the worst state of its pages, never "正常" while a monitored page is down / undecided / stale or nothing is monitored)."""
        out = dict(self.unit_overview())
        if self.parent is None:
            lines = [out if u is self else u.unit_overview() for u in self.units()]
            out = {**out, 'pages': lines, 'aggregate': rollup(lines)}
        return out

    def unit_overview(self):
        """The line of this one page, cached briefly: the screen polls every few seconds."""
        if self._overview is not None and time.monotonic() - self._overview[0] < OVERVIEW_SECONDS:
            return self._overview[1]
        info = self.site.info
        out = {'site_id': self.site_id, 'name': info['name'], 'url': info['url'], 'label': info['label'], 'href': self.href(), 'unit': self.unit, 'unit_label': info['label']}
        try:
            s = self.status()
            http, view, last = s['http'], s['monitor_view'], s['monitor']['last'] or {}
            attention = []
            if view['kind'] == 'error' or view['state'] in ('WAIT_BASELINE', 'WAIT_CHANGE', 'WAIT_DECISION'):
                attention.append('画像監視：' + view['label'])
            if last.get('outcome') in ('CHANGED', 'UNKNOWN', 'FAILED') and view['kind'] != 'error':
                attention.append('画像監視：' + s['outcomes'][last['outcome']])
            if s['baseline']['state'] == 'AUTO' and view['state'] != 'WAIT_BASELINE':
                attention.append('自動作成のBaselineが未確認です')
            if s['permit'] and s['permit']['warning']:
                attention.append('撮影の許可の期限・回数を確認してください')
            if http.get('state') in ('DOWN', 'UNKNOWN', 'STALE'):
                attention.append('HTTP監視：' + http['state_label'])
            if http.get('paused_reason') not in (None, 'USER'):
                attention.append('HTTP監視が停止しました')
            if s['disk']['warn']:
                attention.append('保存容量が上限に近づいています')
            if http.get('grant_notice') and http['grant_notice']['level'] == 'error' and http.get('configured'):
                attention.append(http['grant_notice']['text'])
            if (http.get('history_usage') or {}).get('warn'):
                attention.append('HTTP監視の履歴が保存の上限に近づいています')
            out.update(image={'state': view['state'], 'label': view['label'], 'kind': view['kind'], 'enabled': s['monitor']['enabled'], 'can_start': view['can_start'],
                              'start_block': view['start_block'], 'last_at': last.get('finished_at'), 'outcome': OUTCOME(s, last), 'next_due_at': s['monitor']['next_due_at'],
                              'running': s['monitor']['running']},
                       http={k: http.get(k) for k in ('state', 'state_label', 'enabled', 'can_start', 'start_block', 'last_at', 'next_due_at', 'http_status', 'error', 'not_run')},
                       baseline=s['baseline']['state'], permit=s['permit'], http_grant=http.get('grant'), disk=s['disk'], runs=s['runs'], attention=attention, error=s['error'])
            parts = []
            if http.get('enabled'):
                parts.append({'OK': 'OK', 'DOWN': 'DOWN', 'STALE': 'STALE'}.get(http.get('state'), 'UNKNOWN'))  # started, nothing observed yet = undecided
            if s['monitor']['enabled'] and view['state'] in ('MONITORING', 'RUNNING'):
                parts.append('UNKNOWN' if view['kind'] == 'error' or last.get('outcome') in ('UNKNOWN', 'FAILED') else 'OK')
            stopped = not (s['monitor']['enabled'] or http.get('enabled'))
            state = next((x for x in WORST if x in parts), 'OK') if parts else 'STOPPED' if stopped else 'NOT_MONITORED'
            out.update(state=state, state_label=STATE_LABELS[state], stopped=stopped)
        except Exception as exc:  # one unreadable site never hides the others
            out['error'] = type(exc).__name__ + ': ' + str(exc)[:200]
        self._overview = (time.monotonic(), out)
        return out


WORST = ('DOWN', 'UNKNOWN', 'STALE', 'OK')


def rollup(lines):
    """The site's aggregate over its pages' lines. A page whose line could not be read counts as undecided; with nothing monitored the state is 未監視 / 停止中."""
    states = [line.get('state', 'UNKNOWN') for line in lines]
    bad = next((x for x in WORST[:3] if x in states), None)
    state = bad or ('OK' if 'OK' in states else 'STOPPED' if all(x == 'STOPPED' for x in states) else 'NOT_MONITORED')
    attention = [f"{line.get('unit_label') or line.get('label')}：{a}" for line in lines for a in (line.get('attention') or ())]
    attention += [f"{line.get('unit_label') or line.get('label')}：{line['error']}" for line in lines if line.get('error')]
    return {'state': state, 'state_label': STATE_LABELS[state], 'attention': attention, 'units': len(lines), 'stopped': sum(1 for line in lines if line.get('stopped'))}


def OUTCOME(s, last):
    return s['outcomes'].get(last.get('outcome')) if last else None
