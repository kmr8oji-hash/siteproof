"""SiteProof local app: the existing HOME / REVIEW / ACTIVITY pages plus the user's own site and the synthetic demo. No AWS, no real site.

The user's site (src/noxiworks/site_workflow.py): サイトを追加 -> capture (offline fixture) -> the user approves the Baseline ->
later captures are compared. Its pages are served at / and generated with SITEPROOF_TARGETS / SITEPROOF_CAPTURE_PLAN pointing at the
site's own files, so only that site is shown. The synthetic demo below is served at /demo/ only; / shows an empty dashboard until
a site is registered, and a site that cannot be captured for real is never monitored with generated images.

Run: py -3.15 -B -m src.noxiworks.app [--data DIR] [--port N] [--no-browser]

The pages are the static export of `python -m src.noxiworks` (unchanged design), regenerated from the app's own data folder
after every inspection and at every start, so saved history survives a restart. One action is added: POST /app/api/run runs
one inspection of an allowed SYNTHETIC fixture through the product pipeline (RuntimeService -> S1 save -> ComparisonService,
via tools/offline_capture_compare.run_case) against the app's synthetic, approved Baseline. The capture step is the offline
stand-in that hands back stored or edited Baseline bytes: no browser, no socket, nothing leaves the machine. Every page says
サンプルデータ（デモ）/ 合成デモ; real captures and AWS data are never mixed in (local_capture refuses that).

Data folder (default %LOCALAPPDATA%\\SiteProof or ~/.local/share/siteproof; never .local or a fixed drive):
  registry/   synthetic Baseline registry, created once (Desktop 1440 / Mobile 390, approved by a synthetic actor)
  runs/<id>/  one saved inspection each: <id>/ (S1 workspace + SQLite + run results + diff PNGs, export-sha256.json), result.json
  ui/<gen>/   generated pages; the newest is served
Security: 127.0.0.1 only; POST needs the exact Host/Origin, JSON, a custom header and a per-launch token that only a
same-origin page can read (no CORS headers are ever sent). One inspection at a time.
"""
import argparse
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import threading
import webbrowser

from src.noxiworks.uiview import explain_failure, monitor_view

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = {'unchanged': ('変更なし（Baselineと同じ画像）', 'NO_VISUAL_CHANGE_DETECTED'),
            'changed': ('変更あり（画面上部に赤い帯）', 'VISUAL_CHANGED'),
            'unstable': ('撮影が不安定（撮影ごとに画像が変わる）', 'UNKNOWN')}
TYPES = {'.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
         '.json': 'application/json', '.png': 'image/png'}
RUN_ID = re.compile(r'^\d{8}T\d{6}Z-\d{2}-(unchanged|changed|unstable)$')
KEEP_UI = 2
SITE_ROUTES = ('/app/api/site/register', '/app/api/site/inspect', '/app/api/site/monitor', '/app/api/site/confirm', '/app/api/site/setup',
               '/app/api/site/baseline-update', '/app/api/site/baseline-approve')


RENEW_WARNING_DAYS, RENEW_WARNING_RUNS = 7, 5  # HOME suggests "監視設定を更新" from here on


def query_background_task(data):
    """Read-only `schtasks /Query` for this data folder's task (tools/background_monitor.task_name). None when it cannot be asked."""
    if os.name != 'nt':
        return None
    from tools.background_monitor import task_name  # the app runs from the project folder (python -m src.noxiworks.app)
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    p = subprocess.run(['schtasks', '/Query', '/TN', task_name(data)], capture_output=True, timeout=10, creationflags=flags)
    return p.returncode == 0


def already_running(port):
    """Something already answers on 127.0.0.1:port (a SiteProof started earlier): open it instead of starting a second one."""
    import socket
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(('127.0.0.1', port)) == 0


def launch_detached(args, console=False):
    """Start a tool from the project folder and do not wait. console=True: in a new console window the USER interacts with."""
    flags = getattr(subprocess, 'CREATE_NEW_CONSOLE', 0) if console else getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
    return subprocess.Popen(args, cwd=Path(__file__).resolve().parents[2], env=env, creationflags=flags,
                            stdin=None if console else subprocess.DEVNULL, stdout=None if console else subprocess.DEVNULL,
                            stderr=None if console else subprocess.DEVNULL)


def default_data():
    base = os.environ.get('LOCALAPPDATA')
    return Path(base) / 'SiteProof' if base else Path.home() / '.local' / 'share' / 'siteproof'


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


class App:
    def __init__(self, data, interval_override=None):
        self.data = Path(data).resolve()
        self.interval_override = interval_override  # --check-every (testing): seconds between scheduled inspections
        self.stop_event = threading.Event()
        self.site_shown = self.site_rendered = self.site_archive = None
        self.docker_found = self.real_runner = None  # injectable for offline tests only; the app itself never sets them
        self.launcher = launch_detached  # starts the USER-facing setup console / Docker Desktop / schtasks; tests replace it
        self.background_query = query_background_task  # is this data folder's Windows task registered? (read-only; tests replace it)
        self._background = (0.0, None)
        self.fixture_capture = False  # tests of the monitoring engine only (serve(..., fixture_capture=True)); never from the GUI / CLI
        self._disk = None
        self.lock = threading.Lock()
        self.token = secrets.token_urlsafe(24)
        self.state = {'running': None, 'last': None, 'error': None}
        self.ui = None          # the synthetic demo pages (served under /demo/ only)
        self.empty_ui = None    # / before a site is registered: no targets, no synthetic data
        self.site = None        # the user-registered site (site_workflow.Site), at most one in MVP v1.0
        self.site_ui = None
        self.site_error = None

    # ---- data folder
    def setup(self):
        from src.aws_b.model import format_utc
        (self.data / 'runs').mkdir(parents=True, exist_ok=True)
        (self.data / 'ui').mkdir(exist_ok=True)
        if not (self.data / 'registry' / 'APPROVAL-RECORD.json').is_file():
            from tools.build_offline_demo import make_registry
            work = self.data / '.registry-work'
            shutil.rmtree(work, ignore_errors=True)
            work.mkdir()
            make_registry(work, utc_now())
            (work / 'registry').rename(self.data / 'registry')
            shutil.rmtree(work, ignore_errors=True)
        for leftover in (self.data / 'runs').glob('.tmp-*'):  # an inspection interrupted by a crash or a stop
            shutil.rmtree(leftover, ignore_errors=True)
        self.rebuild()
        runs = self.runs()
        if runs and (runs[-1].parent / 'result.json').is_file():  # the newest saved inspection, shown again after a restart
            self.state['last'] = json.loads((runs[-1].parent / 'result.json').read_text('utf-8'))
        sites = self.data / 'sites'
        sites.mkdir(exist_ok=True)
        for leftover in sites.glob('.tmp-*'):  # a registration interrupted by a crash or a stop
            shutil.rmtree(leftover, ignore_errors=True)
        found = sorted(p for p in sites.iterdir() if p.name.startswith('site-') and (p / 'site.json').is_file())
        if found:
            from src.noxiworks.site_workflow import Site
            self.site = Site(found[0])
            if not (self.site.root / 'monitor.json').is_file():  # registered before automatic monitoring existed
                from src.noxiworks.site_monitor import Monitor
                Monitor.create(self.site, utc_now())
            for leftover in list((self.site.root / 'runs').glob('.tmp-*')) + [self.site.root / '.tmp-registry']:
                shutil.rmtree(leftover, ignore_errors=True)
            self.rebuild_site()
        self.rebuild_empty()
        self.state['started_at'] = format_utc(utc_now())

    def runs(self):
        """Saved inspections, oldest first. Each is runs/<id>/<id> (the run directory carries its id as its name)."""
        return sorted(p / p.name for p in (self.data / 'runs').iterdir() if RUN_ID.match(p.name) and (p / p.name).is_dir())

    @staticmethod
    def generate(ui_dir, runs, registry, env=None, schedule=None, archive=None, older=()):
        """Regenerate pages through the unchanged CLI into ui_dir/<next gen>: the newest run is shown, earlier runs are history."""
        from src.aws_b.model import format_utc
        gens = [int(p.name) for p in ui_dir.iterdir() if p.name.isdigit()]
        out = ui_dir / str(max(gens, default=0) + 1)
        command = [sys.executable, '-B', '-m', 'src.noxiworks', '--out', str(out), '--now', format_utc(utc_now())]
        if schedule:
            command += ['--schedule', str(schedule)]
        if archive:  # the user's own AWS-B results, imported with src.noxiworks.archive import-export (saved HTTP results, never live)
            command += ['--archive', str(archive)]
        if runs:
            command += ['--local-capture', str(runs[-1])] + (['--baseline-registry', str(registry)] if registry else [])
            for kept in (older if registry else ()):
                command += ['--baseline-older', str(kept)]
            for run in runs[:-1]:
                command += ['--history-run', str(run)]
        p = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', **(env or {})})
        if p.returncode != 0:
            raise RuntimeError('page generation failed: ' + (p.stderr.strip().splitlines() or ['?'])[-1][:300])
        for old in sorted(int(x.name) for x in ui_dir.iterdir() if x.name.isdigit())[:-KEEP_UI]:
            shutil.rmtree(ui_dir / str(old), ignore_errors=True)
        return out

    def rebuild_empty(self):
        """The page behind / before any site is registered: the unchanged dashboard with no targets (no synthetic data)."""
        empty = self.data / 'empty'
        (empty / 'ui').mkdir(parents=True, exist_ok=True)
        (empty / 'targets.json').write_text(json.dumps({'schema': 'siteproof.targets.v1', 'http_interval_seconds': 21600, 'capture_interval_seconds': 86400,
                                                        'tls_stale_seconds': 172800, 'domain_stale_seconds': 2592000, 'pages': [], 'sites': []}), encoding='utf-8')
        (empty / 'capture_plan.json').write_text(json.dumps({'schema': 'siteproof.capture-plan.v1', 'sites': []}), encoding='utf-8')
        self.empty_ui = self.generate(empty / 'ui', [], None, {'SITEPROOF_TARGETS': str(empty / 'targets.json'),
                                                                 'SITEPROOF_CAPTURE_PLAN': str(empty / 'capture_plan.json')})
        return self.empty_ui

    def rebuild(self):
        self.ui = self.generate(self.data / 'ui', self.runs(), self.data / 'registry')
        return self.ui

    def rebuild_site(self):
        """The user's site pages: the unchanged CLI pointed at the site's own targets / capture plan (only that site is shown)."""
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
                targets['capture_interval_seconds'] = self.interval_override or settings['interval_seconds']
                (site.root / 'targets.json').write_text(json.dumps(targets, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
                last = settings['last'] or {}
                record = [{'schema': SCHEDULE_SCHEMA, 'target_id': site.page_id, 'channel': 'capture', 'enabled': settings['enabled'],
                           'last_finished_at': last.get('finished_at'), 'last_outcome': ('FAILED' if last.get('outcome') == 'FAILED' else 'COMPLETED') if last else None,
                           'next_due_at': settings['next_due_at'] if settings['enabled'] else None, 'observed_at': format_utc(utc_now()),
                           'source': 'SiteProofアプリの自動監視（このPC）'}]
                (site.root / 'schedule.json').write_text(json.dumps(record, ensure_ascii=False) + '\n', encoding='utf-8')
            real = site.mode() == 'REAL'  # real captures are shown alone; the offline fixture runs stay on disk, unshown
            runs = site.real_runs() if real else site.runs()
            self.site_rendered = (settings['enabled'], settings['interval_seconds']) if settings else None
            self.site_archive = self.archive_signature()
            self.site_ui = self.generate(site.root / 'ui', runs, site.real_registry() if real else site.registry(), env,
                                         schedule=site.root / 'schedule.json' if settings else None,
                                         archive=site.root / 'aws-archive' if self.site_archive else None,
                                         older=site.baseline_history_dirs() if real else ())
            self.site_shown = [r.name for r in runs]
            self.site_error = None
        except RuntimeError as exc:  # keep serving the last good pages; the panel shows why
            self.site_error = str(exc)
            if self.site_ui is None:
                raise
        return self.site_ui

    def display_targets(self, site):
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

    # ---- the user's site: register -> automatic monitoring (site_monitor). The GUI only registers, pauses / resumes, confirms.
    def monitor(self):
        from src.noxiworks.site_monitor import Monitor
        return Monitor(self.site, docker_found=self.docker_found, real_runner=self.real_runner, fixture_capture=self.fixture_capture)

    def disk(self, monitor):
        """Disk usage of the site folder, rescanned at most every 30 s (HOME polls every few seconds)."""
        import time
        if self._disk is None or time.monotonic() - self._disk[0] > 30:
            self._disk = (time.monotonic(), monitor.disk())
        return self._disk[1]

    def site_action(self, action, body):
        from src.noxiworks.site_monitor import Busy, Monitor
        from src.noxiworks.site_workflow import FIXTURES as SITE_FIXTURES, Site
        if action == 'setup' and self.site is not None:
            return self.setup_step(body)
        if action in ('monitor', 'confirm') and self.site is not None:
            # Settings and the confirmation record only: allowed while an inspection runs (no page regeneration needed).
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
            return self.monitor().update(utc_now(), self.interval_override, **changes)
        if not self.lock.acquire(blocking=False):
            raise BlockingIOError('busy')
        try:
            now = utc_now()
            if action == 'register':
                if self.site is not None:
                    raise ValueError('MVP v1.0で登録できるサイトは1つです')
                site = Site.register(self.data / 'sites', body.get('name'), body.get('url'), body.get('kinds'),
                                     body.get('owner_confirmed'), now)
                monitor = Monitor.create(site, now)  # monitoring on, first inspection due now: the scheduler starts it within seconds
                if body.get('interval_seconds') is not None:
                    from src.noxiworks.site_monitor import INTERVALS
                    if body['interval_seconds'] not in INTERVALS:
                        raise ValueError('検査間隔は 15分・1時間・6時間・24時間 から選んでください')
                    settings = monitor.load()
                    settings['interval_seconds'] = body['interval_seconds']
                    monitor.save(settings)
                self.site = site
                out = {'site_id': site.info['site_id']}
            elif self.site is None:
                raise ValueError('先にサイトを登録してください')
            elif action == 'baseline-update':  # the USER's explicit "新しい基準にする" (never taken from a schedule or an inspection)
                from src.noxiworks.site_workflow import ACTOR
                versions = body.get('expected_versions')
                if (body.get('confirmed') is not True or not isinstance(body.get('run_id'), str) or not isinstance(versions, dict)
                        or not all(type(v) is int for v in versions.values())):
                    raise ValueError('新しい基準にする操作の内容が正しくありません')
                try:
                    done = self.monitor().update_baseline(body['run_id'], versions, now, ACTOR)
                    out = {'versions': {b['kind']: b['version'] for b in done['baselines']}, 'recovered': done.get('recovered') is True}
                except Busy as exc:
                    raise ValueError(str(exc)) from None
            elif action == 'baseline-approve':  # the USER's explicit formal approval of the current Baseline (never from a schedule or an inspection)
                from src.noxiworks.site_workflow import ACTOR
                expected = body.get('expected')
                if (body.get('confirmed') is not True or not isinstance(expected, dict) or not expected
                        or not all(isinstance(v, dict) for v in expected.values())):
                    raise ValueError('正式承認の操作の内容が正しくありません')
                try:
                    self.monitor().approve_baseline(expected, now, ACTOR)
                except Busy as exc:
                    raise ValueError(str(exc)) from None
                out = {'state': self.site.baseline_state()['state']}
            elif action == 'inspect':  # auxiliary: inspect now, outside the schedule
                try:
                    out = self.monitor().run(now, 'MANUAL', self.interval_override, utc_now)
                except Busy:
                    raise BlockingIOError('busy') from None
            else:
                raise ValueError('unknown action')
            self.rebuild_site()
            return out
        finally:
            self.lock.release()

    # ---- first-time setup, delegated (the app holds no key and never signs)
    def setup_step(self, body):
        """One GUI button of the first-time setup. Each starts an existing tool as a separate process and returns at once:
          setup       tools/setup_monitoring.py in its OWN console window: the USER sees the permit, confirms it there and signs with
                      their own key (ssh-keygen asks for the passphrase there). The app passes no key, no answer and no --yes.
          docker      Docker Desktop (`docker desktop start`)
          background  tools/background_monitor.py install (a Windows task for this data folder only)
        The result shows up in the readiness checks once the tool has finished."""
        from src.aws_b.model import format_utc
        step = body.get('step')
        host = self.site.info['url'].split('/')[2]
        workers_dev = re.fullmatch(r'[a-z0-9-]+\.[a-z0-9-]+\.workers\.dev', host) is not None
        if step == 'setup':  # first setup and renewal ("監視設定を更新") are the same tool
            evidence = (self.site.root / 'real' / 'ownership-evidence.json').is_file()
            ownership = body.get('ownership') or ('cloudflare' if workers_dev else None)
            if ownership == 'reuse' and not evidence:
                raise ValueError('再利用できる所有権の確認記録がありません。確認方法を選んでください')
            if ownership not in ('reuse', 'cloudflare', 'well-known-file', 'dns-txt') or (ownership == 'cloudflare' and not workers_dev):
                raise ValueError('所有権の確認方法を選んでください（Cloudflareの確認は workers.dev のサイトだけです）')
            args = [sys.executable, '-B', 'tools/setup_monitoring.py', '--data', str(self.data.resolve()), '--pause']
            if ownership != 'reuse':  # reuse: the tool takes the evidence that is already there (it re-checks it)
                args += ['--ownership', ownership]
            if ownership in ('well-known-file', 'dns-txt'):
                if body.get('confirmed') is not True:
                    raise ValueError('確認用ファイル（またはDNSのTXTレコード）を自分で確認してから、チェックを入れてください')
                args += ['--verified-at', format_utc(utc_now())]
            self.write_setup_status('LAUNCHED', 'セットアップの画面を開きました')
            try:
                self.launcher(args, console=True)
            except OSError as exc:
                self.write_setup_status('FAILED', 'セットアップの画面を開けませんでした：' + str(exc)[:200])
                raise ValueError('セットアップの画面を開けませんでした') from None
            return {'launched': 'setup', 'ownership': ownership,
                    'note': '別のウィンドウで、許可の内容を確認して署名してください。完了すると、この画面の準備が自動で更新されます。'}
        if step == 'docker':
            self.launcher(['docker', 'desktop', 'start'], console=False)
            return {'launched': 'docker', 'note': 'Docker Desktopを起動しています（1〜2分かかることがあります）。'}
        if step in ('background', 'background-remove'):
            action = 'install' if step == 'background' else 'remove'
            self.launcher([sys.executable, '-B', 'tools/background_monitor.py', action, '--data', str(self.data.resolve())], console=False)
            self._background = (0.0, None)  # ask again on the next screen update
            return {'launched': step, 'note': 'アプリを閉じても監視するタスクを登録しました（15分ごとに確認）。' if action == 'install'
                    else 'アプリを閉じている間の監視を解除しました（アプリを開いている間は、これまでどおり監視します）。'}
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

    def background_state(self):
        """True / False / None (unknown), asked at most once a minute (the screen polls every few seconds)."""
        import time
        at, value = self._background
        if time.monotonic() - at > 60 or at == 0.0:
            try:
                value = self.background_query(self.data)
            except Exception:
                value = None
            self._background = (time.monotonic(), value)
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

    def tick(self):
        """One scheduler step: show inspections a background worker saved, and run the next inspection when it is due."""
        from src.noxiworks.site_monitor import Busy
        if self.site is None or not self.lock.acquire(blocking=False):
            return None
        try:
            entry = None
            try:
                entry = self.monitor().run_if_due(utc_now(), self.interval_override, utc_now)
            except Busy:
                pass  # the OS-scheduled worker is inspecting right now
            shown = [r.name for r in (self.site.real_runs() if self.site.mode() == 'REAL' else self.site.runs())]
            settings = self.monitor().load()
            if (entry is not None or shown != self.site_shown or (settings['enabled'], settings['interval_seconds']) != self.site_rendered
                    or self.archive_signature() != self.site_archive):
                self.rebuild_site()
            return entry
        finally:
            self.lock.release()

    def start_scheduler(self, every=2.0):
        def loop():
            while not self.stop_event.wait(every):
                try:
                    self.tick()
                except Exception as exc:  # never kill the scheduler; the panel shows the error
                    self.site_error = 'scheduler: ' + type(exc).__name__ + ': ' + str(exc)[:200]
        self.scheduler = threading.Thread(target=loop, name='siteproof-monitor', daemon=True)
        self.scheduler.start()

    def stop(self):
        self.stop_event.set()

    def site_status(self):
        from src.noxiworks.site_monitor import INTERVALS, OUTCOME_LABELS
        from src.noxiworks.site_workflow import FIXTURES as SITE_FIXTURES
        site = self.site
        if site is None:
            return None
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
        elif self.fixture_capture and site.mode() != 'REAL':
            display = 'OFFLINE_DEMO'
        elif permit and permit['expired']:
            display = 'EXPIRED'  # set up once, the permit ran out (period or runs): "監視設定を更新"
        elif not (site.root / 'real' / 'permit.json').is_file():
            display = 'SETUP_NEEDED'
        else:
            display = 'REAL_PENDING'
        runs = site.runs() + site.real_runs()
        view = self.monitor_view(monitor, settings, readiness, permit, setup)
        log = [{**entry, 'explained': explain_failure(entry.get('error')) if entry.get('outcome') == 'FAILED' else None} for entry in monitor.log(8)]
        return {**{k: site.info[k] for k in ('site_id', 'page_id', 'name', 'url', 'label', 'kinds', 'registered_at', 'owner', 'capture_mode')},
                'monitor': {'enabled': settings['enabled'], 'interval_seconds': self.interval_override or settings['interval_seconds'],
                            'interval_label': INTERVALS.get(settings['interval_seconds']), 'override': self.interval_override,
                            'next_due_at': settings['next_due_at'] if settings['enabled'] else None, 'last': settings['last'],
                            'running': monitor.running(), 'offline_fixture': settings['offline_fixture']},
                'baseline': site.baseline_state(), 'baseline_update': real.baseline_update_state(), 'baseline_history': site.baseline_history(),
                'monitor_view': view, 'runs': len(runs), 'log': log,
                'readiness': readiness, 'real_capture_available': all(c['ok'] for c in readiness), 'mode': site.mode(),
                'setup': setup, 'permit': permit, 'background': self.background_state(),
                'ownership_evidence': (site.root / 'real' / 'ownership-evidence.json').is_file(),
                'display': display, 'permit_present': (site.root / 'real' / 'permit.json').is_file(), 'disk': self.disk(monitor),
                'paused_reason': settings.get('paused_reason'),
                'fixtures': SITE_FIXTURES, 'fixture_capture': self.fixture_capture, 'intervals': INTERVALS, 'outcomes': OUTCOME_LABELS,
                'error': self.site_error}

    def monitor_view(self, monitor, settings, readiness, permit, setup):
        """The monitoring state HOME shows (src/noxiworks/uiview.py), and the one the server enforces when asked to start monitoring."""
        policy = settings.get('stop_policy')
        hold = monitor._hold(policy) if policy else None
        return monitor_view(enabled=settings['enabled'], running=monitor.running(), paused_reason=settings.get('paused_reason'), last=settings.get('last'),
                            readiness=readiness, permit=permit, setup=setup, hold=hold, fixture_engine=self.fixture_capture)

    # ---- one inspection
    def inspect(self, fixture):
        from src.aws_b.model import format_utc
        from src.noxiworks.baseline_runtime import expected_baseline, read_registry
        from tools.offline_capture_compare import run_case
        if fixture not in FIXTURES:
            raise ValueError('unknown fixture')
        if not self.lock.acquire(blocking=False):
            raise BlockingIOError('an inspection is already running')
        try:
            now = utc_now()
            self.state.update(running={'fixture': fixture, 'started_at': format_utc(now)}, error=None)
            n = len(list((self.data / 'runs').iterdir()))
            run_id = f'{now:%Y%m%dT%H%M%SZ}-{n % 100:02d}-{fixture}'
            registry = self.data / 'registry'
            expect = {**expected_baseline(read_registry(registry)),
                      'registry_export_sha256': hashlib.sha256((registry / 'export-sha256.json').read_bytes()).hexdigest()}
            tmp = self.data / 'runs' / ('.tmp-' + run_id)
            run_dir, summary = run_case(fixture, registry, expect, tmp, now)
            if not all(summary['checks'].values()):
                raise RuntimeError('host checks failed: ' + ', '.join(k for k, v in summary['checks'].items() if not v))
            run_dir.rename(tmp / run_id)       # the run id becomes the run directory's name (its history identity)
            shutil.rmtree(tmp / 'worker-evidence', ignore_errors=True)  # the Worker's scratch copy; the run keeps its workspace
            result = {'run_id': run_id, 'fixture': fixture, 'finished_at': format_utc(utc_now()),
                      'profiles': {k: {'verdict': p['verdict'], 'reasons': p['operational_reasons'], 'changed_pixels': p['changed_pixels']}
                                   for k, p in summary['profiles'].items()}}
            (tmp / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            tmp.rename(self.data / 'runs' / run_id)  # only a finished inspection appears under its final name
            self.rebuild()
            self.state['last'] = result
            return result
        except Exception as exc:
            self.state['error'] = type(exc).__name__ + ': ' + str(exc)[:300]
            raise
        finally:
            self.state['running'] = None
            self.lock.release()

    def status(self):
        return {**self.state, 'runs': len(self.runs()), 'fixtures': {k: v[0] for k, v in FIXTURES.items()}, 'data': str(self.data),
                'site': self.site_status()}


def page_with_app(raw):
    """The served copy of a generated page: allow same-origin fetch for the app panel and load app.js. Files stay unchanged."""
    text = raw.decode('utf-8')
    text = text.replace("connect-src 'none'", "connect-src 'self'", 1)
    text = text.replace('</head>', '<link rel="stylesheet" href="/app/app.css"><script src="/app/app.js" defer></script></head>', 1)
    return text.encode('utf-8')


def make_handler(app, authority):
    origin = 'http://' + authority
    assets = Path(__file__).with_name('app_assets')

    class Handler(BaseHTTPRequestHandler):
        server_version = 'SiteProof'
        sys_version = ''

        def log_message(self, fmt, *args):
            pass

        def send(self, status, body, ctype='application/json', extra=None):
            self.send_response(status)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('X-Frame-Options', 'DENY')
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)

        def json(self, status, obj):
            self.send(status, json.dumps(obj, ensure_ascii=False).encode('utf-8'))

        def do_GET(self):
            if self.headers.get('Host') != authority:
                return self.json(421, {'error': 'host'})
            path = self.path.split('?', 1)[0].split('#', 1)[0]
            if path == '/app/api/session':
                # Readable only by a same-origin page: no CORS header is ever sent.
                if self.headers.get('X-SiteProof-App') != '1' or self.headers.get('Sec-Fetch-Site', 'same-origin') != 'same-origin':
                    return self.json(403, {'error': 'forbidden'})
                return self.json(200, {'token': app.token, **app.status()})
            if path in ('/app/app.js', '/app/app.css'):
                f = assets / path.rsplit('/', 1)[1]
                return self.send(200, f.read_bytes(), TYPES[f.suffix])
            # /demo/... = the synthetic demo; / = the user's site once registered (until then, the demo). Never both on one page.
            demo = path == '/demo' or path.startswith('/demo/')
            ui = app.ui if demo else app.site_ui or app.empty_ui  # / never shows the synthetic demo: empty until a site is registered
            if path == '/demo':
                return self.send(302, b'', 'text/plain', {'Location': '/demo/'})
            rel = path[len('/demo/'):] if path.startswith('/demo/') else path.lstrip('/')
            rel = rel or 'index.html'
            if '..' in rel.split('/') or '\\' in rel or ':' in rel:
                return self.json(404, {'error': 'not found'})
            f = (ui / rel).resolve()
            if not f.is_file() or ui.resolve() not in f.parents or f.suffix not in TYPES:
                return self.json(404, {'error': 'not found'})
            raw = f.read_bytes()
            return self.send(200, page_with_app(raw) if f.suffix == '.html' else raw, TYPES[f.suffix])

        do_HEAD = do_GET

        def do_POST(self):
            if (self.path not in ('/app/api/run',) + SITE_ROUTES or self.headers.get('Host') != authority or self.headers.get('Origin') != origin
                    or self.headers.get('X-SiteProof-App') != '1' or self.headers.get('Content-Type', '').split(';')[0] != 'application/json'):
                return self.json(403, {'error': 'forbidden'})
            length = int(self.headers.get('Content-Length') or 0)
            if length > 4096:
                return self.json(413, {'error': 'too large'})
            try:
                body = json.loads(self.rfile.read(length) or b'{}')
            except ValueError:
                return self.json(400, {'error': 'bad json'})
            if not isinstance(body, dict) or not secrets.compare_digest(str(body.get('token', '')), app.token):
                return self.json(403, {'error': 'forbidden'})
            if self.path in SITE_ROUTES:
                from src.noxiworks.site_workflow import SiteRefused
                try:
                    return self.json(200, {'result': app.site_action(self.path.rsplit('/', 1)[1], body)})
                except BlockingIOError:
                    return self.json(409, {'error': '別の処理を実行中です'})
                except (SiteRefused, ValueError) as exc:
                    return self.json(422, {'error': str(exc)[:300]})
                except Exception as exc:
                    return self.json(500, {'error': type(exc).__name__ + ': ' + str(exc)[:300]})
            if body.get('fixture') not in FIXTURES:
                return self.json(422, {'error': 'unknown fixture'})
            try:
                return self.json(200, {'result': app.inspect(body['fixture'])})
            except BlockingIOError:
                return self.json(409, {'error': '別の検査を実行中です'})
            except Exception:
                return self.json(500, {'error': app.state['error']})

    return Handler


def serve(data, port=0, interval_override=None, scheduler=True, fixture_capture=False):
    """-> (server, app). Caller runs server.serve_forever() (or a thread), then server.shutdown() and app.stop()."""
    app = App(data, interval_override)
    app.fixture_capture = fixture_capture
    app.setup()
    if scheduler:
        app.start_scheduler()
    server = ThreadingHTTPServer(('127.0.0.1', port), None)
    authority = f'127.0.0.1:{server.server_address[1]}'
    server.RequestHandlerClass = make_handler(app, authority)
    server.daemon_threads = True
    return server, app


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--data', type=Path, default=default_data(), help='app data folder (created if missing)')
    parser.add_argument('--port', type=int, default=8765, help='127.0.0.1 port (0 = any free port)')
    parser.add_argument('--no-browser', action='store_true', help='do not open the default browser')
    parser.add_argument('--check-every', type=int, metavar='SECONDS', help='testing only: seconds between scheduled inspections (overrides the site setting)')
    args = parser.parse_args(argv)
    if args.check_every is not None and not 5 <= args.check_every <= 86400:
        parser.error('--check-every must be 5..86400 seconds')
    if args.port and already_running(args.port):
        url = f'http://127.0.0.1:{args.port}/'
        print(f'SiteProof はすでに起動しています：{url}（画面を開きます）', flush=True)
        if not args.no_browser:
            webbrowser.open(url)
        return 0
    print('SiteProof を準備しています…' + ('' if (args.data / 'registry').is_dir() else '（初回のみ合成Baselineを作成します）'), flush=True)
    server, app = serve(args.data, args.port, args.check_every)
    url = f'http://127.0.0.1:{server.server_address[1]}/'
    print(f'SiteProof: {url}\nデータ: {app.data}\n保存済みの検査: {len(app.runs())}件\n終了は Ctrl+C', flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.stop()
        server.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
