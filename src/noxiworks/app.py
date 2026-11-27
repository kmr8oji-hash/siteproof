"""SiteProof local app: the existing HOME / REVIEW / ACTIVITY pages plus the user's own site and the synthetic demo. No AWS, no real site.

The user's sites (src/noxiworks/site_workflow.py, one src/noxiworks/site_app.SiteApp each): サイトを追加 -> capture -> the user approves the
Baseline -> later captures are compared. A site's pages are served at /site/<site id>/ (its first page) and /site/<site id>/page/<page id>/ (up to four
further pages of the same host, each a unit folder of its own: only the site's ownership evidence and e-mail switch are shared; every action names `site_id`
and `unit`, and `unit` may be left out only while the site has one page) and show that site only; / shows the only site, the list of
all sites (全サイトの状態) once there are several, or an empty dashboard until one is registered. Every action names its site id; without one it
is accepted only while a single site is registered, so a stale tab can never act on another site. The synthetic demo below is served at /demo/
only, and a site that cannot be captured for real is never monitored with generated images.

Run: py -3.15 -B -m src.noxiworks.app [--data DIR [--remember]] [--where] [--port N] [--no-browser]

The pages are the static export of `python -m src.noxiworks` (unchanged design), regenerated from the app's own data folder
after every inspection and at every start, so saved history survives a restart. One action is added: POST /app/api/run runs
one inspection of an allowed SYNTHETIC fixture through the product pipeline (RuntimeService -> S1 save -> ComparisonService,
via tools/offline_capture_compare.run_case) against the app's synthetic, approved Baseline. The capture step is the offline
stand-in that hands back stored or edited Baseline bytes: no browser, no socket, nothing leaves the machine. Every page says
サンプルデータ（デモ）/ 合成デモ; real captures and AWS data are never mixed in (local_capture refuses that).

Data folder (default %LOCALAPPDATA%\\SiteProof or ~/.local/share/siteproof, or the folder remembered with --remember in <that>/settings.json; never a fixed drive):
  registry/   synthetic Baseline registry, created once (Desktop 1440 / Mobile 390, approved by a synthetic actor)
  runs/<id>/  one saved inspection each: <id>/ (S1 workspace + SQLite + run results + diff PNGs, export-sha256.json), result.json
  ui/<gen>/   generated pages; the newest is served
Security: 127.0.0.1 only; POST needs the exact Host/Origin, JSON, a custom header and a per-launch token that only a
same-origin page can read (no CORS headers are ever sent). One inspection at a time.
"""
import argparse
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

from src.noxiworks import sites as site_folders
from src.noxiworks.site_app import SiteApp, utc_now

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = {'unchanged': ('変更なし（Baselineと同じ画像）', 'NO_VISUAL_CHANGE_DETECTED'),
            'changed': ('変更あり（画面上部に赤い帯）', 'VISUAL_CHANGED'),
            'unstable': ('撮影が不安定（撮影ごとに画像が変わる）', 'UNKNOWN')}
TYPES = {'.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
         '.json': 'application/json', '.png': 'image/png'}
RUN_ID = re.compile(r'^\d{8}T\d{6}Z-\d{2}-(unchanged|changed|unstable)$')
KEEP_UI = 2
SITE_ROUTES = ('/app/api/site/register', '/app/api/site/inspect', '/app/api/site/monitor', '/app/api/site/confirm', '/app/api/site/setup',
               '/app/api/site/baseline-update', '/app/api/site/baseline-approve', '/app/api/site/http', '/app/api/site/notify', '/app/api/site/maintenance',
               '/app/api/site/backup', '/app/api/site/add-page', '/app/api/site/stop-site')


MAX_SITES = 20


def query_background_task(data, site_id, channel):
    """Read-only `schtasks /Query` for this site's task of this data folder (tools/background_monitor.task_name). None when it cannot be asked."""
    if os.name != 'nt':
        return None
    from tools.background_monitor import task_name  # the app runs from the project folder (python -m src.noxiworks.app)
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    p = subprocess.run(['schtasks', '/Query', '/TN', task_name(data, site_id, channel)], capture_output=True, timeout=10, creationflags=flags)
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


class DataFolderError(ValueError):
    pass


def base_folder():
    base = os.environ.get('LOCALAPPDATA')
    return Path(base) / 'SiteProof' if base else Path.home() / '.local' / 'share' / 'siteproof'


def settings_file():
    return base_folder() / 'settings.json'


def default_data():
    """The folder remembered with --remember (<base>/settings.json {data_folder}), else the base folder itself. A remembered folder that cannot be used
    is an error with its reason: the app never falls back to another (empty) folder by itself."""
    f = settings_file()
    if not f.is_file():
        return base_folder()
    try:
        value = json.loads(f.read_text('utf-8'))['data_folder']
        if not isinstance(value, str) or not value.strip():
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError):
        raise DataFolderError(f'保存した設定 {f} を読めません。--data でフォルダを指定するか、この設定ファイルを確認してください（何も変更していません）') from None
    if not Path(value).is_dir():
        raise DataFolderError(f'前に選んだデータフォルダ {value} が見つかりません（ドライブや外付けディスクが接続されていないかもしれません）。接続し直すか、--data で指定してください。'
                              f'別の空のフォルダで勝手に始めることはしません。既定のフォルダに戻すなら {f} を削除してください（データは削除されません）')
    return Path(value)


def remember_data(folder):
    """Write <base>/settings.json {data_folder} (atomically), only when the folder exists or can be created. Never moves or copies data. -> the settings file."""
    folder = Path(folder).resolve()
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise DataFolderError(f'フォルダ {folder} を作れないため、記憶しません（{type(exc).__name__}）') from None
    f = settings_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_name(f.name + '.tmp')
    tmp.write_text(json.dumps({'schema': 'siteproof.settings.v1', 'data_folder': str(folder)}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    os.replace(tmp, f)
    return f


class App:
    def __init__(self, data, interval_override=None):
        self.data = Path(data).resolve()
        self.interval_override = interval_override  # --check-every (testing): seconds between scheduled inspections
        self.stop_event = threading.Event()
        self.docker_found = self.real_runner = None  # injectable for offline tests only; the app itself never sets them
        self.launcher = launch_detached  # starts the USER-facing setup console / Docker Desktop / schtasks; tests replace it
        self.background_query = query_background_task  # is this data folder's Windows task registered? (read-only; tests replace it)
        self.fixture_capture = False  # tests of the monitoring engine only (serve(..., fixture_capture=True)); never from the GUI / CLI
        self.lock = threading.Lock()  # page generation and inspections, one at a time over all sites
        self.token = secrets.token_urlsafe(24)
        self.state = {'running': None, 'last': None, 'error': None}
        self.ui = None          # the synthetic demo pages (served under /demo/ only)
        self.empty_ui = None    # / before a site is registered: no targets, no synthetic data
        self.sites = {}         # site id -> SiteApp, in order of registration
        self.site_problems = []  # folders under sites/ that are not used, with the reason
        self.http_probe = None  # injected by offline tests only; the app itself never sets it (the real probe stays off until approved)
        self.notify_provider = None  # the same for e-mail (the real provider stays off until approved)
        self._storage = self._environment = None

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
        from src.noxiworks.site_monitor import Monitor
        from src.noxiworks.site_workflow import Site
        found, self.site_problems = site_folders.scan(self.data)
        for folder in found:
            one = SiteApp(self, Site(folder))
            for name in ('runs', 'ui'):  # empty folders do not survive a backup and its restore
                (folder / name).mkdir(exist_ok=True)
            if not (folder / 'monitor.json').is_file():  # registered before automatic monitoring existed
                Monitor.create(one.site, utc_now())
            for leftover in list((folder / 'runs').glob('.tmp-*')) + [folder / '.tmp-registry']:
                shutil.rmtree(leftover, ignore_errors=True)
            self.sites[folder.name] = one
            try:
                one.rebuild()
            except Exception as exc:  # its error is on its panel (also with one site: the app still opens and says why); the other sites are served
                one.error = one.error or type(exc).__name__ + ': ' + str(exc)[:200]
            self.load_pages(one)
        self.rebuild_empty()
        self.state['started_at'] = format_utc(utc_now())

    def load_pages(self, one):
        """The further pages of a site (<site>/pages/*): each a SiteApp of its own. A broken page is listed in site_problems and never stops the site or its other pages."""
        from src.noxiworks.site_monitor import Monitor, default_settings
        from src.noxiworks.site_workflow import Site
        found, bad = site_folders.pages(one.site.root)
        self.site_problems += [(f'{one.site.root.name}/pages/{name}', why) for name, why in bad]
        for leftover in (one.site.root / 'pages').glob('.tmp-*') if (one.site.root / 'pages').is_dir() else ():  # a page registration interrupted by a crash
            shutil.rmtree(leftover, ignore_errors=True)
        pages = {}
        for folder in found:
            try:
                page = SiteApp(self, Site(folder), parent=one)
                for name in ('runs', 'ui'):
                    (folder / name).mkdir(exist_ok=True)
                if not (folder / 'monitor.json').is_file():  # a page starts with image monitoring OFF
                    Monitor(page.site).save({**default_settings(utc_now()), 'enabled': False, 'next_due_at': None})
                for leftover in list((folder / 'runs').glob('.tmp-*')) + [folder / '.tmp-registry']:
                    shutil.rmtree(leftover, ignore_errors=True)
                pages[folder.name] = page
            except Exception as exc:
                self.site_problems.append((f'{one.site.root.name}/pages/{folder.name}', type(exc).__name__ + ': ' + str(exc)[:120]))
                continue
            try:
                page.rebuild()
            except Exception as exc:
                page.error = page.error or type(exc).__name__ + ': ' + str(exc)[:200]
        one.pages = pages

    def units(self):
        """Every page of every site (the first pages and the further ones): what the schedulers walk."""
        return [u for one in list(self.sites.values()) for u in one.units()]

    # ---- the registered sites
    def pick_site(self, site_id=None):
        """The SiteApp (first page) a request is about: the named one, or the only one. Never a guess between several."""
        if site_id is not None:
            one = self.sites.get(site_id) if isinstance(site_id, str) else None
            if one is None:
                raise ValueError('指定されたサイトは登録されていません')
            return one
        if not self.sites:
            raise ValueError('先にサイトを登録してください')
        if len(self.sites) > 1:
            raise ValueError('どのサイトの操作かを確認できません。画面を開き直してください（サイトが複数登録されています）')
        return next(iter(self.sites.values()))

    def pick(self, site_id=None, unit=None):
        """The SiteApp of one page: `unit` is its folder name (the site id for the first page, else the page id). It may be left out only while the site
        has a single page: a tab opened before another page was added must never act on the wrong one."""
        one = self.pick_site(site_id)
        if unit is None:
            if one.pages:
                raise ValueError('どのページの操作かを確認できません。画面を開き直してください（このサイトにはページが複数あります）')
            return one
        if unit == one.unit:
            return one
        page = one.pages.get(unit) if isinstance(unit, str) else None
        if page is None:
            raise ValueError('指定されたページは登録されていません')
        return page

    @property
    def first(self):
        return next(iter(self.sites.values()), None)

    @property
    def site(self):
        """The (first) registered site, or None: for one-site data folders, the setup tools and tests."""
        return self.first.site if self.sites else None

    @site.setter
    def site(self, site):
        self.sites = {site.info['site_id']: SiteApp(self, site)}

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

    # ---- one-site shorthands (the only / first site)
    site_ui = property(lambda self: self.first.ui if self.sites else None)
    site_error = property(lambda self: self.first.error if self.sites else None)
    permit_info = SiteApp.permit_info  # it needs the permit and the clock only

    def rebuild_site(self):
        return self.pick_site().rebuild()

    def display_targets(self, site):
        return SiteApp.display_targets(site)

    def monitor(self):
        return self.pick_site().monitor()

    def http_monitor(self):
        return self.pick_site().http_monitor()

    def http_status(self):
        return self.pick_site().http_status()

    def background_state(self, channel='image'):
        return self.pick_site().background_state(channel)

    def setup_status(self):
        return self.pick_site().setup_status()

    def site_status(self, site_id=None, unit=None):
        """The status of the site's first page, or of the named page (`unit`)."""
        return (self.pick(site_id, unit) if unit else self.pick_site(site_id)).status() if self.sites else None

    # ---- actions: register a site, or act on exactly the named one (site_monitor / http_monitor do the work)
    def site_action(self, action, body):
        if action == 'backup':
            return self.backup_now(body)
        if action == 'stop-site':  # the whole site: image and HTTP of every page (no start-all exists)
            return self.pick_site(body.get('site_id')).stop_site(body)
        if action not in ('register', 'add-page'):
            one = self.pick(body.get('site_id'), body.get('unit'))
            if action == 'setup':
                return one.setup_step(body)
            if action == 'http':
                return one.http_action(body)
            if action == 'notify':
                return one.notify_action(body)
            if action == 'maintenance':
                return one.maintenance_action(body)
            if action in ('monitor', 'confirm'):
                return one.settings_action(action, body)
            if action not in ('baseline-update', 'baseline-approve', 'inspect'):
                raise ValueError('unknown action')
        if not self.lock.acquire(blocking=False):
            raise BlockingIOError('busy')
        try:
            now = utc_now()
            if action == 'register':
                one, out = self.register(body, now)
            elif action == 'add-page':
                one, out = self.add_page(body, now)
            else:
                out = one.inspect_now(now) if action == 'inspect' else one.baseline_action(action, body, now)
            one.rebuild()
            return out
        finally:
            self.lock.release()

    def register(self, body, now):
        from src.noxiworks.site_monitor import INTERVALS, Monitor
        from src.noxiworks.site_workflow import Site
        if len(self.sites) >= MAX_SITES:
            raise ValueError(f'登録できるサイトは{MAX_SITES}個までです')
        if body.get('interval_seconds') is not None and body['interval_seconds'] not in INTERVALS:
            raise ValueError('検査間隔は 15分・1時間・6時間・24時間 から選んでください')
        site = Site.register(self.data / 'sites', body.get('name'), body.get('url'), body.get('kinds'), body.get('owner_confirmed'), now)
        monitor = Monitor.create(site, now)  # monitoring on, first inspection due now: the scheduler starts it within seconds
        if body.get('interval_seconds') is not None:
            settings = monitor.load()
            settings['interval_seconds'] = body['interval_seconds']
            monitor.save(settings)
        one = SiteApp(self, site)
        self.sites = {**self.sites, site.info['site_id']: one}  # replaced, not mutated: the scheduler threads iterate it
        return one, {'site_id': site.info['site_id'], 'href': f"/site/{site.info['site_id']}/"}

    def add_page(self, body, now):
        """A further page of an existing site (same host): a unit folder of its own, image monitoring OFF, HTTP not configured. The caller holds the app lock."""
        from src.noxiworks.site_workflow import Site
        first = self.pick_site(body.get('site_id'))
        site = Site.register_page(first.site, body.get('path'), body.get('label'), body.get('kinds'), now)
        page = SiteApp(self, site, parent=first)
        first.pages = {**first.pages, site.root.name: page}  # replaced, not mutated: the scheduler threads iterate it
        first._overview = None
        return page, {'site_id': first.site_id, 'unit': page.unit, 'href': page.href()}

    # ---- long-term operation over the whole data folder
    def backup_folder(self):
        """Next to the data folder, never inside it."""
        return self.data.with_name(self.data.name + '-backups')

    def backup_now(self, body):
        """A verified local copy (src/noxiworks/backup.py) into a NEW folder; refused while an inspection runs. Nothing is uploaded or deleted."""
        from src.noxiworks import backup
        site_id = body.get('site_id') if body.get('scope') == 'site' else None
        if body.get('scope') not in ('all', 'site') or (site_id is not None and site_id not in self.sites) or (body.get('scope') == 'site' and site_id is None):
            raise ValueError('バックアップの対象が正しくありません')
        if not self.lock.acquire(blocking=False):
            raise BlockingIOError('busy')
        try:
            parent = self.backup_folder()
            parent.mkdir(exist_ok=True)
            try:
                done = backup.create(self.data, parent, utc_now(), site_id)
            except backup.BackupRefused as exc:
                raise ValueError(str(exc)) from None
            checked = backup.verify(done['path'])
            return {**{k: done[k] for k in ('ok', 'path', 'files', 'bytes', 'skipped', 'changed', 'problems')}, 'verified': checked['ok']}
        finally:
            self.lock.release()

    def storage(self):
        """Disk usage of the data folder by area and by site, rescanned at most once a minute."""
        import time
        from src.noxiworks import retention
        if self._storage is None or time.monotonic() - self._storage[0] > 60:
            kept = self.backup_folder()
            backups = sorted(p.name for p in kept.iterdir() if p.name.startswith('siteproof-backup-') and (p / 'MANIFEST.json').is_file()) if kept.is_dir() else []
            self._storage = (time.monotonic(), {**retention.data_usage(self.data), 'backup_folder': str(kept), 'backups': len(backups), 'last_backup': backups[-1] if backups else None})
        return self._storage[1]

    def environment(self):
        """導入環境の確認 (src/noxiworks/environment.py), read only, rescanned at most once a minute. The Docker probes are only asked as the real ones when
        `docker_found` is not injected (offline tests set it; the app itself never does)."""
        import time
        from src.noxiworks import environment
        if self._environment is None or time.monotonic() - self._environment[0] > 60:
            probes = {'background': self.background_query}
            if self.docker_found is not None:
                found = self.docker_found
                probes.update(docker_cli=lambda: 'docker', docker_engine=lambda: found, docker_image=lambda pinned: pinned if found else None)
            self._environment = (time.monotonic(), environment.report(self.data, probes))
        return self._environment[1]

    # ---- schedulers
    def tick(self):
        """One scheduler step over all sites, the one due first first. One site's error is shown on that site and never stops the others."""
        first = None
        for one in sorted(self.units(), key=lambda s: s.next_due()):
            if self.stop_event.is_set() or not self.lock.acquire(blocking=False):
                break
            try:
                entry = one.tick()
                first = first or entry
            except Exception as exc:
                one.error = 'scheduler: ' + type(exc).__name__ + ': ' + str(exc)[:200]
            finally:
                self.lock.release()
        return first

    def http_pass(self):
        """Start the due HTTP checks, each site in its own thread: a slow site or a long image capture never holds another site's check back."""
        for one in self.units():
            if one.http_thread is None or not one.http_thread.is_alive():
                one.http_thread = threading.Thread(target=one.http_tick, name='siteproof-http-' + one.unit, daemon=True)
                one.http_thread.start()

    def notify_pass(self):
        """E-mail, one site after the other (one connection at a time); a slow mail server never holds a check back."""
        for one in self.units():
            if not self.stop_event.is_set():
                one.notify_tick()

    def start_scheduler(self, every=2.0):
        def loop(step, seconds):
            while not self.stop_event.wait(seconds):
                try:
                    step()
                except Exception as exc:  # never kill the scheduler; the panel shows the error
                    if self.first:
                        self.first.error = 'scheduler: ' + type(exc).__name__ + ': ' + str(exc)[:200]
        self.scheduler = threading.Thread(target=loop, args=(self.tick, every), name='siteproof-monitor', daemon=True)
        self.scheduler.start()
        self.http_scheduler = threading.Thread(target=loop, args=(self.http_pass, 5.0), name='siteproof-http', daemon=True)
        self.http_scheduler.start()
        self.notify_scheduler = threading.Thread(target=loop, args=(self.notify_pass, 15.0), name='siteproof-notify', daemon=True)
        self.notify_scheduler.start()

    def stop(self):
        self.stop_event.set()

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

    def status(self, site_id=None, page_id=None):
        """`site` is the page the screen is about (the named site's named page, else its first page; or the only site); `sites` the list of all sites."""
        one = self.sites.get(site_id) if site_id else self.first if len(self.sites) == 1 else None
        if one is not None and page_id:
            one = one.pages.get(page_id, one)
        return {**self.state, 'runs': len(self.runs()), 'fixtures': {k: v[0] for k, v in FIXTURES.items()}, 'data': str(self.data),
                'site': one.status() if one else None, 'sites': [s.overview() for s in self.sites.values()], 'max_sites': MAX_SITES, 'storage': self.storage(),
                'site_problems': [{'folder': n, 'reason': r} for n, r in self.site_problems]}

    def pages(self, path):
        """-> (folder of generated pages, path inside it) for a GET path, a redirect (None, target) or None. /demo/... = the synthetic demo;
        /site/<id>/... = that site; / = the only site, or (none / several) the empty dashboard the app's panels fill. Never two on one page."""
        if path in ('/demo', *('/site/' + s for s in self.sites), *(f'/site/{s}/page/{p}' for s, one in self.sites.items() for p in one.pages)):
            return None, path + '/'
        if path.startswith('/demo/'):
            return self.ui, path[len('/demo/'):]
        if path.startswith('/site/'):
            site_id, _, rel = path[len('/site/'):].partition('/')
            one = self.sites.get(site_id)
            if one is None:
                return None
            if rel == 'page' or rel.startswith('page/'):  # a further page: /site/<site id>/page/<page id>/...
                _, _, rest = rel.partition('/')
                page_id, _, inside = rest.partition('/')
                page = one.pages.get(page_id)
                return (page.ui or self.empty_ui, inside) if page else None
            return one.ui or self.empty_ui, rel
        return (self.first.ui or self.empty_ui) if len(self.sites) == 1 else self.empty_ui, path.lstrip('/')


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
                asked = re.fullmatch(r'site=(site-[0-9a-f]{8})(?:&page=(site-[0-9a-f]{8}-p[2-9]))?', self.path.partition('?')[2])
                return self.json(200, {'token': app.token, **app.status(asked and asked.group(1), asked and asked.group(2))})
            if path == '/app/api/environment':  # the same checks as the session: only a same-origin page of the app reads it
                if self.headers.get('X-SiteProof-App') != '1' or self.headers.get('Sec-Fetch-Site', 'same-origin') != 'same-origin':
                    return self.json(403, {'error': 'forbidden'})
                return self.json(200, app.environment())
            if path in ('/app/app.js', '/app/app.css'):
                f = assets / path.rsplit('/', 1)[1]
                return self.send(200, f.read_bytes(), TYPES[f.suffix])
            found = app.pages(path)
            if found is None:
                return self.json(404, {'error': 'not found'})
            ui, rel = found
            if ui is None:
                return self.send(302, b'', 'text/plain', {'Location': rel})
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
    parser.add_argument('--data', type=Path, help='app data folder (created if missing; default: the folder chosen with --remember, else %%LOCALAPPDATA%%\\SiteProof)')
    parser.add_argument('--remember', action='store_true', help='with --data: use this folder from now on when --data is left out (writes <base>/settings.json; moves no data)')
    parser.add_argument('--where', action='store_true', help='print the data folder in use and exit (starts nothing)')
    parser.add_argument('--port', type=int, default=8765, help='127.0.0.1 port (0 = any free port)')
    parser.add_argument('--no-browser', action='store_true', help='do not open the default browser')
    parser.add_argument('--check-every', type=int, metavar='SECONDS', help='testing only: seconds between scheduled inspections (overrides the site setting)')
    args = parser.parse_args(argv)
    if args.check_every is not None and not 5 <= args.check_every <= 86400:
        parser.error('--check-every must be 5..86400 seconds')
    if args.remember and not args.data:
        parser.error('--remember needs --data <folder>')
    try:
        source = '--data で指定' if args.data else '前に選んだフォルダ' if settings_file().is_file() else '既定の場所'
        args.data = args.data or default_data()
        if args.remember:
            print(f'今後は --data を付けなくても、このフォルダを使います：{remember_data(args.data)}（データは移動していません）', flush=True)
    except DataFolderError as exc:
        print('SiteProof を起動できません：' + str(exc), flush=True)
        return 2
    if args.where:
        print(f'データフォルダ：{args.data.resolve()}（{source}' + ('' if args.data.is_dir() else '・まだありません。起動すると作られます') + '）', flush=True)
        return 0
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
