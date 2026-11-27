"""Background monitoring with the app closed: two independent Windows Task Scheduler tasks per site, registered only when the USER runs `install`
(SiteProof never registers one by itself). While the USER is signed in:

    image channel   every 15 min   `tick`       the image inspection (may start Docker Desktop, runs the browser harness)
    http channel    every  5 min   `http-tick`  the HTTP availability check only (no Docker, no browser, no image monitor)

    py -3.15 -B tools/background_monitor.py install --data <app data folder> [--site <id>] --channel image|http [--every N] [--dry-run]
    py -3.15 -B tools/background_monitor.py status  --data <app data folder> [--site <id>] [--channel image|http]
    py -3.15 -B tools/background_monitor.py remove  --data <app data folder> [--site <id>] --channel image|http   (--legacy: the old SiteProof-Monitor-<id> task only)
    py -3.15 -B tools/background_monitor.py tick|http-tick --data <app data folder> [--site <id>]               (what the tasks run)

--site may be left out only while exactly one site is registered (`status` without it lists every site and channel, read only, and prints the `remove` commands that stop
everything). The launcher .cmd is plain ASCII when every path is; with a Japanese (non-ASCII) path it is UTF-8 without BOM and starts with `chcp 65001 >nul`. The task name is per data folder, site AND channel: SiteProof-Image-<site id>-<h> /
SiteProof-Http-<site id>-<h>, h = first 8 hex of the SHA-256 of the resolved data folder path (case-folded), so two data folders, two sites or the two channels
never collide, and `remove` deletes only the task it names. The old name SiteProof-Monitor-<site id> is never created again: `status` mentions it (read only)
and `remove` touches it only with --legacy.

`tick` does nothing unless an inspection is due (monitor.json next_due_at). Without --site it looks at every registered site, one after the other (an old
tick.cmd without --site keeps working, image only). When a due site is set up for real capture it starts Docker Desktop if its engine is not answering (waiting
up to 3 minutes) -- only then -- and runs the same single pass as `python -m src.noxiworks.site_monitor --data --site`; the monitor lock keeps it from ever overlapping the app.
`http-tick` runs the HTTP check (src/noxiworks/http_monitor.py) of every site (or --site) whose http-monitor.json is enabled and due within the next every*60-20 seconds
(it waits for the due time, re-reading the settings so a stop is honoured at once), at most once per site and run, never catching up on missed checks, never re-enabling a
stopped or blocked monitor, never starting Docker, a browser or the image monitor. Each site has its own thread: a slow or broken site never holds another back.
Tasks stay per site and channel; both channels cover every page of the site (sites.units: the first page, then <site>/pages/*), each page with its own settings, and
one broken page never stops the others. After either channel the e-mail dispatch of each page runs (it does nothing unless the USER switched e-mail on). Output goes to <data>/background/<site id>-<channel>.log.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import threading
import time
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aws_b.model import parse_utc
from src.noxiworks import sites

DOCKER_WAIT_SECONDS = 180
CHANNELS = {'image': {'prefix': 'SiteProof-Image-', 'action': 'tick', 'every': 15}, 'http': {'prefix': 'SiteProof-Http-', 'action': 'http-tick', 'every': 5}}
LEGACY_PREFIX = 'SiteProof-Monitor-'
POLL_SECONDS = 5
WINDOW_MARGIN = 20


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def resolve_site(data, site_id=None):
    """The one site a command is about; SystemExit with the plain message when there is none / several and no --site."""
    try:
        return sites.resolve(data, site_id)
    except sites.SiteUnknown as exc:
        raise SystemExit(str(exc)) from None


def site_folder(data, site_id=None):
    return resolve_site(data, site_id)


def data_hash(data):
    return hashlib.sha256(str(Path(data).resolve()).casefold().encode('utf-8')).hexdigest()[:8]


def task_name(data, site_id=None, channel='image'):
    """SiteProof-Image-<site id>-<h> / SiteProof-Http-<site id>-<h>."""
    if channel not in CHANNELS:
        raise ValueError('channel')
    return f"{CHANNELS[channel]['prefix']}{site_id or resolve_site(data).name}-{data_hash(data)}"


def legacy_task_name(data, site_id=None):
    return LEGACY_PREFIX + (site_id or resolve_site(data).name)


def interpreter():
    """The Python the task runs: the one running this tool (sys.executable, so a venv stays a venv and no other Python on PATH is
    picked up; any version). Its windowless pythonw.exe when it sits next to it, else the interpreter itself (a console window then
    opens at each tick). Never a version switch (`pyw -3.x`). SystemExit with a plain message when no such file exists."""
    exe = Path(sys.executable) if sys.executable else None
    candidates = []
    if exe is not None:
        if exe.stem.lower() == 'python':
            candidates.append(exe.with_name('pythonw' + exe.suffix))
        candidates.append(exe)
    for path in candidates:
        if path.is_file():
            return path.resolve()
    raise SystemExit('バックグラウンド監視に使うPythonの実行ファイルが見つかりません（sys.executable: ' + (sys.executable or '空') + '）。'
                     'タスクは登録していません。SiteProofを動かしているPythonで、もう一度実行してください')


def batch_text(text):
    return str(text).replace('%', '%%')  # cmd expands %VAR% inside a batch file


def batch_problem(*paths):
    """None, or why a path cannot be written into a batch file: a control or invisible character, a quote or something UTF-8 cannot hold."""
    for text in map(str, paths):
        for ch in text:
            if ch == '"' or unicodedata.category(ch) in ('Cc', 'Cf', 'Cs', 'Co', 'Cn'):
                return f'パスに使えない文字（{ch!r}）があります'
        try:
            text.encode('utf-8')
        except UnicodeEncodeError:
            return 'パスにUTF-8で表せない文字があります'
    return None


def launcher(data, site_id=None, channel='image', every=None):
    """<data>/background/<site id>-<channel>.cmd: the task's action (cwd = this worktree, output to <site id>-<channel>.log, the same Python as this tool).
    All paths ASCII: the file is plain ASCII, as it always was. Otherwise it is UTF-8 without BOM and its second line is `chcp 65001 >nul`, so cmd reads the paths
    (Japanese folder names) correctly. Control characters, quotes and characters UTF-8 cannot hold in a path are still refused (nothing is written)."""
    python = interpreter()  # before anything is written: no usable Python, no task
    site = site_id or resolve_site(data).name
    folder = Path(data).resolve() / 'background'
    log, shown = folder / f'{site}-{channel}.log', (batch_text(ROOT), batch_text(python), batch_text(Path(data).resolve()))
    problem = batch_problem(ROOT, python, folder, *shown)
    if problem:
        raise SystemExit(problem + '。使える文字のパスにしてください。タスクは登録していません')
    folder.mkdir(parents=True, exist_ok=True)
    cmd = folder / f'{site}-{channel}.cmd'
    extra = f' --every {int(every)}' if channel == 'http' and every else ''
    utf8 = not all(str(x).isascii() for x in (ROOT, python, folder, *shown))
    cmd.write_text('@echo off\r\n' + ('chcp 65001 >nul\r\n' if utf8 else '')
                   + f'cd /d "{batch_text(ROOT)}"\r\n'
                   'set PYTHONDONTWRITEBYTECODE=1\r\n'
                   f'"{batch_text(python)}" -B tools\\background_monitor.py {CHANNELS[channel]["action"]} --data "{batch_text(Path(data).resolve())}" --site {site}{extra}'
                   f' >> "{batch_text(log)}" 2>&1\r\n',
                   encoding='utf-8' if utf8 else 'ascii', newline='')  # CRLF as written above (no second conversion on Windows); utf-8 without BOM
    return cmd


def schtasks(*args):
    return subprocess.run(['schtasks', *args], capture_output=True, text=True)


def install(data, every=None, dry_run=False, site_id=None, channel='image'):
    site = resolve_site(data, site_id).name
    every = CHANNELS[channel]['every'] if every is None else every
    if not 1 <= every <= 1439:
        raise SystemExit('--every は 1〜1439（分）で指定してください')
    cmd = launcher(data, site, channel, every)
    args = ['/Create', '/F', '/SC', 'MINUTE', '/MO', str(every), '/TN', task_name(data, site, channel), '/TR', f'"{cmd}"']
    if dry_run:
        print('schtasks ' + ' '.join(args))
        return 0
    p = schtasks(*args)
    print(p.stdout.strip() or p.stderr.strip())
    return p.returncode


def status(data, site_id=None, channel=None):
    """Read only (`schtasks /Query` only). Without --site: every registered site (with exactly one site that is the same as before), each channel; then, for what IS registered,
    the exact `remove` commands that stop everything (nothing is run here)."""
    names = [s.name for s in scope(data, site_id)] or [resolve_site(data).name]
    registered = []
    for site in names:
        if len(names) > 1:
            print(f'=== {site}')
        for name in ([channel] if channel else list(CHANNELS)):
            task = task_name(data, site, name)
            p = schtasks('/Query', '/TN', task, '/FO', 'LIST')
            print(p.stdout.strip() if p.returncode == 0 else f'{task}: 登録されていません')
            if p.returncode == 0:
                registered.append((site, name))
            log = Path(data) / 'background' / f'{site}-{name}.log'
            if log.is_file():
                print(f'--- {log.name} (last lines)')
                print('\n'.join(log.read_text('utf-8', errors='replace').splitlines()[-5:]))
        if schtasks('/Query', '/TN', legacy_task_name(data, site)).returncode == 0:  # read only: never changed here
            print(f'注意：古い名前のタスク {legacy_task_name(data, site)} が登録されています（このツールは作りません）。不要なら remove --legacy で解除できます')
    if registered:
        print('すべて止めるには（あなたが実行します。ここでは何も解除していません）：')
        for site, name in registered:
            print(f'  py -3.15 -B tools/background_monitor.py remove --data "{Path(data).resolve()}" --site {site} --channel {name}')
        print('  ※ 画面の「このサイトの監視をすべて停止」は、監視の設定を止めます（タスクは残りますが、停止中の監視は撮影も検査もしません）。')
    else:
        print('登録されているバックグラウンドのタスクはありません。')
    return 0


def remove(data, site_id=None, channel=None, legacy=False):
    site = resolve_site(data, site_id).name
    code = 0
    for task in ([task_name(data, site, channel)] if channel else []) + ([legacy_task_name(data, site)] if legacy else []):
        p = schtasks('/Delete', '/F', '/TN', task)
        print(p.stdout.strip() or p.stderr.strip())
        code = code or p.returncode
    return code


def docker_answers():
    try:
        return subprocess.run(['docker', 'info', '--format', '{{.ServerVersion}}'], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def ensure_docker(answers=docker_answers, start=lambda: subprocess.run(['docker', 'desktop', 'start'], capture_output=True, timeout=120),
                  wait=DOCKER_WAIT_SECONDS, sleep=time.sleep):
    if answers():
        return True
    try:
        start()
    except (OSError, subprocess.TimeoutExpired):
        return False
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if answers():
            return True
        sleep(5)
    return False


def due(site, now):
    try:
        settings = json.loads((Path(site) / 'monitor.json').read_text('utf-8'))
    except (OSError, ValueError):
        return False
    when = parse_utc(settings.get('next_due_at') or '') if isinstance(settings, dict) else None
    return isinstance(settings, dict) and settings.get('enabled') is True and when is not None and when <= now


def scope(data, site_id=None):
    return [resolve_site(data, site_id)] if site_id else sites.folders(data)


def dispatch(site, now_fn=utc_now):
    """The site's e-mail dispatch after a tick: does nothing unless the USER switched e-mail on; a failure never takes the tick down."""
    try:
        from src.noxiworks.notify_dispatch import Dispatcher
        from src.noxiworks.site_workflow import Site
        out = Dispatcher(Site(site)).run(now_fn())
        if isinstance(out, dict) and out.get('sent'):
            print(f'{site.name} メール通知：{out["sent"]}通を処理しました', flush=True)
        elif out == 'busy':
            print(f'{site.name} メール通知：別の処理が動いています', flush=True)
    except Exception as exc:
        print(f'{site.name} メール通知のエラー：{type(exc).__name__}', flush=True)


def tick(data, now=None, docker=ensure_docker, site_id=None):
    """The image channel only: every due site (or --site), one after the other. -> 0, or 1 when an inspection failed."""
    from src.noxiworks import site_monitor
    now = now or utc_now()
    stamp = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    found = scope(data, site_id)
    waiting = [s for s in found if any(due(u, now) for u in sites.units(s))]  # a site is due when any of its pages is
    if any((u / 'real' / 'permit.json').is_file() for s in waiting for u in sites.units(s) if due(u, now)) and not docker():
        print(f'{stamp} Docker Desktop が応答しません（起動を待ちましたが応答なし）：この回は撮影せず、記録だけ残します', flush=True)
    code = 0
    for site in waiting:
        print(stamp, site.name, end=' ', flush=True)
        try:
            code = site_monitor.main(['--data', str(data), '--site', site.name]) or code
        except Exception as exc:  # one site never stops the next
            print('error:', type(exc).__name__, flush=True)
            code = code or 1
    for site in found:
        for unit in sites.units(site):
            dispatch(unit)
    return code


def http_settings(site):
    try:
        s = json.loads((Path(site) / 'http-monitor.json').read_text('utf-8'))
    except (OSError, ValueError):
        return None
    return s if isinstance(s, dict) and s.get('enabled') is True else None


def http_due(site):
    s = http_settings(site)
    return parse_utc(s.get('next_due_at') or '') if s else None


def check_site(site, window_end, now_fn, sleep, poll):
    """Wait for this site's due time (not beyond `window_end`), then make the one check. A stop during the wait is honoured at once."""
    from src.noxiworks.http_monitor import Busy, HttpMonitor
    from src.noxiworks.site_workflow import Site
    try:
        while True:
            when = http_due(site)  # re-read every time: stopped, changed, or made by the app meanwhile
            if when is None:
                return
            now = now_fn()
            if when > window_end:
                return
            if now >= when:
                break
            sleep(min(poll, max(0.0, (when - now).total_seconds())))
        obs = HttpMonitor(Site(site)).run_if_due(now_fn(), now_fn)
        if obs is not None:
            print(site.name, 'HTTP', obs.get('blocked') and 'blocked: ' + obs['blocked'] or obs['state'], flush=True)
    except Busy:
        print(site.name, 'HTTP busy', flush=True)
    except Exception as exc:  # never takes the tick down
        print(site.name, 'HTTP check error:', type(exc).__name__, flush=True)


def http_tick(data, every=5, site_id=None, now_fn=utc_now, sleep=time.sleep, poll=POLL_SECONDS):
    """The HTTP channel only. -> 0 always (the task never fails because a site did)."""
    from datetime import timedelta
    found = [unit for site in scope(data, site_id) for unit in sites.units(site)]  # every page of the site(s), the first page included
    window_end = now_fn() + timedelta(seconds=every * 60 - WINDOW_MARGIN)
    todo = sorted((s for s in found if http_due(s) is not None and http_due(s) <= window_end), key=http_due)
    threads = [threading.Thread(target=check_site, args=(s, window_end, now_fn, sleep, poll), name='siteproof-http-tick-' + s.name, daemon=True) for s in todo]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for site in found:  # in turn, after the checks (one mail connection at a time): none is left for the next tick because another site's was running
        dispatch(site, now_fn)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=('install', 'status', 'remove', 'tick', 'http-tick'))
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--site', help='the site id (may be left out only while exactly one site is registered)')
    parser.add_argument('--channel', choices=tuple(CHANNELS))
    parser.add_argument('--every', type=int, help='minutes between runs (install; default 15 image / 5 http; http-tick: the window)')
    parser.add_argument('--dry-run', action='store_true', help='install: print the schtasks command only')
    parser.add_argument('--legacy', action='store_true', help='remove: the old SiteProof-Monitor-<id> task (only with this flag)')
    args = parser.parse_args(argv)
    if args.action == 'install' and not args.channel:
        parser.error('--channel image|http is required')
    if args.action == 'remove' and not args.channel and not args.legacy:
        parser.error('--channel image|http (or --legacy) is required')
    if args.action == 'install':
        return install(args.data, args.every, args.dry_run, args.site, args.channel)
    if args.action == 'status':
        return status(args.data, args.site, args.channel)
    if args.action == 'remove':
        return remove(args.data, args.site, args.channel, args.legacy)
    if args.action == 'http-tick':
        return http_tick(args.data, args.every or CHANNELS['http']['every'], args.site)
    return tick(args.data, site_id=args.site)


if __name__ == '__main__':
    raise SystemExit(main())
