"""Background monitoring with the app closed: a Windows Task Scheduler task that runs one `tick` every 15 minutes while the USER is
signed in. Registered only when the USER runs `install`; SiteProof never registers it by itself.

    py -3.15 -B tools/background_monitor.py install --data <app data folder> [--every 15] [--dry-run]
    py -3.15 -B tools/background_monitor.py status  --data <app data folder>
    py -3.15 -B tools/background_monitor.py remove  --data <app data folder>
    py -3.15 -B tools/background_monitor.py tick    --data <app data folder>     (what the task runs)

`tick` does nothing unless an inspection is due (monitor.json next_due_at). When one is due and the site is set up for real capture,
it starts Docker Desktop if its engine is not answering (waiting up to 3 minutes), then runs the same single pass as
`python -m src.noxiworks.site_monitor --data` -- the monitor lock keeps it from ever overlapping the app. Its output is appended to
<data>/background/tick.log. The task name is per data folder (SiteProof-Monitor-<site id>) and never touches other tasks.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.aws_b.model import parse_utc

DOCKER_WAIT_SECONDS = 180


def site_folder(data):
    sites = sorted(p for p in (Path(data) / 'sites').glob('site-*') if (p / 'site.json').is_file())
    return sites[0] if sites else None


def task_name(data):
    site = site_folder(data)
    return 'SiteProof-Monitor-' + (site.name if site else 'unregistered')


def launcher(data):
    """<data>/background/tick.cmd: the task's action (cwd = this worktree, no console window, output to tick.log)."""
    folder = Path(data).resolve() / 'background'
    folder.mkdir(parents=True, exist_ok=True)
    pyw = shutil.which('pyw') or 'pyw'
    cmd = folder / 'tick.cmd'
    cmd.write_text('@echo off\r\n'
                   f'cd /d "{ROOT}"\r\n'
                   'set PYTHONDONTWRITEBYTECODE=1\r\n'
                   f'"{pyw}" -3.15 -B tools\\background_monitor.py tick --data "{Path(data).resolve()}" >> "{folder / "tick.log"}" 2>&1\r\n',
                   encoding='ascii', newline='')  # CRLF as written above (no second conversion on Windows)
    return cmd


def schtasks(*args):
    return subprocess.run(['schtasks', *args], capture_output=True, text=True)


def install(data, every, dry_run):
    if site_folder(data) is None:
        raise SystemExit('no registered site in ' + str(data))
    cmd = launcher(data)
    args = ['/Create', '/F', '/SC', 'MINUTE', '/MO', str(every), '/TN', task_name(data), '/TR', f'"{cmd}"']
    if dry_run:
        print('schtasks ' + ' '.join(args))
        return 0
    p = schtasks(*args)
    print(p.stdout.strip() or p.stderr.strip())
    return p.returncode


def status(data):
    p = schtasks('/Query', '/TN', task_name(data), '/FO', 'LIST')
    print(p.stdout.strip() if p.returncode == 0 else f'{task_name(data)}: 登録されていません')
    log = Path(data) / 'background' / 'tick.log'
    if log.is_file():
        print('--- tick.log (last lines)')
        print('\n'.join(log.read_text('utf-8', errors='replace').splitlines()[-5:]))
    return 0


def remove(data):
    p = schtasks('/Delete', '/F', '/TN', task_name(data))
    print(p.stdout.strip() or p.stderr.strip())
    return p.returncode


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
    settings = json.loads((site / 'monitor.json').read_text('utf-8'))
    when = parse_utc(settings.get('next_due_at') or '')
    return settings.get('enabled') is True and when is not None and when <= now


def tick(data, now=None, docker=ensure_docker):
    from src.noxiworks import site_monitor
    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    site = site_folder(data)
    stamp = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    if site is None or not due(site, now):
        return 0
    if (site / 'real' / 'permit.json').is_file() and not docker():
        print(f'{stamp} Docker Desktop が応答しません（起動を待ちましたが応答なし）：この回は撮影せず、記録だけ残します')
    print(stamp, end=' ', flush=True)
    return site_monitor.main(['--data', str(data)])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=('install', 'status', 'remove', 'tick'))
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--every', type=int, default=15, help='minutes between ticks (install)')
    parser.add_argument('--dry-run', action='store_true', help='install: print the schtasks command only')
    args = parser.parse_args(argv)
    if args.action == 'install':
        return install(args.data, args.every, args.dry_run)
    if args.action == 'status':
        return status(args.data)
    if args.action == 'remove':
        return remove(args.data)
    return tick(args.data)


if __name__ == '__main__':
    raise SystemExit(main())
