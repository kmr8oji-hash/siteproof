"""GUI rehearsal server: the REAL local app (src/noxiworks/app.py, same pages, same API, same scheduler) on an ISOLATED new data folder,
with stand-ins only where an action would leave this PC or touch the system. For driving the GUI in a browser (tests/ui/firefox_gui.py).

Stand-ins (each recorded in <data>/rehearsal-calls.jsonl):
  setup window   runs the REAL tools/setup_monitoring.py (after 3 s, so "セットアップ中" is visible), but non-interactively with a
                 SYNTHETIC key in <data>/../rehearsal-keys (no passphrase, --yes) instead of the USER's own window and key;
                 Cloudflare is a fake API (no network); the readiness check sees Docker as present (no `docker` call)
  harness        tests.ui.test_real_capture.FakeHarness (offline image producer; no Docker, no browser, no network)
  docker start   recorded only (no Docker)
  background     recorded only (no Windows task)
Usage: py -3.15 -B tests/ui/gui_rehearsal.py --data <NEW folder> [--port 8799]
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import threading
import time
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.noxiworks.app import serve
from tests.ui.test_real_capture import FakeHarness
from tests.ui.test_setup_monitoring import FakeCloudflare


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--port', type=int, default=8799)
    args = parser.parse_args(argv)
    if args.data.exists():
        parser.error('--data must be a NEW folder (isolated rehearsal data)')
    data = args.data.resolve()
    server, app = serve(data, args.port, scheduler=False)
    calls = data / 'rehearsal-calls.jsonl'
    keys = data.parent / (data.name + '-rehearsal-keys')

    def record(kind, argv):
        with calls.open('a', encoding='utf-8') as f:
            f.write(json.dumps({'at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'kind': kind, 'argv': argv}, ensure_ascii=False) + '\n')

    def setup_window(argv):
        from tools import setup_monitoring
        time.sleep(3)
        tool_args = argv[argv.index('tools/setup_monitoring.py') + 1:]
        tool_args = [a for a in tool_args if a != '--pause'] + ['--key', str(keys / 'synthetic'), '--no-passphrase', '--yes']
        docker_present = lambda root, now, real=setup_monitoring.readiness: real(root, now, docker_found=True)
        with mock.patch('tools.cf_ownership.wrangler_token', return_value='synthetic-token'), \
                mock.patch('tools.cf_ownership.find_wrangler', return_value=['wrangler']), \
                mock.patch('urllib.request.urlopen', FakeCloudflare()), mock.patch.object(setup_monitoring, 'readiness', docker_present):
            record('setup-tool-exit', setup_monitoring.main(tool_args))

    def launcher(argv, console=False):
        argv = [str(a) for a in argv]
        if 'tools/setup_monitoring.py' in argv:
            record('setup-window', argv)
            threading.Thread(target=setup_window, args=(argv,), daemon=True).start()
        elif argv[:3] == ['docker', 'desktop', 'start']:
            record('docker-start', argv)
        elif 'tools/background_monitor.py' in argv:
            record('background-' + argv[argv.index('tools/background_monitor.py') + 1], argv)
        else:
            raise OSError('unexpected launch in the rehearsal: ' + ' '.join(argv))

    app.docker_found, app.real_runner, app.launcher = True, FakeHarness(), launcher
    # background task state: as recorded by the stand-in (registered after an install, gone after a remove; no schtasks query)
    app.background_query = lambda *asked: (lambda kinds: bool(kinds) and kinds[-1] == 'background-install')(
        [json.loads(l)['kind'] for l in calls.read_text('utf-8').splitlines() if 'background' in l] if calls.is_file() else [])
    app.start_scheduler()
    print(f'GUI rehearsal: http://127.0.0.1:{server.server_address[1]}/  data: {data}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        app.stop()


if __name__ == '__main__':
    raise SystemExit(main())
