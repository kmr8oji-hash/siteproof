"""S1-C-FIX untrusted capture client with stage markers. Investigation aid, not a trust source.

Same capture path as m5_browser (reused unchanged). It only wraps the Playwright sync API
to print a monotonic timestamp at each stage to stderr. The trusted proxy ledger uses the
same VM clock, so a record can be attributed to a stage after the fact. The markers are never
used to include/exclude traffic from a verdict; the verdict relies on the proxy's own order only.
Stage names stay short (< 24 chars) so the launcher's long-token log redaction leaves them intact.
"""
import json
import os
import re
import shutil
import sys
import time
from urllib.parse import urlsplit

from playwright.sync_api import Browser, BrowserType, Page

from tests.runtime import m5_browser as base
from tests.runtime.browser_process import IsolatedPlaywright, FixtureProxyBinding, install_fixture_ca
from src.comparison.profile import CaptureProfile
from src.runtime.browser import DISABLED_FEATURES
from src.runtime.browser import ResourceLimits
from src.worker.capture import capture, CaptureRequest
from src.isolation.frames import FrameLimits  # noqa: F401  (parity with m5_browser imports)


def mark(stage, **fields):
    sys.stderr.write(json.dumps({'t': round(time.monotonic(), 3), 'stage': stage, **fields}) + '\n')
    sys.stderr.flush()


def tmp_state():
    usage = shutil.disk_usage('/tmp')
    return {'tmp_free_mb': usage.free // 2**20, 'tmp_used_mb': usage.used // 2**20}


def wrap(cls, name, label, detail=None):
    original = getattr(cls, name)

    def wrapper(self, *args, **kwargs):
        mark(label + '_begin', **(detail(args, kwargs) if detail else {}))
        try:
            return original(self, *args, **kwargs)
        finally:
            mark(label + '_end')
    setattr(cls, name, wrapper)


def authority(args, kwargs):
    url = urlsplit(args[0]) if args else None  # Scheme and host only: never a path or query.
    return {'url': (url.scheme + '://' + (url.hostname or '')) if url else None}


FLAG = re.compile(r'--[a-z0-9-]+(=[A-Za-z0-9_,./:-]*)?\Z')
NETLOG = '/tmp/s1c-netlog.json'


def with_launch_flags(extra, netlog):
    """Investigation only: append vetted switches to the existing launch options."""
    if not all(type(a) is str and FLAG.match(a) for a in extra):
        raise ValueError('vetted switches only')
    original = BrowserType.launch

    def launch(self, *args, **kwargs):
        kwargs['args'] = [*kwargs.get('args', []), *extra, *(['--log-net-log=' + NETLOG] if netlog else [])]
        mark('launch_args', extra=extra, netlog=netlog)
        return original(self, *args, **kwargs)
    BrowserType.launch = launch


def with_context_proxy(port):
    """Investigation only: the page context alone uses the audited proxy; the browser-wide default is unreachable.

    Everything the browser does on its own (sign-in, updater, search-provider preconnect) then never
    reaches the audited proxy, while page requests do. Nothing is selected by host name.
    """
    launch_original, context_original = BrowserType.launch, Browser.new_context

    def launch(self, *args, **kwargs):
        kwargs['proxy'] = {'server': 'http://127.0.0.1:1', 'bypass': '<-loopback>'}
        mark('browser_wide_proxy', server='unreachable')
        return launch_original(self, *args, **kwargs)

    def new_context(self, *args, **kwargs):
        if 'viewport' in kwargs:  # The page context (PlaywrightDriver.start); not the sandbox self-check context.
            kwargs['proxy'] = {'server': f'http://127.0.0.1:{port}', 'bypass': '<-loopback>'}
            mark('context_proxy', server='audited')
        return context_original(self, *args, **kwargs)
    BrowserType.launch, Browser.new_context = launch, new_context


def features_guard():
    """The product repeats Playwright's default --disable-features (the last switch wins): it must still cover it."""
    import playwright
    source = open(os.path.join(os.path.dirname(playwright.__file__), 'driver/package/lib/coreBundle.js'),
                  encoding='utf-8').read()
    block = re.search(r'disabledFeatures = \[(.*?)\]\.filter', source, re.S).group(1)
    defaults = re.findall(r'"([A-Za-z0-9]+)"', re.sub(r'//[^\n]*', '', block))
    mark('features_guard', playwright_defaults=len(defaults), missing=[f for f in defaults if f not in DISABLED_FEATURES])


def netlog_summary():
    """Chromium's own URL-request log, reduced to scheme/host/path (no query) + source type."""
    try:
        raw = open(NETLOG, encoding='utf-8', errors='replace').read()
        try:
            data = json.loads(raw)
        except ValueError:
            data = json.loads(raw.rstrip().rstrip(',') + ']}')
        line = data['constants'].get('clientInfo', {}).get('command_line', '')
        found = re.findall(r'--disable-features=(\S+)', line)  # Chromium honours the LAST one.
        mark('effective_features', features=(found[-1].split(',') if found else None), switches=len(found),
             proxy_server=(re.search(r'--proxy-server=(\S+)', line) or [None, None])[1])
        types = {v: k for k, v in data['constants']['logEventTypes'].items()}
        sources = {v: k for k, v in data['constants']['logSourceType'].items()}
        rows = []
        for event in data.get('events', []):
            if types.get(event['type']) == 'URL_REQUEST_START_JOB':
                params = event.get('params', {})
                url = urlsplit(params.get('url', ''))
                rows.append({'ms': event.get('time'), 'src': sources.get(event['source']['type']),
                             'url': f'{url.scheme}://{url.hostname}{url.path}', 'flags': params.get('load_flags'),
                             'initiator': (params.get('initiator') or '')[:60]})
        mark('netlog', requests=rows[:80], total=len(rows))
        # Socket-level evidence for connections that are not URL requests (preconnects): event/source
        # type names and scalar parameters only; headers and anything long are dropped.
        google = []
        for event in data.get('events', []):
            if 'www.google.com' in json.dumps(event):
                params = {k: str(v)[:70] for k, v in event.get('params', {}).items() if k not in ('headers', 'line')}
                google.append({'ev': types.get(event['type']), 'src': sources.get(event['source']['type']),
                               'sid': event['source']['id'], 'p': params})
        mark('netlog_google', events=google[:40], total=len(google))
    except Exception as exc:
        mark('netlog_failed', type=type(exc).__name__)


class TimedBinding(FixtureProxyBinding):
    """Harness liveness probe with a longer connect timeout, recording every probe's latency.

    Same destination validation as FixtureProxyBinding; only the TCP liveness check to the owned proxy is
    more patient, so a rare scheduling stall is measured instead of being mistaken for a capture timeout.
    The product's ProxyLease.check does not open a socket at all.
    """
    def __init__(self, port, seconds):
        super().__init__(port)
        self.seconds = seconds

    def check(self, url=None):
        import socket
        from src.runtime.browser import RuntimeRefused
        from src.isolation.destination import check_authority
        if url is not None:
            u = urlsplit(url)
            fixture_http = (u.scheme == 'http' and u.hostname == 'fixture.invalid' and u.port in (None, 80))
            if (u.username or u.password or u.fragment or not (fixture_http or (
                    u.scheme == 'https' and check_authority(self.policy, u.hostname, u.port or 443).allowed))):
                raise RuntimeRefused('DESTINATION_REFUSED')
        started = time.monotonic()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.seconds)
                s.connect(('127.0.0.1', self.port))
        finally:
            mark('probe', ms=round((time.monotonic() - started) * 1000))
        return 'http://127.0.0.1:' + str(self.port)


def main():
    raw = sys.stdin.buffer.readline(16385)
    if len(raw) > 16384:
        raise ValueError('input cap')
    config = json.loads(raw)
    install_fixture_ca()
    mark('main_start', **tmp_state())
    features_guard()
    if config.get('extra_args') or config.get('netlog'):
        with_launch_flags(config.get('extra_args', []), config.get('netlog') is True)
    if config.get('context_proxy'):
        with_context_proxy(config['proxy_port'])
    wrap(BrowserType, 'launch', 'launch')
    wrap(Browser, 'new_context', 'context')
    wrap(Browser, 'close', 'close')
    wrap(Page, 'goto', 'goto', authority)
    wrap(Page, 'wait_for_load_state', 'load_wait')
    wrap(Page, 'screenshot', 'shot')
    req = config['request']
    profile = CaptureProfile(req['profile']['profile_id'], req['profile']['attributes'])
    request = CaptureRequest(req['page_id'], profile, req['url'], req['baseline_id'])
    launcher = IsolatedPlaywright()
    binding = TimedBinding(config['proxy_port'], config['probe_seconds']) if config.get('probe_seconds') else FixtureProxyBinding(config['proxy_port'])
    driver = base.Driver(launcher, binding, ResourceLimits(**config['resources']),
                         is_mobile=profile.profile_id == 'Mobile')
    output = capture(request, driver, driver.lease, driver.limits)
    mark('main_end', reason=output.reason, **tmp_state())
    if config.get('netlog'):
        netlog_summary()
    repeat = getattr(driver, 'repeat', b'')
    base.emit({'length': len(output.wire), 'repeat_length': len(repeat), 'reason': output.reason,
               'cleanup': output.cleanup_confirmed, 'sandbox': launcher.sandbox,
               'browser_report': {'classification': 'BROWSER_SELF_REPORT', 'runtime': getattr(driver, 'report', {}),
                                  'request_audit': driver.request_audit(), 'stability': getattr(driver, 'stability', None),
                                  'is_mobile_instruction': driver.is_mobile}}, output.wire, repeat)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        sys.stderr.write(json.dumps({'failure': 'S1C_BROWSER_FAILED', 'type': type(exc).__name__}) + '\n')
        raise SystemExit(1)
