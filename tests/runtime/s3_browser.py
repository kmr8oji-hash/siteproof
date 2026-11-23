"""S3-1 untrusted capture client (Browser UID 1000, sandboxed Chromium, no capabilities, no credentials).

The production capture path, unchanged: m5_browser.Driver (PlaywrightDriver: audited proxy for the page context only, unreachable
browser-wide default route, request-audit collector) + src.worker.capture.capture. It differs from s1c_browser only in the proxy
binding: the single registered real host instead of the fixture. No fixture CA, no netlog, no extra launch switches, TLS checks on.
Output: one JSON metadata line, then the framed capture, the stability repeat; the request audit travels inside the metadata.
"""
import json
import os
import sys
import time

from src.comparison.profile import CaptureProfile
from src.runtime.browser import PlaywrightDriver, ResourceLimits
from src.worker.capture import capture, CaptureRequest
from tests.runtime import m5_browser as base
from tests.runtime.browser_process import IsolatedPlaywright, install_fixture_ca
from tests.runtime.s2b_browser import RealProxyBinding


def main():
    raw = sys.stdin.buffer.readline(16385)
    if len(raw) > 16384:
        raise ValueError('input cap')
    config = json.loads(raw)
    os.makedirs(os.environ['HOME'], exist_ok=True)
    if config.get('fixture_ca') is True:  # Offline fixture runs only: trust the generated fixture certificate.
        if not str(config.get('host', '')).endswith('.invalid'):
            raise ValueError('fixture CA is only ever installed for a .invalid fixture host')  # Never for a real site.
        install_fixture_ca()
    req = config['request']
    profile = CaptureProfile(req['profile']['profile_id'], req['profile']['attributes'])
    request = CaptureRequest(req['page_id'], profile, req['url'], req['baseline_id'])
    launcher = IsolatedPlaywright()
    driver = base.Driver(launcher, RealProxyBinding(config['proxy_port'], config['host']), ResourceLimits(**config['resources']),
                         is_mobile=profile.profile_id == 'Mobile')
    driver.stability_policy = req.get('stability')  # From the trusted Worker (capture plan); None = default policy.
    started = time.monotonic()
    output = capture(request, driver, driver.lease, driver.limits)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    repeat = getattr(driver, 'repeat', b'')
    probes = getattr(driver.lease, 'probes', [])
    # Evidence for a "<stage>_TIMEOUT" that is not the stage limit: how long the capture really ran, what the Playwright timeout was, and how the
    # proxy liveness probes went. The host ignores this key (it is kept in the saved stdout); nothing decides on it.
    diagnostics = {'elapsed_ms': elapsed_ms, 'stage_seconds': driver.limits.stage_seconds, 'total_seconds': driver.limits.seconds,
                   'last_playwright_timeout': PlaywrightDriver.last_timeout,
                   'lease_probes': {'count': len(probes), 'max_ms': max((p['ms'] for p in probes), default=0),
                                    'errors': [p for p in probes if p['error']][:8]}}
    base.emit({'length': len(output.wire), 'repeat_length': len(repeat), 'reason': output.reason, 'cleanup': output.cleanup_confirmed,
               'diagnostics': diagnostics, 'sandbox': launcher.sandbox,
               'browser_report': {'classification': 'BROWSER_SELF_REPORT', 'runtime': getattr(driver, 'report', {}),
                                  'request_audit': driver.request_audit(), 'stability': getattr(driver, 'stability', None),
                                  'is_mobile_instruction': driver.is_mobile}}, output.wire, repeat)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        sys.stderr.write(json.dumps({'failure': 'S3_BROWSER_FAILED', 'type': type(exc).__name__}) + '\n')
        raise SystemExit(1)
