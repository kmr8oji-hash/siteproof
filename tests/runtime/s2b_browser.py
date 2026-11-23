"""S2-B Browser (UID 1000, sandboxed Chromium, no capabilities). Two modes, both bounded and metadata-only.

  network   Direct (unproxied) navigations to targets that must all fail at the OS boundary, then proxied
            navigations to hosts the policy must refuse. Reports only error classes; no content.
  navigate  ONE top-level navigation of the registered page through the production PlaywrightDriver (audited proxy,
            unreachable browser-wide default route, request-audit collector) and a wait for `load`.
            NO screenshot, no page content, no title and no DOM is read or stored: only the HTTP status, the final
            host and the browser's own request-audit summary (untrusted, downgrade-only) leave this process.
"""
import json
import os
import socket
import sys
import time
from urllib.parse import urlsplit

from src.comparison.profile import CaptureProfile
from src.isolation.destination import AllowedDestination, DestinationPolicy, check_authority
from src.runtime.browser import PlaywrightDriver, ResourceLimits, RuntimeRefused
from tests.runtime.browser_process import IsolatedPlaywright
from tests.runtime.negative_guard import proxied_negatives

# Anything that proves a TCP/TLS exchange happened is a leak even though Chromium reports an "error" for it.
CONNECTED_ERRORS = ('ERR_CERT', 'ERR_SSL', 'ERR_BAD_SSL', 'ERR_HTTP', 'ERR_EMPTY_RESPONSE', 'ERR_RESPONSE')


class RealProxyBinding:
    """Pinned endpoint for the owned proxy plus the single registered host; no fallback and no other host."""
    def __init__(self, port, host):
        self.port, self.policy = port, DestinationPolicy((AllowedDestination(host, 443),))
        self.probes = []  # evidence only: how long each liveness probe of the proxy took and how it ended (bounded)

    def check(self, url=None):
        if url is not None:
            u = urlsplit(url)
            if (u.scheme != 'https' or u.username or u.password or u.fragment
                    or not check_authority(self.policy, u.hostname, u.port or 443).allowed):
                raise RuntimeRefused('DESTINATION_REFUSED')
        started, error = time.monotonic(), None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect(('127.0.0.1', self.port))
        except Exception as exc:
            error = type(exc).__name__
            raise  # unchanged: the probe still fails closed exactly as before
        finally:
            if len(self.probes) < 64:
                self.probes.append({'ms': int((time.monotonic() - started) * 1000), 'error': error})
        return 'http://127.0.0.1:' + str(self.port)


def attempt(context, url, seconds=1.5):
    page = context.new_page()
    try:
        page.goto(url, timeout=seconds * 1000, wait_until='commit')
        return {'reached': True, 'error': None}
    except Exception as exc:
        text = str(exc).split('\n')[0]
        token = next((w for w in text.replace('=', ' ').split() if w.startswith('net::ERR_')), None)
        return {'reached': False, 'error': token or ('Timeout' if 'Timeout' in text else type(exc).__name__)}
    finally:
        page.close()


def network(config):
    proxied = proxied_negatives(config)  # Before the browser exists: a refused test sends nothing at all.
    launcher, out = IsolatedPlaywright(), {}
    try:
        browser = launcher.open_browser()
        direct = {'canary_tcp': 'http://127.0.0.2:18555/', 'canary_metadata': 'http://169.254.169.254/',
                  'canary_lan': 'http://10.231.77.5:18555/', 'canary_host_model': 'http://127.0.0.4:18555/',
                  'canary_ipv6': 'http://[::1]:18555/', 'direct_dns_name': 'http://dns-probe.s2b.invalid/',
                  'documentation_http': 'http://192.0.2.1/', 'documentation_https': 'https://192.0.2.1/',
                  'bridge_gateway_http': 'http://' + config['gateway'] + '/', 'bridge_gateway_https': 'https://' + config['gateway'] + '/',
                  'desktop_host_model_https': 'https://192.168.65.254/', 'documentation_ipv6': 'https://[2001:db8::1]/'}
        # (Port 53 is a Chromium-restricted port: a navigation there fails before any socket, so the embedded resolver
        # is measured by the socket probe instead.)
        if config.get('real_ip'):
            direct['allowed_host_ip_direct_https'] = 'https://' + config['real_ip'] + '/'
            direct['allowed_host_ip_direct_http'] = 'http://' + config['real_ip'] + '/'
            direct['allowed_host_name_direct'] = 'https://' + config['host'] + '/'  # no proxy on this context
        # Deliberately direct contexts: the OS boundary alone must still deny.
        context = browser.new_context(service_workers='block')
        out['direct'] = {key: attempt(context, url, config.get('direct_seconds', 1.5)) for key, url in direct.items()}
        page = context.new_page()
        out['udp_attempt_completed'] = page.evaluate('''async()=>{const p=new RTCPeerConnection({iceServers:[{urls:'stun:127.0.0.3:5353'},{urls:'stun:192.0.2.1:3478'}]});p.createDataChannel('s2b');await p.setLocalDescription(await p.createOffer());await new Promise(r=>setTimeout(r,1200));p.close();return true;}''')
        context.close()
        context = browser.new_context(proxy={'server': 'http://127.0.0.1:' + str(config['proxy_port']), 'bypass': '<-loopback>'})
        out['proxied_refused'] = {key: attempt(context, url, config.get('proxied_seconds', 3)) for key, url in proxied.items()}
        context.close()
        out['sandbox'] = launcher.sandbox
        return out
    finally:
        launcher.close()


def navigate(config):
    host, url = config['host'], config['url']
    attributes = {'viewport_width': 1440, 'viewport_height': 900, 'device_scale_factor': 1, 'color_scheme': 'light', 'locale': 'ja-JP',
                  'timezone': 'Asia/Tokyo', 'user_agent': 'SiteProof-S2B-isolation-check', 'reduced_motion': True, 'full_page': False}
    profile = CaptureProfile('Desktop', attributes)
    launcher = IsolatedPlaywright()
    driver = PlaywrightDriver(launcher, RealProxyBinding(config['proxy_port'], host), ResourceLimits(**config['resources']))
    result = {'url_host': host}
    try:
        driver.start(profile)
        result['http_status'] = driver.http(url, 20)
        driver.load(20)
        result['final_host'] = urlsplit(driver.page.url).hostname
        result['final_path_is_root'] = urlsplit(driver.page.url).path == '/'
    except Exception as exc:
        result['error'] = type(exc).__name__
    finally:
        result['cleanup'] = driver.close()
    result['request_audit'] = driver.request_audit()
    result['sandbox'] = launcher.sandbox
    result['screenshot_taken'] = False
    return result


def main():
    config = json.loads(sys.stdin.buffer.readline(16385))
    os.makedirs(os.environ['HOME'], exist_ok=True)
    result = {'network': network, 'navigate': navigate}[config['mode']](config)
    print(json.dumps(result, separators=(',', ':')), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        sys.stderr.write(json.dumps({'failure': 'S2B_BROWSER_FAILED', 'type': type(exc).__name__}) + '\n')
        raise SystemExit(1)
