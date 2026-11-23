"""Static pre-send guard for NEGATIVE (must-be-refused) browser tests. Pure: no I/O, no heavy imports, unit-testable on the host.

Why: `*.workers.dev` is HSTS-preloaded. A proxied `http://<registered host>/` negative test is therefore upgraded by Chromium to
`https://<registered host>/`, which IS an allowed destination, and the "refused" test becomes a real page fetch (S3-1, s3-gate-01).
Rule: a negative test that is routed through the audited proxy must never name the registered real host on a port the policy allows
(none/80/443), whatever the scheme. Refused BEFORE the browser sends anything. This does NOT restrict the real capture path, which
opens the approved https page on purpose and never uses this guard.
"""
from urllib.parse import urlsplit


class NegativeTestRefused(ValueError):
    pass


def refuse_registered_host(urls, registered_host):
    host = str(registered_host).lower().rstrip('.')
    for label, url in urls.items():
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            raise NegativeTestRefused(f'unparseable negative-test URL: {label}') from None
        if parts.hostname and parts.hostname.lower().rstrip('.') == host and port in (None, 80, 443):
            raise NegativeTestRefused(f'negative test would reach the registered host: {label}')
    return True


def proxied_negatives(config):
    """Negative tests routed THROUGH the audited proxy. None may be able to reach the registered host (see negative_guard)."""
    proxied = {'unregistered_name': 'https://unlisted-s2b.invalid/', 'www_subdomain': 'https://www.' + config['host'] + '/',
               'other_subdomain': 'https://cdn.' + config['host'] + '/', 'ip_literal': 'https://192.0.2.1/',
               # Plain http to an UNREGISTERED .invalid name: .invalid is never HSTS-preloaded, so nothing upgrades it.
               'plain_http_unregistered': 'http://plain-s2b.invalid/',
               'registered_host_other_port': 'https://' + config['host'] + ':8443/'}
    for skipped in config.get('skip_proxied', []):
        proxied.pop(skipped, None)
    proxied.update(config.get('extra_proxied', {}))  # Test hook for the guard itself; still guarded below.
    refuse_registered_host(proxied, config['host'])
    return proxied
