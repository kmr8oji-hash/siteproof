"""S2-B trusted Worker: the PRODUCTION connect path (ConnectTransport + SystemResolver + real numeric dial)
for exactly ONE exact hostname from the registered monitoring target, only for the lifetime of this validation run.

Nothing here is a test double for the network: the resolver is the production SystemResolver, the dial is the
production `_dial`, TLS is verified with the default context (chain AND hostname, never disabled). The only
additions are recorders (every DNS answer set, every dialed address and peer) and the in-process, per-run switch
`site_policy.REAL_SITE_ACCESS_ENABLED`, which is flipped to True here and back to False before this process exits.
The repository default stays False: this process never changes the source file.

The registered target is read from src/noxiworks/targets.json (target_id `noxiworks-home`); a different host cannot be
passed in by the harness. No wildcard, no subdomain, no CDN is ever added.
"""
import json
import os
import socket
import ssl
import time
from urllib.parse import urlsplit

from tests.runtime import linux_worker as base
from src.isolation import site_policy
from src.isolation.connect_dns import DnsLimits, check_connect_authority
from src.isolation.destination import check_destination
from src.isolation.site_policy import RealSiteAccessDisabled, SiteEntry, SiteNetworkPlan, real_site_policy
from src.isolation.transport import ConnectTransport, SystemResolver, TransportLimits

TARGET_ID = 'noxiworks-home'
TARGETS = '/opt/siteproof/src/noxiworks/targets.json'
USER_AGENT = 'SiteProof-S2B-isolation-check'


def registered_host():
    config = json.load(open(TARGETS, encoding='utf-8'))
    page = next(p for p in config['pages'] if p['target_id'] == TARGET_ID)
    site = next(s for s in config['sites'] if s['site_id'] == page['site_id'])
    u, o = urlsplit(page['url']), urlsplit(site['origin'])
    if (u.scheme != 'https' or u.port not in (None, 443) or u.hostname != o.hostname or u.path != '/'
            or o.scheme != 'https' or o.port not in (None, 443) or u.username or u.password or u.query or u.fragment):
        raise RuntimeError('registered target is not a plain https origin')
    return u.hostname, page['url'], site


class RecordingResolver:
    """Production SystemResolver plus a record of every call and its complete answer set."""
    def __init__(self):
        self.inner, self.log = SystemResolver(), []

    def resolve_complete(self, hostname):
        started = time.monotonic()
        entry = {'host': hostname}
        self.log.append(entry)
        try:
            result = self.inner.resolve_complete(hostname)
        except BaseException as exc:
            entry.update(status='EXCEPTION', error=type(exc).__name__, ms=round((time.monotonic() - started) * 1000))
            raise
        entry.update(status=result.status, a_complete=result.a_complete, aaaa_complete=result.aaaa_complete,
                     addresses=list(result.addresses), ms=round((time.monotonic() - started) * 1000))
        return result


class RecordingTransport(ConnectTransport):
    """Production `_dial` unchanged; only records the numeric address dialed and the peer actually connected."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dialed = []

    def _dial(self, ip, port, deadline):
        entry = {'ip': ip, 'port': port}
        self.dialed.append(entry)
        try:
            handle = super()._dial(ip, port, deadline)
        except BaseException as exc:
            entry['error'] = type(exc).__name__ + (':' + str(exc.errno) if getattr(exc, 'errno', None) else '')
            raise
        entry['peer'] = list(handle.getpeername())
        return handle


STATE = {'lease': None, 'resolver': None, 'host': None, 'plan': None}


def start_real():
    host, url, site = registered_host()
    plan = SiteNetworkPlan('REAL', (SiteEntry(TARGET_ID, (host,)),), enabled=True)
    site_policy.REAL_SITE_ACCESS_ENABLED = True  # This process only, until stop_real.
    policy = real_site_policy(plan)
    limits = base.BudgetLimits(8 * 1024 * 1024, 32, 8, 64, 300)
    session = base.QuotaSession('s2b-real', base.NetworkBudget(limits, limits), base.IoLimits(16384, 65536),
                                termination_limits=base.TerminationLimits(8, 30))
    resolver = RecordingResolver()
    proxy = RecordingTransport(session, policy, resolver, DnsLimits(16, 1024), TransportLimits(4096, 3, .01, 16, 5),
                               listen_port=base.PROXY_PORT)
    proxy.start()
    STATE.update(lease=base.ProxyLease(proxy), resolver=resolver, host=host, plan=plan)
    return {'host': host, 'url': url, 'hostnames': [d.hostname for d in policy.allowlist],
            'ports': [d.port for d in policy.allowlist], 'site': {k: site.get(k) for k in ('site_id', 'name', 'origin', 'registration_domain')},
            'flag_during_run': site_policy.REAL_SITE_ACCESS_ENABLED}


def stop_real():
    confirmed = STATE['lease'].stop() if STATE['lease'] is not None else True
    site_policy.REAL_SITE_ACCESS_ENABLED = False
    try:
        real_site_policy(SiteNetworkPlan('REAL', (SiteEntry(TARGET_ID, ('noxiworks.com',)),), enabled=True))
        refused_after = False
    except RealSiteAccessDisabled:
        refused_after = True
    STATE['lease'] = None
    return {'stopped': confirmed, 'flag_after_stop': site_policy.REAL_SITE_ACCESS_ENABLED, 'real_policy_refused_after_stop': refused_after}


def policy_default():
    out = {'flag': site_policy.REAL_SITE_ACCESS_ENABLED}
    for label, enabled in (('plan_enabled_flag_off', True), ('plan_disabled', False)):
        try:
            real_site_policy(SiteNetworkPlan('REAL', (SiteEntry(TARGET_ID, ('noxiworks.com',)),), enabled=enabled))
            out[label] = 'POLICY_BUILT'
        except RealSiteAccessDisabled:
            out[label] = 'REFUSED'
    return out


def connect(authority, *, tls_host=None, request=None, wait=3):
    """One raw CONNECT to the owned proxy, as any client could send it. Optional strict TLS afterwards.

    `wait` only bounds this client; the Connector's own deadline (TerminationLimits) is what limits DNS and the dial."""
    out = {'authority': authority}
    with socket.create_connection(('127.0.0.1', base.PROXY_PORT), timeout=wait) as s:
        s.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode('ascii'))
        response = b''
        while not response.endswith(b'\r\n\r\n') and len(response) < 4096:
            try:
                part = s.recv(1024)
            except ConnectionResetError:
                break
            if not part:
                break
            response += part
        out['status'] = response.split(b'\r\n')[0].decode('ascii', 'replace')
        if not (out['status'].startswith('HTTP/1.1 200') and tls_host):
            return out
        context = ssl.create_default_context()  # Default verification: chain AND hostname. Never disabled.
        out['tls_verify'] = {'verify_mode': int(context.verify_mode), 'check_hostname': context.check_hostname}  # 2 == CERT_REQUIRED
        s.settimeout(15)
        try:
            with context.wrap_socket(s, server_hostname=tls_host) as tls:
                cert = tls.getpeercert()
                out['tls'] = {'result': 'OK', 'version': tls.version(), 'cipher': tls.cipher()[0],
                              'subject': [list(x[0]) for x in cert.get('subject', ())],
                              'issuer': [list(x[0]) for x in cert.get('issuer', ())],
                              'not_before': cert.get('notBefore'), 'not_after': cert.get('notAfter'),
                              'san_dns': [v for k, v in cert.get('subjectAltName', ()) if k == 'DNS'],
                              'verified_against': tls_host}
                tls.sendall(request)
                raw = b''
                while b'\r\n\r\n' not in raw and len(raw) < 16384:
                    part = tls.recv(4096)
                    if not part:
                        break
                    raw += part
                head = raw.split(b'\r\n\r\n')[0].decode('latin-1').split('\r\n')
                out['http_status'] = head[0]
                keep = ('server', 'content-type', 'location', 'strict-transport-security', 'content-length', 'cache-control')
                out['http_headers'] = {k.lower(): v.strip()[:200] for k, _, v in (h.partition(':') for h in head[1:]) if k.lower() in keep}
        except ssl.SSLCertVerificationError as exc:
            out['tls'] = {'result': 'CERT_VERIFY_FAILED', 'reason': exc.verify_message}
        except (ssl.SSLError, OSError) as exc:
            out['tls'] = {'result': type(exc).__name__}
    return out


def dns_diag():
    """Registered host only: one A query to the resolver this Worker uses (Docker embedded DNS). Reports timing and rcode."""
    labels = STATE['host'].split('.')
    question = b''.join(bytes([len(x)]) + x.encode('ascii') for x in labels) + b'\x00\x00\x01\x00\x01'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(12)
        started = time.monotonic()
        try:
            s.sendto(b'\x53\x32\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + question, ('127.0.0.11', 53))
            data = s.recv(512)
        except OSError as exc:
            return {'error': type(exc).__name__, 'ms': round((time.monotonic() - started) * 1000)}
    return {'rcode': data[3] & 15, 'answers': int.from_bytes(data[6:8], 'big'), 'ms': round((time.monotonic() - started) * 1000)}


def traced(lease, authority, **kwargs):
    proxy, resolver = lease.transport, STATE['resolver']
    mark, calls, dials = proxy.ledger.mark(), len(resolver.log), len(proxy.dialed)
    try:
        out = connect(authority, **kwargs)
    except OSError as exc:
        out = {'authority': authority, 'status': '', 'error': type(exc).__name__}
    deadline = time.monotonic() + kwargs.get('wait', 3)
    while proxy.ledger.window(mark)['in_flight'] and time.monotonic() < deadline:
        time.sleep(.02)
    window = proxy.ledger.window(mark)
    out.update(records=[[e['host'], e['port'], e['decision'], e['reason'], e['count']] for e in window['entries']],
               complete=window['complete'], resolutions=resolver.log[calls:], dialed=proxy.dialed[dials:])
    return out


def real_head(lease):
    host = STATE['host']
    out = traced(lease, host + ':443', tls_host=host, wait=20, request=(
        f'HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n\r\n').encode('ascii'))
    # The DNS answer set, classified by the production destination layer (the connector did exactly this before dialing).
    answers = next((r['addresses'] for r in out['resolutions'] if r.get('addresses')), [])
    decision = check_destination(lease.transport.policy, host, 443, answers) if answers else None
    out['destination_decision'] = None if decision is None else {'allowed': decision.allowed, 'reason': decision.reason,
                                                                    'addresses': list(decision.addresses)}
    location = (out.get('http_headers') or {}).get('location')
    if location:
        target = urlsplit(location)
        out['redirect'] = {'followed': False, 'target_scheme': target.scheme, 'target_host': target.hostname,
                           'target_port': target.port, 'same_host': target.hostname == host}
        if target.hostname and target.hostname != host:
            # Off-list target: what the browser would do next. Refused by policy before any resolution.
            out['redirect']['connect_result'] = traced(lease, f'{target.hostname}:{target.port or 443}')
    return out


def deny_matrix(lease, gateway):
    host = STATE['host']
    authorities = [f'www.{host}:443', f'evil.{host}:443', f'{host}.evil.invalid:443', f'*.{host}:443', f'{host}.:443',
                   f'{host}:80', f'{host}:8443', f'{host}:2375', 'unlisted-s2b.invalid:443', 'example.com:443',
                   'host.docker.internal:443', 'metadata.google.internal:443', 'localhost:443', '169.254.169.254:443',
                   '10.0.0.5:443', f'{gateway}:443', '[::1]:443', '[2001:db8::1]:443', f'{host}']
    return [traced(lease, authority) for authority in authorities]


def main():
    if os.getuid() != 1001:
        raise RuntimeError('trusted Worker UID required')
    for address, key in ((('127.0.0.2', 18555), 'tcp'), (('169.254.169.254', 80), 'metadata'), (('10.231.77.5', 18555), 'lan'),
                         (('127.0.0.4', 18555), 'host_model'), (('127.0.0.5', 2375), 'docker_api')):
        base.canary(address, key=key)
    base.canary(('127.0.0.3', 53), kind=socket.SOCK_DGRAM, key='dns')
    base.canary(('127.0.0.3', 5353), kind=socket.SOCK_DGRAM, key='udp')
    base.canary(('::1', 18555), family=socket.AF_INET6, key='ipv6')
    host, url, _ = registered_host()
    base.output({'type': 'ready', 'proxy_port': base.PROXY_PORT, 'namespace': os.readlink('/proc/self/ns/net'), 'uid': os.getuid(),
                 'resources': vars(base.RESOURCES), 'registered_host': host, 'registered_url': url,
                 'flag_at_start': site_policy.REAL_SITE_ACCESS_ENABLED})
    try:
        while True:
            command = base.command()
            kind = command.get('type')
            lease = STATE['lease']
            if kind == 'counts':
                with base.LOCK:
                    base.output({'type': 'counts', 'counts': dict(base.COUNTS)})
            elif kind == 'policy_default':
                base.output({'type': 'policy_default', **policy_default()})
            elif kind == 'start_real':
                base.output({'type': 'real_started', **start_real()})
            elif kind == 'stop_real':
                base.output({'type': 'real_stopped', **stop_real()})
            elif kind == 'real_head':
                base.output({'type': 'real_head', 'result': real_head(lease)})
            elif kind == 'dns_diag':
                base.output({'type': 'dns_diag', 'result': dns_diag()})
            elif kind == 'deny_matrix':
                base.output({'type': 'deny_matrix', 'results': deny_matrix(lease, command['gateway']), 'resolver_calls': len(STATE['resolver'].log)})
            elif kind == 'mark':
                base.output({'type': 'mark', 'mark': list(lease.ledger.mark()), 'resolutions': len(STATE['resolver'].log), 'dials': len(lease.transport.dialed)})
            elif kind == 'window':
                window = lease.ledger.window(tuple(command['mark']), (STATE['host'], 443))
                base.output({'type': 'window', 'window': window, 'resolutions': STATE['resolver'].log[command['resolutions']:],
                             'dialed': lease.transport.dialed[command['dials']:]})
            elif kind == 'quit':
                break
            else:
                raise ValueError('unknown trusted command')
    finally:
        confirmed = stop_real()
        for sock, t, stop in base.SERVERS:
            stop.set()
            sock.close()
            t.join(1)
        base.output({'type': 'closed', **confirmed, 'fixtures': all(not t.is_alive() for _, t, _ in base.SERVERS)})


if __name__ == '__main__':
    main()
