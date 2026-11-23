"""S2-A trusted Worker: the PRODUCTION connect path against a fully synthetic network. Offline fixture only.

Unlike s1c_worker (fixture short-cut for fixture.invalid), every destination here, including the
allowed fixture, goes through ConnectTransport._open_target unchanged: authority policy -> one DNS
resolution -> whole-answer address validation -> one numeric-IP dial -> peer verification.
Only two things are test-only and live in this file: the resolver (a fixed table, no real DNS) and
the dialer (a numeric test address is "dialed" by connecting to the local TLS fixture; any address not in
the table raises, so nothing can leave the container). Test hostnames are all `.invalid` and come from a
FIXTURE SiteNetworkPlan, which can never be a REAL plan.
"""
import io
import json
import socket
import ssl
import threading
import time
from collections import Counter

from playwright.sync_api import sync_playwright
from tests.runtime import linux_worker as base
from src.baseline.model import BaselineStatus
from src.bff.baseline import BFFLimits
from src.bff.local_ui import LocalBaselineHOME
from src.bridge.adapter import EvidenceBridge
from src.comparison.service import ComparisonService, PixelPolicy
from src.core.offline import OfflineWorkspace, profile_body
from src.isolation.connect_dns import DnsLimits, DnsResolution
from src.isolation.frames import FrameReader, TrustedContext
from src.isolation.site_policy import SiteEntry, SiteNetworkPlan, fixture_policy
from src.isolation.transport import ConnectTransport, SocketHandle, TransportLimits
from src.runtime.profile_observer import WorkerProfileObserver, EphemeralFixtureSigner
from src.runtime.service import RuntimeService
from src.storage.artifacts import ArtifactStore
from src.storage.comparison import initialize as initialize_comparison
from src.storage.finalizer import EvidenceFinalizer
from src.storage.repository import Repository
from src.storage.runtime import initialize
from src.worker.trusted import TrustedWorker


VARIANT = 'original'
SKIP_BROWSER_AUDIT = False

# Synthetic answers. None of these is ever connected to; the dialer below refuses every other address.
PUB = {'fixture': '11.22.33.44', 'ok2': '11.22.33.45', 'badcert': '11.22.33.46', 'mismatch': '11.22.33.47',
       'rebind': '11.22.33.48', 'v6ok': '2a05:d018:1::1'}
PEER_LIE = {PUB['mismatch']: '11.22.33.99'}  # The socket "turns out" to be connected to a different peer.
DIAL_MAP = set(PUB.values())
PRIVATE = '10.0.0.5'
ANSWERS = {
    'fixture.invalid': [[PUB['fixture']]], 'ok2.invalid': [[PUB['ok2']]], 'v6ok.invalid': [[PUB['v6ok']]],
    'badcert.invalid': [[PUB['badcert']]], 'mismatch.invalid': [[PUB['mismatch']]],
    'private.invalid': [[PRIVATE]], 'loopback.invalid': [['127.0.0.1']], 'metadata.invalid': [['169.254.169.254']],
    'v6loop.invalid': [['::1']], 'v6ula.invalid': [['fd00::5']], 'v4mapped.invalid': [['::ffff:10.0.0.5']],
    'nat64.invalid': [['64:ff9b::a00:5']], 'dockerhost.invalid': [['172.17.0.1']], 'hostgw.invalid': [['192.168.65.254']],
    'mixed.invalid': [[PUB['ok2'], PRIVATE]], 'mixed2.invalid': [[PRIVATE, PUB['ok2']]],
    # Rebinding: public on the first resolution, internal afterwards. Each CONNECT resolves exactly once.
    'rebind.invalid': [[PUB['rebind']], [PRIVATE]],
}
SPECIAL = {'dnserr.invalid': ('ERROR', True, True, ()), 'dnsincomplete.invalid': ('COMPLETE', True, False, (PUB['ok2'],)),
           'dnsempty.invalid': ('COMPLETE', True, True, ())}
TLS_HOSTS = ('fixture.invalid', 'ok2.invalid', 'v6ok.invalid', 'rebind.invalid')  # certificate SANs; badcert/mismatch lack one
PLAN = SiteNetworkPlan('FIXTURE', (SiteEntry('s2a-fixture', tuple(sorted({*ANSWERS, *SPECIAL}))),))

MATRIX = ['https://unlisted.invalid/a.css', 'https://host.docker.internal/a.css', 'https://private.invalid/a.css',
          'https://loopback.invalid/a.css', 'https://metadata.invalid/a.css', 'https://v6loop.invalid/a.css',
          'https://v6ula.invalid/a.css', 'https://v4mapped.invalid/a.css', 'https://nat64.invalid/a.css',
          'https://dockerhost.invalid/a.css', 'https://hostgw.invalid/a.css', 'https://mixed.invalid/a.css',
          'https://dnserr.invalid/a.css', 'https://169.254.169.254/a.css', 'https://10.0.0.5/a.css',
          'https://[::1]/a.css', 'https://[fd00::5]/a.css', 'https://docker-api.invalid:2375/a.css',
          'https://fixture.invalid:8443/a.css', 'http://169.254.169.254/a.css']
LINKS = {'notfound': ['https://fixture.invalid/missing.css'], 'ok2': ['https://ok2.invalid/a.css', 'https://v6ok.invalid/a.css', 'https://fixture.invalid/ok.css'],
         'matrix': MATRIX,
         'redirect': ['https://fixture.invalid/redir-blocked.css', 'https://fixture.invalid/redir-private.css',
                      'https://fixture.invalid/redir-same.css'],
         'badcert': ['https://badcert.invalid/a.css']}
REDIRECTS = {'/redir-blocked.css': 'https://unlisted.invalid/r.css', '/redir-private.css': 'https://private.invalid/r.css',
             '/redir-same.css': 'https://fixture.invalid/ok.css'}
BYPASS_SCRIPT = """<script>
const t=u=>{try{fetch(u,{mode:'no-cors'}).catch(()=>{})}catch(e){}};
t('https://169.254.169.254/latest/meta-data/');t('http://169.254.169.254/');t('http://127.0.0.1:18555/');
t('http://[::1]:18555/');t('http://127.0.0.2:18555/');t('http://10.231.77.5:18555/');t('http://127.0.0.5:2375/');
try{new WebSocket('wss://unlisted.invalid/ws')}catch(e){}
try{navigator.sendBeacon('https://unlisted.invalid/b','x')}catch(e){}
try{const pc=new RTCPeerConnection({iceServers:[{urls:'stun:127.0.0.3:5353'}]});pc.createDataChannel('x');
pc.createOffer().then(o=>pc.setLocalDescription(o)).catch(()=>{})}catch(e){}
new Image().src='https://unlisted.invalid/i.png';
</script>"""


class Handler(base.Handler):
    def do_GET(self):
        base.count('https' if getattr(self.server, 'is_tls', False) else 'http')
        path = self.path.split('?')[0]
        try:
            if path in REDIRECTS:
                self.send_response(302)
                self.send_header('Location', REDIRECTS[path])
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            if path == '/slow':
                time.sleep(12)  # A request that is still pending when the capture ends.
            if path == '/missing.css':
                self.send_response(404)
                self.send_header('Content-Type', 'text/css')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            if path.endswith('.css') or path == '/slow':
                raw, kind = b'/* s2a */', 'text/css'
            else:
                color = '#d52c35' if VARIANT == 'changed' else '#213876'
                links = ''.join(f'<link rel="stylesheet" href="{u}">' for u in LINKS.get(VARIANT, []))
                script = BYPASS_SCRIPT if VARIANT == 'bypass' else ("<script>fetch('/slow').catch(()=>{})</script>" if VARIANT == 'pending' else '')
                raw = ('<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                       '<title>S2-A fixture</title>' + links + '<style>body{margin:0;background:#eef2ff;font:24px sans-serif;padding:24px;box-sizing:border-box}'
                       'h1{color:' + color + '}*{animation:none!important;transition:none!important}</style>'
                       '<h1>SiteProof S2-A fixture</h1><p>Controlled local HTTPS</p>' + script + '</html>').encode()
                kind = 'text/html; charset=utf-8'
            self.send_response(200)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(raw)
        except (OSError, base.ssl.SSLError):
            pass


class TableResolver:
    """Fixed DNS answers; never resolves anything real. Counts every resolution."""
    def __init__(self):
        self.calls = Counter()

    def resolve_complete(self, hostname):
        index = self.calls[hostname]
        self.calls[hostname] += 1
        if hostname in SPECIAL:
            status, a, aaaa, addresses = SPECIAL[hostname]
            return DnsResolution(hostname, status, a, aaaa, addresses)
        if hostname not in ANSWERS:
            return DnsResolution(hostname, 'ERROR', False, False, ())
        sequence = ANSWERS[hostname]
        return DnsResolution(hostname, 'COMPLETE', True, True, tuple(sequence[min(index, len(sequence) - 1)]))


class PeerHandle(SocketHandle):
    def __init__(self, sock, peer):
        super().__init__(sock)
        self._peer = peer

    def getpeername(self):
        return self._peer


class S2ATransport(ConnectTransport):
    """Production `_open_target`, `_serve`, policy and ledger; only the dial is substituted."""
    def __init__(self, session, resolver):
        super().__init__(session, fixture_policy(PLAN), resolver, DnsLimits(8, 512), TransportLimits(4096, 2, .01, 16, 3),
                         listen_port=base.PROXY_PORT)
        self.dialed = []

    def _dial(self, ip, port, deadline):
        self.dialed.append((ip, port))
        if ip not in DIAL_MAP:
            raise OSError('test address is never dialed')  # Nothing can reach the network from here.
        handle = super()._dial('127.0.0.1', base.TLS_PORT, deadline)
        return PeerHandle(handle.socket, (PEER_LIE.get(ip, ip), port))


RESOLVER = TableResolver()


class StallMonitor(threading.Thread):
    """Records the acceptor's accept-queue depth, scheduler drift and load. Opens no connection."""
    def __init__(self):
        super().__init__(name='stall-monitor', daemon=True)
        self.stop_event, self.samples, self.anomalies, self.max_queue, self.max_drift = threading.Event(), 0, [], 0, 0.0

    @staticmethod
    def queue_depth(port=base.PROXY_PORT):
        try:
            for line in open('/proc/net/tcp').read().splitlines()[1:]:
                fields = line.split()
                if fields[3] == '0A' and int(fields[1].split(':')[1], 16) == port:
                    return int(fields[4].split(':')[1], 16)  # rx_queue of a LISTEN socket = accept-queue length
        except (OSError, ValueError, IndexError):
            return None
        return None

    def run(self):
        last = time.monotonic()
        while not self.stop_event.wait(.2):
            now = time.monotonic()
            drift, last = now - last - .2, now
            queue = self.queue_depth()
            self.samples += 1
            self.max_drift, self.max_queue = max(self.max_drift, drift), max(self.max_queue, queue or 0)
            if drift > .3 or (queue or 0) > 0:
                load = open('/proc/loadavg').read().split()[:3]
                self.anomalies.append({'t': round(now, 3), 'drift_ms': round(drift * 1000), 'accept_queue': queue,
                                       'loadavg': load, 'threads': threading.active_count()})
                del self.anomalies[:-50]

    def report(self):
        return {'samples': self.samples, 'max_accept_queue': self.max_queue, 'max_drift_ms': round(self.max_drift * 1000),
                'anomalies': self.anomalies}


STALL = StallMonitor()


def make_proxy():
    limits = base.BudgetLimits(32 * 1024 * 1024, 64, 8, 128, 300)
    session = base.QuotaSession('fixture-runtime', base.NetworkBudget(limits, limits), base.IoLimits(16384, 65536),
                                termination_limits=base.TerminationLimits(3, 20))
    proxy = S2ATransport(session, RESOLVER)
    proxy.start()
    return base.ProxyLease(proxy)


class WithoutLedger:
    def __init__(self, lease):
        self._lease = lease

    def check(self, url=None):
        return self._lease.check(url)

    def stop(self):
        return self._lease.stop()


def ensure_certificate():
    private = base.ROOT / 'private'
    private.mkdir(mode=0o700, exist_ok=True)
    cert, key = private / 'fixture.crt', private / 'fixture.key'
    if not cert.exists():
        names = ','.join('DNS:' + h for h in TLS_HOSTS)
        base.subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', str(key),
                             '-out', str(cert), '-subj', '/CN=fixture.invalid', '-addext', 'subjectAltName=' + names],
                            check=True, stdout=base.subprocess.DEVNULL, stderr=base.subprocess.DEVNULL)
        key.chmod(0o600)


def connect_through(proxy_port, authority, ca_pem=None, tls_host=None):
    """One raw CONNECT to the owned proxy, as any client could send it. Optional strict TLS afterwards."""
    out = {'authority': authority}
    with socket.create_connection(('127.0.0.1', proxy_port), timeout=3) as s:
        s.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode('ascii'))
        response = b''
        while not response.endswith(b'\r\n\r\n') and len(response) < 4096:
            try:
                part = s.recv(1024)
            except ConnectionResetError:  # The proxy closes right after a refusal; keep what was received.
                break
            if not part:
                break
            response += part
        out['status'] = response.split(b'\r\n')[0].decode('ascii', 'replace')
        if out['status'].startswith('HTTP/1.1 200') and ca_pem and tls_host:
            try:  # Default verification: certificate chain AND hostname. Never disabled.
                with ssl.create_default_context(cadata=ca_pem).wrap_socket(s, server_hostname=tls_host) as tls:
                    tls.sendall(b'GET /s2a HTTP/1.1\r\nHost: ' + tls_host.encode() + b'\r\nConnection: close\r\n\r\n')
                    out['tls'] = 'OK' if b'200' in tls.recv(4096).split(b'\r\n')[0] else 'BAD_RESPONSE'
            except ssl.SSLCertVerificationError:
                out['tls'] = 'CERT_VERIFY_FAILED'
            except (ssl.SSLError, OSError) as exc:
                out['tls'] = type(exc).__name__
    return out


def proxy_matrix(lease, ca_pem):
    """Raw CONNECT cases against the production path; per case: response, ledger record, resolutions, dials."""
    proxy = lease.transport
    cases = [
        ('fixture.invalid:443', 'fixture.invalid'), ('FIXTURE.INVALID:443', 'fixture.invalid'), ('ok2.invalid:443', 'ok2.invalid'),
        ('v6ok.invalid:443', 'v6ok.invalid'), ('badcert.invalid:443', 'badcert.invalid'), ('rebind.invalid:443', 'rebind.invalid'),
        ('rebind.invalid:443', 'rebind.invalid'),  # same name; the second resolution now answers an internal address
        ('unlisted.invalid:443', None), ('host.docker.internal:443', None),
        ('fixture.invalid.:443', None), ('169.254.169.254:443', None), ('10.0.0.5:443', None), ('[::1]:443', None),
        ('fixture.invalid:8443', None), ('fixture.invalid:80', None), ('docker-api.invalid:2375', None),
        ('private.invalid:443', None), ('loopback.invalid:443', None), ('metadata.invalid:443', None),
        ('v6loop.invalid:443', None), ('v6ula.invalid:443', None), ('v4mapped.invalid:443', None),
        ('nat64.invalid:443', None), ('dockerhost.invalid:443', None), ('hostgw.invalid:443', None),
        ('mixed.invalid:443', None), ('mixed2.invalid:443', None), ('dnserr.invalid:443', None),
        ('dnsincomplete.invalid:443', None), ('dnsempty.invalid:443', None),
        # A peer that is not the approved IP stops the whole QuotaSession (fail closed): last, then a follow-up
        # that must NOT succeed on the stopped session.
        ('mismatch.invalid:443', None), ('fixture.invalid:443', 'fixture.invalid')]
    results = []
    for authority, tls_host in cases:
        host = authority.rsplit(':', 1)[0].lower()
        mark, calls, dials = proxy.ledger.mark(), RESOLVER.calls[host], len(proxy.dialed)
        try:
            out = connect_through(base.PROXY_PORT, authority, ca_pem, tls_host)
        except OSError as exc:  # Only expected on the stopped session: no listener answers any more.
            out = {'authority': authority, 'status': '', 'error': type(exc).__name__}
        deadline = time.monotonic() + 3
        while proxy.ledger.window(mark)['in_flight'] and time.monotonic() < deadline:
            time.sleep(.02)
        window = proxy.ledger.window(mark)
        out.update(records=[[e['host'], e['port'], e['decision'], e['reason'], e['count']] for e in window['entries']],
                   complete=window['complete'], resolutions=RESOLVER.calls[host] - calls,
                   dialed=proxy.dialed[dials:])
        results.append(out)
    return results


def main():
    global VARIANT, SKIP_BROWSER_AUDIT
    if base.os.getuid() != 1001:
        raise RuntimeError('trusted Worker UID required')
    base.Handler = Handler
    ensure_certificate()
    http, thread, plain, plain_thread, cert = base.start_fixtures()
    base.canary(('127.0.0.5', 2375), key='docker_api')  # Controlled model of a Docker API endpoint.
    root = base.ROOT
    db = root / 'siteproof.sqlite'
    workspace = OfflineWorkspace.create(db, root)
    workspace.save_site({'label': 'S2-A controlled fixture', 'origin': 'https://fixture.invalid', 'expected_revision': 0})
    workspace.save_page({'page_id': 'fixture-page', 'label': 'S2-A local fixture', 'path': '/', 'expected_revision': 0})
    initialize(db, root)
    worker = TrustedWorker(EvidenceBridge(EvidenceFinalizer(Repository(db), ArtifactStore(root))))
    service = RuntimeService(workspace, worker)
    home = LocalBaselineHOME(db, root, offline=workspace, runtime=service, approval_actor='s2a-fixture-local-operator',
                             limits=BFFLimits(request_timeout_seconds=5, session_seconds=1800))
    home.start()
    lease = make_proxy()
    STALL.start()
    signer = observer = comparison = None
    resources = base.RESOURCES
    ca_pem = cert.read_text()
    base.output({'type': 'ready', 'proxy_port': base.PROXY_PORT, 'ui_port': home.address[1], 'ca_pem': ca_pem,
                 'pairing_code': home.pairing_for_local_user(), 'namespace': base.os.readlink('/proc/self/ns/net'),
                 'uid': base.os.getuid(), 'resources': vars(resources)})

    def remote(req, remaining):
        running = [j for j, _, _ in service.store.bindings() if service.repo.get_job(j).status.value == 'RUNNING']
        if len(running) != 1:
            raise RuntimeError('single active child required')
        jid = running[0]
        base.output({'type': 'capture', 'job_id': jid, 'request': {'page_id': req.page_id, 'profile': profile_body(req.profile),
                     'url': req.url, 'baseline_id': req.baseline_id}, 'remaining': remaining, 'resources': vars(resources)})
        reply = base.command()
        length = reply.get('length')
        repeat_length = reply.get('repeat_length', 0)
        if (reply.get('type') != 'capture_result' or type(length) is not int or type(repeat_length) is not int
                or min(length, repeat_length) < 0 or length + repeat_length > resources.output_bytes):
            raise ValueError('bounded producer payload required')
        wire = base.sys.stdin.buffer.read(length)
        repeat = base.sys.stdin.buffer.read(repeat_length)
        if len(wire) != length or len(repeat) != repeat_length:
            raise EOFError()
        # The page-request audit travels in the payload (bounded), not in the 4 KiB control line.
        audit_length = reply.get('audit_length', 0)
        if type(audit_length) is not int or not 0 <= audit_length <= 262144:
            raise ValueError('bounded audit payload required')
        audit_raw = base.sys.stdin.buffer.read(audit_length)
        if len(audit_raw) != audit_length:
            raise EOFError()
        try:
            request_audit = json.loads(audit_raw) if audit_raw else None
        except ValueError:
            request_audit = {'not': 'json'}  # Recorded as INVALID by the service, never repaired.
        observer.record_browser_report(jid, reply.get('browser_report', {}))
        if not SKIP_BROWSER_AUDIT:  # Untrusted report: rebuilt and validated by the service, usable only to lower a verdict.
            service.record_browser_audit(jid, request_audit)
        if repeat and reply.get('reason') == 'CAPTURE_COMPLETE':
            stream = FrameReader(io.BytesIO(wire), TrustedContext(jid, 'capture-1', 1)).read()
            png = next(f.payload for f in stream.frames if f.kind == 'SCREENSHOT_PNG')
            observer.record_repetition(jid, png, repeat, (reply.get('browser_report') or {}).get('stability'))
        return io.BytesIO(wire), reply['reason'], reply.get('cleanup') is True

    try:
        while True:
            command = base.command()
            kind = command.get('type')
            if kind == 'counts':
                with base.LOCK:
                    base.output({'type': 'counts', 'counts': dict(base.COUNTS)})
            elif kind == 'stop_proxy':
                base.output({'type': 'proxy_stopped', 'confirmed': lease.stop()})
            elif kind == 'restart_proxy':
                if not lease.stop():
                    raise RuntimeError('proxy cleanup unconfirmed')
                RESOLVER.calls.clear()
                lease = make_proxy()
                base.output({'type': 'proxy_ready', 'port': base.PROXY_PORT})
            elif kind == 'stall_report':
                base.output({'type': 'stall_report', 'report': STALL.report()})
            elif kind == 'proxy_matrix':
                base.output({'type': 'proxy_matrix', 'results': proxy_matrix(lease, ca_pem), 'dns_calls': dict(RESOLVER.calls)})
            elif kind == 'enable_m5':
                if comparison is not None:
                    raise RuntimeError('one initialization only')
                with sync_playwright() as pw:
                    executable = pw.chromium.executable_path
                observer = WorkerProfileObserver(command['image'], executable=executable)
                signer = EphemeralFixtureSigner(observer)
                initialize_comparison(db, root)
                comparison = ComparisonService(workspace, authority=signer.authority,
                    policy=PixelPolicy(0, 'S2-A controlled static fixture: exact RGBA equality; no production tolerance adoption'),
                    allow_unattested_preview=True)
                service.comparison = comparison
                home._comparison = comparison
                home._approval._candidate_validator = comparison.validate_candidate
                base.output({'type': 'enabled', 'observer': observer.report(), 'key_events': signer.events})
            elif kind == 'run':
                if comparison is None:
                    raise RuntimeError('preflight/observer not enabled')
                VARIANT = command.get('variant', 'original')
                mode = command.get('case', 'normal')
                SKIP_BROWSER_AUDIT = mode == 'no_browser_audit'
                batch = service.submit(source='REAL_CHROMIUM_FIXTURE_UNATTESTED')
                mark = lease.ledger.mark()
                dial_mark = len(lease.transport.dialed)
                resolver_mark = dict(RESOLVER.calls)
                run_lease = WithoutLedger(lease) if mode == 'no_ledger' else lease
                if mode == 'incomplete':
                    lease.ledger.begin()
                state = service.run(batch, remote, run_lease, resources)
                base.output({'type': 'result', 'batch_id': batch, 'runtime': state, 'comparison': comparison.state(),
                             'ledger_total': lease.ledger.window(mark), 'dialed': lease.transport.dialed[dial_mark:],
                             'dns_calls': {h: n - resolver_mark.get(h, 0) for h, n in RESOLVER.calls.items() if n != resolver_mark.get(h, 0)}})
            elif kind == 'approve':
                approved = []
                for cid in command['candidates']:
                    item = workspace.repo.baselines.read_page(limit=1, candidate_id=cid).items[0]
                    before = {'revision': item.record.revision, 'digest': item.record.registered_digest,
                              'current_version': item.current_version or 0}
                    workspace.repo.baselines.decide(cid, decision=BaselineStatus.APPROVED, actor='s2a-fixture-local-operator',
                        expected_revision=item.record.revision, reviewed_digest=item.record.registered_digest,
                        expected_current_version=item.current_version or 0)
                    approved.append({'candidate_id': cid, 'before': before, 'after': comparison.candidate_view(cid)})
                base.output({'type': 'approved', 'approvals': approved})
            elif kind == 'state':
                base.output({'type': 'state', 'runtime': service.state(), 'comparison': comparison.state()})
            elif kind == 'quit':
                break
            else:
                raise ValueError('unknown trusted fixture command')
    finally:
        STALL.stop_event.set()
        if signer:
            signer.destroy()
            (root / 'm5-key-events.json').write_text(json.dumps(signer.events, indent=2))
        if observer:
            (root / 'm5-observer.json').write_text(json.dumps(observer.report(), indent=2))
        proxy_clean = lease.stop()
        ui_clean = home.stop()
        http.shutdown()
        http.server_close()
        thread.join(3)
        plain.shutdown()
        plain.server_close()
        plain_thread.join(3)
        for sock, t, stop in base.SERVERS:
            stop.set()
            sock.close()
            t.join(1)
        base.output({'type': 'closed', 'proxy': proxy_clean, 'ui': ui_clean, 'key_revoked': signer.authority._key is None if signer else True,
                     'fixtures': all(not t.is_alive() for _, t, _ in base.SERVERS) and not thread.is_alive() and not plain_thread.is_alive()})


if __name__ == '__main__':
    main()
