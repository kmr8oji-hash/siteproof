"""S1-C trusted Worker: offline fixture only, real Chromium via the owned CONNECT proxy.

Derived from m5_worker (unchanged) for the S1-A/S1-B operational verdict E2E. Adds only:
a page variant with two subresource references that the proxy must refuse/fail, a
fixture-only DNS failure for one allowlisted fixture name, explicit baseline approval, and
two audit-withholding run modes. No real site, no registry, no external resolver.
"""
import io
import json
import time

from playwright.sync_api import sync_playwright
from tests.runtime import linux_worker as base
from src.baseline.model import BaselineStatus
from src.bff.baseline import BFFLimits
from src.bff.local_ui import LocalBaselineHOME
from src.bridge.adapter import EvidenceBridge
from src.comparison.service import ComparisonService, PixelPolicy
from src.core.offline import OfflineWorkspace, profile_body
from src.isolation.connect_dns import DnsResolution
from src.isolation.destination import AllowedDestination
from src.isolation.frames import FrameReader, TrustedContext
from src.isolation.transport import ConnectTransport
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
# Never resolvable: no real name, no external DNS. blocked.invalid is simply not allowlisted.
SUBRESOURCES = ('<link rel="stylesheet" href="https://blocked.invalid/s1c.css">'
                '<link rel="stylesheet" href="https://down.invalid/s1c.css">')


class Handler(base.Handler):
    def do_GET(self):
        base.count('https' if getattr(self.server, 'is_tls', False) else 'http')
        if self.path.startswith('/slow'):
            time.sleep(12)
        color = '#d52c35' if VARIANT == 'changed' else '#213876'
        extra = SUBRESOURCES if VARIANT == 'blocked' else ''
        raw = ('<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
               '<title>S1-C fixture</title>' + extra + '<style>body{margin:0;background:#eef2ff;font:24px sans-serif;padding:24px;box-sizing:border-box}'
               'h1{color:' + color + '}*{animation:none!important;transition:none!important}</style>'
               '<h1>SiteProof S1-C fixture</h1><p>Controlled local HTTPS</p></html>').encode()
        try:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(raw)
        except (OSError, base.ssl.SSLError):
            pass


class Resolver(base.fixtures.ControlledResolver):
    def resolve_complete(self, hostname):
        if hostname == 'down.invalid':
            return DnsResolution(hostname, 'ERROR', False, False, ())  # Fixture-only DNS failure.
        return super().resolve_complete(hostname)


def make_proxy():
    """Same exact fixture capability as linux_worker.proxy(); other authorities take the production path."""
    limits = base.BudgetLimits(32 * 1024 * 1024, 64, 8, 128, 300)
    session = base.QuotaSession('fixture-runtime', base.NetworkBudget(limits, limits), base.IoLimits(16384, 65536),
                                termination_limits=base.TerminationLimits(3, 20))

    class S1CFixture(base.HTTPFixtureMixin, base.fixtures.FixtureTransport):
        def __init__(self):
            super().__init__(session, base.DestinationPolicy((AllowedDestination('fixture.invalid', 443),
                                                              AllowedDestination('down.invalid', 443))),
                             Resolver(), base.DnsLimits(8, 512), base.TransportLimits(4096, 2, .01, 16, 3),
                             endpoint=('127.0.0.1', base.TLS_PORT), listen_port=base.PROXY_PORT)
            self.authority = b'fixture.invalid:443'

        def _open_target(self, tunnel, authority, deadline):
            if authority == self.authority:
                return super()._open_target(tunnel, authority, deadline)
            # Production policy/DNS path: refuses before any resolution unless allowlisted.
            return ConnectTransport._open_target(self, tunnel, authority, deadline)

    proxy = S1CFixture()
    proxy.start()
    return base.ProxyLease(proxy)


class WithoutLedger:
    """Lease view that withholds the audit: the run must then be UNKNOWN, never "0 blocked"."""
    def __init__(self, lease):
        self._lease = lease

    def check(self, url=None):
        return self._lease.check(url)

    def stop(self):
        return self._lease.stop()


def main():
    global VARIANT
    if base.os.getuid() != 1001:
        raise RuntimeError('trusted Worker UID required')
    base.Handler = Handler
    http, thread, plain, plain_thread, cert = base.start_fixtures()
    root = base.ROOT
    db = root / 'siteproof.sqlite'
    workspace = OfflineWorkspace.create(db, root)
    workspace.save_site({'label': 'S1-C controlled fixture', 'origin': 'https://fixture.invalid', 'expected_revision': 0})
    workspace.save_page({'page_id': 'fixture-page', 'label': 'S1-C local fixture', 'path': '/', 'expected_revision': 0})
    initialize(db, root)
    worker = TrustedWorker(EvidenceBridge(EvidenceFinalizer(Repository(db), ArtifactStore(root))))
    service = RuntimeService(workspace, worker)
    # The UI listener is part of the shared preflight; no UI Chromium is started in S1-C.
    home = LocalBaselineHOME(db, root, offline=workspace, runtime=service, approval_actor='s1c-fixture-local-operator',
                             limits=BFFLimits(request_timeout_seconds=5, session_seconds=1800))
    home.start()
    lease = make_proxy()
    signer = observer = comparison = None
    resources = base.RESOURCES
    base.output({'type': 'ready', 'proxy_port': base.PROXY_PORT, 'ui_port': home.address[1],
                 'ca_pem': cert.read_text(), 'pairing_code': home.pairing_for_local_user(),
                 'namespace': base.os.readlink('/proc/self/ns/net'), 'uid': base.os.getuid(),
                 'resources': vars(resources)})

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
                lease = make_proxy()
                base.output({'type': 'proxy_ready', 'port': base.PROXY_PORT})
            elif kind == 'enable_m5':
                if comparison is not None:
                    raise RuntimeError('one initialization only')
                with sync_playwright() as pw:
                    executable = pw.chromium.executable_path
                observer = WorkerProfileObserver(command['image'], executable=executable)
                signer = EphemeralFixtureSigner(observer)
                initialize_comparison(db, root)
                comparison = ComparisonService(workspace, authority=signer.authority,
                    policy=PixelPolicy(0, 'S1-C controlled static fixture: exact RGBA equality; no production tolerance adoption'),
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
                batch = service.submit(source='REAL_CHROMIUM_FIXTURE_UNATTESTED')
                mark = lease.ledger.mark()
                run_lease = WithoutLedger(lease) if mode == 'no_ledger' else lease
                if mode == 'incomplete':
                    lease.ledger.begin()  # Injected: one CONNECT that never reports an outcome.
                state = service.run(batch, remote, run_lease, resources)
                base.output({'type': 'result', 'batch_id': batch, 'runtime': state, 'comparison': comparison.state(),
                             'ledger_total': lease.ledger.window(mark)})
            elif kind == 'approve':
                approved = []
                for cid in command['candidates']:
                    item = workspace.repo.baselines.read_page(limit=1, candidate_id=cid).items[0]
                    before = {'revision': item.record.revision, 'digest': item.record.registered_digest,
                              'current_version': item.current_version or 0}
                    workspace.repo.baselines.decide(cid, decision=BaselineStatus.APPROVED, actor='s1c-fixture-local-operator',
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
