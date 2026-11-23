"""Temporary S1 runtime with synthetic trusted observations. No browser/network."""
from pathlib import Path
from urllib.parse import urlsplit
import tempfile
import secrets

from src.bridge.adapter import EvidenceBridge
from src.comparison import preview
from src.comparison.provenance import TrustedProfileAuthority
from src.comparison.service import ComparisonService, PixelPolicy
from src.core.offline import OfflineWorkspace
from src.isolation.ledger import ConnectLedger
from src.runtime.browser import ResourceLimits
from src.runtime.request_audit import RequestAuditCollector, unavailable as audit_unavailable
from src.runtime.service import RuntimeService
from src.storage.artifacts import ArtifactStore
from src.storage.comparison import initialize as initialize_comparison
from src.storage.finalizer import EvidenceFinalizer
from src.storage.repository import Repository
from src.storage.runtime import initialize as initialize_runtime
from src.worker.capture import capture, MemoryChannel
from src.worker.trusted import TrustedWorker


class _Context:
    def __init__(self):
        self.handlers = {}

    def on(self, name, handler):
        self.handlers[name] = handler


class _Request:
    def __init__(self, url='https://fixture.invalid/', kind='document', failure=None, navigation=False):
        self.url, self.resource_type, self.failure, self._navigation = url, kind, failure, navigation

    def is_navigation_request(self):
        return self._navigation


class _Response:
    def __init__(self, request, status):
        self.request, self.url, self.status = request, request.url, status


def synthetic_browser_audit(kind='ok'):
    """What the real collector reports for a synthetic page load, produced by the real collector class.

    kind: ok | tls | load | http404 | pending | unfinalized | attach_failed | handler_error | unavailable | none
    """
    if kind == 'none':
        return None
    if kind == 'unavailable':
        return audit_unavailable('MONITOR_NOT_STARTED')
    if kind == 'invalid':
        return {'schema': 'siteproof.browser-audit.v1', 'source': 'BROWSER_SELF_REPORT', 'requests': 'many'}
    collector, context = RequestAuditCollector(), _Context()
    collector.attach(object() if kind == 'attach_failed' else context)
    if kind != 'attach_failed':
        page = _Request(navigation=True)
        context.handlers['request'](page)
        context.handlers['requestfinished'](page)
        if kind in ('tls', 'load', 'http404', 'pending'):
            sub = _Request('https://sub.invalid/a.css?token=secret', 'stylesheet',
                           failure={'tls': 'net::ERR_CERT_COMMON_NAME_INVALID', 'load': 'net::ERR_CONNECTION_RESET'}.get(kind))
            context.handlers['request'](sub)
            if kind in ('tls', 'load'):
                context.handlers['requestfailed'](sub)
            elif kind == 'http404':
                context.handlers['response'](_Response(sub, 404))
                context.handlers['requestfinished'](sub)
        if kind == 'handler_error':
            context.handlers['requestfailed'](object())  # Not a request: the handler raises, the audit must say so.
    return collector.summary(final=kind != 'unfinalized')


LIMITS = ResourceLimits(10, 1, 1024*1024, 128*1024*1024, 16, 64, 10, 1024*1024)
KEY = secrets.token_bytes(32)  # Ephemeral per test process; never persisted.


def observations(profile, phase, job_id):
    result = {name: {'value': value, 'source': 'worker:synthetic-enforced-context'}
              for name, value in profile.attributes.items()}
    result.update({name: {'value': value, 'source': source} for name, value, source in (
        ('os', 'SyntheticLinux', 'launcher:synthetic-image-inspect'),
        ('architecture', 'fixture-amd64', 'launcher:synthetic-image-inspect'),
        ('browser_version', 'fixture-browser-1', 'worker:synthetic-binary-manifest'),
        ('playwright_version', 'fixture-playwright-1', 'worker:synthetic-package-manifest'),
        ('image_digest', 'a'*64, 'launcher:synthetic-image-inspect'),
        ('fonts_digest', 'b'*64, 'worker:synthetic-font-inventory'),
        ('is_mobile', profile.profile_id == 'Mobile', 'worker:synthetic-enforced-context'),
        ('animations', 'disabled', 'worker:synthetic-screenshot-options'),
        ('wait_until', 'load', 'worker:synthetic-load-state'),
        ('stability_policy', 'two-identical-fixture-frames', 'worker:synthetic-stability-policy'))})
    result['stability_result'] = {'value': 'STABLE', 'source': 'worker:synthetic-stability-observation'}
    return result


class Lease:
    def __init__(self, *, clean=True, ledger=True):
        self.active, self.clean = True, clean
        # The real ConnectLedger the trusted proxy owns; omitted to model "no audit available".
        if ledger: self.ledger = ConnectLedger()
    def check(self, url=None):
        if not self.active or url is not None and not url.startswith('https://fixture.invalid/'):
            raise ValueError('fixture lease refused')
        return 'http://127.0.0.1:12345'
    def stop(self): self.active = False; return self.clean


class Driver:
    def __init__(self, changed=False, status=200, bad=False, clean=True, ledger=None, net='ok'):
        self.changed, self.status, self.bad, self.clean = changed, status, bad, clean
        self.ledger, self.net = ledger, net
    def connect(self, host, decision, reason):
        self.ledger.begin(); self.ledger.record(host, 443, decision, reason)
    def start(self, profile): pass
    def http(self, url, seconds):
        # Synthetic proxy-side record of what this "page load" asked for. net='silent' records nothing.
        if self.ledger is not None and self.net != 'silent':
            if self.net in ('prelude', 'prelude_allowed'):  # Browser start-up traffic, before the page's own document.
                self.connect('www.google.com', 'BLOCK', 'NOT_ALLOWLISTED')
                self.ledger.begin(); self.ledger.record(None, None, 'IDLE', 'EMPTY_CONNECTION')
            if self.net == 'prelude_allowed': self.connect('other.fixture.invalid', 'ALLOW', 'ALLOW')
            self.connect(urlsplit(url).hostname, 'ALLOW', 'ALLOW')  # The job's own authority, as the real proxy would see it.
            if self.net == 'blocked': self.connect('cdn.fixture.invalid', 'BLOCK', 'NOT_ALLOWLISTED')
            if self.net == 'failed': self.connect('cdn.fixture.invalid', 'FAILED', 'DNS_TIMEOUT')
            if self.net == 'pending': self.ledger.begin()
            if self.net == 'overflow':
                for n in range(self.ledger.max_records + 2): self.connect(f'h{n}.fixture.invalid', 'ALLOW', 'ALLOW')
        return self.status
    def load(self, seconds): pass
    def capture(self, profile, seconds):
        if self.bad: return b'not png'
        a = profile.attributes; w, h = a['viewport_width'], a['viewport_height']
        pixels = bytearray(b'\xee\xee\xee\xff' * (w*h))
        if self.changed: pixels[:4] = b'\x10\x20\x30\xff'
        return preview.png(w, h, pixels)
    def close(self): return self.clean


class Fixture:
    def __init__(self, *, observer=observations, trusted=True, threshold=True):
        self.temp = tempfile.TemporaryDirectory(prefix='siteproof-m4-')
        self.root = Path(self.temp.name); self.db = self.root/'state.sqlite'
        self.workspace = OfflineWorkspace.create(self.db, self.root)
        self.workspace.save_site({'label':'Synthetic','origin':'https://fixture.invalid','expected_revision':0})
        self.workspace.save_page({'page_id':'p','label':'Fixture','path':'/','expected_revision':0})
        for kind in ('Desktop', 'Mobile'):
            self.workspace.save_profile({'page_id':'p','kind':kind,'width':8,'height':8,'expected_revision':1})
        initialize_runtime(self.db, self.root)
        initialize_comparison(self.db, self.root)
        self.authority = TrustedProfileAuthority(KEY, observer, domain='OFFLINE_TEST') if trusted else None
        self.policy = PixelPolicy(0, 'Explicit offline acceptance: exact RGBA equality') if threshold else None
        self.comparison = ComparisonService(self.workspace, authority=self.authority, policy=self.policy)
        self.repo = Repository(self.db)
        worker = TrustedWorker(EvidenceBridge(EvidenceFinalizer(self.repo, ArtifactStore(self.root))))
        self.runtime = RuntimeService(self.workspace, worker, comparison=self.comparison)

    def run(self, *, changed=False, status=200, bad=False, clean=True, proxy_clean=True, batch=None,
            net='ok', ledger=True, browser='ok', stability=None):
        lease = Lease(clean=proxy_clean, ledger=ledger)
        def factory(request, remaining):
            out = capture(request, Driver(changed, status, bad, clean, getattr(lease, 'ledger', None), net), lease, LIMITS)
            running = [j for j, _, _ in self.runtime.store.bindings() if self.repo.get_job(j).status.value == 'RUNNING']
            report = synthetic_browser_audit(browser)
            if report is not None and len(running) == 1:  # browser='none': the starter delivers no audit at all
                self.runtime.record_browser_audit(running[0], report)
            if stability is not None and len(running) == 1:  # 'STABLE' / 'UNSTABLE' / a raw record; None = no record (older data)
                record = stability if type(stability) is dict else {'schema': 'siteproof.capture-stability.v1', 'value': stability,
                                                                    'reason': None if stability == 'STABLE' else 'NOT_SETTLED'}
                self.runtime.record_capture_stability(running[0], record)
            return MemoryChannel(out.wire), out.reason, out.cleanup_confirmed
        batch = batch or self.runtime.submit()
        self.runtime.run(batch, factory, lease, LIMITS)
        return self.comparison.state()

    def approve(self, candidate, *, current=None):
        from src.baseline.model import BaselineStatus
        cid = candidate['candidate_id']
        item = self.workspace.repo.baselines.read_page(limit=1, candidate_id=cid).items[0]
        return self.workspace.repo.baselines.decide(cid, decision=BaselineStatus.APPROVED,
            actor='offline-human-operator', expected_revision=item.record.revision,
            reviewed_digest=item.record.registered_digest,
            expected_current_version=(item.current_version or 0) if current is None else current)

    def close(self): self.temp.cleanup()
