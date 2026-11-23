"""M1 immutable input -> one shared-proxy batch -> individual S1 jobs.

The trusted starter supplies channels from an isolated runtime, or synthetic
channels in offline tests. HTTP never accepts drivers, paths, SQL or launch args.
No automatic retries: every S1 child has its own immutable attempt, and all children
share the same supplied ProxyLease/QuotaSession and a single batch deadline.
"""
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from src.bridge.s1_evidence import read_s1_capture
from src.bridge.s1_s2_contract import EvidenceFile, EvidenceOrigin, UnattestedProfileDeclaration
from src.core.frames import CheckType, FrameKind
from src.core.model import JobIntent, JobStatus
from src.core.offline import read_profile
from src.core.rules import is_terminal
from src.isolation.ledger import ConnectLedger, unavailable
from src.runtime.request_audit import SCHEMA as BROWSER_AUDIT_SCHEMA, check_browser_audit
from src.runtime.stability import SCHEMA as STABILITY_SCHEMA
from src.storage.runtime import RuntimeStore, ReadRepository
from src.worker.capture import CaptureRequest
from src.worker.trusted import WireBudget


_PRODUCER_FAILURES = frozenset({
    'BROWSER_START_FAILED', 'BROWSER_START_TIMEOUT', 'HTTP_FAILED', 'HTTP_TIMEOUT',
    'LOAD_FAILED', 'LOAD_TIMEOUT', 'CAPTURE_FAILED', 'CAPTURE_TIMEOUT', 'CANCELLED',
    'BROWSER_CLEANUP_UNCONFIRMED', 'OUTPUT_LIMIT',
})


class RuntimeService:
    def __init__(self, workspace, worker, *, comparison=None):
        self.workspace, self.worker = workspace, worker
        self.store = RuntimeStore(workspace)
        self.repo = worker.bridge.finalizer.repo
        if comparison is not None:
            from src.comparison.service import ComparisonService
            if type(comparison) is not ComparisonService or comparison.workspace is not workspace:
                raise ValueError('comparison must use the same explicitly supplied workspace')
        self.comparison = comparison
        if (Path(self.repo.db_path).resolve() != workspace.db_path.resolve()
                or worker.bridge.finalizer.store.root.resolve() != workspace.storage_root.resolve()):
            raise ValueError('runtime must use fixed M1 DB and evidence root')

    def submit(self, *, source='OFFLINE_FIXTURE_UNATTESTED'):
        if source not in ('OFFLINE_FIXTURE_UNATTESTED', 'REAL_CHROMIUM_FIXTURE_UNATTESTED'):
            raise ValueError('explicit fixture provenance required')
        batch_id = uuid.uuid4().hex
        snapshot = self.store.snapshot(batch_id)
        pages = {p['page_id']: p for p in snapshot['pages']}
        prepared = []
        for p in snapshot['profiles']:
            profile = read_profile(p['body'])
            if profile.fingerprint != p['fingerprint'] or p['kind'] not in ('Desktop', 'Mobile'):
                raise ValueError('PROFILE_BINDING_INVALID')
            plan = self.comparison.prepare(profile, p['page_id'], p['kind'], source) if self.comparison else None
            intent = JobIntent(snapshot['site']['origin'] + pages[p['page_id']]['path'],
                               p['page_id'], profile.profile_id, tuple(CheckType),
                               plan['baseline']['candidate_id'] if plan and plan['baseline'] else None)
            prepared.append((p, profile, intent, plan))
        for p, profile, intent, plan in prepared:
            job = self.repo.accept_job(f'm2-{batch_id}-{p["page_id"]}-{p["kind"]}', intent).job
            self.store.bind(job.job_id, batch_id, {
                'page': pages[p['page_id']], 'profile': {'profile_id': profile.profile_id,
                    'attributes': dict(profile.attributes)}, 'fingerprint': profile.fingerprint,
                'profile_revision': p['revision'], 'kind': p['kind'],
                'snapshot_sha256': job.snapshot.sha256, 'source': source})
            if self.comparison:
                self.comparison.bind(job, plan)
        return batch_id

    def record_browser_audit(self, job_id, report):
        """Starter side: attach the producer's request audit to the job that is running right now.

        The report is untrusted; it is rebuilt through `check_browser_audit` and can only ever lower a verdict.
        A malformed report is stored as INVALID, never repaired. Not calling this leaves the job without an
        audit, which is UNKNOWN as well.
        """
        if self.repo.get_job(job_id).status is not JobStatus.RUNNING:
            raise ValueError('browser audit only for the running job')
        audit = check_browser_audit(report)
        if audit is None and type(report) is dict and report.get('source') == 'UNAVAILABLE':
            audit = {'schema': BROWSER_AUDIT_SCHEMA, 'source': 'UNAVAILABLE'}
        self.store.event(job_id, {'browser_audit': audit or {'schema': BROWSER_AUDIT_SCHEMA, 'source': 'INVALID'}})

    def record_capture_stability(self, job_id, record):
        """Starter side: the trusted stability check of the running job's screenshot (stability.verify, done by the Worker).

        Only STABLE / UNSTABLE are stored; anything else is stored as UNSTABLE. Not calling this leaves the job without a record,
        which the comparison reports as unverified, never as stable.
        """
        if self.repo.get_job(job_id).status is not JobStatus.RUNNING:
            raise ValueError('capture stability only for the running job')
        ok = type(record) is dict and record.get('schema') == STABILITY_SCHEMA and record.get('value') in ('STABLE', 'UNSTABLE')
        self.store.event(job_id, {'capture_stability': dict(record) if ok else
                                  {'schema': STABILITY_SCHEMA, 'value': 'UNSTABLE', 'reason': 'RECORD_INVALID'}})

    def run(self, batch_id, channel_factory, lease, resources, *, cancel=None):
        """Factory(request, remaining_seconds) -> (binary_source, producer_reason,
        producer_cleanup_confirmed). Factory runs in trusted launcher, not HTTP.
        Real launcher must supervise process startup/IPC/death; no host fallback.
        """
        deadline = time.monotonic() + resources.seconds
        output_budget = WireBudget(resources.output_bytes)
        bindings = self.store.bindings(batch_id)
        if not bindings:
            raise ValueError('BATCH_NOT_FOUND')
        self.store.claim(batch_id)  # One run only; a fresh lease cannot reset batch quota.
        ledger = getattr(lease, 'ledger', None)
        ledger = ledger if type(ledger) is ConnectLedger else None
        try:
            for job_id, _, body in reversed(bindings):
                job = self.repo.get_job(job_id)
                if is_terminal(job.status):
                    continue  # never retry a completed/failed attempt
                if job.status is not JobStatus.ACCEPTED:
                    raise ValueError('RUNTIME_ALREADY_STARTED')
                job = self.repo.transition(job_id, job.version, JobStatus.WAITING_WORKER)
                attempt = self.repo.register_attempt(job_id, 'capture-1', 1)
                job = self.repo.transition(job_id, job.version, JobStatus.RUNNING)
                source = None
                mark = ledger.mark() if ledger else None
                try:
                    if cancel is not None and cancel.is_set():
                        self.repo.cancel(job_id)
                        continue
                    if time.monotonic() >= deadline:
                        raise TimeoutError()
                    if output_budget.remaining <= 0:
                        raise ValueError('JOB_OUTPUT_LIMIT')
                    profile = read_profile(body['profile'])
                    if job.snapshot.sha256 != body['snapshot_sha256'] or profile.fingerprint != body['fingerprint']:
                        raise ValueError('BINDING_CHANGED')
                    lease.check(job.snapshot.intent.target_url)
                    request = CaptureRequest(job.snapshot.page_id, profile, job.snapshot.intent.target_url,
                                             job.snapshot.baseline_id)
                    capture_permit = (self.comparison.start_capture(job_id, deadline - time.monotonic())
                                      if self.comparison else None)
                    source, reason, producer_clean = channel_factory(request, deadline - time.monotonic())
                    lease.check()
                    if cancel is not None and cancel.is_set():
                        self.repo.cancel(job_id)
                    elif time.monotonic() >= deadline:
                        raise TimeoutError()
                    elif not producer_clean or reason != 'CAPTURE_COMPLETE':
                        fixed_reason = reason if reason in _PRODUCER_FAILURES else 'CAPTURE_FAILED'
                        self.worker.fail(job_id, attempt, fixed_reason if producer_clean else 'BROWSER_CLEANUP_UNCONFIRMED')
                        if not producer_clean:
                            lease.stop()
                    else:
                        job = self.repo.transition(job_id, job.version, JobStatus.SAVING)
                        channel, source = source, None  # Worker owns it even if finalization raises.
                        result, cleanup = self.worker.ingest(job_id, attempt.attempt_id, channel, cancel=cancel,
                            seconds=max(.001, deadline - time.monotonic()), byte_budget=output_budget)
                        if not cleanup:
                            lease.stop()  # Do not start more producers while cleanup is unconfirmed.
                        self.store.event(job_id, {'cleanup_confirmed': cleanup,
                            'commit_state': result.outcome.commit_state.value if result else 'NOT_ATTEMPTED',
                            'reason': ('S1_FINALIZATION_REQUIRES_INSPECTION' if result.outcome.reason else None)
                                      if result else 'CANCELLED'})
                        if self.comparison and cleanup and self.repo.get_job(job_id).status is JobStatus.COMPLETED:
                            try:
                                self.comparison.attest(job_id, capture_permit)
                            except Exception:
                                self.store.event(job_id, {'comparison_reason': 'PROFILE_RECEIPT_UNAVAILABLE'})
                except TimeoutError:
                    self.worker.fail(job_id, attempt, 'CAPTURE_TIMEOUT')
                except Exception:
                    # Unknown finalization/save results remain unknown; terminal S1 state wins.
                    self.worker.fail(job_id, attempt, 'RUNTIME_FAILED')
                    self.store.event(job_id, {'cleanup_confirmed': False, 'reason': 'RUNTIME_FAILED'})
                finally:
                    # Connection record for exactly this job's window; no ledger is "unavailable", never zero.
                    try:
                        # The anchor is the trusted job intent's own authority, never a browser report.
                        target = urlsplit(self.repo.get_job(job_id).snapshot.intent.target_url)
                        audit = (ledger.window(mark, (target.hostname, target.port or 443)) if ledger
                                 else unavailable('LEDGER_UNAVAILABLE'))
                    except Exception:
                        audit = unavailable('LEDGER_ERROR')
                    self.store.event(job_id, {'network_audit': audit})
                    if self.comparison:
                        self.comparison.end_capture(job_id)
                    if source is not None:
                        # Real factory must return a bounded-close channel; Worker also
                        # supervises its close when ingestion actually starts.
                        from src.worker.trusted import DeadlineSource
                        guard = DeadlineSource(source, self.worker.cleanup_seconds)
                        cleanup = guard.close(self.worker.cleanup_seconds)
                        if not cleanup:
                            lease.stop()
                        self.store.event(job_id, {'cleanup_confirmed': cleanup, 'reason': 'UNADOPTED_CHANNEL'})
        finally:
            cleanup = lease.stop()
            # False (e.g. OS DNS call still active) cannot become technical success.
            for job_id, _, _ in bindings:
                self.store.event(job_id, {'proxy_cleanup_confirmed': cleanup})
        if self.comparison:
            for job_id, _, _ in bindings:
                try:
                    job = self.repo.get_job(job_id)
                    if job.status is JobStatus.COMPLETED:
                        try:
                            self.comparison.candidate(job_id)
                        except Exception:
                            self.store.event(job_id, {'comparison_reason': 'BASELINE_CANDIDATE_UNAVAILABLE'})
                    self.comparison.compare(job_id)
                except Exception:
                    self.store.event(job_id, {'comparison_reason': 'COMPARISON_SAVE_UNCONFIRMED'})
        return self.state(batch_id)

    def state(self, batch_id=None):
        items = []
        repo = ReadRepository(self.workspace.db_path)
        for jid, batch, body in self.store.bindings(batch_id):
            job = repo.get_job(jid)
            item = {'job_id': jid, 'batch_id': batch, 'page_id': job.snapshot.page_id,
                'kind': body['kind'], 'profile': body['profile'], 'fingerprint': body['fingerprint'],
                'execution': job.status.value,
                # S1 diagnostics may contain record/OS details. Fixed code only on HTTP.
                'reason': job.terminal_reason.split(':', 1)[0] if job.terminal_reason else None,
                'quality': 'UNKNOWN', 'profile_reason': 'PROFILE_UNATTESTED',
                'source': body['source'], 'events': self.store.events(jid), 'evidence': None}
            reports = repo.list_check_results(jid, job.adopted_attempt_id) if job.adopted_attempt_id else []
            item['checks'] = [{'type': r.check_type.value, 'outcome': r.outcome.value,
                              'reason': r.reason_code} for r in reports]
            item['missing_checks'] = sorted(c.value for c in job.snapshot.required_checks
                                            if c not in {r.check_type for r in reports})
            if job.status is JobStatus.COMPLETED:
                attempt = repo.get_attempt(jid, job.adopted_attempt_id)
                snap = job.snapshot
                pngs = [a for a in repo.list_artifacts(jid, attempt.attempt_id)
                        if a.kind is FrameKind.SCREENSHOT_PNG]
                manifest = repo.get_manifest_row(jid, attempt.attempt_id)
                if len(pngs) == 1 and manifest:
                    png = pngs[0]
                    origin = EvidenceOrigin(jid, attempt.attempt_id, attempt.lease_epoch, snap.sha256,
                                            snap.intent.intent_hash, snap.page_id, snap.profile_id, snap.baseline_id)
                    binding = UnattestedProfileDeclaration(origin, EvidenceFile(png.rel_path, png.sha256, png.byte_length),
                        read_profile(body['profile']), body['fingerprint'],
                        EvidenceFile(manifest.rel_path, manifest.sha256, manifest.byte_length))
                    checked = read_s1_capture(self.workspace.db_path, self.workspace.storage_root,
                                              jid, profile_declaration=binding)
                    if checked.evidence is not None:
                        item['evidence'] = {'artifact_ref': png.rel_path, 'digest': png.sha256,
                            'manifest_ref': manifest.rel_path, 'profile_trust': 'UNATTESTED'}
                    else:
                        item['reason'] = 'EVIDENCE_UNAVAILABLE'
            items.append(item)
        return {'jobs': items, 'limit': 100, 'quality': 'UNKNOWN', 'isolation': 'NOT VERIFIED'}
