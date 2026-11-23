"""M4 S1 -> pending Baseline -> pinned comparison -> immutable history.

S1 execution/check rows are never rewritten. Human approval does not authenticate
profiles. Both images are re-observed before each comparison; old results retain
their observation and report separately if their sources are no longer readable.
"""
from dataclasses import asdict, dataclass
import json
import time
import uuid

from src.baseline.model import BaselineCandidate
from src.bridge.s1_evidence import read_s1_capture_payload
from src.bridge.s1_s2_contract import EvidenceFile, EvidenceOrigin, UnattestedProfileDeclaration
from src.comparison import preview
from src.comparison.operational import operational_verdict
from src.comparison.provenance import (TrustedProfileAuthority, complete, context_fingerprint,
                                       fingerprint, unverified_settings, values)
from src.comparison.profile import is_clean_text
from src.core.frames import FrameKind
from src.core.model import JobStatus, validate_id
from src.core.offline import fields, read_profile
from src.storage.comparison import ComparisonStore
from src.storage.m1 import M1Error
from src.storage.runtime import ReadRepository


MAX_PIXELS = 16 * 1024 * 1024  # e.g. Desktop 1440 x 11650, Mobile 390 x 16384 (full page)
MAX_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class PixelPolicy:
    # No default threshold: the trusted starter must explicitly choose and explain it.
    maximum_changed_pixels: int
    rationale: str

    def __post_init__(self):
        if (type(self.maximum_changed_pixels) is not int
                or not 0 <= self.maximum_changed_pixels <= MAX_PIXELS
                or not is_clean_text(self.rationale)):
            raise ValueError('explicit pixel threshold and rationale required')

    def body(self):
        return {'method': 'exact-rgba', 'method_version': '1',
                'maximum_changed_pixels': self.maximum_changed_pixels,
                'rationale': self.rationale, 'max_pixels': MAX_PIXELS, 'max_bytes': MAX_BYTES}


class ComparisonService:
    def __init__(self, workspace, *, authority=None, policy=None, allow_unattested_preview=False):
        if authority is not None and type(authority) is not TrustedProfileAuthority:
            raise ValueError('trusted in-process authority required')
        if policy is not None and type(policy) is not PixelPolicy:
            raise ValueError('explicit PixelPolicy required')
        self.workspace, self.authority, self.policy = workspace, authority, policy
        if type(allow_unattested_preview) is not bool:
            raise ValueError('explicit preview opt-in required')
        self.allow_unattested_preview = allow_unattested_preview
        self.store = ComparisonStore(workspace)
        self.repo = ReadRepository(workspace.db_path)
        self.baselines = workspace.repo.baselines
        self._captures = {}

    def prepare(self, profile, page_id, kind, source):
        settings = (self.authority.observe(profile, 'prepare') if self.authority else unverified_settings(profile))
        context = context_fingerprint(profile, settings)
        # Prefer a compatible current head; retain the latest same-kind head to
        # explain a mismatch instead of silently selecting an unrelated page.
        with self.workspace.repo.read() as c:
            self.store.audit(c)
            rows = c.execute('SELECT mc.body,v.version,v.candidate_id FROM baseline_heads h '
                'JOIN baseline_versions v USING(page_id,profile_fingerprint,version) '
                'JOIN m4_candidates mc USING(candidate_id) WHERE h.page_id=? '
                'ORDER BY mc.rowid DESC LIMIT 100', (page_id,)).fetchall()
        pins = []
        for row in rows:
            candidate = json.loads(row['body'])
            if candidate['kind'] != kind:
                continue
            record = self.baselines.get(row['candidate_id'])
            if record.is_valid_approval():
                pins.append({'candidate_id': record.candidate.candidate_id, 'version': row['version'],
                             'digest': record.registered_digest, 'fingerprint': record.candidate.profile_fingerprint})
        pin = next((p for p in pins if p['fingerprint'] == context), pins[0] if pins else None)
        return {'profile': {'profile_id': profile.profile_id, 'attributes': dict(profile.attributes)},
                'page_id': page_id, 'kind': kind, 'source': source, 'settings': settings,
                'context_fingerprint': context, 'baseline': pin,
                'policy': self.policy.body() if self.policy else None,
                'unattested_preview': self.allow_unattested_preview}

    def bind(self, job, prepared):
        if job.status is not JobStatus.ACCEPTED or self.repo.latest_attempt(job.job_id) is not None:
            raise M1Error('CAPTURE_PLAN_TOO_LATE', 409)
        body = {**prepared, 'job_id': job.job_id, 'snapshot_sha256': job.snapshot.sha256}
        if (body['page_id'] != job.snapshot.page_id
                or body['profile']['profile_id'] != job.snapshot.profile_id
                or (body['baseline']['candidate_id'] if body['baseline'] else None) != job.snapshot.baseline_id):
            raise M1Error('CAPTURE_PLAN_MISMATCH', 409)
        envelope = self.authority.sign(body) if self.authority else {'body': body}
        self.store.put('jobs', job.job_id, envelope)

    def plan(self, job_id):
        envelope = self.store.body('jobs', job_id)
        body = envelope['body']
        job = self.repo.get_job(job_id)
        if (body['job_id'] != job_id or body['snapshot_sha256'] != job.snapshot.sha256
                or body['page_id'] != job.snapshot.page_id
                or body['profile']['profile_id'] != job.snapshot.profile_id
                or (body['baseline']['candidate_id'] if body['baseline'] else None) != job.snapshot.baseline_id
                or context_fingerprint(read_profile(body['profile']), body['settings']) != body['context_fingerprint']):
            raise M1Error('CAPTURE_PLAN_MISMATCH', 503)
        return envelope, body, job

    def observe(self, job_id):
        envelope, body, job = self.plan(job_id)
        if job.status is not JobStatus.COMPLETED or not job.adopted_attempt_id:
            raise M1Error('JOB_NOT_COMPLETED', 409)
        attempt = self.repo.get_attempt(job_id, job.adopted_attempt_id)
        pngs = [a for a in self.repo.list_artifacts(job_id, attempt.attempt_id)
                if a.kind is FrameKind.SCREENSHOT_PNG]
        manifest = self.repo.get_manifest_row(job_id, attempt.attempt_id)
        if len(pngs) != 1 or manifest is None:
            raise M1Error('EVIDENCE_MISSING', 422)
        snap, png = job.snapshot, pngs[0]
        binding = UnattestedProfileDeclaration(
            EvidenceOrigin(job_id, attempt.attempt_id, attempt.lease_epoch, snap.sha256,
                           snap.intent.intent_hash, snap.page_id, snap.profile_id, snap.baseline_id),
            EvidenceFile(png.rel_path, png.sha256, png.byte_length), read_profile(body['profile']),
            read_profile(body['profile']).fingerprint,
            EvidenceFile(manifest.rel_path, manifest.sha256, manifest.byte_length))
        checked, data = read_s1_capture_payload(self.workspace.db_path, self.workspace.storage_root,
                                              job_id, profile_declaration=binding)
        if not checked.accepted:
            raise M1Error(checked.rejection.reason.value, 422)
        width, height = preview.dimensions(data, max_pixels=MAX_PIXELS, max_bytes=MAX_BYTES)
        attrs = read_profile(body['profile']).attributes
        expected = (attrs['viewport_width'] * attrs['device_scale_factor'],
                    attrs['viewport_height'] * attrs['device_scale_factor'])
        if (width != expected[0] or (height < expected[1] if attrs['full_page'] else height != expected[1])):
            raise M1Error('CAPTURE_DIMENSIONS_MISMATCH', 422)
        return envelope, body, checked.evidence, data

    @staticmethod
    def evidence_pin(evidence):
        return {'origin': asdict(evidence.origin), 'manifest': asdict(evidence.manifest),
                'screenshot': asdict(evidence.screenshot.file)}

    def start_capture(self, job_id, seconds):
        """Ephemeral, single-use permit issued BEFORE the channel factory runs.

        A crash/lost permit cannot be reconstructed from historical DB evidence.
        """
        _, _, job = self.plan(job_id)
        attempt = self.repo.latest_attempt(job_id)
        if job.status is not JobStatus.RUNNING or attempt is None or job_id in self._captures:
            raise M1Error('CAPTURE_PLAN_TOO_LATE', 409)
        token = object()
        self._captures[job_id] = (token, attempt.attempt_id, time.monotonic() + seconds)
        return token

    def end_capture(self, job_id):
        self._captures.pop(job_id, None)

    def attest(self, job_id, token=None):
        """Called only by RuntimeService immediately after trusted S1 ingestion.

        No public API seals historical evidence. The pre-capture signed plan and
        independent post observation must agree; incomplete observations stay so.
        """
        permit = self._captures.pop(job_id, None)
        if (permit is None or token is not permit[0] or time.monotonic() >= permit[2]
                or self.repo.get_job(job_id).adopted_attempt_id != permit[1]):
            raise M1Error('CAPTURE_RECEIPT_TOO_LATE', 409)
        envelope, plan, evidence, _ = self.observe(job_id)
        if self.store.get('receipts', job_id) is not None:
            raise M1Error('RECEIPT_EXISTS', 409)
        post = self.authority.observe(read_profile(plan['profile']), 'captured', job_id) if self.authority else {}
        stability = self.authority.stability(read_profile(plan['profile']), job_id) if self.authority else None
        receipt = {'plan_sha256': fingerprint(envelope), 'evidence': self.evidence_pin(evidence),
                   'post': post, 'stability': stability}
        self.store.put('receipts', job_id, self.authority.sign(receipt) if self.authority else {'body': receipt})

    def trust(self, envelope, plan, evidence):
        authority = self.authority
        row = self.store.get('receipts', plan['job_id'])
        receipt = json.loads(row['body']) if row else None
        profile = read_profile(plan['profile'])
        if (authority is None or not authority.verifies(envelope) or not authority.verifies(receipt)
                or not authority.accepts_source(plan['source'])):
            return 'UNATTESTED', 'PROFILE_UNATTESTED'
        body = receipt['body']
        if (body['plan_sha256'] != fingerprint(envelope) or body['evidence'] != self.evidence_pin(evidence)
                or values(body['post']) != values(plan['settings'])):
            return 'UNATTESTED', 'PROFILE_ATTESTATION_MISMATCH'
        if not complete(profile, plan['settings']) or not complete(profile, body['post']):
            return 'UNATTESTED', 'PROFILE_UNATTESTED'
        if values(body['post'])['is_mobile'] is not (plan['kind'] == 'Mobile'):
            return 'UNATTESTED', 'PROFILE_ATTESTATION_MISMATCH'
        if self.cleanup_unconfirmed(plan['job_id']):
            return 'UNATTESTED', 'RESOURCE_CLEANUP_UNCONFIRMED'
        # Stability is a measured capture condition, not an arbitrary wait delay.
        stability = body['stability']
        if (type(stability) is not dict or set(stability) != {'value', 'source'}
                or stability['value'] != 'STABLE' or not is_clean_text(stability['source'])
                or not stability['source'].startswith('worker:')):
            return 'UNATTESTED', 'CAPTURE_UNSTABLE'
        return ('TRUSTED_TEST' if authority.domain == 'OFFLINE_TEST' else 'ATTESTED'), 'PROFILE_VERIFIED'

    def cleanup_unconfirmed(self, job_id):
        with self.workspace.repo.read() as c:
            events = [json.loads(r[0]) for r in c.execute(
                'SELECT body FROM runtime_events WHERE job_id=? ORDER BY event_id DESC LIMIT 10', (job_id,))]
        return any(not any(e.get(key) is True for e in events) or any(e.get(key) is False for e in events)
                   for key in ('cleanup_confirmed', 'proxy_cleanup_confirmed'))

    def network_audit(self, job_id):
        """Trusted proxy audit recorded by the runtime for this job; None if none was ever recorded."""
        with self.workspace.repo.read() as c:
            rows = [json.loads(r[0]) for r in c.execute(
                'SELECT body FROM runtime_events WHERE job_id=? ORDER BY event_id DESC', (job_id,))]
        return next((e['network_audit'] for e in rows if 'network_audit' in e), None)

    def browser_audit(self, job_id):
        """Producer-reported page request audit recorded for this job (untrusted, downgrade-only); None if never recorded."""
        with self.workspace.repo.read() as c:
            rows = [json.loads(r[0]) for r in c.execute(
                'SELECT body FROM runtime_events WHERE job_id=? ORDER BY event_id DESC', (job_id,))]
        return next((e['browser_audit'] for e in rows if 'browser_audit' in e), None)

    def capture_stability(self, job_id):
        """Trusted stability record of this job's screenshot (RuntimeService.record_capture_stability); None if never recorded."""
        with self.workspace.repo.read() as c:
            rows = [json.loads(r[0]) for r in c.execute(
                'SELECT body FROM runtime_events WHERE job_id=? ORDER BY event_id DESC', (job_id,))]
        return next((e['capture_stability'] for e in rows if 'capture_stability' in e), None)

    @staticmethod
    def _unstable(record):
        """A recorded stability check that is not exactly STABLE blocks; no record (older data) adds no claim either way."""
        return record is not None and (type(record) is not dict or record.get('value') != 'STABLE')

    def candidate(self, job_id):
        envelope, plan, evidence, _ = self.observe(job_id)
        cid = 'capture-' + job_id
        existing = self.store.get('candidates', cid)
        if existing is not None:
            self.validate_candidate(cid)
            return self.candidate_view(cid)
        candidate = BaselineCandidate(cid, plan['page_id'], plan['context_fingerprint'],
                                      evidence.screenshot.file.artifact_ref, evidence.screenshot.file.sha256)
        record = self.baselines.register(candidate)  # Always PENDING; no decision here.
        self.store.put('candidates', cid, {'job_id': job_id, 'candidate_id': cid, 'kind': plan['kind'],
            'evidence': self.evidence_pin(evidence), 'digest': record.registered_digest}, job_id=job_id)
        return self.candidate_view(cid)

    def validate_candidate(self, candidate_id):
        row = self.store.body('candidates', candidate_id)
        envelope, plan, evidence, _ = self.observe(row['job_id'])
        record = self.baselines.get(candidate_id)
        candidate = record.candidate
        if (row['candidate_id'] != candidate_id or row['evidence'] != self.evidence_pin(evidence)
                or row['digest'] != record.registered_digest or candidate.page_id != plan['page_id']
                or candidate.profile_fingerprint != plan['context_fingerprint']
                or candidate.artifact_ref != evidence.screenshot.file.artifact_ref
                or candidate.artifact_sha256 != evidence.screenshot.file.sha256):
            raise M1Error('BASELINE_EVIDENCE_MISMATCH', 422)
        return envelope, plan, evidence

    def candidate_view(self, cid):
        item = self.baselines.read_page(limit=1, candidate_id=cid).items[0]
        return {'candidate_id': cid, 'approval_state': item.record.status.value,
                'baseline_state': 'BASELINE_PENDING' if item.record.status.value == 'PENDING' else item.record.status.value,
                'version': item.candidate_version, 'revision': item.record.revision,
                'digest': item.record.registered_digest, 'current_version': item.current_version,
                'quality': 'UNKNOWN'}

    def compare(self, job_id):
        envelope, plan, job = self.plan(job_id)
        pin = plan['baseline']
        reasons, metrics, diff, current, before, baseline_job_id = [], None, None, None, None, None
        trust, profile_reason = 'UNATTESTED', 'PROFILE_UNATTESTED'
        before_trust, baseline_source = None, None
        try:
            envelope, plan, evidence, current = self.observe(job_id)
            trust, profile_reason = self.trust(envelope, plan, evidence)
            if trust == 'UNATTESTED':
                reasons.append(profile_reason)
        except (M1Error, preview.PreviewError) as exc:
            reasons.append(exc.code if isinstance(exc, M1Error) else str(exc))
        # The S3 path (unattested profile) records stability as an event; the M5 path also reaches CAPTURE_UNSTABLE through trust().
        stability = self.capture_stability(job_id)
        if self._unstable(stability):
            reasons.append('CAPTURE_UNSTABLE')
        if pin is None:
            reasons.append('BASELINE_PENDING' if self.store.get('candidates', 'capture-' + job_id) else 'BASELINE_UNSET')
        else:
            try:
                b_env, b_plan, b_evidence = self.validate_candidate(pin['candidate_id'])
                record = self.baselines.get(pin['candidate_id'])
                versions = self.baselines.history(record.candidate.page_id, record.candidate.profile_fingerprint)
                if (not record.is_valid_approval() or not any(v.version == pin['version'] and
                        v.record.candidate.candidate_id == pin['candidate_id'] for v in versions)):
                    reasons.append('BASELINE_NOT_APPROVED')
                if record.registered_digest != pin['digest'] or record.candidate.profile_fingerprint != pin['fingerprint']:
                    reasons.append('BASELINE_EVIDENCE_MISMATCH')
                baseline_job_id, baseline_source = b_plan['job_id'], b_plan['source']
                _, _, _, before = self.observe(baseline_job_id)
                before_trust, before_reason = self.trust(b_env, b_plan, b_evidence)
                if before_trust == 'UNATTESTED':
                    reasons.append(before_reason)
                if self._unstable(self.capture_stability(baseline_job_id)):
                    reasons.append('BASELINE_CAPTURE_UNSTABLE')
                if (b_plan['page_id'] != plan['page_id'] or b_plan['kind'] != plan['kind']
                        or b_plan['context_fingerprint'] != plan['context_fingerprint']):
                    reasons.append('PROFILE_MISMATCH')
            except (M1Error, preview.PreviewError) as exc:
                reasons.append(exc.code if isinstance(exc, M1Error) else str(exc))
        if plan['policy'] is None:
            reasons.append('THRESHOLD_UNDEFINED')
        checks = self.repo.list_check_results(job_id, job.adopted_attempt_id) if job.adopted_attempt_id else []
        by_type = {c.check_type: c for c in checks}
        for required in job.snapshot.required_checks:
            if required not in by_type or (required.value != 'CAPTURE' and by_type[required].outcome.value != 'PASS'):
                reasons.append('CHECK_NOT_PASSED')
        quality = 'UNKNOWN'
        preview_only = bool(reasons and plan.get('unattested_preview') is True
                            and set(reasons).issubset({'PROFILE_UNATTESTED', 'CAPTURE_UNSTABLE'}))
        if not reasons or preview_only:
            try:
                # Cache only the pure pixel calculation, after fresh source,
                # approval, policy and provenance checks above. Verdicts are
                # recomputed; key loss or failed evidence never reuses PASS.
                cached = self.store.rows('results', job_id=job_id, limit=1)
                saved = self.result(cached[0]['result_id'], verify_sources=False) if cached else None
                if (saved and saved['metrics'] is not None and saved['policy'] == plan['policy']
                        and saved['current_sha256'] == preview.digest(current)
                        and saved.get('baseline_sha256') == preview.digest(before)
                        and saved['context_fingerprint'] == plan['context_fingerprint']):
                    metrics, diff = saved['metrics'], cached[0]['diff']
                else:
                    metrics, diff = preview.compare(before, current, max_pixels=MAX_PIXELS, max_bytes=MAX_BYTES)
                if not preview_only:
                    quality = 'CHANGED' if metrics['changed_pixels'] > plan['policy']['maximum_changed_pixels'] else 'PASS'
            except preview.PreviewError as exc:
                reasons.append(str(exc))
        if any(c.outcome.value == 'FAIL' for c in checks):
            quality = 'FAIL'
            reasons.append('CHECK_FAILED')
        audit = self.network_audit(job_id)
        browser_audit = self.browser_audit(job_id)
        # Operational verdict: derived from the strict result inputs, never from or into `quality`.
        operational = operational_verdict(
            reasons=reasons, metrics=metrics, policy=plan['policy'], baseline=pin,
            source=plan['source'], baseline_source=baseline_source, execution=job.status.value,
            cleanup_confirmed=not self.cleanup_unconfirmed(job_id)
            and (baseline_job_id is None or not self.cleanup_unconfirmed(baseline_job_id)),
            profile_trust=trust, network_audit=audit,
            baseline_network_audit=self.network_audit(baseline_job_id) if baseline_job_id else None,
            browser_audit=browser_audit,
            baseline_browser_audit=self.browser_audit(baseline_job_id) if baseline_job_id else None)
        result = {'result_id': uuid.uuid4().hex, 'job_id': job_id, 'page_id': plan['page_id'],
            'kind': plan['kind'], 'baseline': pin, 'baseline_job_id': baseline_job_id,
            'quality': quality, 'reasons': list(dict.fromkeys(reasons)), 'metrics': metrics,
            'policy': plan['policy'], 'profile_trust': trust, 'profile_reason': profile_reason,
            'baseline_profile_trust': before_trust, 'context_fingerprint': plan['context_fingerprint'],
            'profile_compatibility': ('MISMATCH' if 'PROFILE_MISMATCH' in reasons else
                'MATCH' if trust != 'UNATTESTED' and before_trust not in (None, 'UNATTESTED') else
                'UNATTESTED' if pin else 'NOT_EVALUATED'),
            'current_sha256': preview.digest(current) if current else None,
            'baseline_sha256': preview.digest(before) if before else None,
            'diff_sha256': preview.digest(diff) if diff else None, 'execution': job.status.value,
            'preview_only': preview_only, 'preview_changed': bool(metrics and plan['policy'] and
                metrics['changed_pixels'] > plan['policy']['maximum_changed_pixels']),
            'checks': [{'type': c.check_type.value, 'outcome': c.outcome.value, 'reason': c.reason_code} for c in checks],
            'source': plan['source'], 'trust_domain': self.authority.domain if self.authority else None,
            'operational': operational, 'network_audit': audit, 'browser_audit': browser_audit, 'capture_stability': stability}
        self.store.put('results', result['result_id'], result, job_id=job_id, diff=diff)
        return result

    def result(self, result_id, *, verify_sources=True):
        row = self.store.get('results', result_id)
        if row is None:
            raise M1Error('COMPARISON_NOT_FOUND', 404)
        result = json.loads(row['body'])
        if (row['job_id'] != result['job_id'] or result['result_id'] != result_id
                or (preview.digest(row['diff']) if row['diff'] is not None else None) != result['diff_sha256']):
            raise M1Error('COMPARISON_INTEGRITY_FAILED', 503)
        availability = []
        for jid in (result['job_id'], result['baseline_job_id']) if verify_sources else ():
            if jid:
                try:
                    self.observe(jid)
                except (M1Error, preview.PreviewError):
                    availability.append('EVIDENCE_UNAVAILABLE')
        return {**result, 'source_availability': ('UNAVAILABLE' if availability else 'VERIFIED')
                if verify_sources else 'NOT_RECHECKED'}

    def image(self, job_id):
        return self.observe(job_id)[3]

    def result_image(self, result_id, role):
        result = self.result(result_id)
        if result['source_availability'] != 'VERIFIED':
            raise M1Error('EVIDENCE_UNAVAILABLE', 422)
        if role == 'diff':
            data = self.store.get('results', result_id)['diff']
            if data is None:
                raise M1Error('COMPARISON_NOT_RUN', 404)
            return data
        jid = result['job_id'] if role == 'current' else result['baseline_job_id']
        if role not in ('current', 'baseline') or jid is None:
            raise M1Error('EVIDENCE_MISSING', 404)
        return self.image(jid)

    def state(self):
        jobs = []
        for row in self.store.rows('jobs', limit=10):
            _, plan, job = self.plan(row['job_id'])
            item = {'job_id': job.job_id, 'page_id': plan['page_id'], 'kind': plan['kind'],
                    'execution': job.status.value, 'baseline': plan['baseline'], 'source': plan['source'],
                    'profile': plan['profile'], 'conditions': plan['settings'],
                    'profile_trust': 'UNATTESTED', 'profile_reason': 'PROFILE_UNATTESTED',
                    'evidence_available': False, 'candidate': None}
            try:
                env, body, evidence, _ = self.observe(job.job_id)
                item['profile_trust'], item['profile_reason'] = self.trust(env, body, evidence)
                item['evidence_available'] = True
            except (M1Error, preview.PreviewError) as exc:
                item['evidence_reason'] = exc.code if isinstance(exc, M1Error) else str(exc)
            if self.store.get('candidates', 'capture-' + job.job_id):
                item['candidate'] = self.candidate_view('capture-' + job.job_id)
            jobs.append(item)
        return {'jobs': jobs, **self.history(0), 'job_limit': 10, 'comparison_enabled': True}

    def history(self, offset):
        rows = self.store.rows('results', limit=26, offset=offset)
        results = [self.result(r['result_id'], verify_sources=False) for r in rows[:25]]
        return {'results': results, 'history_limit': 25,
                'next_offset': offset + 25 if len(rows) > 25 else None}

    def action(self, name, obj):
        fields(obj, 'job_id')
        validate_id(obj['job_id'], 'job_id')
        try:
            if name == 'candidate':
                return self.candidate(obj['job_id'])
            if name == 'compare':
                return self.compare(obj['job_id'])
        except preview.PreviewError as exc:
            raise M1Error(str(exc), 422) from None
        raise M1Error('NOT_FOUND', 404)
