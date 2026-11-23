"""Real FrameReader -> adapter -> EvidenceFinalizer, using synthetic wire bytes.

Source provenance and formal-matrix limitations are in MATRIX.md.
"""

from dataclasses import replace
import io

from src.bridge import AdapterError, EvidenceBridge, adapt_stream
from src.core.errors import (EvidenceMismatch, InvalidTransition, StaleAttemptError,
                             TerminalJobError, UnknownAttempt, UnknownJob, ValidationError)
from src.core.frames import CheckType
from src.core.model import CheckOutcome, JobIntent, JobStatus, QualityVerdict
from src.isolation.frames import FrameLimits, FrameReader, TrustedContext
from src.storage.finalizer import CommitState, EvidenceFinalizer
from src.storage.manifest import compare_with_db, verify_published
from src.storage.repository import Repository
from tests.integration.fixtures import capture, complete, http, load, record, stream, wire
from tests.integration.support import IntegrationCase

HTTP, LOAD, CAPTURE = CheckType.HTTP, CheckType.LOAD, CheckType.CAPTURE


class WiredEvidenceTests(IntegrationCase):
    def test_http_load_pass_persisted_and_reopened(self):
        job, attempt = self.job((HTTP, LOAD))
        result = self.run_wire(job, attempt, complete()[:2])
        self.assertIs(result.outcome.commit_state, CommitState.COMMITTED)
        self.assertIs(result.outcome.quality, QualityVerdict.PASS)
        self.assertEqual(result.transport.summary.termination, "CLEAN")
        # Fresh repository handle proves SQLite readback, not cached return objects.
        repo = Repository(self.repo.db_path)
        saved = repo.get_job(job.job_id)
        self.assertEqual((saved.status, saved.adopted_attempt_id, saved.version),
                         (JobStatus.COMPLETED, attempt.attempt_id, job.version + 1))
        rows = repo.list_artifacts(job.job_id, attempt.attempt_id)
        manifest = repo.get_manifest_row(job.job_id, attempt.attempt_id)
        self.assertEqual(manifest.rel_path, result.outcome.manifest_rel_path)
        doc = verify_published(self.store, rows, manifest, saved.snapshot, attempt)
        checks = repo.list_check_results(job.job_id)
        self.assertEqual(compare_with_db(doc, saved.snapshot, checks, rows, (HTTP, LOAD)), [])
        for frame, row in zip(result.transport.frames, rows, strict=True):
            self.assertEqual(self.store.read_bytes(row.rel_path), frame.payload)
            self.assertEqual((row.seq, row.sha256, row.byte_length),
                             (frame.seq, frame.sha256, frame.byte_length))

    def test_capture_baseline_states_persist_unknown_with_real_png(self):
        for baseline, reason in ((None, "BASELINE_PENDING"), ("baseline-1", "COMPARISON_NOT_RUN")):
            with self.subTest(baseline=baseline):
                job, attempt = self.job(baseline=baseline)
                result = self.run_wire(job, attempt, complete(baseline))
                self.assertIs(result.outcome.commit_state, CommitState.COMMITTED)
                self.assertIs(result.outcome.quality, QualityVerdict.UNKNOWN)
                checks = {r.check_type: r for r in self.repo.list_check_results(job.job_id)}
                self.assertEqual((checks[CAPTURE].outcome, checks[CAPTURE].reason_code),
                                 (CheckOutcome.UNKNOWN, reason))
                self.assertEqual(self.repo.get_job(job.job_id).snapshot.baseline_id, baseline)
                rows = self.repo.list_artifacts(job.job_id, attempt.attempt_id)
                manifest = self.repo.get_manifest_row(job.job_id, attempt.attempt_id)
                doc = verify_published(self.store, rows, manifest, job.snapshot, attempt)
                self.assertEqual((doc["baseline_id"], doc["quality"]), (baseline, "UNKNOWN"))
                png = next(r for r in rows if r.kind.value == "SCREENSHOT_PNG")
                self.assertEqual(self.store.read_bytes(png.rel_path), wire.png_1x1())

    def test_http_status_classes_derive_without_promotion(self):
        for status, outcome in ((100, "UNKNOWN"), (199, "UNKNOWN"), (200, "PASS"),
                                (299, "PASS"), (300, "UNKNOWN"), (399, "UNKNOWN"),
                                (400, "FAIL"), (404, "FAIL"), (500, "FAIL"), (599, "FAIL")):
            with self.subTest(status=status):
                job, attempt = self.job((HTTP,))
                result = self.run_wire(job, attempt, [("HTTP_RECORD", http(status))])
                self.assertIs(result.outcome.commit_state, CommitState.COMMITTED)
                self.assertEqual(result.outcome.quality.value, outcome)
                check, = self.repo.list_check_results(job.job_id)
                self.assertEqual(check.outcome.value, outcome)
                self.assertEqual(check.reason_code, f"HTTP_{status}_UNRESOLVED"
                                 if outcome == "UNKNOWN" else f"HTTP_{status}")

    def test_explicit_unknowns_stay_unknown(self):
        items = [("HTTP_RECORD", record("HTTP", state="UNKNOWN", reason_code="NO_OBSERVATION")),
                 ("LOAD_RECORD", load("UNKNOWN", "NO_OBSERVATION")),
                 ("CAPTURE_RECORD", capture(state="UNKNOWN", comparison="NOT_EVALUATED",
                                              reason="NO_OBSERVATION"))]
        job, attempt = self.job()
        result = self.run_wire(job, attempt, items)
        self.assertIs(result.outcome.commit_state, CommitState.COMMITTED)
        self.assertIs(result.outcome.quality, QualityVerdict.UNKNOWN)
        self.assertTrue(all(r.outcome is CheckOutcome.UNKNOWN
                            for r in self.repo.list_check_results(job.job_id)))

    def test_explicit_http_failure_justifies_follower_skips(self):
        job, attempt = self.job()
        items = [("HTTP_RECORD", http(404)),
                 ("LOAD_RECORD", load("SKIPPED", "UPSTREAM_HTTP_FAILED")),
                 ("CAPTURE_RECORD", capture(state="SKIPPED", comparison="NOT_EVALUATED",
                                              reason="UPSTREAM_HTTP_FAILED"))]
        result = self.run_wire(job, attempt, items)
        self.assertIs(result.outcome.commit_state, CommitState.COMMITTED)
        self.assertIs(result.outcome.quality, QualityVerdict.FAIL)
        checks = {r.check_type: r.outcome for r in self.repo.list_check_results(job.job_id)}
        self.assertEqual(checks, {HTTP: CheckOutcome.FAIL, LOAD: CheckOutcome.SKIPPED,
                                  CAPTURE: CheckOutcome.SKIPPED})

    def test_invalid_skips_rejected(self):
        skipped = load("SKIPPED", "UPSTREAM_HTTP_FAILED")
        cases = [((HTTP,), [("HTTP_RECORD", record("HTTP", state="SKIPPED",
                                                   reason_code="UPSTREAM_HTTP_FAILED"))]),
                 ((LOAD,), [("LOAD_RECORD", skipped)]),
                 ((HTTP, LOAD), [("HTTP_RECORD", http()), ("LOAD_RECORD", skipped)]),
                 ((HTTP, LOAD), [("HTTP_RECORD", http(302)), ("LOAD_RECORD", skipped)]),
                 ((HTTP, LOAD), [("HTTP_RECORD", record("HTTP", state="UNKNOWN", reason_code="NO_HTTP")),
                                 ("LOAD_RECORD", skipped)]),
                 ((HTTP, LOAD), [("HTTP_RECORD", http(404)),
                                 ("LOAD_RECORD", load("SKIPPED", "OTHER_REASON"))]),
                 ((CAPTURE,), [("CAPTURE_RECORD", capture(state="SKIPPED", comparison="NOT_EVALUATED",
                                                          reason="UPSTREAM_HTTP_FAILED"))]),
                 ((HTTP, CAPTURE), [("HTTP_RECORD", http()),
                                    ("CAPTURE_RECORD", capture(state="SKIPPED", comparison="NOT_EVALUATED",
                                                               reason="UPSTREAM_HTTP_FAILED"))])]
        for checks, items in cases:
            with self.subTest(checks=checks, items=items):
                job, attempt = self.job(checks)
                result = self.run_wire(job, attempt, items)
                self.assertEqual(result.transport.summary.termination, "CLEAN")
                self.assertIs(result.outcome.job.status, JobStatus.FAILED_EVIDENCE)
                self.assertTrue(result.outcome.reason.startswith("SKIP_NOT_JUSTIFIED:"))
                self.assert_no_adoption(job, attempt)
        self.assert_no_files()

    def test_missing_required_records_or_png_never_autofilled(self):
        for items in ([], complete()[:1], complete()[:2], complete()[:3],
                      [complete()[0], complete()[1], complete()[3]]):
            with self.subTest(kinds=[k for k, _ in items]):
                job, attempt = self.job()
                result = self.run_wire(job, attempt, items)
                self.assertEqual(result.transport.summary.termination, "CLEAN")
                self.assertIs(result.outcome.job.status, JobStatus.FAILED_EVIDENCE)
                self.assertTrue(result.outcome.reason.startswith(
                    ("REQUIRED_CHECK_MISSING:", "ARTIFACT_MISSING:")))
                self.assert_no_adoption(job, attempt)
        self.assert_no_files()

    def test_record_syntax_and_schema_rejections(self):
        valid = http()
        bad = [b"\xff", b"{", b"[]", b"null", valid + b" x",
               valid.replace(b'"record_type":"HTTP"', b'"record_type":"LOAD"'),
               valid.replace(b'"record_type":"HTTP"', b'"record_type":"HTTP","record_type":"HTTP"'),
               valid.replace(b'"status_code":200', b'"status_code":NaN'),
               valid.replace(b'"status_code":200', b'"status_code":true'),
               valid.replace(b'"status_code":200', b'"status_code":600'),
               valid.replace(b'"status_code":200', b'"status_code":99'),
               valid.replace(b'"schema_version":"siteproof.record.v0.1"', b'"schema_version":"other"'),
               valid.replace(b'"observation":{', b'"job_id":"forged","observation":{'),
               record("HTTP", state="OBSERVED", reason_code="NO_STATUS"),
               record("HTTP", state="UNKNOWN", status_code=200, reason_code="WRONG_FIELDS"),
               record("HTTP", state="OBSERVED", status_code=200, reason_code=" ")]
        for payload in bad:
            with self.subTest(payload=payload):
                job, attempt = self.job((HTTP,))
                result = self.run_wire(job, attempt, [("HTTP_RECORD", payload)])
                self.assertEqual(result.transport.summary.termination, "CLEAN")
                self.assertIs(result.outcome.job.status, JobStatus.FAILED_EVIDENCE)
                self.assert_no_adoption(job, attempt)
        self.assert_no_files()

    def test_capture_baseline_and_comparison_fabrication_rejected(self):
        for baseline, payload in ((None, capture("baseline-1")), ("baseline-1", capture()),
                                  (None, capture(reason="BASELINE_PENDING")),
                                  (None, capture(comparison="SAME")),
                                  (None, capture(state="PASS")),
                                  ("baseline-1", capture("baseline-1", comparison="CHANGED"))):
            with self.subTest(baseline=baseline, payload=payload):
                job, attempt = self.job((CAPTURE,), baseline)
                result = self.run_wire(job, attempt, [("CAPTURE_RECORD", payload),
                                                     ("SCREENSHOT_PNG", wire.png_1x1())])
                self.assertIs(result.outcome.job.status, JobStatus.FAILED_EVIDENCE)
                self.assert_no_adoption(job, attempt)
        self.assert_no_files()

    def test_unexpected_png_for_failed_capture_rejected(self):
        job, attempt = self.job((CAPTURE,))
        result = self.run_wire(job, attempt, [
            ("CAPTURE_RECORD", capture(state="FAILED", comparison="NOT_EVALUATED", reason="CAPTURE_FAILED")),
            ("SCREENSHOT_PNG", wire.png_1x1())])
        self.assertTrue(result.outcome.reason.startswith("ARTIFACT_UNEXPECTED:"))
        self.assert_no_adoption(job, attempt)
        self.assert_no_files()

    def test_failed_capture_without_png_is_explicit_fail(self):
        job, attempt = self.job((CAPTURE,))
        result = self.run_wire(job, attempt, [("CAPTURE_RECORD", capture(
            state="FAILED", comparison="NOT_EVALUATED", reason="CAPTURE_FAILED"))])
        self.assertIs(result.outcome.commit_state, CommitState.COMMITTED)
        self.assertIs(result.outcome.quality, QualityVerdict.FAIL)

    def test_s1_rechecks_page_profile_required_check_and_duplicates(self):
        payload = http()
        cases = [((HTTP,), wire.packet(wire.header(0, length=len(payload), page_id="other"), payload) + wire.end()),
                 ((HTTP,), wire.packet(wire.header(0, length=len(payload), profile_id="other"), payload) + wire.end()),
                 ((LOAD,), stream([("HTTP_RECORD", payload)])),
                 ((HTTP,), stream([("HTTP_RECORD", payload), ("HTTP_RECORD", payload)]))]
        for (checks, data), code in zip(cases, ("PAGE_MISMATCH", "PROFILE_MISMATCH", "CHECK_NOT_REQUIRED", "DUPLICATE_FRAME")):
            with self.subTest(code=code):
                job, attempt = self.job(checks)
                result = self.bridge.finalize(job.job_id, attempt.attempt_id, io.BytesIO(data))
                self.assertEqual(result.transport.summary.termination, "CLEAN")
                self.assertEqual(result.outcome.reason, f"FRAME_REJECTED:{code}")
                self.assert_no_adoption(job, attempt)
        self.assert_no_files()

    def test_s1_rejects_preserved_post_reader_corruption(self):
        # This boundary-specific test deliberately mutates real reader output;
        # normal end-to-end tests above go through EvidenceBridge without mutation.
        changes = [("schema_version", "other", "SCHEMA_VERSION"),
                   ("job_id", "other", "JOB_MISMATCH"),
                   ("attempt_id", "other", "ATTEMPT_MISMATCH"),
                   ("lease_epoch", 99, "LEASE_EPOCH_MISMATCH"),
                   ("seq", 4, "SEQ_NOT_CONTIGUOUS"),
                   ("check_type", "LOAD", "KIND_CHECK_MISMATCH"),
                   ("byte_length", 0, "LENGTH_MISMATCH"),
                   ("sha256", "0" * 64, "HASH_MISMATCH"),
                   ("payload", b"x" * len(http()), "HASH_MISMATCH"),
                   ("provenance", "other", "PROVENANCE")]
        for field, value, code in changes:
            with self.subTest(field=field):
                job, attempt = self.job((HTTP,))
                result = FrameReader(io.BytesIO(stream([("HTTP_RECORD", http())])),
                                     TrustedContext(job.job_id, attempt.attempt_id, attempt.lease_epoch)).read()
                frame = replace(result.frames[0], **{field: value})
                adapted = adapt_stream(replace(result, frames=(frame,)))
                self.assertEqual(getattr(adapted.frames[0], field), value)
                outcome = self.finalizer.finalize(job.job_id, attempt.attempt_id, adapted.frames, adapted.summary)
                self.assertEqual(outcome.reason, f"FRAME_REJECTED:{code}")
                self.assert_no_adoption(job, attempt)
        self.assert_no_files()

    def test_s1_rejects_preserved_wrong_summary_counts(self):
        for changes, code in ((dict(frame_count=2), "FRAME_COUNT_MISMATCH"),
                               (dict(total_payload_bytes=0), "TOTAL_BYTES_MISMATCH")):
            with self.subTest(changes=changes):
                job, attempt = self.job((HTTP,))
                result = FrameReader(io.BytesIO(stream([("HTTP_RECORD", http())])),
                                     TrustedContext(job.job_id, attempt.attempt_id, 1)).read()
                adapted = adapt_stream(replace(result, summary=replace(result.summary, **changes)))
                outcome = self.finalizer.finalize(job.job_id, attempt.attempt_id, adapted.frames, adapted.summary)
                self.assertEqual(outcome.reason, code)
                self.assert_no_adoption(job, attempt)
        self.assert_no_files()

    def test_bounded_fragmented_source_not_closed_or_seeked(self):
        class Fragments(io.BytesIO):
            def read(self, size=-1):
                if size < 0:
                    raise AssertionError("unbounded read")
                return super().read(min(size, 3))

            def seek(self, *args):
                raise AssertionError("unexpected seek")

        job, attempt = self.job((HTTP,))
        source = Fragments(stream([("HTTP_RECORD", http())]))
        result = self.bridge.finalize(job.job_id, attempt.attempt_id, source)
        self.assertIs(result.outcome.commit_state, CommitState.COMMITTED)
        self.assertFalse(source.closed)

    def test_manifest_readback_detects_post_commit_artifact_tampering(self):
        job, attempt = self.job((HTTP,))
        result = self.run_wire(job, attempt, [("HTTP_RECORD", http())])
        self.assertIs(result.outcome.commit_state, CommitState.COMMITTED)
        rows = self.repo.list_artifacts(job.job_id, attempt.attempt_id)
        manifest = self.repo.get_manifest_row(job.job_id, attempt.attempt_id)
        self.store.resolve(rows[0].rel_path).write_bytes(b"tampered")
        with self.assertRaises(EvidenceMismatch):
            verify_published(self.store, rows, manifest, job.snapshot, attempt)


class WiredTransportTests(IntegrationCase):
    def test_wire_protocol_failures_do_not_adopt_prefix(self):
        prefix = stream([("HTTP_RECORD", http())], finish=False)
        raw_duplicate = wire.raw_header(wire.header()).replace(b'"seq":0', b'"seq":0,"seq":0')
        cases = [(b"", "TRUNCATED"), (prefix, "TRUNCATED"),
                 (prefix + wire.end(1) + b"x", "PROTOCOL_ERROR"),
                 (wire.packet(wire.header(1)), "PROTOCOL_ERROR"),
                 (prefix + wire.packet(wire.header(0)), "PROTOCOL_ERROR"),
                 (wire.packet(wire.header(seq=True)), "PROTOCOL_ERROR"),
                 (wire.packet(wire.header(version="other")), "PROTOCOL_ERROR"),
                 (wire.packet(wire.header(magic="other")), "PROTOCOL_ERROR"),
                 (wire.packet(wire.header(kind="OTHER")), "PROTOCOL_ERROR"),
                 (wire.packet(wire.header(length=-1)), "PROTOCOL_ERROR"),
                 (wire.packet(wire.header(length=True)), "PROTOCOL_ERROR"),
                 (wire.packet(wire.header(extra="unexpected")), "PROTOCOL_ERROR"),
                 (wire.packet(wire.header(page_id="")), "PROTOCOL_ERROR"),
                 (wire.end(0, declared_length=1), "PROTOCOL_ERROR"),
                 ((1).to_bytes(4, "big") + b"\xff", "PROTOCOL_ERROR"),
                 (len(raw_duplicate).to_bytes(4, "big") + raw_duplicate, "PROTOCOL_ERROR"),
                 (wire.packet(wire.header(length=999), b"partial"), "TRUNCATED")]
        for data, termination in cases:
            with self.subTest(data=data):
                job, attempt = self.job((HTTP,))
                result = self.bridge.finalize(job.job_id, attempt.attempt_id, io.BytesIO(data))
                self.assertEqual(result.transport.summary.termination, termination)
                self.assertIs(result.outcome.job.status, JobStatus.FAILED_EVIDENCE)
                self.assertEqual(result.outcome.reason, f"STREAM_{termination}")
                self.assert_no_adoption(job, attempt)
        self.assert_no_files()

    def test_wire_context_claims_rejected(self):
        for field, value in (("job_id", "forged"), ("attempt_id", "forged"), ("lease_epoch", 99)):
            with self.subTest(field=field):
                job, attempt = self.job((HTTP,))
                data = wire.packet(wire.header(**{field: value}))
                result = self.bridge.finalize(job.job_id, attempt.attempt_id, io.BytesIO(data))
                self.assertEqual(result.transport.reason, "UNTRUSTED_CONTEXT_CLAIM")
                self.assert_no_adoption(job, attempt)
        self.assert_no_files()

    def test_transport_quotas(self):
        items = complete()
        cases = [(FrameLimits(max_header_bytes=1), "HEADER_LIMIT"),
                 (FrameLimits(max_record_bytes=1), "FRAME_PAYLOAD_LIMIT"),
                 (FrameLimits(max_png_bytes=1), "FRAME_PAYLOAD_LIMIT"),
                 (FrameLimits(max_stream_payload_bytes=len(http())), "STREAM_PAYLOAD_LIMIT"),
                 (FrameLimits(max_data_frames=1), "FRAME_COUNT_LIMIT")]
        for limits, reason in cases:
            with self.subTest(reason=reason, limits=limits):
                job, attempt = self.job()
                result = self.run_wire(job, attempt, items, limits=limits)
                self.assertEqual((result.transport.summary.termination, result.transport.reason),
                                 ("OVERSIZE", reason))
                self.assertIs(result.outcome.job.status, JobStatus.FAILED_EVIDENCE)
                self.assert_no_adoption(job, attempt)
        self.assert_no_files()

    def test_invalid_png_container_and_pixel_limit(self):
        for png in (b"\x89PNG\r\n\x1a\n", wire.png_1x1()[:-1],
                    wire.png_1x1()[:-5] + b"broken", wire.png_1x1() + b"extra"):
            with self.subTest(png=png):
                job, attempt = self.job((CAPTURE,))
                result = self.run_wire(job, attempt, [("CAPTURE_RECORD", capture()), ("SCREENSHOT_PNG", png)])
                self.assertEqual((result.transport.summary.termination, result.transport.reason),
                                 ("PROTOCOL_ERROR", "INVALID_PNG"))
                self.assert_no_adoption(job, attempt)
        job, attempt = self.job((CAPTURE,))
        result = self.run_wire(job, attempt, [("SCREENSHOT_PNG", wire.png(width=2))],
                               limits=FrameLimits(max_png_pixels=1))
        self.assertEqual(result.transport.reason, "INVALID_PNG")
        self.assert_no_adoption(job, attempt)
        self.assert_no_files()

    def test_timeout_error_and_deadline_become_timed_out(self):
        class TimeoutSource:
            def read(self, size):
                raise TimeoutError("offline injected")

        for source, kwargs, reason in ((TimeoutSource(), {}, "SOURCE_TIMEOUT"),
                                       (io.BytesIO(b""), dict(clock=iter((0.0, 1.0)).__next__,
                                                              limits=FrameLimits(timeout_seconds=1)), "DEADLINE")):
            with self.subTest(reason=reason):
                job, attempt = self.job((HTTP,))
                result = self.bridge.finalize(job.job_id, attempt.attempt_id, source, **kwargs)
                self.assertEqual(result.transport.reason, reason)
                self.assertIs(result.outcome.job.status, JobStatus.TIMED_OUT)
                self.assert_no_adoption(job, attempt)
        self.assert_no_files()

    def test_source_errors_and_invalid_reads_are_protocol_errors(self):
        class BadSource:
            def __init__(self, value):
                self.value = value

            def read(self, size):
                if isinstance(self.value, Exception):
                    raise self.value
                return self.value

        for value in (OSError("offline injected"), None, "text", b"x" * 5):
            with self.subTest(value=value):
                job, attempt = self.job((HTTP,))
                result = self.bridge.finalize(job.job_id, attempt.attempt_id, BadSource(value))
                self.assertEqual(result.transport.summary.termination, "PROTOCOL_ERROR")
                self.assert_no_adoption(job, attempt)
        self.assert_no_files()


class WiredAttemptSafetyTests(IntegrationCase):
    def test_canonical_connection_id_preconditions_are_not_sanitized(self):
        # The committed model's '$' regex admits a trailing newline (PF03).
        # If that is fixed later, upstream rejection also satisfies this test.
        for field in ("job_id", "attempt_id", "page_id", "profile_id"):
            with self.subTest(field=field):
                repo = Repository(self.base / f"{field}.sqlite3", id_factory=lambda: (
                    "job-1\n" if field == "job_id" else "job-1"))
                repo.init()
                source = io.BytesIO(b"untouched")
                try:
                    intent = JobIntent("https://fixture.invalid/", "page-1\n" if field == "page_id" else "page-1",
                                       "profile-1\n" if field == "profile_id" else "profile-1", (HTTP,))
                    job = repo.accept_job("key-1", intent).job
                    attempt = repo.register_attempt(job.job_id,
                                                    "attempt-1\n" if field == "attempt_id" else "attempt-1", 1)
                    for status in (JobStatus.WAITING_WORKER, JobStatus.RUNNING, JobStatus.SAVING):
                        job = repo.transition(job.job_id, job.version, status)
                except ValidationError:
                    self.assertEqual(source.tell(), 0)
                    continue
                bridge = EvidenceBridge(EvidenceFinalizer(repo, self.store))
                with self.assertRaises(AdapterError):
                    bridge.finalize(job.job_id, attempt.attempt_id, source)
                self.assertEqual(source.tell(), 0)
                self.assertEqual(repo.get_job(job.job_id), job)
                self.assertEqual(repo.list_check_results(job.job_id), [])
        self.assert_no_files()

    def test_canonical_repository_attempt_context(self):
        job, old = self.job((HTTP,))
        attempt = self.repo.register_attempt(job.job_id, "attempt-2", 7)
        result = self.run_wire(job, attempt, [("HTTP_RECORD", http())])
        frame, = result.transport.frames
        self.assertEqual((frame.job_id, frame.attempt_id, frame.lease_epoch),
                         (job.job_id, attempt.attempt_id, 7))
        self.assertEqual(result.outcome.job.adopted_attempt_id, attempt.attempt_id)
        self.assertEqual(self.repo.list_artifacts(job.job_id, old.attempt_id), [])

    def test_stale_attempt_rejected_before_read(self):
        job, old = self.job((HTTP,))
        self.repo.register_attempt(job.job_id, "attempt-2", 2)
        source = io.BytesIO(stream([("HTTP_RECORD", http())]))
        with self.assertRaises(StaleAttemptError):
            self.bridge.finalize(job.job_id, old.attempt_id, source)
        self.assertEqual(source.tell(), 0)
        self.assertEqual(self.repo.get_job(job.job_id), job)
        self.assert_no_adoption(job, old)
        self.assert_no_files()

    def test_unknown_and_invalid_context_rejected_before_read(self):
        job, attempt = self.job((HTTP,))
        for job_id, attempt_id, error in (("unknown", attempt.attempt_id, UnknownJob),
                                          (job.job_id, "unknown", UnknownAttempt),
                                          (job.job_id, "bad/id", ValidationError)):
            with self.subTest(job=job_id, attempt=attempt_id):
                source = io.BytesIO(b"untouched")
                with self.assertRaises(error):
                    self.bridge.finalize(job_id, attempt_id, source)
                self.assertEqual(source.tell(), 0)
        self.assert_no_files()

    def test_non_saving_and_terminal_jobs_rejected_before_read(self):
        job, attempt = self.job((HTTP,), saving=False)
        source = io.BytesIO(b"untouched")
        with self.assertRaises(InvalidTransition):
            self.bridge.finalize(job.job_id, attempt.attempt_id, source)
        self.repo.cancel(job.job_id)
        with self.assertRaises(TerminalJobError):
            self.bridge.finalize(job.job_id, attempt.attempt_id, source)
        self.assertEqual(source.tell(), 0)
        self.assert_no_files()

    def test_attempt_changed_during_read_cannot_adopt_or_fail_new_attempt(self):
        for data in (stream([("HTTP_RECORD", http())]), b"invalid"):
            with self.subTest(data=data):
                job, attempt = self.job((HTTP,))
                repo = self.repo

                class SupersedingSource(io.BytesIO):
                    changed = False

                    def read(self, size=-1):
                        if not self.changed:
                            self.changed = True
                            repo.register_attempt(job.job_id, "attempt-2", 2)
                        return super().read(size)

                with self.assertRaises(StaleAttemptError):
                    self.bridge.finalize(job.job_id, attempt.attempt_id, SupersedingSource(data))
                self.assertEqual(self.repo.get_job(job.job_id), job)
                self.assert_no_adoption(job, attempt)
        self.assert_no_files()

    def test_new_attempt_during_commit_is_lost_race(self):
        job, attempt = self.job((HTTP,))
        self.fp.on("before_final_commit", lambda: self.repo.register_attempt(job.job_id, "attempt-2", 2))
        result = self.run_wire(job, attempt, [("HTTP_RECORD", http())])
        self.assertIs(result.outcome.commit_state, CommitState.LOST_RACE)
        self.assertEqual(self.repo.get_job(job.job_id), job)
        self.assertTrue(result.outcome.unadopted_files)
        self.assertTrue(all(self.store.exists(p) for p in result.outcome.unadopted_files))
        self.assert_no_adoption(job, attempt)

    def test_new_attempt_during_failure_does_not_terminalise_it(self):
        job, attempt = self.job((HTTP,))
        self.fp.on("after_entry_checks", lambda: self.repo.register_attempt(job.job_id, "attempt-2", 2))
        result = self.bridge.finalize(job.job_id, attempt.attempt_id, io.BytesIO(b""))
        self.assertIs(result.outcome.commit_state, CommitState.LOST_RACE)
        self.assertEqual(self.repo.get_job(job.job_id), job)
        self.assert_no_adoption(job, attempt)
        self.assert_no_files()

    def test_cancel_during_commit_wins(self):
        job, attempt = self.job((HTTP,))
        self.fp.on("before_final_commit", lambda: self.repo.cancel(job.job_id))
        result = self.run_wire(job, attempt, [("HTTP_RECORD", http())])
        self.assertIs(result.outcome.commit_state, CommitState.LOST_RACE)
        self.assertIs(self.repo.get_job(job.job_id).status, JobStatus.CANCELLED)
        self.assert_no_adoption(job, attempt)

    def test_precommit_artifact_corruption_never_adopted(self):
        job, attempt = self.job((HTTP,))

        def corrupt():
            path, = self.store.attempt_dir(job.job_id, attempt.attempt_id).glob("*.bin")
            path.write_bytes(b"tampered")

        self.fp.on("before_final_commit", corrupt)
        result = self.run_wire(job, attempt, [("HTTP_RECORD", http())])
        self.assertIs(result.outcome.job.status, JobStatus.FAILED_EVIDENCE)
        self.assertTrue(result.outcome.reason.startswith("PRECOMMIT_REVERIFY_FAILED:"))
        self.assert_no_adoption(job, attempt)

    def test_lost_commit_ack_resolved_from_database(self):
        job, attempt = self.job((HTTP,))
        self.fp.fail("after_commit")
        result = self.run_wire(job, attempt, [("HTTP_RECORD", http())])
        self.assertIs(result.outcome.commit_state, CommitState.COMMITTED)
        self.assertIs(self.repo.get_job(job.job_id).status, JobStatus.COMPLETED)
        self.assertTrue(result.outcome.reason.startswith("COMMIT_RESULT_UNCERTAIN:"))

    def test_rolled_back_commit_remains_not_committed(self):
        job, attempt = self.job((HTTP,))
        self.fp.fail("before_commit")
        result = self.run_wire(job, attempt, [("HTTP_RECORD", http())])
        self.assertIs(result.outcome.commit_state, CommitState.NOT_COMMITTED)
        self.assertEqual(self.repo.get_job(job.job_id), job)
        self.assertTrue(result.outcome.unadopted_files)
        self.assert_no_adoption(job, attempt)
