import dataclasses
import json
import sqlite3
import types
import unittest

from src.core.errors import (ArtifactExistsError, EvidenceMismatch, StaleAttemptError,
                             TerminalJobError, ValidationError)
from src.core.frames import Termination
from src.core.model import (AttemptRef, CheckReport, JobStatus, QualityVerdict, sha256_hex)
from src.core.synthetic import (capture_record, http_record, load_record, make_summary,
                                record_bytes)
from src.storage.artifacts import ArtifactStore
from src.storage.failpoints import SimulatedCrash
from src.storage.finalizer import CommitState, EvidenceFinalizer
from src.storage.manifest import (manifest_bytes, verify_manifest_document, verify_stored)
from src.storage.recovery import plan_recovery

from support import CAPTURE, HTTP, K, LOAD, O, StorageTestCase

S = JobStatus
SKIP404 = {K.HTTP_RECORD: http_record(404),
           K.LOAD_RECORD: load_record("SKIPPED", "UPSTREAM_HTTP_FAILED"),
           K.CAPTURE_RECORD: capture_record("SKIPPED", "NOT_EVALUATED", "UPSTREAM_HTTP_FAILED")}


class NormalFinalizeTests(StorageTestCase):
    def test_http_and_load_pass_gives_quality_pass_with_verified_manifest(self):
        job, att, fr, out = self.run_complete(checks=(HTTP, LOAD))
        self.assertEqual(out.commit_state, CommitState.COMMITTED)
        self.assertEqual((out.job.status, out.quality), (S.COMPLETED, QualityVerdict.PASS))
        self.assertEqual(out.job.adopted_attempt_id, att.attempt_id)
        self.assertEqual(out.job.version, job.version + 1)
        m = self.repo.get_manifest_row(job.job_id, att.attempt_id)
        self.assertEqual(m.rel_path, out.manifest_rel_path)
        doc = verify_stored(self.store, m.rel_path, m.sha256, job.snapshot, att)
        self.assertEqual((doc["quality"], len(doc["artifacts"])), ("PASS", 2))
        self.assertEqual(len(self.evidence_files()), 3)  # 2 records + manifest, no temp left
        for r, f in zip(self.repo.list_artifacts(job.job_id, att.attempt_id), fr):
            self.assertEqual((r.sha256, r.byte_length), (f.sha256, f.byte_length))
            self.assertEqual(self.store.read_bytes(r.rel_path), f.payload)

    def test_first_capture_without_baseline_completes_as_unknown_baseline_pending(self):
        job, att, fr, out = self.run_complete(baseline=None)
        self.assertEqual((out.job.status, out.quality), (S.COMPLETED, QualityVerdict.UNKNOWN))
        res = {r.check_type: r for r in self.repo.list_check_results(job.job_id)}
        self.assertEqual((res[CAPTURE].outcome, res[CAPTURE].reason_code),
                         (O.UNKNOWN, "BASELINE_PENDING"))
        self.assertEqual((res[HTTP].outcome, res[LOAD].outcome), (O.PASS, O.PASS))
        self.assertEqual(len(self.evidence_files()), 5)  # PNG + all records + manifest
        self.assertIsNone(self.repo.get_job(job.job_id).snapshot.baseline_id)  # none invented
        types = {a.kind for a in self.repo.list_artifacts(job.job_id, att.attempt_id)}
        self.assertIn(K.SCREENSHOT_PNG, types)

    def test_baseline_present_but_comparison_not_run_is_unknown_not_pass(self):
        job, att, fr, out = self.run_complete(baseline="base-1")
        self.assertEqual((out.job.status, out.quality), (S.COMPLETED, QualityVerdict.UNKNOWN))
        cap = {r.check_type: r for r in self.repo.list_check_results(job.job_id)}[CAPTURE]
        self.assertEqual((cap.outcome, cap.reason_code), (O.UNKNOWN, "COMPARISON_NOT_RUN"))

    def test_first_capture_does_not_hide_a_real_failure(self):
        job, att = self.start_saving(self.new_job(baseline=None))
        fr = self.frames(job, att, self.ALL_KINDS, payloads={K.HTTP_RECORD: http_record(503)})
        out = self.finalize(job, att, fr)
        self.assertEqual((out.job.status, out.quality), (S.COMPLETED, QualityVerdict.FAIL))

    def test_http_404_with_explicit_skipped_followers_completes_but_quality_fails(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.RECORD_KINDS, payloads=SKIP404)
        out = self.finalize(job, att, fr)
        self.assertEqual(out.job.status, S.COMPLETED)          # execution + evidence complete
        self.assertEqual(out.quality, QualityVerdict.FAIL)      # ...yet quality is FAIL
        res = {r.check_type: r for r in self.repo.list_check_results(job.job_id)}
        self.assertEqual((res[HTTP].outcome, res[LOAD].outcome, res[CAPTURE].outcome),
                         (O.FAIL, O.SKIPPED, O.SKIPPED))
        self.assertEqual(res[LOAD].reason_code, "UPSTREAM_HTTP_FAILED")
        self.assertFalse(any("screenshot" in p for p in self.evidence_files()))  # no PNG needed

    def test_unknown_and_3xx_never_yield_quality_pass(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.RECORD_KINDS, payloads={
            K.HTTP_RECORD: http_record(302),
            K.LOAD_RECORD: load_record("UNKNOWN", "LOAD_SIGNAL_LOST"),
            K.CAPTURE_RECORD: capture_record("UNKNOWN", "NOT_EVALUATED", "VIEWPORT_LOST")})
        out = self.finalize(job, att, fr)
        self.assertEqual((out.job.status, out.quality), (S.COMPLETED, QualityVerdict.UNKNOWN))
        res = {r.check_type: r for r in self.repo.list_check_results(job.job_id)}
        self.assertEqual(res[HTTP].outcome, O.UNKNOWN)

    def test_explicit_capture_failure_needs_no_png(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.RECORD_KINDS, payloads={
            K.CAPTURE_RECORD: capture_record("FAILED", "NOT_EVALUATED", "RENDER_CRASH")})
        out = self.finalize(job, att, fr)
        self.assertEqual((out.job.status, out.quality), (S.COMPLETED, QualityVerdict.FAIL))

    def test_matching_explicit_reports_are_accepted(self):
        job, att = self.start_saving(self.new_job(checks=(HTTP, LOAD)))
        fr = self.frames(job, att, [K.HTTP_RECORD, K.LOAD_RECORD])
        out = self.finalize(job, att, fr, [CheckReport(HTTP, O.PASS, "HTTP_STATUS_OBSERVED"),
                                           CheckReport(LOAD, O.PASS, "LOAD_EVENT_OBSERVED")])
        self.assertEqual(out.job.status, S.COMPLETED)


class EvidenceFailureTests(StorageTestCase):
    def assert_failed_evidence(self, job, out, text):
        self.assertEqual(out.job.status, S.FAILED_EVIDENCE)
        self.assertIn(text, out.job.terminal_reason)
        self.assertEqual(out.commit_state, CommitState.NOT_ATTEMPTED)
        self.assertEqual(self.repo.list_check_results(job.job_id), [])
        self.assertIsNone(self.repo.get_job(job.job_id).adopted_attempt_id)

    def test_http_404_record_with_pass_report_is_rejected(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS, payloads={K.HTTP_RECORD: http_record(404)})
        lying = [CheckReport(HTTP, O.PASS, "HTTP_STATUS_OBSERVED"),
                 CheckReport(LOAD, O.PASS, "LOAD_EVENT_OBSERVED"),
                 CheckReport(CAPTURE, O.UNKNOWN, "COMPARISON_NOT_RUN")]
        out = self.finalize(job, att, fr, lying)
        self.assert_failed_evidence(job, out, "REPORT_RECORD_MISMATCH")
        self.assertEqual(self.evidence_files(), [])

    def test_report_that_differs_in_any_way_from_the_records_is_rejected(self):
        derived = [CheckReport(HTTP, O.PASS, "HTTP_STATUS_OBSERVED"),
                   CheckReport(LOAD, O.PASS, "LOAD_EVENT_OBSERVED"),
                   CheckReport(CAPTURE, O.UNKNOWN, "COMPARISON_NOT_RUN")]
        variants = [
            derived[:2],                                                     # incomplete
            derived[:2] + [CheckReport(CAPTURE, O.PASS, "COMPARISON_NOT_RUN")],  # promoted
            derived[:2] + [CheckReport(CAPTURE, O.UNKNOWN, "OTHER_REASON")],     # other reason
            [CheckReport(HTTP, O.PASS, "WHY_NOT")] + derived[1:],                # other reason
        ]
        for i, reports in enumerate(variants):
            job, att = self.start_saving(self.new_job(f"key-{i}"))
            out = self.finalize(job, att, self.frames(job, att, self.ALL_KINDS), reports)
            self.assert_failed_evidence(job, out, "REPORT_RECORD_MISMATCH")

    def test_unrequired_or_duplicate_reports_fail(self):
        job, att = self.start_saving(self.new_job(checks=(HTTP,)))
        fr = self.frames(job, att, [K.HTTP_RECORD])
        out = self.finalize(job, att, fr, [CheckReport(HTTP, O.PASS, "HTTP_STATUS_OBSERVED"),
                                           CheckReport(LOAD, O.PASS, "OK")])
        self.assert_failed_evidence(job, out, "CHECK_NOT_REQUIRED")
        job2, att2 = self.start_saving(self.new_job("k2", checks=(HTTP,)))
        out2 = self.finalize(job2, att2, self.frames(job2, att2, [K.HTTP_RECORD]),
                             [CheckReport(HTTP, O.PASS, "OK"), CheckReport(HTTP, O.FAIL, "X")])
        self.assert_failed_evidence(job2, out2, "DUPLICATE_CHECK_REPORT")

    def test_reports_of_the_wrong_container_or_element_type_fail_cleanly(self):
        """PF-01: no AttributeError/TypeError escapes; the job ends FAILED_EVIDENCE."""
        good = CheckReport(HTTP, O.PASS, "HTTP_STATUS_OBSERVED")
        duck = types.SimpleNamespace(check_type=HTTP, outcome=O.PASS,
                                     reason_code="HTTP_STATUS_OBSERVED")
        bad_reports = {
            "dict": {HTTP: good},
            "set": {good},
            "str": "HTTP",
            "bytes": b"HTTP",
            "int": 7,
            "generator": (r for r in [good]),
            "tuple_element": [(HTTP, O.PASS, "HTTP_STATUS_OBSERVED")],
            "dict_element": [{"check_type": "HTTP", "outcome": "PASS"}],
            "none_element": [None],
            "duck_typed_element": [duck],
            "good_then_bad": [good, duck],
        }
        for i, (name, reports) in enumerate(bad_reports.items()):
            job, att = self.start_saving(self.new_job(f"key-{i}", checks=(HTTP,)))
            fr = self.frames(job, att, [K.HTTP_RECORD])
            out = self.finalize(job, att, fr, reports)
            with self.subTest(name):
                self.assert_failed_evidence(job, out, "CHECK_REPORT_TYPE")
                self.assertEqual(self.evidence_files(), [])

    def test_reports_as_tuple_or_list_of_checkreports_are_still_accepted(self):
        for i, container in enumerate((tuple, list)):
            job, att = self.start_saving(self.new_job(f"key-{i}", checks=(HTTP,)))
            fr = self.frames(job, att, [K.HTTP_RECORD])
            out = self.finalize(job, att, fr,
                                container([CheckReport(HTTP, O.PASS, "HTTP_STATUS_OBSERVED")]))
            self.assertEqual((out.job.status, out.commit_state),
                             (S.COMPLETED, CommitState.COMMITTED))

    def test_missing_required_check_record_is_not_backfilled(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, [K.HTTP_RECORD, K.LOAD_RECORD])  # CAPTURE never reported
        out = self.finalize(job, att, fr)
        self.assert_failed_evidence(job, out, "REQUIRED_CHECK_MISSING:CAPTURE")
        self.assertEqual(self.evidence_files(), [])

    def test_screenshot_alone_does_not_stand_in_for_the_capture_record(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, [K.HTTP_RECORD, K.LOAD_RECORD, K.SCREENSHOT_PNG])
        self.assert_failed_evidence(job, self.finalize(job, att, fr),
                                    "REQUIRED_CHECK_MISSING:CAPTURE")

    def test_successful_capture_without_png_fails_with_or_without_baseline(self):
        for i, baseline in enumerate((None, "base-1")):
            job, att = self.start_saving(self.new_job(f"key-{i}", baseline=baseline))
            fr = self.frames(job, att, self.RECORD_KINDS)  # capture succeeded, no PNG
            out = self.finalize(job, att, fr)
            self.assert_failed_evidence(job, out, "ARTIFACT_MISSING")
        self.assertEqual(self.evidence_files(), [])

    def test_png_with_explicit_capture_failure_is_inconsistent(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS, payloads={
            K.CAPTURE_RECORD: capture_record("FAILED", "NOT_EVALUATED", "RENDER_CRASH")})
        self.assert_failed_evidence(job, self.finalize(job, att, fr), "ARTIFACT_UNEXPECTED")

    def test_malformed_records_fail_the_job_before_any_write(self):
        bad_payloads = {
            "RECORD_NOT_JSON": b"{not json",
            "RECORD_NOT_UTF8": b"\xff\xfe",
            "RECORD_NOT_OBJECT": b"[1]",
            "RECORD_DUPLICATE_KEY": b'{"schema_version":"x","schema_version":"y"}',
            "RECORD_SCHEMA_VERSION": record_bytes("HTTP", {"state": "SKIPPED",
                                                           "reason_code": "R"}).replace(
                b"v0.1", b"v9.9"),
            "RECORD_STATUS_CODE_INVALID": http_record(True),
            "RECORD_TYPE_MISMATCH": load_record(),  # a LOAD record inside HTTP_RECORD
        }
        for i, (code, payload) in enumerate(bad_payloads.items()):
            job, att = self.start_saving(self.new_job(f"key-{i}"))
            fr = self.frames(job, att, self.ALL_KINDS, payloads={K.HTTP_RECORD: payload})
            out = self.finalize(job, att, fr)
            self.assert_failed_evidence(job, out, code)
        self.assertEqual(self.evidence_files(), [])

    def test_capture_record_must_match_the_jobs_baseline_state(self):
        job, att = self.start_saving(self.new_job(baseline="base-1"))
        fr = self.frames(job, att, self.ALL_KINDS, payloads={K.CAPTURE_RECORD: capture_record()})
        self.assert_failed_evidence(job, self.finalize(job, att, fr),
                                    "RECORD_BASELINE_STATE_MISMATCH")

    def test_skip_without_justification_is_rejected(self):
        job, att = self.start_saving(self.new_job(checks=(HTTP, LOAD)))
        fr = self.frames(job, att, [K.HTTP_RECORD, K.LOAD_RECORD], payloads={
            K.LOAD_RECORD: load_record("SKIPPED", "UPSTREAM_HTTP_FAILED")})  # but HTTP was 200
        self.assert_failed_evidence(job, self.finalize(job, att, fr), "SKIP_NOT_JUSTIFIED")
        job2, att2 = self.start_saving(self.new_job("k2", checks=(HTTP, LOAD)))
        fr2 = self.frames(job2, att2, [K.HTTP_RECORD, K.LOAD_RECORD], payloads={
            K.HTTP_RECORD: http_record(404),
            K.LOAD_RECORD: load_record("SKIPPED", "BROWSER_SAID_SO")})
        self.assert_failed_evidence(job2, self.finalize(job2, att2, fr2), "SKIP_NOT_JUSTIFIED")

    def test_frame_hash_mismatch_fails_before_any_write(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS)
        fr[2] = dataclasses.replace(fr[2], sha256="a" * 64)
        out = self.finalize(job, att, fr)
        self.assert_failed_evidence(job, out, "FRAME_REJECTED:HASH_MISMATCH")
        self.assertEqual(self.evidence_files(), [])

    def test_seq_offset_or_gap_fails_before_any_write(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS, start_seq=1)  # starts at 1, count matches
        self.assert_failed_evidence(job, self.finalize(job, att, fr),
                                    "FRAME_REJECTED:SEQ_NOT_CONTIGUOUS")
        job2, att2 = self.start_saving(self.new_job("k2"))
        fr2 = self.frames(job2, att2, self.ALL_KINDS)
        fr2[3] = dataclasses.replace(fr2[3], seq=4)  # 0,1,2,4
        self.assert_failed_evidence(job2, self.finalize(job2, att2, fr2),
                                    "FRAME_REJECTED:SEQ_NOT_CONTIGUOUS")
        self.assertEqual(self.evidence_files(), [])

    def test_incomplete_streams_never_complete(self):
        for i, (term, expected) in enumerate((
                (Termination.TRUNCATED, S.FAILED_EVIDENCE),
                (Termination.OVERSIZE, S.FAILED_EVIDENCE),
                (Termination.PROTOCOL_ERROR, S.FAILED_EVIDENCE),
                (Termination.TIMEOUT, S.TIMED_OUT))):
            job, att = self.start_saving(self.new_job(f"key-{i}"))
            fr = self.frames(job, att, self.ALL_KINDS)
            out = self.finalize(job, att, fr, summary=make_summary(fr, term))
            self.assertEqual(out.job.status, expected, term)
        self.assertEqual(self.evidence_files(), [])

    def test_frame_for_unrequired_check_fails_the_job(self):
        job, att = self.start_saving(self.new_job(checks=(HTTP,)))
        fr = self.frames(job, att, [K.HTTP_RECORD, K.LOAD_RECORD])
        out = self.finalize(job, att, fr)
        self.assert_failed_evidence(job, out, "FRAME_REJECTED:CHECK_NOT_REQUIRED")

    def test_readback_detects_corruption_between_write_and_manifest_verification(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS)

        def corrupt():
            self.store.resolve(f"{job.job_id}/{att.attempt_id}/000001_load_record.bin"
                               ).write_bytes(b"tampered")
        self.fp.on("after_manifest_write", corrupt)
        out = self.finalize(job, att, fr)
        self.assertEqual(out.job.status, S.FAILED_EVIDENCE)
        self.assertIn("EVIDENCE_WRITE_FAILED:EvidenceMismatch", out.job.terminal_reason)
        self.assertEqual(self.repo.list_check_results(job.job_id), [])
        self.assertTrue(out.unadopted_files)
        for rel in out.unadopted_files:
            self.assertTrue(self.store.exists(rel))               # reported, not deleted

    def test_write_failure_midway_leaves_orphans_and_fails_evidence(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS)
        calls = []

        def fail_second():
            calls.append(1)
            if len(calls) == 2:
                raise OSError("disk full (simulated)")
        self.fp.on("after_artifact_write", fail_second)
        out = self.finalize(job, att, fr)
        self.assertEqual(out.job.status, S.FAILED_EVIDENCE)
        self.assertEqual(len(out.unadopted_files), 2)
        self.assertEqual(self.repo.list_check_results(job.job_id), [])


class LyingReadBackStore(ArtifactStore):
    """Agent-controlled store whose read-back disagrees with what was written."""

    def read_back(self, rel_path):
        real = super().read_back(rel_path)
        if rel_path.endswith("000001_load_record.bin"):
            return dataclasses.replace(real, sha256="0" * 64)
        return real


class PreCommitReverificationTests(StorageTestCase):
    """INT-09: everything published is re-read and re-hashed right before the final commit."""

    def setUp(self):
        super().setUp()
        self.job, self.att = self.start_saving(self.new_job())
        self.fr = self.frames(self.job, self.att, self.ALL_KINDS)
        self.adir = f"{self.job.job_id}/{self.att.attempt_id}"

    def assert_not_adopted(self, out, tampered_path=None, expected_bytes=None):
        self.assertEqual(out.job.status, S.FAILED_EVIDENCE)
        self.assertIn("PRECOMMIT_REVERIFY_FAILED", out.job.terminal_reason)
        self.assertNotEqual(out.job.status, S.COMPLETED)
        self.assertEqual(self.repo.list_check_results(self.job.job_id), [])
        self.assertEqual(self.repo.list_artifacts(self.job.job_id, self.att.attempt_id), [])
        self.assertIsNone(self.repo.get_manifest_row(self.job.job_id, self.att.attempt_id))
        self.assertTrue(out.unadopted_files)
        if tampered_path is not None:  # no automatic repair, deletion or re-adoption
            if expected_bytes is None:
                self.assertFalse(self.store.exists(tampered_path))
            else:
                self.assertEqual(self.store.read_bytes(tampered_path), expected_bytes)

    def test_artifact_modified_just_before_commit(self):
        path = f"{self.adir}/000001_load_record.bin"
        self.fp.on("before_final_commit", lambda: self.store.resolve(path).write_bytes(b"x" * 9))
        out = self.finalize(self.job, self.att, self.fr)
        self.assert_not_adopted(out, path, b"x" * 9)
        self.assertIn("ARTIFACT", out.job.terminal_reason)

    def test_artifact_modified_with_same_length(self):
        path = f"{self.adir}/000000_http_record.bin"
        original = self.fr[0].payload
        flipped = bytes([original[0] ^ 1]) + original[1:]
        self.fp.on("before_final_commit", lambda: self.store.resolve(path).write_bytes(flipped))
        out = self.finalize(self.job, self.att, self.fr)
        self.assert_not_adopted(out, path, flipped)
        self.assertIn("ARTIFACT_HASH_MISMATCH", out.job.terminal_reason)

    def test_artifact_deleted_just_before_commit(self):
        path = f"{self.adir}/000003_screenshot_png.png"
        self.fp.on("before_final_commit", lambda: self.store.resolve(path).unlink())
        out = self.finalize(self.job, self.att, self.fr)
        self.assert_not_adopted(out, path, None)
        self.assertIn("ARTIFACT_MISSING", out.job.terminal_reason)

    def test_manifest_modified_just_before_commit(self):
        path = f"{self.adir}/manifest.json"
        self.fp.on("before_final_commit",
                   lambda: self.store.resolve(path).write_bytes(b'{"forged":true}'))
        out = self.finalize(self.job, self.att, self.fr)
        self.assert_not_adopted(out, path, b'{"forged":true}')
        self.assertIn("MANIFEST", out.job.terminal_reason)

    def test_manifest_replaced_by_self_consistent_but_different_document(self):
        path = f"{self.adir}/manifest.json"

        def forge():
            p = self.store.resolve(path)
            doc = json.loads(p.read_bytes())
            doc["checks"][0]["reason_code"] = "FORGED"
            p.write_bytes(manifest_bytes(doc))
        self.fp.on("before_final_commit", forge)
        out = self.finalize(self.job, self.att, self.fr)
        self.assert_not_adopted(out)
        self.assertIn("MANIFEST_HASH_MISMATCH", out.job.terminal_reason)

    def test_manifest_deleted_just_before_commit(self):
        path = f"{self.adir}/manifest.json"
        self.fp.on("before_final_commit", lambda: self.store.resolve(path).unlink())
        out = self.finalize(self.job, self.att, self.fr)
        self.assert_not_adopted(out, path, None)
        self.assertIn("MANIFEST_UNREADABLE", out.job.terminal_reason)

    def test_stored_hash_differs_from_readback_result(self):
        finalizer = EvidenceFinalizer(
            self.repo, LyingReadBackStore(self.evidence_root, failpoints=self.fp))
        out = finalizer.finalize(self.job.job_id, self.att.attempt_id, self.fr,
                                 make_summary(self.fr))
        self.assertEqual(out.job.status, S.FAILED_EVIDENCE)
        self.assertIn("EVIDENCE_WRITE_FAILED:EvidenceMismatch", out.job.terminal_reason)
        self.assertEqual(self.repo.list_check_results(self.job.job_id), [])

    def test_untampered_evidence_is_adopted(self):
        out = self.finalize(self.job, self.att, self.fr)
        self.assertEqual((out.job.status, out.commit_state),
                         (S.COMPLETED, CommitState.COMMITTED))

    def test_tampering_after_the_last_check_is_not_prevented_but_is_detected_later(self):
        """Residual TOCTOU window: documented limitation. Not claimed to be closed."""
        path = f"{self.adir}/000000_http_record.bin"
        self.fp.on("after_precommit_reverify",
                   lambda: self.store.resolve(path).write_bytes(b"late tamper"))
        out = self.finalize(self.job, self.att, self.fr)
        self.assertEqual(out.commit_state, CommitState.COMMITTED)   # the window exists...
        report = plan_recovery(self.db_path, str(self.evidence_root))
        self.assertIn("EVIDENCE_INCONSISTENT", report.codes())      # ...recovery reports it
        self.assertEqual(self.store.read_bytes(path), b"late tamper")  # and never repairs it


class IntegrityAfterCompletionTests(StorageTestCase):
    def test_hash_mismatch_and_missing_file_are_detected_on_verify(self):
        job, att, fr, out = self.run_complete()
        m = self.repo.get_manifest_row(job.job_id, att.attempt_id)
        arts = self.repo.list_artifacts(job.job_id, att.attempt_id)
        path = self.store.resolve(arts[0].rel_path)
        original = path.read_bytes()
        path.write_bytes(original + b"x")
        with self.assertRaises(EvidenceMismatch) as cm:
            verify_stored(self.store, m.rel_path, m.sha256, job.snapshot, att)
        self.assertIn("LENGTH_MISMATCH", str(cm.exception))
        path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        with self.assertRaises(EvidenceMismatch) as cm:
            verify_stored(self.store, m.rel_path, m.sha256, job.snapshot, att)
        self.assertIn("HASH_MISMATCH", str(cm.exception))
        path.unlink()
        with self.assertRaises(EvidenceMismatch) as cm:
            verify_stored(self.store, m.rel_path, m.sha256, job.snapshot, att)
        self.assertIn("ARTIFACT_MISSING", str(cm.exception))

    def test_manifest_inconsistencies_are_detected(self):
        job, att, fr, out = self.run_complete()
        m = self.repo.get_manifest_row(job.job_id, att.attempt_id)
        doc = json.loads(self.store.read_bytes(m.rel_path))
        self.assertEqual(verify_manifest_document(doc, job.snapshot, att), [])

        def problems(mutate):
            d = json.loads(json.dumps(doc))
            mutate(d)
            return verify_manifest_document(d, job.snapshot, att)

        self.assertTrue(any("REQUIRED_CHECK_MISSING" in p for p in
                            problems(lambda d: d["checks"].pop(0))))
        self.assertIn("MANIFEST_QUALITY_MISMATCH", problems(lambda d: d.update(quality="FAIL")))
        png = next(a for a in doc["artifacts"] if a["kind"] == "SCREENSHOT_PNG")
        self.assertTrue(any("CHECK_ARTIFACT_MISSING:CAPTURE" in p for p in problems(
            lambda d: d["artifacts"].remove(next(a for a in d["artifacts"]
                                                 if a["seq"] == png["seq"])))))
        self.assertIn("MANIFEST_FIELD_MISMATCH:attempt_id",
                      problems(lambda d: d.update(attempt_id="other")))
        self.assertTrue(any("OUTSIDE_ATTEMPT" in p for p in problems(
            lambda d: d["artifacts"][0].update(rel_path="other-job/x/000000.bin"))))
        self.assertTrue(any(p.startswith("MANIFEST_MALFORMED") for p in
                            problems(lambda d: d["checks"][0].pop("outcome"))))
        self.store.resolve(m.rel_path).write_bytes(b"{}")
        with self.assertRaises(EvidenceMismatch):
            verify_stored(self.store, m.rel_path, m.sha256, job.snapshot, att)

    def test_hostile_manifest_values_become_problems_never_exceptions(self):
        job, att, fr, out = self.run_complete()
        m = self.repo.get_manifest_row(job.job_id, att.attempt_id)
        doc = json.loads(self.store.read_bytes(m.rel_path))

        def http_changed(d):
            others = json.loads(json.dumps([c for c in d["checks"]
                                           if c["check_type"] != "HTTP"]))
            next(c for c in d["checks"] if c["check_type"] == "HTTP").update(
                outcome="CHANGED")
            self.assertEqual(next(c for c in d["checks"]
                                  if c["check_type"] == "HTTP")["outcome"], "CHANGED")
            self.assertEqual([c for c in d["checks"] if c["check_type"] != "HTTP"], others)

        mutations = {
            "http_changed": http_changed,
            "unknown_outcome": lambda d: d["checks"][0].update(outcome="MAYBE"),
            "unknown_check_type": lambda d: d["checks"][0].update(check_type="DNS"),
            "reason_none": lambda d: d["checks"][0].update(reason_code=None),
            "reason_padded": lambda d: d["checks"][0].update(reason_code=" x "),
            "seqs_not_list": lambda d: d["checks"][0].update(artifact_seqs="0"),
            "seqs_strings": lambda d: d["checks"][0].update(artifact_seqs=["0"]),
            "seqs_nested": lambda d: d["checks"][0].update(artifact_seqs=[[0]]),
            "artifacts_string": lambda d: d.update(artifacts="oops"),
            "artifacts_null": lambda d: d.update(artifacts=None),
            "checks_null": lambda d: d.update(checks=None),
            "checks_dict": lambda d: d.update(checks={}),
            "artifact_not_object": lambda d: d["artifacts"].append(7),
            "artifact_seq_list": lambda d: d["artifacts"][0].update(seq=[1]),
            "artifact_seq_bool": lambda d: d["artifacts"][0].update(seq=True),
            "artifact_kind_bogus": lambda d: d["artifacts"][0].update(kind="PDF"),
            "artifact_kind_not_str": lambda d: d["artifacts"][0].update(kind=3),
            "artifact_hash_short": lambda d: d["artifacts"][0].update(sha256="abc"),
            "artifact_len_neg": lambda d: d["artifacts"][0].update(byte_length=-1),
            "artifact_len_float": lambda d: d["artifacts"][0].update(byte_length=1.5),
            "artifact_path_none": lambda d: d["artifacts"][0].update(rel_path=None),
            "artifact_missing_key": lambda d: d["artifacts"][0].pop("sha256"),
            "capture_pass_untrusted": lambda d: next(
                c for c in d["checks"] if c["check_type"] == "CAPTURE").update(outcome="PASS"),
            "capture_reason_flip": lambda d: next(
                c for c in d["checks"] if c["check_type"] == "CAPTURE").update(
                    reason_code="BASELINE_PENDING"),
            "required_not_list": lambda d: d.update(required_checks=7),
            "unjustified_skip": lambda d: next(
                c for c in d["checks"] if c["check_type"] == "LOAD").update(
                    outcome="SKIPPED", reason_code="WHATEVER"),
        }
        for name, mutate in mutations.items():
            d = json.loads(json.dumps(doc))
            mutate(d)
            try:
                found = verify_manifest_document(d, job.snapshot, att)
            except Exception as e:  # noqa: BLE001 - this is exactly what must not happen
                self.fail(f"{name}: leaked {type(e).__name__}: {e}")
            self.assertTrue(found, f"{name}: no problem reported")
            if name == "http_changed":
                self.assertIn("CHECK_OUTCOME_INVALID:HTTP:OUTCOME_NOT_ALLOWED", found)

    def test_manifest_artifact_policy_covers_every_artifact_of_the_check(self):
        """PF-06: a screenshot listed in `artifacts` but left out of a check's `artifact_seqs`
        must still be judged by the live finalizer's policy (validate_report)."""
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.RECORD_KINDS, payloads={
            K.CAPTURE_RECORD: capture_record("FAILED", "NOT_EVALUATED", "RENDER_CRASH")})
        out = self.finalize(job, att, fr)
        self.assertEqual(out.job.status, S.COMPLETED)
        m = self.repo.get_manifest_row(job.job_id, att.attempt_id)
        doc = json.loads(self.store.read_bytes(m.rel_path))
        self.assertEqual(verify_manifest_document(doc, job.snapshot, att), [])
        cap = next(c for c in doc["checks"] if c["check_type"] == "CAPTURE")
        self.assertEqual((cap["outcome"], cap["reason_code"]), ("FAIL", "RENDER_CRASH"))

        d = json.loads(json.dumps(doc))
        extra = dict(d["artifacts"][0], seq=max(a["seq"] for a in d["artifacts"]) + 1,
                     kind="SCREENSHOT_PNG", check_type="CAPTURE")
        d["artifacts"].append(extra)
        self.assertNotIn(extra["seq"], cap["artifact_seqs"])  # not referenced by the check
        self.assertEqual(verify_manifest_document(d, job.snapshot, att),
                         ["CHECK_EVIDENCE_INVALID:CAPTURE:ARTIFACT_UNEXPECTED"])

    def test_manifest_capture_pass_is_reported_by_the_shared_policy_too(self):
        job, att, fr, out = self.run_complete()
        m = self.repo.get_manifest_row(job.job_id, att.attempt_id)
        doc = json.loads(self.store.read_bytes(m.rel_path))
        next(c for c in doc["checks"] if c["check_type"] == "CAPTURE").update(outcome="PASS")
        found = verify_manifest_document(doc, job.snapshot, att)
        self.assertIn("CAPTURE_COMPARISON_UNTRUSTED", found)
        self.assertIn("CHECK_EVIDENCE_INVALID:CAPTURE:COMPARISON_EVIDENCE_UNAVAILABLE", found)

    def test_manifest_outcome_that_contradicts_the_stored_records_is_detected(self):
        job, att, fr, out = self.run_complete(checks=(HTTP, LOAD))
        m = self.repo.get_manifest_row(job.job_id, att.attempt_id)
        p = self.store.resolve(m.rel_path)
        doc = json.loads(p.read_bytes())
        doc["checks"][0].update(outcome="FAIL", reason_code="HTTP_STATUS_OBSERVED")  # record: 200
        doc["quality"] = "FAIL"                                  # internally consistent lie
        p.write_bytes(manifest_bytes(doc))
        self.assertEqual(verify_manifest_document(doc, job.snapshot, att), [])
        with self.assertRaises(EvidenceMismatch) as cm:
            verify_stored(self.store, m.rel_path, None, job.snapshot, att)
        self.assertIn("RECORD_MANIFEST_MISMATCH", str(cm.exception))

    def test_sql_cannot_complete_with_missing_required_check_or_artifact(self):
        job, att = self.start_saving(self.new_job(checks=(HTTP, LOAD)))
        c = self.raw()
        c.execute("BEGIN IMMEDIATE")
        c.execute("INSERT INTO check_results VALUES(?,?,?,?,?,?,?)",
                  (job.job_id, att.attempt_id, "page-1", "desktop", "HTTP", "PASS", "OK"))
        c.execute("INSERT INTO manifests VALUES(?,?,?,?,?,?)",
                  (job.job_id, att.attempt_id, "m.json", "0" * 64, 1, "t"))
        with self.assertRaises(sqlite3.IntegrityError) as cm:
            c.execute("UPDATE jobs SET status='COMPLETED', version=version+1, "
                      "adopted_attempt_id=? WHERE job_id=?", (att.attempt_id, job.job_id))
        self.assertIn("completed_requirements_unmet", str(cm.exception))
        c.execute("ROLLBACK")

    def test_sql_requires_png_for_succeeded_but_unjudged_capture(self):
        job, att = self.start_saving(self.new_job(checks=(CAPTURE,), baseline=None))
        c = self.raw()
        c.execute("BEGIN IMMEDIATE")
        c.execute("INSERT INTO check_results VALUES(?,?,?,?,?,?,?)",
                  (job.job_id, att.attempt_id, "page-1", "desktop", "CAPTURE", "UNKNOWN",
                   "BASELINE_PENDING"))
        c.execute("INSERT INTO artifacts VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (job.job_id, att.attempt_id, 0, "CAPTURE_RECORD", "page-1", "desktop",
                   "CAPTURE", "j/a/0.bin", "0" * 64, 1))
        c.execute("INSERT INTO manifests VALUES(?,?,?,?,?,?)",
                  (job.job_id, att.attempt_id, "m.json", "0" * 64, 1, "t"))
        with self.assertRaises(sqlite3.IntegrityError):   # record only, no PNG
            c.execute("UPDATE jobs SET status='COMPLETED', version=version+1, "
                      "adopted_attempt_id=? WHERE job_id=?", (att.attempt_id, job.job_id))
        c.execute("INSERT INTO artifacts VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (job.job_id, att.attempt_id, 1, "SCREENSHOT_PNG", "page-1", "desktop",
                   "CAPTURE", "j/a/1.png", "1" * 64, 1))
        c.execute("UPDATE jobs SET status='COMPLETED', version=version+1, "
                  "adopted_attempt_id=? WHERE job_id=?", (att.attempt_id, job.job_id))
        c.execute("ROLLBACK")


class RawJobWithoutRequiredRowsTests(StorageTestCase):
    def test_job_inserted_without_required_check_rows_cannot_complete(self):
        c = self.raw()
        c.execute("INSERT INTO jobs(job_id, idempotency_key, intent_hash, snapshot_json, "
                  "snapshot_sha256, page_id, profile_id, baseline_id, required_checks, status, "
                  "version, created_at, updated_at) VALUES('job-raw','k',?,?,?,'p','d',NULL,"
                  "'HTTP','ACCEPTED',0,'t','t')", ("0" * 64, "{}", "0" * 64))
        for st in ("WAITING_WORKER", "RUNNING", "SAVING"):
            c.execute("UPDATE jobs SET status=?, version=version+1 WHERE job_id='job-raw'", (st,))
        c.execute("INSERT INTO attempts VALUES('job-raw','a',1,'t')")
        c.execute("INSERT INTO manifests VALUES('job-raw','a','m',?,1,'t')", ("0" * 64,))
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("UPDATE jobs SET status='COMPLETED', version=version+1, "
                      "adopted_attempt_id='a' WHERE job_id='job-raw'")


class AttemptAndTerminalTests(StorageTestCase):
    def test_stale_attempt_cannot_finalize_at_entry_and_changes_nothing(self):
        job, att1 = self.start_saving(self.new_job())
        att2 = self.repo.register_attempt(job.job_id, "att-2", 2)
        fr = self.frames(job, att1, self.ALL_KINDS)
        with self.assertRaises(StaleAttemptError):
            self.finalize(job, att1, fr)
        cur = self.repo.get_job(job.job_id)
        self.assertEqual((cur.status, cur.version), (S.SAVING, job.version))
        self.assertEqual(self.evidence_files(), [])
        # the current attempt still can; frames carrying the old epoch are rejected
        old_epoch = self.frames(job, att2, self.ALL_KINDS, lease_epoch=1)
        out = self.finalize(job, att2, old_epoch)
        self.assertEqual(out.job.status, S.FAILED_EVIDENCE)
        self.assertIn("LEASE_EPOCH_MISMATCH", out.job.terminal_reason)

    def test_current_attempt_is_adopted_exactly_once(self):
        job, att1 = self.start_saving(self.new_job())
        att2 = self.repo.register_attempt(job.job_id, "att-2", 2)
        out = self.finalize(job, att2, self.frames(job, att2, self.ALL_KINDS))
        self.assertEqual(out.job.adopted_attempt_id, "att-2")
        with self.assertRaises(TerminalJobError):
            self.finalize(job, att2, self.frames(job, att2, self.ALL_KINDS))
        with self.assertRaises(sqlite3.IntegrityError):
            self.raw().execute("UPDATE jobs SET adopted_attempt_id='att-1'")

    def test_terminal_job_is_never_rerun_or_modified(self):
        job, att, fr, out = self.run_complete()
        done = self.repo.get_job(job.job_id)
        with self.assertRaises(TerminalJobError):
            self.repo.transition(job.job_id, done.version, S.FAILED_EXECUTION, "X",
                                 expected_attempt=att)
        with self.assertRaises(TerminalJobError):
            self.repo.cancel(job.job_id)
        with self.assertRaises(TerminalJobError):
            self.repo.register_attempt(job.job_id, "att-9", 9)
        with self.assertRaises(sqlite3.IntegrityError):
            self.raw().execute("INSERT INTO manifests VALUES(?,?,?,?,?,?)",
                               (job.job_id, att.attempt_id, "z", "0" * 64, 1, "t"))
        self.assertEqual(self.repo.get_job(job.job_id), done)

    def test_attempt_ids_cannot_escape_the_store(self):
        with self.assertRaises(ValidationError):
            self.store.attempt_dir("job-001", "../evil")
        with self.assertRaises(Exception):
            self.store.write_new("job-001", "att-1", "../x.bin", b"x")


class StaleAttemptDuringFinalizeTests(StorageTestCase):
    """INT-05: a newer attempt registered while an old one is still validating."""

    def setUp(self):
        super().setUp()
        self.job, self.att1 = self.start_saving(self.new_job())
        self.att2 = None

    def register_newer(self):
        self.att2 = self.repo.register_attempt(self.job.job_id, "att-2", 2)

    def assert_job_untouched_by_old_attempt(self, out):
        self.assertEqual(out.commit_state, CommitState.LOST_RACE)
        cur = self.repo.get_job(self.job.job_id)
        self.assertEqual((cur.status, cur.version, cur.terminal_reason, cur.adopted_attempt_id),
                         (S.SAVING, self.job.version, None, None))
        self.assertEqual(out.job, cur)
        self.assertEqual(self.repo.latest_attempt(self.job.job_id), self.att2)

    def assert_new_attempt_still_completes(self):
        fr = self.frames(self.job, self.att2, self.ALL_KINDS)
        out = self.finalize(self.job, self.att2, fr)
        self.assertEqual((out.job.status, out.commit_state, out.job.adopted_attempt_id),
                         (S.COMPLETED, CommitState.COMMITTED, "att-2"))

    def test_old_attempt_with_bad_stream_does_not_fail_the_current_job(self):
        self.fp.on("after_entry_checks", self.register_newer)
        fr = self.frames(self.job, self.att1, self.ALL_KINDS)
        fr[0] = dataclasses.replace(fr[0], sha256="b" * 64)
        out = self.finalize(self.job, self.att1, fr)
        self.assertIn("STALE_ATTEMPT_JOB_UNTOUCHED", out.reason)
        self.assert_job_untouched_by_old_attempt(out)
        self.assertEqual(self.evidence_files(), [])
        self.fp.on("after_entry_checks", lambda: None)
        self.assert_new_attempt_still_completes()

    def test_old_attempt_timeout_does_not_time_out_the_current_job(self):
        self.fp.on("after_entry_checks", self.register_newer)
        fr = self.frames(self.job, self.att1, self.ALL_KINDS)
        out = self.finalize(self.job, self.att1, fr, summary=make_summary(
            fr, Termination.TIMEOUT))
        self.assert_job_untouched_by_old_attempt(out)
        self.assertNotEqual(self.repo.get_job(self.job.job_id).status, S.TIMED_OUT)

    def test_old_attempt_with_unsupported_records_does_not_fail_the_current_job(self):
        self.fp.on("after_entry_checks", self.register_newer)
        fr = self.frames(self.job, self.att1, self.RECORD_KINDS)  # CAPTURE succeeded, no PNG
        out = self.finalize(self.job, self.att1, fr)
        self.assert_job_untouched_by_old_attempt(out)

    def test_old_attempt_io_error_mid_write_does_not_fail_the_current_job(self):
        def register_then_fail():
            self.register_newer()
            raise OSError("disk full (simulated)")
        self.fp.on("after_artifact_write", register_then_fail)
        out = self.finalize(self.job, self.att1, self.frames(self.job, self.att1,
                                                             self.ALL_KINDS))
        self.assert_job_untouched_by_old_attempt(out)
        self.assertTrue(out.unadopted_files)  # old attempt's files stay as unadopted orphans
        self.fp.on("after_artifact_write", lambda: None)
        self.assert_new_attempt_still_completes()

    def test_old_attempt_precommit_verification_failure_does_not_fail_current_job(self):
        def register_then_tamper():
            self.register_newer()
            self.store.resolve(f"{self.job.job_id}/att-1/000000_http_record.bin"
                               ).write_bytes(b"tampered")
        self.fp.on("before_final_commit", register_then_tamper)
        out = self.finalize(self.job, self.att1, self.frames(self.job, self.att1,
                                                             self.ALL_KINDS))
        self.assert_job_untouched_by_old_attempt(out)

    def test_old_attempt_cannot_commit_after_newer_attempt_registered(self):
        self.fp.on("before_final_commit", self.register_newer)
        out = self.finalize(self.job, self.att1, self.frames(self.job, self.att1,
                                                             self.ALL_KINDS))
        self.assertEqual(out.reason, "STALE_ATTEMPT_AT_COMMIT")
        self.assert_job_untouched_by_old_attempt(out)
        self.assertEqual(self.repo.list_check_results(self.job.job_id), [])
        self.assertEqual(len(out.unadopted_files), 5)

    def test_same_attempt_id_with_wrong_epoch_is_stale_too(self):
        wrong_epoch = AttemptRef(self.job.job_id, "att-1", 99)
        with self.assertRaises(StaleAttemptError):
            self.repo.transition(self.job.job_id, self.job.version, S.FAILED_EVIDENCE, "X",
                                 expected_attempt=wrong_epoch)
        self.assertEqual(self.repo.get_job(self.job.job_id).status, S.SAVING)

    def test_failure_transition_requires_the_expected_attempt(self):
        for target in (S.FAILED_EVIDENCE, S.FAILED_EXECUTION, S.TIMED_OUT):
            with self.assertRaises(ValidationError, msg=target.value):
                self.repo.transition(self.job.job_id, self.job.version, target, "X")
        self.register_newer()
        for target in (S.FAILED_EVIDENCE, S.FAILED_EXECUTION, S.TIMED_OUT):
            with self.assertRaises(StaleAttemptError, msg=target.value):
                self.repo.transition(self.job.job_id, self.job.version, target, "X",
                                     expected_attempt=self.att1)
        cur = self.repo.get_job(self.job.job_id)
        self.assertEqual((cur.status, cur.version), (S.SAVING, self.job.version))
        done = self.repo.transition(self.job.job_id, self.job.version, S.FAILED_EXECUTION, "X",
                                    expected_attempt=self.att2)
        self.assertEqual(done.status, S.FAILED_EXECUTION)

    def test_attempt_free_failures_and_cancel_do_not_need_an_attempt(self):
        job = self.new_job("key-2")
        w = self.repo.transition(job.job_id, 0, S.WAITING_WORKER)
        done = self.repo.transition(job.job_id, w.version, S.FAILED_WORKER_START, "NO_WORKER")
        self.assertEqual(done.status, S.FAILED_WORKER_START)
        job3 = self.new_job("key-3")
        self.assertEqual(self.repo.cancel(job3.job_id).status, S.CANCELLED)
        job4 = self.new_job("key-4")
        w4 = self.repo.transition(job4.job_id, 0, S.WAITING_WORKER)
        self.assertEqual(self.repo.transition(job4.job_id, w4.version, S.TIMED_OUT,
                                              "NO_WORKER_IN_TIME").status, S.TIMED_OUT)


class CancelRaceAndFailpointTests(StorageTestCase):
    def test_cancel_wins_race_before_final_commit(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS)
        self.fp.on("after_precommit_reverify", lambda: self.repo.cancel(job.job_id))
        out = self.finalize(job, att, fr)
        self.assertEqual(out.commit_state, CommitState.LOST_RACE)
        self.assertEqual(self.repo.get_job(job.job_id).status, S.CANCELLED)
        self.assertEqual(self.repo.list_check_results(job.job_id), [])
        self.assertIsNone(self.repo.get_manifest_row(job.job_id, att.attempt_id))
        self.assertEqual(len(out.unadopted_files), 5)        # written, not adopted...
        self.assertEqual(len(self.evidence_files()), 5)      # ...and not deleted

    def test_cancel_before_failure_transition_wins_too(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS)
        fr[0] = dataclasses.replace(fr[0], sha256="b" * 64)
        self.fp.on("after_entry_checks", lambda: self.repo.cancel(job.job_id))
        out = self.finalize(job, att, fr)
        self.assertEqual(out.commit_state, CommitState.LOST_RACE)
        self.assertEqual(self.repo.get_job(job.job_id).status, S.CANCELLED)

    def test_final_commit_wins_then_cancel_is_refused(self):
        job, att, fr, out = self.run_complete()
        with self.assertRaises(TerminalJobError):
            self.repo.cancel(job.job_id)
        self.assertEqual(self.repo.get_job(job.job_id).status, S.COMPLETED)

    def test_error_before_commit_rolls_back(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS)
        self.fp.fail("before_commit")
        out = self.finalize(job, att, fr)
        self.assertEqual(out.commit_state, CommitState.NOT_COMMITTED)
        cur = self.repo.get_job(job.job_id)
        self.assertEqual((cur.status, cur.version), (S.SAVING, job.version))
        self.assertEqual(self.repo.list_check_results(job.job_id), [])
        self.assertEqual(self.repo.list_artifacts(job.job_id, att.attempt_id), [])
        self.assertEqual(len(out.unadopted_files), 5)

    def test_error_after_commit_is_resolved_by_rereading(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS)
        self.fp.fail("after_commit", "ack lost")
        out = self.finalize(job, att, fr)
        self.assertEqual(out.commit_state, CommitState.COMMITTED)   # confirmed from SQLite
        self.assertEqual(out.job.status, S.COMPLETED)
        self.assertIn("COMMIT_RESULT_UNCERTAIN", out.reason)
        self.assertEqual(out.unadopted_files, ())

    def test_unreadable_database_after_error_is_reported_unknown(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS)

        def break_reads():
            self.repo.db_path = str(self.base / "missing" / "gone.sqlite3")
            raise sqlite3.OperationalError("disk I/O error (simulated)")
        self.fp.on("before_commit", break_reads)
        out = self.finalize(job, att, fr)
        self.assertEqual(out.commit_state, CommitState.UNKNOWN)
        self.assertIsNone(out.job)

    def test_crash_before_commit_leaves_saving_job_and_orphans(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS)
        self.fp.crash("before_commit")
        with self.assertRaises(SimulatedCrash):
            self.finalize(job, att, fr)
        self.assertEqual(self.repo.get_job(job.job_id).status, S.SAVING)
        self.assertEqual(self.repo.list_check_results(job.job_id), [])
        self.assertEqual(len(self.evidence_files()), 5)

    def test_crash_after_commit_leaves_consistent_completed_job(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS)
        self.fp.crash("after_commit")
        with self.assertRaises(SimulatedCrash):
            self.finalize(job, att, fr)
        cur = self.repo.get_job(job.job_id)
        self.assertEqual((cur.status, cur.adopted_attempt_id), (S.COMPLETED, att.attempt_id))
        m = self.repo.get_manifest_row(job.job_id, att.attempt_id)
        verify_stored(self.store, m.rel_path, m.sha256, job.snapshot, att)


class OrphanTests(StorageTestCase):
    def test_existing_file_is_never_overwritten_or_adopted(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS)
        adir = self.store.attempt_dir(job.job_id, att.attempt_id)
        adir.mkdir(parents=True)
        orphan = adir / "000000_http_record.bin"
        orphan.write_bytes(b"left over from a crashed run")
        out = self.finalize(job, att, fr)
        self.assertEqual(out.job.status, S.FAILED_EVIDENCE)
        self.assertIn("ArtifactExistsError", out.job.terminal_reason)
        self.assertEqual(orphan.read_bytes(), b"left over from a crashed run")
        self.assertEqual(self.repo.list_artifacts(job.job_id, att.attempt_id), [])

    def test_store_refuses_overwrite_and_leaves_no_temp(self):
        self.store.write_new("job-001", "att-1", "a.bin", b"first")
        with self.assertRaises(ArtifactExistsError):
            self.store.write_new("job-001", "att-1", "a.bin", b"second")
        self.assertEqual(self.store.read_bytes("job-001/att-1/a.bin"), b"first")
        self.assertEqual(self.evidence_files(), ["job-001/att-1/a.bin"])

    def test_unreferenced_file_in_completed_attempt_dir_stays_untouched(self):
        job, att, fr, out = self.run_complete()
        stray = self.store.attempt_dir(job.job_id, att.attempt_id) / "stray.bin"
        stray.write_bytes(b"stray")
        m = self.repo.get_manifest_row(job.job_id, att.attempt_id)
        verify_stored(self.store, m.rel_path, m.sha256, job.snapshot, att)
        self.assertEqual(stray.read_bytes(), b"stray")
        self.assertEqual(sha256_hex(self.store.read_bytes(m.rel_path)), m.sha256)


if __name__ == "__main__":
    unittest.main()
