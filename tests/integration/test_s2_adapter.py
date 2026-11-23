"""Offline S2-ADAPTER-BOUNDARY-v0.1 acceptance; synthetic fixtures only."""

import ast
from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.baseline import approval as baseline_approval
from src.bridge import s2_adapter as module
from src.bridge.s1_evidence import read_s1_capture
from src.bridge.s1_s2_contract import (EvidenceArtifact, EvidenceFile, EvidenceOrigin,
                                      EvidenceReadResult, EvidenceRejection,
                                      RejectionReason, StructurallyCheckedCaptureEvidence,
                                      UnattestedProfileFingerprint)
from src.bridge.s2_adapter import (AdapterRejection, AdapterRejectionReason as A,
                                   evaluate_s1_evidence_boundary)
from src.comparison import decision
from src.comparison.decision import EligibilityStatus, UnknownReason, evaluate_eligibility
from tests.integration import s1_s2_fixtures
from tests.integration.s1_s2_fixtures import FoundationCase

JOB, ATTEMPT = "job-1", "attempt-1"
H = {c: c * 64 for c in "abcdef0123"}


def temp_root():
    root = Path(tempfile.gettempdir()) / "siteproof-s2-adapter-boundary-01"
    root.mkdir(parents=True, exist_ok=True)
    return root


def evidence():
    return StructurallyCheckedCaptureEvidence(
        EvidenceOrigin(JOB, ATTEMPT, 1, H["a"], H["b"], "page-1", "profile-1", None),
        EvidenceFile(f"{JOB}/{ATTEMPT}/manifest.json", H["c"], 10),
        EvidenceArtifact(1, "CAPTURE_RECORD", "CAPTURE",
                         EvidenceFile(f"{JOB}/{ATTEMPT}/capture.json", H["d"], 20)),
        EvidenceArtifact(2, "SCREENSHOT_PNG", "CAPTURE",
                         EvidenceFile(f"{JOB}/{ATTEMPT}/shot.png", H["e"], 30)),
        UnattestedProfileFingerprint(H["f"]))


def accepted(ev=None):
    return EvidenceReadResult(evidence=ev or evidence())


def corrupt(obj, **changes):
    """Bypass frozen-ness the way a hostile caller could."""
    for name, value in changes.items():
        object.__setattr__(obj, name, value)
    return obj


class BoundaryTests(unittest.TestCase):
    def refused(self, result, reason):
        out = evaluate_s1_evidence_boundary(result)
        self.assertIsInstance(out, AdapterRejection)
        self.assertIs(out.reason, reason, out.detail)
        self.assertIs(out.status, EligibilityStatus.UNKNOWN)
        self.assertIs(out.unknown_reasons[-1], UnknownReason.COMPARISON_NOT_RUN)
        return out

    def test_well_formed_evidence_is_read_but_refused_as_unattested(self):
        out = self.refused(accepted(), A.PROFILE_UNATTESTED)
        self.assertIn(UnknownReason.BASELINE_NOT_APPROVED, out.unknown_reasons)
        self.assertIn(UnknownReason.PROFILE_MISMATCH, out.unknown_reasons)
        self.assertIsNone(out.bridge_reason)

    def test_no_success_path_or_bypass_surface(self):
        import inspect
        self.assertEqual(list(inspect.signature(evaluate_s1_evidence_boundary).parameters),
                         ["result"])
        self.assertFalse(hasattr(AdapterRejection, "eligible"))
        self.assertFalse(hasattr(AdapterRejection, "accepted"))
        self.assertFalse({a.value for a in A} & {"ELIGIBLE", "PASS", "CHANGED", "TRUSTED"})

    def test_matching_profile_id_and_fingerprint_do_not_promote_trust(self):
        a = evaluate_s1_evidence_boundary(accepted())
        b = evaluate_s1_evidence_boundary(accepted(evidence()))
        self.assertEqual(a, b)
        self.assertIs(a.reason, A.PROFILE_UNATTESTED)
        same = evidence()
        self.assertEqual(same.unattested_profile, evidence().unattested_profile)
        self.assertIs(evaluate_s1_evidence_boundary(accepted(same)).reason, A.PROFILE_UNATTESTED)

    def test_unattested_reasons_align_with_s2_unknown_contract(self):
        out = evaluate_s1_evidence_boundary(accepted())
        self.assertTrue(set(out.unknown_reasons) <= set(UnknownReason))
        absent = evaluate_s1_evidence_boundary(EvidenceReadResult(
            rejection=EvidenceRejection(RejectionReason.JOB_NOT_FOUND)))
        self.assertEqual(absent.unknown_reasons, evaluate_eligibility(None).reasons)

    def test_invalid_ids_are_refused(self):
        for field, bad in [("job_id", "../x"), ("job_id", ""), ("job_id", 5),
                           ("adopted_attempt_id", "a b"), ("adopted_attempt_id", "-x"),
                           ("page_id", "p" * 65), ("profile_id", "pro/file"),
                           ("baseline_id", "bad id"), ("lease_epoch", 0),
                           ("lease_epoch", True), ("snapshot_sha256", "A" * 64),
                           ("intent_hash", "abc")]:
            with self.subTest(field=field, bad=bad):
                ev = evidence()
                corrupt(ev.origin, **{field: bad})
                self.refused(accepted(ev), A.INVALID_INPUT)

    def test_missing_ids_are_refused(self):
        for field in ("job_id", "adopted_attempt_id", "page_id", "profile_id"):
            with self.subTest(field=field):
                ev = evidence()
                corrupt(ev.origin, **{field: None})
                self.refused(accepted(ev), A.REQUIRED_INFORMATION_MISSING)

    def test_job_attempt_ids_must_match_artifact_references(self):
        ev = evidence()
        corrupt(ev.origin, job_id="job-2")
        self.refused(accepted(ev), A.EVIDENCE_REFERENCE_MISMATCH)
        ev = evidence()
        corrupt(ev.origin, adopted_attempt_id="attempt-9")
        self.refused(accepted(ev), A.EVIDENCE_REFERENCE_MISMATCH)

    def test_bad_artifact_refs_are_refused(self):
        for ref in ["../a/b", "job-1/attempt-1/../x.png", "/job-1/attempt-1/x.png",
                    "job-1\\attempt-1\\x.png", "C:/x/y", "job-1/attempt-1/", "job-1/x.png",
                    "job-1/attempt-1/a/b.png", "job-1/attempt-1/./x.png", "job-1/attempt-1/x.png.", "job-1/attempt-1/x:y", "job-2/attempt-1/x.png",
                    "job-1/attempt-9/x.png", "job-1//x.png"]:
            with self.subTest(ref=ref):
                ev = evidence()
                corrupt(ev.screenshot.file, artifact_ref=ref)
                self.refused(accepted(ev), A.EVIDENCE_REFERENCE_MISMATCH)

    def test_whitespace_padded_refs_are_refused(self):
        for ref in ("job-1/attempt-1/x.png ", " job-1/attempt-1/x.png", "job-1/attempt-1/x\n.png"):
            with self.subTest(ref=ref):
                ev = evidence()
                corrupt(ev.screenshot.file, artifact_ref=ref)
                self.refused(accepted(ev), A.INVALID_INPUT)

    def test_non_string_ref_and_bad_hashes_and_lengths_are_refused(self):
        for target, field, bad in [("screenshot", "artifact_ref", 7),
                                   ("screenshot", "sha256", "G" * 64),
                                   ("screenshot", "sha256", H["a"][:-1]),
                                   ("screenshot", "sha256", H["a"].upper()),
                                   ("screenshot", "byte_length", 0),
                                   ("screenshot", "byte_length", True),
                                   ("capture_record", "sha256", 12),
                                   ("manifest", "sha256", "")]:
            with self.subTest(target=target, field=field, bad=bad):
                ev = evidence()
                holder = ev.manifest if target == "manifest" else getattr(ev, target).file
                corrupt(holder, **{field: bad})
                self.refused(accepted(ev), A.INVALID_INPUT)

    def test_reference_inconsistencies_are_refused(self):
        ev = evidence()
        corrupt(ev.manifest, artifact_ref=f"{JOB}/{ATTEMPT}/other.json")
        self.refused(accepted(ev), A.EVIDENCE_REFERENCE_MISMATCH)
        ev = evidence()
        corrupt(ev.screenshot.file, artifact_ref=ev.capture_record.file.artifact_ref)
        self.refused(accepted(ev), A.EVIDENCE_REFERENCE_MISMATCH)
        ev = evidence()
        corrupt(ev.screenshot.file, sha256=ev.manifest.sha256)
        self.refused(accepted(ev), A.EVIDENCE_REFERENCE_MISMATCH)
        ev = evidence()
        corrupt(ev.screenshot, kind="CAPTURE_RECORD")
        self.refused(accepted(ev), A.EVIDENCE_REFERENCE_MISMATCH)
        ev = evidence()
        corrupt(ev.screenshot, check_type="LAYOUT")
        self.refused(accepted(ev), A.EVIDENCE_REFERENCE_MISMATCH)
        ev = evidence()
        corrupt(ev.screenshot, seq=ev.capture_record.seq)
        self.refused(accepted(ev), A.EVIDENCE_REFERENCE_MISMATCH)

    def test_missing_or_corrupt_dtos_fail_closed(self):
        for bad in [None, "x", 1, object(), {"evidence": 1}, EvidenceReadResult,
                    EvidenceRejection(RejectionReason.INVALID_INPUT),
                    evidence()]:
            with self.subTest(bad=repr(bad)[:30]):
                self.refused(bad, A.INVALID_INPUT)
        for name in ("origin", "manifest", "capture_record", "screenshot", "unattested_profile"):
            with self.subTest(missing=name):
                ev = evidence()
                corrupt(ev, **{name: None})
                self.refused(accepted(ev), A.INVALID_INPUT)
                ev = evidence()
                del vars(ev)[name]
                self.refused(accepted(ev), A.REQUIRED_INFORMATION_MISSING)
        ev = evidence()
        vars(ev)["extra"] = 1
        self.refused(accepted(ev), A.INVALID_INPUT)
        ev = evidence()
        corrupt(ev, unattested_profile=H["f"])  # bare hash str, not the declaration type
        self.refused(accepted(ev), A.INVALID_INPUT)
        ev = evidence()
        corrupt(ev.unattested_profile, declared_sha256="nope")
        self.refused(accepted(ev), A.INVALID_INPUT)

    def test_subclassed_or_spoofed_objects_are_refused(self):
        class Spoof(StructurallyCheckedCaptureEvidence):
            pass
        ev = evidence()
        spoof = Spoof(ev.origin, ev.manifest, ev.capture_record, ev.screenshot,
                      ev.unattested_profile)
        self.refused(accepted(spoof), A.INVALID_INPUT)

        class Trusting(UnattestedProfileFingerprint):
            def require_trusted_use(self, operation):
                return None
        ev = evidence()
        corrupt(ev, unattested_profile=Trusting(H["f"]))
        self.refused(accepted(ev), A.INVALID_INPUT)

        result = accepted()
        corrupt(result, rejection=EvidenceRejection(RejectionReason.INVALID_INPUT))
        self.refused(result, A.INVALID_INPUT)
        neither = accepted()
        corrupt(neither, evidence=None)
        self.refused(neither, A.INVALID_INPUT)

    def test_bridge_rejections_are_never_s2_success(self):
        for reason in RejectionReason:
            with self.subTest(reason=reason):
                out = self.refused(EvidenceReadResult(rejection=EvidenceRejection(reason, "x")),
                                   A.BRIDGE_REJECTED)
                self.assertIs(out.bridge_reason, reason)
        bad = EvidenceReadResult(rejection=EvidenceRejection(RejectionReason.INVALID_INPUT))
        corrupt(bad.rejection, reason="INVALID_INPUT")  # plain str is not the enum
        self.refused(bad, A.INVALID_INPUT)

    def test_internal_errors_fail_closed(self):
        with patch.object(module, "_check_evidence", side_effect=RuntimeError("boom")):
            self.refused(accepted(), A.INVALID_INPUT)
        with patch.object(module, "_check_evidence", side_effect=RecursionError):
            self.refused(accepted(), A.INVALID_INPUT)

    def test_rejection_detail_does_not_echo_input_values(self):
        ev = evidence()
        secret = "secret-token/" + "x" * 10
        corrupt(ev.screenshot.file, artifact_ref=secret)
        out = self.refused(accepted(ev), A.EVIDENCE_REFERENCE_MISMATCH)
        self.assertNotIn("secret", out.detail)

    def test_no_baseline_or_comparison_machinery_is_invoked(self):
        def boom(*a, **k):
            raise AssertionError("trusted S2 operation reached")
        with patch.object(decision, "evaluate_eligibility", boom), \
                patch.object(baseline_approval.BaselineRecord, "is_valid_approval", boom), \
                patch.object(decision.ComparisonRequest, "__init__", boom):
            self.refused(accepted(), A.PROFILE_UNATTESTED)
            self.refused(None, A.INVALID_INPUT)
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        names = {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
        self.assertFalse(any(m and ("baseline" in m or m.startswith("src.storage"))
                             for m in imported))
        self.assertTrue(names.isdisjoint({"ComparisonRequest", "BaselineRecord", "BaselineCandidate",
                                          "evaluate_eligibility", "CheckOutcome", "Repository"}))
        source = Path(module.__file__).read_text(encoding="utf-8")
        for forbidden in ("sqlite3", "open(", "write", "PASS", "CHANGED"):
            self.assertNotIn(forbidden, source.replace("CAPTURE PASS/CHANGED", ""))

    def test_inputs_are_not_mutated(self):
        ev = evidence()
        result = accepted(ev)
        before = (repr(result), dict(vars(ev)), dict(vars(ev.origin)))
        evaluate_s1_evidence_boundary(result)
        self.assertEqual((repr(result), dict(vars(ev)), dict(vars(ev.origin))), before)

    def test_fixture_files_are_untouched(self):
        with tempfile.TemporaryDirectory(prefix="fx-", dir=temp_root()) as tmp:
            base = Path(tmp)
            (base / "s1.sqlite3").write_bytes(b"synthetic-db")
            (base / "manifest.json").write_bytes(b"{}")
            (base / "shot.png").write_bytes(b"png")

            def snap():
                return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in sorted(base.iterdir())}
            before = snap()
            evaluate_s1_evidence_boundary(accepted())
            evaluate_s1_evidence_boundary(None)
            self.assertEqual(snap(), before)


class RealBridgeTests(FoundationCase):
    def setUp(self):
        with patch.object(s1_s2_fixtures, "fixture_root", temp_root):
            super().setUp()

    def read(self, **kwargs):
        args = dict(profile_declaration=self.binding)
        args.update(kwargs)
        return read_s1_capture(self.repo.db_path, self.store.root, self.saved.job_id, **args)

    def test_real_bridge_result_is_read_then_refused_as_unattested(self):
        before = self.snapshot()
        result = self.read()
        self.assertTrue(result.accepted, result.rejection)
        out = evaluate_s1_evidence_boundary(result)
        self.assertIs(out.reason, A.PROFILE_UNATTESTED)
        self.assertIs(out.status, EligibilityStatus.UNKNOWN)
        self.assertEqual(self.snapshot(), before)

    def test_real_bridge_refusals_are_not_s2_success(self):
        result = self.read(profile_declaration=None)
        self.assertFalse(result.accepted)
        out = evaluate_s1_evidence_boundary(result)
        self.assertIs(out.reason, A.BRIDGE_REJECTED)
        self.assertIs(out.bridge_reason, RejectionReason.PROFILE_DECLARATION_MISSING)

    def test_real_s1_state_is_unchanged_by_the_adapter(self):
        result = self.read()
        outcomes = self.repo.list_check_results(self.saved.job_id)
        snapshot = self.repo.get_job(self.saved.job_id).snapshot
        before = self.snapshot()
        evaluate_s1_evidence_boundary(result)
        self.assertEqual(self.repo.list_check_results(self.saved.job_id), outcomes)
        self.assertEqual(self.repo.get_job(self.saved.job_id).snapshot, snapshot)
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
