"""Pure eligibility tests; no I/O, no image comparison."""

from dataclasses import replace
import unittest

from src.baseline.approval import decide, register_candidate
from src.baseline.model import BaselineCandidate, BaselineStatus
from src.comparison.decision import (
    ComparisonRequest,
    EligibilityStatus,
    EvidenceRef,
    UnknownReason as U,
    evaluate_eligibility,
)
from src.comparison.profile import CaptureProfile, ComparisonProfile

CAPTURE = {
    "viewport_width": 1280, "viewport_height": 720, "device_scale_factor": 1,
    "color_scheme": "light", "locale": "en-US", "timezone": "UTC", "user_agent": "ua/1",
    "reduced_motion": True, "full_page": False,
}
CAP = CaptureProfile("cap", CAPTURE)


def comp(fp=CAP.fingerprint):
    return ComparisonProfile("cmp", {"capture_fingerprint": fp, "method": "pixel",
                                     "method_version": "1", "threshold_policy": "strict"})


def baseline(status=BaselineStatus.APPROVED, **over):
    f = dict(candidate_id="c1", page_id="pg1", profile_fingerprint=CAP.fingerprint,
             artifact_ref="art/base.png", artifact_sha256="b" * 64)
    f.update(over)
    rec = register_candidate(BaselineCandidate(**f))
    if status is BaselineStatus.PENDING:
        return rec
    return decide(rec, decision=status, actor="alice", expected_revision=0,
                  reviewed_digest=rec.registered_digest)


def request(**over):
    f = dict(page_id="pg1", baseline=baseline(), current_capture_profile=CAP,
             comparison_profile=comp(), current_evidence=EvidenceRef("art/new.png", "c" * 64))
    f.update(over)
    return ComparisonRequest(**f)


def base_reasons(res):
    return set(res.reasons) - {U.COMPARISON_NOT_RUN}


class EligibilityTests(unittest.TestCase):
    def test_all_preconditions_met_is_eligible_but_not_run(self):
        res = evaluate_eligibility(request())
        self.assertEqual(res.status, EligibilityStatus.ELIGIBLE)
        self.assertTrue(res.eligible)
        self.assertEqual(res.reasons, (U.COMPARISON_NOT_RUN,))

    def test_no_pass_or_changed_vocabulary(self):
        names = {m.name for m in EligibilityStatus} | {m.name for m in U}
        self.assertFalse(names & {"PASS", "CHANGED", "FAIL"})

    def test_pending_or_rejected_baseline(self):
        for st in (BaselineStatus.PENDING, BaselineStatus.REJECTED):
            res = evaluate_eligibility(request(baseline=baseline(st)))
            self.assertEqual(res.status, EligibilityStatus.UNKNOWN)
            self.assertIn(U.BASELINE_NOT_APPROVED, res.reasons)
            self.assertIn(U.COMPARISON_NOT_RUN, res.reasons)

    def test_forged_or_tampered_approval(self):
        ok = baseline()
        forged = replace(ok, decision=None)
        self.assertIn(U.BASELINE_NOT_APPROVED, evaluate_eligibility(request(baseline=forged)).reasons)
        tampered = baseline()
        object.__setattr__(tampered.candidate, "artifact_ref", "evil.png")
        self.assertIn(U.BASELINE_NOT_APPROVED, evaluate_eligibility(request(baseline=tampered)).reasons)

    def test_page_mismatch(self):
        res = evaluate_eligibility(request(page_id="other"))
        self.assertEqual(base_reasons(res), {U.PAGE_MISMATCH})
        self.assertFalse(res.eligible)

    def test_profile_mismatch_capture(self):
        other = CaptureProfile("cap", {**CAPTURE, "viewport_width": 800})
        res = evaluate_eligibility(request(current_capture_profile=other))
        self.assertEqual(base_reasons(res), {U.PROFILE_MISMATCH})

    def test_same_profile_id_different_content_is_mismatch(self):
        other = CaptureProfile(CAP.profile_id, {**CAPTURE, "locale": "ja-JP"})
        self.assertIn(U.PROFILE_MISMATCH, evaluate_eligibility(request(current_capture_profile=other)).reasons)

    def test_different_profile_id_same_content_is_ok(self):
        same = CaptureProfile("renamed", CAPTURE)
        self.assertTrue(evaluate_eligibility(request(current_capture_profile=same)).eligible)

    def test_comparison_profile_bound_to_other_capture(self):
        res = evaluate_eligibility(request(comparison_profile=comp("d" * 64)))
        self.assertEqual(base_reasons(res), {U.PROFILE_MISMATCH})

    def test_wrong_profile_kinds_fail_closed(self):
        self.assertIn(U.PROFILE_MISMATCH, evaluate_eligibility(request(current_capture_profile=comp())).reasons)
        self.assertIn(U.PROFILE_MISMATCH, evaluate_eligibility(request(comparison_profile=CAP)).reasons)
        self.assertIn(U.PROFILE_MISMATCH, evaluate_eligibility(request(comparison_profile=None)).reasons)

    def test_evidence_missing_or_malformed(self):
        for ev in (None, "art/new.png", EvidenceRef("", "c" * 64), EvidenceRef("x", "C" * 64),
                   EvidenceRef(None, "c" * 64), EvidenceRef("x", None)):
            res = evaluate_eligibility(request(current_evidence=ev))
            self.assertEqual(base_reasons(res), {U.EVIDENCE_MISSING}, ev)
            self.assertFalse(res.eligible)

    def test_multiple_reasons_accumulate(self):
        res = evaluate_eligibility(request(page_id="x", baseline=baseline(BaselineStatus.PENDING),
                                           current_evidence=None))
        self.assertEqual(base_reasons(res), {U.PAGE_MISMATCH, U.BASELINE_NOT_APPROVED,
                                             U.PROFILE_MISMATCH, U.EVIDENCE_MISSING})

    def test_corrupt_baseline_records_are_unknown_not_exceptions(self):
        ok = baseline()
        d = ok.decision
        corrupt = [
            replace(ok, candidate=None), replace(ok, candidate="x"), replace(ok, revision=None),
            replace(ok, revision=True), replace(ok, revision=-1), replace(ok, revision="1"),
            replace(ok, status="APPROVED"), replace(ok, status=None),
            replace(ok, registered_digest=None), replace(ok, decision="x"),
            replace(ok, decision=replace(d, revision=True)), replace(ok, decision=replace(d, actor=None)),
            replace(ok, decision=replace(d, candidate_digest=None)),
            replace(ok, decision=replace(d, status="APPROVED")),
        ]
        deleted = baseline()
        object.__delattr__(deleted.candidate, "artifact_ref")
        wrong_type = baseline()
        object.__setattr__(wrong_type.candidate, "page_id", None)
        for rec in corrupt + [deleted, wrong_type]:
            res = evaluate_eligibility(request(baseline=rec))
            self.assertEqual(res.status, EligibilityStatus.UNKNOWN)
            self.assertFalse(res.eligible)
            self.assertIn(U.BASELINE_NOT_APPROVED, res.reasons)
            self.assertEqual(res.reasons[-1], U.COMPARISON_NOT_RUN)

    def test_corrupt_candidate_with_matching_page_still_not_eligible(self):
        rec = baseline()
        object.__setattr__(rec.candidate, "profile_fingerprint", None)
        res = evaluate_eligibility(request(baseline=rec))
        self.assertFalse(res.eligible)
        self.assertIn(U.PROFILE_MISMATCH, res.reasons)

    def test_garbage_inputs_never_raise_and_never_eligible(self):
        for junk in (None, {}, "x", 1):
            self.assertFalse(evaluate_eligibility(junk).eligible)
        res = evaluate_eligibility(request(baseline=None, page_id=None))
        self.assertFalse(res.eligible)
        self.assertIn(U.BASELINE_NOT_APPROVED, res.reasons)

    def test_corrupted_profile_internals_are_unknown_never_eligible(self):
        from types import MappingProxyType

        def damaged(profile, attributes):
            p = CaptureProfile(profile.profile_id, CAPTURE) if profile is CAP else comp()
            object.__setattr__(p, "attributes", attributes)
            return p

        cases = {
            "capture empty": ("capture", MappingProxyType({})),
            "capture None": ("capture", None),
            "capture plain dict": ("capture", dict(CAPTURE)),
            "capture bool width": ("capture", MappingProxyType({**CAPTURE, "viewport_width": True})),
            "capture missing": ("capture", MappingProxyType({k: v for k, v in CAPTURE.items() if k != "locale"})),
            "capture unknown": ("capture", MappingProxyType({**CAPTURE, "extra": 1})),
            "comparison empty": ("comparison", MappingProxyType({})),
            "comparison None": ("comparison", None),
            "comparison bad fp": ("comparison", MappingProxyType({
                "capture_fingerprint": "Z", "method": "pixel", "method_version": "1",
                "threshold_policy": "strict"})),
        }
        for label, (which, attrs) in cases.items():
            with self.subTest(label):
                if which == "capture":
                    req = request(current_capture_profile=damaged(CAP, attrs))
                else:
                    req = request(comparison_profile=damaged(None, attrs))
                res = evaluate_eligibility(req)
                self.assertEqual(res.status, EligibilityStatus.UNKNOWN)
                self.assertFalse(res.eligible)
                self.assertEqual(base_reasons(res), {U.PROFILE_MISMATCH})
                self.assertEqual(res.reasons[-1], U.COMPARISON_NOT_RUN)

    def test_corrupted_profile_with_matching_profile_id_is_not_promoted(self):
        from types import MappingProxyType

        twin = CaptureProfile(CAP.profile_id, CAPTURE)
        object.__setattr__(twin, "attributes", MappingProxyType({**CAPTURE, "locale": None}))
        res = evaluate_eligibility(request(current_capture_profile=twin))
        self.assertFalse(res.eligible)
        self.assertIn(U.PROFILE_MISMATCH, res.reasons)

    def test_instance_kind_shadow_and_deleted_state_fail_closed(self):
        shadow = CaptureProfile("cap", CAPTURE)
        object.__setattr__(shadow, "KIND", comp().KIND)
        deleted = CaptureProfile("cap", CAPTURE)
        object.__delattr__(deleted, "profile_id")
        for p in (shadow, deleted):
            res = evaluate_eligibility(request(current_capture_profile=p))
            self.assertFalse(res.eligible)
            self.assertEqual(base_reasons(res), {U.PROFILE_MISMATCH})

    def test_valid_request_still_eligible_after_hardening(self):
        res = evaluate_eligibility(request())
        self.assertTrue(res.eligible)
        self.assertEqual(res.reasons, (U.COMPARISON_NOT_RUN,))


if __name__ == "__main__":
    unittest.main()
