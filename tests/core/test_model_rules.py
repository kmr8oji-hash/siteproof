import dataclasses
import unittest

from src.core.errors import EvidenceIncomplete, ValidationError
from src.core.frames import CheckType, FrameKind
from src.core.model import (AttemptRef, CheckOutcome, CheckReport, CheckResult, JobIntent,
                            JobSnapshot, JobStatus, QualityVerdict, validate_id)
from src.core.rules import (ALLOWED_TRANSITIONS, TERMINAL_STATUSES, can_transition,
                            classify_http_status, derive_quality, required_artifact_kinds,
                            validate_report)

HTTP, LOAD, CAPTURE = CheckType.HTTP, CheckType.LOAD, CheckType.CAPTURE
O = CheckOutcome


def intent(**kw):
    base = dict(target_url="https://example.invalid/", page_id="page-1", profile_id="desktop",
                required_checks=(CAPTURE, HTTP, LOAD), baseline_id="base-1")
    base.update(kw)
    return JobIntent(**base)


class IntentSnapshotTests(unittest.TestCase):
    def test_intent_hash_is_order_independent_and_deduplicated(self):
        a = intent(required_checks=(HTTP, LOAD, CAPTURE))
        b = intent(required_checks=(CAPTURE, CAPTURE, LOAD, HTTP))
        self.assertEqual(a.intent_hash, b.intent_hash)
        self.assertEqual(a.required_checks, (CAPTURE, HTTP, LOAD))

    def test_intent_hash_changes_with_any_field(self):
        base = intent().intent_hash
        for kw in (dict(target_url="https://example.invalid/x"), dict(page_id="page-2"),
                   dict(profile_id="mobile"), dict(baseline_id=None),
                   dict(required_checks=(HTTP,))):
            self.assertNotEqual(base, intent(**kw).intent_hash, kw)

    def test_invalid_intents_rejected(self):
        for kw in (dict(required_checks=()), dict(target_url="file:///etc/passwd"),
                   dict(target_url="https://"), dict(page_id="../x"), dict(profile_id=""),
                   dict(baseline_id="a b")):
            with self.assertRaises(ValidationError, msg=str(kw)):
                intent(**kw)

    def test_snapshot_is_frozen_and_roundtrips(self):
        snap = JobSnapshot("job-1", intent(), "2026-01-01T00:00:00+00:00")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            snap.job_id = "other"
        with self.assertRaises(dataclasses.FrozenInstanceError):
            snap.intent.page_id = "other"
        self.assertIsInstance(snap.required_checks, tuple)
        again = JobSnapshot.from_json(snap.to_json())
        self.assertEqual(snap, again)
        self.assertEqual(snap.sha256, again.sha256)


class IdValidationTests(unittest.TestCase):
    """PF-03: an ID must match in full; `$` alone would let a trailing newline through."""
    TRAILING = ("page-1\n", "page-1\r\n", "page-1\n\n", "a\n")
    BAD = ("", ".a", "-a", "_a", "a b", "a/b", "../x", "a\nb", "\na", "a\x00", "é", "a" * 65,
           " a", "a ", 5, None, b"a")

    def test_validate_id_rejects_trailing_newline_and_other_bad_ids(self):
        for bad in self.TRAILING + self.BAD:
            with self.assertRaises(ValidationError, msg=repr(bad)):
                validate_id(bad, "x")

    def test_validate_id_accepts_well_formed_ids_unchanged(self):
        for good in ("a", "A0", "page-1", "a.b_c-d", "0" + "a" * 63):
            self.assertIs(validate_id(good, "x"), good)

    def test_every_id_field_rejects_a_trailing_newline(self):
        for kw in (dict(page_id="page-1\n"), dict(profile_id="desktop\n"),
                   dict(baseline_id="base-1\n")):
            with self.assertRaises(ValidationError, msg=str(kw)):
                intent(**kw)
        with self.assertRaises(ValidationError):
            JobSnapshot("job-1\n", intent(), "2026-01-01T00:00:00+00:00")
        with self.assertRaises(ValidationError):
            AttemptRef("job-1\n", "att-1", 1)
        with self.assertRaises(ValidationError):
            AttemptRef("job-1", "att-1\n", 1)


class CheckResultTests(unittest.TestCase):
    def test_reason_code_is_mandatory(self):
        for bad in ("", "   ", None, " X", "X "):
            with self.assertRaises(ValidationError, msg=repr(bad)):
                CheckReport(HTTP, O.PASS, bad)
            with self.assertRaises(ValidationError, msg=repr(bad)):
                CheckResult("j", "a", "p", "d", HTTP, O.PASS, bad)

    def test_unique_key_has_five_components(self):
        r = CheckResult("j", "a", "p", "d", HTTP, O.PASS, "OK")
        self.assertEqual(r.key, ("j", "a", "p", "d", "HTTP"))


class TransitionTests(unittest.TestCase):
    def test_terminal_states_have_no_outgoing_transitions(self):
        for t in TERMINAL_STATUSES:
            self.assertEqual(ALLOWED_TRANSITIONS[t], frozenset())
            for dst in JobStatus:
                self.assertFalse(can_transition(t, dst))

    def test_happy_path_and_skips_are_restricted(self):
        S = JobStatus
        self.assertTrue(can_transition(S.ACCEPTED, S.WAITING_WORKER))
        self.assertTrue(can_transition(S.RUNNING, S.SAVING))
        self.assertTrue(can_transition(S.SAVING, S.COMPLETED))
        self.assertFalse(can_transition(S.ACCEPTED, S.COMPLETED))
        self.assertFalse(can_transition(S.RUNNING, S.COMPLETED))
        self.assertFalse(can_transition(S.WAITING_WORKER, S.SAVING))


class ArtifactRequirementTests(unittest.TestCase):
    def test_requirement_table(self):
        K = FrameKind
        self.assertEqual(required_artifact_kinds(HTTP, O.PASS), {K.HTTP_RECORD})
        self.assertEqual(required_artifact_kinds(HTTP, O.FAIL), {K.HTTP_RECORD})
        self.assertEqual(required_artifact_kinds(LOAD, O.PASS), {K.LOAD_RECORD})
        self.assertEqual(required_artifact_kinds(LOAD, O.FAIL), {K.LOAD_RECORD})
        for oc in (O.PASS, O.CHANGED):
            self.assertEqual(required_artifact_kinds(CAPTURE, oc),
                             {K.CAPTURE_RECORD, K.SCREENSHOT_PNG})
        for ct, rec in ((HTTP, K.HTTP_RECORD), (LOAD, K.LOAD_RECORD), (CAPTURE, K.CAPTURE_RECORD)):
            for oc in (O.UNKNOWN, O.SKIPPED):
                self.assertEqual(required_artifact_kinds(ct, oc), {rec})  # no PNG required

    def test_changed_is_capture_only(self):
        for ct in (HTTP, LOAD):
            with self.assertRaises(EvidenceIncomplete):
                required_artifact_kinds(ct, O.CHANGED)

    def test_validate_report_needs_artifacts_for_trusted_capture_pass(self):
        # PASS/CHANGED are only reachable with a (future) trusted comparison
        with self.assertRaises(EvidenceIncomplete) as cm:
            validate_report(CheckReport(CAPTURE, O.PASS, "SAME"), baseline_id="b",
                            kinds_present=[FrameKind.CAPTURE_RECORD], trusted_comparison=True)
        self.assertEqual(cm.exception.code, "ARTIFACT_MISSING")
        validate_report(CheckReport(CAPTURE, O.PASS, "SAME"), baseline_id="b",
                        kinds_present=[FrameKind.CAPTURE_RECORD, FrameKind.SCREENSHOT_PNG],
                        trusted_comparison=True)

    def test_baseline_id_alone_never_yields_capture_pass_or_changed(self):
        kinds = [FrameKind.CAPTURE_RECORD, FrameKind.SCREENSHOT_PNG]
        for oc in (O.PASS, O.CHANGED):
            with self.assertRaises(EvidenceIncomplete) as cm:
                validate_report(CheckReport(CAPTURE, oc, "X"), baseline_id="b",
                                kinds_present=kinds)
            self.assertEqual(cm.exception.code, "COMPARISON_EVIDENCE_UNAVAILABLE")
            with self.assertRaises(EvidenceIncomplete) as cm:
                validate_report(CheckReport(CAPTURE, oc, "X"), baseline_id=None,
                                kinds_present=kinds, trusted_comparison=True)
            self.assertEqual(cm.exception.code, "BASELINE_NOT_SET")

    def test_succeeded_but_unjudged_capture_needs_png_but_explicit_failure_does_not(self):
        K = FrameKind
        for reason in ("BASELINE_PENDING", "COMPARISON_NOT_RUN"):
            self.assertEqual(required_artifact_kinds(CAPTURE, O.UNKNOWN, reason),
                             {K.CAPTURE_RECORD, K.SCREENSHOT_PNG})
            with self.assertRaises(EvidenceIncomplete) as cm:
                validate_report(CheckReport(CAPTURE, O.UNKNOWN, reason), baseline_id=None,
                                kinds_present=[K.CAPTURE_RECORD])
            self.assertEqual(cm.exception.code, "ARTIFACT_MISSING")
        for oc, reason in ((O.UNKNOWN, "VIEWPORT_LOST"), (O.FAIL, "RENDER_CRASH"),
                           (O.SKIPPED, "UPSTREAM_HTTP_FAILED")):
            validate_report(CheckReport(CAPTURE, oc, reason), baseline_id=None,
                            kinds_present=[K.CAPTURE_RECORD])

    def test_screenshot_with_explicit_capture_failure_is_inconsistent(self):
        with self.assertRaises(EvidenceIncomplete) as cm:
            validate_report(CheckReport(CAPTURE, O.FAIL, "RENDER_CRASH"), baseline_id=None,
                            kinds_present=[FrameKind.CAPTURE_RECORD, FrameKind.SCREENSHOT_PNG])
        self.assertEqual(cm.exception.code, "ARTIFACT_UNEXPECTED")


class QualityTests(unittest.TestCase):
    def test_all_pass_is_pass(self):
        self.assertIs(derive_quality([HTTP, LOAD], {HTTP: O.PASS, LOAD: O.PASS}),
                      QualityVerdict.PASS)

    def test_unknown_skipped_and_missing_never_become_pass(self):
        for other in (O.UNKNOWN, O.SKIPPED):
            self.assertIs(derive_quality([HTTP, LOAD], {HTTP: O.PASS, LOAD: other}),
                          QualityVerdict.UNKNOWN)
        self.assertIs(derive_quality([HTTP, LOAD], {HTTP: O.PASS}), QualityVerdict.UNKNOWN)
        self.assertIs(derive_quality([HTTP], {}), QualityVerdict.UNKNOWN)

    def test_changed_is_not_fail(self):
        self.assertIs(derive_quality([HTTP, CAPTURE], {HTTP: O.PASS, CAPTURE: O.CHANGED}),
                      QualityVerdict.CHANGED)

    def test_fail_dominates_even_with_skipped_followers(self):
        self.assertIs(derive_quality([HTTP, LOAD, CAPTURE],
                                     {HTTP: O.FAIL, LOAD: O.SKIPPED, CAPTURE: O.SKIPPED}),
                      QualityVerdict.FAIL)

    def test_http_404_semantics(self):
        self.assertEqual(classify_http_status(404, observation_reliable=True),
                         (O.FAIL, "HTTP_404"))
        self.assertEqual(classify_http_status(404, observation_reliable=False)[0], O.UNKNOWN)
        self.assertEqual(classify_http_status(200, observation_reliable=True)[0], O.PASS)
        self.assertEqual(classify_http_status(99, observation_reliable=True)[0], O.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
