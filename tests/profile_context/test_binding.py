"""Pure association checks, including the limits of coherent fabricated histories."""

import ast
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import unittest
from unittest.mock import patch

from src.bridge.s1_s2_contract import (ProfileTrust, TrustedS2Use, UnattestedProfileError,
                                     UnattestedProfileFingerprint)
from src.bridge.s2_adapter import evaluate_s1_evidence_boundary
from src.bridge.s1_s2_contract import EvidenceReadResult
from src.comparison.decision import EligibilityStatus
from src.core.model import AttemptRef
from src.core.frames import CheckType
from src.profile_context import (BindingReason as R, BindingStatus as S, CaptureResult,
                                evaluate_binding, evaluate_bindings)
from src.profile_context import binding as module
from tests.profile_context.test_model import attributes, make_bundle


class BindingTests(unittest.TestCase):
    def test_normal_four_records_are_structurally_consistent_unattested(self):
        result = evaluate_binding(make_bundle())
        self.assertIs(result.status, S.STRUCTURALLY_CONSISTENT)
        self.assertIs(result.trust, ProfileTrust.UNATTESTED)
        self.assertEqual(result.records_checked, 1)
        self.assertEqual(result.rejections, ())

    def test_same_job_retry_shares_spec_but_uses_new_attempt_epoch_nonce(self):
        a = make_bundle()
        b = make_bundle(attempt="attempt-2", epoch=2, nonce="nonce-2", context_id="context-2")
        self.assertEqual(a.spec.sha256, b.spec.sha256)
        self.assertIs(evaluate_bindings([a, b]).status, S.STRUCTURALLY_CONSISTENT)

    def test_multiple_jobs_and_order_of_input_are_not_execution_order_proof(self):
        a = make_bundle()
        b = make_bundle(job="job-2", nonce="nonce-2", context_id="context-2", request_key="key-2")
        for entries in ([a, b], [b, a]):
            result = evaluate_bindings(entries)
            self.assertIs(result.status, S.STRUCTURALLY_CONSISTENT)
            self.assertIs(result.trust, ProfileTrust.UNATTESTED)

    def test_new_calls_do_not_claim_persistent_nonce_or_request_key_detection(self):
        a = make_bundle()
        b = make_bundle(attrs=attributes(viewport_width=800))
        self.assertIs(evaluate_binding(a).status, S.STRUCTURALLY_CONSISTENT)
        self.assertIs(evaluate_binding(a).status, S.STRUCTURALLY_CONSISTENT)
        self.assertIs(evaluate_binding(b).status, S.STRUCTURALLY_CONSISTENT)
        self.assertIs(evaluate_bindings([a, b]).status, S.UNKNOWN)

    def test_fully_coherent_retrospective_declarations_do_not_attest_authenticity(self):
        # These records are all fabricated after our synthetic screenshot metadata.
        # There is no pre-capture coordinator or temporal witness to query.
        e = make_bundle(attrs=attributes(viewport_width=800, user_agent="invented-after-capture"))
        result = evaluate_binding(e)
        self.assertIs(result.status, S.STRUCTURALLY_CONSISTENT)
        self.assertIs(result.trust, ProfileTrust.UNATTESTED)
        self.assertFalse(hasattr(result, "ordering_verified"))
        self.assertFalse(hasattr(result, "eligible"))
        for operation in TrustedS2Use:
            with self.subTest(operation=operation), self.assertRaises(UnattestedProfileError):
                result.require_trusted_use(operation)

    def test_result_cannot_enable_existing_s2_boundary(self):
        e = make_bundle()
        result = evaluate_binding(e)
        self.assertIs(evaluate_s1_evidence_boundary(result).status, EligibilityStatus.UNKNOWN)
        self.assertIs(evaluate_s1_evidence_boundary(EvidenceReadResult(evidence=e.evidence)).status,
                      EligibilityStatus.UNKNOWN)

    def test_input_snapshot_attempt_and_evidence_are_not_modified(self):
        e = make_bundle()
        before = repr(e), e.snapshot.to_json(), e.spec.canonical_json()
        evaluate_binding(e)
        evaluate_binding(replace(e, receipt=replace(e.receipt, nonce="wrong")))
        self.assertEqual((repr(e), e.snapshot.to_json(), e.spec.canonical_json()), before)

    def test_no_persistence_browser_or_trusted_s2_operations_are_called(self):
        from src.baseline import approval
        from src.comparison import decision
        from src.storage.repository import Repository
        e = make_bundle()
        def forbidden(*a, **k):
            raise AssertionError("outside offline scope")
        with patch.object(Repository, "get_job", forbidden), \
                patch.object(Repository, "commit_completed", forbidden), \
                patch.object(approval, "register_candidate", forbidden), \
                patch.object(approval, "decide", forbidden), \
                patch.object(decision, "evaluate_eligibility", forbidden), \
                patch("builtins.open", forbidden):
            self.assertIs(evaluate_binding(e).status, S.STRUCTURALLY_CONSISTENT)
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        imports = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        self.assertFalse(any(m and m.startswith(("src.storage", "src.baseline", "sqlite3",
                                                "subprocess", "socket")) for m in imports))

    def test_all_validation_results_are_frozen_and_cannot_select_trust(self):
        for result in (evaluate_binding(make_bundle()), evaluate_binding(None)):
            self.assertIs(result.trust, ProfileTrust.UNATTESTED)
            with self.assertRaises(FrozenInstanceError):
                result.trust = "TRUSTED"
            for operation in TrustedS2Use:
                with self.assertRaises(UnattestedProfileError):
                    result.require_trusted_use(operation)


class BindingRejectionTests(unittest.TestCase):
    def refused(self, e, reason):
        result = evaluate_binding(e)
        self.assertIs(result.status, S.UNKNOWN)
        self.assertIs(result.trust, ProfileTrust.UNATTESTED)
        self.assertIs(result.rejections[0].reason, reason, result.rejections)
        return result

    def test_missing_malformed_or_noncollection_batch_input(self):
        for entries in (None, [], (), {}, "x", iter([make_bundle()])):
            with self.subTest(type=type(entries)):
                result = evaluate_bindings(entries)
                self.assertIs(result.status, S.UNKNOWN)
                self.assertIs(result.trust, ProfileTrust.UNATTESTED)
        self.refused(None, R.INVALID_RECORD)

    def test_missing_unknown_and_corrupt_schema_fields(self):
        for name in ("spec", "context", "receipt", "binding"):
            for mode in ("missing", "unknown", "extra"):
                e = make_bundle();record = getattr(e, name)
                if mode == "missing":
                    object.__delattr__(record, "schema_version")
                elif mode == "unknown":
                    object.__setattr__(record, "schema_version", "v999")
                else:
                    object.__setattr__(record, "trusted", True)
                with self.subTest(name=name, mode=mode):
                    self.refused(e, R.INVALID_RECORD)

    def test_attributes_must_match_the_supplied_fingerprint(self):
        e = make_bundle()
        object.__setattr__(e.spec, "profile_fingerprint", "0" * 64)
        self.refused(e, R.INVALID_RECORD)

    def test_same_profile_id_different_attributes_do_not_match_evidence(self):
        e, other = make_bundle(), make_bundle(attrs=attributes(viewport_width=800))
        self.assertEqual(e.spec.profile_id, other.spec.profile_id)
        self.refused(replace(e, spec=other.spec), R.PROFILE_MISMATCH)

    def test_same_request_key_different_profiles_is_a_conflict(self):
        a = make_bundle()
        b = make_bundle(job="job-2", nonce="nonce-2", context_id="context-2",
                        attrs=attributes(viewport_width=800))
        result = evaluate_bindings([a, b])
        self.assertIs(result.status, S.UNKNOWN)
        self.assertIs(result.rejections[0].reason, R.REQUEST_SPEC_CONFLICT)

    def test_same_job_cannot_change_spec_even_with_another_request_key(self):
        a = make_bundle()
        b = make_bundle(attempt="attempt-2", epoch=2, nonce="nonce-2", context_id="context-2",
                        request_key="key-2", attrs=attributes(locale="en-US"))
        result = evaluate_bindings([a, b])
        self.assertIs(result.rejections[0].reason, R.JOB_SPEC_CONFLICT)

    def test_context_must_reference_exact_job_spec(self):
        e = make_bundle()
        ctx = replace(e.context, spec_sha256="0" * 64, spec_ref="job-profile-spec:sha256:" + "0" * 64)
        self.refused(replace(e, context=ctx), R.SPEC_MISMATCH)

    def test_page_and_profile_labels_cannot_replace_snapshot_identity(self):
        e = make_bundle()
        for field in ("page_id", "profile_id", "job_id"):
            with self.subTest(field=field):
                self.refused(replace(e, spec=replace(e.spec, **{field: "other"})), R.SPEC_MISMATCH)

    def test_another_attempt_cannot_enter_context_or_receipt(self):
        for name in ("context", "receipt"):
            e = make_bundle()
            self.refused(replace(e, **{name: replace(getattr(e, name), attempt_id="old-attempt")}),
                         R.ATTEMPT_MISMATCH)

    def test_old_epoch_is_rejected_against_the_explicit_attempt(self):
        e = make_bundle(epoch=2)
        for name in ("context", "receipt"):
            with self.subTest(name=name):
                self.refused(replace(e, **{name: replace(getattr(e, name), lease_epoch=1)}),
                             R.ATTEMPT_MISMATCH)

    def test_nonce_must_match_context(self):
        e = make_bundle()
        self.refused(replace(e, receipt=replace(e.receipt, nonce="other")), R.NONCE_MISMATCH)

    def test_nonce_reuse_is_detected_within_one_input(self):
        a = make_bundle()
        b = make_bundle(job="job-2", context_id="context-2", request_key="key-2")
        self.assertIs(evaluate_bindings([a, b]).rejections[0].reason, R.NONCE_REUSED)

    def test_attempt_reuse_is_detected_even_with_a_new_nonce(self):
        a = make_bundle()
        b = make_bundle(epoch=2, context_id="context-2", nonce="nonce-2")
        self.assertIs(evaluate_bindings([a, b]).rejections[0].reason, R.ATTEMPT_REUSED)

    def test_epoch_reuse_is_detected_with_different_attempt_id(self):
        a = make_bundle()
        b = make_bundle(attempt="attempt-2", context_id="context-2", nonce="nonce-2")
        self.assertIs(evaluate_bindings([a, b]).rejections[0].reason, R.EPOCH_REUSED)

    def test_context_id_reuse_is_detected_across_jobs(self):
        a = make_bundle()
        b = make_bundle(job="job-2", request_key="key-2", nonce="nonce-2")
        self.assertIs(evaluate_bindings([a, b]).rejections[0].reason, R.CONTEXT_REUSED)

    def test_context_hash_and_context_id_must_match_receipt(self):
        e = make_bundle()
        for changes in (dict(context_sha256="0" * 64), dict(context_id="other")):
            with self.subTest(changes=changes):
                self.refused(replace(e, receipt=replace(e.receipt, **changes)), R.CONTEXT_MISMATCH)

    def test_binding_context_hash_cannot_be_swapped(self):
        e = make_bundle()
        self.refused(replace(e, binding=replace(e.binding, context_sha256="0" * 64)),
                     R.CONTEXT_MISMATCH)

    def test_receipt_hash_cannot_be_swapped(self):
        e = make_bundle()
        self.refused(replace(e, binding=replace(e.binding, receipt_sha256="0" * 64)),
                     R.RECEIPT_MISMATCH)

    def test_snapshot_hash_must_match_spec_and_binding(self):
        e = make_bundle()
        for name in ("spec", "binding"):
            with self.subTest(name=name):
                self.refused(replace(e, **{name: replace(getattr(e, name), snapshot_sha256="0" * 64)}),
                             R.SNAPSHOT_MISMATCH)

    def test_manifest_reference_and_hash_cannot_be_replaced(self):
        e = make_bundle()
        self.refused(replace(e, binding=replace(e.binding,
                                                manifest=replace(e.binding.manifest, sha256="0" * 64))),
                     R.EVIDENCE_MISMATCH)

    def test_coherent_manifest_hash_cannot_duplicate_either_member(self):
        for member in ("capture_record", "screenshot"):
            e = make_bundle()
            manifest = replace(e.evidence.manifest,
                               sha256=getattr(e.evidence, member).file.sha256)
            evidence = replace(e.evidence, manifest=manifest)
            binding = replace(e.binding, manifest=manifest)
            with self.subTest(member=member):
                self.refused(replace(e, evidence=evidence, binding=binding),
                             R.EVIDENCE_MISMATCH)

    def test_screenshot_reference_hash_and_length_cannot_be_replaced(self):
        e = make_bundle()
        for changes in (dict(sha256="0" * 64), dict(byte_length=101),
                         dict(artifact_ref="job-1/attempt-1/other.png")):
            with self.subTest(changes=changes):
                self.refused(replace(e, binding=replace(e.binding,
                                          screenshot=replace(e.binding.screenshot, **changes))),
                             R.EVIDENCE_MISMATCH)

    def test_interrupted_failed_and_unknown_results_are_refused(self):
        e = make_bundle()
        for result in (CaptureResult.FAILED, CaptureResult.INTERRUPTED, CaptureResult.UNKNOWN):
            receipt = replace(e.receipt, result=result)
            binding = replace(e.binding, receipt_sha256=receipt.sha256)
            with self.subTest(result=result):
                self.refused(replace(e, receipt=receipt, binding=binding), R.CAPTURE_NOT_SUCCEEDED)

    def test_receipt_screenshot_claim_must_match_supplied_evidence(self):
        e = make_bundle()
        receipt = replace(e.receipt, screenshot_sha256="0" * 64)
        self.refused(replace(e, receipt=receipt,
                              binding=replace(e.binding, receipt_sha256=receipt.sha256)),
                     R.EVIDENCE_MISMATCH)

    def test_bridge_origin_and_attempt_ref_cannot_disagree(self):
        e = make_bundle()
        self.refused(replace(e, attempt=AttemptRef("job-1", "old-attempt", 1)), R.ATTEMPT_MISMATCH)
        origin = replace(e.evidence.origin, snapshot_sha256="0" * 64)
        self.refused(replace(e, evidence=replace(e.evidence, origin=origin)), R.SOURCE_MISMATCH)

    def test_corrupt_bridge_shape_is_never_repaired(self):
        for field in ("origin", "manifest", "screenshot", "unattested_profile"):
            e = make_bundle()
            object.__setattr__(e.evidence, field, None)
            with self.subTest(field=field):
                self.refused(e, R.INVALID_RECORD)

    def test_bridge_artifact_kind_and_check_type_require_exact_strings(self):
        class String(str):
            pass
        class EqualToAnything:
            def __eq__(self, other):
                return True
        for member in ("capture_record", "screenshot"):
            for field in ("kind", "check_type"):
                for mode in ("subclass", "equality-spoof"):
                    e = make_bundle()
                    artifact = getattr(e.evidence, member)
                    value = String(getattr(artifact, field)) if mode == "subclass" else EqualToAnything()
                    object.__setattr__(artifact, field, value)
                    with self.subTest(member=member, field=field, mode=mode):
                        self.refused(e, R.EVIDENCE_MISMATCH)

    def test_source_snapshot_timestamp_cannot_be_mutable_or_mistyped(self):
        for value in ({"declared": "before"}, ["before"], 1, True, None):
            e = make_bundle()
            object.__setattr__(e.snapshot, "created_at", value)
            with self.subTest(value=value):
                self.refused(e, R.INVALID_RECORD)

    def test_source_checks_cannot_be_a_mutable_container(self):
        e = make_bundle()
        object.__setattr__(e.snapshot.intent, "required_checks",
                           list(e.snapshot.intent.required_checks))
        self.refused(e, R.SOURCE_MISMATCH)

    def test_coherent_snapshot_without_capture_cannot_supply_capture_evidence(self):
        self.refused(make_bundle(checks=(CheckType.HTTP,)), R.CAPTURE_NOT_SUCCEEDED)

    def test_source_scalar_subclasses_are_not_coerced_by_json(self):
        class String(str):
            pass
        class Integer(int):
            pass
        for target, field in (("snapshot", "job_id"), ("snapshot", "created_at"),
                              ("intent", "target_url"), ("intent", "page_id"),
                              ("intent", "profile_id"), ("attempt", "job_id"),
                              ("attempt", "attempt_id"), ("attempt", "lease_epoch")):
            e = make_bundle()
            obj = e.snapshot.intent if target == "intent" else getattr(e, target)
            value = getattr(obj, field)
            object.__setattr__(obj, field, Integer(value) if field == "lease_epoch" else String(value))
            with self.subTest(target=target, field=field):
                self.refused(e, R.INVALID_RECORD)

    def test_malformed_keys_and_subclassed_models_are_refused(self):
        for key in (None, "", " padded", "x" * 201, True):
            self.refused(replace(make_bundle(), request_key=key), R.INVALID_INPUT)
        e = make_bundle()
        object.__setattr__(e.context, "trusted", True)
        self.refused(e, R.INVALID_RECORD)

    def test_internal_errors_never_become_consistency_or_quality_success(self):
        for error in (RuntimeError("synthetic"), RecursionError()):
            with patch.object(module, "_source", side_effect=error):
                self.refused(make_bundle(), R.INVALID_INPUT)
