"""Synthetic records only: no capture, DB, filesystem, clock or trust source."""

from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import json
import unittest

from src.bridge.s1_s2_contract import (EvidenceArtifact, EvidenceFile, EvidenceOrigin,
                                     ProfileTrust, StructurallyCheckedCaptureEvidence,
                                     TrustedS2Use, UnattestedProfileError,
                                     UnattestedProfileFingerprint)
from src.comparison.profile import CaptureProfile
from src.core.frames import CheckType
from src.core.model import AttemptRef, JobIntent, JobSnapshot
from src.profile_context import (BINDING_SCHEMA, CONTEXT_SCHEMA, JOB_PROFILE_SCHEMA,
                                RECEIPT_SCHEMA, BindingInput, CaptureContext,
                                CaptureReceipt, CaptureResult, EvidenceBinding,
                                JobProfileSpec, ModelError, checked_copy)


def attributes(**over):
    return {**dict(viewport_width=1366, viewport_height=768, device_scale_factor=1,
                   color_scheme="light", locale="ja-JP", timezone="Asia/Tokyo",
                   user_agent="synthetic/1", reduced_motion=True, full_page=False), **over}


def make_bundle(*, job="job-1", attempt="attempt-1", epoch=1, nonce="nonce-1",
                context_id="context-1", request_key="key-1", attrs=None, revision=1,
                checks=(CheckType.HTTP, CheckType.LOAD, CheckType.CAPTURE)):
    profile = CaptureProfile("profile-1", attributes() if attrs is None else attrs)
    intent = JobIntent("https://fixture.invalid/", "page-1", profile.profile_id, checks)
    snapshot = JobSnapshot(job, intent, "synthetic-created-at-not-an-order-proof")
    att = AttemptRef(job, attempt, epoch)
    spec = JobProfileSpec(schema_version=JOB_PROFILE_SCHEMA, job_id=job,
                          page_id=intent.page_id, profile_id=profile.profile_id,
                          snapshot_sha256=snapshot.sha256,
                          profile_definition_revision=revision,
                          capture_attributes=profile.attributes,
                          profile_fingerprint=profile.fingerprint)
    ctx = CaptureContext(schema_version=CONTEXT_SCHEMA, context_id=context_id,
                         spec_ref=spec.reference, spec_sha256=spec.sha256, job_id=job,
                         attempt_id=attempt, lease_epoch=epoch, nonce=nonce,
                         policy_ref="declared-policy/v1", environment_ref="declared-environment/v1")
    manifest = EvidenceFile(f"{job}/{attempt}/manifest.json", "a" * 64, 1000)
    screenshot = EvidenceFile(f"{job}/{attempt}/000003_screenshot_png.png", "b" * 64, 100)
    receipt = CaptureReceipt(schema_version=RECEIPT_SCHEMA, context_id=context_id,
                             context_sha256=ctx.sha256, job_id=job, attempt_id=attempt,
                             lease_epoch=epoch, nonce=nonce, execution_id="execution-1",
                             executor_ref="declared-executor/v1", result=CaptureResult.SUCCEEDED,
                             screenshot_sha256=screenshot.sha256,
                             screenshot_byte_length=screenshot.byte_length)
    binding = EvidenceBinding(schema_version=BINDING_SCHEMA, context_sha256=ctx.sha256,
                              receipt_sha256=receipt.sha256, snapshot_sha256=snapshot.sha256,
                              job_id=job, adopted_attempt_id=attempt, lease_epoch=epoch,
                              manifest=manifest, screenshot=screenshot)
    origin = EvidenceOrigin(job, attempt, epoch, snapshot.sha256, intent.intent_hash,
                            intent.page_id, intent.profile_id, intent.baseline_id)
    evidence = StructurallyCheckedCaptureEvidence(
        origin, manifest,
        EvidenceArtifact(2, "CAPTURE_RECORD", "CAPTURE",
                         EvidenceFile(f"{job}/{attempt}/000002_capture_record.bin", "c" * 64, 200)),
        EvidenceArtifact(3, "SCREENSHOT_PNG", "CAPTURE", screenshot),
        UnattestedProfileFingerprint(profile.fingerprint))
    return BindingInput(request_key=request_key, spec=spec, context=ctx, receipt=receipt,
                        binding=binding, snapshot=snapshot, attempt=att, evidence=evidence)


def records():
    e = make_bundle()
    return (e.spec, e.context, e.receipt, e.binding)


class ModelTests(unittest.TestCase):
    def test_all_four_models_have_explicit_versions_and_stable_hashes(self):
        for model in records():
            with self.subTest(model=type(model).__name__):
                self.assertTrue(model.schema_version)
                self.assertEqual(model.sha256, model.sha256)
                self.assertEqual(len(model.sha256), 64)
                self.assertEqual(checked_copy(model), model)

    def test_profile_fingerprint_matches_existing_v1(self):
        spec = make_bundle().spec
        self.assertEqual(spec.profile_fingerprint,
                         CaptureProfile(spec.profile_id, attributes()).fingerprint)
        self.assertEqual(len(spec.capture_attributes), 9)

    def test_input_attribute_mapping_is_defensively_frozen(self):
        raw = attributes()
        spec = make_bundle(attrs=raw).spec
        digest = spec.sha256
        raw["viewport_width"] = 1
        self.assertEqual(spec.capture_attributes["viewport_width"], 1366)
        self.assertEqual(spec.sha256, digest)
        with self.assertRaises(TypeError):
            spec.capture_attributes["viewport_width"] = 1

    def test_all_record_fields_are_frozen(self):
        for model in records():
            with self.subTest(model=type(model).__name__), self.assertRaises(FrozenInstanceError):
                model.schema_version = "other"

    def test_canonical_json_is_sorted_compact_ascii_and_matches_sha256(self):
        spec = make_bundle(attrs=attributes(locale="日本語")).spec
        expected = json.dumps(spec.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        self.assertEqual(spec.canonical_json(), expected)
        self.assertIn("\\u", expected)
        self.assertEqual(spec.sha256, hashlib.sha256(expected.encode("utf-8")).hexdigest())

    def test_attribute_key_order_does_not_change_hash(self):
        a = make_bundle(attrs=attributes()).spec
        b = make_bundle(attrs=dict(reversed(list(attributes().items())))).spec
        self.assertEqual(a.sha256, b.sha256)

    def test_label_and_revision_are_in_spec_hash_not_profile_fingerprint(self):
        a = make_bundle().spec
        b = replace(a, profile_id="renamed-label")
        c = replace(a, profile_definition_revision=2)
        self.assertEqual(a.profile_fingerprint, b.profile_fingerprint)
        self.assertEqual(a.profile_fingerprint, c.profile_fingerprint)
        self.assertNotEqual(a.sha256, b.sha256)
        self.assertNotEqual(a.sha256, c.sha256)

    def test_each_declared_field_participates_in_record_hash(self):
        e = make_bundle()
        variants = [(e.spec, dict(snapshot_sha256="d" * 64)),
                    (e.context, dict(policy_ref="other-policy")),
                    (e.context, dict(environment_ref="other-environment")),
                    (e.context, dict(nonce="other-nonce")),
                    (e.receipt, dict(executor_ref="other-executor")),
                    (e.receipt, dict(execution_id="other-execution")),
                    (e.binding, dict(receipt_sha256="d" * 64))]
        for record, change in variants:
            with self.subTest(change=change):
                self.assertNotEqual(record.sha256, replace(record, **change).sha256)

    def test_job_spec_is_shared_but_attempt_context_is_distinct(self):
        a, b = make_bundle(), make_bundle(attempt="attempt-2", epoch=2, nonce="nonce-2",
                                         context_id="context-2")
        self.assertEqual(a.spec.sha256, b.spec.sha256)
        self.assertNotEqual(a.context.sha256, b.context.sha256)
        self.assertFalse(hasattr(a.spec, "attempt_id"))

    def test_context_contains_no_future_evidence_or_temporal_proof(self):
        ctx = make_bundle().context
        names = {f.name for f in fields(ctx)}
        self.assertTrue(names.isdisjoint({"manifest", "screenshot", "receipt_sha256",
                                         "manifest_sha256", "screenshot_sha256", "created_at"}))

    def test_file_dtos_are_copied_and_serialized_by_value(self):
        e = make_bundle()
        self.assertIsNot(e.binding.screenshot, e.evidence.screenshot.file)
        body = e.binding.to_dict()
        body["screenshot"]["sha256"] = "0" * 64
        self.assertEqual(e.binding.screenshot.sha256, "b" * 64)

    def test_failure_receipts_can_preserve_partial_output_without_becoming_success(self):
        receipt = make_bundle().receipt
        for result in (CaptureResult.FAILED, CaptureResult.INTERRUPTED, CaptureResult.UNKNOWN):
            with self.subTest(result=result):
                partial = replace(receipt, result=result)
                empty = replace(receipt, result=result, screenshot_sha256=None,
                                screenshot_byte_length=None)
                self.assertIs(partial.trust, ProfileTrust.UNATTESTED)
                self.assertIsNone(empty.screenshot_sha256)

    def test_every_record_denies_all_trusted_operations(self):
        for record in records():
            self.assertIs(record.trust, ProfileTrust.UNATTESTED)
            for operation in TrustedS2Use:
                with self.subTest(model=type(record).__name__, operation=operation), \
                        self.assertRaises(UnattestedProfileError):
                    record.require_trusted_use(operation)


class ModelRejectionTests(unittest.TestCase):
    def test_missing_schema_is_not_defaulted(self):
        for record in records():
            state = dict(vars(record));del state["schema_version"]
            with self.subTest(model=type(record).__name__), self.assertRaises(TypeError):
                type(record)(**state)

    def test_unknown_schema_and_wrong_schema_types(self):
        for record in records():
            for value in ("future-v999", None, 1):
                with self.subTest(model=type(record).__name__, value=value), self.assertRaises(ModelError):
                    replace(record, schema_version=value)

    def test_trusted_and_timestamp_flags_are_not_accepted(self):
        for record in records():
            for name, value in (("trusted", True), ("created_at", "before-capture")):
                with self.subTest(model=type(record).__name__, field=name), self.assertRaises(TypeError):
                    type(record)(**vars(record), **{name: value})

    def test_missing_or_unknown_profile_attributes(self):
        for missing in attributes():
            raw = attributes();del raw[missing]
            with self.subTest(missing=missing), self.assertRaises(ModelError):
                replace(make_bundle().spec, capture_attributes=raw)
        with self.assertRaises(ModelError):
            replace(make_bundle().spec, capture_attributes={**attributes(), "fonts": "invented"})

    def test_bool_int_and_nested_mutable_profile_values_are_rejected(self):
        for name, bad in (("viewport_width", True), ("device_scale_factor", 1.5),
                           ("viewport_height", 0), ("full_page", 1), ("reduced_motion", "false"),
                           ("locale", []), ("user_agent", {"mutable": True})):
            with self.subTest(field=name, value=bad), self.assertRaises(ModelError):
                replace(make_bundle().spec, capture_attributes=attributes(**{name: bad}))

    def test_fingerprint_is_required_and_cannot_disagree_with_attributes(self):
        spec = make_bundle().spec
        for value in (None, "A" * 64, "z" * 64, "0" * 64, True):
            with self.subTest(value=value), self.assertRaises(ModelError):
                replace(spec, profile_fingerprint=value)
        with self.assertRaises(ModelError):
            replace(spec, capture_attributes=attributes(viewport_width=800))

    def test_id_constraints_match_s1_without_sanitization(self):
        for field in ("job_id", "page_id", "profile_id"):
            for value in (None, "../x", "x\n", "x" * 65, "日本語", True):
                with self.subTest(field=field, value=value), self.assertRaises(ModelError):
                    replace(make_bundle().spec, **{field: value})

    def test_revision_and_epoch_do_not_accept_bool_or_nonpositive_values(self):
        e = make_bundle()
        for value in (True, False, 0, -1, 1.0, "1", None):
            for record, name in ((e.spec, "profile_definition_revision"), (e.context, "lease_epoch"),
                                  (e.receipt, "lease_epoch"), (e.binding, "lease_epoch")):
                with self.subTest(field=name, value=value), self.assertRaises(ModelError):
                    replace(record, **{name: value})

    def test_bad_context_spec_reference_is_rejected(self):
        with self.assertRaises(ModelError):
            replace(make_bundle().context, spec_ref="arbitrary-current-settings")

    def test_capture_result_requires_explicit_enum(self):
        for value in ("SUCCEEDED", "PASS", None, True):
            with self.subTest(value=value), self.assertRaises(ModelError):
                replace(make_bundle().receipt, result=value)

    def test_succeeded_receipt_requires_hash_and_positive_length(self):
        for over in (dict(screenshot_sha256=None), dict(screenshot_byte_length=None),
                     dict(screenshot_sha256=None, screenshot_byte_length=None),
                     dict(screenshot_byte_length=True), dict(screenshot_byte_length=0)):
            with self.subTest(over=over), self.assertRaises(ModelError):
                replace(make_bundle().receipt, **over)

    def test_binding_rejects_noncanonical_cross_attempt_and_alias_refs(self):
        e = make_bundle()
        for ref in ("../a", "/job-1/attempt-1/a", "job-2/attempt-1/a", "job-1/old/a",
                    "job-1/attempt-1/../a", "job-1/attempt-1/a.", "job-1/attempt-1/a ",
                    "job-1/attempt-1/a:stream", "job-1\\attempt-1\\a"):
            with self.subTest(ref=ref), self.assertRaises(ModelError):
                replace(e.binding, screenshot=EvidenceFile(ref, "b" * 64, 100))

    def test_binding_file_hashes_and_lengths_are_strict(self):
        e = make_bundle()
        for sha, size in (("A" * 64, 100), ("b" * 64, True), (None, 100), ("b" * 64, 0)):
            with self.subTest(sha=sha, size=size), self.assertRaises(ModelError):
                replace(e.binding, screenshot=EvidenceFile(e.binding.screenshot.artifact_ref, sha, size))

    def test_binding_manifest_and_screenshot_must_be_distinct(self):
        e = make_bundle()
        with self.assertRaises(ModelError):
            replace(e.binding, screenshot=e.binding.manifest)

    def test_corrupted_mutable_attributes_are_not_repaired(self):
        spec = make_bundle().spec
        object.__setattr__(spec, "capture_attributes", attributes())
        with self.assertRaises(ModelError):
            checked_copy(spec)
        with self.assertRaises(ModelError):
            _ = spec.sha256

    def test_extra_deleted_and_subclass_state_are_rejected(self):
        for record in records():
            state = dict(vars(record))
            object.__setattr__(record, "trusted", True)
            with self.assertRaises(ModelError):
                checked_copy(record)
            record.__dict__.pop("trusted")
            record.__dict__.pop("schema_version")
            with self.assertRaises(ModelError):
                checked_copy(record)
            class Subclass(type(record)):
                pass
            with self.assertRaises(ModelError):
                Subclass(**state)
