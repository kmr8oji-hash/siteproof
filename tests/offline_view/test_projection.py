"""Synthetic, isolated S1 fixtures only. No capture or development DB access.

Contract tests validate unauthenticated claims; integration tests additionally
call the real reader and verify that projection changes none of its source.
"""

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from src.bridge import s1_evidence, s2_adapter
from src.bridge.s1_s2_contract import EvidenceReadResult, RejectionReason
from src.bridge.s2_adapter import AdapterRejectionReason
from src.offline_view import (ContractError, MAX_BYTES, NOTICE, SCHEMA_VERSION,
                              canonical_json, parse_report, project_s1_capture,
                              project_s1_capture_json, validate_report)
from src.offline_view.contracts import FIXED
from tests.integration.s1_s2_fixtures import FoundationCase


def report_claim(status="UNKNOWN"):
    """A report CLAIM for serializer/parser tests, not verified source evidence."""
    doc = {**FIXED, "job_id": None, "attempt_id": None,
           "bridge": {"status": status, "reason": None},
           "evidence": {"status": "NOT_VERIFIED", "manifest_ref": None, "screenshot_ref": None},
           "unknown_reasons": ["COMPARISON_NOT_RUN"], "notice": NOTICE}
    if status == "REJECTED":
        doc["bridge"]["reason"] = "EVIDENCE_MISSING"
        doc["unknown_reasons"].insert(0, "EVIDENCE_MISSING")
    if status == "STRUCTURALLY_CHECKED":
        doc.update(job_id="job-1", attempt_id="attempt-1")
        doc["evidence"] = {"status": status, "manifest_ref": "job-1/attempt-1/manifest.json",
                           "screenshot_ref": "job-1/attempt-1/000003_screenshot_png.png"}
        doc["unknown_reasons"].insert(0, "PROFILE_UNATTESTED")
    return doc


class ContractTests(unittest.TestCase):
    def rejected(self, doc):
        with self.assertRaises(ContractError):
            canonical_json(doc)

    def test_three_report_states_roundtrip_without_authentication(self):
        for state in ("STRUCTURALLY_CHECKED", "REJECTED", "UNKNOWN"):
            claim = report_claim(state)
            self.assertEqual(parse_report(canonical_json(claim)), claim)
            self.assertEqual(claim["eligibility"], "UNKNOWN")

    def test_deterministic_canonical_ascii_json_independent_of_key_order(self):
        doc = report_claim()
        encoded = canonical_json(doc)
        self.assertTrue(encoded.isascii())
        self.assertEqual(encoded, canonical_json(dict(reversed(list(doc.items())))))
        self.assertEqual(encoded, json.dumps(doc, ensure_ascii=True, sort_keys=True,
                                            separators=(",", ":"), allow_nan=False))

    def test_validator_returns_defensive_nested_containers(self):
        original = report_claim()
        clean = validate_report(original)
        clean["unknown_reasons"].append("OTHER")
        clean["bridge"]["status"] = "REJECTED"
        self.assertEqual(original, report_claim())

    def test_all_fixed_fields_reject_spoofing(self):
        for key in FIXED:
            doc = report_claim()
            doc[key] = "APPROVED" if key == "human_approval" else "PASS"
            with self.subTest(key=key):
                self.rejected(doc)

    def test_unsupported_schema_version_is_rejected(self):
        doc = report_claim()
        doc["schema_version"] = "siteproof.offline-result.v2"
        self.rejected(doc)

    def test_exact_fields_required_at_every_level(self):
        for key in report_claim():
            doc = report_claim()
            del doc[key]
            with self.subTest(missing=key):
                self.rejected(doc)
        for field in (None, "bridge", "evidence"):
            doc = report_claim()
            (doc if field is None else doc[field])["unexpected"] = "x"
            self.rejected(doc)

    def test_wrong_types_and_subclasses_are_not_coerced(self):
        class FakeDict(dict):
            pass
        self.rejected(FakeDict(report_claim()))
        for key in report_claim():
            for value in (False, 1, [], {}):
                doc = report_claim()
                doc[key] = value
                with self.subTest(key=key, value=type(value).__name__):
                    self.rejected(doc)

    def test_ids_are_nullable_but_bounded_ascii_identifiers(self):
        for value in ("", "../x", "a/b", "a" * 65, "job\n", "job\r", "job\u2028", "日本語"):
            doc = report_claim()
            doc["job_id"] = value
            with self.subTest(value=repr(value)):
                self.rejected(doc)
        doc = report_claim()
        doc["job_id"] = "a" * 64
        self.assertEqual(validate_report(doc)["job_id"], doc["job_id"])

    def test_unsupported_bridge_and_evidence_enums(self):
        for field in ("bridge", "evidence"):
            for status in ("VERIFIED", "PASS", "APPROVED", "", None, True):
                doc = report_claim()
                doc[field]["status"] = status
                self.rejected(doc)

    def test_unknown_reasons_cannot_be_absent_empty_or_not_run_omitted(self):
        for reasons in ([], None, (), ["PROFILE_UNATTESTED"], "COMPARISON_NOT_RUN"):
            doc = report_claim()
            doc["unknown_reasons"] = reasons
            self.rejected(doc)

    def test_reason_codes_are_unique_bounded_nonempty_and_control_free(self):
        for reasons in (["COMPARISON_NOT_RUN"] * 2, ["COMPARISON_NOT_RUN", "x"],
                        ["COMPARISON_NOT_RUN", "CODE\n"], ["COMPARISON_NOT_RUN", None],
                        ["COMPARISON_NOT_RUN", "A" * 129],
                        ["COMPARISON_NOT_RUN"] + ["CODE_" + str(i) for i in range(128)]):
            doc = report_claim()
            doc["unknown_reasons"] = reasons
            self.rejected(doc)

    def test_rejected_report_preserves_reason_without_evidence_promotion(self):
        doc = report_claim("REJECTED")
        self.assertEqual(validate_report(doc)["bridge"]["reason"], "EVIDENCE_MISSING")
        for edit in ("missing", "unlisted", "checked"):
            bad = deepcopy(doc)
            if edit == "missing":
                bad["bridge"]["reason"] = None
            elif edit == "unlisted":
                bad["bridge"]["reason"] = "SOME_OTHER_REASON"
            else:
                bad["evidence"]["status"] = "STRUCTURALLY_CHECKED"
            self.rejected(bad)

    def test_checked_requires_matching_status_ids_refs_and_profile_reason(self):
        for field in ("job_id", "attempt_id", "manifest_ref", "screenshot_ref", "profile_reason", "status"):
            bad = report_claim("STRUCTURALLY_CHECKED")
            if field in ("job_id", "attempt_id"):
                bad[field] = None
            elif field in ("manifest_ref", "screenshot_ref"):
                bad["evidence"][field] = None
            elif field == "profile_reason":
                bad["unknown_reasons"] = ["COMPARISON_NOT_RUN"]
            else:
                bad["evidence"]["status"] = "NOT_VERIFIED"
            self.rejected(bad)

    def test_unknown_has_no_reason_or_verified_references(self):
        for key in ("reason", "manifest_ref", "screenshot_ref"):
            doc = report_claim()
            if key == "reason":
                doc["bridge"][key] = "COMPARISON_NOT_RUN"
            else:
                doc["evidence"][key] = "job-1/attempt-1/file.png"
            self.rejected(doc)

    def test_refs_are_job_attempt_bound_canonical_relative_display_text(self):
        bads = ("other/attempt-1/shot.png", "job-1/other/shot.png", "/job-1/attempt-1/shot.png",
                "job-1/attempt-1/../shot.png", "job-1/attempt-1/..", "job-1/attempt-1/shot.png.",
                "job-1/attempt-1/shot.png ", "job-1/attempt-1/a:b", "job-1/attempt-1/a\\b",
                "job-1/attempt-1/a\x00b", "job-1/attempt-1/a\x85b", "https://x/shot.png",
                "job-1/attempt-1/" + "a" * 4096, "job-1/attempt-1/manifest.json")
        for ref in bads:
            doc = report_claim("STRUCTURALLY_CHECKED")
            doc["evidence"]["screenshot_ref"] = ref
            with self.subTest(ref=repr(ref[:60])):
                self.rejected(doc)

    def test_manifest_name_is_not_an_arbitrary_file(self):
        doc = report_claim("STRUCTURALLY_CHECKED")
        doc["evidence"]["manifest_ref"] = "job-1/attempt-1/other.json"
        self.rejected(doc)

    def test_surrogate_and_non_finite_values_rejected_by_serializer(self):
        for value in (float("nan"), float("inf"), "\ud800"):
            doc = report_claim()
            doc["notice"] = value
            self.rejected(doc)
        doc = report_claim("STRUCTURALLY_CHECKED")
        doc["evidence"]["screenshot_ref"] = "job-1/attempt-1/\udfff.png"
        self.rejected(doc)

    def test_malformed_utf8_bom_and_oversized_input_are_rejected(self):
        for raw in (b"\xff", b"\xef\xbb\xbf{}", b" " * (MAX_BYTES + 1), b"", "\ud800"):
            with self.subTest(raw=type(raw).__name__), self.assertRaises(ContractError):
                parse_report(raw)

    def test_duplicate_members_including_escaped_equivalents_are_rejected(self):
        raw = canonical_json(report_claim())
        for extra in ('"job_id":null,', '"job_\\u0069d":null,'):
            with self.assertRaises(ContractError) as caught:
                parse_report("{" + extra + raw[1:])
            self.assertEqual(caught.exception.code, "DUPLICATE_KEY")

    def test_json_nan_trailing_data_deep_nesting_and_root_types_fail_closed(self):
        for raw in ('{"x":NaN}', '{"x":Infinity}', '{} {}', '[]', 'null', 'false',
                    '[' * 2000 + 'null' + ']' * 2000, canonical_json(report_claim())[:-1]):
            with self.subTest(raw=raw[:30]), self.assertRaises(ContractError):
                parse_report(raw)

    def test_notice_cannot_be_changed_to_a_trust_or_quality_claim(self):
        doc = report_claim()
        doc["notice"] = "Authenticated quality PASS"
        self.rejected(doc)


class ProjectionTests(FoundationCase):
    def project(self, **overrides):
        args = {"profile_declaration": self.binding}
        args.update(overrides)
        return project_s1_capture(self.repo.db_path, self.store.root, self.saved.job_id, **args)

    def unchanged(self, operation):
        before = self.snapshot()
        result = operation()
        self.assertEqual(before, self.snapshot())
        return result

    def checked(self):
        return s1_evidence.read_s1_capture(self.repo.db_path, self.store.root, self.saved.job_id,
                                           profile_declaration=self.binding)

    def test_real_reader_observation_has_checked_refs_but_no_trust_promotion(self):
        doc = self.unchanged(self.project)
        self.assertEqual(doc["bridge"], {"status": "STRUCTURALLY_CHECKED", "reason": None})
        self.assertEqual(doc["evidence"]["status"], "STRUCTURALLY_CHECKED")
        self.assertEqual(doc["job_id"], self.saved.job_id)
        self.assertEqual(doc["attempt_id"], self.attempt.attempt_id)
        self.assertEqual(doc["evidence"]["manifest_ref"], self.binding.manifest.artifact_ref)
        self.assertEqual(doc["evidence"]["screenshot_ref"], self.binding.screenshot.artifact_ref)
        self.assertEqual(doc["profile_trust"], "UNATTESTED")
        self.assertEqual(doc["eligibility"], "UNKNOWN")
        self.assertEqual(doc["comparison"], "NOT_RUN")
        self.assertEqual(doc["human_approval"], "NOT_RECORDED")
        self.assertEqual(doc["unknown_reasons"], ["PROFILE_UNATTESTED", "BASELINE_NOT_APPROVED",
                                                "PROFILE_MISMATCH", "COMPARISON_NOT_RUN"])

    def test_real_canonical_projection_roundtrips_deterministically(self):
        def call():
            return project_s1_capture_json(self.repo.db_path, self.store.root, self.saved.job_id,
                                            profile_declaration=self.binding)
        encoded = self.unchanged(call)
        self.assertEqual(encoded, call())
        self.assertEqual(parse_report(encoded), self.project())

    def test_real_reader_and_adapter_are_both_called(self):
        with patch.object(s1_evidence, "read_s1_capture", wraps=s1_evidence.read_s1_capture) as read, \
                patch.object(s2_adapter, "evaluate_s1_evidence_boundary", wraps=s2_adapter.evaluate_s1_evidence_boundary) as adapt:
            self.assertEqual(self.project()["bridge"]["status"], "STRUCTURALLY_CHECKED")
        self.assertEqual(read.call_count, 1)
        self.assertEqual(adapt.call_count, 1)

    def test_bridge_refusal_preserves_codes_without_copying_requested_ids(self):
        doc = self.unchanged(lambda: self.project(profile_declaration=None))
        self.assertEqual(doc["bridge"], {"status": "REJECTED", "reason": "PROFILE_DECLARATION_MISSING"})
        self.assertIn("PROFILE_DECLARATION_MISSING", doc["unknown_reasons"])
        self.assertIn("BRIDGE_REJECTED", doc["unknown_reasons"])
        self.assertIsNone(doc["job_id"])
        self.assertIsNone(doc["attempt_id"])
        self.assertEqual(doc["evidence"], report_claim()["evidence"])

    def test_wrong_requested_attempt_is_never_projected_as_checked(self):
        doc = self.unchanged(lambda: self.project(attempt_id="wrong-attempt"))
        self.assertEqual(doc["bridge"]["status"], "REJECTED")
        self.assertEqual(doc["evidence"]["status"], "NOT_VERIFIED")
        self.assertIsNone(doc["attempt_id"])

    def test_missing_screenshot_cannot_be_verified(self):
        (self.store.root / self.png.rel_path).rename(self.base / "own-preserved.png")
        doc = self.unchanged(self.project)
        self.assertEqual(doc["bridge"]["status"], "REJECTED")
        self.assertEqual(doc["evidence"]["status"], "NOT_VERIFIED")
        self.assertIsNone(doc["evidence"]["screenshot_ref"])

    def test_mismatched_manifest_is_refused_and_not_rewritten(self):
        path = self.store.root / self.binding.manifest.artifact_ref
        path.write_bytes(path.read_bytes() + b" ")  # this fresh fixture only
        doc = self.unchanged(self.project)
        self.assertEqual(doc["bridge"]["status"], "REJECTED")
        self.assertEqual(doc["evidence"]["status"], "NOT_VERIFIED")

    def test_mismatched_screenshot_is_refused_and_not_rewritten(self):
        path = self.store.root / self.png.rel_path
        path.write_bytes(b"synthetic-invalid-png")
        doc = self.unchanged(self.project)
        self.assertEqual(doc["bridge"]["status"], "REJECTED")
        self.assertIn("COMPARISON_NOT_RUN", doc["unknown_reasons"])

    def test_absent_db_is_not_created_or_inferred_from_user_id(self):
        path = self.base / "absent.sqlite"
        doc = self.unchanged(lambda: project_s1_capture(path, self.store.root, "caller-job"))
        self.assertFalse(path.exists())
        self.assertEqual(doc["bridge"]["reason"], "SOURCE_UNREADABLE")
        self.assertIsNone(doc["job_id"])

    def test_invalid_db_and_job_input_never_escape_or_succeed(self):
        for db, job in ((object(), self.saved.job_id), (self.repo.db_path, None),
                        (self.repo.db_path, "../escape"), (self.repo.db_path, True)):
            with self.subTest(job=job):
                doc = self.unchanged(lambda: project_s1_capture(db, self.store.root, job))
                self.assertNotEqual(doc["bridge"]["status"], "STRUCTURALLY_CHECKED")
                canonical_json(doc)

    def test_dto_as_source_cannot_promote_a_constructed_claim(self):
        dto = self.checked()
        doc = self.unchanged(lambda: project_s1_capture(dto, self.store.root, self.saved.job_id))
        self.assertNotEqual(doc["bridge"]["status"], "STRUCTURALLY_CHECKED")
        import src.offline_view as api
        self.assertFalse(hasattr(api, "project_result"))

    def test_explicit_network_device_and_uri_locators_never_reach_reader(self):
        with patch.object(s1_evidence, "read_s1_capture") as reader:
            for remote in ("//server/share/db", "\\\\server\\share\\db", "https://host/db",
                           "file:///C:/db", "\\\\?\\UNC\\host\\share\\db", "C:/db:stream"):
                for db, root in ((remote, self.store.root), (self.repo.db_path, remote)):
                    doc = project_s1_capture(db, root, self.saved.job_id)
                    self.assertEqual(doc["bridge"]["status"], "UNKNOWN")
        reader.assert_not_called()

    def test_corrupt_dto_fields_are_rejected_by_actual_adapter(self):
        for field, value in (("job_id", "other-job"), ("adopted_attempt_id", "other-attempt")):
            dto = self.checked()
            object.__setattr__(dto.evidence.origin, field, value)
            with patch.object(s1_evidence, "read_s1_capture", return_value=dto):
                doc = self.project()
            self.assertEqual(doc["bridge"]["status"], "UNKNOWN")
            self.assertEqual(doc["evidence"]["status"], "NOT_VERIFIED")

    def test_coherent_but_request_mismatched_dto_is_not_projected(self):
        dto = self.checked()
        with patch.object(s1_evidence, "read_s1_capture", return_value=dto):
            doc = project_s1_capture(self.repo.db_path, self.store.root, "different-job")
            other = self.project(attempt_id="different-attempt")
        for result in (doc, other):
            self.assertEqual(result["bridge"]["status"], "UNKNOWN")
            self.assertIn("EVIDENCE_REFERENCE_MISMATCH", result["unknown_reasons"])

    def test_unvalidated_dictionary_is_not_evidence(self):
        for raw in (report_claim("STRUCTURALLY_CHECKED"), None, object()):
            with patch.object(s1_evidence, "read_s1_capture", return_value=raw):
                doc = self.project()
            self.assertEqual(doc["bridge"]["status"], "UNKNOWN")

    def test_reader_exception_is_generic_unknown_without_leaking_paths(self):
        with patch.object(s1_evidence, "read_s1_capture", side_effect=RuntimeError("sensitive-path-never-echo")):
            doc = self.project()
        self.assertEqual(doc["bridge"]["status"], "UNKNOWN")
        self.assertNotIn("sensitive", canonical_json(doc))
        self.assertIn("COMPARISON_NOT_RUN", doc["unknown_reasons"])

    def test_adapter_exception_or_malformed_outcome_cannot_promote(self):
        with patch.object(s2_adapter, "evaluate_s1_evidence_boundary", side_effect=RuntimeError):
            self.assertEqual(self.project()["bridge"]["status"], "UNKNOWN")
        with patch.object(s2_adapter, "evaluate_s1_evidence_boundary", return_value={"status": "PASS"}):
            self.assertEqual(self.project()["bridge"]["status"], "UNKNOWN")

    def test_adapter_missing_unknown_reasons_is_fail_closed(self):
        boundary = s2_adapter.evaluate_s1_evidence_boundary(self.checked())
        for reasons in ((), [], ("COMPARISON_NOT_RUN",), boundary.unknown_reasons[:-1]):
            with patch.object(s2_adapter, "evaluate_s1_evidence_boundary", return_value=replace(boundary, unknown_reasons=reasons)):
                self.assertEqual(self.project()["bridge"]["status"], "UNKNOWN")

    def test_projection_does_not_call_comparison_or_baseline_approval(self):
        from src.comparison import decision
        from src.baseline import approval
        def forbidden(*a, **kw):
            raise AssertionError("outside read-only projection")
        with patch.object(decision, "evaluate_eligibility", forbidden), \
                patch.object(approval, "register_candidate", forbidden), \
                patch("subprocess.Popen", forbidden), patch("socket.socket", forbidden):
            doc = self.project()
        self.assertEqual(doc["bridge"]["status"], "STRUCTURALLY_CHECKED")
        self.assertEqual(doc["comparison"], "NOT_RUN")
        self.assertEqual(doc["human_approval"], "NOT_RECORDED")


if __name__ == "__main__":
    unittest.main()
