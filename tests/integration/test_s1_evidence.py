"""Offline S1/S2 foundation acceptance; not formal T01-T21 signoff."""

from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src.bridge import s1_evidence as module
from src.bridge.s1_evidence import read_s1_capture
from src.bridge.s1_s2_contract import (EvidenceReadResult, RejectionReason as R,
                                      ProfileTrust, TrustedS2Use, UnattestedProfileError)
from src.comparison.profile import CaptureProfile
from src.core.frames import CheckType, FrameKind
from src.storage.manifest import compare_with_db, manifest_bytes, verify_published
from src.storage.repository import Repository
from tests.integration.fixtures import complete
from tests.integration.s1_s2_fixtures import FoundationCase, directory_link


def stat_with(info, **changes):
    values = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
    values.update(changes)
    return SimpleNamespace(**values)


class S1EvidenceTests(FoundationCase):
    def read(self, **kwargs):
        args = dict(profile_declaration=self.binding)
        args.update(kwargs)
        return read_s1_capture(self.repo.db_path, self.store.root, self.saved.job_id, **args)

    def refused(self, reason, **kwargs):
        before = self.snapshot()
        result = self.read(**kwargs)
        self.assertFalse(result.accepted)
        self.assertIsNone(result.evidence)
        self.assertIs(result.rejection.reason, reason)
        self.assertEqual(self.snapshot(), before)
        return result

    def test_adopted_capture_is_reverified_without_quality_promotion(self):
        before = self.snapshot()
        result = self.read()
        self.assertTrue(result.accepted, result.rejection)
        dto = result.evidence
        self.assertEqual(dto.origin, self.binding.origin)
        self.assertEqual(dto.screenshot.file, self.binding.screenshot)
        self.assertEqual(dto.screenshot.kind, "SCREENSHOT_PNG")
        self.assertEqual(dto.capture_record.kind, "CAPTURE_RECORD")
        self.assertEqual(dto.unattested_profile.declared_sha256,
                         self.binding.declared_profile.fingerprint)
        self.assertIs(dto.unattested_profile.trust, ProfileTrust.UNATTESTED)
        self.assertNotEqual(dto.manifest.artifact_ref, dto.screenshot.file.artifact_ref)
        self.assertNotEqual(dto.manifest.sha256, dto.screenshot.file.sha256)
        self.assertFalse(hasattr(dto, "quality"))
        capture = next(c for c in self.repo.list_check_results(self.saved.job_id)
                       if c.check_type is CheckType.CAPTURE)
        self.assertEqual(capture.outcome.value, "UNKNOWN")
        self.assertEqual(self.snapshot(), before)

    def test_existing_baseline_still_has_comparison_not_run(self):
        job, attempt = self.completed("baseline-1")
        binding = self.binding_for(job, attempt)
        before = self.snapshot()
        result = read_s1_capture(self.repo.db_path, self.store.root, job.job_id,
                                 profile_declaration=binding)
        self.assertTrue(result.accepted, result.rejection)
        self.assertEqual(result.evidence.origin.baseline_id, "baseline-1")
        capture = next(c for c in self.repo.list_check_results(job.job_id)
                       if c.check_type is CheckType.CAPTURE)
        self.assertEqual((capture.outcome.value, capture.reason_code),
                         ("UNKNOWN", "COMPARISON_NOT_RUN"))
        self.assertEqual(self.snapshot(), before)

    def test_result_and_nested_dtos_are_frozen(self):
        result = self.read()
        for obj, name, value in ((result, "evidence", None),
                                 (result.evidence.origin, "job_id", "other"),
                                 (result.evidence.screenshot, "seq", 99),
                                 (result.evidence.screenshot.file, "sha256", "0" * 64)):
            with self.assertRaises(FrozenInstanceError):
                setattr(obj, name, value)
        with self.assertRaises(ValueError):
            EvidenceReadResult()

    def test_missing_database_is_not_created(self):
        path = self.base / "missing.sqlite3"
        before = self.snapshot()
        result = read_s1_capture(path, self.store.root, self.saved.job_id)
        self.assertIs(result.rejection.reason, R.SOURCE_UNREADABLE)
        self.assertFalse(path.exists())
        self.assertEqual(self.snapshot(), before)

    def test_invalid_and_unknown_job_ids(self):
        before = self.snapshot()
        for value, reason in (("../job", R.INVALID_INPUT), (None, R.INVALID_INPUT),
                              ("job-absent", R.JOB_NOT_FOUND)):
            with self.subTest(value=value):
                result = read_s1_capture(self.repo.db_path, self.store.root, value)
                self.assertIs(result.rejection.reason, reason)
        self.assertEqual(self.snapshot(), before)

    def test_non_completed_job_is_refused(self):
        self.corrupt_db("UPDATE jobs SET status='SAVING'")
        self.refused(R.JOB_NOT_COMPLETED)

    def test_missing_adoption_is_refused(self):
        self.corrupt_db("UPDATE jobs SET adopted_attempt_id=NULL")
        self.refused(R.NO_ADOPTED_ATTEMPT)

    def test_explicit_unadopted_attempt_never_selects_other_evidence(self):
        self.refused(R.ATTEMPT_NOT_ADOPTED, attempt_id="attempt-old")

    def test_canonical_adoption_can_follow_an_older_attempt(self):
        job, attempt = self.completed(older_attempt=True)
        before = self.snapshot()
        result = read_s1_capture(self.repo.db_path, self.store.root, job.job_id,
                                 profile_declaration=self.binding_for(job, attempt))
        self.assertTrue(result.accepted, result.rejection)
        self.assertEqual(result.evidence.origin.lease_epoch, 2)
        old = read_s1_capture(self.repo.db_path, self.store.root, job.job_id,
                              attempt_id="attempt-1")
        self.assertIs(old.rejection.reason, R.ATTEMPT_NOT_ADOPTED)
        self.assertEqual(self.snapshot(), before)

    def test_adopted_attempt_must_exist_under_this_job(self):
        self.corrupt_db("UPDATE attempts SET job_id='other-job'")
        self.refused(R.ATTEMPT_MISMATCH)

    def test_adopted_attempt_must_remain_latest(self):
        self.corrupt_db("INSERT INTO attempts VALUES(?,?,?,?)",
                        (self.saved.job_id, "new-attempt", 2, "fixture-time"))
        self.refused(R.ATTEMPT_MISMATCH)

    def test_snapshot_hash_mismatch(self):
        self.corrupt_db("UPDATE jobs SET snapshot_sha256=?", ("0" * 64,))
        self.refused(R.SNAPSHOT_INVALID)

    def test_snapshot_json_corruption(self):
        self.corrupt_db("UPDATE jobs SET snapshot_json='not json'")
        self.refused(R.DB_RECORD_INVALID)

    def test_db_identity_columns_cannot_disagree_with_snapshot(self):
        for col, value in (("page_id", "other-page"), ("profile_id", "other-profile"),
                           ("baseline_id", "later-baseline"), ("required_checks", "HTTP")):
            with self.subTest(column=col):
                original = self.saved.snapshot
                self.corrupt_db(f"UPDATE jobs SET {col}=?", (value,))
                self.refused(R.SNAPSHOT_INVALID)
                restore = {"page_id": original.page_id, "profile_id": original.profile_id,
                           "baseline_id": original.baseline_id,
                           "required_checks": ",".join(c.value for c in original.required_checks)}[col]
                self.corrupt_db(f"UPDATE jobs SET {col}=?", (restore,))

    def test_manifest_row_missing(self):
        self.corrupt_db("DELETE FROM manifests")
        self.refused(R.MANIFEST_MISSING)

    def test_manifest_file_missing(self):
        manifest = self.repo.get_manifest_row(self.saved.job_id, self.attempt.attempt_id)
        (self.store.root / manifest.rel_path).unlink()
        self.refused(R.EVIDENCE_MISSING)

    def test_manifest_hash_and_length_are_checked(self):
        row = self.repo.get_manifest_row(self.saved.job_id, self.attempt.attempt_id)
        self.corrupt_db("UPDATE manifests SET sha256=?", ("0" * 64,))
        self.refused(R.EVIDENCE_MISMATCH)
        self.corrupt_db("UPDATE manifests SET sha256=?, byte_length=?",
                        (row.sha256, row.byte_length + 1))
        self.refused(R.EVIDENCE_MISMATCH)

    def test_manifest_and_db_check_disagreement(self):
        self.corrupt_db("UPDATE check_results SET reason_code='OTHER' WHERE check_type='HTTP'")
        self.refused(R.EVIDENCE_MISMATCH)

    def test_required_checks_db_disagreement(self):
        self.corrupt_db("DELETE FROM job_required_checks WHERE check_type='LOAD'")
        self.refused(R.EVIDENCE_MISMATCH)

    def test_screenshot_row_missing(self):
        self.corrupt_db("DELETE FROM artifacts WHERE kind='SCREENSHOT_PNG'")
        self.refused(R.EVIDENCE_MISSING)

    def test_screenshot_file_missing(self):
        (self.store.root / self.png.rel_path).unlink()
        self.refused(R.EVIDENCE_MISSING)

    def test_same_length_image_tampering(self):
        path = self.store.root / self.png.rel_path
        data = path.read_bytes()
        path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
        self.refused(R.EVIDENCE_MISMATCH)

    def test_image_length_tampering(self):
        path = self.store.root / self.png.rel_path
        path.write_bytes(path.read_bytes() + b"extra")
        self.refused(R.EVIDENCE_MISMATCH)

    def test_db_artifact_hash_cannot_override_manifest(self):
        self.corrupt_db("UPDATE artifacts SET sha256=? WHERE kind='SCREENSHOT_PNG'", ("0" * 64,))
        self.refused(R.EVIDENCE_MISMATCH)
        self.corrupt_db("UPDATE artifacts SET sha256=? WHERE kind='SCREENSHOT_PNG'", (self.png.sha256,))
        # Coherent forgery: change valid record bytes, artifact DB hash/length,
        # manifest content and its DB hash/length together. S1's internal
        # consistency verifier alone accepts this. The independently retained
        # fixture manifest pin must reject it; never obtain a new pin from the
        # same untrusted bundle under review.
        rows = self.repo.list_artifacts(self.saved.job_id, self.attempt.attempt_id)
        row = next(a for a in rows if a.kind is FrameKind.HTTP_RECORD)
        data = self.store.read_bytes(row.rel_path) + b" "
        (self.store.root / row.rel_path).write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        self.corrupt_db("UPDATE artifacts SET sha256=?, byte_length=? WHERE kind='HTTP_RECORD'",
                        (digest, len(data)))
        manifest = self.repo.get_manifest_row(self.saved.job_id, self.attempt.attempt_id)
        doc = json.loads(self.store.read_bytes(manifest.rel_path))
        artifact = next(a for a in doc["artifacts"] if a["kind"] == "HTTP_RECORD")
        artifact.update(sha256=digest, byte_length=len(data))
        raw = manifest_bytes(doc)
        (self.store.root / manifest.rel_path).write_bytes(raw)
        self.corrupt_db("UPDATE manifests SET sha256=?, byte_length=?",
                        (hashlib.sha256(raw).hexdigest(), len(raw)))
        rows = self.repo.list_artifacts(self.saved.job_id, self.attempt.attempt_id)
        manifest = self.repo.get_manifest_row(self.saved.job_id, self.attempt.attempt_id)
        verified = verify_published(self.store, rows, manifest, self.saved.snapshot, self.attempt)
        self.assertEqual(compare_with_db(verified, self.saved.snapshot,
                                         self.repo.list_check_results(self.saved.job_id),
                                         rows, self.saved.snapshot.required_checks), [])
        self.refused(R.PROFILE_DECLARATION_MISMATCH)

    def test_artifact_page_and_profile_must_match_snapshot(self):
        for col in ("page_id", "profile_id"):
            with self.subTest(column=col):
                self.corrupt_db(f"UPDATE artifacts SET {col}='other' WHERE kind='SCREENSHOT_PNG'")
                self.refused(R.IDENTITY_MISMATCH)
                self.corrupt_db(f"UPDATE artifacts SET {col}=? WHERE kind='SCREENSHOT_PNG'",
                                (getattr(self.saved.snapshot, col),))

    def test_check_identity_must_match_snapshot(self):
        self.corrupt_db("UPDATE check_results SET page_id='other' WHERE check_type='CAPTURE'")
        self.refused(R.IDENTITY_MISMATCH)

    def test_duplicate_artifact_rows_are_not_collapsed_by_set_comparison(self):
        original = Repository.list_artifacts
        def duplicates(repo, *args):
            rows = original(repo, *args)
            return [*rows, rows[-1]]
        with patch.object(Repository, "list_artifacts", duplicates):
            self.refused(R.EVIDENCE_AMBIGUOUS)

    def test_duplicate_check_rows_are_refused(self):
        original = Repository.list_check_results
        def duplicates(repo, *args):
            rows = original(repo, *args)
            return [*rows, rows[-1]]
        with patch.object(Repository, "list_check_results", duplicates):
            self.refused(R.EVIDENCE_AMBIGUOUS)

    def test_noncanonical_and_escaping_paths_are_refused(self):
        prefix = f"{self.saved.job_id}/{self.attempt.attempt_id}"
        paths = [("../outside.png", R.PATH_INVALID), ("/outside.png", R.PATH_ESCAPE),
                 ("C:/outside.png", R.PATH_ESCAPE), ("//server/share.png", R.PATH_ESCAPE),
                 ("other-job/attempt-1/a.png", R.PATH_ESCAPE),
                 (prefix + "/../a.png", R.PATH_INVALID),
                 (prefix + "//a.png", R.PATH_INVALID),
                 (prefix + "/a.png:stream", R.PATH_INVALID),
                 (prefix.replace("/", "\\") + "\\a.png", R.PATH_INVALID)]
        for path, reason in paths:
            with self.subTest(path=path):
                self.corrupt_db("UPDATE artifacts SET rel_path=? WHERE kind='SCREENSHOT_PNG'", (path,))
                self.refused(reason)

    def test_root_junction_or_symlink_is_refused(self):
        target = self.base / "linked-root"
        self.store.root.rename(target)
        directory_link(self.store.root, target)
        self.refused(R.LINK_NOT_ALLOWED)

    def test_attempt_junction_or_symlink_is_refused(self):
        path = self.store.root / self.saved.job_id / self.attempt.attempt_id
        target = self.base / "outside-attempt"
        path.rename(target)
        directory_link(path, target)
        self.refused(R.LINK_NOT_ALLOWED)

    def test_unreferenced_file_in_adopted_attempt_is_not_used(self):
        path = self.store.root / self.saved.job_id / self.attempt.attempt_id / "orphan.png"
        path.write_bytes(b"not evidence")
        self.refused(R.ORPHAN_EVIDENCE)

    def test_profile_declaration_is_required_and_not_inferred(self):
        self.refused(R.PROFILE_DECLARATION_MISSING, profile_declaration=None)
        self.refused(R.PROFILE_DECLARATION_MISMATCH, profile_declaration=self.binding.declared_profile)

    def test_binding_must_match_exact_capture_origin_and_artifact(self):
        variants = [replace(self.binding, origin=replace(self.binding.origin, **{name: value}))
                    for name, value in (("job_id", "other"), ("adopted_attempt_id", "old"),
                                        ("lease_epoch", 7), ("snapshot_sha256", "0" * 64),
                                        ("page_id", "other"), ("profile_id", "other"))]
        variants.extend(replace(self.binding, screenshot=replace(self.binding.screenshot, **{name: value}))
                        for name, value in (("artifact_ref", "other/attempt/a.png"),
                                            ("sha256", "0" * 64), ("byte_length", 1)))
        for binding in variants:
            with self.subTest(binding=binding):
                self.refused(R.PROFILE_DECLARATION_MISMATCH, profile_declaration=binding)

    def test_same_profile_id_does_not_validate_changed_attributes(self):
        cap = self.binding.declared_profile
        changed = CaptureProfile(cap.profile_id, {**cap.attributes, "viewport_width": 800})
        self.refused(R.PROFILE_DECLARATION_MISMATCH,
                     profile_declaration=replace(self.binding, declared_profile=changed))

    def test_corrupt_or_wrong_kind_profile_is_refused(self):
        from src.comparison.profile import ComparisonProfile
        other = ComparisonProfile("cmp", {"capture_fingerprint": "a" * 64,
                                          "method": "pixel", "method_version": "1",
                                          "threshold_policy": "strict"})
        self.refused(R.PROFILE_DECLARATION_MISMATCH,
                     profile_declaration=replace(self.binding, declared_profile=other))
        cap = self.binding.declared_profile
        object.__setattr__(cap, "attributes", {})
        self.refused(R.PROFILE_DECLARATION_MISMATCH)

    def test_jobs_without_capture_cannot_supply_baselines(self):
        job, attempt = self.job(checks=(CheckType.HTTP, CheckType.LOAD))
        self.run_wire(job, attempt, complete()[:2])
        before = self.snapshot()
        result = read_s1_capture(self.repo.db_path, self.store.root, job.job_id)
        self.assertIs(result.rejection.reason, R.CAPTURE_NOT_SUCCEEDED)
        self.assertEqual(self.snapshot(), before)

    def test_fabricated_capture_pass_or_changed_remains_rejected(self):
        for outcome in ("PASS", "CHANGED"):
            with self.subTest(outcome=outcome):
                self.corrupt_db("UPDATE check_results SET outcome=? WHERE check_type='CAPTURE'", (outcome,))
                self.refused(R.EVIDENCE_MISMATCH)

    def test_only_existing_readers_and_read_only_connection_are_used(self):
        connect = module.connect
        calls = []
        connections = []
        def checked_connect(path, *, read_only=False):
            self.assertTrue(read_only)
            conn = connect(path, read_only=read_only)
            with self.assertRaises(module.sqlite3.OperationalError):
                conn.execute("DELETE FROM jobs")
            conn.set_trace_callback(calls.append)
            connections.append(conn)
            return conn
        before = self.snapshot()
        with patch.object(module, "connect", checked_connect), \
                patch.object(Repository, "commit_completed", side_effect=AssertionError("write")), \
                patch.object(Repository, "transition", side_effect=AssertionError("write")):
            self.assertTrue(self.read().accepted)
            self.assertIs(self.read(profile_declaration=None).rejection.reason, R.PROFILE_DECLARATION_MISSING)
        self.assertTrue(any("BEGIN" in sql for sql in calls))
        for conn in connections:
            with self.assertRaises(module.sqlite3.ProgrammingError):
                conn.execute("SELECT 1")
        self.assertEqual(self.snapshot(), before)

    def test_post_verification_content_change_is_refused(self):
        # Substitute the opened file before its first byte is read. File identity
        # must disagree with the checked lexical path, even on Windows.
        replacement = self.base / "replacement.bin"
        replacement.write_bytes(b"other fixture file")
        original_open = module.os.open
        def substitute(path, flags):
            return original_open(replacement, flags)
        with patch.object(module.os, "open", substitute):
            self.refused(R.SOURCE_CHANGED)
        original = module._ConfinedStore.confirm_unchanged
        def mutate_then_check(store):
            path = store.root / self.png.rel_path
            path.write_bytes(path.read_bytes() + b"late")
            return original(store)
        # This explicit fault injector writes only the fresh fixture. The reader
        # must detect it, and must not repair it or alter Snapshot/check results.
        old_snapshot = self.repo.get_job(self.saved.job_id).snapshot
        old_checks = self.repo.list_check_results(self.saved.job_id)
        with patch.object(module._ConfinedStore, "confirm_unchanged", mutate_then_check):
            result = self.read()
        self.assertIs(result.rejection.reason, R.SOURCE_CHANGED)
        self.assertEqual(self.repo.get_job(self.saved.job_id).snapshot, old_snapshot)
        self.assertEqual(self.repo.list_check_results(self.saved.job_id), old_checks)
        self.assertTrue((self.store.root / self.png.rel_path).read_bytes().endswith(b"late"))

    def test_image_size_refusal_does_not_read_unbounded_input(self):
        with patch.object(module._ConfinedStore, "_MAX_FILE", 1):
            self.refused(R.READ_LIMIT_EXCEEDED)

    def test_trailing_dot_ref_is_refused(self):
        self.screenshot_ref("shot.png", rename_file=True)
        self.assertTrue(self.read().accepted)
        self.screenshot_ref("shot.png.")
        self.refused(R.PATH_INVALID)

    def test_trailing_space_ref_is_refused(self):
        self.screenshot_ref("shot.png", rename_file=True)
        self.screenshot_ref("shot.png ")
        self.refused(R.PATH_INVALID)

    def test_case_alias_must_match_real_filename(self):
        self.screenshot_ref("shot.png", rename_file=True)
        self.screenshot_ref("SHOT.PNG")
        self.refused(R.PATH_INVALID)

    def test_reserved_devices_with_extensions_are_refused(self):
        for name in ("CON", "con.png", "PrN.json", "AUX.txt", "NUL.png", "COM1.bin",
                     "COM9.png", "LPT1.json", "LPT9.png", "COM\u00b9.png", "LPT\u00b2.png",
                     "COM\u00b3.txt", "CON .png", "CONIN$.png", "CONOUT$.json", "CLOCK$.txt"):
            with self.subTest(name=name):
                self.screenshot_ref(name)
                self.refused(R.PATH_INVALID)

    def test_windows_invalid_characters_are_refused(self):
        for name in ('s*ot.png', 's?ot.png', 's|ot.png', 's<ot.png', 's>ot.png', 's"ot.png'):
            with self.subTest(name=name):
                self.screenshot_ref(name)
                self.refused(R.PATH_INVALID)

    def test_windows_rules_apply_to_job_and_attempt_components(self):
        for job, attempt in (("job-1.", "attempt-1"), ("job-1 ", "attempt-1"),
                             ("CON.txt", "attempt-1"), ("job-1", "attempt-1."),
                             ("job-1", "attempt-1 "), ("job-1", "LPT1.txt")):
            with self.subTest(job=job, attempt=attempt):
                confined = module._ConfinedStore(self.store.root, job, attempt)
                with self.assertRaises(module._Rejected) as raised:
                    confined.checked_path(f"{job}/{attempt}/shot.png")
                self.assertIs(raised.exception.reason, R.PATH_INVALID)

    @unittest.skipUnless(os.name == "nt", "requires actual Windows filename resolution")
    def test_windows_dot_alias_resolves_to_same_file_but_is_refused(self):
        self.screenshot_ref("shot.png", rename_file=True)
        path = self.store.root / self.png.rel_path
        self.assertTrue(path.samefile(path.with_name("shot.png.")))
        self.screenshot_ref("shot.png.")
        self.refused(R.PATH_INVALID)

    @unittest.skipUnless(os.name == "nt", "requires actual Windows filename resolution")
    def test_windows_space_alias_resolves_to_same_file_but_is_refused(self):
        self.screenshot_ref("shot.png", rename_file=True)
        path = self.store.root / self.png.rel_path
        self.assertTrue(path.samefile(path.with_name("shot.png ")))
        self.screenshot_ref("shot.png ")
        self.refused(R.PATH_INVALID)

    @unittest.skipUnless(os.name == "nt", "requires actual Windows filename resolution")
    def test_windows_combined_case_and_tail_aliases_are_refused(self):
        self.screenshot_ref("shot.png", rename_file=True)
        path = self.store.root / self.png.rel_path
        for name in ("SHOT.PNG", "SHOT.PNG.", "SHOT.PNG ", "shot.png. "):
            with self.subTest(name=name):
                self.assertTrue(path.samefile(path.with_name(name)))
                self.screenshot_ref(name)
                self.refused(R.PATH_INVALID)

    @unittest.skipUnless(os.name == "nt", "requires actual Windows reserved-name rules")
    def test_windows_reserved_names_are_confirmed_by_runtime(self):
        for name in ("CON.png", "prn.json", "AUX", "NUL.txt", "COM1.png", "LPT9.txt",
                     "COM\u00b9.txt", "LPT\u00b2.png", "COM\u00b3.json"):
            with self.subTest(name=name):
                self.assertTrue(os.path.isreserved(name))
                self.screenshot_ref(name)
                self.refused(R.PATH_INVALID)

    @unittest.skipUnless(os.name == "nt", "requires actual Windows directory case aliases")
    def test_windows_directory_component_case_must_match(self):
        job = self.store.root / self.saved.job_id
        attempt = job / self.attempt.attempt_id
        attempt.rename(attempt.with_name(attempt.name.upper()))
        self.refused(R.PATH_INVALID)
        attempt.with_name(attempt.name.upper()).rename(attempt)
        job.rename(job.with_name(job.name.upper()))
        self.refused(R.PATH_INVALID)

    def test_hardlinked_screenshot_is_refused(self):
        path = self.store.root / self.png.rel_path
        alias = self.base / "outside-evidence-hardlink.png"
        os.link(path, alias)
        self.assertEqual(path.stat().st_nlink, 2)
        self.assertEqual((path.stat().st_dev, path.stat().st_ino),
                         (alias.stat().st_dev, alias.stat().st_ino))
        self.refused(R.LINK_NOT_ALLOWED)

    def test_hardlinked_manifest_and_records_are_refused(self):
        manifest = self.repo.get_manifest_row(self.saved.job_id, self.attempt.attempt_id)
        rows = [manifest, *(a for a in self.repo.list_artifacts(
            self.saved.job_id, self.attempt.attempt_id) if a.kind is not FrameKind.SCREENSHOT_PNG)]
        for row in rows:
            with self.subTest(ref=row.rel_path):
                alias = self.base / "outside-hardlink.bin"
                os.link(self.store.root / row.rel_path, alias)
                try:
                    self.refused(R.LINK_NOT_ALLOWED)
                finally:
                    alias.unlink()

    def test_distinct_refs_with_same_identity_are_refused_even_if_link_count_lies(self):
        # Actual hardlinks give two names one identity. Simulate an unreliable
        # filesystem reporting nlink=1 to exercise the independent identity rule.
        path = self.store.root / self.png.rel_path
        alias = path.with_name("second.png")
        os.link(path, alias)
        self.assertTrue(path.samefile(alias))
        real_lstat, real_fstat = Path.lstat, os.fstat
        def single_link_lstat(path, *args, **kwargs):
            return stat_with(real_lstat(path, *args, **kwargs), st_nlink=1)
        def single_link_fstat(fd):
            return stat_with(real_fstat(fd), st_nlink=1)
        with patch.object(Path, "lstat", single_link_lstat), \
                patch.object(module.os, "fstat", single_link_fstat):
            confined = module._ConfinedStore(self.store.root, self.saved.job_id,
                                             self.attempt.attempt_id)
            confined.read_bytes(self.png.rel_path)
            with self.assertRaises(module._Rejected) as raised:
                confined.read_bytes(alias.relative_to(self.store.root).as_posix())
        self.assertIs(raised.exception.reason, R.FILE_IDENTITY_DUPLICATE)

    def test_unavailable_or_invalid_file_identity_is_refused(self):
        real_fstat = os.fstat
        for changes in ({"st_ino": None}, {"st_ino": 0}, {"st_ino": True},
                        {"st_dev": None}, {"st_dev": -1}, {"st_nlink": None}):
            with self.subTest(changes=changes), patch.object(
                    module.os, "fstat", lambda fd: stat_with(real_fstat(fd), **changes)):
                self.refused(R.FILE_IDENTITY_UNAVAILABLE)

    def test_non_single_link_counts_are_refused(self):
        real_fstat = os.fstat
        for count in (0, 2, -1):
            with self.subTest(count=count), patch.object(
                    module.os, "fstat", lambda fd: stat_with(real_fstat(fd), st_nlink=count)):
                self.refused(R.LINK_NOT_ALLOWED)

    def test_link_added_during_handle_read_is_refused(self):
        real_fstat = os.fstat
        calls = 0
        def changed_links(fd):
            nonlocal calls
            calls += 1
            return stat_with(real_fstat(fd), st_nlink=1 if calls == 1 else 2)
        with patch.object(module.os, "fstat", changed_links):
            self.refused(R.LINK_NOT_ALLOWED)

    def test_same_bytes_at_new_identity_are_not_accepted_on_recheck(self):
        confined = module._ConfinedStore(self.store.root, self.saved.job_id,
                                         self.attempt.attempt_id)
        raw = confined.read_bytes(self.png.rel_path)
        path = self.store.root / self.png.rel_path
        info = path.stat()
        path.rename(self.base / "old-screenshot.png")
        path.write_bytes(raw)
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
        self.assertNotEqual(info.st_ino, path.stat().st_ino)
        with self.assertRaises(module._Rejected) as raised:
            confined.confirm_unchanged()
        self.assertIs(raised.exception.reason, R.SOURCE_CHANGED)

    def test_file_symlink_is_refused(self):
        path = self.store.root / self.png.rel_path
        target = self.base / "outside-screenshot.png"
        path.rename(target)
        try:
            path.symlink_to(target)
        except OSError as error:
            if os.name == "nt" and getattr(error, "winerror", None) == 1314:
                self.skipTest("Windows file symlink privilege unavailable; no elevation")
            raise
        self.refused(R.LINK_NOT_ALLOWED)

    def test_matching_arbitrary_declaration_remains_unattested(self):
        before = self.snapshot()
        actual = self.binding.declared_profile
        for field, value in (("viewport_width", 800), ("locale", "en-US"),
                             ("user_agent", "caller-invented/1")):
            with self.subTest(field=field):
                invented = CaptureProfile(actual.profile_id, {**actual.attributes, field: value})
                declaration = replace(self.binding, declared_profile=invented,
                                      declared_fingerprint=invented.fingerprint)
                result = self.read(profile_declaration=declaration)
                # S1 did not attest these conditions. A matching invented hash
                # can establish internal consistency, never capture authenticity.
                self.assertTrue(result.accepted, result.rejection)
                observed = result.evidence.unattested_profile
                self.assertEqual(observed.declared_sha256, invented.fingerprint)
                self.assertIs(observed.trust, ProfileTrust.UNATTESTED)
                for operation in TrustedS2Use:
                    with self.assertRaises(UnattestedProfileError):
                        observed.require_trusted_use(operation)
        self.assertEqual(self.snapshot(), before)

    def test_unattested_profile_cannot_be_trusted_compatibility_input(self):
        from src.comparison.profile import check_profile_compatibility
        profile = self.read().evidence.unattested_profile
        result = check_profile_compatibility(self.binding.declared_profile, profile)
        self.assertFalse(result.compatible)
        self.assertEqual(result.reason, "NOT_A_PROFILE")
        with self.assertRaises(UnattestedProfileError):
            profile.require_trusted_use(TrustedS2Use.PROFILE_COMPATIBILITY)

    def test_unattested_profile_cannot_be_registered_or_approved_as_baseline(self):
        from src.baseline.model import BaselineCandidate, CandidateError
        dto = self.read().evidence
        before = self.snapshot()
        for operation in (TrustedS2Use.BASELINE_REGISTRATION, TrustedS2Use.BASELINE_APPROVAL):
            with self.subTest(operation=operation), self.assertRaises(UnattestedProfileError):
                dto.unattested_profile.require_trusted_use(operation)
        with self.assertRaises(CandidateError):
            BaselineCandidate("candidate", dto.origin.page_id, dto.unattested_profile,
                              dto.screenshot.file.artifact_ref, dto.screenshot.file.sha256)
        self.assertEqual(self.snapshot(), before)

    def test_unattested_profile_cannot_establish_trusted_comparison(self):
        from src.baseline.approval import decide, register_candidate
        from src.baseline.model import BaselineCandidate, BaselineStatus
        from src.comparison.decision import (ComparisonRequest, EligibilityStatus,
                                             EvidenceRef, UnknownReason, evaluate_eligibility)
        from src.comparison.profile import ComparisonProfile
        dto = self.read().evidence
        # Independent synthetic approved baseline, to avoid a refusal caused
        # merely by a missing approval rather than the current profile type.
        pending = register_candidate(BaselineCandidate(
            "independent-synthetic-baseline", dto.origin.page_id,
            dto.unattested_profile.declared_sha256, "synthetic/baseline.png", "b" * 64))
        approved = decide(pending, decision=BaselineStatus.APPROVED, actor="fixture-reviewer",
                          expected_revision=0, reviewed_digest=pending.registered_digest)
        comparison = ComparisonProfile("cmp", {
            "capture_fingerprint": dto.unattested_profile.declared_sha256,
            "method": "pixel", "method_version": "1", "threshold_policy": "strict"})
        result = evaluate_eligibility(ComparisonRequest(
            dto.origin.page_id, approved, dto.unattested_profile, comparison,
            EvidenceRef(dto.screenshot.file.artifact_ref, dto.screenshot.file.sha256)))
        self.assertIs(result.status, EligibilityStatus.UNKNOWN)
        self.assertIn(UnknownReason.PROFILE_MISMATCH, result.reasons)
        self.assertNotIn(UnknownReason.BASELINE_NOT_APPROVED, result.reasons)
        with self.assertRaises(UnattestedProfileError):
            dto.unattested_profile.require_trusted_use(TrustedS2Use.COMPARISON)

    def test_unattested_profile_cannot_produce_capture_pass_or_changed(self):
        before = self.snapshot()
        dto = self.read().evidence
        for operation in (TrustedS2Use.CAPTURE_PASS, TrustedS2Use.CAPTURE_CHANGED):
            with self.subTest(operation=operation), self.assertRaises(UnattestedProfileError):
                dto.unattested_profile.require_trusted_use(operation)
        capture = next(c for c in self.repo.list_check_results(self.saved.job_id)
                       if c.check_type is CheckType.CAPTURE)
        self.assertEqual(capture.outcome.value, "UNKNOWN")
        self.assertEqual(self.snapshot(), before)

    def test_unattested_state_is_identifiable_and_cannot_be_selected_by_caller(self):
        dto = self.read().evidence
        self.assertEqual(dto.unattested_profile.trust.value, "UNATTESTED")
        self.assertFalse(hasattr(dto, "capture_profile_fingerprint"))
        with self.assertRaises(FrozenInstanceError):
            dto.unattested_profile.trust = "TRUSTED"
        with self.assertRaises(TypeError):
            replace(dto.unattested_profile, trust="TRUSTED")
        for value in ("TRUSTED", None, True):
            # Even object-level tampering cannot enable the guard.
            object.__setattr__(dto.unattested_profile, "declared_sha256", value)
            with self.assertRaises(UnattestedProfileError):
                dto.unattested_profile.require_trusted_use(TrustedS2Use.PROFILE_COMPATIBILITY)

    def test_missing_or_invalid_declared_profile_and_fingerprint_fail_closed(self):
        for field, value in (("declared_profile", None), ("declared_fingerprint", None),
                             ("declared_fingerprint", ""), ("declared_fingerprint", "A" * 64),
                             ("declared_fingerprint", "0" * 64)):
            with self.subTest(field=field, value=value):
                self.refused(R.PROFILE_DECLARATION_MISMATCH,
                             profile_declaration=replace(self.binding, **{field: value}))
