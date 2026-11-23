import hashlib
import json
import unittest
from pathlib import Path

from src.storage.failpoints import SimulatedCrash
from src.storage.manifest import manifest_bytes
from src.storage.recovery import plan_recovery

from support import StorageTestCase


def snapshot_tree(root: Path, db_path: str):
    files = {}
    for p in sorted(Path(root).rglob("*")) if Path(root).exists() else []:
        if p.is_file():
            files[p.relative_to(root).as_posix()] = (hashlib.sha256(p.read_bytes()).hexdigest(),
                                                   p.stat().st_mtime_ns)
    db = Path(db_path)
    return files, hashlib.sha256(db.read_bytes()).hexdigest(), db.stat().st_mtime_ns


class RecoveryDryRunTests(StorageTestCase):
    def plan(self):
        return plan_recovery(self.db_path, str(self.evidence_root))

    def test_clean_state_has_no_findings(self):
        self.run_complete()
        self.run_complete("key-2", baseline=None)
        report = self.plan()
        self.assertEqual(report.findings, ())
        self.assertFalse(report.applied)

    def test_dry_run_changes_nothing(self):
        job, att, fr, out = self.run_complete()
        (self.store.attempt_dir(job.job_id, att.attempt_id) / "stray.bin").write_bytes(b"s")
        self.store.resolve(self.repo.list_artifacts(job.job_id, att.attempt_id)[0].rel_path
                           ).write_bytes(b"corrupt")
        before = snapshot_tree(self.evidence_root, self.db_path)
        report = self.plan()
        self.assertTrue(report.findings)
        self.assertEqual(snapshot_tree(self.evidence_root, self.db_path), before)
        self.assertFalse(report.applied)
        self.assertTrue(all("REVIEW_ONLY" in f.proposal for f in report.findings))

    def test_detects_corruption_missing_and_orphans(self):
        job, att, fr, out = self.run_complete()
        adir = self.store.attempt_dir(job.job_id, att.attempt_id)
        (adir / "stray.bin").write_bytes(b"s")
        (self.evidence_root / "_tmp").mkdir(exist_ok=True)
        (self.evidence_root / "_tmp" / "x.tmp").write_bytes(b"t")
        arts = self.repo.list_artifacts(job.job_id, att.attempt_id)
        self.store.resolve(arts[1].rel_path).unlink()
        codes = self.plan().codes()
        self.assertIn("EVIDENCE_INCONSISTENT", codes)
        self.assertIn("ORPHAN_FILE", codes)
        self.assertIn("TEMP_LEFTOVER", codes)

    def test_crash_before_commit_is_reported_not_repaired(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS)
        self.fp.crash("before_commit")
        with self.assertRaises(SimulatedCrash):
            self.finalize(job, att, fr)
        before = snapshot_tree(self.evidence_root, self.db_path)
        codes = self.plan().codes()
        self.assertEqual(codes.count("ORPHAN_FILE"), 5)
        self.assertIn("NONTERMINAL_JOB", codes)
        self.assertEqual(snapshot_tree(self.evidence_root, self.db_path), before)
        self.assertEqual(self.repo.get_job(job.job_id).status.value, "SAVING")

    def test_cancelled_after_files_written_reports_orphans(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS)
        self.fp.on("after_precommit_reverify", lambda: self.repo.cancel(job.job_id))
        self.finalize(job, att, fr)
        self.assertEqual(self.plan().codes().count("ORPHAN_FILE"), 5)

    def test_files_published_before_a_failed_commit_are_reported_as_unadopted(self):
        job, att = self.start_saving(self.new_job())
        fr = self.frames(job, att, self.ALL_KINDS)
        self.fp.fail("before_commit")
        out = self.finalize(job, att, fr)
        self.assertEqual(len(out.unadopted_files), 5)
        report = self.plan()
        self.assertEqual(sorted(f.subject for f in report.findings if f.code == "ORPHAN_FILE"),
                         sorted(out.unadopted_files))
        self.assertTrue(all(self.store.exists(p) for p in out.unadopted_files))  # not deleted

    def test_manifest_hash_mismatch_with_database_is_detected(self):
        job, att, fr, out = self.run_complete()
        m = self.repo.get_manifest_row(job.job_id, att.attempt_id)
        path = self.store.resolve(m.rel_path)
        path.write_bytes(path.read_bytes() + b" ")
        self.assertIn("EVIDENCE_INCONSISTENT", self.plan().codes())


class RecoveryDatabaseDisagreementTests(StorageTestCase):
    """INT-08: SQLite rows vs manifest vs snapshot, including metadata beyond path/hash."""

    def setUp(self):
        super().setUp()
        self.job, self.att, self.fr, self.out = self.run_complete(baseline=None)
        self.c = self.raw()
        self.c.execute("PRAGMA foreign_keys = OFF")  # simulate out-of-band tampering of the file
        for trg in [r[0] for r in self.c.execute("SELECT name FROM sqlite_master "
                                                 "WHERE type='trigger'")]:
            self.c.execute(f"DROP TRIGGER {trg}")

    def plan_codes(self):
        report = plan_recovery(self.db_path, str(self.evidence_root))
        self.assertFalse(report.applied)
        return report.codes()

    def test_baseline_state_is_consistent(self):
        self.assertEqual(self.plan_codes(), [])

    def test_artifact_kind_in_db_differs_from_manifest(self):
        self.c.execute("UPDATE artifacts SET kind='SCREENSHOT_PNG' WHERE seq=0")
        self.assertIn("DB_MANIFEST_DISAGREE", self.plan_codes())

    def test_artifact_check_type_in_db_differs_from_manifest(self):
        self.c.execute("UPDATE artifacts SET check_type='LOAD' WHERE seq=0")
        self.assertIn("DB_MANIFEST_DISAGREE", self.plan_codes())

    def restore_artifact_row(self, seq):
        """Put the DB row back to what the manifest says (test-only tamper undo)."""
        m = self.repo.get_manifest_row(self.job.job_id, self.att.attempt_id)
        doc = json.loads(self.store.read_bytes(m.rel_path))
        a = next(x for x in doc["artifacts"] if x["seq"] == seq)
        self.c.execute("UPDATE artifacts SET sha256=?, byte_length=?, rel_path=? WHERE seq=?",
                       (a["sha256"], a["byte_length"], a["rel_path"], seq))

    def test_artifact_hash_length_and_path_in_db_differ_from_manifest(self):
        for col, val in (("sha256", "f" * 64), ("byte_length", 99999), ("rel_path", "x/y/z.bin")):
            self.c.execute(f"UPDATE artifacts SET {col} = ? WHERE seq = 1", (val,))
            self.assertIn("DB_MANIFEST_DISAGREE", self.plan_codes(), col)
            self.restore_artifact_row(1)
            self.assertEqual(self.plan_codes(), [], f"after restoring {col}")

    def test_check_outcome_and_reason_in_db_differ_from_manifest(self):
        self.c.execute("UPDATE check_results SET outcome='FAIL' WHERE check_type='HTTP'")
        self.assertIn("DB_CHECK_RESULT_DISAGREE", self.plan_codes())
        self.c.execute("UPDATE check_results SET outcome='PASS' WHERE check_type='HTTP'")
        self.assertEqual(self.plan_codes(), [])
        self.c.execute("UPDATE check_results SET reason_code='SOMETHING_ELSE' "
                       "WHERE check_type='LOAD'")
        self.assertIn("DB_CHECK_RESULT_DISAGREE", self.plan_codes())

    def test_required_check_set_mismatch_is_reported(self):
        self.c.execute("DELETE FROM job_required_checks WHERE check_type='LOAD'")
        self.assertIn("REQUIRED_CHECK_SET_MISMATCH", self.plan_codes())

    def test_missing_check_result_row_is_reported(self):
        self.c.execute("DELETE FROM check_results WHERE check_type='LOAD'")
        codes = self.plan_codes()
        self.assertIn("REQUIRED_CHECK_SET_MISMATCH", codes)
        self.assertIn("DB_CHECK_RESULT_DISAGREE", codes)

    def test_identity_in_db_differs_from_snapshot(self):
        self.c.execute("UPDATE artifacts SET page_id='other-page' WHERE seq=0")
        self.assertIn("DB_IDENTITY_DISAGREE", self.plan_codes())

    def test_corrupt_snapshot_is_a_finding_not_an_exception(self):
        self.c.execute("UPDATE jobs SET snapshot_json='not json'")
        self.assertIn("SNAPSHOT_CORRUPT", self.plan_codes())
        self.c.execute("UPDATE jobs SET snapshot_json='{}'")
        self.assertIn("SNAPSHOT_CORRUPT", self.plan_codes())
        self.c.execute("UPDATE jobs SET snapshot_json='[1,2]'")
        self.assertIn("SNAPSHOT_CORRUPT", self.plan_codes())

    def test_completed_without_manifest_or_adopted_attempt(self):
        self.c.execute("DELETE FROM manifests")
        self.assertIn("COMPLETED_WITHOUT_MANIFEST", self.plan_codes())

    def test_hostile_manifest_content_with_matching_db_hash_is_reported(self):
        """Even if the DB hash was rewritten to match, odd manifest values never raise."""
        m = self.repo.get_manifest_row(self.job.job_id, self.att.attempt_id)
        path = self.store.resolve(m.rel_path)
        good = json.loads(path.read_bytes())

        def http_changed(d):
            others = json.loads(json.dumps([c for c in d["checks"]
                                           if c["check_type"] != "HTTP"]))
            next(c for c in d["checks"] if c["check_type"] == "HTTP").update(
                outcome="CHANGED")
            self.assertEqual(next(c for c in d["checks"]
                                  if c["check_type"] == "HTTP")["outcome"], "CHANGED")
            self.assertEqual([c for c in d["checks"] if c["check_type"] != "HTTP"], others)

        hostile = [
            http_changed,
            lambda d: d.update(artifacts="oops"),
            lambda d: d.update(checks=None),
            lambda d: d["artifacts"][0].update(seq=[1], kind=3),
            lambda d: d["checks"][0].update(artifact_seqs=[[0]], reason_code=None),
        ]
        for mutate in hostile:
            doc = json.loads(json.dumps(good))
            mutate(doc)
            data = manifest_bytes(doc)
            path.write_bytes(data)
            self.c.execute("UPDATE manifests SET sha256=?, byte_length=?",
                           (hashlib.sha256(data).hexdigest(), len(data)))
            report = plan_recovery(self.db_path, str(self.evidence_root))   # must not raise
            self.assertFalse(report.applied)
            self.assertIn("EVIDENCE_INCONSISTENT", report.codes())
            if mutate is http_changed:
                self.assertTrue(any(
                    f.code == "EVIDENCE_INCONSISTENT"
                    and "CHECK_OUTCOME_INVALID:HTTP:OUTCOME_NOT_ALLOWED" in f.detail
                    for f in report.findings))

    def test_manifest_path_escaping_the_store_is_reported(self):
        self.c.execute("UPDATE manifests SET rel_path='../../outside.json'")
        self.assertIn("EVIDENCE_INCONSISTENT", self.plan_codes())

    def test_everything_stays_report_only(self):
        self.c.execute("UPDATE check_results SET outcome='FAIL' WHERE check_type='HTTP'")
        before = snapshot_tree(self.evidence_root, self.db_path)
        report = plan_recovery(self.db_path, str(self.evidence_root))
        self.assertTrue(report.findings)
        self.assertEqual(snapshot_tree(self.evidence_root, self.db_path), before)


if __name__ == "__main__":
    unittest.main()
