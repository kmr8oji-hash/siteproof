import sqlite3
import unittest

from src.core.errors import (CasConflict, DuplicateAttemptError, IdempotencyConflict,
                             InvalidTransition, StaleAttemptError, StorageError,
                             TerminalJobError, ValidationError)
from src.core.model import JobStatus

from support import HTTP, StorageTestCase, make_intent

S = JobStatus


class AcceptTests(StorageTestCase):
    def test_accept_creates_job_in_accepted_with_fixed_required_checks(self):
        res = self.repo.accept_job("k1", make_intent())
        self.assertTrue(res.created)
        self.assertEqual(res.job.status, S.ACCEPTED)
        self.assertEqual(res.job.version, 0)
        n = self.raw().execute("SELECT count(*) FROM job_required_checks").fetchone()[0]
        self.assertEqual(n, 3)

    def test_duplicate_acceptance_returns_same_job(self):
        a = self.repo.accept_job("k1", make_intent())
        b = self.repo.accept_job("k1", make_intent())
        self.assertFalse(b.created)
        self.assertEqual(a.job.job_id, b.job.job_id)
        self.assertEqual(len(self.repo.list_jobs()), 1)

    def test_same_key_different_intent_is_rejected_and_nothing_is_stored(self):
        self.repo.accept_job("k1", make_intent())
        with self.assertRaises(IdempotencyConflict):
            self.repo.accept_job("k1", make_intent(url="https://example.invalid/other"))
        with self.assertRaises(IdempotencyConflict):
            self.repo.accept_job("k1", make_intent(checks=(HTTP,)))
        self.assertEqual(len(self.repo.list_jobs()), 1)

    def test_blank_key_rejected(self):
        for k in ("", "  "):
            with self.assertRaises(ValidationError):
                self.repo.accept_job(k, make_intent())


class SnapshotImmutabilityTests(StorageTestCase):
    def test_snapshot_columns_cannot_be_updated(self):
        job = self.new_job()
        c = self.raw()
        for col, val in (("snapshot_json", "{}"), ("intent_hash", "0" * 64),
                         ("snapshot_sha256", "0" * 64), ("page_id", "x"), ("profile_id", "x"),
                         ("baseline_id", None), ("idempotency_key", "other"),
                         ("created_at", "x"), ("job_id", "job-999")):
            with self.assertRaises(sqlite3.IntegrityError, msg=col):
                c.execute(f"UPDATE jobs SET {col} = ?, status='WAITING_WORKER', version=1 "
                          "WHERE job_id = ?", (val, job.job_id))
        self.assertEqual(self.repo.get_job(job.job_id), job)

    def test_required_checks_cannot_change_after_acceptance(self):
        job = self.new_job(checks=(HTTP,))
        c = self.raw()
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("INSERT INTO job_required_checks VALUES(?,?,?,?)",
                      (job.job_id, "page-1", "desktop", "LOAD"))
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("UPDATE jobs SET required_checks='HTTP,LOAD', status='WAITING_WORKER', "
                      "version=1 WHERE job_id = ?", (job.job_id,))
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("DELETE FROM job_required_checks WHERE job_id = ?", (job.job_id,))
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("UPDATE job_required_checks SET check_type='LOAD' WHERE job_id = ?",
                      (job.job_id,))

    def test_jobs_cannot_be_deleted(self):
        job = self.new_job()
        with self.assertRaises(sqlite3.IntegrityError):
            self.raw().execute("DELETE FROM jobs WHERE job_id = ?", (job.job_id,))

    def test_tampered_snapshot_is_detected_on_read(self):
        job = self.new_job()
        c = self.raw()
        for trg in ("jobs_snapshot_immutable", "jobs_transition_valid", "jobs_version_step"):
            c.execute(f"DROP TRIGGER {trg}")  # simulate out-of-band tampering of the file
        c.execute("UPDATE jobs SET snapshot_json = replace(snapshot_json,'page-1','page-2')")
        with self.assertRaises(StorageError):
            self.repo.get_job(job.job_id)

    def test_foreign_keys_are_enforced(self):
        c = self.raw()
        self.assertEqual(c.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("INSERT INTO attempts VALUES('nope','a',1,'t')")


class TransitionAndCasTests(StorageTestCase):
    def test_version_increments_and_stale_version_conflicts(self):
        job = self.new_job()
        j1 = self.repo.transition(job.job_id, 0, S.WAITING_WORKER)
        self.assertEqual(j1.version, 1)
        with self.assertRaises(CasConflict) as cm:
            self.repo.transition(job.job_id, 0, S.RUNNING)
        self.assertEqual(cm.exception.current_version, 1)
        self.assertEqual(self.repo.get_job(job.job_id).status, S.WAITING_WORKER)

    def test_invalid_transition_rejected(self):
        job = self.new_job()
        with self.assertRaises(InvalidTransition):
            self.repo.transition(job.job_id, 0, S.SAVING)
        with self.assertRaises(InvalidTransition):
            self.repo.transition(job.job_id, 0, S.COMPLETED)

    def test_failure_states_need_reason(self):
        job, att = self.start_saving(self.new_job())
        with self.assertRaises(ValidationError):
            self.repo.transition(job.job_id, job.version, S.FAILED_EVIDENCE,
                                 expected_attempt=att)
        done = self.repo.transition(job.job_id, job.version, S.FAILED_EVIDENCE, "TEST",
                                    expected_attempt=att)
        self.assertEqual(done.terminal_reason, "TEST")

    def test_terminal_job_cannot_be_modified_by_api_or_sql(self):
        job = self.new_job()
        done = self.repo.cancel(job.job_id)
        self.assertEqual(done.status, S.CANCELLED)
        for dst in (S.WAITING_WORKER, S.CANCELLED, S.FAILED_EXECUTION):
            with self.assertRaises(TerminalJobError):
                self.repo.transition(job.job_id, done.version, dst, "x")
        with self.assertRaises(TerminalJobError):
            self.repo.cancel(job.job_id)
        with self.assertRaises(TerminalJobError):
            self.repo.register_attempt(job.job_id, "att-1", 1)
        c = self.raw()
        for status in ("ACCEPTED", "COMPLETED", "RUNNING"):
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("UPDATE jobs SET status=?, version=version+1 WHERE job_id=?",
                          (status, job.job_id))
        self.assertEqual(self.repo.get_job(job.job_id), done)

    def test_sql_transitions_must_be_valid_single_steps(self):
        job = self.new_job()
        c = self.raw()
        with self.assertRaises(sqlite3.IntegrityError):  # ACCEPTED -> RUNNING not allowed
            c.execute("UPDATE jobs SET status='RUNNING', version=1 WHERE job_id=?", (job.job_id,))
        with self.assertRaises(sqlite3.IntegrityError):  # version skip
            c.execute("UPDATE jobs SET status='WAITING_WORKER', version=5 WHERE job_id=?",
                      (job.job_id,))
        waiting = self.repo.transition(job.job_id, 0, S.WAITING_WORKER)
        with self.assertRaises(sqlite3.IntegrityError):  # terminal failure without reason
            c.execute("UPDATE jobs SET status='TIMED_OUT', version=? WHERE job_id=?",
                      (waiting.version + 1, job.job_id))

    def test_sql_cannot_complete_without_evidence(self):
        job, att = self.start_saving(self.new_job())
        c = self.raw()
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("UPDATE jobs SET status='COMPLETED', version=version+1, "
                      "adopted_attempt_id=? WHERE job_id=?", (att.attempt_id, job.job_id))
        self.assertEqual(self.repo.get_job(job.job_id).status, S.SAVING)

    def test_reference_tables_are_read_only(self):
        c = self.raw()
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("DELETE FROM allowed_transitions")
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("UPDATE artifact_requirements SET kind='HTTP_RECORD'")


class AttemptTests(StorageTestCase):
    def test_attempt_registration_rules(self):
        job = self.new_job()
        self.repo.register_attempt(job.job_id, "att-1", 5)
        with self.assertRaises(DuplicateAttemptError):
            self.repo.register_attempt(job.job_id, "att-1", 6)
        with self.assertRaises(StaleAttemptError):
            self.repo.register_attempt(job.job_id, "att-2", 5)
        with self.assertRaises(StaleAttemptError):
            self.repo.register_attempt(job.job_id, "att-2", 4)
        self.repo.register_attempt(job.job_id, "att-3", 6)
        self.assertEqual(self.repo.latest_attempt(job.job_id).attempt_id, "att-3")

    def test_epoch_rule_also_holds_at_sql_level(self):
        job = self.new_job()
        self.repo.register_attempt(job.job_id, "att-1", 5)
        c = self.raw()
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("INSERT INTO attempts VALUES(?,?,?,?)", (job.job_id, "att-x", 3, "t"))
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("UPDATE attempts SET lease_epoch = 99")

    def test_invalid_ids_rejected(self):
        job = self.new_job()
        for bad in ("../x", "", "a/b", "a b"):
            with self.assertRaises(ValidationError):
                self.repo.register_attempt(job.job_id, bad, 1)
        with self.assertRaises(ValidationError):
            self.repo.register_attempt(job.job_id, "ok", 0)


class CheckResultConstraintTests(StorageTestCase):
    def _insert(self, c, **over):
        row = dict(job_id=None, attempt_id="att-1", page_id="page-1", profile_id="desktop",
                   check_type="HTTP", outcome="PASS", reason_code="OK")
        row.update(over)
        c.execute("INSERT INTO check_results VALUES(:job_id,:attempt_id,:page_id,:profile_id,"
                  ":check_type,:outcome,:reason_code)", row)

    def test_check_key_is_unique_and_reason_is_mandatory(self):
        job, att = self.start_saving(self.new_job())
        c = self.raw()
        self._insert(c, job_id=job.job_id)
        with self.assertRaises(sqlite3.IntegrityError):  # duplicate unique key
            self._insert(c, job_id=job.job_id, outcome="FAIL")
        for bad in ("", "   "):
            with self.assertRaises(sqlite3.IntegrityError):
                self._insert(c, job_id=job.job_id, check_type="LOAD", reason_code=bad)
        with self.assertRaises(sqlite3.IntegrityError):  # NULL reason
            self._insert(c, job_id=job.job_id, check_type="LOAD", reason_code=None)

    def test_results_must_reference_required_checks_and_known_attempts(self):
        job, att = self.start_saving(self.new_job(checks=(HTTP,)))
        c = self.raw()
        with self.assertRaises(sqlite3.IntegrityError):  # LOAD is not required
            self._insert(c, job_id=job.job_id, check_type="LOAD")
        with self.assertRaises(sqlite3.IntegrityError):  # other page
            self._insert(c, job_id=job.job_id, page_id="page-2")
        with self.assertRaises(sqlite3.IntegrityError):  # unknown/non-current attempt
            self._insert(c, job_id=job.job_id, attempt_id="att-ghost")

    def test_results_only_while_saving(self):
        job = self.new_job()
        with self.assertRaises(sqlite3.IntegrityError):
            self._insert(self.raw(), job_id=job.job_id)

    def test_results_are_immutable(self):
        job, _ = self.start_saving(self.new_job())
        c = self.raw()
        self._insert(c, job_id=job.job_id)
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("UPDATE check_results SET outcome='FAIL'")
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("DELETE FROM check_results")

    def test_capture_pass_requires_baseline_and_changed_is_capture_only(self):
        job, _ = self.start_saving(self.new_job(baseline=None))
        c = self.raw()
        for oc in ("PASS", "CHANGED"):
            with self.assertRaises(sqlite3.IntegrityError):
                self._insert(c, job_id=job.job_id, check_type="CAPTURE", outcome=oc)
        # a baseline id alone does not unlock PASS/CHANGED either (no trusted comparison)
        job2, _ = self.start_saving(self.new_job("key-b", baseline="base-1"))
        for oc in ("PASS", "CHANGED"):
            with self.assertRaises(sqlite3.IntegrityError):
                self._insert(c, job_id=job2.job_id, check_type="CAPTURE", outcome=oc)
        self._insert(c, job_id=job.job_id, check_type="CAPTURE", outcome="UNKNOWN",
                     reason_code="NO_BASELINE")
        with self.assertRaises(sqlite3.IntegrityError):
            self._insert(c, job_id=job.job_id, check_type="HTTP", outcome="CHANGED")


if __name__ == "__main__":
    unittest.main()
