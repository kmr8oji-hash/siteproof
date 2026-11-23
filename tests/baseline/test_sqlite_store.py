"""LOCAL-BASELINE-STORE-01 B01..B10; only fresh temporary S1+baseline DBs.

No artifact files, real user DB, network, subprocess, UI or capture is used.
These IDs do not stand for the formal project T01-T21 acceptance cases.
"""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import sqlite3
import tempfile
import time
from threading import Barrier
import unittest
from unittest.mock import patch

from src.baseline.approval import (AlreadyDecided, CandidateTampered, DuplicateCandidate,
                                   InvalidDecision, RevisionConflict, UnknownCandidate)
from src.baseline.model import BaselineCandidate, BaselineStatus, CandidateError
from src.baseline.sqlite_store import (AmbiguousBaselineCommit, BaselineStoreCorrupt,
                                      BaselineStoreError, SQLiteBaselineStore)
from src.bridge.s1_s2_contract import (EvidenceArtifact, EvidenceFile, EvidenceOrigin,
    EvidenceReadResult, StructurallyCheckedCaptureEvidence, TrustedS2Use,
    UnattestedProfileError, UnattestedProfileFingerprint)
from src.bridge.s2_adapter import AdapterRejectionReason, evaluate_s1_evidence_boundary
from src.comparison.decision import EligibilityStatus
from src.storage import baseline_schema
from src.storage.repository import Repository


A, R, P = BaselineStatus.APPROVED, BaselineStatus.REJECTED, BaselineStatus.PENDING


def candidate(cid="candidate-1", **changes):
    values = dict(candidate_id=cid, page_id="page-1", profile_fingerprint="a" * 64,
                  artifact_ref="job-1/attempt-1/shot.png", artifact_sha256="b" * 64)
    values.update(changes)
    return BaselineCandidate(**values)


class SQLiteBaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="siteproof-baseline-store-01-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "siteproof.sqlite"
        self.store = SQLiteBaselineStore.create(self.path, self.root)

    def approve(self, cid="candidate-1", current=0, **changes):
        record = self.store.get(cid)
        values = dict(decision=A, actor="alice", expected_revision=0,
                      reviewed_digest=record.registered_digest, expected_current_version=current)
        values.update(changes)
        return self.store.decide(cid, **values)

    def reopen(self):
        self.store = SQLiteBaselineStore.open(self.path, self.root)
        return self.store

    def counts(self):
        with closing(sqlite3.connect(self.path)) as conn, conn:
            return tuple(conn.execute("SELECT count(*) FROM " + table).fetchone()[0]
                         for table in ("baseline_candidates", "baseline_decisions",
                                       "baseline_versions", "baseline_heads"))

    def test_B01_register_read_back_retains_all_fields_without_artifact_io(self):
        c = candidate(artifact_ref="unopened/nonexistent.png")
        pending = self.store.register(c)
        self.assertEqual(pending.candidate, c)
        self.assertEqual(self.store.get(c.candidate_id), pending)
        self.assertEqual((pending.status, pending.revision, pending.decision), (P, 0, None))
        self.assertIsNone(self.store.current(c.page_id, c.profile_fingerprint))
        self.assertEqual(self.counts(), (1, 0, 0, 0))
        self.assertEqual({p.name for p in self.root.iterdir()}, {"siteproof.sqlite"})

    def test_B01_rejects_invalid_missing_and_tampered_candidates(self):
        for field, value in (("candidate_id", ""), ("page_id", None),
                             ("profile_fingerprint", "bad"), ("artifact_sha256", "A" * 64)):
            with self.subTest(field=field), self.assertRaises(CandidateError):
                self.store.register(candidate(**{field: value}))
        bad = candidate()
        object.__setattr__(bad, "artifact_ref", "")
        with self.assertRaises(CandidateError):
            self.store.register(bad)
        missing = candidate()
        object.__delattr__(missing, "page_id")
        with self.assertRaises(CandidateError):
            self.store.register(missing)
        with self.assertRaises(CandidateError):
            self.store.register({})
        self.assertEqual(self.counts(), (0, 0, 0, 0))

    def test_B02_reopen_preserves_candidate_and_decision(self):
        pending = self.store.register(candidate())
        self.assertEqual(self.reopen().get("candidate-1"), pending)
        approved = self.approve()
        self.assertEqual(self.reopen().get("candidate-1"), approved)
        self.assertEqual(self.store.current("page-1", "a" * 64).record, approved)

    def test_B03_approval_history_records_reviewed_actor_digest_and_revision(self):
        pending = self.store.register(candidate())
        approved = self.approve()
        version = self.store.history("page-1", "a" * 64)[0]
        self.assertEqual(version.version, 1)
        self.assertEqual(version.record, approved)
        self.assertEqual((approved.decision.actor, approved.decision.candidate_digest,
                          approved.decision.revision), ("alice", pending.registered_digest, 1))
        with closing(sqlite3.connect(self.path)) as conn, conn:
            self.assertEqual(conn.execute("SELECT expected_revision,revision FROM baseline_decisions").fetchone(), (0, 1))
        self.assertEqual(self.counts(), (1, 1, 1, 1))

    def test_B03_rejection_is_durable_and_does_not_create_current_version(self):
        self.store.register(candidate())
        rejected = self.approve(decision=R)
        self.assertIs(rejected.status, R)
        self.assertEqual(self.reopen().get("candidate-1"), rejected)
        self.assertEqual(self.store.history("page-1", "a" * 64), ())
        with self.assertRaises(AlreadyDecided):
            self.approve()

    def test_B04_candidate_revision_conflict_and_invalid_approval_input(self):
        self.store.register(candidate())
        for revision in (1, -1, True, "0"):
            with self.subTest(revision=revision), self.assertRaises(RevisionConflict):
                self.approve(expected_revision=revision)
        for actor in ("", "system", "ＳＹＳＴＥＭ"):
            with self.subTest(actor=actor), self.assertRaises(InvalidDecision):
                self.approve(actor=actor)
        with self.assertRaises(CandidateTampered):
            self.approve(reviewed_digest="f" * 64)
        self.assertEqual(self.counts(), (1, 0, 0, 0))

    def test_B04_explicit_current_version_required(self):
        self.store.register(candidate())
        for version in (None, True, -1, 1, "0"):
            with self.subTest(version=version), self.assertRaises(RevisionConflict):
                self.approve(current=version)
        self.assertEqual(self.counts(), (1, 0, 0, 0))

    def test_B05_two_candidates_reviewing_same_head_cannot_both_approve(self):
        self.store.register(candidate("a"))
        self.store.register(candidate("b"))
        stores = [SQLiteBaselineStore.open(self.path, self.root) for _ in range(2)]
        barrier = Barrier(2)
        def attempt(i):
            cid = ("a", "b")[i]
            record = stores[i].get(cid)
            barrier.wait(timeout=2)
            try:
                return stores[i].decide(cid, decision=A, actor="alice", expected_revision=0,
                    reviewed_digest=record.registered_digest, expected_current_version=0)
            except RevisionConflict:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, range(2)))
        self.assertEqual(sum(r is not None for r in results), 1)
        self.assertEqual(self.reopen().current("page-1", "a" * 64).version, 1)
        self.assertEqual(self.counts(), (2, 1, 1, 1))
        self.assertEqual(sum(self.store.get(cid).status is P for cid in ("a", "b")), 1)

    def test_B05_same_candidate_decision_is_one_shot_across_handles(self):
        pending = self.store.register(candidate())
        stores = [SQLiteBaselineStore.open(self.path, self.root) for _ in range(2)]
        barrier = Barrier(2)
        def attempt(store):
            barrier.wait(timeout=2)
            try:
                return store.decide("candidate-1", decision=A, actor="alice", expected_revision=0,
                    reviewed_digest=pending.registered_digest, expected_current_version=0)
            except AlreadyDecided:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, stores))
        self.assertEqual(sum(r is not None for r in results), 1)
        self.assertEqual(self.counts(), (1, 1, 1, 1))

    def test_B06_new_approved_version_preserves_old_snapshot_and_history(self):
        self.store.register(candidate("old"))
        old = self.approve("old")
        old_version = self.store.current("page-1", "a" * 64)
        self.store.register(candidate("new", artifact_sha256="c" * 64))
        self.assertEqual(self.store.current("page-1", "a" * 64), old_version)
        self.approve("new", current=1)
        history = self.reopen().history("page-1", "a" * 64)
        self.assertEqual([v.version for v in history], [1, 2])
        self.assertEqual(history[0], old_version)
        self.assertEqual(self.store.get("old"), old)
        self.assertEqual(self.store.current("page-1", "a" * 64), history[-1])
        with self.assertRaises(FrozenInstanceError):
            old_version.version = 2

    def test_B06_page_and_profile_have_independent_version_scopes(self):
        for c in (candidate("one"), candidate("two", profile_fingerprint="c" * 64),
                  candidate("three", page_id="page-2")):
            self.store.register(c)
            self.approve(c.candidate_id)
            self.assertEqual(self.store.current(c.page_id, c.profile_fingerprint).version, 1)

    def test_B07_duplicate_identical_and_changed_content_never_overwrites(self):
        original = self.store.register(candidate())
        for c in (candidate(), candidate(artifact_ref="different.png"), candidate(page_id="page-2")):
            with self.subTest(c=c), self.assertRaises(DuplicateCandidate):
                self.store.register(c)
        self.assertEqual(self.store.get("candidate-1"), original)
        self.approve()
        with self.assertRaises(DuplicateCandidate):
            self.store.register(candidate())
        self.assertEqual(self.counts(), (1, 1, 1, 1))

    def test_B08_failure_between_decision_and_version_rolls_back(self):
        self.store.register(candidate())
        original_connect = self.store._connect
        def failed_connect(readonly):
            conn = original_connect(readonly)
            if not readonly:
                conn.set_authorizer(lambda action, table, *args: sqlite3.SQLITE_DENY
                                    if action == sqlite3.SQLITE_INSERT and table == "baseline_versions"
                                    else sqlite3.SQLITE_OK)
            return conn
        with patch.object(self.store, "_connect", side_effect=failed_connect):
            with self.assertRaises(BaselineStoreError):
                self.approve()
        self.assertIs(self.reopen().get("candidate-1").status, P)
        self.assertEqual(self.counts(), (1, 0, 0, 0))

    def test_B08_failure_updating_current_rolls_back_decision_and_version(self):
        self.store.register(candidate("old"))
        self.approve("old")
        self.store.register(candidate("new"))
        before = self.store.history("page-1", "a" * 64)
        original_connect = self.store._connect
        def failed_connect(readonly):
            conn = original_connect(readonly)
            if not readonly:
                conn.set_authorizer(lambda action, table, *args: sqlite3.SQLITE_DENY
                                    if action == sqlite3.SQLITE_UPDATE and table == "baseline_heads"
                                    else sqlite3.SQLITE_OK)
            return conn
        with patch.object(self.store, "_connect", side_effect=failed_connect):
            with self.assertRaises(BaselineStoreError):
                self.approve("new", current=1)
        self.assertEqual(self.reopen().history("page-1", "a" * 64), before)
        self.assertIs(self.store.get("new").status, P)
        self.assertEqual(self.counts(), (2, 1, 1, 1))

    def test_B08_lost_readback_after_commit_is_ambiguous_retry_cannot_double_approve(self):
        pending = self.store.register(candidate())
        original_connect = self.store._connect
        def failed_readback(readonly):
            if readonly:
                raise BaselineStoreError("read connection unavailable after commit")
            return original_connect(readonly)
        with patch.object(self.store, "_connect", side_effect=failed_readback):
            with self.assertRaises(AmbiguousBaselineCommit):
                self.store.decide("candidate-1", decision=A, actor="alice", expected_revision=0,
                                  reviewed_digest=pending.registered_digest, expected_current_version=0)
        self.reopen()
        with self.assertRaises(AlreadyDecided):
            self.approve()
        self.assertEqual(self.counts(), (1, 1, 1, 1))

    def test_B09_saved_approval_remains_unattested_and_s2_boundary_refuses(self):
        c = candidate()
        self.store.register(c)
        self.approve()
        version = self.reopen().current(c.page_id, c.profile_fingerprint)
        self.assertEqual(version.profile_trust, "UNATTESTED")
        profile = UnattestedProfileFingerprint(c.profile_fingerprint)
        for use in TrustedS2Use:
            with self.assertRaises(UnattestedProfileError):
                profile.require_trusted_use(use)
        evidence = StructurallyCheckedCaptureEvidence(
            EvidenceOrigin("job-1", "attempt-1", 1, "d" * 64, "e" * 64,
                           "page-1", "profile-1", c.candidate_id),
            EvidenceFile("job-1/attempt-1/manifest.json", "f" * 64, 100),
            EvidenceArtifact(0, "CAPTURE_RECORD", "CAPTURE", EvidenceFile("job-1/attempt-1/record.bin", "c" * 64, 100)),
            EvidenceArtifact(1, "SCREENSHOT_PNG", "CAPTURE", EvidenceFile(c.artifact_ref, c.artifact_sha256, 100)), profile)
        result = evaluate_s1_evidence_boundary(EvidenceReadResult(evidence=evidence))
        self.assertIs(result.status, EligibilityStatus.UNKNOWN)
        self.assertIs(result.reason, AdapterRejectionReason.PROFILE_UNATTESTED)
        self.assertEqual(result.unknown_reasons[-1].value, "COMPARISON_NOT_RUN")

    def test_B10_unknown_id_and_missing_database_are_not_success(self):
        with self.assertRaises(UnknownCandidate):
            self.store.get("missing")
        with self.assertRaises(BaselineStoreError):
            SQLiteBaselineStore.open(self.root / "missing.sqlite", self.root)
        self.assertFalse((self.root / "missing.sqlite").exists())
        with self.assertRaises(BaselineStoreError):
            SQLiteBaselineStore.create(self.root / "missing-parent" / "new.sqlite", self.root)

    def test_B10_detects_missing_current_reference_on_reopen_without_repair(self):
        self.store.register(candidate())
        self.approve()
        trigger = next(sql for sql in baseline_schema.TRIGGERS if "baseline_heads_no_delete " in sql)
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute("DROP TRIGGER baseline_heads_no_delete")
            conn.execute("DELETE FROM baseline_heads")
            conn.execute(trigger)
        before = self.path.read_bytes()
        with self.assertRaises(BaselineStoreCorrupt):
            self.reopen()
        self.assertEqual(self.path.read_bytes(), before)

    def test_B10_immutable_tables_reject_direct_update_delete(self):
        self.store.register(candidate())
        self.approve()
        with closing(sqlite3.connect(self.path)) as conn, conn:
            for table in ("baseline_meta", "baseline_candidates", "baseline_decisions", "baseline_versions", "baseline_heads"):
                with self.subTest(table=table), self.assertRaises(sqlite3.IntegrityError):
                    conn.execute("DELETE FROM " + table)
                conn.rollback()
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE baseline_candidates SET artifact_ref='changed'")
        self.reopen()

    def test_existing_s1_database_is_not_extended_or_overwritten(self):
        old = self.root / "existing.sqlite"
        Repository(str(old)).init()
        before = old.read_bytes()
        with self.assertRaises(BaselineStoreError):
            SQLiteBaselineStore.create(old, self.root)
        with self.assertRaises(BaselineStoreCorrupt):
            SQLiteBaselineStore.open(old, self.root)
        self.assertEqual(old.read_bytes(), before)

    def test_same_database_compatible_with_unchanged_s1_repository(self):
        record = self.store.register(candidate())
        Repository(str(self.path)).init()
        self.assertEqual(self.reopen().get("candidate-1"), record)
        with closing(sqlite3.connect(self.path)) as conn, conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM jobs").fetchone()[0], 0)
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_read_page_lists_candidates_and_versions_in_bounded_snapshot(self):
        self.store.register(candidate("a"))
        self.approve("a")
        self.store.register(candidate("b"))
        self.approve("b", current=1)
        self.store.register(candidate("c"))
        before = self.path.read_bytes()
        page = self.store.read_page(limit=2)
        self.assertEqual([i.record.candidate.candidate_id for i in page.items], ["a", "b"])
        self.assertTrue(page.has_more)
        self.assertEqual(page.items[0].candidate_version, 1)
        self.assertEqual((page.items[0].current_version, page.items[0].current_candidate_id), (2, "b"))
        history = self.store.read_page(limit=1, offset=1, candidate_id="c", history=True)
        self.assertEqual(history.versions[0].version, 2)
        self.assertFalse(history.has_more)
        self.assertIsNone(history.items[0].candidate_version)
        self.assertEqual(self.path.read_bytes(), before)

    def test_read_page_refuses_invalid_limits_and_expired_deadline(self):
        for kwargs in ({"limit": 0}, {"limit": 101}, {"limit": True}, {"limit": 1, "offset": -1},
                       {"limit": 1, "offset": 10001}, {"limit": 1, "history": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.store.read_page(**kwargs)
        with self.assertRaises(BaselineStoreError):
            self.store.read_page(limit=1, deadline=time.monotonic() - 1)
        self.assertEqual(self.counts(), (0, 0, 0, 0))


if __name__ == "__main__":
    unittest.main()
