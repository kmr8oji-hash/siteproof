"""Pure in-memory approval tests; no I/O."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import unittest

from src.baseline.approval import (
    AlreadyDecided,
    ApprovalDecision,
    BaselineApprovalStore,
    BaselineRecord,
    CandidateTampered,
    DuplicateCandidate,
    InvalidDecision,
    MalformedRecord,
    RevisionConflict,
    UnknownCandidate,
    decide,
    register_candidate,
)
from src.baseline.model import BaselineCandidate, BaselineStatus, CandidateError

A, R, P = BaselineStatus.APPROVED, BaselineStatus.REJECTED, BaselineStatus.PENDING


def cand(**over):
    f = dict(candidate_id="c1", page_id="pg1", profile_fingerprint="a" * 64,
             artifact_ref="art/1.png", artifact_sha256="b" * 64)
    f.update(over)
    return BaselineCandidate(**f)


def approve(rec, **over):
    kw = dict(decision=A, actor="alice", expected_revision=rec.revision, reviewed_digest=rec.registered_digest)
    kw.update(over)
    return decide(rec, **kw)


class CandidateTests(unittest.TestCase):
    def test_fields_validated(self):
        for k, v in (("candidate_id", ""), ("page_id", None), ("artifact_ref", " x"),
                     ("profile_fingerprint", "A" * 64), ("artifact_sha256", "b" * 10)):
            with self.assertRaises(CandidateError, msg=k):
                cand(**{k: v})

    def test_immutable_and_digest_covers_all_fields(self):
        c = cand()
        with self.assertRaises(Exception):
            c.page_id = "x"
        for k, v in (("candidate_id", "c2"), ("page_id", "p2"), ("profile_fingerprint", "c" * 64),
                     ("artifact_ref", "z"), ("artifact_sha256", "d" * 64)):
            self.assertNotEqual(c.digest, replace(c, **{k: v}).digest, k)


class DecisionTests(unittest.TestCase):
    def test_new_candidate_is_pending_never_auto_approved(self):
        rec = register_candidate(cand())
        self.assertIs(rec.status, P)
        self.assertEqual(rec.revision, 0)
        self.assertIsNone(rec.decision)
        self.assertFalse(rec.is_valid_approval())

    def test_approve_and_reject(self):
        rec = register_candidate(cand())
        ok = approve(rec)
        self.assertIs(ok.status, A)
        self.assertEqual((ok.revision, ok.decision.actor), (1, "alice"))
        self.assertTrue(ok.is_valid_approval())
        self.assertIs(rec.status, P)  # original untouched
        no = approve(rec, decision=R)
        self.assertIs(no.status, R)
        self.assertFalse(no.is_valid_approval())

    def test_double_decision_rejected(self):
        done = approve(register_candidate(cand()))
        for d in (A, R):
            with self.assertRaises(AlreadyDecided):
                approve(done, decision=d, expected_revision=done.revision)

    def test_revision_conflict(self):
        rec = register_candidate(cand())
        for bad in (1, -1, "0", None, True, 0.0):
            with self.assertRaises(RevisionConflict, msg=bad):
                approve(rec, expected_revision=bad)

    def test_actor_required_and_not_automatic(self):
        rec = register_candidate(cand())
        for actor in ("", None, "  ", "system", "AUTO", "Bot", 5):
            with self.assertRaises(InvalidDecision, msg=actor):
                approve(rec, actor=actor)

    def test_decision_must_be_explicit_terminal(self):
        rec = register_candidate(cand())
        for d in (P, "APPROVED", None):
            with self.assertRaises(InvalidDecision):
                approve(rec, decision=d)

    def test_candidate_tampering_rejected(self):
        rec = register_candidate(cand())
        object.__setattr__(rec.candidate, "artifact_sha256", "e" * 64)  # in-place mutation
        with self.assertRaises(CandidateTampered):
            approve(rec)

    def test_swapped_candidate_rejected(self):
        rec = register_candidate(cand())
        swapped = replace(rec, candidate=cand(artifact_sha256="e" * 64))
        with self.assertRaises(CandidateTampered):
            approve(swapped)

    def test_reviewed_digest_must_match(self):
        rec = register_candidate(cand())
        for d in ("0" * 64, "", None):
            with self.assertRaises(CandidateTampered):
                approve(rec, reviewed_digest=d)

    def test_forged_approved_records_are_not_valid_approvals(self):
        c = cand()
        rec = register_candidate(c)
        self.assertFalse(replace(rec, status=A, revision=1).is_valid_approval())  # no decision
        ok = approve(rec)
        self.assertFalse(replace(ok, revision=2).is_valid_approval())
        self.assertFalse(replace(ok, registered_digest="0" * 64).is_valid_approval())
        bad = ApprovalDecision(A, "system", ok.registered_digest, 1)
        self.assertFalse(replace(ok, decision=bad).is_valid_approval())
        rej = approve(rec, decision=R)
        self.assertFalse(replace(rej, status=A).is_valid_approval())
        object.__setattr__(ok.candidate, "page_id", "other")
        self.assertFalse(ok.is_valid_approval())  # post-approval tamper

    def test_type_errors(self):
        with self.assertRaises(TypeError):
            register_candidate({"candidate_id": "c1"})
        with self.assertRaises(TypeError):
            decide("x", decision=A, actor="a", expected_revision=0, reviewed_digest="x")


class MalformedRecordTests(unittest.TestCase):
    """M1: corrupt internal state is rejected in a controlled way, never AttributeError/TypeError."""

    def pending(self):
        return register_candidate(cand())

    def corrupt_candidate(self, how):
        rec = self.pending()
        if how == "none":
            return replace(rec, candidate=None)
        if how == "dict":
            return replace(rec, candidate={"page_id": "pg1"})
        if how == "deleted":
            object.__delattr__(rec.candidate, "artifact_ref")
        elif how == "bad_type":
            object.__setattr__(rec.candidate, "page_id", None)
        elif how == "bad_hex":
            object.__setattr__(rec.candidate, "artifact_sha256", "XYZ")
        return rec

    def test_decide_rejects_corrupt_candidate(self):
        for how in ("none", "dict", "deleted", "bad_type", "bad_hex"):
            rec = self.corrupt_candidate(how)
            self.assertFalse(rec.is_well_formed(), how)
            with self.assertRaises(MalformedRecord, msg=how):
                approve(rec, reviewed_digest="0" * 64)

    def test_decide_rejects_bad_record_fields(self):
        rec = self.pending()
        for bad in (replace(rec, status="PENDING"), replace(rec, status=None),
                    replace(rec, revision=None), replace(rec, revision=-1),
                    replace(rec, revision=False), replace(rec, revision=0.0),
                    replace(rec, revision="0"), replace(rec, registered_digest=None),
                    replace(rec, registered_digest="g" * 64), replace(rec, decision="x"),
                    replace(rec, decision=ApprovalDecision(A, "alice", rec.registered_digest, 1))):
            self.assertFalse(bad.is_well_formed())
            with self.assertRaises(MalformedRecord):
                decide(bad, decision=A, actor="alice", expected_revision=0,
                       reviewed_digest=rec.registered_digest)

    def test_decide_input_types_raise_controlled_errors(self):
        rec = self.pending()
        for kw, exc in (({"expected_revision": -1}, RevisionConflict),
                        ({"expected_revision": False}, RevisionConflict),
                        ({"expected_revision": None}, RevisionConflict),
                        ({"expected_revision": 1.0}, RevisionConflict),
                        ({"actor": ["a"]}, InvalidDecision), ({"actor": "ＳＹＳＴＥＭ"}, InvalidDecision),
                        ({"decision": []}, InvalidDecision), ({"decision": {}}, InvalidDecision),
                        ({"reviewed_digest": []}, CandidateTampered),
                        ({"reviewed_digest": 5}, CandidateTampered)):
            with self.assertRaises(exc, msg=kw):
                approve(rec, **kw)

    def test_malformed_never_validates_as_approval(self):
        ok = approve(self.pending())
        d = ok.decision
        for bad in (replace(ok, candidate=None), replace(ok, revision=None), replace(ok, revision=True),
                    replace(ok, revision=-1), replace(ok, status="APPROVED"),
                    replace(ok, registered_digest=None), replace(ok, decision="x"),
                    replace(ok, decision=replace(d, revision=True)),
                    replace(ok, decision=replace(d, actor=None)),
                    replace(ok, decision=replace(d, status="APPROVED")),
                    replace(ok, decision=replace(d, candidate_digest=None))):
            self.assertFalse(bad.is_valid_approval())
        self.assertTrue(ok.is_valid_approval())

    def test_store_rejects_non_string_ids(self):
        s = BaselineApprovalStore()
        for bad in ([], {}, None, 1):
            with self.assertRaises(UnknownCandidate):
                s.get(bad)
            with self.assertRaises(UnknownCandidate):
                s.decide(bad, decision=A, actor="a", expected_revision=0, reviewed_digest="x")


class StoreTests(unittest.TestCase):
    def test_register_get_decide(self):
        s = BaselineApprovalStore()
        c = cand()
        rec = s.register(c)
        self.assertEqual(s.get("c1"), rec)
        out = s.decide("c1", decision=A, actor="bob", expected_revision=0, reviewed_digest=c.digest)
        self.assertEqual(s.get("c1"), out)
        with self.assertRaises(AlreadyDecided):
            s.decide("c1", decision=R, actor="bob", expected_revision=1, reviewed_digest=c.digest)

    def test_duplicate_and_unknown(self):
        s = BaselineApprovalStore()
        s.register(cand())
        with self.assertRaises(DuplicateCandidate):
            s.register(cand())
        with self.assertRaises(UnknownCandidate):
            s.get("nope")
        with self.assertRaises(UnknownCandidate):
            s.decide("nope", decision=A, actor="a", expected_revision=0, reviewed_digest="x")

    def test_failed_decision_leaves_record_pending(self):
        s = BaselineApprovalStore()
        c = cand()
        s.register(c)
        with self.assertRaises(RevisionConflict):
            s.decide("c1", decision=A, actor="a", expected_revision=9, reviewed_digest=c.digest)
        self.assertIs(s.get("c1").status, P)

    def test_concurrent_decisions_exactly_one_wins(self):
        s = BaselineApprovalStore()
        c = cand()
        s.register(c)

        def attempt(i):
            try:
                s.decide("c1", decision=A if i % 2 else R, actor=f"u{i}", expected_revision=0,
                         reviewed_digest=c.digest)
                return "ok"
            except (AlreadyDecided, RevisionConflict):
                return "lost"

        with ThreadPoolExecutor(16) as ex:
            results = list(ex.map(attempt, range(32)))
        self.assertEqual(results.count("ok"), 1)
        self.assertEqual(s.get("c1").revision, 1)


if __name__ == "__main__":
    unittest.main()
