"""Provenance UNKNOWN, simulation-only compatibility and explicit limits.

All SQLite data, including the rollback demonstration, is created by this test.
No historical Job, S1 DB, snapshot or evidence root is inspected or modified.
"""

from contextlib import closing
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from src.bridge.s1_s2_contract import ProfileTrust, TrustedS2Use, UnattestedProfileError
from src.bridge.s2_adapter import evaluate_s1_evidence_boundary
from src.comparison.decision import EligibilityStatus
from src.profile_context.sqlite_store import SQLiteContextStore
from src.profile_context.start_gate import StartDecision, StartStatus, request_simulated_start
from tests.profile_context.test_model import make_bundle


class ProvenanceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="siteproof-batch03-provenance-A-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "ledger.sqlite"
        self.store = SQLiteContextStore.create(self.db, self.root)
        self.entry = make_bundle()

    def request(self, **kwargs):
        return request_simulated_start(self.store, self.entry.spec, self.entry.context, **kwargs)

    def assert_unknown_boundaries(self, decision):
        self.assertIs(decision.intake_provenance_status, StartStatus.UNKNOWN)
        self.assertIs(decision.lease_fencing_status, StartStatus.UNKNOWN)
        self.assertIs(decision.trust, ProfileTrust.UNATTESTED)
        for operation in TrustedS2Use:
            with self.assertRaises(UnattestedProfileError):
                decision.require_trusted_use(operation)
        self.assertIs(evaluate_s1_evidence_boundary(decision).status, EligibilityStatus.UNKNOWN)

    def test_missing_legacy_context_remains_unknown_without_write(self):
        before = self.db.read_bytes()
        for spec, context in ((None, None), (self.entry.spec, None), (None, self.entry.context)):
            for strict in (False, True):
                decision = request_simulated_start(self.store, spec, context,
                                                   require_intake_provenance=strict)
                self.assertIs(decision.status, StartStatus.UNKNOWN)
                self.assert_unknown_boundaries(decision)
        self.assertEqual(self.db.read_bytes(), before)

    def test_coherent_posthoc_context_is_not_verified_new_intake(self):
        # make_bundle deliberately has a non-temporal, synthetic created_at.
        self.assertIn("not-an-order-proof", self.entry.snapshot.created_at)
        simulation = self.request()
        self.assertIs(simulation.status, StartStatus.AUTHORIZED_SIMULATION)
        self.assert_unknown_boundaries(simulation)
        strict = self.request(require_intake_provenance=True)
        self.assertIs(strict.status, StartStatus.UNKNOWN)
        self.assertEqual(strict.reason, "INTAKE_PROVENANCE_UNVERIFIED")
        self.assertIsNone(strict.decision_id)

    def test_provenance_requirement_never_calls_register_or_reserve(self):
        before = self.db.read_bytes()
        with patch.object(self.store, "register") as register, \
                patch.object(self.store, "reserve_simulated_start") as reserve:
            result = self.request(require_intake_provenance=True)
        register.assert_not_called()
        reserve.assert_not_called()
        self.assertIs(result.status, StartStatus.UNKNOWN)
        self.assertEqual(self.db.read_bytes(), before)

    def test_declared_policy_and_environment_do_not_prove_provenance(self):
        context = replace(self.entry.context, policy_ref="new-intake-verified-by-caller",
                          environment_ref="caller-claims-pre-capture")
        decision = request_simulated_start(self.store, self.entry.spec, context,
                                           require_intake_provenance=True)
        self.assertEqual(decision.reason, "INTAKE_PROVENANCE_UNVERIFIED")
        self.assert_unknown_boundaries(decision)

    def test_reopened_persistent_ledger_does_not_confer_intake_provenance(self):
        self.store.register(self.entry.spec, self.entry.context)
        self.store = SQLiteContextStore.open(self.db, self.root)
        decision = self.request(require_intake_provenance=True)
        self.assertIs(decision.status, StartStatus.UNKNOWN)
        self.assertIsNone(self.store.read(self.entry.context.context_id).decision_id)

    def test_strict_check_does_not_consume_simulation_attempt(self):
        self.assertIs(self.request(require_intake_provenance=True).status, StartStatus.UNKNOWN)
        self.assertIs(self.request().status, StartStatus.AUTHORIZED_SIMULATION)

    def test_non_boolean_provenance_flags_are_rejected_without_ledger_access(self):
        with patch.object(self.store, "register") as register:
            for flag in (None, 0, 1, "false", "true", [], object()):
                with self.subTest(flag=type(flag).__name__):
                    decision = self.request(require_intake_provenance=flag)
                    self.assertIs(decision.status, StartStatus.UNKNOWN)
                    self.assertEqual(decision.reason, "INVALID_INPUT")
        register.assert_not_called()

    def test_strict_requirement_cannot_be_satisfied_by_malformed_input(self):
        decision = request_simulated_start(self.store, {}, {}, require_intake_provenance=True)
        self.assertIs(decision.status, StartStatus.UNKNOWN)
        self.assert_unknown_boundaries(decision)

    def test_explicit_false_preserves_three_argument_simulation_contract(self):
        decision = self.request(require_intake_provenance=False)
        self.assertIs(decision.status, StartStatus.AUTHORIZED_SIMULATION)
        self.assertEqual(decision.reason, "OFFLINE_LEDGER_READBACK_ONLY")
        self.assertEqual(decision.context_sha256, self.entry.context.sha256)
        self.assertIsNotNone(decision.decision_id)
        self.assert_unknown_boundaries(decision)

    def test_authorized_and_rejected_decisions_have_unknown_boundaries(self):
        for decision in (self.request(), self.request()):
            self.assert_unknown_boundaries(decision)

    def test_caller_constructed_decision_never_conveys_profile_trust(self):
        decision = StartDecision(StartStatus.AUTHORIZED_SIMULATION, "caller-claimed",
                                 "a" * 64, "caller-decision")
        self.assert_unknown_boundaries(decision)

    def test_new_epoch_after_final_readback_demonstrates_no_continuing_fence(self):
        newer = make_bundle(attempt="attempt-2", epoch=2, nonce="nonce-2", context_id="context-2")
        original = self.store._readback

        def readback(spec, context, decision_id=None, *, check_decision=False):
            snapshot = original(spec, context, decision_id, check_decision=check_decision)
            if check_decision:
                SQLiteContextStore.open(self.db, self.root).register(newer.spec, newer.context)
            return snapshot

        with patch.object(self.store, "_readback", side_effect=readback):
            decision = self.request()
        self.assertIs(decision.status, StartStatus.AUTHORIZED_SIMULATION)
        self.assertIs(decision.lease_fencing_status, StartStatus.UNKNOWN)
        self.assertEqual(self.store.read("context-1").latest_epoch, 2)
        self.assertEqual(self.request().reason, "STALE_EPOCH")

    def test_fixture_whole_db_rollback_demonstrates_external_anchor_requirement(self):
        self.store.register(self.entry.spec, self.entry.context)
        backup = self.root / "own-fixture-before-reservation.sqlite"
        with closing(sqlite3.connect(self.db)) as source, closing(sqlite3.connect(backup)) as target:
            source.backup(target)
        first = self.request()
        self.assertIs(first.status, StartStatus.AUTHORIZED_SIMULATION)
        # Restore ONLY this newly generated test DB. No existing user DB involved.
        with closing(sqlite3.connect(backup)) as source, closing(sqlite3.connect(self.db)) as target:
            source.backup(target)
        self.store = SQLiteContextStore.open(self.db, self.root)
        second = self.request()
        self.assertIs(second.status, StartStatus.AUTHORIZED_SIMULATION)
        self.assertNotEqual(first.decision_id, second.decision_id)
        self.assert_unknown_boundaries(second)
        self.assertIs(self.request(require_intake_provenance=True).status, StartStatus.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
