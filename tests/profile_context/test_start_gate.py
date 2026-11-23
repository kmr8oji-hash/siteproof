"""Simulated start decisions are never capture attestations or quality PASS."""

from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
import sqlite3
import unittest
from unittest.mock import patch

from src.bridge.s1_s2_contract import ProfileTrust, TrustedS2Use, UnattestedProfileError
from src.bridge.s2_adapter import evaluate_s1_evidence_boundary
from src.comparison.decision import EligibilityStatus
from src.profile_context.start_gate import StartStatus as S, request_simulated_start
from src.profile_context.sqlite_store import SQLiteContextStore, StoreError, StoreReason as R
from tests.profile_context.test_sqlite_store import _Fixture


class StartGateTests(_Fixture, unittest.TestCase):
    def start(self, e=None):
        e = self.e if e is None else e
        return request_simulated_start(self.store, e.spec, e.context)

    def test_start_only_after_persistent_registration_and_readback(self):
        result = self.start()
        self.assertIs(result.status, S.AUTHORIZED_SIMULATION)
        self.assertEqual(result.context_sha256, self.e.context.sha256)
        with closing(sqlite3.connect(self.db.as_uri() + "?mode=ro", uri=True)) as conn:
            self.assertEqual(conn.execute("SELECT decision_id FROM starts").fetchone()[0], result.decision_id)

    def test_prior_exact_registration_is_safe_but_start_is_one_shot(self):
        self.register()
        self.assertIs(self.start().status, S.AUTHORIZED_SIMULATION)
        result = self.start()
        self.assertIs(result.status, S.UNKNOWN)
        self.assertEqual(result.reason, R.START_ALREADY_RESERVED.value)
        self.assertIsNone(result.decision_id)

    def test_concurrent_start_requests_grant_exactly_one_simulation(self):
        stores = [SQLiteContextStore.open(self.db, self.root) for _ in range(2)]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda store: request_simulated_start(
                store, self.e.spec, self.e.context), stores))
        self.assertEqual(sum(r.status is S.AUTHORIZED_SIMULATION for r in results), 1)
        self.assertEqual(sum(r.status is S.UNKNOWN for r in results), 1)
        self.assertEqual(self.sql("SELECT count(*) FROM starts"), [(1,)])

    def test_retry_with_fresh_attempt_epoch_nonce_is_distinct(self):
        self.start()
        result = self.start(self.retry())
        self.assertIs(result.status, S.AUTHORIZED_SIMULATION)

    def test_old_registered_attempt_is_unknown_after_new_epoch(self):
        self.register(); self.register(self.retry())
        result = self.start()
        self.assertIs(result.status, S.UNKNOWN)
        self.assertEqual(result.reason, R.STALE_EPOCH.value)

    def test_legacy_jobs_without_records_never_get_backfilled_or_trusted(self):
        for spec, ctx in ((None, None), (self.e.spec, None), (None, self.e.context)):
            result = request_simulated_start(self.store, spec, ctx)
            self.assertIs(result.status, S.UNKNOWN)
            self.assertIs(result.trust, ProfileTrust.UNATTESTED)
        self.assertEqual(self.sql("SELECT count(*) FROM specs"), [(0,)])

    def test_invalid_store_or_models_cannot_authorize(self):
        for store, spec, ctx in ((object(), self.e.spec, self.e.context), (self.store, {}, {})):
            self.assertIs(request_simulated_start(store, spec, ctx).status, S.UNKNOWN)

    def test_no_authorization_when_registration_readback_is_lost(self):
        with patch.object(self.store, "read", side_effect=StoreError(R.MISSING)):
            result = self.start()
        self.assertIs(result.status, S.UNKNOWN)
        self.assertEqual(self.sql("SELECT count(*) FROM starts"), [(0,)])
        # Registration is safely idempotent; no start had been reserved.
        self.assertIs(self.start().status, S.AUTHORIZED_SIMULATION)

    def test_no_regrant_when_start_readback_reply_is_lost(self):
        real = self.store.read
        def read(cid):
            result = real(cid)
            if result.decision_id is not None:
                raise OSError("synthetic lost start reply")
            return result
        with patch.object(self.store, "read", side_effect=read):
            self.assertIs(self.start().status, S.UNKNOWN)
        self.assertEqual(self.start().reason, R.START_ALREADY_RESERVED.value)

    def test_no_authorization_when_records_changed_or_corrupt(self):
        self.register()
        changed = replace(self.e.context, policy_ref="changed")
        result = request_simulated_start(self.store, self.e.spec, changed)
        self.assertIs(result.status, S.UNKNOWN)
        self.assertEqual(result.reason, R.CONFLICT.value)

    def test_internal_errors_are_unknown_without_a_quality_path(self):
        for error in (RuntimeError("synthetic"), StoreError(R.CORRUPT)):
            with patch.object(self.store, "register", side_effect=error):
                result = self.start()
                self.assertIs(result.status, S.UNKNOWN)
                self.assertIsNone(result.decision_id)

    def test_decisions_remain_unattested_and_cannot_enter_trusted_s2(self):
        for result in (self.start(), self.start()):
            self.assertIs(result.trust, ProfileTrust.UNATTESTED)
            for operation in TrustedS2Use:
                with self.assertRaises(UnattestedProfileError):
                    result.require_trusted_use(operation)
            self.assertIs(evaluate_s1_evidence_boundary(result).status, EligibilityStatus.UNKNOWN)
            self.assertFalse(hasattr(result, "eligible"))
            self.assertFalse(hasattr(result, "quality"))

    def test_no_browser_s1_storage_or_baseline_execution(self):
        from src.storage.repository import Repository
        from src.baseline import approval
        def forbidden(*a, **k): raise AssertionError("outside offline slice")
        with patch.object(Repository, "commit_completed", forbidden), \
                patch.object(approval, "register_candidate", forbidden), \
                patch("subprocess.Popen", forbidden), patch("socket.socket", forbidden):
            self.assertIs(self.start().status, S.AUTHORIZED_SIMULATION)

    def test_decision_is_frozen_but_not_an_authenticated_credential(self):
        result = self.start()
        with self.assertRaises(FrozenInstanceError):
            result.trust = "TRUSTED"
        self.assertEqual(result.reason, "OFFLINE_LEDGER_READBACK_ONLY")
