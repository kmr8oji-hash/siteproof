"""Only fresh dedicated fixture databases; no existing S1 DB/evidence access."""

from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from src.profile_context import sqlite_store as module
from src.profile_context.sqlite_store import SQLiteContextStore, StoreError, StoreReason as R
from tests.profile_context.test_model import attributes, make_bundle


class _Fixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="siteproof-profile-start-gate-01-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "context-ledger.sqlite"
        self.store = SQLiteContextStore.create(self.db, self.root)
        self.e = make_bundle()

    def register(self, e=None):
        e = self.e if e is None else e
        return self.store.register(e.spec, e.context)

    def refused(self, reason, function, *args):
        with self.assertRaises(StoreError) as caught:
            function(*args)
        self.assertIs(caught.exception.reason, reason)

    def sql(self, statement, parameters=()):
        with closing(sqlite3.connect(self.db)) as conn:
            rows = conn.execute(statement, parameters).fetchall()
            conn.commit()
            return rows

    def retry(self, **over):
        return make_bundle(attempt=over.pop("attempt", "attempt-2"),
                           epoch=over.pop("epoch", 2), nonce=over.pop("nonce", "nonce-2"),
                           context_id=over.pop("context_id", "context-2"), **over)


class SQLiteStoreTests(_Fixture, unittest.TestCase):
    def test_new_store_is_dedicated_and_empty(self):
        self.assertEqual(self.sql("SELECT count(*) FROM contexts"), [(0,)])
        self.assertEqual(self.sql("PRAGMA application_id"), [(module._APP_ID,)])

    def test_registration_roundtrips_exact_canonical_models(self):
        result = self.register()
        self.assertTrue(result.created)
        self.assertEqual(result.record.spec.canonical_json(), self.e.spec.canonical_json())
        self.assertEqual(result.record.context.canonical_json(), self.e.context.canonical_json())
        self.assertIsNone(result.record.decision_id)

    def test_exact_registration_retry_is_idempotent(self):
        self.register()
        result = self.register()
        self.assertFalse(result.created)
        self.assertEqual(self.sql("SELECT count(*) FROM contexts"), [(1,)])

    def test_new_store_handle_reads_persistent_records(self):
        self.register()
        other = SQLiteContextStore.open(self.db, self.root)
        self.assertEqual(other.read(self.e.context.context_id).context, self.e.context)

    def test_simulated_start_has_one_persistent_reservation(self):
        self.register()
        decision = self.store.reserve_simulated_start(self.e.spec, self.e.context)
        record = SQLiteContextStore.open(self.db, self.root).read(self.e.context.context_id)
        self.assertEqual(record.decision_id, decision)
        self.assertEqual(record.latest_epoch, 1)

    def test_independent_connection_observes_both_commits_before_readback(self):
        real = self.store.read
        observed = []
        def read(cid):
            with closing(sqlite3.connect(self.db.as_uri() + "?mode=ro", uri=True)) as conn:
                observed.append((conn.execute("SELECT count(*) FROM contexts").fetchone()[0],
                                 conn.execute("SELECT count(*) FROM starts").fetchone()[0]))
            return real(cid)
        with patch.object(self.store, "read", side_effect=read):
            self.register()
            self.store.reserve_simulated_start(self.e.spec, self.e.context)
        self.assertEqual(observed, [(1, 0), (1, 1)])

    def test_retry_uses_new_attempt_epoch_nonce_context(self):
        self.register()
        b = self.retry()
        self.register(b)
        self.assertEqual(self.store.read(b.context.context_id).latest_epoch, 2)
        self.store.reserve_simulated_start(b.spec, b.context)

    def test_other_jobs_can_use_same_attempt_and_epoch_but_not_nonce(self):
        self.register()
        b = make_bundle(job="job-2", context_id="context-2", nonce="nonce-2")
        self.register(b)
        self.assertEqual(self.sql("SELECT count(*) FROM contexts"), [(2,)])

    def test_returned_records_are_immutable_defensive_snapshots(self):
        record = self.register().record
        with self.assertRaises(FrozenInstanceError):
            record.decision_id = "changed"
        with self.assertRaises(TypeError):
            record.spec.capture_attributes["locale"] = "changed"

    def test_schema_rejects_updates_and_deletes(self):
        self.register()
        self.store.reserve_simulated_start(self.e.spec, self.e.context)
        for table in ("specs", "contexts", "starts"):
            for statement in (f"DELETE FROM {table}", f"UPDATE {table} SET rowid=rowid"):
                with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                    self.sql(statement)

    def test_connections_are_closed_after_operations(self):
        self.register()
        self.store.read(self.e.context.context_id)
        renamed = self.root / "moved.sqlite"
        self.db.rename(renamed)  # Windows refuses this with a leaked SQLite handle.
        renamed.rename(self.db)

    def test_path_with_uri_metacharacters_remains_local(self):
        path = self.root / "a #percent%.sqlite"
        store = SQLiteContextStore.create(path, self.root)
        store.register(self.e.spec, self.e.context)
        self.assertTrue(path.exists())

    def test_concurrent_exact_registration_is_serialized_and_idempotent(self):
        stores = [SQLiteContextStore.open(self.db, self.root) for _ in range(2)]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda s: s.register(self.e.spec, self.e.context), stores))
        self.assertEqual(sorted(r.created for r in results), [False, True])
        self.assertEqual(self.sql("SELECT count(*) FROM contexts"), [(1,)])


class SQLiteStoreRejectionTests(_Fixture, unittest.TestCase):
    def test_create_never_overwrites_existing_database(self):
        before = self.db.read_bytes()
        self.refused(R.ALREADY_EXISTS, SQLiteContextStore.create, self.db, self.root)
        self.assertEqual(self.db.read_bytes(), before)

    def test_missing_database_is_not_created_by_open(self):
        path = self.root / "absent.sqlite"
        self.refused(R.UNAVAILABLE, SQLiteContextStore.open, path, self.root)
        self.assertFalse(path.exists())

    def test_existing_nonledger_database_is_not_migrated(self):
        path = self.root / "synthetic-unrelated.sqlite"
        with closing(sqlite3.connect(path)) as conn:
            conn.execute("CREATE TABLE jobs(x)"); conn.commit()
        before = path.read_bytes()
        self.refused(R.CORRUPT, SQLiteContextStore.open, path, self.root)
        self.assertEqual(path.read_bytes(), before)

    def test_relative_escape_and_root_itself_are_rejected(self):
        for path in (Path("relative.sqlite"), self.root, self.root / ".." / "escape.sqlite"):
            with self.subTest(path=path):
                self.refused(R.PATH_REJECTED, SQLiteContextStore.create, path, self.root)

    def test_path_outside_dedicated_root_is_rejected(self):
        inner = self.root / "dedicated"; inner.mkdir()
        self.refused(R.PATH_REJECTED, SQLiteContextStore.open, self.db, inner)

    def test_hardlinked_database_is_rejected(self):
        alias = self.root / "alias.sqlite"
        os.link(self.db, alias)
        self.refused(R.PATH_REJECTED, SQLiteContextStore.open, alias, self.root)

    def test_hardlinked_sidecar_is_rejected_without_modifying_its_target(self):
        protected = self.root / "protected.bin"; protected.write_bytes(b"fixture-only")
        os.link(protected, Path(str(self.db) + "-journal"))
        self.refused(R.PATH_REJECTED, self.store.read, "context-1")
        self.assertEqual(protected.read_bytes(), b"fixture-only")

    def test_windows_stream_device_and_trailing_alias_paths_are_rejected(self):
        for name in ("ledger.sqlite:stream", "NUL.sqlite", "trailing.sqlite.", "trailing.sqlite "):
            with self.subTest(name=name):
                self.refused(R.PATH_REJECTED, SQLiteContextStore.create, self.root / name, self.root)

    def test_reparse_path_metadata_is_rejected_without_host_changes(self):
        real = Path.lstat
        class Reparse:
            st_mode = 0
            st_file_attributes = 0x400
        with patch.object(Path, "lstat", side_effect=lambda *a, **k: Reparse(), autospec=True):
            self.refused(R.PATH_REJECTED, SQLiteContextStore.open, self.db, self.root)
        self.assertIsNotNone(real)

    def test_removed_database_is_not_recreated(self):
        self.db.rename(self.root / "preserved.sqlite")
        self.refused(R.UNAVAILABLE, self.store.read, "context-1")
        self.assertFalse(self.db.exists())

    def test_replaced_database_is_rejected_by_old_handle(self):
        self.db.rename(self.root / "preserved.sqlite")
        SQLiteContextStore.create(self.db, self.root)
        self.refused(R.PATH_REJECTED, self.store.read, "context-1")

    def test_missing_context_is_unknown(self):
        self.refused(R.MISSING, self.store.read, "missing")
        self.refused(R.MISSING, self.store.reserve_simulated_start, self.e.spec, self.e.context)

    def test_changed_context_cannot_overwrite_registration(self):
        self.register()
        changed = replace(self.e.context, environment_ref="changed")
        self.refused(R.CONFLICT, self.store.register, self.e.spec, changed)
        self.assertEqual(self.store.read("context-1").context, self.e.context)

    def test_same_job_cannot_replace_profile(self):
        self.register()
        b = self.retry(attrs=attributes(viewport_width=800))
        self.refused(R.CONFLICT, self.register, b)

    def test_mismatched_spec_reference_is_not_persisted(self):
        other = make_bundle(attrs=attributes(viewport_width=800))
        self.refused(R.CONFLICT, self.store.register, other.spec, self.e.context)
        self.assertEqual(self.sql("SELECT count(*) FROM specs"), [(0,)])

    def test_duplicate_attempt_rejected_across_handles(self):
        self.register()
        b = self.retry(attempt="attempt-1")
        other = SQLiteContextStore.open(self.db, self.root)
        self.refused(R.CONFLICT, other.register, b.spec, b.context)

    def test_duplicate_and_older_epochs_rejected(self):
        self.register(self.retry(epoch=3))
        for epoch in (1, 2, 3):
            b = make_bundle(attempt="other", epoch=epoch, nonce="other", context_id="other")
            with self.subTest(epoch=epoch):
                self.refused(R.STALE_EPOCH, self.register, b)

    def test_nonce_reuse_across_jobs_rejected_and_partial_job_insert_rolled_back(self):
        self.register()
        b = make_bundle(job="job-2", context_id="context-2")
        self.refused(R.CONFLICT, self.register, b)
        self.assertEqual(self.sql("SELECT count(*) FROM specs"), [(1,)])

    def test_reserved_start_never_regranted_even_after_reopen(self):
        self.register()
        self.store.reserve_simulated_start(self.e.spec, self.e.context)
        other = SQLiteContextStore.open(self.db, self.root)
        self.assertFalse(other.register(self.e.spec, self.e.context).created)
        self.refused(R.START_ALREADY_RESERVED, other.reserve_simulated_start,
                     self.e.spec, self.e.context)

    def test_registered_old_attempt_cannot_start_after_retry_registered(self):
        self.register(); self.register(self.retry())
        self.assertFalse(self.register().created)
        self.refused(R.STALE_EPOCH, self.store.reserve_simulated_start, self.e.spec, self.e.context)

    def test_dropped_schema_guard_is_rejected(self):
        self.sql("DROP TRIGGER contexts_no_update")
        self.refused(R.CORRUPT, self.store.read, "context-1")

    def test_unknown_table_or_schema_version_is_rejected(self):
        self.sql("PRAGMA user_version=99")
        self.refused(R.CORRUPT, SQLiteContextStore.open, self.db, self.root)

    def test_extra_table_is_not_accepted_as_a_migration(self):
        self.sql("CREATE TABLE unknown(x)")
        self.refused(R.CORRUPT, self.register)

    def test_sqlite_lookalike_name_cannot_hide_an_extra_schema_object(self):
        self.sql("CREATE TABLE sqliteXhidden(x)")
        self.refused(R.CORRUPT, self.register)

    def test_audit_uses_one_snapshot_and_full_index_integrity_check(self):
        with closing(sqlite3.connect(self.db, isolation_level=None)) as conn:
            statements = []
            conn.set_trace_callback(statements.append)
            self.store._audit(conn)
        self.assertEqual(statements[0], "BEGIN")
        self.assertEqual(statements[-1], "ROLLBACK")
        self.assertIn("PRAGMA integrity_check", statements)

    def test_changed_canonical_payload_is_rejected_even_with_guards_restored(self):
        self.register()
        self.sql("DROP TRIGGER contexts_no_update")
        self.sql("UPDATE contexts SET context_json=context_json || ' '")
        self.sql(next(s for s in module._TRIGGERS if s.startswith("CREATE TRIGGER contexts_no_update")))
        self.refused(R.CORRUPT, self.store.read, "context-1")

    def test_changed_redundant_hash_is_rejected(self):
        self.register()
        self.sql("DROP TRIGGER contexts_no_update")
        self.sql("UPDATE contexts SET context_sha=?", ("0" * 64,))
        self.sql(next(s for s in module._TRIGGERS if s.startswith("CREATE TRIGGER contexts_no_update")))
        self.refused(R.CORRUPT, self.store.read, "context-1")

    def test_corrupt_unrelated_record_blocks_new_registration(self):
        self.register()
        self.sql("DROP TRIGGER specs_no_update")
        self.sql("UPDATE specs SET spec_json='{}'")
        self.sql(next(s for s in module._TRIGGERS if s.startswith("CREATE TRIGGER specs_no_update")))
        self.refused(R.CORRUPT, self.register, self.retry())

    def test_missing_or_changed_start_readback_is_ambiguous(self):
        self.register()
        real = self.store.read
        for mode in ("missing", "changed"):
            # Only the first reservation can commit; test each on its own retry.
            e = self.retry(epoch=2 if mode == "missing" else 3,
                           context_id=mode, attempt=mode, nonce=mode)
            self.register(e)
            def read(cid):
                if mode == "missing":
                    raise StoreError(R.MISSING)
                return replace(real(cid), decision_id="changed")
            with patch.object(self.store, "read", side_effect=read):
                self.refused(R.AMBIGUOUS_COMMIT_OR_READBACK,
                             self.store.reserve_simulated_start, e.spec, e.context)
            self.refused(R.START_ALREADY_RESERVED, self.store.reserve_simulated_start,
                         e.spec, e.context)

    def test_commit_success_then_lost_reply_consumes_start_fail_closed(self):
        self.register()
        real = self.store._connect
        class LostCommitReply:
            def __init__(self, conn): self.conn = conn
            def __getattr__(self, name): return getattr(self.conn, name)
            def commit(self):
                self.conn.commit()
                raise OSError("synthetic lost reply after commit")
        def connect(readonly, **kw):
            conn = real(readonly, **kw)
            return conn if readonly else LostCommitReply(conn)
        with patch.object(self.store, "_connect", side_effect=connect):
            self.refused(R.AMBIGUOUS_COMMIT_OR_READBACK,
                         self.store.reserve_simulated_start, self.e.spec, self.e.context)
        self.assertIsNotNone(self.store.read("context-1").decision_id)
        self.refused(R.START_ALREADY_RESERVED, self.store.reserve_simulated_start,
                     self.e.spec, self.e.context)

    def test_new_epoch_before_final_readback_consumes_old_start_without_authorizing(self):
        self.register()
        real = self.store.read
        def read(cid):
            b = self.retry()
            other = SQLiteContextStore.open(self.db, self.root)
            other.register(b.spec, b.context)
            return real(cid)
        with patch.object(self.store, "read", side_effect=read):
            self.refused(R.AMBIGUOUS_COMMIT_OR_READBACK,
                         self.store.reserve_simulated_start, self.e.spec, self.e.context)
        self.assertIsNotNone(real("context-1").decision_id)

    def test_locked_store_fails_closed_and_does_not_add_a_record(self):
        with closing(sqlite3.connect(self.db, isolation_level=None)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            self.refused(R.UNAVAILABLE, self.register)
            conn.rollback()
        self.assertEqual(self.sql("SELECT count(*) FROM contexts"), [(0,)])

    def test_corrupt_model_state_and_bool_epoch_are_rejected_before_db_write(self):
        for field, value in (("schema_version", "unknown"), ("lease_epoch", True),
                             ("nonce", None), ("trusted", True)):
            e = make_bundle(); object.__setattr__(e.context, field, value)
            with self.subTest(field=field):
                self.refused(R.INVALID_INPUT, self.store.register, e.spec, e.context)
        self.assertEqual(self.sql("SELECT count(*) FROM contexts"), [(0,)])

    def test_nonmodel_and_subclass_inputs_are_rejected(self):
        self.refused(R.INVALID_INPUT, self.store.register, {}, {})
        self.refused(R.INVALID_INPUT, self.store.read, True)
