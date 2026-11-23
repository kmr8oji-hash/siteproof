"""Dedicated offline ledger, never an S1 database or a capture trust source.

Registration is idempotent only for byte-identical canonical records. Start
reservation is one-shot: a lost reply after commit cannot be retried into a new
permission. Each successful write is checked through a NEW read-only connection.
This protects honest cooperating callers in this ledger, not an administrator
who replaces/rolls back the entire database, a compromised host, or a browser.
SQLite FULL synchronous commits are not a proof against every hardware failure.
No application-level migration, recovery, deletion, execution or production
integration is provided.

Process termination is handled by SQLite's ordinary transaction recovery on a
subsequent writable connection, never by deleting/reinitializing a database.
Durable reservations survive restart; callers must not interpret a lost reply
as permission to repeat a start. Registration alone carries no intake provenance.
There is no external monotonic anchor: a coherent whole-ledger rollback can
resurrect a previously consumed reservation and is outside this ledger's claims.
"""

from contextlib import closing, contextmanager
from dataclasses import dataclass
from enum import Enum
import json
import os
from pathlib import Path
import sqlite3
import stat
from uuid import uuid4

from .model import CaptureContext, JobProfileSpec, ModelError, _id, checked_copy


class StoreReason(str, Enum):
    INVALID_INPUT = "INVALID_INPUT"
    PATH_REJECTED = "PATH_REJECTED"
    ALREADY_EXISTS = "ALREADY_EXISTS"
    UNAVAILABLE = "UNAVAILABLE"
    CORRUPT = "CORRUPT"
    MISSING = "MISSING"
    CONFLICT = "CONFLICT"
    STALE_EPOCH = "STALE_EPOCH"
    START_ALREADY_RESERVED = "START_ALREADY_RESERVED"
    AMBIGUOUS_COMMIT_OR_READBACK = "AMBIGUOUS_COMMIT_OR_READBACK"


class StoreError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason.value)


_APP_ID = 0x53504331
_SCHEMA_VERSION = 1
_TABLES = (
    "CREATE TABLE specs(job_id TEXT PRIMARY KEY NOT NULL, spec_sha TEXT NOT NULL UNIQUE, spec_json TEXT NOT NULL)",
    "CREATE TABLE contexts(context_id TEXT PRIMARY KEY NOT NULL, job_id TEXT NOT NULL REFERENCES specs(job_id), attempt_id TEXT NOT NULL, lease_epoch INTEGER NOT NULL CHECK(typeof(lease_epoch)='integer' AND lease_epoch>0), nonce TEXT NOT NULL UNIQUE, context_sha TEXT NOT NULL UNIQUE, context_json TEXT NOT NULL, UNIQUE(job_id,attempt_id), UNIQUE(job_id,lease_epoch))",
    "CREATE TABLE starts(context_id TEXT PRIMARY KEY NOT NULL REFERENCES contexts(context_id), context_sha TEXT NOT NULL, decision_id TEXT NOT NULL UNIQUE)",
)
_TRIGGERS = tuple(
    f"CREATE TRIGGER {table}_no_{op.lower()} BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT,'append_only'); END"
    for table in ("specs", "contexts", "starts") for op in ("UPDATE", "DELETE")
)
_EXPECTED_SQL = set(_TABLES + _TRIGGERS)


def _need(ok, reason):
    if not ok:
        raise StoreError(reason)


def _pair(spec, context):
    try:
        _need(type(spec) is JobProfileSpec and type(context) is CaptureContext,
              StoreReason.INVALID_INPUT)
        spec, context = checked_copy(spec), checked_copy(context)
        _need((context.job_id, context.spec_ref, context.spec_sha256) ==
              (spec.job_id, spec.reference, spec.sha256), StoreReason.CONFLICT)
        return spec, context
    except ModelError:
        raise StoreError(StoreReason.INVALID_INPUT) from None


def _no_alias(path):
    for part in (path, *path.parents):
        if part.exists() or part.is_symlink():
            s = part.lstat()
            _need(not stat.S_ISLNK(s.st_mode) and not
                  (getattr(s, "st_file_attributes", 0) &
                   getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)), StoreReason.PATH_REJECTED)


def _location(path, fixture_root):
    try:
        path, root = Path(path), Path(fixture_root)
        _need(path.is_absolute() and root.is_absolute(), StoreReason.PATH_REJECTED)
        _need(not path.drive.startswith("\\\\") and not root.drive.startswith("\\\\"),
              StoreReason.PATH_REJECTED)  # No UNC/network database namespace.
        _need(".." not in path.parts and ".." not in root.parts, StoreReason.PATH_REJECTED)
        for part in path.parts[1:]:
            _need(":" not in part and part == part.rstrip(". ") and
                  part.split(".")[0].upper() not in
                  {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                   *(f"LPT{i}" for i in range(1, 10))}, StoreReason.PATH_REJECTED)
        _no_alias(path); _no_alias(root)
        _need(root.is_dir(), StoreReason.PATH_REJECTED)
        path, root = path.resolve(), root.resolve()
        _need(path != root and path.is_relative_to(root) and path.parent.is_dir(),
              StoreReason.PATH_REJECTED)
        return path, root
    except (TypeError, OSError, RuntimeError):
        raise StoreError(StoreReason.PATH_REJECTED) from None


def _decode(raw, cls):
    _need(type(raw) is str, StoreReason.CORRUPT)
    try:
        obj = cls(**json.loads(raw))
        _need(obj.canonical_json() == raw, StoreReason.CORRUPT)
        return obj
    except (TypeError, ValueError, KeyError):
        raise StoreError(StoreReason.CORRUPT) from None


@dataclass(frozen=True)
class StoredContext:
    spec: JobProfileSpec
    context: CaptureContext
    decision_id: str | None
    latest_epoch: int


@dataclass(frozen=True)
class Registration:
    created: bool
    record: StoredContext


class SQLiteContextStore:
    """Use create() only on a new dedicated fixture path; open() never creates.

    The explicit fixture_root is a caller-owned namespace, not an authorization
    boundary against a malicious caller. A path is pinned to a file identity for
    this handle's lifetime. Coherent offline forgeries remain UNATTESTED.
    """

    def __init__(self, path, fixture_root):
        self.path, self.fixture_root = _location(path, fixture_root)
        try:
            self._identity = self._file_identity()
        except OSError:
            raise StoreError(StoreReason.UNAVAILABLE) from None

    def _file_identity(self):
        _no_alias(self.path)
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            try:
                s = sidecar.lstat()
            except FileNotFoundError:
                continue  # A cooperating SQLite writer can remove a journal.
            _need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and not
                  (getattr(s, "st_file_attributes", 0) &
                   getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)), StoreReason.PATH_REJECTED)
        s = self.path.stat()
        _need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, StoreReason.PATH_REJECTED)
        return s.st_dev, s.st_ino

    @classmethod
    def create(cls, path, fixture_root):
        path, root = _location(path, fixture_root)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        except FileExistsError:
            raise StoreError(StoreReason.ALREADY_EXISTS) from None
        except OSError:
            raise StoreError(StoreReason.UNAVAILABLE) from None
        store = cls(path, root)
        try:
            with closing(store._connect(False, initializing=True)) as conn:
                conn.execute("BEGIN IMMEDIATE")
                for statement in _TABLES + _TRIGGERS:
                    conn.execute(statement)
                conn.execute(f"PRAGMA application_id={_APP_ID}")
                conn.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
                conn.commit()
            # Initialization also requires a new connection readback.
            with closing(store._connect(True)) as conn:
                store._audit(conn)
            return store
        except Exception:
            # Leave any partial database in place; never silently recreate it.
            raise StoreError(StoreReason.AMBIGUOUS_COMMIT_OR_READBACK) from None

    @classmethod
    def open(cls, path, fixture_root):
        store = cls(path, fixture_root)
        with closing(store._connect(True)) as conn:
            store._audit(conn)
        return store

    def _connect(self, readonly, *, initializing=False):
        conn = None
        try:
            _need(self._file_identity() == self._identity, StoreReason.PATH_REJECTED)
            conn = sqlite3.connect(self.path.as_uri() + ("?mode=ro" if readonly else "?mode=rw"),
                                   uri=True, timeout=0.25, isolation_level=None)
            _need(self._file_identity() == self._identity, StoreReason.PATH_REJECTED)
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("PRAGMA foreign_keys=ON")
            if not readonly:
                conn.execute("PRAGMA synchronous=FULL")
            if not initializing:
                self._audit(conn)
            return conn
        except StoreError:
            if conn is not None:
                conn.close()
            raise
        except (sqlite3.Error, OSError):
            if conn is not None:
                conn.close()
            raise StoreError(StoreReason.UNAVAILABLE) from None

    def _audit(self, conn):
        # Every multi-query audit observes one database snapshot, including the
        # initial connection check when no writer transaction has begun yet.
        own_transaction = not conn.in_transaction
        if own_transaction:
            conn.execute("BEGIN")
        try:
            self._audit_contents(conn)
        finally:
            if own_transaction and conn.in_transaction:
                conn.rollback()

    def _audit_contents(self, conn):
        try:
            _need(conn.execute("PRAGMA application_id").fetchone()[0] == _APP_ID and
                  conn.execute("PRAGMA user_version").fetchone()[0] == _SCHEMA_VERSION,
                  StoreReason.CORRUPT)
            actual = conn.execute("SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL").fetchall()
            _need(len(actual) == len(_EXPECTED_SQL) and {r[0] for r in actual} == _EXPECTED_SQL,
                  StoreReason.CORRUPT)
            _need(conn.execute("PRAGMA integrity_check").fetchall() == [("ok",)] and
                  not conn.execute("PRAGMA foreign_key_check").fetchall(), StoreReason.CORRUPT)
            specs, contexts = {}, {}
            for job, digest, raw in conn.execute("SELECT job_id,spec_sha,spec_json FROM specs"):
                spec = _decode(raw, JobProfileSpec)
                _need((job, digest) == (spec.job_id, spec.sha256), StoreReason.CORRUPT)
                specs[job] = spec
            for row in conn.execute("SELECT context_id,job_id,attempt_id,lease_epoch,nonce,context_sha,context_json FROM contexts"):
                cid, job, attempt, epoch, nonce, digest, raw = row
                context = _decode(raw, CaptureContext)
                _need(job in specs, StoreReason.CORRUPT)
                _pair(specs[job], context)
                _need((cid, job, attempt, epoch, nonce, digest) ==
                      (context.context_id, context.job_id, context.attempt_id,
                       context.lease_epoch, context.nonce, context.sha256), StoreReason.CORRUPT)
                contexts[cid] = context
            for cid, digest, decision in conn.execute("SELECT context_id,context_sha,decision_id FROM starts"):
                _id(decision, "decision_id")
                _need(cid in contexts and contexts[cid].sha256 == digest, StoreReason.CORRUPT)
        except (sqlite3.Error, TypeError, ValueError, KeyError):
            raise StoreError(StoreReason.CORRUPT) from None

    @contextmanager
    def _transaction(self):
        with closing(self._connect(False)) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                self._audit(conn)
                yield conn
            except StoreError:
                if conn.in_transaction:
                    conn.rollback()
                raise
            except sqlite3.IntegrityError:
                if conn.in_transaction:
                    conn.rollback()
                raise StoreError(StoreReason.CONFLICT) from None
            except Exception:
                if conn.in_transaction:
                    conn.rollback()
                raise StoreError(StoreReason.UNAVAILABLE) from None
            else:
                try:
                    conn.commit()
                    _need(self._file_identity() == self._identity, StoreReason.PATH_REJECTED)
                except Exception:
                    raise StoreError(StoreReason.AMBIGUOUS_COMMIT_OR_READBACK) from None

    def read(self, context_id):
        try:
            _id(context_id, "context_id")
        except ModelError:
            raise StoreError(StoreReason.INVALID_INPUT) from None
        with closing(self._connect(True)) as conn:
            # A single read transaction sees all referenced records together.
            conn.execute("BEGIN")
            self._audit(conn)
            row = conn.execute("SELECT s.spec_json,c.context_json,t.decision_id FROM contexts c JOIN specs s ON s.job_id=c.job_id LEFT JOIN starts t ON t.context_id=c.context_id WHERE c.context_id=?", (context_id,)).fetchone()
            _need(row is not None, StoreReason.MISSING)
            context = _decode(row[1], CaptureContext)
            latest = conn.execute("SELECT max(lease_epoch) FROM contexts WHERE job_id=?", (context.job_id,)).fetchone()[0]
            _need(self._file_identity() == self._identity, StoreReason.PATH_REJECTED)
            return StoredContext(_decode(row[0], JobProfileSpec), context, row[2], latest)

    def _readback(self, spec, context, decision_id=None, *, check_decision=False):
        try:
            result = self.read(context.context_id)
            _need(result.spec.canonical_json() == spec.canonical_json() and
                  result.context.canonical_json() == context.canonical_json(), StoreReason.CORRUPT)
            if check_decision:
                _need(result.decision_id == decision_id and
                      result.latest_epoch == context.lease_epoch, StoreReason.CORRUPT)
            return result
        except Exception:
            raise StoreError(StoreReason.AMBIGUOUS_COMMIT_OR_READBACK) from None

    def register(self, spec, context):
        spec, context = _pair(spec, context)
        created = False
        with self._transaction() as conn:
            previous = conn.execute("SELECT spec_json FROM specs WHERE job_id=?", (spec.job_id,)).fetchone()
            if previous is None:
                conn.execute("INSERT INTO specs VALUES(?,?,?)", (spec.job_id, spec.sha256, spec.canonical_json()))
            else:
                _need(previous[0] == spec.canonical_json(), StoreReason.CONFLICT)
            previous = conn.execute("SELECT context_json FROM contexts WHERE context_id=?", (context.context_id,)).fetchone()
            if previous is not None:
                _need(previous[0] == context.canonical_json(), StoreReason.CONFLICT)
            else:
                maximum = conn.execute("SELECT max(lease_epoch) FROM contexts WHERE job_id=?", (context.job_id,)).fetchone()[0]
                _need(maximum is None or context.lease_epoch > maximum, StoreReason.STALE_EPOCH)
                conn.execute("INSERT INTO contexts VALUES(?,?,?,?,?,?,?)", (context.context_id, context.job_id, context.attempt_id, context.lease_epoch, context.nonce, context.sha256, context.canonical_json()))
                created = True
        return Registration(created, self._readback(spec, context))

    def reserve_simulated_start(self, spec, context):
        spec, context = _pair(spec, context)
        decision_id = uuid4().hex  # Correlation only, never an execution credential.
        with self._transaction() as conn:
            row = conn.execute("SELECT context_json FROM contexts WHERE context_id=?", (context.context_id,)).fetchone()
            _need(row is not None, StoreReason.MISSING)
            _need(row[0] == context.canonical_json(), StoreReason.CONFLICT)
            row = conn.execute("SELECT spec_json FROM specs WHERE job_id=?", (spec.job_id,)).fetchone()
            _need(row is not None and row[0] == spec.canonical_json(), StoreReason.CONFLICT)
            maximum = conn.execute("SELECT max(lease_epoch) FROM contexts WHERE job_id=?", (context.job_id,)).fetchone()[0]
            _need(maximum == context.lease_epoch, StoreReason.STALE_EPOCH)
            _need(conn.execute("SELECT 1 FROM starts WHERE context_id=?", (context.context_id,)).fetchone() is None,
                  StoreReason.START_ALREADY_RESERVED)
            conn.execute("INSERT INTO starts VALUES(?,?,?)", (context.context_id, context.sha256, decision_id))
        self._readback(spec, context, decision_id, check_decision=True)
        return decision_id
