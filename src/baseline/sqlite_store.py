"""Durable candidate/approval/version records in the SAME database as S1.

create(path, storage_root) initializes a NEW S1 database plus baseline tables;
open() never creates tables, migrates, repairs or replaces an existing database.
No default path or separate ledger is invented. S1 Repository can use this file.
All operations own short-lived connections, explicit transactions and FULL sync.

Candidate revisions retain approval.py's one-shot 0->1 semantics. Approved versions
are numbered separately per (page_id, capture-profile fingerprint). Approving needs
an explicit expected_current_version (0 before the first approval). Repeated
decisions, including retries after a lost reply, raise AlreadyDecided, never create
another approval. A post-commit readback failure is reported as ambiguous.

Records/hashes are integrity claims, not authentication or capture attestation.
No artifact file is opened/copied; no evidence existence or profile trust is
asserted. No UI, comparison or S1/S2 bridge is invoked. A whole-database rollback
or hostile filesystem administrator is outside this store's guarantees.
"""

from contextlib import closing, contextmanager
from dataclasses import dataclass, fields
import os
from pathlib import Path
import sqlite3
import stat
import time

from src.storage import baseline_schema
from src.storage.schema import SCHEMA_VERSION, connect, init_schema
from src.comparison.profile import is_clean_text, is_sha256_hex
from .approval import (ApprovalError, BaselineRecord, DuplicateCandidate,
                       RevisionConflict, UnknownCandidate, decide, register_candidate)
from .model import BaselineCandidate, BaselineStatus, CandidateError


class BaselineStoreError(ValueError):
    """Storage unavailable, unsupported, corrupt, or commit/readback ambiguous."""


class BaselineStoreCorrupt(BaselineStoreError):
    pass


class AmbiguousBaselineCommit(BaselineStoreError):
    """May have committed: inspect/reopen; do not blindly repeat the decision."""


@dataclass(frozen=True)
class BaselineVersion:
    version: int
    record: BaselineRecord

    @property
    def profile_trust(self):
        return "UNATTESTED"


@dataclass(frozen=True)
class BaselineReadItem:
    record: BaselineRecord
    candidate_version: int | None
    current_version: int | None
    current_candidate_id: str | None


@dataclass(frozen=True)
class BaselineReadPage:
    items: tuple[BaselineReadItem, ...]
    versions: tuple[BaselineVersion, ...]
    has_more: bool


def _check_deadline(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise TimeoutError("baseline read deadline")


def _copy(candidate):
    if type(candidate) is not BaselineCandidate:
        raise CandidateError("exact BaselineCandidate required")
    names = {f.name for f in fields(BaselineCandidate)}
    if set(vars(candidate)) != names:
        raise CandidateError("malformed candidate")
    return BaselineCandidate(**{name: getattr(candidate, name) for name in names})


def _scope(page_id, profile_fingerprint):
    if not is_clean_text(page_id) or not is_sha256_hex(profile_fingerprint):
        raise CandidateError("invalid page/profile scope")
    return page_id, profile_fingerprint


def _location(path, storage_root):
    try:
        path, root = Path(path), Path(storage_root)
        if (not path.is_absolute() or not root.is_absolute()
                or path.drive.startswith("\\\\") or root.drive.startswith("\\\\")
                or ".." in path.parts or ".." in root.parts):
            raise BaselineStoreError("local absolute storage paths required")
        for item in (path, root):
            for part in (*reversed(item.parents), item):
                if part.exists() or part.is_symlink():
                    info = part.lstat()
                    if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0)
                            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
                        raise BaselineStoreError("linked database path")
        path, root = path.resolve(), root.resolve()
        if not root.is_dir() or path == root or not path.is_relative_to(root) or not path.parent.is_dir():
            raise BaselineStoreError("database must be inside existing storage root")
        return path, root
    except (TypeError, OSError, RuntimeError) as exc:
        raise BaselineStoreError("database path unavailable") from exc


class SQLiteBaselineStore:
    def __init__(self, path, storage_root):
        self.path, self.storage_root = _location(path, storage_root)
        self._identity = self._file_identity()

    def _file_identity(self):
        try:
            _location(self.path, self.storage_root)
            info = self.path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise BaselineStoreError("regular unaliased database required")
            for suffix in ("-journal", "-wal", "-shm"):
                side = Path(str(self.path) + suffix)
                if side.exists() or side.is_symlink():
                    s = side.lstat()
                    if (not stat.S_ISREG(s.st_mode) or s.st_nlink != 1
                            or getattr(s, "st_file_attributes", 0)
                            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
                        raise BaselineStoreError("linked database sidecar")
            return info.st_dev, info.st_ino
        except OSError as exc:
            raise BaselineStoreError("database missing or unavailable") from exc

    @classmethod
    def create(cls, path, storage_root):
        path, root = _location(path, storage_root)
        # Exclusive creation: never initialize an existing S1/user database.
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        except OSError as exc:
            raise BaselineStoreError("new database path required") from exc
        store = cls(path, root)
        try:
            with closing(connect(str(path))) as conn:
                init_schema(conn)  # Reuse unchanged S1 initialization on this NEW file.
                conn.execute("BEGIN IMMEDIATE")
                try:
                    baseline_schema.initialize(conn)
                    store._audit(conn)
                    conn.commit()
                except BaseException:
                    if conn.in_transaction:
                        conn.rollback()
                    raise
            return cls.open(path, root)
        except Exception as exc:
            # Preserve partial creation for inspection; never delete/recreate.
            raise BaselineStoreError("creation incomplete; file preserved") from exc

    @classmethod
    def open(cls, path, storage_root):
        store = cls(path, storage_root)
        with store._read():
            pass
        return store

    def _connect(self, readonly):
        conn = None
        try:
            if self._file_identity() != self._identity:
                raise BaselineStoreError("database replaced")
            if readonly:
                conn = connect(str(self.path), read_only=True)
            else:
                # Same explicit-transaction/FK/FULL scheme as the existing stores;
                # mode=rw additionally prevents accidental recreation on deletion.
                conn = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True,
                                       isolation_level=None, timeout=5.0)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA foreign_keys=ON")
                conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA trusted_schema=OFF")
            if self._file_identity() != self._identity:
                raise BaselineStoreError("database replaced")
            return conn
        except (sqlite3.Error, BaselineStoreError):
            if conn is not None:
                conn.close()
            raise BaselineStoreError("database unavailable") from None

    def _records(self, conn, *, deadline=None):
        records = {}
        for row in conn.execute("SELECT * FROM baseline_candidates"):
            _check_deadline(deadline)
            candidate = BaselineCandidate(**{f.name: row[f.name] for f in fields(BaselineCandidate)})
            if candidate.digest != row["digest"]:
                raise BaselineStoreCorrupt("candidate digest mismatch")
            records[candidate.candidate_id] = register_candidate(candidate)
        for row in conn.execute("SELECT * FROM baseline_decisions"):
            _check_deadline(deadline)
            records[row["candidate_id"]] = decide(
                records[row["candidate_id"]], decision=BaselineStatus(row["status"]),
                actor=row["actor"], expected_revision=row["expected_revision"],
                reviewed_digest=row["reviewed_digest"])
            if records[row["candidate_id"]].revision != row["revision"]:
                raise BaselineStoreCorrupt("decision revision mismatch")
        return records

    def _audit(self, conn, *, deadline=None):
        try:
            row = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
            if row is None or row[0] != SCHEMA_VERSION or not baseline_schema.matches(conn):
                raise BaselineStoreCorrupt("unsupported or altered schema; no migration performed")
            if ([tuple(r) for r in conn.execute("PRAGMA integrity_check")] != [("ok",)]
                    or conn.execute("PRAGMA foreign_key_check").fetchall()):
                raise BaselineStoreCorrupt("database integrity failure")
            records = self._records(conn, deadline=deadline)
            maxima, adopted = {}, set()
            for row in conn.execute("SELECT * FROM baseline_versions ORDER BY page_id,profile_fingerprint,version"):
                _check_deadline(deadline)
                scope = row["page_id"], row["profile_fingerprint"]
                record = records[row["candidate_id"]]
                if (not record.is_valid_approval() or scope != (
                        record.candidate.page_id, record.candidate.profile_fingerprint)
                        or row["version"] != maxima.get(scope, 0) + 1):
                    raise BaselineStoreCorrupt("version chain invalid")
                maxima[scope] = row["version"]
                adopted.add(row["candidate_id"])
            if adopted != {cid for cid, rec in records.items() if rec.status is BaselineStatus.APPROVED}:
                raise BaselineStoreCorrupt("approval/version reference missing")
            heads = {(r["page_id"], r["profile_fingerprint"]): r["version"]
                     for r in conn.execute("SELECT * FROM baseline_heads")}
            if heads != maxima:
                raise BaselineStoreCorrupt("current version reference invalid")
            return records
        except (sqlite3.Error, ApprovalError, ValueError, KeyError, TypeError) as exc:
            if isinstance(exc, BaselineStoreCorrupt):
                raise
            raise BaselineStoreCorrupt("baseline records inconsistent") from exc

    @contextmanager
    def _read(self, *, deadline=None):
        with closing(self._connect(True)) as conn:
            try:
                conn.execute("PRAGMA query_only=ON")
                if deadline is not None:
                    _check_deadline(deadline)
                    conn.execute("PRAGMA busy_timeout=" + str(max(1, min(5000, int(
                        (deadline - time.monotonic()) * 1000)))))
                    conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 100)
                conn.execute("BEGIN")
                self._audit(conn, deadline=deadline)
                yield conn
                _check_deadline(deadline)
                if self._file_identity() != self._identity:
                    raise BaselineStoreError("database replaced")
            except (sqlite3.Error, TimeoutError) as exc:
                raise BaselineStoreError("baseline read unavailable") from exc
            finally:
                conn.set_progress_handler(None, 0)
                if conn.in_transaction:
                    conn.rollback()

    @contextmanager
    def _transaction(self):
        with closing(self._connect(False)) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                self._audit(conn)
                yield conn
                self._audit(conn)
            except BaseException as exc:
                if conn.in_transaction:
                    conn.rollback()
                if isinstance(exc, sqlite3.Error):
                    raise BaselineStoreError("baseline transaction rolled back") from exc
                raise
            try:
                conn.commit()
                if self._file_identity() != self._identity:
                    raise BaselineStoreError("database replaced")
            except Exception as exc:
                if conn.in_transaction:
                    conn.rollback()
                raise AmbiguousBaselineCommit("commit result uncertain; inspect before retry") from exc

    def get(self, candidate_id):
        if not is_clean_text(candidate_id):
            raise UnknownCandidate("invalid candidate id")
        with self._read() as conn:
            records = self._records(conn)
            if candidate_id not in records:
                raise UnknownCandidate(candidate_id)
            return records[candidate_id]

    def _readback(self, record):
        try:
            actual = self.get(record.candidate.candidate_id)
            # A pending candidate can have been decided by another writer after
            # registration. Its immutable fields, not its mutable head, must match.
            if (actual.candidate != record.candidate or actual.registered_digest != record.registered_digest
                    or record.status is not BaselineStatus.PENDING and actual != record):
                raise BaselineStoreCorrupt("readback mismatch")
        except Exception as exc:
            raise AmbiguousBaselineCommit("committed record could not be confirmed") from exc

    def register(self, candidate):
        record = register_candidate(_copy(candidate))
        with self._transaction() as conn:
            if conn.execute("SELECT 1 FROM baseline_candidates WHERE candidate_id=?",
                            (record.candidate.candidate_id,)).fetchone():
                raise DuplicateCandidate(record.candidate.candidate_id)
            c = record.candidate
            conn.execute("INSERT INTO baseline_candidates VALUES(?,?,?,?,?,?)", (
                c.candidate_id, c.page_id, c.profile_fingerprint, c.artifact_ref,
                c.artifact_sha256, record.registered_digest))
        self._readback(record)
        return record

    def decide(self, candidate_id, *, decision, actor, expected_revision, reviewed_digest,
               expected_current_version=None):
        if not is_clean_text(candidate_id):
            raise UnknownCandidate("invalid candidate id")
        with self._transaction() as conn:
            records = self._records(conn)
            if candidate_id not in records:
                raise UnknownCandidate(candidate_id)
            updated = decide(records[candidate_id], decision=decision, actor=actor,
                             expected_revision=expected_revision, reviewed_digest=reviewed_digest)
            c = updated.candidate
            scope = c.page_id, c.profile_fingerprint
            if decision is BaselineStatus.APPROVED:
                row = conn.execute("SELECT version FROM baseline_heads WHERE page_id=? AND profile_fingerprint=?", scope).fetchone()
                current = row[0] if row else 0
                if type(expected_current_version) is not int or expected_current_version != current:
                    raise RevisionConflict("current baseline version changed or not explicitly reviewed")
            conn.execute("INSERT INTO baseline_decisions VALUES(?,?,?,?,?,?)", (
                candidate_id, decision.value, updated.decision.actor, reviewed_digest,
                expected_revision, updated.revision))
            if decision is BaselineStatus.APPROVED:
                conn.execute("INSERT INTO baseline_versions VALUES(?,?,?,?)", (*scope, current + 1, candidate_id))
                if current == 0:
                    conn.execute("INSERT INTO baseline_heads VALUES(?,?,?)", (*scope, 1))
                else:
                    changed = conn.execute("UPDATE baseline_heads SET version=? WHERE page_id=? AND profile_fingerprint=? AND version=?",
                                           (current + 1, *scope, current)).rowcount
                    if changed != 1:
                        raise RevisionConflict("current version CAS failed")
        self._readback(updated)
        return updated

    def history(self, page_id, profile_fingerprint):
        scope = _scope(page_id, profile_fingerprint)
        with self._read() as conn:
            records = self._records(conn)
            return tuple(BaselineVersion(row["version"], records[row["candidate_id"]])
                         for row in conn.execute("SELECT version,candidate_id FROM baseline_versions WHERE page_id=? AND profile_fingerprint=? ORDER BY version", scope))

    def current(self, page_id, profile_fingerprint):
        versions = self.history(page_id, profile_fingerprint)
        return versions[-1] if versions else None

    def read_page(self, *, limit, offset=0, candidate_id=None, history=False, deadline=None):
        """Bounded, one-snapshot read for a local BFF; never opens a writer.

        limit 1..100 and offset 0..10000 apply to candidates or approved versions.
        History belongs to the selected candidate's page/profile scope. Decisions
        retain their existing one-shot records; timestamps are not invented.
        Paging observes each request separately, not a multi-request snapshot.
        """
        if (type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int
                or not 0 <= offset <= 10000 or type(history) is not bool
                or history and candidate_id is None):
            raise ValueError("invalid bounded read page")
        if candidate_id is not None and not is_clean_text(candidate_id):
            raise UnknownCandidate("invalid candidate id")
        with self._read(deadline=deadline) as conn:
            records = self._records(conn, deadline=deadline)
            if candidate_id is not None and candidate_id not in records:
                raise UnknownCandidate(candidate_id)
            if candidate_id is None:
                ids = [row[0] for row in conn.execute(
                    "SELECT candidate_id FROM baseline_candidates ORDER BY candidate_id LIMIT ? OFFSET ?",
                    (limit + 1, offset))]
                more = len(ids) > limit
                ids = ids[:limit]
            else:
                ids, more = [candidate_id], False
            items = []
            for cid in ids:
                _check_deadline(deadline)
                record = records[cid]
                c = record.candidate
                row = conn.execute("SELECT h.version,v.candidate_id FROM baseline_heads h JOIN baseline_versions v USING(page_id,profile_fingerprint,version) WHERE h.page_id=? AND h.profile_fingerprint=?",
                                   (c.page_id, c.profile_fingerprint)).fetchone()
                own = conn.execute("SELECT version FROM baseline_versions WHERE candidate_id=?", (cid,)).fetchone()
                items.append(BaselineReadItem(record, own[0] if own else None,
                                             row[0] if row else None, row[1] if row else None))
            versions = ()
            if history:
                c = records[candidate_id].candidate
                rows = conn.execute("SELECT version,candidate_id FROM baseline_versions WHERE page_id=? AND profile_fingerprint=? ORDER BY version LIMIT ? OFFSET ?",
                                    (c.page_id, c.profile_fingerprint, limit + 1, offset)).fetchall()
                more = len(rows) > limit
                versions = tuple(BaselineVersion(r[0], records[r[1]]) for r in rows[:limit])
            return BaselineReadPage(tuple(items), versions, more)
