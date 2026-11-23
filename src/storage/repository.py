"""SQLite repository for jobs, attempts, check results and artifact metadata."""
from __future__ import annotations

import contextlib
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterator, Optional, Sequence

from ..core.errors import (CasConflict, DuplicateAttemptError, IdempotencyConflict,
                           InvalidTransition, StaleAttemptError, StorageError,
                           TerminalJobError, UnknownAttempt, UnknownJob, ValidationError)
from ..core.frames import CheckType, FrameKind
from ..core.model import (AttemptRef, CheckOutcome, CheckResult, JobIntent, JobRecord,
                          JobSnapshot, JobStatus, validate_id)
from ..core.rules import can_transition, is_terminal
from .failpoints import Failpoints, hit
from .schema import connect, init_schema


@dataclass(frozen=True)
class ArtifactRow:
    seq: int
    kind: FrameKind
    page_id: str
    profile_id: str
    check_type: CheckType
    rel_path: str
    sha256: str
    byte_length: int


@dataclass(frozen=True)
class ManifestRow:
    rel_path: str
    sha256: str
    byte_length: int


@dataclass(frozen=True)
class AcceptResult:
    job: JobRecord
    created: bool


_ATTEMPT_DRIVEN_FAILURES = frozenset({JobStatus.FAILED_EXECUTION, JobStatus.FAILED_EVIDENCE,
                                      JobStatus.TIMED_OUT})


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class Repository:
    def __init__(self, db_path: str, *, clock: Callable[[], str] = _utc_now,
                 id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
                 failpoints: Optional[Failpoints] = None) -> None:
        self.db_path = str(db_path)
        self._clock = clock
        self._new_id = id_factory
        self._fp = failpoints

    # ---- plumbing -------------------------------------------------------
    def init(self) -> None:
        conn = connect(self.db_path)
        try:
            init_schema(conn)
        finally:
            conn.close()

    @contextlib.contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        conn = connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()

    @contextlib.contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        conn = connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()

    @staticmethod
    def _record(row: sqlite3.Row) -> JobRecord:
        snapshot = JobSnapshot.from_json(row["snapshot_json"])
        if (snapshot.sha256 != row["snapshot_sha256"]
                or snapshot.intent.intent_hash != row["intent_hash"]
                or snapshot.job_id != row["job_id"]):
            raise StorageError(f"snapshot integrity violation for job {row['job_id']}")
        return JobRecord(
            snapshot=snapshot, idempotency_key=row["idempotency_key"],
            status=JobStatus(row["status"]), version=row["version"],
            adopted_attempt_id=row["adopted_attempt_id"],
            terminal_reason=row["terminal_reason"], updated_at=row["updated_at"])

    # ---- jobs -----------------------------------------------------------
    def accept_job(self, idempotency_key: str, intent: JobIntent) -> AcceptResult:
        """Accept a job; same key + same intent returns the existing job."""
        if not isinstance(idempotency_key, str) or not idempotency_key.strip() \
                or len(idempotency_key) > 200:
            raise ValidationError("invalid idempotency_key")
        with self._tx() as c:
            row = c.execute("SELECT * FROM jobs WHERE idempotency_key = ?",
                            (idempotency_key,)).fetchone()
            if row is not None:
                if row["intent_hash"] != intent.intent_hash:
                    raise IdempotencyConflict(
                        f"idempotency key {idempotency_key!r} already used with a different intent")
                return AcceptResult(self._record(row), False)
            now = self._clock()
            snapshot = JobSnapshot(job_id=self._new_id(), intent=intent, created_at=now)
            c.execute(
                "INSERT INTO jobs(job_id, idempotency_key, intent_hash, snapshot_json, "
                "snapshot_sha256, page_id, profile_id, baseline_id, required_checks, status, "
                "version, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (snapshot.job_id, idempotency_key, intent.intent_hash, snapshot.to_json(),
                 snapshot.sha256, intent.page_id, intent.profile_id, intent.baseline_id,
                 ",".join(c.value for c in intent.required_checks),
                 JobStatus.ACCEPTED.value, 0, now, now))
            for ct in intent.required_checks:
                c.execute("INSERT INTO job_required_checks VALUES(?,?,?,?)",
                          (snapshot.job_id, intent.page_id, intent.profile_id, ct.value))
            row = c.execute("SELECT * FROM jobs WHERE job_id = ?", (snapshot.job_id,)).fetchone()
            return AcceptResult(self._record(row), True)

    def get_job(self, job_id: str) -> JobRecord:
        with self._read() as c:
            row = c.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            raise UnknownJob(job_id)
        return self._record(row)

    def list_jobs(self) -> list[JobRecord]:
        with self._read() as c:
            rows = c.execute("SELECT * FROM jobs ORDER BY created_at, job_id").fetchall()
        return [self._record(r) for r in rows]

    def transition(self, job_id: str, expected_version: int, to_status: JobStatus,
                   reason: Optional[str] = None, *,
                   expected_attempt: Optional[AttemptRef] = None) -> JobRecord:
        """CAS status change. Terminal jobs are never modified.

        Registering an attempt does not bump the job version, so version CAS alone cannot
        see a newer lease epoch. Attempt-driven failures (FAILED_EXECUTION / FAILED_EVIDENCE /
        TIMED_OUT) on a job that has attempts therefore REQUIRE `expected_attempt`, which is
        checked against the newest attempt/epoch inside the same transaction; a mismatch
        raises StaleAttemptError and changes nothing.
        """
        to_status = JobStatus(to_status)
        if to_status is JobStatus.COMPLETED:
            raise InvalidTransition("COMPLETED can only be reached via commit_completed")
        needs_reason = is_terminal(to_status) and to_status is not JobStatus.CANCELLED
        if needs_reason and not (reason and reason.strip()):
            raise ValidationError(f"reason required for {to_status.value}")
        with self._tx() as c:
            row = c.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            if row is None:
                raise UnknownJob(job_id)
            current = JobStatus(row["status"])
            if is_terminal(current):
                raise TerminalJobError(f"job {job_id} is terminal ({current.value})")
            if row["version"] != expected_version:
                raise CasConflict(
                    f"version {expected_version} != {row['version']}",
                    current_status=current.value, current_version=row["version"])
            if not can_transition(current, to_status):
                raise InvalidTransition(f"{current.value} -> {to_status.value}")
            top = c.execute("SELECT attempt_id, lease_epoch FROM attempts WHERE job_id = ? "
                            "ORDER BY lease_epoch DESC LIMIT 1", (job_id,)).fetchone()
            if expected_attempt is None:
                if top is not None and to_status in _ATTEMPT_DRIVEN_FAILURES:
                    raise ValidationError(
                        f"expected_attempt required for {to_status.value} on a job with attempts")
            elif (top is None or top["attempt_id"] != expected_attempt.attempt_id
                    or top["lease_epoch"] != expected_attempt.lease_epoch
                    or expected_attempt.job_id != job_id):
                raise StaleAttemptError(
                    f"attempt {expected_attempt.attempt_id}/epoch {expected_attempt.lease_epoch} "
                    "is not the current attempt")
            cur = c.execute(
                "UPDATE jobs SET status = ?, version = version + 1, terminal_reason = ?, "
                "updated_at = ? WHERE job_id = ? AND version = ? AND status = ?",
                (to_status.value, reason, self._clock(), job_id, expected_version,
                 current.value))
            if cur.rowcount != 1:
                raise CasConflict("lost compare-and-swap")
            row = c.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            return self._record(row)

    def cancel(self, job_id: str, *, retries: int = 3) -> JobRecord:
        """Cancel a non-terminal job; loses cleanly against a concurrent terminal commit."""
        last: Optional[CasConflict] = None
        for _ in range(retries):
            rec = self.get_job(job_id)
            if is_terminal(rec.status):
                raise TerminalJobError(f"job {job_id} is terminal ({rec.status.value})")
            try:
                return self.transition(job_id, rec.version, JobStatus.CANCELLED,
                                       reason="CANCELLED_BY_USER")
            except CasConflict as e:
                last = e
        raise last if last else CasConflict("cancel failed")

    # ---- attempts -------------------------------------------------------
    def register_attempt(self, job_id: str, attempt_id: str, lease_epoch: int) -> AttemptRef:
        ref = AttemptRef(job_id, attempt_id, lease_epoch)
        with self._tx() as c:
            row = c.execute("SELECT status FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            if row is None:
                raise UnknownJob(job_id)
            if is_terminal(JobStatus(row["status"])):
                raise TerminalJobError(f"job {job_id} is terminal")
            if c.execute("SELECT 1 FROM attempts WHERE job_id=? AND attempt_id=?",
                         (job_id, attempt_id)).fetchone():
                raise DuplicateAttemptError(attempt_id)
            top = c.execute("SELECT max(lease_epoch) FROM attempts WHERE job_id = ?",
                            (job_id,)).fetchone()[0]
            if top is not None and lease_epoch <= top:
                raise StaleAttemptError(f"lease_epoch {lease_epoch} <= current {top}")
            c.execute("INSERT INTO attempts VALUES(?,?,?,?)",
                      (job_id, attempt_id, lease_epoch, self._clock()))
        return ref

    def get_attempt(self, job_id: str, attempt_id: str) -> AttemptRef:
        validate_id(attempt_id, "attempt_id")
        with self._read() as c:
            row = c.execute("SELECT * FROM attempts WHERE job_id=? AND attempt_id=?",
                            (job_id, attempt_id)).fetchone()
        if row is None:
            raise UnknownAttempt(f"{job_id}/{attempt_id}")
        return AttemptRef(row["job_id"], row["attempt_id"], row["lease_epoch"])

    def latest_attempt(self, job_id: str) -> Optional[AttemptRef]:
        with self._read() as c:
            row = c.execute("SELECT * FROM attempts WHERE job_id=? ORDER BY lease_epoch DESC "
                            "LIMIT 1", (job_id,)).fetchone()
        return None if row is None else AttemptRef(
            row["job_id"], row["attempt_id"], row["lease_epoch"])

    # ---- evidence reads -------------------------------------------------
    def list_check_results(self, job_id: str, attempt_id: Optional[str] = None
                           ) -> list[CheckResult]:
        sql = "SELECT * FROM check_results WHERE job_id = ?"
        args: list[object] = [job_id]
        if attempt_id is not None:
            sql += " AND attempt_id = ?"
            args.append(attempt_id)
        with self._read() as c:
            rows = c.execute(sql + " ORDER BY attempt_id, check_type", args).fetchall()
        return [CheckResult(r["job_id"], r["attempt_id"], r["page_id"], r["profile_id"],
                            CheckType(r["check_type"]), CheckOutcome(r["outcome"]),
                            r["reason_code"]) for r in rows]

    def list_artifacts(self, job_id: str, attempt_id: str) -> list[ArtifactRow]:
        with self._read() as c:
            rows = c.execute("SELECT * FROM artifacts WHERE job_id=? AND attempt_id=? "
                             "ORDER BY seq", (job_id, attempt_id)).fetchall()
        return [ArtifactRow(r["seq"], FrameKind(r["kind"]), r["page_id"], r["profile_id"],
                            CheckType(r["check_type"]), r["rel_path"], r["sha256"],
                            r["byte_length"]) for r in rows]

    def get_manifest_row(self, job_id: str, attempt_id: str) -> Optional[ManifestRow]:
        with self._read() as c:
            r = c.execute("SELECT * FROM manifests WHERE job_id=? AND attempt_id=?",
                          (job_id, attempt_id)).fetchone()
        return None if r is None else ManifestRow(r["rel_path"], r["sha256"], r["byte_length"])

    # ---- final commit ---------------------------------------------------
    def commit_completed(self, *, job_id: str, expected_version: int, attempt: AttemptRef,
                         results: Sequence[CheckResult], artifacts: Sequence[ArtifactRow],
                         manifest: ManifestRow) -> JobRecord:
        """Atomically (single SQLite transaction) store evidence rows and move
        SAVING -> COMPLETED with `attempt` adopted. CAS on job version.

        Failpoints: `before_commit` (rolled back), `after_commit` (already durable
        in SQLite, but the caller sees an error: commit result unknown to caller).
        """
        conn = connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
                if row is None:
                    raise UnknownJob(job_id)
                current = JobStatus(row["status"])
                if is_terminal(current):
                    raise TerminalJobError(f"job {job_id} is terminal ({current.value})")
                if current is not JobStatus.SAVING or row["version"] != expected_version:
                    raise CasConflict(
                        f"expected SAVING v{expected_version}, found {current.value} "
                        f"v{row['version']}",
                        current_status=current.value, current_version=row["version"])
                top = conn.execute(
                    "SELECT attempt_id, lease_epoch FROM attempts WHERE job_id=? "
                    "ORDER BY lease_epoch DESC LIMIT 1", (job_id,)).fetchone()
                if top is None or top["attempt_id"] != attempt.attempt_id \
                        or top["lease_epoch"] != attempt.lease_epoch:
                    raise StaleAttemptError(f"attempt {attempt.attempt_id} is not current")
                for r in results:
                    if r.job_id != job_id or r.attempt_id != attempt.attempt_id:
                        raise ValidationError("result does not belong to job/attempt")
                    conn.execute("INSERT INTO check_results VALUES(?,?,?,?,?,?,?)",
                                 (r.job_id, r.attempt_id, r.page_id, r.profile_id,
                                  r.check_type.value, r.outcome.value, r.reason_code))
                for a in artifacts:
                    conn.execute("INSERT INTO artifacts VALUES(?,?,?,?,?,?,?,?,?,?)",
                                 (job_id, attempt.attempt_id, a.seq, a.kind.value, a.page_id,
                                  a.profile_id, a.check_type.value, a.rel_path, a.sha256,
                                  a.byte_length))
                conn.execute("INSERT INTO manifests VALUES(?,?,?,?,?,?)",
                             (job_id, attempt.attempt_id, manifest.rel_path, manifest.sha256,
                              manifest.byte_length, self._clock()))
                cur = conn.execute(
                    "UPDATE jobs SET status='COMPLETED', version = version + 1, "
                    "adopted_attempt_id = ?, terminal_reason = NULL, updated_at = ? "
                    "WHERE job_id = ? AND version = ? AND status = 'SAVING'",
                    (attempt.attempt_id, self._clock(), job_id, expected_version))
                if cur.rowcount != 1:
                    raise CasConflict("lost compare-and-swap at final commit")
                hit(self._fp, "before_commit")
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            hit(self._fp, "after_commit")
        finally:
            conn.close()
        return self.get_job(job_id)
