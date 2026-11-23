"""Evidence finalization: verify stream -> derive checks from records -> write artifacts +
manifest -> read back -> re-verify -> SQLite commit.

SQLite and the filesystem are not one atomic transaction. This module therefore never
infers success: after any uncertain commit it re-reads the database.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Sequence as RuntimeSequence
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Sequence

from ..core.errors import (CasConflict, EvidenceIncomplete, EvidenceMismatch, FrameRejected,
                           InvalidTransition, StaleAttemptError, StorageError,
                           StreamIncomplete, TerminalJobError)
from ..core.frames import CheckType, StreamSummary, Termination, VerifiedFrame
from ..core.ingest import IngestLimits, verify_stream
from ..core.model import (AttemptRef, CheckReport, CheckResult, JobRecord, JobSnapshot,
                          JobStatus, QualityVerdict)
from ..core.records import derive_reports
from ..core.rules import derive_quality, is_terminal, validate_report
from .artifacts import ArtifactStore
from .failpoints import Failpoints, InjectedFailure, hit
from .manifest import MANIFEST_NAME, build_manifest, manifest_bytes, verify_published
from .repository import ArtifactRow, ManifestRow, Repository


class CommitState(str, Enum):
    COMMITTED = "COMMITTED"          # confirmed by re-reading SQLite
    NOT_COMMITTED = "NOT_COMMITTED"  # confirmed: job unchanged, still SAVING
    LOST_RACE = "LOST_RACE"          # another writer (cancel / newer attempt) got there first
    UNKNOWN = "UNKNOWN"              # could not determine; do not assume success
    NOT_ATTEMPTED = "NOT_ATTEMPTED"  # job moved to a failure state before any final commit


@dataclass(frozen=True)
class FinalizeOutcome:
    job: Optional[JobRecord]
    commit_state: CommitState
    quality: Optional[QualityVerdict] = None
    reason: Optional[str] = None
    manifest_rel_path: Optional[str] = None
    unadopted_files: tuple[str, ...] = ()  # written but NOT adopted and NOT deleted


def build_results(snapshot: JobSnapshot, attempt: AttemptRef,
                  frames: Sequence[VerifiedFrame],
                  reports: Optional[Sequence[CheckReport]] = None) -> list[CheckResult]:
    """Derive check results from the record frames. Raises EvidenceIncomplete; never fills gaps.

    The outcome of every check comes from its record (`records.derive_reports`). If the caller
    also passes `reports`, they must equal the derived ones exactly: a report can never be more
    favourable than, or merely different from, what the record supports.
    """
    derived = derive_reports(frames, snapshot)  # may raise RecordInvalid
    for ct in snapshot.required_checks:
        if ct not in derived:
            raise EvidenceIncomplete("REQUIRED_CHECK_MISSING", ct.value)
    if reports is not None:
        if not isinstance(reports, RuntimeSequence):
            raise EvidenceIncomplete("CHECK_REPORT_TYPE", "reports must be a sequence")
        seen: dict[CheckType, CheckReport] = {}
        for rep in reports:
            if not isinstance(rep, CheckReport):
                raise EvidenceIncomplete("CHECK_REPORT_TYPE", "not a CheckReport")
            if rep.check_type in seen:
                raise EvidenceIncomplete("DUPLICATE_CHECK_REPORT", rep.check_type.value)
            if rep.check_type not in snapshot.required_checks:
                raise EvidenceIncomplete("CHECK_NOT_REQUIRED", rep.check_type.value)
            seen[rep.check_type] = rep

        def _brief(d: dict[CheckType, CheckReport]) -> list[tuple[str, str, str]]:
            return sorted((c.value, r.outcome.value, r.reason_code) for c, r in d.items())

        if seen != derived:
            raise EvidenceIncomplete(
                "REPORT_RECORD_MISMATCH", f"reports={_brief(seen)} records={_brief(derived)}")
    results = []
    for ct in snapshot.required_checks:
        rep = derived[ct]
        validate_report(rep, baseline_id=snapshot.baseline_id,
                        kinds_present=[f.kind for f in frames if f.check_type is ct])
        results.append(CheckResult(snapshot.job_id, attempt.attempt_id, snapshot.page_id,
                                   snapshot.profile_id, ct, rep.outcome, rep.reason_code))
    return results


class EvidenceFinalizer:
    def __init__(self, repo: Repository, store: ArtifactStore, *,
                 failpoints: Optional[Failpoints] = None,
                 limits: IngestLimits = IngestLimits()) -> None:
        self.repo = repo
        self.store = store
        self._fp = failpoints
        self._limits = limits

    def finalize(self, job_id: str, attempt_id: str, frames: Sequence[VerifiedFrame],
                 summary: StreamSummary,
                 reports: Optional[Sequence[CheckReport]] = None) -> FinalizeOutcome:
        """Job must be SAVING. Terminal jobs are never touched or re-run.

        Called with a stale attempt, it raises StaleAttemptError and changes nothing. If the
        attempt becomes stale *during* finalization, the outcome is LOST_RACE and the current
        job (owned by the newer attempt) is left untouched.
        """
        job = self.repo.get_job(job_id)
        if is_terminal(job.status):
            raise TerminalJobError(f"job {job_id} is terminal ({job.status.value})")
        if job.status is not JobStatus.SAVING:
            raise InvalidTransition(f"finalize requires SAVING, found {job.status.value}")
        attempt = self.repo.get_attempt(job_id, attempt_id)
        latest = self.repo.latest_attempt(job_id)
        if (latest is None or latest.attempt_id != attempt.attempt_id
                or latest.lease_epoch != attempt.lease_epoch):
            # A newer lease epoch owns the job: this attempt must not change anything.
            raise StaleAttemptError(f"attempt {attempt_id} is not the current attempt")
        snapshot = job.snapshot
        hit(self._fp, "after_entry_checks")

        try:
            verified = verify_stream(frames, summary, snapshot, attempt, self._limits)
        except StreamIncomplete as e:
            target = (JobStatus.TIMED_OUT if e.termination == Termination.TIMEOUT.value
                      else JobStatus.FAILED_EVIDENCE)
            return self._fail(job, attempt, target, e.code)
        except FrameRejected as e:
            return self._fail(job, attempt, JobStatus.FAILED_EVIDENCE,
                              f"FRAME_REJECTED:{e.code}")

        try:
            results = build_results(snapshot, attempt, verified, reports)
        except EvidenceIncomplete as e:
            return self._fail(job, attempt, JobStatus.FAILED_EVIDENCE, f"{e.code}:{e.detail}")

        written: list[str] = []
        try:
            artifact_rows, manifest_row = self._write_evidence(
                snapshot, attempt, verified, results, written)
        except (StorageError, OSError, InjectedFailure, EvidenceMismatch) as e:
            return self._fail(job, attempt, JobStatus.FAILED_EVIDENCE,
                              f"EVIDENCE_WRITE_FAILED:{type(e).__name__}", unadopted=written)

        hit(self._fp, "before_final_commit")
        try:
            # Narrow the TOCTOU window: re-read and re-hash everything just before commit.
            verify_published(self.store, artifact_rows, manifest_row, snapshot, attempt)
        except (EvidenceMismatch, StorageError, OSError) as e:
            return self._fail(job, attempt, JobStatus.FAILED_EVIDENCE,
                              f"PRECOMMIT_REVERIFY_FAILED:{str(e)[:300]}", unadopted=written)
        hit(self._fp, "after_precommit_reverify")  # residual window before the SQLite commit
        return self._commit(job, attempt, results, artifact_rows, manifest_row, written)

    # ---- steps ----------------------------------------------------------
    def _write_evidence(self, snapshot: JobSnapshot, attempt: AttemptRef,
                        frames: Sequence[VerifiedFrame], results: Sequence[CheckResult],
                        written: list[str]) -> tuple[list[ArtifactRow], ManifestRow]:
        rows: list[ArtifactRow] = []
        for f in frames:
            ext = "png" if f.kind.value == "SCREENSHOT_PNG" else "bin"
            name = f"{f.seq:06d}_{f.kind.value.lower()}.{ext}"
            sf = self.store.write_new(snapshot.job_id, attempt.attempt_id, name, f.payload)
            written.append(sf.rel_path)
            if sf.sha256 != f.sha256 or sf.byte_length != f.byte_length:
                raise EvidenceMismatch(f"stored artifact differs from frame: {sf.rel_path}")
            rows.append(ArtifactRow(f.seq, f.kind, f.page_id, f.profile_id, f.check_type,
                                    sf.rel_path, sf.sha256, sf.byte_length))
            hit(self._fp, "after_artifact_write")
        data = manifest_bytes(build_manifest(snapshot, attempt, results, rows))
        msf = self.store.write_new(snapshot.job_id, attempt.attempt_id, MANIFEST_NAME, data)
        written.append(msf.rel_path)
        manifest = ManifestRow(msf.rel_path, msf.sha256, msf.byte_length)
        hit(self._fp, "after_manifest_write")
        verify_published(self.store, rows, manifest, snapshot, attempt)
        return rows, manifest

    def _commit(self, job: JobRecord, attempt: AttemptRef, results: list[CheckResult],
                rows: list[ArtifactRow], manifest: ManifestRow,
                written: list[str]) -> FinalizeOutcome:
        quality = derive_quality(job.snapshot.required_checks,
                                 {r.check_type: r.outcome for r in results})
        try:
            self.repo.commit_completed(job_id=job.job_id, expected_version=job.version,
                                       attempt=attempt, results=results, artifacts=rows,
                                       manifest=manifest)
        except (CasConflict, TerminalJobError) as e:
            cur = self.repo.get_job(job.job_id)
            return FinalizeOutcome(cur, CommitState.LOST_RACE, None,
                                   f"FINAL_COMMIT_LOST:{type(e).__name__}", None,
                                   tuple(written))
        except StaleAttemptError:
            return FinalizeOutcome(self.repo.get_job(job.job_id), CommitState.LOST_RACE,
                                   None, "STALE_ATTEMPT_AT_COMMIT", None, tuple(written))
        except (sqlite3.Error, InjectedFailure) as e:
            return self._resolve(job, attempt, manifest, quality, written, repr(e))
        cur = self.repo.get_job(job.job_id)
        return FinalizeOutcome(cur, CommitState.COMMITTED, quality, None, manifest.rel_path, ())

    def _resolve(self, job: JobRecord, attempt: AttemptRef, manifest: ManifestRow,
                 quality: QualityVerdict, written: list[str], err: str) -> FinalizeOutcome:
        """Commit result unknown to the caller: decide only from what SQLite says now."""
        reason = f"COMMIT_RESULT_UNCERTAIN:{err}"
        try:
            cur = self.repo.get_job(job.job_id)
            row = self.repo.get_manifest_row(job.job_id, attempt.attempt_id)
        except Exception:
            return FinalizeOutcome(None, CommitState.UNKNOWN, None, reason, None, tuple(written))
        if (cur.status is JobStatus.COMPLETED and cur.version == job.version + 1
                and cur.adopted_attempt_id == attempt.attempt_id
                and row is not None and row.sha256 == manifest.sha256):
            return FinalizeOutcome(cur, CommitState.COMMITTED, quality, reason,
                                   manifest.rel_path, ())
        if cur.version == job.version and cur.status is JobStatus.SAVING and row is None:
            return FinalizeOutcome(cur, CommitState.NOT_COMMITTED, None, reason, None,
                                   tuple(written))
        return FinalizeOutcome(cur, CommitState.LOST_RACE, None, reason, None, tuple(written))

    def _fail(self, job: JobRecord, attempt: AttemptRef, target: JobStatus, reason: str, *,
              unadopted: Sequence[str] = ()) -> FinalizeOutcome:
        """Failure transition, valid only for the attempt/epoch that is still current."""
        try:
            cur = self.repo.transition(job.job_id, job.version, target, reason=reason,
                                       expected_attempt=attempt)
        except StaleAttemptError:
            # A newer attempt owns the job now: do not terminalise it on this attempt's behalf.
            return FinalizeOutcome(self.repo.get_job(job.job_id), CommitState.LOST_RACE, None,
                                   f"{reason};STALE_ATTEMPT_JOB_UNTOUCHED", None,
                                   tuple(unadopted))
        except (CasConflict, TerminalJobError):
            cur = self.repo.get_job(job.job_id)
            return FinalizeOutcome(cur, CommitState.LOST_RACE, None,
                                   f"{reason};FAILURE_TRANSITION_LOST", None, tuple(unadopted))
        return FinalizeOutcome(cur, CommitState.NOT_ATTEMPTED, None, reason, None,
                               tuple(unadopted))
