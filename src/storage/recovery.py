"""Read-only recovery *dry-run*: detect inconsistencies, propose actions, change nothing.

Applying any proposal (delete / move / adopt / terminal-state rewrite) is deliberately NOT
implemented; it needs separate USER approval.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterator

from ..core.errors import EvidenceMismatch, StorageError
from ..core.frames import CheckType, FrameKind
from ..core.model import AttemptRef, CheckOutcome, CheckResult, JobStatus
from ..core.rules import is_terminal
from .artifacts import TMP_DIRNAME, ArtifactStore
from .manifest import compare_with_db, verify_stored
from .repository import ArtifactRow, Repository
from .schema import connect

REVIEW_ONLY = "REVIEW_ONLY: no automatic delete/adopt; applying needs separate USER approval"


@dataclass(frozen=True)
class Finding:
    code: str
    subject: str
    detail: str
    proposal: str = REVIEW_ONLY


@dataclass(frozen=True)
class RecoveryReport:
    findings: tuple[Finding, ...]
    applied: bool = False  # always False: this module never applies anything

    def codes(self) -> list[str]:
        return [f.code for f in self.findings]


def _walk_files(root: str) -> Iterator[str]:
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            yield os.path.join(dirpath, name)


def _verify_completed_job(conn, store, job, referenced: set[str]) -> list[Finding]:
    att = conn.execute("SELECT * FROM attempts WHERE job_id=? AND attempt_id=?",
                       (job.job_id, job.adopted_attempt_id)).fetchone()
    man = conn.execute("SELECT * FROM manifests WHERE job_id=? AND attempt_id=?",
                       (job.job_id, job.adopted_attempt_id)).fetchone()
    if att is None or man is None:
        return [Finding("COMPLETED_WITHOUT_MANIFEST", job.job_id,
                        "adopted attempt or manifest row missing")]
    referenced.add(man["rel_path"])
    art_rows = conn.execute("SELECT * FROM artifacts WHERE job_id=? AND attempt_id=?",
                            (job.job_id, job.adopted_attempt_id)).fetchall()
    referenced.update(a["rel_path"] for a in art_rows)
    ref = AttemptRef(att["job_id"], att["attempt_id"], att["lease_epoch"])
    try:
        doc = verify_stored(store, man["rel_path"], man["sha256"], job.snapshot, ref,
                            expected_length=man["byte_length"])
    except (EvidenceMismatch, OSError, StorageError) as e:
        return [Finding("EVIDENCE_INCONSISTENT", job.job_id, str(e))]
    results = [CheckResult(r["job_id"], r["attempt_id"], r["page_id"], r["profile_id"],
                           CheckType(r["check_type"]), CheckOutcome(r["outcome"]),
                           r["reason_code"])
               for r in conn.execute("SELECT * FROM check_results WHERE job_id=? AND "
                                     "attempt_id=?", (job.job_id, job.adopted_attempt_id))]
    artifacts = [ArtifactRow(a["seq"], FrameKind(a["kind"]), a["page_id"], a["profile_id"],
                             CheckType(a["check_type"]), a["rel_path"], a["sha256"],
                             a["byte_length"]) for a in art_rows]
    required_db = [CheckType(r["check_type"]) for r in conn.execute(
        "SELECT check_type FROM job_required_checks WHERE job_id=?", (job.job_id,))]
    out = []
    for problem in compare_with_db(doc, job.snapshot, results, artifacts, required_db):
        out.append(Finding(problem.split(":", 1)[0], job.job_id, problem))
    return out


def plan_recovery(db_path: str, evidence_root: str) -> RecoveryReport:
    store = ArtifactStore(evidence_root)  # constructing does not touch the filesystem
    findings: list[Finding] = []
    referenced: set[str] = set()
    conn = connect(db_path, read_only=True)
    try:
        for row in conn.execute("SELECT * FROM jobs ORDER BY created_at, job_id").fetchall():
            try:
                job = Repository._record(row)
            except Exception as e:  # corrupt snapshot / unparsable row: report, never raise
                findings.append(Finding("SNAPSHOT_CORRUPT", row["job_id"],
                                        f"{type(e).__name__}: {e}"))
                continue
            if not is_terminal(job.status):
                findings.append(Finding(
                    "NONTERMINAL_JOB", job.job_id,
                    f"status={job.status.value} v{job.version}; may be a stalled or crashed run"))
                continue
            if job.status is not JobStatus.COMPLETED:
                continue
            try:
                findings.extend(_verify_completed_job(conn, store, job, referenced))
            except Exception as e:  # unexpected shape in DB or manifest: still just a finding
                findings.append(Finding("VERIFY_ERROR", job.job_id,
                                        f"{type(e).__name__}: {e}"))
    finally:
        conn.close()

    if os.path.isdir(store.root):
        for path in sorted(_walk_files(str(store.root))):
            rel = os.path.relpath(path, store.root).replace(os.sep, "/")
            if rel in referenced:
                continue
            if rel.split("/", 1)[0] == TMP_DIRNAME:
                findings.append(Finding("TEMP_LEFTOVER", rel, "temp file from an interrupted write"))
            else:
                findings.append(Finding("ORPHAN_FILE", rel,
                                        "not referenced by any adopted manifest"))
    return RecoveryReport(tuple(findings))
