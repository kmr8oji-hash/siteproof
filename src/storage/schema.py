"""SQLite schema. Invariants are enforced in the database itself (constraints + triggers),
so they hold even if a caller bypasses the Python repository."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from ..core.rules import ALLOWED_TRANSITIONS, TERMINAL_STATUSES, all_artifact_requirements
from ..core.model import JobStatus

SCHEMA_VERSION = "siteproof.s1.schema.v2"

_DDL = """
CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE job_statuses(
  status TEXT PRIMARY KEY,
  is_terminal INTEGER NOT NULL CHECK(is_terminal IN (0,1)));
CREATE TABLE allowed_transitions(
  from_status TEXT NOT NULL REFERENCES job_statuses(status),
  to_status   TEXT NOT NULL REFERENCES job_statuses(status),
  PRIMARY KEY(from_status, to_status));
CREATE TABLE artifact_requirements(
  check_type TEXT NOT NULL CHECK(check_type IN ('HTTP','LOAD','CAPTURE')),
  outcome    TEXT NOT NULL CHECK(outcome IN ('PASS','CHANGED','FAIL','UNKNOWN','SKIPPED')),
  reason_code TEXT NOT NULL,  -- '*' = any reason
  kind       TEXT NOT NULL CHECK(kind IN ('HTTP_RECORD','LOAD_RECORD','CAPTURE_RECORD','SCREENSHOT_PNG')),
  PRIMARY KEY(check_type, outcome, reason_code, kind));

CREATE TABLE jobs(
  job_id TEXT PRIMARY KEY CHECK(length(job_id) BETWEEN 1 AND 64),
  idempotency_key TEXT NOT NULL UNIQUE CHECK(length(idempotency_key) BETWEEN 1 AND 200),
  intent_hash TEXT NOT NULL CHECK(length(intent_hash) = 64),
  snapshot_json TEXT NOT NULL,
  snapshot_sha256 TEXT NOT NULL CHECK(length(snapshot_sha256) = 64),
  page_id TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  baseline_id TEXT,
  required_checks TEXT NOT NULL CHECK(length(required_checks) > 0),
  status TEXT NOT NULL REFERENCES job_statuses(status),
  version INTEGER NOT NULL CHECK(version >= 0),
  adopted_attempt_id TEXT,
  terminal_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(job_id, page_id, profile_id),
  FOREIGN KEY(job_id, adopted_attempt_id) REFERENCES attempts(job_id, attempt_id));

CREATE TABLE job_required_checks(
  job_id TEXT NOT NULL,
  page_id TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  check_type TEXT NOT NULL CHECK(check_type IN ('HTTP','LOAD','CAPTURE')),
  PRIMARY KEY(job_id, page_id, profile_id, check_type),
  FOREIGN KEY(job_id, page_id, profile_id) REFERENCES jobs(job_id, page_id, profile_id));

CREATE TABLE attempts(
  job_id TEXT NOT NULL REFERENCES jobs(job_id),
  attempt_id TEXT NOT NULL CHECK(length(attempt_id) BETWEEN 1 AND 64),
  lease_epoch INTEGER NOT NULL CHECK(lease_epoch >= 1),
  created_at TEXT NOT NULL,
  PRIMARY KEY(job_id, attempt_id),
  UNIQUE(job_id, lease_epoch));

CREATE TABLE check_results(
  job_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  page_id TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  check_type TEXT NOT NULL CHECK(check_type IN ('HTTP','LOAD','CAPTURE')),
  outcome TEXT NOT NULL CHECK(outcome IN ('PASS','CHANGED','FAIL','UNKNOWN','SKIPPED')),
  reason_code TEXT NOT NULL CHECK(length(trim(reason_code)) > 0),
  PRIMARY KEY(job_id, attempt_id, page_id, profile_id, check_type),
  FOREIGN KEY(job_id, attempt_id) REFERENCES attempts(job_id, attempt_id),
  FOREIGN KEY(job_id, page_id, profile_id, check_type)
    REFERENCES job_required_checks(job_id, page_id, profile_id, check_type));

CREATE TABLE artifacts(
  job_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  seq INTEGER NOT NULL CHECK(seq >= 0),
  kind TEXT NOT NULL CHECK(kind IN ('HTTP_RECORD','LOAD_RECORD','CAPTURE_RECORD','SCREENSHOT_PNG')),
  page_id TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  check_type TEXT NOT NULL,
  rel_path TEXT NOT NULL UNIQUE,
  sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
  byte_length INTEGER NOT NULL CHECK(byte_length >= 0),
  PRIMARY KEY(job_id, attempt_id, seq),
  UNIQUE(job_id, attempt_id, page_id, profile_id, check_type, kind),
  FOREIGN KEY(job_id, attempt_id, page_id, profile_id, check_type)
    REFERENCES check_results(job_id, attempt_id, page_id, profile_id, check_type));

CREATE TABLE manifests(
  job_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  rel_path TEXT NOT NULL UNIQUE,
  sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
  byte_length INTEGER NOT NULL CHECK(byte_length > 0),
  created_at TEXT NOT NULL,
  PRIMARY KEY(job_id, attempt_id),
  FOREIGN KEY(job_id, attempt_id) REFERENCES attempts(job_id, attempt_id));
"""

_TRIGGERS = """
-- reference tables are fixed after seeding
CREATE TRIGGER ref_statuses_ro_u BEFORE UPDATE ON job_statuses BEGIN SELECT RAISE(ABORT,'reference_table_readonly'); END;
CREATE TRIGGER ref_statuses_ro_d BEFORE DELETE ON job_statuses BEGIN SELECT RAISE(ABORT,'reference_table_readonly'); END;
CREATE TRIGGER ref_trans_ro_u BEFORE UPDATE ON allowed_transitions BEGIN SELECT RAISE(ABORT,'reference_table_readonly'); END;
CREATE TRIGGER ref_trans_ro_d BEFORE DELETE ON allowed_transitions BEGIN SELECT RAISE(ABORT,'reference_table_readonly'); END;
CREATE TRIGGER ref_req_ro_u BEFORE UPDATE ON artifact_requirements BEGIN SELECT RAISE(ABORT,'reference_table_readonly'); END;
CREATE TRIGGER ref_req_ro_d BEFORE DELETE ON artifact_requirements BEGIN SELECT RAISE(ABORT,'reference_table_readonly'); END;

-- jobs: no deletion, snapshot immutable, terminal immutable, valid versioned transitions only
CREATE TRIGGER jobs_no_delete BEFORE DELETE ON jobs BEGIN SELECT RAISE(ABORT,'jobs_no_delete'); END;
CREATE TRIGGER jobs_insert_initial BEFORE INSERT ON jobs
WHEN NEW.status <> 'ACCEPTED' OR NEW.version <> 0 OR NEW.adopted_attempt_id IS NOT NULL
BEGIN SELECT RAISE(ABORT,'jobs_insert_must_be_initial'); END;
CREATE TRIGGER jobs_snapshot_immutable BEFORE UPDATE ON jobs
WHEN NEW.job_id <> OLD.job_id OR NEW.idempotency_key <> OLD.idempotency_key
  OR NEW.intent_hash <> OLD.intent_hash OR NEW.snapshot_json <> OLD.snapshot_json
  OR NEW.snapshot_sha256 <> OLD.snapshot_sha256 OR NEW.page_id <> OLD.page_id
  OR NEW.profile_id <> OLD.profile_id OR NEW.created_at <> OLD.created_at
  OR NEW.baseline_id IS NOT OLD.baseline_id OR NEW.required_checks <> OLD.required_checks
BEGIN SELECT RAISE(ABORT,'snapshot_immutable'); END;
CREATE TRIGGER jobs_terminal_immutable BEFORE UPDATE ON jobs
WHEN (SELECT is_terminal FROM job_statuses WHERE status = OLD.status) = 1
BEGIN SELECT RAISE(ABORT,'terminal_immutable'); END;
CREATE TRIGGER jobs_transition_valid BEFORE UPDATE ON jobs
WHEN NEW.status = OLD.status
  OR NOT EXISTS(SELECT 1 FROM allowed_transitions WHERE from_status = OLD.status AND to_status = NEW.status)
BEGIN SELECT RAISE(ABORT,'invalid_transition'); END;
CREATE TRIGGER jobs_version_step BEFORE UPDATE ON jobs
WHEN NEW.version <> OLD.version + 1
BEGIN SELECT RAISE(ABORT,'version_must_increment_by_one'); END;
CREATE TRIGGER jobs_adoption_only_completed BEFORE UPDATE ON jobs
WHEN (NEW.adopted_attempt_id IS NOT NULL) <> (NEW.status = 'COMPLETED')
BEGIN SELECT RAISE(ABORT,'adoption_iff_completed'); END;
CREATE TRIGGER jobs_failure_needs_reason BEFORE UPDATE ON jobs
WHEN NEW.status IN ('FAILED_WORKER_START','FAILED_EXECUTION','FAILED_EVIDENCE','TIMED_OUT')
  AND (NEW.terminal_reason IS NULL OR length(trim(NEW.terminal_reason)) = 0)
BEGIN SELECT RAISE(ABORT,'terminal_reason_required'); END;
CREATE TRIGGER jobs_completed_requirements BEFORE UPDATE ON jobs
WHEN NEW.status = 'COMPLETED' AND (
     NEW.adopted_attempt_id IS NULL
  OR (SELECT count(*) FROM job_required_checks WHERE job_id = NEW.job_id)
     <> length(NEW.required_checks) - length(replace(NEW.required_checks, ',', '')) + 1
  OR NEW.adopted_attempt_id <> (SELECT attempt_id FROM attempts WHERE job_id = NEW.job_id
                                ORDER BY lease_epoch DESC LIMIT 1)
  OR NOT EXISTS(SELECT 1 FROM manifests m
                WHERE m.job_id = NEW.job_id AND m.attempt_id = NEW.adopted_attempt_id)
  OR EXISTS(SELECT 1 FROM job_required_checks rc WHERE rc.job_id = NEW.job_id
            AND NOT EXISTS(SELECT 1 FROM check_results cr
                           WHERE cr.job_id = rc.job_id AND cr.attempt_id = NEW.adopted_attempt_id
                             AND cr.page_id = rc.page_id AND cr.profile_id = rc.profile_id
                             AND cr.check_type = rc.check_type))
  OR EXISTS(SELECT 1 FROM check_results cr
            JOIN artifact_requirements ar ON ar.check_type = cr.check_type AND ar.outcome = cr.outcome
                 AND (ar.reason_code = '*' OR ar.reason_code = cr.reason_code)
            WHERE cr.job_id = NEW.job_id AND cr.attempt_id = NEW.adopted_attempt_id
              AND NOT EXISTS(SELECT 1 FROM artifacts a
                             WHERE a.job_id = cr.job_id AND a.attempt_id = cr.attempt_id
                               AND a.page_id = cr.page_id AND a.profile_id = cr.profile_id
                               AND a.check_type = cr.check_type AND a.kind = ar.kind)))
BEGIN SELECT RAISE(ABORT,'completed_requirements_unmet'); END;

-- required checks are fixed at acceptance
CREATE TRIGGER rc_insert_only_at_accept BEFORE INSERT ON job_required_checks
WHEN (SELECT status FROM jobs WHERE job_id = NEW.job_id) <> 'ACCEPTED'
  OR (SELECT version FROM jobs WHERE job_id = NEW.job_id) <> 0
  OR instr(',' || (SELECT required_checks FROM jobs WHERE job_id = NEW.job_id) || ',',
           ',' || NEW.check_type || ',') = 0
BEGIN SELECT RAISE(ABORT,'required_checks_fixed'); END;
CREATE TRIGGER rc_no_update BEFORE UPDATE ON job_required_checks BEGIN SELECT RAISE(ABORT,'required_checks_fixed'); END;
CREATE TRIGGER rc_no_delete BEFORE DELETE ON job_required_checks BEGIN SELECT RAISE(ABORT,'required_checks_fixed'); END;

-- attempts: only for non-terminal jobs, strictly increasing lease epoch, immutable
CREATE TRIGGER att_insert_rules BEFORE INSERT ON attempts
WHEN (SELECT is_terminal FROM job_statuses WHERE status = (SELECT status FROM jobs WHERE job_id = NEW.job_id)) = 1
  OR EXISTS(SELECT 1 FROM attempts WHERE job_id = NEW.job_id AND lease_epoch >= NEW.lease_epoch)
BEGIN SELECT RAISE(ABORT,'attempt_rejected_terminal_or_stale_epoch'); END;
CREATE TRIGGER att_no_update BEFORE UPDATE ON attempts BEGIN SELECT RAISE(ABORT,'attempts_immutable'); END;
CREATE TRIGGER att_no_delete BEFORE DELETE ON attempts BEGIN SELECT RAISE(ABORT,'attempts_immutable'); END;

-- evidence rows: only while SAVING, only for the newest epoch, then immutable
CREATE TRIGGER cr_insert_rules BEFORE INSERT ON check_results
WHEN (SELECT status FROM jobs WHERE job_id = NEW.job_id) <> 'SAVING'
  OR NEW.attempt_id <> (SELECT attempt_id FROM attempts WHERE job_id = NEW.job_id ORDER BY lease_epoch DESC LIMIT 1)
BEGIN SELECT RAISE(ABORT,'evidence_requires_saving_and_current_attempt'); END;
-- No trusted image comparison exists yet: a baseline id alone never yields PASS/CHANGED.
CREATE TRIGGER cr_baseline_rule BEFORE INSERT ON check_results
WHEN NEW.check_type = 'CAPTURE' AND NEW.outcome IN ('PASS','CHANGED')
BEGIN SELECT RAISE(ABORT,'capture_pass_changed_requires_trusted_comparison'); END;
CREATE TRIGGER cr_changed_capture_only BEFORE INSERT ON check_results
WHEN NEW.outcome = 'CHANGED' AND NEW.check_type <> 'CAPTURE'
BEGIN SELECT RAISE(ABORT,'changed_only_for_capture'); END;
CREATE TRIGGER cr_no_update BEFORE UPDATE ON check_results BEGIN SELECT RAISE(ABORT,'check_results_immutable'); END;
CREATE TRIGGER cr_no_delete BEFORE DELETE ON check_results BEGIN SELECT RAISE(ABORT,'check_results_immutable'); END;

CREATE TRIGGER art_insert_rules BEFORE INSERT ON artifacts
WHEN (SELECT status FROM jobs WHERE job_id = NEW.job_id) <> 'SAVING'
BEGIN SELECT RAISE(ABORT,'evidence_requires_saving'); END;
CREATE TRIGGER art_no_update BEFORE UPDATE ON artifacts BEGIN SELECT RAISE(ABORT,'artifacts_immutable'); END;
CREATE TRIGGER art_no_delete BEFORE DELETE ON artifacts BEGIN SELECT RAISE(ABORT,'artifacts_immutable'); END;

CREATE TRIGGER man_insert_rules BEFORE INSERT ON manifests
WHEN (SELECT status FROM jobs WHERE job_id = NEW.job_id) <> 'SAVING'
BEGIN SELECT RAISE(ABORT,'evidence_requires_saving'); END;
CREATE TRIGGER man_no_update BEFORE UPDATE ON manifests BEGIN SELECT RAISE(ABORT,'manifests_immutable'); END;
CREATE TRIGGER man_no_delete BEFORE DELETE ON manifests BEGIN SELECT RAISE(ABORT,'manifests_immutable'); END;
"""


def connect(path: str, *, read_only: bool = False) -> sqlite3.Connection:
    """Open a connection with FK enforcement. Autocommit mode: transactions are explicit."""
    if read_only:
        uri = Path(path).resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=5.0)
    else:
        conn = sqlite3.connect(path, isolation_level=None, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if not read_only:
        conn.execute("PRAGMA synchronous = FULL")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """Create the schema in an empty database. Refuses to touch an existing one."""
    existing = conn.execute(
        "SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
    if existing:
        row = None
        try:
            row = conn.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
        except sqlite3.Error:
            pass
        if row is None or row[0] != SCHEMA_VERSION:
            raise RuntimeError("database is not empty and not a SiteProof S1 database")
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        for stmt in _split(_DDL):
            conn.execute(stmt)
        conn.execute("INSERT INTO schema_meta VALUES('schema_version', ?)", (SCHEMA_VERSION,))
        for st in JobStatus:
            conn.execute("INSERT INTO job_statuses VALUES(?,?)",
                         (st.value, 1 if st in TERMINAL_STATUSES else 0))
        for src, dsts in ALLOWED_TRANSITIONS.items():
            for dst in dsts:
                conn.execute("INSERT INTO allowed_transitions VALUES(?,?)",
                             (src.value, dst.value))
        for ct, oc, reason, kind in all_artifact_requirements():
            conn.execute("INSERT INTO artifact_requirements VALUES(?,?,?,?)",
                         (ct.value, oc.value, reason, kind.value))
        for stmt in _split(_TRIGGERS):
            conn.execute(stmt)
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def _split(script: str) -> list[str]:
    """Split a script into statements (triggers contain ';' inside BEGIN..END)."""
    stmts: list[str] = []
    buf: list[str] = []
    in_trigger = False
    for raw in script.splitlines():
        line = raw.strip()
        if not line or line.startswith("--"):
            continue
        buf.append(raw)
        if line.upper().startswith("CREATE TRIGGER"):
            in_trigger = True
        if in_trigger:
            if line.rstrip().upper().endswith("END;"):
                stmts.append("\n".join(buf))
                buf, in_trigger = [], False
        elif line.endswith(";"):
            stmts.append("\n".join(buf))
            buf = []
    if buf:
        raise RuntimeError("unterminated statement in schema script")
    return stmts
