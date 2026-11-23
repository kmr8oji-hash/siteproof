"""Baseline-only extension initialized ONLY alongside a fresh S1 database.

No S1 schema change, migration, artifact operation, independent database format,
or production profile trust. Existing databases without this extension are refused.
"""

VERSION = "siteproof.baseline.schema.v1"

TABLES = (
    "CREATE TABLE baseline_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), version TEXT NOT NULL)",
    "CREATE TABLE baseline_candidates(candidate_id TEXT PRIMARY KEY NOT NULL, page_id TEXT NOT NULL, profile_fingerprint TEXT NOT NULL, artifact_ref TEXT NOT NULL, artifact_sha256 TEXT NOT NULL, digest TEXT NOT NULL, UNIQUE(candidate_id,page_id,profile_fingerprint))",
    "CREATE TABLE baseline_decisions(candidate_id TEXT PRIMARY KEY NOT NULL REFERENCES baseline_candidates(candidate_id), status TEXT NOT NULL CHECK(status IN ('APPROVED','REJECTED')), actor TEXT NOT NULL, reviewed_digest TEXT NOT NULL, expected_revision INTEGER NOT NULL CHECK(typeof(expected_revision)='integer' AND expected_revision=0), revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision=1))",
    "CREATE TABLE baseline_versions(page_id TEXT NOT NULL, profile_fingerprint TEXT NOT NULL, version INTEGER NOT NULL CHECK(typeof(version)='integer' AND version>0), candidate_id TEXT NOT NULL UNIQUE REFERENCES baseline_decisions(candidate_id), PRIMARY KEY(page_id,profile_fingerprint,version), FOREIGN KEY(candidate_id,page_id,profile_fingerprint) REFERENCES baseline_candidates(candidate_id,page_id,profile_fingerprint))",
    "CREATE TABLE baseline_heads(page_id TEXT NOT NULL, profile_fingerprint TEXT NOT NULL, version INTEGER NOT NULL CHECK(typeof(version)='integer' AND version>0), PRIMARY KEY(page_id,profile_fingerprint), FOREIGN KEY(page_id,profile_fingerprint,version) REFERENCES baseline_versions(page_id,profile_fingerprint,version))",
)

TRIGGERS = tuple(
    f"CREATE TRIGGER {table}_no_{operation.lower()} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'baseline_append_only'); END"
    for table in ("baseline_meta", "baseline_candidates", "baseline_decisions", "baseline_versions")
    for operation in ("UPDATE", "DELETE")
) + (
    "CREATE TRIGGER baseline_heads_no_delete BEFORE DELETE ON baseline_heads BEGIN SELECT RAISE(ABORT,'baseline_history_preserved'); END",
    "CREATE TRIGGER baseline_decision_digest BEFORE INSERT ON baseline_decisions WHEN NEW.reviewed_digest IS NOT (SELECT digest FROM baseline_candidates WHERE candidate_id=NEW.candidate_id) BEGIN SELECT RAISE(ABORT,'baseline_digest_mismatch'); END",
    "CREATE TRIGGER baseline_version_sequence BEFORE INSERT ON baseline_versions WHEN (SELECT status FROM baseline_decisions WHERE candidate_id=NEW.candidate_id) IS NOT 'APPROVED' OR NEW.version<>COALESCE((SELECT MAX(version) FROM baseline_versions WHERE page_id=NEW.page_id AND profile_fingerprint=NEW.profile_fingerprint),0)+1 BEGIN SELECT RAISE(ABORT,'baseline_version_conflict'); END",
    "CREATE TRIGGER baseline_head_initial BEFORE INSERT ON baseline_heads WHEN NEW.version<>1 BEGIN SELECT RAISE(ABORT,'baseline_head_conflict'); END",
    "CREATE TRIGGER baseline_head_advance BEFORE UPDATE ON baseline_heads WHEN NEW.page_id<>OLD.page_id OR NEW.profile_fingerprint<>OLD.profile_fingerprint OR NEW.version<>OLD.version+1 OR NEW.version<>(SELECT MAX(version) FROM baseline_versions WHERE page_id=NEW.page_id AND profile_fingerprint=NEW.profile_fingerprint) BEGIN SELECT RAISE(ABORT,'baseline_head_conflict'); END",
)


def initialize(conn):
    """Caller owns a fresh database and an explicit write transaction."""
    for statement in TABLES + TRIGGERS:
        conn.execute(statement)
    conn.execute("INSERT INTO baseline_meta VALUES(1,?)", (VERSION,))


def matches(conn):
    actual = conn.execute(
        "SELECT sql FROM sqlite_schema WHERE name GLOB 'baseline_*' AND sql IS NOT NULL"
    ).fetchall()
    return (len(actual) == len(TABLES + TRIGGERS)
            and {row[0] for row in actual} == set(TABLES + TRIGGERS)
            and [tuple(row) for row in conn.execute("SELECT * FROM baseline_meta")] == [(1, VERSION)])
