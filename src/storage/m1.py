"""Explicit, additive M1 extension in the existing S1+Baseline SQLite database.

Initialization is a trusted startup operation, never an HTTP GET side effect.
No existing table, schema version, evidence file or terminal S1 record is changed.
All images/results/profiles are append-only; page edits use revision CAS.
"""
from contextlib import contextmanager
import json
import sqlite3

from src.baseline.sqlite_store import SQLiteBaselineStore, BaselineStoreError

VERSION = 'siteproof.m1.offline.v1'
TABLES = (
    'CREATE TABLE m1_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version TEXT NOT NULL)',
    'CREATE TABLE m1_site(singleton INTEGER PRIMARY KEY CHECK(singleton=1),origin TEXT NOT NULL,label TEXT NOT NULL,revision INTEGER NOT NULL)',
    'CREATE TABLE m1_pages(page_id TEXT PRIMARY KEY,label TEXT NOT NULL,path TEXT NOT NULL,revision INTEGER NOT NULL)',
    "CREATE TABLE m1_profiles(page_id TEXT NOT NULL REFERENCES m1_pages(page_id),kind TEXT NOT NULL CHECK(kind IN ('Desktop','Mobile')),revision INTEGER NOT NULL,fingerprint TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(page_id,kind,revision))",
    'CREATE TABLE m1_captures(capture_id TEXT PRIMARY KEY,page_id TEXT NOT NULL REFERENCES m1_pages(page_id),kind TEXT NOT NULL,profile TEXT NOT NULL,fingerprint TEXT NOT NULL,sha256 TEXT,png BLOB,body TEXT NOT NULL)',
    'CREATE TABLE m1_results(result_id TEXT PRIMARY KEY,capture_id TEXT NOT NULL REFERENCES m1_captures(capture_id),baseline_id TEXT NOT NULL REFERENCES baseline_candidates(candidate_id),body TEXT NOT NULL,diff BLOB)',
)
TRIGGERS = tuple(
    f"CREATE TRIGGER {table}_no_{op.lower()} BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT,'m1_append_only'); END"
    for table in ('m1_meta','m1_profiles','m1_captures','m1_results') for op in ('UPDATE','DELETE')
) + (
    "CREATE TRIGGER m1_pages_limit BEFORE INSERT ON m1_pages WHEN (SELECT COUNT(*) FROM m1_pages)>=5 BEGIN SELECT RAISE(ABORT,'PAGE_LIMIT'); END",
    "CREATE TRIGGER m1_pages_no_delete BEFORE DELETE ON m1_pages BEGIN SELECT RAISE(ABORT,'m1_history_preserved'); END",
    "CREATE TRIGGER m1_site_no_delete BEFORE DELETE ON m1_site BEGIN SELECT RAISE(ABORT,'m1_history_preserved'); END",
)


class M1Error(ValueError):
    def __init__(self, code, status=400):
        self.code, self.status = code, status
        super().__init__(code)


def initialize(db_path, storage_root):
    """Explicit opt-in addition; preserve existing records; refuse any partial extension."""
    store = SQLiteBaselineStore.open(db_path, storage_root)
    with store._transaction() as conn:
        if conn.execute("SELECT 1 FROM sqlite_schema WHERE name GLOB 'm1_*'").fetchone():
            raise M1Error('M1_ALREADY_INITIALIZED', 409)
        for sql in TABLES + TRIGGERS:
            conn.execute(sql)
        conn.execute('INSERT INTO m1_meta VALUES(1,?)', (VERSION,))


class M1Repository:
    def __init__(self, db_path, storage_root):
        self.baselines = SQLiteBaselineStore.open(db_path, storage_root)
        with self.read():
            pass

    def _audit(self, conn):
        rows = conn.execute("SELECT sql FROM sqlite_schema WHERE name GLOB 'm1_*' AND sql IS NOT NULL").fetchall()
        if ({r[0] for r in rows} != set(TABLES + TRIGGERS)
                or [tuple(r) for r in conn.execute('SELECT * FROM m1_meta')] != [(1, VERSION)]):
            raise M1Error('M1_SCHEMA_UNSUPPORTED', 503)

    @contextmanager
    def read(self):
        try:
            with self.baselines._read() as conn:
                self._audit(conn)
                yield conn
        except (sqlite3.Error, BaselineStoreError):
            raise M1Error('M1_DATA_UNAVAILABLE', 503) from None

    @contextmanager
    def write(self):
        try:
            with self.baselines._transaction() as conn:
                self._audit(conn)
                yield conn
        except (sqlite3.Error, BaselineStoreError):
            # Includes uncertain commit outcomes: the caller must read back, never
            # claim success or automatically retry. No exception details escape.
            raise M1Error('M1_SAVE_UNCONFIRMED', 503) from None

    def row(self, table, key, value):
        if (table,key) not in (('m1_captures','capture_id'),('m1_results','result_id')):
            raise ValueError('fixed internal lookup only')
        with self.read() as conn:
            row = conn.execute(f'SELECT * FROM {table} WHERE {key}=?', (value,)).fetchone()
            if row is None:
                raise M1Error('NOT_FOUND', 404)
            return dict(row)

    @staticmethod
    def dump(value):
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
