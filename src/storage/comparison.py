"""Explicit additive M4 ledger; no implicit migration or historical adoption."""
import json

from src.storage.m1 import M1Repository, M1Error


VERSION = 'siteproof.comparison.m4.v1'
TABLES = (
    'CREATE TABLE m4_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version TEXT NOT NULL)',
    'CREATE TABLE m4_jobs(job_id TEXT PRIMARY KEY REFERENCES runtime_jobs(job_id),body TEXT NOT NULL)',
    'CREATE TABLE m4_receipts(job_id TEXT PRIMARY KEY REFERENCES m4_jobs(job_id),body TEXT NOT NULL)',
    'CREATE TABLE m4_candidates(candidate_id TEXT PRIMARY KEY REFERENCES baseline_candidates(candidate_id),job_id TEXT NOT NULL UNIQUE REFERENCES m4_jobs(job_id),body TEXT NOT NULL)',
    'CREATE TABLE m4_results(result_id TEXT PRIMARY KEY,job_id TEXT NOT NULL REFERENCES m4_jobs(job_id),body TEXT NOT NULL,diff BLOB)',
)
TRIGGERS = tuple(
    f"CREATE TRIGGER {table}_no_{op.lower()} BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT,'m4_append_only'); END"
    for table in ('m4_meta', 'm4_jobs', 'm4_receipts', 'm4_candidates', 'm4_results')
    for op in ('UPDATE', 'DELETE'))


def initialize(db_path, storage_root):
    repo = M1Repository(db_path, storage_root)
    with repo.write() as c:
        if not c.execute("SELECT 1 FROM sqlite_schema WHERE name='runtime_jobs'").fetchone():
            raise M1Error('RUNTIME_REQUIRED', 503)
        if c.execute("SELECT 1 FROM sqlite_schema WHERE name GLOB 'm4_*'").fetchone():
            raise M1Error('COMPARISON_ALREADY_INITIALIZED', 409)
        for sql in TABLES + TRIGGERS:
            c.execute(sql)
        c.execute('INSERT INTO m4_meta VALUES(1,?)', (VERSION,))


class ComparisonStore:
    def __init__(self, workspace):
        self.repo = workspace.repo
        with self.repo.read() as c:
            self.audit(c)

    @staticmethod
    def audit(c):
        sql = {r[0] for r in c.execute("SELECT sql FROM sqlite_schema WHERE name GLOB 'm4_*' AND sql IS NOT NULL")}
        if sql != set(TABLES + TRIGGERS) or [tuple(r) for r in c.execute('SELECT * FROM m4_meta')] != [(1, VERSION)]:
            raise M1Error('COMPARISON_SCHEMA_UNSUPPORTED', 503)

    def put(self, table, key, body, *, job_id=None, diff=None):
        if table not in ('jobs', 'receipts', 'candidates', 'results'):
            raise ValueError('fixed ledger table required')
        with self.repo.write() as c:
            self.audit(c)
            raw = self.repo.dump(body)
            if table == 'results':
                c.execute('INSERT INTO m4_results VALUES(?,?,?,?)', (key, job_id, raw, diff))
            elif table == 'candidates':
                c.execute('INSERT INTO m4_candidates VALUES(?,?,?)', (key, job_id, raw))
            else:
                c.execute(f'INSERT INTO m4_{table} VALUES(?,?)', (key, raw))

    def get(self, table, key):
        field = {'jobs': 'job_id', 'receipts': 'job_id', 'candidates': 'candidate_id', 'results': 'result_id'}.get(table)
        if field is None:
            raise ValueError('fixed ledger table required')
        with self.repo.read() as c:
            self.audit(c)
            row = c.execute(f'SELECT * FROM m4_{table} WHERE {field}=?', (key,)).fetchone()
        return dict(row) if row else None

    def rows(self, table, *, job_id=None, limit=100, offset=0):
        if table not in ('jobs', 'candidates', 'results'):
            raise ValueError('fixed ledger table required')
        if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or not 0 <= offset <= 10000:
            raise ValueError('bounded pagination required')
        with self.repo.read() as c:
            self.audit(c)
            rows = c.execute(f'SELECT * FROM m4_{table} WHERE (? IS NULL OR job_id=?) ORDER BY rowid DESC LIMIT ? OFFSET ?', (job_id, job_id, limit, offset)).fetchall()
        return [dict(r) for r in rows]

    def body(self, table, key):
        row = self.get(table, key)
        if row is None:
            raise M1Error('COMPARISON_NOT_FOUND', 404)
        return json.loads(row['body'])
