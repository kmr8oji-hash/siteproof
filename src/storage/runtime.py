"""Explicit additive M2 bindings in the SAME S1/M1 DB; never initialized by GET.

Bindings are append-only. S1 owns job/attempt/finalization state. This extension
pins declared profiles and M1 revisions; it provides no authenticity guarantee.
No migration, repair, deletion or artifact duplication is performed here.
"""
import json
from contextlib import contextmanager, closing

from src.storage.m1 import M1Repository, M1Error
from src.storage.repository import Repository
from src.storage.schema import connect


class ReadRepository(Repository):
    @contextmanager
    def _read(self):
        with closing(connect(self.db_path, read_only=True)) as conn:
            conn.execute('PRAGMA query_only=ON')
            yield conn


VERSION = 'siteproof.runtime.v1'
TABLES = (
    'CREATE TABLE runtime_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version TEXT NOT NULL)',
    'CREATE TABLE runtime_batches(batch_id TEXT PRIMARY KEY,body TEXT NOT NULL)',
    'CREATE TABLE runtime_runs(batch_id TEXT PRIMARY KEY REFERENCES runtime_batches(batch_id))',
    'CREATE TABLE runtime_jobs(job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),batch_id TEXT NOT NULL REFERENCES runtime_batches(batch_id),body TEXT NOT NULL)',
    'CREATE TABLE runtime_events(event_id INTEGER PRIMARY KEY,job_id TEXT NOT NULL REFERENCES runtime_jobs(job_id),body TEXT NOT NULL)',
)
TRIGGERS = tuple(
    f"CREATE TRIGGER {table}_no_{op.lower()} BEFORE {op} ON {table} BEGIN SELECT RAISE(ABORT,'runtime_append_only'); END"
    for table in ('runtime_meta', 'runtime_batches', 'runtime_runs', 'runtime_jobs', 'runtime_events')
    for op in ('UPDATE', 'DELETE'))


def initialize(db_path, storage_root):
    repo = M1Repository(db_path, storage_root)
    with repo.write() as c:
        if c.execute("SELECT 1 FROM sqlite_schema WHERE name GLOB 'runtime_*'").fetchone():
            raise M1Error('RUNTIME_ALREADY_INITIALIZED', 409)
        for sql in TABLES + TRIGGERS:
            c.execute(sql)
        c.execute('INSERT INTO runtime_meta VALUES(1,?)', (VERSION,))


class RuntimeStore:
    def __init__(self, workspace):
        self.workspace = workspace
        self.repo = workspace.repo
        with self.repo.read() as c:
            self.audit(c)

    @staticmethod
    def audit(c):
        rows = c.execute("SELECT sql FROM sqlite_schema WHERE name GLOB 'runtime_*' AND sql IS NOT NULL")
        if ({r[0] for r in rows} != set(TABLES + TRIGGERS)
                or [tuple(r) for r in c.execute('SELECT * FROM runtime_meta')] != [(1, VERSION)]):
            raise M1Error('RUNTIME_SCHEMA_UNSUPPORTED', 503)

    def snapshot(self, batch_id):
        with self.repo.write() as c:
            self.audit(c)
            site = c.execute('SELECT * FROM m1_site').fetchone()
            pages = [dict(r) for r in c.execute('SELECT * FROM m1_pages ORDER BY page_id')]
            profiles = [dict(r) for r in c.execute('SELECT p.* FROM m1_profiles p WHERE revision=(SELECT MAX(revision) FROM m1_profiles q WHERE q.page_id=p.page_id AND q.kind=p.kind) ORDER BY page_id,kind')]
            if site is None or not 1 <= len(pages) <= 5 or len(profiles) != 2 * len(pages):
                raise M1Error('RUNTIME_INPUT_INCOMPLETE')
            body = {'site': dict(site), 'pages': pages, 'profiles': profiles}
            c.execute('INSERT INTO runtime_batches VALUES(?,?)', (batch_id, self.repo.dump(body)))
        return body

    def bind(self, job_id, batch_id, body):
        with self.repo.write() as c:
            self.audit(c)
            c.execute('INSERT INTO runtime_jobs VALUES(?,?,?)', (job_id, batch_id, self.repo.dump(body)))

    def claim(self, batch_id):
        with self.repo.write() as c:
            self.audit(c)
            if c.execute('SELECT 1 FROM runtime_runs WHERE batch_id=?', (batch_id,)).fetchone():
                raise M1Error('RUNTIME_ALREADY_STARTED', 409)
            c.execute('INSERT INTO runtime_runs VALUES(?)', (batch_id,))

    def event(self, job_id, body):
        with self.repo.write() as c:
            self.audit(c)
            c.execute('INSERT INTO runtime_events(job_id,body) VALUES(?,?)', (job_id, self.repo.dump(body)))

    def bindings(self, batch_id=None):
        with self.repo.read() as c:
            self.audit(c)
            rows = c.execute('SELECT * FROM runtime_jobs WHERE (? IS NULL OR batch_id=?) ORDER BY rowid DESC LIMIT 100', (batch_id, batch_id)).fetchall()
        return [(r['job_id'], r['batch_id'], json.loads(r['body'])) for r in rows]

    def events(self, job_id):
        with self.repo.read() as c:
            self.audit(c)
            return [json.loads(r[0]) for r in c.execute('SELECT body FROM runtime_events WHERE job_id=? ORDER BY event_id DESC LIMIT 10', (job_id,))]
