"""Lane B per-test SQLite/artifact isolation, with no workers or sockets."""

import io
import itertools
from pathlib import Path
import tempfile
import unittest

from src.bridge import EvidenceBridge
from src.core.frames import CheckType
from src.core.model import JobIntent, JobStatus
from src.storage.artifacts import ArtifactStore
from src.storage.failpoints import Failpoints
from src.storage.finalizer import EvidenceFinalizer
from src.storage.repository import Repository
from tests.integration.fixtures import stream


class IntegrationCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="siteproof-int01-lane-b-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.fp = Failpoints()
        self.ids = itertools.count(1)
        self.repo = Repository(self.base / "lane-b.sqlite3",
                               id_factory=lambda: f"job-{next(self.ids)}", failpoints=self.fp)
        self.repo.init()
        self.store = ArtifactStore(self.base / "evidence", failpoints=self.fp)
        self.finalizer = EvidenceFinalizer(self.repo, self.store, failpoints=self.fp)
        self.bridge = EvidenceBridge(self.finalizer)

    def job(self, checks=tuple(CheckType), baseline=None, *, saving=True):
        intent = JobIntent("https://fixture.invalid/", "page-1", "profile-1", checks, baseline)
        job = self.repo.accept_job(f"key-{next(self.ids)}", intent).job
        attempt = self.repo.register_attempt(job.job_id, "attempt-1", 1)
        if saving:
            for status in (JobStatus.WAITING_WORKER, JobStatus.RUNNING, JobStatus.SAVING):
                job = self.repo.transition(job.job_id, job.version, status)
        return job, attempt

    def run_wire(self, job, attempt, items, **kwargs):
        return self.bridge.finalize(job.job_id, attempt.attempt_id, io.BytesIO(stream(items)), **kwargs)

    def assert_no_adoption(self, job, attempt):
        self.assertIsNone(self.repo.get_job(job.job_id).adopted_attempt_id)
        self.assertEqual(self.repo.list_check_results(job.job_id), [])
        self.assertEqual(self.repo.list_artifacts(job.job_id, attempt.attempt_id), [])
        self.assertIsNone(self.repo.get_manifest_row(job.job_id, attempt.attempt_id))

    def assert_no_files(self):
        self.assertEqual([p for p in self.store.root.rglob("*") if p.is_file()], [])
