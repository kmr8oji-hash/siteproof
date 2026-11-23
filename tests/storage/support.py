"""Shared helpers for storage tests. Everything lives in a per-test temp directory."""
import itertools
import os
import tempfile
import unittest
from pathlib import Path

from src.core.frames import KIND_TO_CHECK_TYPE, CheckType, FrameKind
from src.core.model import CheckOutcome, JobIntent, JobStatus
from src.core.synthetic import default_record_payload, make_frame, make_summary
from src.storage.artifacts import ArtifactStore
from src.storage.failpoints import Failpoints
from src.storage.finalizer import EvidenceFinalizer
from src.storage.repository import Repository
from src.storage.schema import connect

HTTP, LOAD, CAPTURE = CheckType.HTTP, CheckType.LOAD, CheckType.CAPTURE
K = FrameKind
O = CheckOutcome
ALL_CHECKS = (HTTP, LOAD, CAPTURE)


def make_intent(checks=ALL_CHECKS, baseline="base-1", url="https://example.invalid/"):
    return JobIntent(url, "page-1", "desktop", checks, baseline)


class StorageTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="siteproof-s1-test-")
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.db_path = str(self.base / "db" / "siteproof.sqlite3")
        os.makedirs(self.base / "db")
        self.evidence_root = self.base / "evidence"
        self.fp = Failpoints()
        counter = itertools.count(1)
        self.repo = Repository(self.db_path, id_factory=lambda: f"job-{next(counter):03d}",
                               failpoints=self.fp)
        self.repo.init()
        self.store = ArtifactStore(self.evidence_root, failpoints=self.fp)
        self.finalizer = EvidenceFinalizer(self.repo, self.store, failpoints=self.fp)

    # ---- builders -------------------------------------------------------
    def raw(self):
        conn = connect(self.db_path)
        self.addCleanup(conn.close)
        return conn

    def new_job(self, key="key-1", **kw):
        return self.repo.accept_job(key, make_intent(**kw)).job

    def start_saving(self, job, attempt_id="att-1", epoch=1):
        """ACCEPTED -> ... -> SAVING with a synthetic attempt (no worker is launched)."""
        att = self.repo.register_attempt(job.job_id, attempt_id, epoch)
        rec = job
        for st in (JobStatus.WAITING_WORKER, JobStatus.RUNNING, JobStatus.SAVING):
            rec = self.repo.transition(rec.job_id, rec.version, st)
        return rec, att

    def frames(self, job, att, kinds, *, start_seq=0, payloads=None, **overrides):
        """Synthetic frames, seq from `start_seq`. Record payloads default to a valid
        'observed' record matching the job's baseline state; `payloads` maps kind -> bytes."""
        baseline_set = job.snapshot.baseline_id is not None
        out = []
        for i, kind in enumerate(kinds):
            args = dict(job_id=job.job_id, attempt_id=att.attempt_id,
                        lease_epoch=att.lease_epoch, seq=start_seq + i, kind=kind,
                        page_id="page-1", profile_id="desktop")
            args.update(overrides)
            payload = (payloads or {}).get(kind)
            if payload is None:
                payload = default_record_payload(kind, baseline_set=baseline_set)
            out.append(make_frame(payload=payload, **args))
        return out

    def finalize(self, job, att, frames, reports=None, summary=None):
        return self.finalizer.finalize(job.job_id, att.attempt_id, frames,
                                       summary or make_summary(frames), reports)

    ALL_KINDS = (K.HTTP_RECORD, K.LOAD_RECORD, K.CAPTURE_RECORD, K.SCREENSHOT_PNG)
    RECORD_KINDS = (K.HTTP_RECORD, K.LOAD_RECORD, K.CAPTURE_RECORD)

    def run_complete(self, key="key-1", checks=ALL_CHECKS, baseline="base-1"):
        """A fully consistent job. With CAPTURE required, the capture is UNKNOWN (first
        capture / comparison not run), so quality can be PASS only for HTTP+LOAD jobs."""
        job = self.new_job(key, checks=checks, baseline=baseline)
        job, att = self.start_saving(job)
        kinds = [k for k in self.ALL_KINDS if KIND_TO_CHECK_TYPE[k] in checks]
        fr = self.frames(job, att, kinds)
        return job, att, fr, self.finalize(job, att, fr)

    def evidence_files(self):
        if not self.evidence_root.exists():
            return []
        return sorted(p.relative_to(self.evidence_root).as_posix()
                      for p in self.evidence_root.rglob("*") if p.is_file())
