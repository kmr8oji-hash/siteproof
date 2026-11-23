"""Offline helpers for AWS-C tests: a real S1 export built with the existing storage code."""
import itertools
import json
from datetime import datetime, timezone
from pathlib import Path

from src.core.frames import KIND_TO_CHECK_TYPE, CheckType, FrameKind
from src.core.model import JobIntent, JobStatus
from src.core.synthetic import default_record_payload, make_frame, make_summary
from src.storage.artifacts import ArtifactStore
from src.storage.finalizer import EvidenceFinalizer
from src.storage.repository import Repository

T0 = datetime(2026, 12, 1, 2, 0, 0, tzinfo=timezone.utc)
DEADLINE = "2026-12-01T03:00:00Z"
RUN_ID = "pilot-20261201-a"
KINDS = (FrameKind.HTTP_RECORD, FrameKind.LOAD_RECORD, FrameKind.CAPTURE_RECORD,
         FrameKind.SCREENSHOT_PNG)
CHECKS = (CheckType.HTTP, CheckType.LOAD, CheckType.CAPTURE)


def make_export(export_root, jobs=2):
    """Create <export_root>/siteproof.sqlite plus completed job evidence, exactly as the
    existing Repository / EvidenceFinalizer write them. Returns the job ids."""
    root = Path(export_root)
    root.mkdir(parents=True, exist_ok=True)
    counter = itertools.count(1)
    repo = Repository(str(root / "siteproof.sqlite"),
                      id_factory=lambda: "job-%03d" % next(counter))
    repo.init()
    finalizer = EvidenceFinalizer(repo, ArtifactStore(root))
    job_ids = []
    for index in range(jobs):
        intent = JobIntent("https://fixture.invalid/", "page-1",
                           "desktop" if index == 0 else "mobile", CHECKS, None)
        job = repo.accept_job("key-%d" % index, intent).job
        attempt = repo.register_attempt(job.job_id, "capture-1", 1)
        for status in (JobStatus.WAITING_WORKER, JobStatus.RUNNING, JobStatus.SAVING):
            job = repo.transition(job.job_id, job.version, status)
        frames = [make_frame(payload=default_record_payload(kind, baseline_set=False),
                             job_id=job.job_id, attempt_id=attempt.attempt_id,
                             lease_epoch=attempt.lease_epoch, seq=seq, kind=kind,
                             page_id=intent.page_id, profile_id=intent.profile_id)
                  for seq, kind in enumerate(KINDS) if KIND_TO_CHECK_TYPE[kind] in CHECKS]
        finalizer.finalize(job.job_id, attempt.attempt_id, frames, make_summary(frames), None)
        job_ids.append(job.job_id)
    return job_ids


def write_validation_result(evidence_dir, passed=True, isolation=True, leak=0):
    keys = ("tcp", "dns", "udp", "metadata", "lan", "host_model", "ipv6")
    report = {"task": "SITEPROOF-M2-RUNTIME-VALIDATION-01", "passed": passed,
              "preflight": {"passed": isolation, "netns": "net:[4026532999]",
                            "canary_positive": {k: 1 for k in keys},
                            "canary_zero": {k: (leak if k == "metadata" else 0) for k in keys}},
              "profile_trust": "UNATTESTED", "quality": "UNKNOWN"}
    path = Path(evidence_dir)
    path.mkdir(parents=True, exist_ok=True)
    (path / "validation-result.json").write_text(json.dumps(report), encoding="utf-8")
    (path / "preflight.json").write_text(json.dumps(report["preflight"]), encoding="utf-8")
    (path / "worker-stderr.log").write_text("not collected", encoding="utf-8")
    return report
