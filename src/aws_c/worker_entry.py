"""AWS-C worker entry: one fixture-only run on a single-use EC2 instance.

Sequence (the bootstrap script arms the OS shutdown timer BEFORE this starts and shuts
the instance down AFTER it returns, whatever it returns):

    start gate   control record must be RESERVED for this run and the deadline must leave
                 enough time; otherwise nothing is launched
    isolation    the existing validation harness (tests/runtime/validate.py) runs through
                 the Linux launcher adapter: measured preflight before Chromium, then
                 controlled-fixture captures into the existing SQLite/S1 store
    evidence     local re-verification, write-once publication to S3, run manifest last
    journal      control record updated; a journal failure never blocks publication

Scope of this entry is the controlled fixture only. Capturing an owner-operated real site
on AWS is a later, separately approved step and is not implemented here.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from src.aws_b.model import format_utc, parse_utc
from src.core.model import validate_id

from . import control
from .evidence import publish_run, verify_local

MIN_RUNTIME_SECONDS = 15 * 60
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_REPORT_FILES = 200


@dataclass
class Deps:
    pilot_run_id: str
    hard_deadline: datetime
    evidence_dir: Path
    store: Any                                   # control.ControlStore
    publisher: Any                               # s3_publisher.S3Publisher
    signer: Any                                  # signer.Signer
    harness: Callable[[Path], None]              # runs the fixture harness; may raise
    now: Callable[[], datetime]
    source: dict[str, Any] = field(default_factory=dict)
    log: Callable[[str], None] = lambda message: None


def _reports(evidence_dir: Path) -> dict[str, bytes]:
    """Top-level harness JSON reports. Logs, keys and certificates are not collected."""
    found: dict[str, bytes] = {}
    if not evidence_dir.is_dir():
        return found
    for path in sorted(evidence_dir.glob("*.json"))[:MAX_REPORT_FILES]:
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_REPORT_BYTES:
            found[path.name] = path.read_bytes()
    return found


def _harness_result(evidence_dir: Path) -> tuple[bool, bool]:
    """(harness passed, isolation preflight passed) from the harness's own report."""
    try:
        report = json.loads((evidence_dir / "validation-result.json").read_text("utf-8"))
        preflight = report.get("preflight", {})
        isolation = (preflight.get("passed") is True
                     and all(v == 0 for v in preflight.get("canary_zero", {"x": 1}).values()))
        return report.get("passed") is True, isolation
    except (OSError, ValueError, AttributeError):
        return False, False


def run_pilot(deps: Deps) -> dict[str, Any]:
    out: dict[str, Any] = {"pilot_run_id": deps.pilot_run_id, "harness_started": False,
                           "journal": []}

    def journal(source: str, target: str, version: int, detail: str = "") -> tuple[str, int]:
        result = deps.store.transition(deps.pilot_run_id, source, target, version,
                                       format_utc(deps.now()), detail)
        out["journal"].append(f"{source}->{target}:{result.reason}")
        return (target, result.version) if result.ok else (source, version)

    current = deps.store.read(deps.pilot_run_id)
    if not current.ok or current.state != control.RESERVED:
        out.update(outcome="NOT_RESERVED", control_reason=current.reason,
                   control_state=current.state)
        return out
    remaining = (deps.hard_deadline - deps.now()).total_seconds()
    if remaining < MIN_RUNTIME_SECONDS:
        out.update(outcome="INSUFFICIENT_TIME", remaining_seconds=int(remaining))
        return out
    started = deps.store.transition(deps.pilot_run_id, control.RESERVED, control.RUNNING,
                                    current.version, format_utc(deps.now()), "worker boot")
    if not started.ok:
        # Another actor changed the record, or the write is uncertain: do not run.
        out.update(outcome="START_NOT_CONFIRMED", control_reason=started.reason)
        return out
    state, version = control.RUNNING, started.version

    out["harness_started"] = True
    try:
        deps.harness(deps.evidence_dir)
        out["harness_error"] = None
    except Exception as exc:
        out["harness_error"] = type(exc).__name__
        deps.log("harness failed: " + type(exc).__name__)
    passed, isolation = _harness_result(deps.evidence_dir)
    out.update(harness_passed=passed, isolation_passed=isolation)
    if isolation:
        state, version = journal(state, control.ISOLATION_PASSED, version)
    else:
        state, version = journal(state, control.ISOLATION_FAILED, version,
                                 out["harness_error"] or "preflight not passed")

    # Evidence is published whatever happened above: a failed run is evidence too.
    export = deps.evidence_dir / "s1"
    database = export / "siteproof.sqlite"
    verification = (verify_local(database, export) if database.is_file() else
                    {"status": "UNVERIFIED",
                     "findings": [{"code": "DATABASE_MISSING", "subject": "", "detail": ""}]})
    summary = publish_run(
        deps.publisher, deps.signer, pilot_run_id=deps.pilot_run_id, export_root=export,
        verification=verification, created_at=format_utc(deps.now()), source=deps.source,
        extra=_reports(deps.evidence_dir))
    out["publication"] = summary

    success = passed and isolation and summary["committed"]
    if state == control.ISOLATION_PASSED:
        journal(state, control.EVIDENCE_COMMITTED if success else control.FAILED, version,
                "" if success else "evidence not committed or harness failed")
    out["outcome"] = "EVIDENCE_COMMITTED" if success else (
        "ISOLATION_FAILED" if not isolation else "FAILED")
    return out


def run_validation_harness(evidence_dir: Path, *, image: str, docker: str) -> None:
    """Run the unmodified M2 harness with the Linux launcher substituted for the
    Windows Docker Desktop launcher. Requires a local Docker engine: NOT RUN offline."""
    import tests.runtime.validate as validate
    from .linux_launcher import LinuxDockerLauncher

    original_launcher, original_argv = validate.DockerLauncher, sys.argv
    validate.DockerLauncher = lambda evidence, image_name, seccomp: LinuxDockerLauncher(
        evidence, image_name, seccomp, docker=docker)
    sys.argv = ["validate", "--evidence", str(evidence_dir), "--image", image]
    try:
        validate.main()
    finally:
        validate.DockerLauncher, sys.argv = original_launcher, original_argv


def main() -> int:
    env = os.environ
    run_id = validate_id(env.get("PILOT_RUN_ID"), "PILOT_RUN_ID")
    deadline = parse_utc(env.get("HARD_DEADLINE_UTC"))
    if deadline is None:
        print("HARD_DEADLINE_UTC invalid", file=sys.stderr)
        return 2
    import boto3  # installed on the worker host by the bootstrap; never imported offline
    from botocore.config import Config
    from .s3_publisher import S3Publisher
    from .signer import KmsSigner, UnsignedSigner

    options = Config(connect_timeout=3, read_timeout=20,
                     retries={"total_max_attempts": 3, "mode": "standard"})
    key_id = env.get("SIGNING_KEY_ID")
    signer = KmsSigner(boto3.client("kms", config=options), key_id) if key_id else UnsignedSigner()
    evidence_dir = Path(env.get("EVIDENCE_DIR", "/var/lib/siteproof/evidence"))
    deps = Deps(
        pilot_run_id=run_id, hard_deadline=deadline, evidence_dir=evidence_dir,
        store=control.ControlStore(boto3.client("dynamodb", config=options), env["TABLE_NAME"]),
        publisher=S3Publisher(boto3.client("s3", config=options), env["EVIDENCE_BUCKET"],
                              f"runs/{run_id}/"),
        signer=signer,
        harness=lambda directory: run_validation_harness(
            directory, image=env["RUNTIME_IMAGE"], docker=env.get("DOCKER_BIN", "/usr/bin/docker")),
        now=lambda: datetime.now(timezone.utc),
        source={"bundle_sha256": env.get("BUNDLE_SHA256"), "runtime_image": env.get("RUNTIME_IMAGE")},
        log=lambda message: print(message, file=sys.stderr, flush=True))
    result = run_pilot(deps)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("outcome") == "EVIDENCE_COMMITTED" else 1


if __name__ == "__main__":
    sys.exit(main())
