"""Verify a finished worker's local S1 export and publish it to S3 as one pilot run.

The worker keeps using the existing SQLite store, write-once artifact files and
manifest.json unchanged. This module adds nothing to those formats. It

  1. re-verifies the export with the existing read-only planner
     (src/storage/recovery.plan_recovery: DB rows vs manifest vs file hashes),
  2. publishes every file as-is, write-once, including after a failed verification
     (failed runs are evidence too), and
  3. publishes a run manifest last, listing each object's SHA-256 and the verification
     result. A run manifest that is absent means the run's evidence is not committed.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Optional

from src.core.model import canonical_json
from src.storage.recovery import plan_recovery

from .s3_publisher import MAX_OBJECT_BYTES, S3Publisher
from .signer import Signer

RUN_MANIFEST_SCHEMA = "siteproof.awsc.run-manifest.v1"
RUN_MANIFEST_NAME = "run-manifest.json"
SIGNATURE_NAME = "run-manifest.sig.json"
MAX_FILES = 2000
_DB_SIDE_FILES = ("", "-wal", "-shm", "-journal")


def collect(root: str | os.PathLike[str]) -> tuple[list[tuple[str, Path]], list[str]]:
    """Regular files under root as (posix relative name, path). Links are refused."""
    base = Path(root)
    files: list[tuple[str, Path]] = []
    problems: list[str] = []
    if not base.is_dir():
        return files, ["EXPORT_ROOT_MISSING"]
    for path in sorted(base.rglob("*")):
        relative = path.relative_to(base).as_posix()
        if path.is_symlink():
            problems.append("LINK_REFUSED:" + relative)
        elif path.is_file():
            if len(files) >= MAX_FILES:
                problems.append("TOO_MANY_FILES")
                break
            files.append((relative, path))
    return files, problems


def verify_local(db_path: str | os.PathLike[str], evidence_root: str | os.PathLike[str]
                 ) -> dict[str, Any]:
    """CONSISTENT only if the existing planner reports nothing but the database itself."""
    root, db = Path(evidence_root).resolve(), Path(db_path).resolve()
    tolerated = set()
    if root == db.parent or root in db.parents:
        name = db.relative_to(root).as_posix()
        tolerated = {name + suffix for suffix in _DB_SIDE_FILES}
    try:
        report = plan_recovery(str(db), str(root))
    except Exception as exc:
        return {"status": "UNVERIFIED", "findings": [
            {"code": "VERIFY_ERROR", "subject": "", "detail": type(exc).__name__}]}
    findings = [{"code": f.code, "subject": f.subject, "detail": f.detail[:300]}
                for f in report.findings
                if not (f.code == "ORPHAN_FILE" and f.subject in tolerated)]
    return {"status": "CONSISTENT" if not findings else "INCONSISTENT", "findings": findings}


def _entry(name: str, data: bytes, result: Any) -> dict[str, Any]:
    """Manifest row. Identical for a first publication and an idempotent re-run, so a
    repeated run produces byte-identical manifest content."""
    entry = {"name": name, "sha256": hashlib.sha256(data).hexdigest(),
             "byte_length": len(data), "published": result.ok}
    if not result.ok:
        entry["status"] = result.status
    return entry


def publish_run(publisher: S3Publisher, signer: Signer, *, pilot_run_id: str,
                export_root: str | os.PathLike[str], verification: dict[str, Any],
                created_at: str, source: Optional[dict[str, Any]] = None,
                extra: Optional[dict[str, bytes]] = None) -> dict[str, Any]:
    """Publish files, then the run manifest, then its signature. Returns a summary.

    `committed` is True only when every file and the manifest were published (or already
    present with identical bytes) and the local verification was CONSISTENT.
    """
    files, problems = collect(export_root)
    objects: list[dict[str, Any]] = []
    for relative, path in files:
        try:
            if path.stat().st_size > MAX_OBJECT_BYTES:
                raise ValueError("too large")
            data = path.read_bytes()
        except (OSError, ValueError) as exc:
            objects.append({"name": "s1/" + relative, "published": False,
                            "status": "UNREADABLE", "error": type(exc).__name__})
            continue
        objects.append(_entry("s1/" + relative, data,
                              publisher.publish("s1/" + relative, data)))
    for name, data in sorted((extra or {}).items()):
        objects.append(_entry("run/" + name, data, publisher.publish("run/" + name, data)))

    all_published = bool(objects) and all(o["published"] for o in objects) and not problems
    document = {
        "schema": RUN_MANIFEST_SCHEMA,
        "pilot_run_id": pilot_run_id,
        "created_at": created_at,
        "source": source or {},
        "local_verification": verification,
        "collection_problems": problems,
        "objects": objects,
        "all_objects_published": all_published,
        # Fixed statements: publication proves storage integrity, nothing about rendering.
        "claims": {"quality": "UNKNOWN", "profile_trust": "PROFILE_UNATTESTED",
                   "target_scope": "CONTROLLED_FIXTURE_ONLY"},
    }
    manifest_bytes = canonical_json(document).encode("utf-8")
    manifest = publisher.publish(RUN_MANIFEST_NAME, manifest_bytes,
                                 content_type="application/json")
    envelope = signer.sign(manifest_bytes)
    signature = publisher.publish(SIGNATURE_NAME, canonical_json(envelope).encode("utf-8"),
                                  content_type="application/json")
    committed = (all_published and manifest.ok
                 and verification.get("status") == "CONSISTENT")
    return {"committed": committed, "all_objects_published": all_published,
            "manifest_status": manifest.status,
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "signature_status": envelope.get("status"),
            "signature_object_status": signature.status,
            "verification_status": verification.get("status"),
            "object_count": len(objects), "problems": problems,
            "failed_objects": [o["name"] for o in objects if not o["published"]]}
