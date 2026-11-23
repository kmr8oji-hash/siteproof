"""Manifest build / parse / consistency verification.

Every verifier here treats the manifest (and the files it names) as untrusted input: any
malformed value must surface as a *reported problem*, never as an unexpected exception.
"""
from __future__ import annotations

import json
from typing import Any, Collection, Optional, Sequence

from ..core.errors import EvidenceMismatch, SiteProofError, ValidationError
from ..core.frames import KIND_TO_CHECK_TYPE, CheckType, FrameKind
from ..core.model import (AttemptRef, CheckOutcome, CheckReport, CheckResult, JobSnapshot,
                          canonical_json, sha256_hex)
from ..core.records import RECORD_KINDS, derive_report, parse_record, validate_skips
from ..core.rules import (REASON_BASELINE_PENDING, REASON_COMPARISON_NOT_RUN, derive_quality,
                          required_artifact_kinds, validate_report)
from .artifacts import ArtifactStore
from .repository import ArtifactRow, ManifestRow

MANIFEST_SCHEMA_VERSION = "siteproof.manifest.v0.1"
MANIFEST_NAME = "manifest.json"


def build_manifest(snapshot: JobSnapshot, attempt: AttemptRef,
                   results: Sequence[CheckResult], artifacts: Sequence[ArtifactRow]
                   ) -> dict[str, Any]:
    outcomes = {r.check_type: r.outcome for r in results}
    quality = derive_quality(snapshot.required_checks, outcomes)
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "job_id": snapshot.job_id,
        "attempt_id": attempt.attempt_id,
        "lease_epoch": attempt.lease_epoch,
        "intent_hash": snapshot.intent.intent_hash,
        "snapshot_sha256": snapshot.sha256,
        "page_id": snapshot.page_id,
        "profile_id": snapshot.profile_id,
        "baseline_id": snapshot.baseline_id,
        "required_checks": [c.value for c in snapshot.required_checks],
        "checks": [
            {"check_type": r.check_type.value, "outcome": r.outcome.value,
             "reason_code": r.reason_code,
             "artifact_seqs": sorted(a.seq for a in artifacts if a.check_type is r.check_type)}
            for r in sorted(results, key=lambda r: r.check_type.value)],
        "artifacts": [
            {"seq": a.seq, "kind": a.kind.value, "check_type": a.check_type.value,
             "rel_path": a.rel_path, "sha256": a.sha256, "byte_length": a.byte_length}
            for a in sorted(artifacts, key=lambda a: a.seq)],
        "quality": quality.value,
    }


def manifest_bytes(doc: dict[str, Any]) -> bytes:
    return canonical_json(doc).encode("utf-8")


def _is_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def verify_manifest_document(doc: Any, snapshot: JobSnapshot, attempt: AttemptRef
                             ) -> list[str]:
    """Return a list of problems (empty == consistent). Never trusts the document and never
    lets a domain/type exception escape."""
    p: list[str] = []
    if not isinstance(doc, dict):
        return ["MANIFEST_NOT_OBJECT"]
    try:
        if doc.get("schema_version") != MANIFEST_SCHEMA_VERSION:
            p.append("MANIFEST_SCHEMA_VERSION")
        for key, want in (("job_id", snapshot.job_id), ("attempt_id", attempt.attempt_id),
                          ("lease_epoch", attempt.lease_epoch),
                          ("intent_hash", snapshot.intent.intent_hash),
                          ("snapshot_sha256", snapshot.sha256), ("page_id", snapshot.page_id),
                          ("profile_id", snapshot.profile_id),
                          ("baseline_id", snapshot.baseline_id)):
            if doc.get(key) != want:
                p.append(f"MANIFEST_FIELD_MISMATCH:{key}")
        if doc.get("required_checks") != [c.value for c in snapshot.required_checks]:
            p.append("MANIFEST_FIELD_MISMATCH:required_checks")
        if not isinstance(doc.get("artifacts"), list) or not isinstance(doc.get("checks"), list):
            return p + ["MANIFEST_MALFORMED:artifacts_or_checks_not_list"]

        arts: dict[int, tuple[FrameKind, CheckType]] = {}
        for a in doc["artifacts"]:
            if not isinstance(a, dict):
                p.append("MANIFEST_MALFORMED:artifact_not_object")
                continue
            if not _is_int(a["seq"]):
                p.append("ARTIFACT_FIELDS_INVALID:seq")
                continue
            kind = FrameKind(a["kind"])
            ct = CheckType(a["check_type"])
            if KIND_TO_CHECK_TYPE[kind] is not ct:
                p.append(f"ARTIFACT_KIND_CHECK_MISMATCH:{a['seq']}")
            if not str(a["rel_path"]).startswith(f"{snapshot.job_id}/{attempt.attempt_id}/"):
                p.append(f"ARTIFACT_PATH_OUTSIDE_ATTEMPT:{a['seq']}")
            if a["seq"] in arts:
                p.append(f"ARTIFACT_DUPLICATE_SEQ:{a['seq']}")
            if not (isinstance(a["sha256"], str) and len(a["sha256"]) == 64
                    and _is_int(a["byte_length"]) and a["byte_length"] >= 0):
                p.append(f"ARTIFACT_FIELDS_INVALID:{a['seq']}")
            arts[a["seq"]] = (kind, ct)

        outcomes: dict[CheckType, CheckOutcome] = {}
        reports: dict[CheckType, CheckReport] = {}
        for chk in doc["checks"]:
            if not isinstance(chk, dict):
                p.append("MANIFEST_MALFORMED:check_not_object")
                continue
            ct = CheckType(chk["check_type"])
            oc = CheckOutcome(chk["outcome"])
            if ct in outcomes:
                p.append(f"CHECK_DUPLICATE:{ct.value}")
            outcomes[ct] = oc
            reason = chk["reason_code"]
            if not isinstance(reason, str) or not reason.strip():
                p.append(f"CHECK_REASON_EMPTY:{ct.value}")
                continue
            try:
                reports[ct] = CheckReport(ct, oc, reason)
            except ValidationError:
                p.append(f"CHECK_REASON_INVALID:{ct.value}")
            if ct not in snapshot.required_checks:
                p.append(f"CHECK_NOT_REQUIRED:{ct.value}")
                continue
            seqs = chk["artifact_seqs"]
            if not isinstance(seqs, list) or any(not _is_int(s) for s in seqs):
                p.append(f"CHECK_ARTIFACT_REF_INVALID:{ct.value}")
                continue
            if any(s not in arts or arts[s][1] is not ct for s in seqs):
                p.append(f"CHECK_ARTIFACT_REF_INVALID:{ct.value}")
            kinds = {arts[s][0] for s in seqs if s in arts}
            try:
                missing = required_artifact_kinds(ct, oc, reason) - kinds
            except SiteProofError as e:
                p.append(f"CHECK_OUTCOME_INVALID:{ct.value}:{getattr(e, 'code', 'ERR')}")
                continue
            if missing:
                p.append(f"CHECK_ARTIFACT_MISSING:{ct.value}:"
                         + ",".join(sorted(k.value for k in missing)))
            if ct in reports:
                try:
                    # Include every artifact for this check, even an image omitted from
                    # artifact_seqs. Recovery must enforce the live finalizer's policy.
                    validate_report(reports[ct], baseline_id=snapshot.baseline_id,
                                    kinds_present=[k for k, c in arts.values() if c is ct])
                except SiteProofError as e:
                    p.append(f"CHECK_EVIDENCE_INVALID:{ct.value}:{e.code}")
            if ct is CheckType.CAPTURE:
                if oc in (CheckOutcome.PASS, CheckOutcome.CHANGED):
                    p.append("CAPTURE_COMPARISON_UNTRUSTED")  # no trusted comparison exists
                if reason == REASON_BASELINE_PENDING and snapshot.baseline_id is not None:
                    p.append("CAPTURE_REASON_BASELINE_MISMATCH")
                if reason == REASON_COMPARISON_NOT_RUN and snapshot.baseline_id is None:
                    p.append("CAPTURE_REASON_BASELINE_MISMATCH")
        for ct in snapshot.required_checks:
            if ct not in outcomes:
                p.append(f"REQUIRED_CHECK_MISSING:{ct.value}")
        try:
            validate_skips(reports)
        except SiteProofError as e:
            p.append(f"SKIP_NOT_JUSTIFIED:{e.detail if hasattr(e, 'detail') else e}")
        if doc.get("quality") != derive_quality(snapshot.required_checks, outcomes).value:
            p.append("MANIFEST_QUALITY_MISMATCH")
    except (KeyError, TypeError, ValueError, AttributeError, SiteProofError) as e:
        p.append(f"MANIFEST_MALFORMED:{type(e).__name__}")
    return p


def verify_stored(store: ArtifactStore, manifest_rel_path: str, expected_sha256: Optional[str],
                  snapshot: JobSnapshot, attempt: AttemptRef, *,
                  expected_length: Optional[int] = None) -> dict[str, Any]:
    """Read manifest + every artifact back from disk and verify. Raises EvidenceMismatch.

    Beyond hashes, the record artifacts are re-parsed and the check outcomes they support
    must equal the manifest's checks.
    """
    try:
        raw = store.read_bytes(manifest_rel_path)
    except (OSError, ValueError, SiteProofError) as e:
        raise EvidenceMismatch(f"MANIFEST_UNREADABLE:{manifest_rel_path}: {e}") from e
    if expected_sha256 is not None and sha256_hex(raw) != expected_sha256:
        raise EvidenceMismatch("MANIFEST_HASH_MISMATCH")
    if expected_length is not None and len(raw) != expected_length:
        raise EvidenceMismatch("MANIFEST_LENGTH_MISMATCH")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise EvidenceMismatch("MANIFEST_NOT_JSON") from e
    problems = verify_manifest_document(doc, snapshot, attempt)
    if problems:
        raise EvidenceMismatch("; ".join(problems))
    derived: dict[CheckType, CheckReport] = {}
    for a in doc["artifacts"]:
        try:
            data = store.read_bytes(a["rel_path"])
        except (OSError, ValueError, SiteProofError) as e:
            raise EvidenceMismatch(f"ARTIFACT_MISSING:{a['rel_path']}") from e
        if len(data) != a["byte_length"]:
            raise EvidenceMismatch(f"ARTIFACT_LENGTH_MISMATCH:{a['rel_path']}")
        if sha256_hex(data) != a["sha256"]:
            raise EvidenceMismatch(f"ARTIFACT_HASH_MISMATCH:{a['rel_path']}")
        kind = FrameKind(a["kind"])
        if kind in RECORD_KINDS:
            try:
                derived[CheckType(a["check_type"])] = derive_report(
                    parse_record(kind, data), snapshot)
            except SiteProofError as e:
                raise EvidenceMismatch(f"RECORD_INVALID:{a['rel_path']}:{e}") from e
    try:
        validate_skips(derived)
    except SiteProofError as e:
        raise EvidenceMismatch(f"RECORD_SKIP_NOT_JUSTIFIED:{e}") from e
    stored = {c["check_type"]: (c["outcome"], c["reason_code"]) for c in doc["checks"]}
    want = {ct.value: (r.outcome.value, r.reason_code) for ct, r in derived.items()}
    if stored != want:
        raise EvidenceMismatch(f"RECORD_MANIFEST_MISMATCH:manifest={stored} records={want}")
    return doc


def verify_published(store: ArtifactStore, rows: Sequence[ArtifactRow], manifest: ManifestRow,
                     snapshot: JobSnapshot, attempt: AttemptRef) -> dict[str, Any]:
    """Re-read and re-hash everything that was published and compare it with the values
    held in memory (not just with what the manifest says about itself)."""
    doc = verify_stored(store, manifest.rel_path, manifest.sha256, snapshot, attempt,
                        expected_length=manifest.byte_length)
    expected = {(r.seq, r.kind.value, r.check_type.value, r.rel_path, r.sha256, r.byte_length)
                for r in rows}
    got = {(a["seq"], a["kind"], a["check_type"], a["rel_path"], a["sha256"],
            a["byte_length"]) for a in doc["artifacts"]}
    if expected != got:
        raise EvidenceMismatch("PUBLISHED_ARTIFACTS_DIFFER_FROM_EXPECTED")
    return doc


def compare_with_db(doc: dict[str, Any], snapshot: JobSnapshot,
                    results: Sequence[CheckResult], artifacts: Sequence[ArtifactRow],
                    required_db: Collection[CheckType]) -> list[str]:
    """Problems where SQLite rows and a (already self-consistent) manifest disagree."""
    p: list[str] = []
    snap_required = {c.value for c in snapshot.required_checks}
    if {c.value for c in required_db} != snap_required:
        p.append("REQUIRED_CHECK_SET_MISMATCH:db_vs_snapshot")
    if set(doc["required_checks"]) != snap_required:
        p.append("REQUIRED_CHECK_SET_MISMATCH:manifest_vs_snapshot")
    if {r.check_type.value for r in results} != snap_required:
        p.append("REQUIRED_CHECK_SET_MISMATCH:results_vs_snapshot")
    db_checks = {r.check_type.value: (r.outcome.value, r.reason_code) for r in results}
    doc_checks = {c["check_type"]: (c["outcome"], c["reason_code"]) for c in doc["checks"]}
    if db_checks != doc_checks:
        p.append("DB_CHECK_RESULT_DISAGREE")
    if any((r.page_id, r.profile_id) != (snapshot.page_id, snapshot.profile_id)
           for r in results) or any(
               (a.page_id, a.profile_id) != (snapshot.page_id, snapshot.profile_id)
               for a in artifacts):
        p.append("DB_IDENTITY_DISAGREE")
    db_arts = {(a.seq, a.kind.value, a.check_type.value, a.rel_path, a.sha256, a.byte_length)
               for a in artifacts}
    doc_arts = {(a["seq"], a["kind"], a["check_type"], a["rel_path"], a["sha256"],
                 a["byte_length"]) for a in doc["artifacts"]}
    if db_arts != doc_arts:
        p.append("DB_MANIFEST_DISAGREE")
    return p
