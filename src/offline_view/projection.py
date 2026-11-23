"""Read-only projection of the REAL S1 reader + refusal-only S2 adapter.

No API accepts a caller-constructed DTO/JSON as proof of a structural read.
The emitted JSON is still unauthenticated and is NOT evidence or a credential.
No comparison, baseline approval, capture, DB/evidence write or browser occurs.
"""

from pathlib import Path

from src.bridge import s1_evidence, s2_adapter
from src.bridge.s1_s2_contract import EvidenceReadResult, EvidenceRejection, RejectionReason
from src.bridge.s2_adapter import AdapterRejection, AdapterRejectionReason
from src.comparison.decision import EligibilityStatus, UnknownReason
from src.core.model import validate_id
from .contracts import FIXED, NOTICE, canonical_json, validate_report


def _reasons(*codes):
    # Preserve all existing refusal codes and their order, without duplicates.
    return list(dict.fromkeys(codes))


def _unknown(reason="INVALID_INPUT"):
    return {**FIXED, "job_id": None, "attempt_id": None,
            "bridge": {"status": "UNKNOWN", "reason": None},
            "evidence": {"status": "NOT_VERIFIED", "manifest_ref": None, "screenshot_ref": None},
            "unknown_reasons": _reasons(reason, "EVIDENCE_MISSING", "COMPARISON_NOT_RUN"),
            "notice": NOTICE}


def _local_locator(value):
    # Lexical only: rejecting explicit UNC/device/URI inputs must not itself
    # stat, resolve or contact a share. Mapped drives/host mounts remain outside
    # our knowledge; this is not a LOCAL-ISOLATION attestation.
    if type(value) is str:
        raw = value
    elif isinstance(value, Path):
        raw = str(value)
    else:
        return False
    if not raw or raw.replace("\\", "/").startswith("//"):
        return False
    colons = [i for i, char in enumerate(raw) if char == ":"]
    return not colons or (colons == [1] and raw[0] in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


def project_s1_capture(db_path, evidence_root, job_id, *, profile_declaration=None, attempt_id=None):
    """Observe adopted evidence through read_s1_capture; return a safe JSON dict.

    Caller locator/ID/declaration strings are NOT copied into output when the
    bridge refuses. Checked IDs/refs come only from its validated evidence DTO.
    Even a checked observation is UNATTESTED and S2 remains UNKNOWN/NOT_RUN.
    Module replacement/host compromise cannot be authenticated by this function.
    """
    try:
        if not _local_locator(db_path) or not _local_locator(evidence_root):
            return _unknown()
        result = s1_evidence.read_s1_capture(db_path, evidence_root, job_id,
                                           profile_declaration=profile_declaration, attempt_id=attempt_id)
        boundary = s2_adapter.evaluate_s1_evidence_boundary(result)
        if type(boundary) is not AdapterRejection or boundary.status is not EligibilityStatus.UNKNOWN:
            return _unknown()
        if type(boundary.reason) is not AdapterRejectionReason:
            return _unknown()
        if type(boundary.unknown_reasons) is not tuple or not boundary.unknown_reasons or any(
                type(r) is not UnknownReason for r in boundary.unknown_reasons):
            return _unknown()
        if boundary.unknown_reasons[-1] is not UnknownReason.COMPARISON_NOT_RUN:
            return _unknown()
        if type(result) is not EvidenceReadResult:
            return _unknown()
        if boundary.reason is AdapterRejectionReason.BRIDGE_REJECTED:
            refusal = result.rejection
            if (result.evidence is not None or type(refusal) is not EvidenceRejection
                    or type(refusal.reason) is not RejectionReason or boundary.bridge_reason is not refusal.reason):
                return _unknown()
            projected = _unknown()
            projected["bridge"] = {"status": "REJECTED", "reason": refusal.reason.value}
            projected["unknown_reasons"] = _reasons(refusal.reason.value, boundary.reason.value,
                                                   *(r.value for r in boundary.unknown_reasons))
        elif boundary.reason is AdapterRejectionReason.PROFILE_UNATTESTED:
            if result.rejection is not None or result.evidence is None or boundary.bridge_reason is not None:
                return _unknown()
            evidence = result.evidence
            origin = evidence.origin
            # Defensive assertion matching: no mismatched DTO may be projected.
            validate_id(job_id, "job_id")
            if type(job_id) is not str or origin.job_id != job_id:
                return _unknown("EVIDENCE_REFERENCE_MISMATCH")
            if attempt_id is not None:
                validate_id(attempt_id, "attempt_id")
                if type(attempt_id) is not str or origin.adopted_attempt_id != attempt_id:
                    return _unknown("EVIDENCE_REFERENCE_MISMATCH")
            projected = {**FIXED, "job_id": origin.job_id, "attempt_id": origin.adopted_attempt_id,
                         "bridge": {"status": "STRUCTURALLY_CHECKED", "reason": None},
                         "evidence": {"status": "STRUCTURALLY_CHECKED",
                                      "manifest_ref": evidence.manifest.artifact_ref,
                                      "screenshot_ref": evidence.screenshot.file.artifact_ref},
                         "unknown_reasons": _reasons(boundary.reason.value,
                                                     *(r.value for r in boundary.unknown_reasons)),
                         "notice": NOTICE}
        else:
            projected = _unknown(boundary.reason.value)
            projected["unknown_reasons"] = _reasons(boundary.reason.value,
                                                   *(r.value for r in boundary.unknown_reasons))
        return validate_report(projected)
    except Exception:
        # Never return a partial structural success or leak paths/error detail.
        return _unknown()


def project_s1_capture_json(db_path, evidence_root, job_id, *, profile_declaration=None, attempt_id=None):
    """Canonical JSON of the read-only projection; does not save a file."""
    return canonical_json(project_s1_capture(db_path, evidence_root, job_id,
                                            profile_declaration=profile_declaration, attempt_id=attempt_id))
