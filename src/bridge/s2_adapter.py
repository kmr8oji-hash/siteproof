"""S2-ADAPTER-BOUNDARY-v0.1: a refusal-only boundary between S1 evidence and S2.

There is NO independent capture-time profile trust source, so this boundary has
no success path: well-formed evidence is refused as PROFILE_UNATTESTED. Nothing
here registers or approves a baseline, builds a ComparisonRequest, evaluates
eligibility, or produces CAPTURE PASS/CHANGED. No flag or option can bypass it.
"""

from dataclasses import dataclass, fields
from enum import Enum

from src.comparison.decision import EligibilityStatus, UnknownReason
from src.comparison.profile import is_clean_text, is_sha256_hex
from src.core.model import validate_id

from .s1_s2_contract import (EvidenceArtifact, EvidenceFile, EvidenceOrigin,
                             EvidenceReadResult, EvidenceRejection,
                             RejectionReason, StructurallyCheckedCaptureEvidence,
                             TrustedS2Use, UnattestedProfileError,
                             UnattestedProfileFingerprint)

_KINDS = {"screenshot": ("SCREENSHOT_PNG", "CAPTURE"), "capture_record": ("CAPTURE_RECORD", "CAPTURE")}
_UNKNOWN_EVIDENCE_ABSENT = (UnknownReason.BASELINE_NOT_APPROVED, UnknownReason.PROFILE_MISMATCH,
                            UnknownReason.EVIDENCE_MISSING, UnknownReason.COMPARISON_NOT_RUN)
_UNKNOWN_UNATTESTED = (UnknownReason.BASELINE_NOT_APPROVED, UnknownReason.PROFILE_MISMATCH,
                       UnknownReason.COMPARISON_NOT_RUN)


class AdapterRejectionReason(str, Enum):
    INVALID_INPUT = "INVALID_INPUT"
    BRIDGE_REJECTED = "BRIDGE_REJECTED"
    REQUIRED_INFORMATION_MISSING = "REQUIRED_INFORMATION_MISSING"
    EVIDENCE_REFERENCE_MISMATCH = "EVIDENCE_REFERENCE_MISMATCH"
    PROFILE_UNATTESTED = "PROFILE_UNATTESTED"


@dataclass(frozen=True)
class AdapterRejection:
    """Always an S2 UNKNOWN; never eligibility, baseline trust or a quality verdict."""

    reason: AdapterRejectionReason
    detail: str
    unknown_reasons: tuple  # tuple[UnknownReason, ...]; ends with COMPARISON_NOT_RUN
    bridge_reason: RejectionReason | None = None

    @property
    def status(self) -> EligibilityStatus:
        return EligibilityStatus.UNKNOWN


class _Refuse(Exception):
    def __init__(self, reason, detail):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


_R = AdapterRejectionReason


def _refuse(reason, detail):
    raise _Refuse(reason, detail)


def _intact(obj, cls, path):
    """Exact class and exact instance state; absent fields are 'missing', not 'invalid'."""
    if type(obj) is not cls:
        _refuse(_R.INVALID_INPUT, f"{path}: unexpected type")
    state = vars(obj)
    if type(state) is not dict:
        _refuse(_R.INVALID_INPUT, f"{path}: corrupt state")
    names = {f.name for f in fields(cls)}
    if names - set(state):
        _refuse(_R.REQUIRED_INFORMATION_MISSING, f"{path}: missing field")
    if set(state) - names:
        _refuse(_R.INVALID_INPUT, f"{path}: unexpected field")
    return state


def _id(value, path, *, optional=False):
    if value is None:
        if optional:
            return
        _refuse(_R.REQUIRED_INFORMATION_MISSING, f"{path}: missing")
    try:
        validate_id(value, path)
    except Exception:
        _refuse(_R.INVALID_INPUT, f"{path}: invalid id")


def _sha(value, path):
    if value is None:
        _refuse(_R.REQUIRED_INFORMATION_MISSING, f"{path}: missing")
    if not is_sha256_hex(value):
        _refuse(_R.INVALID_INPUT, f"{path}: invalid sha256")


def _int(value, path, minimum):
    if value is None:
        _refuse(_R.REQUIRED_INFORMATION_MISSING, f"{path}: missing")
    if type(value) is not int or value < minimum:
        _refuse(_R.INVALID_INPUT, f"{path}: invalid integer")


def _ref(value, path):
    """Canonical relative POSIX path: <job>/<attempt>/<name>, no aliases or escapes."""
    if value is None:
        _refuse(_R.REQUIRED_INFORMATION_MISSING, f"{path}: missing")
    if not is_clean_text(value):
        _refuse(_R.INVALID_INPUT, f"{path}: invalid artifact_ref")
    parts = value.split("/")
    if len(parts) != 3 or any(p in ("", ".", "..") or ":" in p or "\\" in p or p != p.rstrip(". ")
                              for p in parts):
        _refuse(_R.EVIDENCE_REFERENCE_MISMATCH, f"{path}: non-canonical artifact_ref")
    return parts


def _file(file, path):
    state = _intact(file, EvidenceFile, path)
    parts = _ref(state["artifact_ref"], path)
    _sha(state["sha256"], path)
    _int(state["byte_length"], path, 1)
    return parts, state["sha256"]


def _artifact(artifact, role, path):
    state = _intact(artifact, EvidenceArtifact, path)
    _int(state["seq"], path + ".seq", 0)
    if (state["kind"], state["check_type"]) != _KINDS[role]:
        _refuse(_R.EVIDENCE_REFERENCE_MISMATCH, f"{path}: kind/check_type")
    parts, digest = _file(state["file"], path + ".file")
    return state["seq"], parts, digest


def _check_evidence(evidence):
    top = _intact(evidence, StructurallyCheckedCaptureEvidence, "evidence")
    origin = _intact(top["origin"], EvidenceOrigin, "origin")
    _id(origin["job_id"], "job_id")
    _id(origin["adopted_attempt_id"], "attempt_id")
    _id(origin["page_id"], "page_id")
    _id(origin["profile_id"], "profile_id")
    _id(origin["baseline_id"], "baseline_id", optional=True)
    _int(origin["lease_epoch"], "lease_epoch", 1)
    _sha(origin["snapshot_sha256"], "snapshot_sha256")
    _sha(origin["intent_hash"], "intent_hash")

    manifest, manifest_sha = _file(top["manifest"], "manifest")
    seq_r, record, record_sha = _artifact(top["capture_record"], "capture_record", "capture_record")
    seq_s, shot, shot_sha = _artifact(top["screenshot"], "screenshot", "screenshot")

    prefix = [origin["job_id"], origin["adopted_attempt_id"]]
    if manifest != [*prefix, "manifest.json"]:
        _refuse(_R.EVIDENCE_REFERENCE_MISMATCH, "manifest: ref does not match job/attempt")
    for name, parts in (("capture_record", record), ("screenshot", shot)):
        if parts[:2] != prefix:
            _refuse(_R.EVIDENCE_REFERENCE_MISMATCH, f"{name}: ref does not match job/attempt")
    if len({tuple(manifest), tuple(record), tuple(shot)}) != 3 or seq_r == seq_s:
        _refuse(_R.EVIDENCE_REFERENCE_MISMATCH, "evidence members are not distinct")
    if manifest_sha in (record_sha, shot_sha):
        _refuse(_R.EVIDENCE_REFERENCE_MISMATCH, "manifest hash duplicates a member hash")

    profile = top["unattested_profile"]
    state = _intact(profile, UnattestedProfileFingerprint, "unattested_profile")
    _sha(state["declared_sha256"], "unattested_profile.declared_sha256")
    return profile


def _rejection(reason, detail, unknown=_UNKNOWN_EVIDENCE_ABSENT, bridge_reason=None):
    return AdapterRejection(reason, detail, unknown, bridge_reason)


def evaluate_s1_evidence_boundary(result) -> AdapterRejection:
    """Validate an S1 bridge result and refuse it; there is no accepting outcome.

    Fail-closed: any unexpected object or internal error is INVALID_INPUT.
    """
    try:
        state = _intact(result, EvidenceReadResult, "result")
        rejection, evidence = state["rejection"], state["evidence"]
        if (rejection is None) == (evidence is None):
            _refuse(_R.INVALID_INPUT, "result: exactly one of evidence or rejection required")
        if rejection is not None:
            rstate = _intact(rejection, EvidenceRejection, "rejection")
            if type(rstate["reason"]) is not RejectionReason:
                _refuse(_R.INVALID_INPUT, "rejection: invalid reason")
            return _rejection(_R.BRIDGE_REJECTED, "S1 bridge refused the evidence",
                              bridge_reason=rstate["reason"])
        profile = _check_evidence(evidence)
        try:
            profile.require_trusted_use(TrustedS2Use.PROFILE_COMPATIBILITY)
        except UnattestedProfileError:
            pass
        # Even if the check above returned normally, no trust source exists.
        return _rejection(_R.PROFILE_UNATTESTED,
                          "capture profile is UNATTESTED; trusted S2 use is prohibited",
                          _UNKNOWN_UNATTESTED)
    except _Refuse as e:
        return _rejection(e.reason, e.detail)
    except Exception:
        return _rejection(_R.INVALID_INPUT, "unexpected input")
