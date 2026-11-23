"""Pure reference checks only; never a source of capture-time profile trust.

Snapshot, AttemptRef and bridge DTO inputs are themselves caller-supplied objects.
There is no DB read, file read, clock, coordinator, nonce ledger or authentication.
Duplicates/conflicts are detected only inside this explicit validation batch.
Historical/later-created contexts cannot be distinguished from honest histories;
even fully coherent records remain UNATTESTED and cannot enable trusted S2 use.
"""

from dataclasses import dataclass
from enum import Enum

from src.bridge.s1_s2_contract import (EvidenceArtifact, EvidenceFile, EvidenceOrigin,
                                     ProfileTrust, StructurallyCheckedCaptureEvidence,
                                     UnattestedProfileError, UnattestedProfileFingerprint)
from src.comparison.profile import is_clean_text
from src.core.frames import CheckType
from src.core.model import AttemptRef, JobIntent, JobSnapshot

from .model import (CaptureContext, CaptureReceipt, CaptureResult, EvidenceBinding,
                    JobProfileSpec, ModelError, _file, _id, _integer, _sha, _state, _text,
                    checked_copy)


class BindingStatus(str, Enum):
    STRUCTURALLY_CONSISTENT = "STRUCTURALLY_CONSISTENT"
    UNKNOWN = "UNKNOWN"


class BindingReason(str, Enum):
    INVALID_INPUT = "INVALID_INPUT"
    INVALID_RECORD = "INVALID_RECORD"
    SOURCE_MISMATCH = "SOURCE_MISMATCH"
    SPEC_MISMATCH = "SPEC_MISMATCH"
    PROFILE_MISMATCH = "PROFILE_MISMATCH"
    ATTEMPT_MISMATCH = "ATTEMPT_MISMATCH"
    NONCE_MISMATCH = "NONCE_MISMATCH"
    CONTEXT_MISMATCH = "CONTEXT_MISMATCH"
    RECEIPT_MISMATCH = "RECEIPT_MISMATCH"
    SNAPSHOT_MISMATCH = "SNAPSHOT_MISMATCH"
    EVIDENCE_MISMATCH = "EVIDENCE_MISMATCH"
    CAPTURE_NOT_SUCCEEDED = "CAPTURE_NOT_SUCCEEDED"
    REQUEST_SPEC_CONFLICT = "REQUEST_SPEC_CONFLICT"
    JOB_SPEC_CONFLICT = "JOB_SPEC_CONFLICT"
    NONCE_REUSED = "NONCE_REUSED"
    ATTEMPT_REUSED = "ATTEMPT_REUSED"
    EPOCH_REUSED = "EPOCH_REUSED"
    CONTEXT_REUSED = "CONTEXT_REUSED"


@dataclass(frozen=True, kw_only=True)
class BindingInput:
    request_key: str  # Opaque, single-caller batch label; not a durable RequestKey.
    spec: JobProfileSpec
    context: CaptureContext
    receipt: CaptureReceipt
    binding: EvidenceBinding
    snapshot: JobSnapshot
    attempt: AttemptRef
    evidence: StructurallyCheckedCaptureEvidence


@dataclass(frozen=True)
class BindingRejection:
    index: int
    reason: BindingReason
    detail: str = ""


@dataclass(frozen=True)
class BindingValidation:
    records_checked: int
    rejections: tuple[BindingRejection, ...]

    @property
    def status(self):
        return (BindingStatus.STRUCTURALLY_CONSISTENT
                if self.records_checked > 0 and not self.rejections else BindingStatus.UNKNOWN)

    @property
    def trust(self):
        return ProfileTrust.UNATTESTED

    def require_trusted_use(self, operation):
        raise UnattestedProfileError("structural context checks cannot authorize trusted use")


class _Reject(Exception):
    def __init__(self, reason):
        self.reason = reason


def _need(condition, reason):
    if not condition:
        raise _Reject(reason)


def _source(entry):
    snap, attempt, evidence = entry.snapshot, entry.attempt, entry.evidence
    _state(snap, JobSnapshot)
    _state(snap.intent, JobIntent)
    # Serialization can erase type differences (e.g. list/tuple or int subclasses).
    # Validate the supplied DTOs before S1's canonical round-trip validation.
    _id(snap.job_id, "snapshot.job_id")
    _text(snap.created_at, "snapshot.created_at")  # Text only; no temporal proof.
    _text(snap.intent.target_url, "intent.target_url")
    for name in ("page_id", "profile_id"):
        _id(getattr(snap.intent, name), "intent." + name)
    if snap.intent.baseline_id is not None:
        _id(snap.intent.baseline_id, "intent.baseline_id")
    _need(type(snap.intent.required_checks) is tuple
          and all(type(check) is CheckType for check in snap.intent.required_checks),
          BindingReason.SOURCE_MISMATCH)
    # Reuse S1's actual validation and canonicalization, without changing S1.
    rebuilt = JobSnapshot.from_json(snap.to_json())
    _need(rebuilt.to_json() == snap.to_json(), BindingReason.SOURCE_MISMATCH)
    _need(CheckType.CAPTURE in snap.required_checks, BindingReason.CAPTURE_NOT_SUCCEEDED)
    attempt = AttemptRef(**_state(attempt, AttemptRef))
    _id(attempt.job_id, "attempt.job_id")
    _id(attempt.attempt_id, "attempt.attempt_id")
    _integer(attempt.lease_epoch, "attempt.lease_epoch")
    top = _state(evidence, StructurallyCheckedCaptureEvidence)
    origin = _state(top["origin"], EvidenceOrigin)
    for name in ("job_id", "adopted_attempt_id", "page_id", "profile_id"):
        _id(origin[name], name)
    if origin["baseline_id"] is not None:
        _id(origin["baseline_id"], "baseline_id")
    _integer(origin["lease_epoch"], "lease_epoch")
    _sha(origin["snapshot_sha256"], "snapshot_sha256")
    _sha(origin["intent_hash"], "intent_hash")
    _need((origin["job_id"], origin["page_id"], origin["profile_id"],
           origin["baseline_id"], origin["intent_hash"], origin["snapshot_sha256"]) ==
          (snap.job_id, snap.page_id, snap.profile_id, snap.baseline_id,
           snap.intent.intent_hash, snap.sha256), BindingReason.SOURCE_MISMATCH)
    _need((attempt.job_id, attempt.attempt_id, attempt.lease_epoch) ==
          (snap.job_id, origin["adopted_attempt_id"], origin["lease_epoch"]),
          BindingReason.ATTEMPT_MISMATCH)
    manifest = _file(top["manifest"], snap.job_id, attempt.attempt_id, "manifest", manifest=True)
    artifacts = []
    for name, kind in (("capture_record", "CAPTURE_RECORD"), ("screenshot", "SCREENSHOT_PNG")):
        artifact = _state(top[name], EvidenceArtifact)
        _integer(artifact["seq"], "seq", 0)
        _need(type(artifact["kind"]) is str and type(artifact["check_type"]) is str
              and (artifact["kind"], artifact["check_type"]) == (kind, "CAPTURE"),
              BindingReason.EVIDENCE_MISMATCH)
        artifacts.append((artifact["seq"], _file(artifact["file"], snap.job_id,
                                                attempt.attempt_id, name)))
    _need(artifacts[0][0] != artifacts[1][0]
          and len({manifest.artifact_ref, *(a[1].artifact_ref for a in artifacts)}) == 3,
          BindingReason.EVIDENCE_MISMATCH)
    _need(manifest.sha256 not in {a[1].sha256 for a in artifacts},
          BindingReason.EVIDENCE_MISMATCH)
    profile = _state(top["unattested_profile"], UnattestedProfileFingerprint)
    _sha(profile["declared_sha256"], "declared_sha256")
    return snap, attempt, manifest, artifacts[1][1], profile["declared_sha256"]


def _one(entry):
    _state(entry, BindingInput)
    _need(is_clean_text(entry.request_key) and len(entry.request_key) <= 200,
          BindingReason.INVALID_INPUT)
    for name, cls in (("spec", JobProfileSpec), ("context", CaptureContext),
                      ("receipt", CaptureReceipt), ("binding", EvidenceBinding)):
        _need(type(getattr(entry, name)) is cls, BindingReason.INVALID_RECORD)
    spec, ctx, receipt, binding = (checked_copy(getattr(entry, name))
                                   for name in ("spec", "context", "receipt", "binding"))
    snap, attempt, manifest, screenshot, declared_fp = _source(entry)
    _need(spec.snapshot_sha256 == snap.sha256 == binding.snapshot_sha256,
          BindingReason.SNAPSHOT_MISMATCH)
    _need((spec.job_id, spec.page_id, spec.profile_id) ==
          (snap.job_id, snap.page_id, snap.profile_id), BindingReason.SPEC_MISMATCH)
    _need(spec.profile_fingerprint == declared_fp, BindingReason.PROFILE_MISMATCH)
    _need((ctx.spec_ref, ctx.spec_sha256) == (spec.reference, spec.sha256),
          BindingReason.SPEC_MISMATCH)
    for job, att, epoch in ((ctx.job_id, ctx.attempt_id, ctx.lease_epoch),
                            (receipt.job_id, receipt.attempt_id, receipt.lease_epoch),
                            (binding.job_id, binding.adopted_attempt_id, binding.lease_epoch)):
        _need((job, att, epoch) == (attempt.job_id, attempt.attempt_id, attempt.lease_epoch),
              BindingReason.ATTEMPT_MISMATCH)
    _need(receipt.nonce == ctx.nonce, BindingReason.NONCE_MISMATCH)
    _need(receipt.context_id == ctx.context_id and
          receipt.context_sha256 == ctx.sha256 == binding.context_sha256,
          BindingReason.CONTEXT_MISMATCH)
    _need(binding.receipt_sha256 == receipt.sha256, BindingReason.RECEIPT_MISMATCH)
    _need(receipt.result is CaptureResult.SUCCEEDED, BindingReason.CAPTURE_NOT_SUCCEEDED)
    _need(binding.manifest == manifest and binding.screenshot == screenshot and
          (receipt.screenshot_sha256, receipt.screenshot_byte_length) ==
          (screenshot.sha256, screenshot.byte_length), BindingReason.EVIDENCE_MISMATCH)
    return entry.request_key, spec, ctx


def evaluate_bindings(entries) -> BindingValidation:
    """Inspect a list/tuple snapshot; duplicates are scoped to this call only.

    No result permits trusted use. A coherent retroactively invented history may
    be structurally consistent; temporal/provenance authenticity is UNKNOWN.
    """
    if type(entries) not in (list, tuple) or not entries:
        return BindingValidation(0, (BindingRejection(-1, BindingReason.INVALID_INPUT),))
    entries = tuple(entries)
    rejections = []
    requests, jobs = {}, {}
    nonces, attempts, epochs, contexts = set(), set(), set(), set()
    for index, entry in enumerate(entries):
        try:
            key, spec, ctx = _one(entry)
            digest = spec.sha256
            _need(key not in requests or requests[key] == digest,
                  BindingReason.REQUEST_SPEC_CONFLICT)
            _need(spec.job_id not in jobs or jobs[spec.job_id] == digest,
                  BindingReason.JOB_SPEC_CONFLICT)
            _need(ctx.nonce not in nonces, BindingReason.NONCE_REUSED)
            _need((ctx.job_id, ctx.attempt_id) not in attempts, BindingReason.ATTEMPT_REUSED)
            _need((ctx.job_id, ctx.lease_epoch) not in epochs, BindingReason.EPOCH_REUSED)
            _need(ctx.context_id not in contexts, BindingReason.CONTEXT_REUSED)
            requests[key], jobs[spec.job_id] = digest, digest
            nonces.add(ctx.nonce)
            attempts.add((ctx.job_id, ctx.attempt_id))
            epochs.add((ctx.job_id, ctx.lease_epoch))
            contexts.add(ctx.context_id)
        except _Reject as error:
            rejections.append(BindingRejection(index, error.reason))
        except ModelError as error:
            rejections.append(BindingRejection(index, BindingReason.INVALID_RECORD,
                                                error.code + ":" + error.field))
        except Exception:
            # A malformed object must never escape into a success/quality path.
            rejections.append(BindingRejection(index, BindingReason.INVALID_INPUT))
    return BindingValidation(len(entries), tuple(rejections))


def evaluate_binding(entry) -> BindingValidation:
    return evaluate_bindings((entry,))
