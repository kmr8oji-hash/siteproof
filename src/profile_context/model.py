"""PROFILE-CONTEXT-OFFLINE-v0.1: declarations, not capture attestations.

All schema versions are mandatory. Hashes are SHA-256 of UTF-8 canonical JSON
(sorted keys, compact separators, ASCII escaping), over every declared field.
Profile fingerprints retain the existing siteproof.profile.v1 algorithm, which
excludes profile_id. Record hashes DO include labels, revision and source IDs.
No clock, filesystem, database, execution, ordering or persistent replay proof is
provided. Even a fully coherent fabricated history remains UNATTESTED.
"""

from dataclasses import dataclass, fields
from enum import Enum
from types import MappingProxyType
from typing import Mapping

from src.bridge.s1_s2_contract import EvidenceFile, ProfileTrust, UnattestedProfileError
from src.comparison.profile import CaptureProfile, ProfileError, is_clean_text, is_sha256_hex
from src.core.model import canonical_json as _canonical_json, sha256_hex, validate_id

JOB_PROFILE_SCHEMA = "siteproof.job-profile-spec.v0.1"
CONTEXT_SCHEMA = "siteproof.capture-context.v0.1"
RECEIPT_SCHEMA = "siteproof.capture-receipt.v0.1"
BINDING_SCHEMA = "siteproof.evidence-binding.v0.1"


class ModelError(ValueError):
    """Controlled field error, without echoing caller-supplied values."""

    def __init__(self, code, field):
        self.code, self.field = code, field
        super().__init__(f"{code}:{field}")


def _ensure(condition, code, field):
    if not condition:
        raise ModelError(code, field)


def _id(value, name):
    _ensure(type(value) is str, "INVALID_TYPE", name)
    try:
        validate_id(value, name)
    except ValueError:
        raise ModelError("INVALID_ID", name) from None


def _text(value, name):
    _ensure(is_clean_text(value), "INVALID_TEXT", name)


def _sha(value, name):
    _ensure(is_sha256_hex(value), "INVALID_SHA256", name)


def _integer(value, name, minimum=1):
    _ensure(type(value) is int and value >= minimum, "INVALID_INTEGER", name)


def _state(obj, cls):
    _ensure(type(obj) is cls, "INVALID_TYPE", cls.__name__)
    state = vars(obj)
    _ensure(type(state) is dict and set(state) == {f.name for f in fields(cls)},
            "CORRUPT_STATE", cls.__name__)
    return state


def _file(value, job_id, attempt_id, name, *, manifest=False):
    s = _state(value, EvidenceFile)
    ref = s["artifact_ref"]
    _text(ref, name + ".artifact_ref")
    parts = ref.split("/")
    _ensure(len(parts) == 3 and parts[:2] == [job_id, attempt_id]
            and all(p and p not in (".", "..") and ":" not in p and "\\" not in p
                    and p == p.rstrip(". ") for p in parts), "INVALID_REFERENCE", name)
    if manifest:
        _ensure(parts[2] == "manifest.json", "INVALID_REFERENCE", name)
    _sha(s["sha256"], name + ".sha256")
    _integer(s["byte_length"], name + ".byte_length")
    return EvidenceFile(**s)  # Defensive copy of the external DTO.


def _plain(value):
    if isinstance(value, Enum):
        return value.value
    if type(value) is MappingProxyType:
        return dict(value)
    if type(value) is EvidenceFile:
        return dict(_state(value, EvidenceFile))
    _ensure(value is None or type(value) in (str, int, bool), "INVALID_TYPE", "canonical")
    return value


class _Record:
    @property
    def trust(self):
        return ProfileTrust.UNATTESTED

    def require_trusted_use(self, operation):
        raise UnattestedProfileError("offline context records cannot authorize trusted use")

    def to_dict(self):
        clean = checked_copy(self)
        return {f.name: _plain(getattr(clean, f.name)) for f in fields(type(clean))}

    def canonical_json(self):
        return _canonical_json(self.to_dict())

    @property
    def sha256(self):
        return sha256_hex(self.canonical_json().encode("utf-8"))


def _schema(record):
    _ensure(type(record) in _VERSIONS and type(record.schema_version) is str
            and record.schema_version == _VERSIONS[type(record)],
            "UNSUPPORTED_SCHEMA", "schema_version")


@dataclass(frozen=True, kw_only=True)
class JobProfileSpec(_Record):
    schema_version: str
    job_id: str
    page_id: str
    profile_id: str
    snapshot_sha256: str
    profile_definition_revision: int
    capture_attributes: Mapping[str, object]
    profile_fingerprint: str

    def __post_init__(self):
        _schema(self)
        for name in ("job_id", "page_id", "profile_id"):
            _id(getattr(self, name), name)
        _sha(self.snapshot_sha256, "snapshot_sha256")
        _integer(self.profile_definition_revision, "profile_definition_revision")
        _sha(self.profile_fingerprint, "profile_fingerprint")
        try:
            profile = CaptureProfile(self.profile_id, self.capture_attributes)
        except (ProfileError, TypeError, ValueError):
            raise ModelError("INVALID_PROFILE", "capture_attributes") from None
        _ensure(profile.fingerprint == self.profile_fingerprint,
                "PROFILE_FINGERPRINT_MISMATCH", "profile_fingerprint")
        object.__setattr__(self, "capture_attributes", profile.attributes)

    @property
    def reference(self):
        # Content reference only: this is not a filesystem path or registry lookup.
        return "job-profile-spec:sha256:" + self.sha256


@dataclass(frozen=True, kw_only=True)
class CaptureContext(_Record):
    schema_version: str
    context_id: str
    spec_ref: str
    spec_sha256: str
    job_id: str
    attempt_id: str
    lease_epoch: int
    nonce: str
    policy_ref: str
    environment_ref: str

    def __post_init__(self):
        _schema(self)
        for name in ("context_id", "job_id", "attempt_id", "nonce"):
            _id(getattr(self, name), name)
        for name in ("spec_ref", "policy_ref", "environment_ref"):
            _text(getattr(self, name), name)
        _sha(self.spec_sha256, "spec_sha256")
        _ensure(self.spec_ref == "job-profile-spec:sha256:" + self.spec_sha256,
                "INVALID_REFERENCE", "spec_ref")
        _integer(self.lease_epoch, "lease_epoch")


class CaptureResult(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    INTERRUPTED = "INTERRUPTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, kw_only=True)
class CaptureReceipt(_Record):
    schema_version: str
    context_id: str
    context_sha256: str
    job_id: str
    attempt_id: str
    lease_epoch: int
    nonce: str
    execution_id: str
    executor_ref: str  # A declaration, not an authenticated identity.
    result: CaptureResult
    screenshot_sha256: str | None
    screenshot_byte_length: int | None

    def __post_init__(self):
        _schema(self)
        for name in ("context_id", "job_id", "attempt_id", "nonce", "execution_id"):
            _id(getattr(self, name), name)
        _sha(self.context_sha256, "context_sha256")
        _integer(self.lease_epoch, "lease_epoch")
        _text(self.executor_ref, "executor_ref")
        _ensure(type(self.result) is CaptureResult, "INVALID_RESULT", "result")
        has_hash = self.screenshot_sha256 is not None
        has_length = self.screenshot_byte_length is not None
        _ensure(has_hash == has_length, "INCOMPLETE_SCREENSHOT", "screenshot")
        if has_hash:
            _sha(self.screenshot_sha256, "screenshot_sha256")
            _integer(self.screenshot_byte_length, "screenshot_byte_length")
        _ensure(self.result is not CaptureResult.SUCCEEDED or has_hash,
                "INCOMPLETE_SCREENSHOT", "screenshot")


@dataclass(frozen=True, kw_only=True)
class EvidenceBinding(_Record):
    schema_version: str
    context_sha256: str
    receipt_sha256: str
    snapshot_sha256: str
    job_id: str
    adopted_attempt_id: str
    lease_epoch: int
    manifest: EvidenceFile
    screenshot: EvidenceFile

    def __post_init__(self):
        _schema(self)
        for name in ("job_id", "adopted_attempt_id"):
            _id(getattr(self, name), name)
        for name in ("context_sha256", "receipt_sha256", "snapshot_sha256"):
            _sha(getattr(self, name), name)
        _integer(self.lease_epoch, "lease_epoch")
        for name in ("manifest", "screenshot"):
            value = _file(getattr(self, name), self.job_id, self.adopted_attempt_id,
                          name, manifest=name == "manifest")
            object.__setattr__(self, name, value)
        _ensure(self.manifest.artifact_ref != self.screenshot.artifact_ref,
                "INVALID_REFERENCE", "screenshot")


_VERSIONS = {JobProfileSpec: JOB_PROFILE_SCHEMA, CaptureContext: CONTEXT_SCHEMA,
             CaptureReceipt: RECEIPT_SCHEMA, EvidenceBinding: BINDING_SCHEMA}


def checked_copy(record):
    """Revalidate exact types/state after possible object-level corruption.

    Rebuilding is validation, not repair: a swapped mutable attributes container,
    extra fields, unsupported schemas or subclasses are rejected.
    """
    cls = type(record)
    _ensure(cls in _VERSIONS, "INVALID_TYPE", "record")
    state = _state(record, cls)
    if cls is JobProfileSpec:
        _ensure(type(state["capture_attributes"]) is MappingProxyType,
                "CORRUPT_STATE", "capture_attributes")
    return cls(**state)
