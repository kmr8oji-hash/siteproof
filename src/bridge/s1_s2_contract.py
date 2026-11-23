"""Point-in-time S1 evidence observations, not credentials or quality verdicts.

These frozen DTOs can be constructed by callers. Structural consistency is not
proof of authenticity. References must be reverified before later use. There is
NO independent capture-time profile trust source in this bridge.

S2 adapters MUST NOT use an UNATTESTED declaration for trusted compatibility,
baseline registration/approval, trusted comparison, or CAPTURE PASS/CHANGED.
They must enforce require_trusted_use before any such operation. Extracting the
declared hash and feeding existing pure S2 primitives does not establish trust.
This contract cannot constrain arbitrary Python callers that bypass the boundary.
"""

from dataclasses import dataclass
from enum import Enum
from typing import NoReturn

from src.comparison.profile import CaptureProfile


class RejectionReason(str, Enum):
    INVALID_INPUT = "INVALID_INPUT"
    SOURCE_UNREADABLE = "SOURCE_UNREADABLE"
    JOB_NOT_FOUND = "JOB_NOT_FOUND"
    JOB_NOT_COMPLETED = "JOB_NOT_COMPLETED"
    NO_ADOPTED_ATTEMPT = "NO_ADOPTED_ATTEMPT"
    ATTEMPT_NOT_ADOPTED = "ATTEMPT_NOT_ADOPTED"
    ATTEMPT_MISMATCH = "ATTEMPT_MISMATCH"
    SNAPSHOT_INVALID = "SNAPSHOT_INVALID"
    DB_RECORD_INVALID = "DB_RECORD_INVALID"
    MANIFEST_MISSING = "MANIFEST_MISSING"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"
    EVIDENCE_AMBIGUOUS = "EVIDENCE_AMBIGUOUS"
    EVIDENCE_MISMATCH = "EVIDENCE_MISMATCH"
    ORPHAN_EVIDENCE = "ORPHAN_EVIDENCE"
    PATH_INVALID = "PATH_INVALID"
    PATH_ESCAPE = "PATH_ESCAPE"
    LINK_NOT_ALLOWED = "LINK_NOT_ALLOWED"
    FILE_IDENTITY_UNAVAILABLE = "FILE_IDENTITY_UNAVAILABLE"
    FILE_IDENTITY_DUPLICATE = "FILE_IDENTITY_DUPLICATE"
    SOURCE_CHANGED = "SOURCE_CHANGED"
    READ_LIMIT_EXCEEDED = "READ_LIMIT_EXCEEDED"
    CAPTURE_NOT_SUCCEEDED = "CAPTURE_NOT_SUCCEEDED"
    PROFILE_DECLARATION_MISSING = "PROFILE_DECLARATION_MISSING"
    PROFILE_DECLARATION_MISMATCH = "PROFILE_DECLARATION_MISMATCH"


@dataclass(frozen=True)
class EvidenceFile:
    artifact_ref: str  # Canonical POSIX path relative to the configured evidence root.
    sha256: str
    byte_length: int


@dataclass(frozen=True)
class EvidenceArtifact:
    seq: int
    kind: str
    check_type: str
    file: EvidenceFile


@dataclass(frozen=True)
class EvidenceOrigin:
    job_id: str
    adopted_attempt_id: str
    lease_epoch: int
    snapshot_sha256: str
    intent_hash: str
    page_id: str
    profile_id: str
    baseline_id: str | None


@dataclass(frozen=True)
class UnattestedProfileDeclaration:
    """Caller assertion of a profile associated with an evidence observation.

    The full declared profile is validated for internal consistency only. Even a
    matching fingerprint and manifest pin do NOT prove capture-time conditions.
    No current-settings fallback or fingerprint-only input is supported.
    """

    origin: EvidenceOrigin
    screenshot: EvidenceFile
    declared_profile: CaptureProfile
    declared_fingerprint: str
    manifest: EvidenceFile  # Caller-retained observation pin, not a signature.


class ProfileTrust(str, Enum):
    UNATTESTED = "UNATTESTED"


class TrustedS2Use(str, Enum):
    PROFILE_COMPATIBILITY = "TRUSTED_PROFILE_COMPATIBILITY"
    BASELINE_REGISTRATION = "BASELINE_REGISTRATION"
    BASELINE_APPROVAL = "BASELINE_APPROVAL"
    COMPARISON = "TRUSTED_COMPARISON"
    CAPTURE_PASS = "CAPTURE_PASS"
    CAPTURE_CHANGED = "CAPTURE_CHANGED"


class UnattestedProfileError(ValueError):
    """Independent capture-time profile attestation is required but unavailable."""


@dataclass(frozen=True)
class UnattestedProfileFingerprint:
    """A declaration, deliberately neither a CaptureProfile nor a SHA-256 str."""

    declared_sha256: str

    @property
    def trust(self) -> ProfileTrust:
        return ProfileTrust.UNATTESTED

    def require_trusted_use(self, operation: TrustedS2Use) -> NoReturn:
        # No flag, fixture pin, or successful read can enable a trusted path.
        # A production trust source and its integration remain future work.
        raise UnattestedProfileError("UNATTESTED profile: trusted S2 use prohibited")


@dataclass(frozen=True)
class StructurallyCheckedCaptureEvidence:
    """S1 structural checks succeeded; capture profile authenticity is unknown."""

    origin: EvidenceOrigin
    manifest: EvidenceFile
    capture_record: EvidenceArtifact
    screenshot: EvidenceArtifact
    unattested_profile: UnattestedProfileFingerprint


@dataclass(frozen=True)
class EvidenceRejection:
    reason: RejectionReason
    detail: str = ""


@dataclass(frozen=True)
class EvidenceReadResult:
    evidence: StructurallyCheckedCaptureEvidence | None = None
    rejection: EvidenceRejection | None = None

    def __post_init__(self):
        if (self.evidence is None) == (self.rejection is None):
            raise ValueError("exactly one of evidence or rejection is required")

    @property
    def accepted(self) -> bool:
        """Structural read accepted; never profile authentication or quality PASS."""
        return self.evidence is not None
