"""Domain errors for SiteProof S1 (job / check / evidence)."""
from __future__ import annotations


class SiteProofError(Exception):
    """Base class for all S1 domain errors."""


class ValidationError(SiteProofError, ValueError):
    """Input violates a domain invariant."""


class IdempotencyConflict(SiteProofError):
    """Same idempotency key was used with a different intent."""


class CasConflict(SiteProofError):
    """Compare-and-swap on job version/status failed."""

    def __init__(self, message: str, *, current_status: str | None = None,
                 current_version: int | None = None) -> None:
        super().__init__(message)
        self.current_status = current_status
        self.current_version = current_version


class TerminalJobError(SiteProofError):
    """Attempt to modify a job that is already terminal."""


class InvalidTransition(SiteProofError):
    """Requested job status transition is not allowed."""


class UnknownJob(SiteProofError):
    pass


class UnknownAttempt(SiteProofError):
    pass


class DuplicateAttemptError(SiteProofError):
    pass


class StaleAttemptError(SiteProofError):
    """Attempt / lease epoch is not the current one and must not be adopted."""


class FrameRejected(SiteProofError):
    """A frame failed S1's re-verification. `code` is a stable machine code."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class StreamIncomplete(SiteProofError):
    """Stream did not end CLEAN (or counts do not match the summary)."""

    def __init__(self, code: str, termination: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.termination = termination


class EvidenceIncomplete(SiteProofError):
    """Required checks / artifacts are missing or inconsistent."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class RecordInvalid(EvidenceIncomplete):
    """A record payload (HTTP/LOAD/CAPTURE) violates `siteproof.record.v0.1`."""


class StorageError(SiteProofError):
    """Filesystem-side failure while saving evidence."""


class ArtifactExistsError(StorageError):
    """Destination already exists; overwriting is forbidden."""


class EvidenceMismatch(StorageError):
    """Read-back of stored evidence does not match what was written."""
