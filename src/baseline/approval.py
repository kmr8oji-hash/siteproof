"""Explicit baseline approval: PENDING -> APPROVED | REJECTED (pure; in-memory).

No automatic approval: a decision needs a named actor, the expected revision, and the
digest of the candidate the actor reviewed. Authentication and persistence are out of scope.
"""

from dataclasses import dataclass
import threading
import unicodedata
from typing import Optional

from src.baseline.model import BaselineCandidate, BaselineStatus
from src.comparison.profile import is_clean_text, is_sha256_hex

# Identities that denote automation rather than a person making a decision.
_AUTOMATIC_ACTORS = frozenset({"system", "auto", "automatic", "bot", "scheduler", "default"})


class ApprovalError(Exception):
    """Base class for approval rejections."""


class InvalidDecision(ApprovalError):
    """Decision is not APPROVED/REJECTED, or the actor is missing/automatic."""


class AlreadyDecided(ApprovalError):
    """The record is no longer PENDING."""


class RevisionConflict(ApprovalError):
    """expected_revision does not match the current revision."""


class CandidateTampered(ApprovalError):
    """Candidate content differs from what was registered or reviewed."""


class MalformedRecord(ApprovalError):
    """The record's internal state (candidate, status, revision, decision) is invalid."""


class UnknownCandidate(ApprovalError):
    """No record registered under that candidate_id."""


class DuplicateCandidate(ApprovalError):
    """A record already exists for that candidate_id."""


@dataclass(frozen=True)
class ApprovalDecision:
    status: BaselineStatus
    actor: str
    candidate_digest: str
    revision: int  # revision of the record after this decision


@dataclass(frozen=True)
class BaselineRecord:
    candidate: BaselineCandidate
    registered_digest: str
    status: BaselineStatus = BaselineStatus.PENDING
    revision: int = 0
    decision: Optional[ApprovalDecision] = None

    def is_well_formed(self) -> bool:
        """Structural check of every field; never raises, whatever the record contains."""
        return (
            isinstance(self.candidate, BaselineCandidate)
            and self.candidate.is_intact()
            and is_sha256_hex(self.registered_digest)
            and isinstance(self.status, BaselineStatus)
            and _is_revision(self.revision)
            and (self.decision is None or isinstance(self.decision, ApprovalDecision))
            and (self.status is not BaselineStatus.PENDING or self.decision is None)
        )

    def is_valid_approval(self) -> bool:
        """True only for a self-consistent APPROVED record bound to the unaltered candidate."""
        if not self.is_well_formed():
            return False
        d = self.decision
        return (
            self.status is BaselineStatus.APPROVED
            and isinstance(d, ApprovalDecision)
            and d.status is BaselineStatus.APPROVED
            and self.revision >= 1
            and _is_revision(d.revision)
            and d.revision == self.revision
            and self.candidate.digest == self.registered_digest == d.candidate_digest
            and _is_human_actor(d.actor)
        )


def _is_revision(value) -> bool:
    return type(value) is int and value >= 0


def _is_human_actor(actor) -> bool:
    # NFKC folds full-width/compat forms so "ＳＹＳＴＥＭ" cannot slip past the list.
    return (
        is_clean_text(actor)
        and unicodedata.normalize("NFKC", actor).casefold() not in _AUTOMATIC_ACTORS
    )


def register_candidate(candidate: BaselineCandidate) -> BaselineRecord:
    if not isinstance(candidate, BaselineCandidate):
        raise TypeError("candidate must be a BaselineCandidate")
    return BaselineRecord(candidate=candidate, registered_digest=candidate.digest)


def decide(
    record: BaselineRecord,
    *,
    decision: BaselineStatus,
    actor: str,
    expected_revision: int,
    reviewed_digest: str,
) -> BaselineRecord:
    """Return a new decided record; never mutates ``record``."""
    if not isinstance(record, BaselineRecord):
        raise TypeError("record must be a BaselineRecord")
    if decision is not BaselineStatus.APPROVED and decision is not BaselineStatus.REJECTED:
        raise InvalidDecision("decision must be APPROVED or REJECTED")
    if not _is_human_actor(actor):
        raise InvalidDecision("an explicit, non-automatic actor is required")
    if not _is_revision(expected_revision):
        raise RevisionConflict("expected_revision must be a non-negative int")
    if not record.is_well_formed():
        raise MalformedRecord("record is structurally invalid")
    if record.status is not BaselineStatus.PENDING:
        raise AlreadyDecided(f"record already {record.status.value}")
    if expected_revision != record.revision:
        raise RevisionConflict(f"expected {expected_revision}, current {record.revision}")
    if (
        record.candidate.digest != record.registered_digest
        or reviewed_digest != record.registered_digest
    ):
        raise CandidateTampered("candidate differs from the registered/reviewed content")
    new_revision = record.revision + 1
    return BaselineRecord(
        candidate=record.candidate,
        registered_digest=record.registered_digest,
        status=decision,
        revision=new_revision,
        decision=ApprovalDecision(decision, actor, record.registered_digest, new_revision),
    )


class BaselineApprovalStore:
    """Thread-safe in-memory store; decide() is an atomic compare-and-swap on revision."""

    def __init__(self):
        self._lock = threading.Lock()
        self._records: dict[str, BaselineRecord] = {}

    def register(self, candidate: BaselineCandidate) -> BaselineRecord:
        record = register_candidate(candidate)
        with self._lock:
            if candidate.candidate_id in self._records:
                raise DuplicateCandidate(candidate.candidate_id)
            self._records[candidate.candidate_id] = record
        return record

    def get(self, candidate_id: str) -> BaselineRecord:
        if type(candidate_id) is not str:
            raise UnknownCandidate(repr(candidate_id))
        with self._lock:
            try:
                return self._records[candidate_id]
            except KeyError:
                raise UnknownCandidate(candidate_id) from None

    def decide(self, candidate_id: str, **kwargs) -> BaselineRecord:
        if type(candidate_id) is not str:
            raise UnknownCandidate(repr(candidate_id))
        with self._lock:
            try:
                current = self._records[candidate_id]
            except KeyError:
                raise UnknownCandidate(candidate_id) from None
            updated = decide(current, **kwargs)
            self._records[candidate_id] = updated
            return updated
