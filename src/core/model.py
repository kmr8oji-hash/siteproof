"""Immutable domain model: job intent, snapshot, check results."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlsplit

from .errors import ValidationError
from .frames import CheckType

SNAPSHOT_SCHEMA_VERSION = "siteproof.snapshot.v0.1"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_REASON_LEN = 128


class JobStatus(str, Enum):
    ACCEPTED = "ACCEPTED"
    WAITING_WORKER = "WAITING_WORKER"
    RUNNING = "RUNNING"
    SAVING = "SAVING"
    COMPLETED = "COMPLETED"
    FAILED_WORKER_START = "FAILED_WORKER_START"
    FAILED_EXECUTION = "FAILED_EXECUTION"
    FAILED_EVIDENCE = "FAILED_EVIDENCE"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


class CheckOutcome(str, Enum):
    PASS = "PASS"
    CHANGED = "CHANGED"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    SKIPPED = "SKIPPED"


class QualityVerdict(str, Enum):
    """Overall quality, derived from check outcomes. Independent of JobStatus."""
    PASS = "PASS"
    CHANGED = "CHANGED"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"  # includes SKIPPED / missing: never converted to PASS


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValidationError(f"invalid {field}: {value!r}")
    return value


def validate_reason_code(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("reason_code must be a non-empty string")
    if value != value.strip() or len(value) > MAX_REASON_LEN or not value.isprintable():
        raise ValidationError(f"invalid reason_code: {value!r}")
    return value


@dataclass(frozen=True)
class JobIntent:
    """What the user asked for (1 page x 1 CaptureProfile). Hashed for idempotency."""
    target_url: str
    page_id: str
    profile_id: str
    required_checks: tuple[CheckType, ...]
    baseline_id: Optional[str] = None

    def __post_init__(self) -> None:
        parts = urlsplit(self.target_url) if isinstance(self.target_url, str) else None
        if parts is None or parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValidationError(f"invalid target_url: {self.target_url!r}")
        validate_id(self.page_id, "page_id")
        validate_id(self.profile_id, "profile_id")
        if self.baseline_id is not None:
            validate_id(self.baseline_id, "baseline_id")
        try:
            checks = {CheckType(c) for c in self.required_checks}
        except ValueError as e:
            raise ValidationError(f"invalid required_checks: {e}") from e
        if not checks:
            raise ValidationError("required_checks must not be empty")
        # normalise: sorted & unique, so the intent hash is order independent
        object.__setattr__(
            self, "required_checks", tuple(sorted(checks, key=lambda c: c.value)))

    def canonical(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "page_id": self.page_id,
            "profile_id": self.profile_id,
            "required_checks": [c.value for c in self.required_checks],
            "baseline_id": self.baseline_id,
        }

    @property
    def intent_hash(self) -> str:
        return sha256_hex(canonical_json(self.canonical()).encode("utf-8"))


@dataclass(frozen=True)
class JobSnapshot:
    """Immutable record of the accepted job. required_checks are fixed here."""
    job_id: str
    intent: JobIntent
    created_at: str

    def __post_init__(self) -> None:
        validate_id(self.job_id, "job_id")

    @property
    def page_id(self) -> str:
        return self.intent.page_id

    @property
    def profile_id(self) -> str:
        return self.intent.profile_id

    @property
    def required_checks(self) -> tuple[CheckType, ...]:
        return self.intent.required_checks

    @property
    def baseline_id(self) -> Optional[str]:
        return self.intent.baseline_id

    def to_json(self) -> str:
        return canonical_json({
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "job_id": self.job_id,
            "created_at": self.created_at,
            "intent": self.intent.canonical(),
        })

    @property
    def sha256(self) -> str:
        return sha256_hex(self.to_json().encode("utf-8"))

    @classmethod
    def from_json(cls, text: str) -> "JobSnapshot":
        d = json.loads(text)
        if d.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
            raise ValidationError("unsupported snapshot schema_version")
        i = d["intent"]
        intent = JobIntent(
            target_url=i["target_url"], page_id=i["page_id"], profile_id=i["profile_id"],
            required_checks=tuple(CheckType(c) for c in i["required_checks"]),
            baseline_id=i["baseline_id"])
        return cls(job_id=d["job_id"], intent=intent, created_at=d["created_at"])


@dataclass(frozen=True)
class AttemptRef:
    job_id: str
    attempt_id: str
    lease_epoch: int

    def __post_init__(self) -> None:
        validate_id(self.job_id, "job_id")
        validate_id(self.attempt_id, "attempt_id")
        if (not isinstance(self.lease_epoch, int) or isinstance(self.lease_epoch, bool)
                or self.lease_epoch < 1):
            raise ValidationError("lease_epoch must be an int >= 1")


@dataclass(frozen=True)
class CheckReport:
    """What the (untrusted) execution side reports for one check.

    page_id/profile_id come from the snapshot (1 page x 1 profile), not from here.
    A required check with no report is *missing*, never auto-SKIPPED.
    """
    check_type: CheckType
    outcome: CheckOutcome
    reason_code: str

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "check_type", CheckType(self.check_type))
            object.__setattr__(self, "outcome", CheckOutcome(self.outcome))
        except ValueError as e:
            raise ValidationError(str(e)) from e
        validate_reason_code(self.reason_code)


@dataclass(frozen=True)
class CheckResult:
    """A stored check result. Unique key: job_id, attempt_id, page_id, profile_id, check_type."""
    job_id: str
    attempt_id: str
    page_id: str
    profile_id: str
    check_type: CheckType
    outcome: CheckOutcome
    reason_code: str

    def __post_init__(self) -> None:
        validate_reason_code(self.reason_code)

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return (self.job_id, self.attempt_id, self.page_id, self.profile_id,
                self.check_type.value)


@dataclass(frozen=True)
class JobRecord:
    """Snapshot plus mutable execution state, as read from storage."""
    snapshot: JobSnapshot
    idempotency_key: str
    status: JobStatus
    version: int
    adopted_attempt_id: Optional[str]
    terminal_reason: Optional[str]
    updated_at: str

    @property
    def job_id(self) -> str:
        return self.snapshot.job_id
