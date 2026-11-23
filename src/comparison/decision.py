"""Comparison eligibility (pure). ELIGIBLE means "may be compared", never "quality PASS".

No image comparison is performed and no PASS/CHANGED is ever produced. Any failed
precondition yields UNKNOWN with explicit reasons; malformed inputs fail closed.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from src.baseline.approval import BaselineRecord
from src.baseline.model import BaselineCandidate
from src.comparison.profile import (
    CaptureProfile,
    ComparisonProfile,
    is_clean_text,
    is_sha256_hex,
)


class EligibilityStatus(str, Enum):
    ELIGIBLE = "ELIGIBLE"
    UNKNOWN = "UNKNOWN"


class UnknownReason(str, Enum):
    PAGE_MISMATCH = "PAGE_MISMATCH"
    BASELINE_NOT_APPROVED = "BASELINE_NOT_APPROVED"
    PROFILE_MISMATCH = "PROFILE_MISMATCH"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"
    COMPARISON_NOT_RUN = "COMPARISON_NOT_RUN"


@dataclass(frozen=True)
class EvidenceRef:
    artifact_ref: str
    artifact_sha256: str


@dataclass(frozen=True)
class ComparisonRequest:
    page_id: str
    baseline: BaselineRecord
    current_capture_profile: CaptureProfile
    comparison_profile: ComparisonProfile
    current_evidence: Optional[EvidenceRef] = None


@dataclass(frozen=True)
class EligibilityResult:
    status: EligibilityStatus
    reasons: tuple  # tuple[UnknownReason, ...]; always ends with COMPARISON_NOT_RUN

    @property
    def eligible(self) -> bool:
        return self.status is EligibilityStatus.ELIGIBLE


def _evidence_present(evidence) -> bool:
    return (
        isinstance(evidence, EvidenceRef)
        and is_clean_text(evidence.artifact_ref)
        and is_sha256_hex(evidence.artifact_sha256)
    )


def evaluate_eligibility(request) -> EligibilityResult:
    reasons = []
    if not isinstance(request, ComparisonRequest):
        reasons = [UnknownReason.BASELINE_NOT_APPROVED, UnknownReason.PROFILE_MISMATCH,
                   UnknownReason.EVIDENCE_MISSING]
        return EligibilityResult(EligibilityStatus.UNKNOWN,
                                 (*reasons, UnknownReason.COMPARISON_NOT_RUN))

    baseline = request.baseline
    approved = isinstance(baseline, BaselineRecord) and baseline.is_valid_approval()
    if not approved:
        reasons.append(UnknownReason.BASELINE_NOT_APPROVED)

    if not (
        isinstance(baseline, BaselineRecord)
        and isinstance(baseline.candidate, BaselineCandidate)
        and baseline.candidate.is_intact()
        and is_clean_text(request.page_id)
        and request.page_id == baseline.candidate.page_id
    ):
        reasons.append(UnknownReason.PAGE_MISMATCH)

    profile_ok = False
    capture, comparison = request.current_capture_profile, request.comparison_profile
    if (
        approved
        and isinstance(capture, CaptureProfile)
        and isinstance(comparison, ComparisonProfile)
        # Corrupted profile internals must not reach fingerprint/attribute access.
        and capture.is_intact()
        and comparison.is_intact()
    ):
        expected_fp = baseline.candidate.profile_fingerprint
        profile_ok = (
            capture.fingerprint == expected_fp
            and comparison.attributes["capture_fingerprint"] == expected_fp
        )
    if not profile_ok:
        reasons.append(UnknownReason.PROFILE_MISMATCH)

    if not _evidence_present(request.current_evidence):
        reasons.append(UnknownReason.EVIDENCE_MISSING)

    status = EligibilityStatus.UNKNOWN if reasons else EligibilityStatus.ELIGIBLE
    # The comparison itself is never executed here.
    return EligibilityResult(status, (*reasons, UnknownReason.COMPARISON_NOT_RUN))
