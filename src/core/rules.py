"""Pure domain rules: job transitions, artifact requirements, quality derivation."""
from __future__ import annotations

from typing import Iterable, Optional

from .errors import EvidenceIncomplete
from .frames import RECORD_KIND_FOR_CHECK, CheckType, FrameKind
from .model import CheckOutcome, CheckReport, JobStatus, QualityVerdict

S = JobStatus

TERMINAL_STATUSES: frozenset[JobStatus] = frozenset({
    S.COMPLETED, S.FAILED_WORKER_START, S.FAILED_EXECUTION, S.FAILED_EVIDENCE,
    S.TIMED_OUT, S.CANCELLED,
})

ALLOWED_TRANSITIONS: dict[JobStatus, frozenset[JobStatus]] = {
    S.ACCEPTED: frozenset({S.WAITING_WORKER, S.CANCELLED}),
    S.WAITING_WORKER: frozenset({S.RUNNING, S.FAILED_WORKER_START, S.TIMED_OUT, S.CANCELLED}),
    S.RUNNING: frozenset({S.SAVING, S.FAILED_EXECUTION, S.TIMED_OUT, S.CANCELLED}),
    S.SAVING: frozenset({S.COMPLETED, S.FAILED_EVIDENCE, S.FAILED_EXECUTION,
                         S.TIMED_OUT, S.CANCELLED}),
    **{t: frozenset() for t in TERMINAL_STATUSES},
}


def is_terminal(status: JobStatus) -> bool:
    return status in TERMINAL_STATUSES


def can_transition(src: JobStatus, dst: JobStatus) -> bool:
    return dst in ALLOWED_TRANSITIONS[src]


# Reserved reason codes (Batch 02 record contract)
REASON_BASELINE_PENDING = "BASELINE_PENDING"        # capture ok, no baseline to compare with
REASON_COMPARISON_NOT_RUN = "COMPARISON_NOT_RUN"    # capture ok, baseline exists, no comparison
REASON_UPSTREAM_HTTP_FAILED = "UPSTREAM_HTTP_FAILED"  # only justification for SKIPPED (LOAD/CAPTURE)
CAPTURE_SUCCESS_REASONS: frozenset[str] = frozenset({REASON_BASELINE_PENDING,
                                                     REASON_COMPARISON_NOT_RUN})
ANY_REASON = "*"


def allowed_outcomes(check_type: CheckType) -> frozenset[CheckOutcome]:
    """CHANGED is a screen-comparison notion; it is not defined for HTTP/LOAD."""
    if check_type is CheckType.CAPTURE:
        return frozenset(CheckOutcome)
    return frozenset({CheckOutcome.PASS, CheckOutcome.FAIL,
                      CheckOutcome.UNKNOWN, CheckOutcome.SKIPPED})


def required_artifact_kinds(check_type: CheckType, outcome: CheckOutcome,
                            reason_code: Optional[str] = None) -> frozenset[FrameKind]:
    """Minimum artifact kinds that must exist for a (check, outcome[, reason]) triple.

    A CAPTURE that *succeeded* but could not be judged (UNKNOWN with a capture-success
    reason) still needs the screenshot; an explicit capture failure/skip does not.
    """
    if outcome not in allowed_outcomes(check_type):
        raise EvidenceIncomplete("OUTCOME_NOT_ALLOWED", f"{check_type.value}/{outcome.value}")
    record = RECORD_KIND_FOR_CHECK[check_type]
    if (check_type is CheckType.CAPTURE and outcome is CheckOutcome.UNKNOWN
            and reason_code in CAPTURE_SUCCESS_REASONS):
        return frozenset({FrameKind.CAPTURE_RECORD, FrameKind.SCREENSHOT_PNG})
    if outcome in (CheckOutcome.UNKNOWN, CheckOutcome.SKIPPED):
        return frozenset({record})  # verifiable record carrying the reason; no image needed
    if check_type is CheckType.CAPTURE and outcome in (CheckOutcome.PASS, CheckOutcome.CHANGED):
        return frozenset({FrameKind.CAPTURE_RECORD, FrameKind.SCREENSHOT_PNG})
    return frozenset({record})


def all_artifact_requirements() -> list[tuple[CheckType, CheckOutcome, str, FrameKind]]:
    """(check_type, outcome, reason_code or '*', kind) rows seeded into SQLite."""
    rows: list[tuple[CheckType, CheckOutcome, str, FrameKind]] = []
    for ct in CheckType:
        for oc in sorted(allowed_outcomes(ct), key=lambda o: o.value):
            for kind in sorted(required_artifact_kinds(ct, oc), key=lambda k: k.value):
                rows.append((ct, oc, ANY_REASON, kind))
    for reason in sorted(CAPTURE_SUCCESS_REASONS):
        for kind in sorted(required_artifact_kinds(CheckType.CAPTURE, CheckOutcome.UNKNOWN,
                                                   reason), key=lambda k: k.value):
            rows.append((CheckType.CAPTURE, CheckOutcome.UNKNOWN, reason, kind))
    return rows


def validate_report(report: CheckReport, *, baseline_id: Optional[str],
                    kinds_present: Iterable[FrameKind],
                    trusted_comparison: bool = False) -> None:
    """Raise EvidenceIncomplete if a reported outcome is not supportable.

    CAPTURE PASS/CHANGED needs a baseline *and* a trusted image comparison. No such
    comparison exists yet (`trusted_comparison` stays False), so a baseline id alone
    can never produce PASS/CHANGED.
    """
    present = set(kinds_present)
    if (report.check_type is CheckType.CAPTURE
            and report.outcome in (CheckOutcome.PASS, CheckOutcome.CHANGED)):
        if baseline_id is None:
            raise EvidenceIncomplete("BASELINE_NOT_SET", report.outcome.value)
        if not trusted_comparison:
            raise EvidenceIncomplete("COMPARISON_EVIDENCE_UNAVAILABLE", report.outcome.value)
    required = required_artifact_kinds(report.check_type, report.outcome, report.reason_code)
    missing = required - present
    if missing:
        raise EvidenceIncomplete(
            "ARTIFACT_MISSING",
            f"{report.check_type.value}/{report.outcome.value}: "
            + ",".join(sorted(k.value for k in missing)))
    if FrameKind.SCREENSHOT_PNG in present and FrameKind.SCREENSHOT_PNG not in required:
        raise EvidenceIncomplete(
            "ARTIFACT_UNEXPECTED",
            f"screenshot present but capture is {report.outcome.value}/{report.reason_code}")


def derive_quality(required_checks: Iterable[CheckType],
                   outcomes: dict[CheckType, CheckOutcome]) -> QualityVerdict:
    """Overall quality. Never PASS unless every required check is PASS.

    Precedence: FAIL > UNKNOWN (UNKNOWN / SKIPPED / missing) > CHANGED > PASS.
    """
    seen: list[Optional[CheckOutcome]] = [outcomes.get(c) for c in required_checks]
    if any(o is CheckOutcome.FAIL for o in seen):
        return QualityVerdict.FAIL
    if any(o is None or o in (CheckOutcome.UNKNOWN, CheckOutcome.SKIPPED) for o in seen):
        return QualityVerdict.UNKNOWN
    if any(o is CheckOutcome.CHANGED for o in seen):
        return QualityVerdict.CHANGED
    return QualityVerdict.PASS if seen else QualityVerdict.UNKNOWN


def classify_http_status(status: int, *, observation_reliable: bool) -> tuple[CheckOutcome, str]:
    """Provisional HTTP policy (to be confirmed against the S0 HTTP_RECORD format).

    A 404 is FAIL only when the observation is reliable; otherwise UNKNOWN.
    """
    if not observation_reliable:
        return CheckOutcome.UNKNOWN, "HTTP_OBSERVATION_UNRELIABLE"
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        return CheckOutcome.UNKNOWN, "HTTP_STATUS_INVALID"
    if 200 <= status <= 299:
        return CheckOutcome.PASS, f"HTTP_{status}"
    if status >= 400:
        return CheckOutcome.FAIL, f"HTTP_{status}"
    return CheckOutcome.UNKNOWN, f"HTTP_{status}_UNRESOLVED"
