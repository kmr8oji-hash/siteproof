"""Faithful nominal-type conversion for siteproof.bridge.v0.1.

Only kind/check_type/termination change representation. Evidence is never repaired.
S1 remains responsible for independent stream, record and artifact verification.
"""

from dataclasses import dataclass
import re
import time
from typing import BinaryIO, Callable

from src.core.errors import InvalidTransition, StaleAttemptError, TerminalJobError
from src.core.frames import CheckType, FrameKind, StreamSummary, Termination, VerifiedFrame
from src.core.model import JobStatus
from src.core.rules import is_terminal
from src.isolation import frames as s0
from src.storage.finalizer import EvidenceFinalizer, FinalizeOutcome


_CONNECTION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class AdapterError(ValueError):
    """Input is not the exact S0 contract representation; nothing was repaired."""


@dataclass(frozen=True)
class AdaptedStream:
    frames: tuple[VerifiedFrame, ...]
    summary: StreamSummary


@dataclass(frozen=True)
class BridgeResult:
    transport: s0.StreamResult
    outcome: FinalizeOutcome


def _require(value, expected, field):
    # In particular, bool is not an int, and an enum is not an S0 plain string.
    if type(value) is not expected:
        raise AdapterError(f"{field} must be {expected.__name__}")


def adapt_stream(result: s0.StreamResult) -> AdaptedStream:
    """Preserve all 13 frame and 3 summary values, including invalid evidence.

    Reject incompatible shapes/types and unknown enum values. Typed but incorrect
    IDs, sequences, hashes, lengths and totals reach S1 unchanged for rejection.
    Diagnostic reason stays on the original StreamResult, outside the contract.
    """
    _require(result, s0.StreamResult, "result")
    _require(result.frames, tuple, "frames")
    _require(result.summary, s0.StreamSummary, "summary")
    _require(result.reason, str, "reason")
    summary = result.summary
    _require(summary.termination, str, "termination")
    _require(summary.frame_count, int, "frame_count")
    _require(summary.total_payload_bytes, int, "total_payload_bytes")
    try:
        termination = Termination(summary.termination)
    except ValueError as exc:
        raise AdapterError("unknown termination") from exc
    frames = []
    for frame in result.frames:
        _require(frame, s0.VerifiedFrame, "frame")
        for name in ("schema_version", "job_id", "attempt_id", "kind", "page_id",
                     "profile_id", "check_type", "sha256", "provenance"):
            _require(getattr(frame, name), str, name)
        for name in ("lease_epoch", "seq", "byte_length"):
            _require(getattr(frame, name), int, name)
        _require(frame.payload, bytes, "payload")
        try:
            kind, check_type = FrameKind(frame.kind), CheckType(frame.check_type)
        except ValueError as exc:
            raise AdapterError("unknown kind/check_type") from exc
        frames.append(VerifiedFrame(
            frame.schema_version, frame.job_id, frame.attempt_id, frame.lease_epoch,
            frame.seq, kind, frame.page_id, frame.profile_id, check_type,
            frame.byte_length, frame.sha256, frame.payload, frame.provenance))
    return AdaptedStream(tuple(frames), StreamSummary(
        termination, summary.frame_count, summary.total_payload_bytes))


class EvidenceBridge:
    """Read a caller-supplied bounded offline stream and finalize it through S1.

    The only context source is the finalizer's Repository. Entry checks avoid
    consuming input for an already stale/terminal/non-SAVING job; the real S1
    finalizer checks again after reading and fences concurrent attempts at commit.
    Exceptions propagate; they never become a fabricated successful outcome.
    The caller owns the source (including blocking-I/O bounds and closing it).
    """

    def __init__(self, finalizer: EvidenceFinalizer):
        if not isinstance(finalizer, EvidenceFinalizer):
            raise AdapterError("real EvidenceFinalizer required")
        self.finalizer = finalizer

    def finalize(self, job_id: str, attempt_id: str, source: BinaryIO, *,
                 limits: s0.FrameLimits | None = None,
                 clock: Callable[[], float] = time.monotonic) -> BridgeResult:
        repo = self.finalizer.repo
        job = repo.get_job(job_id)
        if is_terminal(job.status):
            raise TerminalJobError(f"job {job_id} is terminal ({job.status.value})")
        if job.status is not JobStatus.SAVING:
            raise InvalidTransition(f"bridge requires SAVING, found {job.status.value}")
        attempt = repo.get_attempt(job_id, attempt_id)
        if attempt != repo.latest_attempt(job_id):
            raise StaleAttemptError(f"attempt {attempt_id} is not the current attempt")
        # INT-07 narrows S0's general UTF-8/epoch-0 context to S1's connection
        # preconditions. Reject invalid canonical values; never sanitize them.
        for name, value in (("job_id", attempt.job_id), ("attempt_id", attempt.attempt_id),
                            ("page_id", job.snapshot.page_id), ("profile_id", job.snapshot.profile_id)):
            if type(value) is not str or _CONNECTION_ID.fullmatch(value) is None:
                raise AdapterError(f"invalid connection {name}")
        if (attempt.job_id != job.snapshot.job_id or type(attempt.lease_epoch) is not int
                or attempt.lease_epoch < 1):
            raise AdapterError("invalid canonical attempt context")
        context = s0.TrustedContext(attempt.job_id, attempt.attempt_id, attempt.lease_epoch)
        transport = s0.FrameReader(source, context, limits, clock=clock).read()
        adapted = adapt_stream(transport)
        outcome = self.finalizer.finalize(job_id, attempt_id, adapted.frames, adapted.summary)
        return BridgeResult(transport, outcome)
