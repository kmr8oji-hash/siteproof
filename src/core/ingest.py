"""S1 re-verification of frames received from S0. Nothing here trusts the sender."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence

from .errors import FrameRejected, StreamIncomplete
from .frames import (BRIDGE_SCHEMA_VERSION, KIND_TO_CHECK_TYPE, PROVENANCE, CheckType,
                     FrameKind, StreamSummary, Termination, VerifiedFrame)
from .model import AttemptRef, JobSnapshot

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


@dataclass(frozen=True)
class IngestLimits:
    max_frame_bytes: int = 32 * 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_frames: int = 64


def _is_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def verify_frame(frame: VerifiedFrame, snapshot: JobSnapshot, attempt: AttemptRef,
                 limits: IngestLimits = IngestLimits()) -> None:
    """Raise FrameRejected unless the frame is consistent with snapshot + attempt."""
    if not isinstance(frame, VerifiedFrame):
        raise FrameRejected("TYPE_ERROR", "not a VerifiedFrame")
    if not isinstance(frame.payload, bytes):
        raise FrameRejected("TYPE_ERROR", "payload must be bytes")
    if not (_is_int(frame.seq) and frame.seq >= 0 and _is_int(frame.lease_epoch)
            and _is_int(frame.byte_length)):
        raise FrameRejected("TYPE_ERROR", "seq/lease_epoch/byte_length must be ints")
    if frame.schema_version != BRIDGE_SCHEMA_VERSION:
        raise FrameRejected("SCHEMA_VERSION", str(frame.schema_version))
    if frame.provenance != PROVENANCE:
        raise FrameRejected("PROVENANCE", str(frame.provenance))
    if frame.job_id != snapshot.job_id or frame.job_id != attempt.job_id:
        raise FrameRejected("JOB_MISMATCH", str(frame.job_id))
    if frame.attempt_id != attempt.attempt_id:
        raise FrameRejected("ATTEMPT_MISMATCH", str(frame.attempt_id))
    if frame.lease_epoch != attempt.lease_epoch:
        raise FrameRejected("LEASE_EPOCH_MISMATCH", f"{frame.lease_epoch}!={attempt.lease_epoch}")
    if not isinstance(frame.kind, FrameKind) or not isinstance(frame.check_type, CheckType):
        raise FrameRejected("TYPE_ERROR", "kind/check_type enums expected")
    if KIND_TO_CHECK_TYPE[frame.kind] is not frame.check_type:
        raise FrameRejected("KIND_CHECK_MISMATCH", f"{frame.kind.value}/{frame.check_type.value}")
    if frame.check_type not in snapshot.required_checks:
        raise FrameRejected("CHECK_NOT_REQUIRED", frame.check_type.value)
    if frame.page_id != snapshot.page_id:
        raise FrameRejected("PAGE_MISMATCH", str(frame.page_id))
    if frame.profile_id != snapshot.profile_id:
        raise FrameRejected("PROFILE_MISMATCH", str(frame.profile_id))
    if len(frame.payload) > limits.max_frame_bytes:
        raise FrameRejected("OVERSIZE", str(len(frame.payload)))
    if frame.byte_length != len(frame.payload):
        raise FrameRejected("LENGTH_MISMATCH", f"{frame.byte_length}!={len(frame.payload)}")
    if frame.sha256 != hashlib.sha256(frame.payload).hexdigest():
        raise FrameRejected("HASH_MISMATCH", f"seq={frame.seq}")
    if frame.kind is FrameKind.SCREENSHOT_PNG and not frame.payload.startswith(PNG_MAGIC):
        raise FrameRejected("PNG_SIGNATURE", f"seq={frame.seq}")


def verify_stream(frames: Sequence[VerifiedFrame], summary: StreamSummary,
                  snapshot: JobSnapshot, attempt: AttemptRef,
                  limits: IngestLimits = IngestLimits()) -> tuple[VerifiedFrame, ...]:
    """Verify a whole stream. COMPLETED may only ever be built from a CLEAN stream whose
    frames carry seq 0,1,2,... exactly (the summary is never rebuilt, seq never renumbered).

    Raises StreamIncomplete (stream-level) or FrameRejected (frame-level).
    """
    if not isinstance(summary, StreamSummary) or not isinstance(summary.termination, Termination):
        raise StreamIncomplete("SUMMARY_INVALID")
    if not (_is_int(summary.frame_count) and summary.frame_count >= 0
            and _is_int(summary.total_payload_bytes) and summary.total_payload_bytes >= 0):
        raise StreamIncomplete("SUMMARY_INVALID")
    if summary.termination is not Termination.CLEAN:
        raise StreamIncomplete(f"STREAM_{summary.termination.value}", summary.termination.value)
    if len(frames) > limits.max_frames:
        raise FrameRejected("TOO_MANY_FRAMES", str(len(frames)))
    if summary.frame_count != len(frames):
        raise StreamIncomplete("FRAME_COUNT_MISMATCH", summary.termination.value)
    seen_slots: set[tuple[CheckType, FrameKind]] = set()
    total = 0
    for index, f in enumerate(frames):
        verify_frame(f, snapshot, attempt, limits)
        if f.seq != index:  # exactly 0,1,2,... : no offset, gap, duplicate or reorder
            raise FrameRejected("SEQ_NOT_CONTIGUOUS", f"position={index} seq={f.seq}")
        slot = (f.check_type, f.kind)
        if slot in seen_slots:
            raise FrameRejected("DUPLICATE_FRAME", f"{f.check_type.value}/{f.kind.value}")
        seen_slots.add(slot)
        total += f.byte_length
    if total > limits.max_total_bytes:
        raise FrameRejected("OVERSIZE", f"total={total}")
    if summary.total_payload_bytes != total:
        raise StreamIncomplete("TOTAL_BYTES_MISMATCH", summary.termination.value)
    return tuple(frames)
