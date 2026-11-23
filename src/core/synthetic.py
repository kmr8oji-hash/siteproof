"""Synthetic data builders shaped like S0's bridge contract (offline tests only).

No S0 connection exists in this batch; these builders stand in for it.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

from .records import RECORD_SCHEMA_VERSION
from .frames import (BRIDGE_SCHEMA_VERSION, KIND_TO_CHECK_TYPE, PROVENANCE, FrameKind,
                     StreamSummary, Termination, VerifiedFrame)

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"synthetic-png-body"


def record_bytes(record_type: str, observation: dict[str, Any], **top: Any) -> bytes:
    doc = {"schema_version": RECORD_SCHEMA_VERSION, "record_type": record_type,
           "observation": observation}
    doc.update(top)
    return json.dumps(doc, sort_keys=True).encode("utf-8")


def http_record(status: Optional[int] = 200, state: str = "OBSERVED",
                reason: str = "HTTP_STATUS_OBSERVED") -> bytes:
    obs: dict[str, Any] = {"state": state, "reason_code": reason}
    if state == "OBSERVED":
        obs["status_code"] = status
    return record_bytes("HTTP", obs)


def load_record(state: str = "SUCCEEDED", reason: str = "LOAD_EVENT_OBSERVED") -> bytes:
    return record_bytes("LOAD", {"state": state, "reason_code": reason})


def capture_record(capture_state: str = "SUCCEEDED", comparison_state: str = "BASELINE_PENDING",
                   reason: str = "BASELINE_NOT_SET") -> bytes:
    return record_bytes("CAPTURE", {"capture_state": capture_state,
                                    "comparison_state": comparison_state,
                                    "reason_code": reason})


def default_record_payload(kind: FrameKind, *, baseline_set: bool) -> Optional[bytes]:
    """A valid 'everything observed' record for `kind` (None for non-record kinds)."""
    if kind is FrameKind.HTTP_RECORD:
        return http_record(200)
    if kind is FrameKind.LOAD_RECORD:
        return load_record()
    if kind is FrameKind.CAPTURE_RECORD:
        return (capture_record(comparison_state="NOT_EVALUATED", reason="COMPARISON_NOT_RUN")
                if baseline_set else capture_record())
    return None


def make_frame(*, job_id: str, attempt_id: str, lease_epoch: int, seq: int,
               kind: FrameKind, page_id: str, profile_id: str,
               payload: Optional[bytes] = None) -> VerifiedFrame:
    if payload is None:
        # default: a valid record for the no-baseline case (baseline-aware callers pass payload)
        payload = default_record_payload(kind, baseline_set=False) or PNG_BYTES
    return VerifiedFrame(
        schema_version=BRIDGE_SCHEMA_VERSION, job_id=job_id, attempt_id=attempt_id,
        lease_epoch=lease_epoch, seq=seq, kind=kind, page_id=page_id, profile_id=profile_id,
        check_type=KIND_TO_CHECK_TYPE[kind], byte_length=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(), payload=payload, provenance=PROVENANCE)


def make_summary(frames, termination: Termination = Termination.CLEAN) -> StreamSummary:
    return StreamSummary(termination=termination, frame_count=len(frames),
                         total_payload_bytes=sum(f.byte_length for f in frames))
