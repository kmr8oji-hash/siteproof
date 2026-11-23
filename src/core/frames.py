"""S1-side mirror of the S0 bridge contract `siteproof.bridge.v0.1`.

These are *shapes only*. S1 never trusts a frame just because it has this type;
see `ingest.verify_frame`.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

BRIDGE_SCHEMA_VERSION = "siteproof.bridge.v0.1"
PROVENANCE = "untrusted_browser_validated_transport"


class CheckType(str, Enum):
    HTTP = "HTTP"
    LOAD = "LOAD"
    CAPTURE = "CAPTURE"


class FrameKind(str, Enum):
    HTTP_RECORD = "HTTP_RECORD"
    LOAD_RECORD = "LOAD_RECORD"
    CAPTURE_RECORD = "CAPTURE_RECORD"
    SCREENSHOT_PNG = "SCREENSHOT_PNG"


class Termination(str, Enum):
    CLEAN = "CLEAN"
    TRUNCATED = "TRUNCATED"
    TIMEOUT = "TIMEOUT"
    OVERSIZE = "OVERSIZE"
    PROTOCOL_ERROR = "PROTOCOL_ERROR"


KIND_TO_CHECK_TYPE: dict[FrameKind, CheckType] = {
    FrameKind.HTTP_RECORD: CheckType.HTTP,
    FrameKind.LOAD_RECORD: CheckType.LOAD,
    FrameKind.CAPTURE_RECORD: CheckType.CAPTURE,
    FrameKind.SCREENSHOT_PNG: CheckType.CAPTURE,
}

# The record kind that carries the (verifiable) record for each check type.
RECORD_KIND_FOR_CHECK: dict[CheckType, FrameKind] = {
    CheckType.HTTP: FrameKind.HTTP_RECORD,
    CheckType.LOAD: FrameKind.LOAD_RECORD,
    CheckType.CAPTURE: FrameKind.CAPTURE_RECORD,
}


@dataclass(frozen=True)
class VerifiedFrame:
    schema_version: str
    job_id: str
    attempt_id: str
    lease_epoch: int
    seq: int
    kind: FrameKind
    page_id: str
    profile_id: str
    check_type: CheckType
    byte_length: int
    sha256: str
    payload: bytes
    provenance: str


@dataclass(frozen=True)
class StreamSummary:
    termination: Termination
    frame_count: int
    total_payload_bytes: int
