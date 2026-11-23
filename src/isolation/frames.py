"""Bounded, single-use offline reader for siteproof.bridge.v0.1.

Transport header: magic='SITEPROOF', version=CONTRACT_VERSION, zero-based seq,
kind, page_id, profile_id, declared_length; no additional keys. END uses the
next seq, empty page/profile IDs and length zero, and must be followed by EOF.
Verified transport is not independent verification of browser observations.
"""

from dataclasses import dataclass
import hashlib
import json
import math
import struct
import time
from typing import BinaryIO, Callable, Literal
import zlib


CONTRACT_VERSION = "siteproof.bridge.v0.1"
MAGIC = "SITEPROOF"
PROVENANCE = "untrusted_browser_validated_transport"
_CHECK_TYPES = {"HTTP_RECORD": "HTTP", "LOAD_RECORD": "LOAD",
                "CAPTURE_RECORD": "CAPTURE", "SCREENSHOT_PNG": "CAPTURE"}
_HEADER_KEYS = {"magic", "version", "seq", "kind", "page_id", "profile_id",
                "declared_length"}
_TRUSTED_KEYS = {"job_id", "attempt_id", "lease_epoch"}
_CHUNK_SIZE = 64 * 1024


def _identifier(value):
    if type(value) is not str or not value or not value.strip():
        return False
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        return False
    return not any(ord(char) < 32 or ord(char) == 127 for char in value)


def _time_value(value):
    try:
        return type(value) in (float, int) and math.isfinite(value)
    except OverflowError:
        return False


@dataclass(frozen=True)
class TrustedContext:
    job_id: str
    attempt_id: str
    lease_epoch: int

    def __post_init__(self):
        if (not _identifier(self.job_id) or not _identifier(self.attempt_id) or
                type(self.lease_epoch) is not int or self.lease_epoch < 0):
            raise ValueError("invalid trusted context")


@dataclass(frozen=True)
class FrameLimits:
    max_header_bytes: int = 4 * 1024
    max_record_bytes: int = 2 * 1024 * 1024
    max_png_bytes: int = 8 * 1024 * 1024
    max_stream_payload_bytes: int = 32 * 1024 * 1024
    max_data_frames: int = 64
    timeout_seconds: float = 30.0
    max_png_pixels: int = 40_000_000

    def __post_init__(self):
        for value in (self.max_header_bytes, self.max_record_bytes,
                      self.max_png_bytes, self.max_stream_payload_bytes,
                      self.max_data_frames, self.max_png_pixels):
            if type(value) is not int or value <= 0:
                raise ValueError("frame limits must be positive integers")
        if not _time_value(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("timeout must be finite and positive")


@dataclass(frozen=True)
class VerifiedFrame:
    schema_version: str
    job_id: str
    attempt_id: str
    lease_epoch: int
    seq: int
    kind: Literal["HTTP_RECORD", "LOAD_RECORD", "CAPTURE_RECORD", "SCREENSHOT_PNG"]
    page_id: str
    profile_id: str
    check_type: Literal["HTTP", "LOAD", "CAPTURE"]
    byte_length: int
    sha256: str
    payload: bytes
    provenance: str


@dataclass(frozen=True)
class StreamSummary:
    termination: Literal["CLEAN", "TRUNCATED", "TIMEOUT", "OVERSIZE", "PROTOCOL_ERROR"]
    frame_count: int
    total_payload_bytes: int


@dataclass(frozen=True)
class StreamResult:
    frames: tuple[VerifiedFrame, ...]
    summary: StreamSummary
    reason: str


class _Failure(Exception):
    def __init__(self, termination, reason):
        self.termination = termination
        self.reason = reason


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("non-JSON numeric constant")


def _validate_png(payload: bytes, max_pixels: int):
    """Check container/chunk order, lengths, CRCs and IHDR, never inflate IDAT.

    This intentionally cannot prove that IDAT is decodable or matches IHDR.
    """
    def fail():
        raise _Failure("PROTOCOL_ERROR", "INVALID_PNG")

    if not payload.startswith(b"\x89PNG\r\n\x1a\n"):
        fail()
    offset = 8
    seen_ihdr = seen_idat = seen_plte = ended_idat = False
    idat_bytes = 0
    color = depth = None
    while offset < len(payload):
        if len(payload) - offset < 12:
            fail()
        length = int.from_bytes(payload[offset:offset + 4], "big")
        chunk_type = payload[offset + 4:offset + 8]
        if (length > 0x7fffffff or length > len(payload) - offset - 12 or
                any(not (65 <= b <= 90 or 97 <= b <= 122) for b in chunk_type) or
                chunk_type[2] & 32):
            fail()
        data_start = offset + 8
        data_end = data_start + length
        data = memoryview(payload)[data_start:data_end]
        expected_crc = int.from_bytes(payload[data_end:data_end + 4], "big")
        if zlib.crc32(data, zlib.crc32(chunk_type)) & 0xffffffff != expected_crc:
            fail()
        offset = data_end + 4
        if not seen_ihdr and chunk_type != b"IHDR":
            fail()
        if chunk_type == b"IHDR":
            if seen_ihdr or length != 13:
                fail()
            width, height, depth, color, compression, filtering, interlace = struct.unpack(
                ">IIBBBBB", data)
            if (not 0 < width <= 0x7fffffff or not 0 < height <= 0x7fffffff or
                    width * height > max_pixels or compression != 0 or filtering != 0 or
                    interlace not in (0, 1) or depth not in {
                        0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8),
                        4: (8, 16), 6: (8, 16),
                    }.get(color, ())):
                fail()
            seen_ihdr = True
        elif chunk_type == b"PLTE":
            if (seen_plte or seen_idat or color in (0, 4) or length == 0 or
                    length % 3 or length > 768 or
                    (color == 3 and length // 3 > 2 ** depth)):
                fail()
            seen_plte = True
        elif chunk_type == b"IDAT":
            if ended_idat or (color == 3 and not seen_plte):
                fail()
            seen_idat = True
            idat_bytes += length
        elif chunk_type == b"IEND":
            if length != 0 or not seen_idat or not idat_bytes or offset != len(payload):
                fail()
            return
        else:
            # Unknown critical chunks must never be silently accepted.
            if not chunk_type[0] & 32:
                fail()
            if seen_idat:
                ended_idat = True
    fail()


class FrameReader:
    """Return bounded verified frames plus an authoritative stream summary.

    Partial verified frames are retained on failure, but CLEAN is required for
    a complete stream. Counts cover only accepted data frames, never END or a
    rejected/incomplete frame. A synchronous read cannot interrupt blocking I/O;
    the supplied file-like source must itself be bounded/nonblocking or timeout.
    """

    def __init__(self, source: BinaryIO, context: TrustedContext,
                 limits: FrameLimits | None = None, *,
                 clock: Callable[[], float] = time.monotonic):
        if type(context) is not TrustedContext:
            raise ValueError("trusted context is required")
        if limits is not None and type(limits) is not FrameLimits:
            raise ValueError("invalid frame limits")
        self._source = source
        self._context = context
        self._limits = limits if limits is not None else FrameLimits()
        self._clock = clock
        self._used = False
        self._started = self._last_time = None

    def _check_time(self):
        try:
            now = self._clock()
        except (OSError, ValueError):
            raise _Failure("PROTOCOL_ERROR", "INVALID_CLOCK") from None
        if not _time_value(now) or (self._last_time is not None and now < self._last_time):
            raise _Failure("PROTOCOL_ERROR", "INVALID_CLOCK")
        if self._started is None:
            self._started = now
        self._last_time = now
        if now - self._started >= self._limits.timeout_seconds:
            raise _Failure("TIMEOUT", "DEADLINE")

    def _read_piece(self, size):
        self._check_time()
        try:
            part = self._source.read(size)
        except TimeoutError:
            raise _Failure("TIMEOUT", "SOURCE_TIMEOUT") from None
        except (OSError, ValueError):
            raise _Failure("PROTOCOL_ERROR", "SOURCE_ERROR") from None
        self._check_time()
        if type(part) is not bytes or len(part) > size:
            raise _Failure("PROTOCOL_ERROR", "INVALID_READ_RESULT")
        return part

    def _read_exact(self, size):
        # Size is a validated header/payload length, or the constant 4.
        parts = bytearray()
        while len(parts) < size:
            part = self._read_piece(min(size - len(parts), _CHUNK_SIZE))
            if not part:
                raise _Failure("TRUNCATED", "UNEXPECTED_EOF")
            parts.extend(part)
        return bytes(parts)

    def _header(self, expected_seq):
        header_size = int.from_bytes(self._read_exact(4), "big")
        if header_size > self._limits.max_header_bytes:
            raise _Failure("OVERSIZE", "HEADER_LIMIT")
        if header_size == 0:
            raise _Failure("PROTOCOL_ERROR", "EMPTY_HEADER")
        raw = self._read_exact(header_size)
        try:
            header = json.loads(raw.decode("utf-8", "strict"),
                                object_pairs_hook=_unique_object,
                                parse_constant=_reject_constant)
        except (UnicodeError, ValueError, RecursionError):
            raise _Failure("PROTOCOL_ERROR", "INVALID_JSON_HEADER") from None
        if type(header) is not dict:
            raise _Failure("PROTOCOL_ERROR", "INVALID_HEADER_TYPE")
        if _TRUSTED_KEYS.intersection(header):
            raise _Failure("PROTOCOL_ERROR", "UNTRUSTED_CONTEXT_CLAIM")
        if set(header) != _HEADER_KEYS:
            raise _Failure("PROTOCOL_ERROR", "HEADER_FIELDS")
        if header["magic"] != MAGIC or type(header["magic"]) is not str:
            raise _Failure("PROTOCOL_ERROR", "INVALID_MAGIC")
        if header["version"] != CONTRACT_VERSION or type(header["version"]) is not str:
            raise _Failure("PROTOCOL_ERROR", "INVALID_VERSION")
        if type(header["seq"]) is not int or header["seq"] != expected_seq:
            raise _Failure("PROTOCOL_ERROR", "INVALID_SEQUENCE")
        kind = header["kind"]
        if type(kind) is not str or (kind not in _CHECK_TYPES and kind != "END"):
            raise _Failure("PROTOCOL_ERROR", "INVALID_KIND")
        length = header["declared_length"]
        if type(length) is not int or length < 0:
            raise _Failure("PROTOCOL_ERROR", "INVALID_LENGTH")
        if kind == "END":
            if (length != 0 or header["page_id"] != "" or header["profile_id"] != ""):
                raise _Failure("PROTOCOL_ERROR", "INVALID_END")
        elif not _identifier(header["page_id"]) or not _identifier(header["profile_id"]):
            raise _Failure("PROTOCOL_ERROR", "INVALID_IDENTIFIER")
        return header

    def read(self) -> StreamResult:
        if self._used:
            raise RuntimeError("FrameReader is single-use")
        self._used = True
        frames = []
        total = 0
        try:
            while True:
                header = self._header(len(frames))
                kind, length = header["kind"], header["declared_length"]
                if kind == "END":
                    if self._read_piece(1):
                        raise _Failure("PROTOCOL_ERROR", "TRAILING_DATA")
                    return StreamResult(tuple(frames), StreamSummary("CLEAN", len(frames), total),
                                        "COMPLETE_END")
                limit = (self._limits.max_png_bytes if kind == "SCREENSHOT_PNG"
                         else self._limits.max_record_bytes)
                if length > limit:
                    raise _Failure("OVERSIZE", "FRAME_PAYLOAD_LIMIT")
                if total + length > self._limits.max_stream_payload_bytes:
                    raise _Failure("OVERSIZE", "STREAM_PAYLOAD_LIMIT")
                if len(frames) >= self._limits.max_data_frames:
                    raise _Failure("OVERSIZE", "FRAME_COUNT_LIMIT")
                payload = self._read_exact(length)
                if kind == "SCREENSHOT_PNG":
                    _validate_png(payload, self._limits.max_png_pixels)
                context = self._context
                frames.append(VerifiedFrame(
                    CONTRACT_VERSION, context.job_id, context.attempt_id, context.lease_epoch,
                    header["seq"], kind, header["page_id"], header["profile_id"],
                    _CHECK_TYPES[kind], len(payload), hashlib.sha256(payload).hexdigest(),
                    payload, PROVENANCE,
                ))
                total += len(payload)
        except _Failure as failure:
            return StreamResult(tuple(frames), StreamSummary(failure.termination, len(frames), total),
                                failure.reason)
