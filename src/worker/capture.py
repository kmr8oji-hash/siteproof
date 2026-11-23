"""Untrusted browser-side producer. It receives no DB or evidence-directory path.

Only bounded framed bytes cross to the trusted side. Observations are self reports,
not proof of profile authenticity, browser execution or network isolation.
"""
import io
import json
import struct
import time
from dataclasses import dataclass

from src.core.model import validate_id
from src.isolation.frames import FrameLimits, MAGIC, CONTRACT_VERSION


class CaptureStopped(Exception):
    pass


@dataclass(frozen=True)
class CaptureRequest:
    page_id: str
    profile: object
    url: str
    baseline_id: str | None = None

    def __post_init__(self):
        validate_id(self.page_id, 'page_id')
        validate_id(self.profile.profile_id, 'profile_id')
        if not self.profile.is_intact():
            raise ValueError('invalid profile')


class FrameWriter:
    def __init__(self, request, limits, max_wire_bytes=None):
        self.request, self.limits = request, limits
        self.max_wire_bytes = max_wire_bytes
        self.data, self.seq, self.total, self.ended = bytearray(), 0, 0, False

    def emit(self, kind, payload=b''):
        if self.ended or type(payload) is not bytes:
            raise ValueError('invalid frame')
        if kind not in ('HTTP_RECORD', 'LOAD_RECORD', 'CAPTURE_RECORD', 'SCREENSHOT_PNG', 'END'):
            raise ValueError('invalid kind')
        end = kind == 'END'
        limit = self.limits.max_png_bytes if kind == 'SCREENSHOT_PNG' else self.limits.max_record_bytes
        if (len(payload) > limit or self.total + len(payload) > self.limits.max_stream_payload_bytes
                or (not end and self.seq >= self.limits.max_data_frames) or (end and payload)):
            raise ValueError('OUTPUT_LIMIT')
        h = {'magic': MAGIC, 'version': CONTRACT_VERSION, 'seq': self.seq, 'kind': kind,
             'page_id': '' if end else self.request.page_id,
             'profile_id': '' if end else self.request.profile.profile_id,
             'declared_length': len(payload)}
        raw = json.dumps(h, separators=(',', ':')).encode()
        if len(raw) > self.limits.max_header_bytes:
            raise ValueError('HEADER_LIMIT')
        if self.max_wire_bytes is not None and len(self.data) + 4 + len(raw) + len(payload) > self.max_wire_bytes:
            raise ValueError('OUTPUT_LIMIT')
        self.data.extend(struct.pack('!I', len(raw)) + raw + payload)
        self.total += len(payload)
        self.seq += 1
        self.ended = end

    def record(self, kind, **observation):
        self.emit(kind + '_RECORD', json.dumps({
            'schema_version': 'siteproof.record.v0.1', 'record_type': kind,
            'observation': observation}, separators=(',', ':')).encode())


@dataclass(frozen=True)
class CaptureOutput:
    wire: bytes
    reason: str
    cleanup_confirmed: bool


def capture(request, driver, lease, resources, *, limits=None, cancel=None,
            clock=time.monotonic):
    """Cooperative stage deadlines + bounded output; no synchronous-call kill claim.

    Caller must run the real producer in a killable isolated process. This function
    intentionally receives neither a Repository nor an ArtifactStore.
    """
    limits = limits or FrameLimits()
    writer = FrameWriter(request, limits, resources.output_bytes)
    deadline = clock() + resources.seconds
    reason, clean = 'CAPTURE_COMPLETE', False
    stage = 'BROWSER_START'

    def check():
        if cancel is not None and cancel.is_set():
            raise CaptureStopped('CANCELLED')
        if clock() >= deadline:
            raise TimeoutError()
        lease.check(request.url)
        return min(resources.stage_seconds, deadline - clock())

    try:
        check()
        driver.start(request.profile)
        stage = 'HTTP'
        status = driver.http(request.url, check())
        check()
        if type(status) is not int or not 100 <= status <= 599:
            raise ValueError('INVALID_HTTP_STATUS')
        writer.record('HTTP', state='OBSERVED', status_code=status, reason_code='HTTP_OBSERVED')
        if status >= 400:
            writer.record('LOAD', state='SKIPPED', reason_code='UPSTREAM_HTTP_FAILED')
            writer.record('CAPTURE', capture_state='SKIPPED', comparison_state='NOT_EVALUATED',
                          reason_code='UPSTREAM_HTTP_FAILED')
        else:
            stage = 'LOAD'
            driver.load(check())
            check()
            writer.record('LOAD', state='SUCCEEDED', reason_code='LOAD_COMPLETE')
            stage = 'CAPTURE'
            image = driver.capture(request.profile, check())
            check()
            writer.emit('SCREENSHOT_PNG', image)
            writer.record('CAPTURE', capture_state='SUCCEEDED',
                          comparison_state='NOT_EVALUATED' if request.baseline_id else 'BASELINE_PENDING',
                          reason_code='COMPARISON_NOT_RUN' if request.baseline_id else 'BASELINE_NOT_SET')
        writer.emit('END')
    except CaptureStopped:
        reason = 'CANCELLED'
    except TimeoutError:
        reason = stage + '_TIMEOUT'
    except Exception:
        # Partial bytes are retained but no synthetic END/success is appended.
        reason = stage + '_FAILED'
    finally:
        try:
            clean = driver.close() is True
        except Exception:
            clean = False
    if not clean:
        reason = 'BROWSER_CLEANUP_UNCONFIRMED'
    raw = bytes(writer.data)
    if len(raw) > resources.output_bytes:
        raw, reason = b'', 'OUTPUT_LIMIT'
    return CaptureOutput(raw, reason, clean)


class MemoryChannel(io.BytesIO):
    """Fixture/simulation channel only; real runtime supplies a separate pipe."""
    pass
