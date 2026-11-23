"""Record payload contract `siteproof.record.v0.1` (provisional, Batch 02).

S1 verifies that record bytes are intact *and* that the record, the check outcome and the
artifacts are mutually consistent. It does NOT verify that what the (untrusted) browser
claims is true: a record is a self-report, bound to the stream only by the frame envelope
(kind / check_type / job / attempt / epoch). The record itself carries no job identifiers.

Check outcome derived from a record:

  HTTP     OBSERVED 200-299 -> PASS        (reason: record reason)
           OBSERVED 400-599 -> FAIL        (reason: record reason)
           OBSERVED 100-199, 300-399 -> UNKNOWN  (reason: HTTP_<status>_UNRESOLVED)
           UNKNOWN / SKIPPED -> UNKNOWN / SKIPPED
  LOAD     SUCCEEDED -> PASS, FAILED -> FAIL, UNKNOWN -> UNKNOWN, SKIPPED -> SKIPPED
  CAPTURE  capture_state SUCCEEDED -> always UNKNOWN (no trusted comparison exists):
             comparison BASELINE_PENDING (record reason BASELINE_NOT_SET)  -> BASELINE_PENDING
             comparison NOT_EVALUATED    (record reason COMPARISON_NOT_RUN) -> COMPARISON_NOT_RUN
           FAILED -> FAIL, UNKNOWN -> UNKNOWN, SKIPPED -> SKIPPED (comparison NOT_EVALUATED)
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

from .errors import RecordInvalid, ValidationError
from .frames import RECORD_KIND_FOR_CHECK, CheckType, FrameKind, VerifiedFrame
from .model import CheckOutcome, CheckReport, JobSnapshot, validate_reason_code
from .rules import (CAPTURE_SUCCESS_REASONS, REASON_BASELINE_PENDING,
                    REASON_COMPARISON_NOT_RUN, REASON_UPSTREAM_HTTP_FAILED,
                    classify_http_status)

RECORD_SCHEMA_VERSION = "siteproof.record.v0.1"
RECORD_KINDS: frozenset[FrameKind] = frozenset(RECORD_KIND_FOR_CHECK.values())

_HTTP_STATES = frozenset({"OBSERVED", "UNKNOWN", "SKIPPED"})
_LOAD_STATES = frozenset({"SUCCEEDED", "FAILED", "UNKNOWN", "SKIPPED"})
_CAPTURE_STATES = _LOAD_STATES
_COMPARISON_STATES = frozenset({"BASELINE_PENDING", "NOT_EVALUATED"})

# record reason that must accompany a successful capture, per comparison state
_CAPTURE_RECORD_REASON = {"BASELINE_PENDING": "BASELINE_NOT_SET",
                          "NOT_EVALUATED": REASON_COMPARISON_NOT_RUN}
_RESERVED_RECORD_REASONS = frozenset(_CAPTURE_RECORD_REASON.values()) | CAPTURE_SUCCESS_REASONS


@dataclass(frozen=True)
class ParsedRecord:
    record_type: CheckType
    state: str                       # HTTP state, LOAD state or CAPTURE capture_state
    reason_code: str
    status_code: Optional[int] = None
    comparison_state: Optional[str] = None


def _bad(code: str, detail: str = "") -> RecordInvalid:
    return RecordInvalid(code, detail)


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise _bad("RECORD_DUPLICATE_KEY", k)
        out[k] = v
    return out


def _no_constants(name: str) -> Any:
    raise _bad("RECORD_NONFINITE_NUMBER", name)


def _load_json(payload: bytes) -> Any:
    if not isinstance(payload, bytes):
        raise _bad("RECORD_NOT_BYTES")
    try:
        text = payload.decode("utf-8")  # strict
    except UnicodeDecodeError as e:
        raise _bad("RECORD_NOT_UTF8", str(e)) from e
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except RecordInvalid:
        raise
    except (ValueError, RecursionError) as e:
        raise _bad("RECORD_NOT_JSON", type(e).__name__) from e


def _expect_keys(obj: Mapping[str, Any], required: set[str], where: str) -> None:
    missing = required - set(obj)
    extra = set(obj) - required
    if missing:
        raise _bad("RECORD_FIELD_MISSING", f"{where}: {','.join(sorted(missing))}")
    if extra:
        raise _bad("RECORD_FIELD_UNEXPECTED", f"{where}: {','.join(sorted(extra))}")


def _str_in(obj: Mapping[str, Any], key: str, allowed: frozenset[str], code: str) -> str:
    v = obj[key]
    if not isinstance(v, str):
        raise _bad("RECORD_FIELD_TYPE", key)
    if v not in allowed:
        raise _bad(code, f"{key}={v!r}")
    return v


def _reason(obj: Mapping[str, Any]) -> str:
    try:
        return validate_reason_code(obj["reason_code"])
    except ValidationError as e:
        raise _bad("RECORD_REASON_INVALID", str(e)) from e


def parse_record(kind: FrameKind, payload: bytes) -> ParsedRecord:
    """Syntactic + schema validation of one record payload. Raises RecordInvalid."""
    if kind not in RECORD_KINDS:
        raise _bad("RECORD_KIND_NOT_A_RECORD", str(kind))
    doc = _load_json(payload)
    if not isinstance(doc, dict):
        raise _bad("RECORD_NOT_OBJECT")
    _expect_keys(doc, {"schema_version", "record_type", "observation"}, "record")
    if doc["schema_version"] != RECORD_SCHEMA_VERSION:
        raise _bad("RECORD_SCHEMA_VERSION", repr(doc["schema_version"]))
    rt = doc["record_type"]
    if not isinstance(rt, str) or rt not in {c.value for c in CheckType}:
        raise _bad("RECORD_TYPE_UNKNOWN", repr(rt))
    record_type = CheckType(rt)
    if RECORD_KIND_FOR_CHECK[record_type] is not kind:
        raise _bad("RECORD_TYPE_MISMATCH", f"{kind.value} carries record_type={rt}")
    obs = doc["observation"]
    if not isinstance(obs, dict):
        raise _bad("RECORD_FIELD_TYPE", "observation")

    if record_type is CheckType.HTTP:
        if not isinstance(obs.get("state"), str):
            raise _bad("RECORD_FIELD_MISSING", "observation: state")
        state = _str_in(obs, "state", _HTTP_STATES, "RECORD_STATE_INVALID")
        if state == "OBSERVED":
            _expect_keys(obs, {"state", "status_code", "reason_code"}, "observation")
            sc = obs["status_code"]
            if isinstance(sc, bool) or not isinstance(sc, int) or not 100 <= sc <= 599:
                raise _bad("RECORD_STATUS_CODE_INVALID", repr(sc))
            return ParsedRecord(record_type, state, _reason(obs), status_code=sc)
        _expect_keys(obs, {"state", "reason_code"}, "observation")
        return ParsedRecord(record_type, state, _reason(obs))

    if record_type is CheckType.LOAD:
        _expect_keys(obs, {"state", "reason_code"}, "observation")
        state = _str_in(obs, "state", _LOAD_STATES, "RECORD_STATE_INVALID")
        return ParsedRecord(record_type, state, _reason(obs))

    _expect_keys(obs, {"capture_state", "comparison_state", "reason_code"}, "observation")
    state = _str_in(obs, "capture_state", _CAPTURE_STATES, "RECORD_STATE_INVALID")
    comparison = _str_in(obs, "comparison_state", _COMPARISON_STATES,
                         "RECORD_COMPARISON_STATE_INVALID")
    return ParsedRecord(record_type, state, _reason(obs), comparison_state=comparison)


def derive_report(rec: ParsedRecord, snapshot: JobSnapshot) -> CheckReport:
    """Semantic step: derive the CheckReport a record supports (never a better one)."""
    ct = rec.record_type
    if ct is CheckType.HTTP:
        if rec.state == "OBSERVED":
            assert rec.status_code is not None
            outcome, unresolved = classify_http_status(rec.status_code,
                                                       observation_reliable=True)
            reason = unresolved if outcome is CheckOutcome.UNKNOWN else rec.reason_code
            return CheckReport(ct, outcome, reason)
        return CheckReport(ct, CheckOutcome(rec.state), rec.reason_code)

    if ct is CheckType.LOAD:
        outcome = {"SUCCEEDED": CheckOutcome.PASS, "FAILED": CheckOutcome.FAIL,
                   "UNKNOWN": CheckOutcome.UNKNOWN, "SKIPPED": CheckOutcome.SKIPPED}[rec.state]
        return CheckReport(ct, outcome, rec.reason_code)

    # CAPTURE
    if rec.reason_code in _RESERVED_RECORD_REASONS and rec.state != "SUCCEEDED":
        raise _bad("RECORD_REASON_RESERVED", rec.reason_code)
    if rec.state != "SUCCEEDED":
        if rec.comparison_state != "NOT_EVALUATED":
            raise _bad("RECORD_COMPARISON_STATE_INVALID",
                       f"capture {rec.state} cannot have comparison {rec.comparison_state}")
        outcome = {"FAILED": CheckOutcome.FAIL, "UNKNOWN": CheckOutcome.UNKNOWN,
                   "SKIPPED": CheckOutcome.SKIPPED}[rec.state]
        return CheckReport(ct, outcome, rec.reason_code)
    # capture succeeded: comparison state must agree with the job's baseline, and the
    # outcome is UNKNOWN because no trusted comparison exists.
    expected_cmp = "NOT_EVALUATED" if snapshot.baseline_id is not None else "BASELINE_PENDING"
    if rec.comparison_state != expected_cmp:
        raise _bad("RECORD_BASELINE_STATE_MISMATCH",
                   f"comparison_state={rec.comparison_state} but baseline "
                   f"{'set' if snapshot.baseline_id is not None else 'not set'}")
    if rec.reason_code != _CAPTURE_RECORD_REASON[expected_cmp]:
        raise _bad("RECORD_REASON_MISMATCH",
                   f"expected {_CAPTURE_RECORD_REASON[expected_cmp]}, got {rec.reason_code}")
    check_reason = REASON_BASELINE_PENDING if expected_cmp == "BASELINE_PENDING" \
        else REASON_COMPARISON_NOT_RUN
    return CheckReport(ct, CheckOutcome.UNKNOWN, check_reason)


def validate_skips(reports: Mapping[CheckType, CheckReport]) -> None:
    """A SKIPPED check is legitimate only when the HTTP check definitively FAILED and the
    reason is UPSTREAM_HTTP_FAILED. HTTP itself has nothing upstream to justify a skip."""
    http = reports.get(CheckType.HTTP)
    for ct, rep in reports.items():
        if rep.outcome is not CheckOutcome.SKIPPED:
            continue
        if ct is CheckType.HTTP:
            raise _bad("SKIP_NOT_JUSTIFIED", "HTTP has no upstream check to justify a skip")
        if rep.reason_code != REASON_UPSTREAM_HTTP_FAILED:
            raise _bad("SKIP_NOT_JUSTIFIED", f"{ct.value}: reason {rep.reason_code!r}")
        if http is None or http.outcome is not CheckOutcome.FAIL:
            raise _bad("SKIP_NOT_JUSTIFIED",
                       f"{ct.value}: upstream HTTP is "
                       f"{'absent' if http is None else http.outcome.value}, not FAIL")


def derive_reports(frames: Sequence[VerifiedFrame], snapshot: JobSnapshot
                   ) -> dict[CheckType, CheckReport]:
    """Parse every record frame and derive one report per check. Checks without a record
    frame are simply absent (the caller decides; nothing is back-filled)."""
    out: dict[CheckType, CheckReport] = {}
    for f in frames:
        if f.kind not in RECORD_KINDS:
            continue
        rec = parse_record(f.kind, f.payload)
        if rec.record_type is not f.check_type:  # frame envelope vs record identity
            raise _bad("RECORD_TYPE_MISMATCH", f"frame {f.check_type.value} / record "
                       f"{rec.record_type.value}")
        out[f.check_type] = derive_report(rec, snapshot)
    validate_skips(out)
    return out
