"""Bounded JSON v1 syntax/consistency checks, never issuer authentication.

Parsing a claim of STRUCTURALLY_CHECKED does not re-read its evidence. Only the
projection reader observes evidence, at a point in time. UI imports remain
unauthenticated regardless of the source string or this validation result.
"""

import json
import re
from types import MappingProxyType

SCHEMA_VERSION = "siteproof.offline-result.v1"
MAX_BYTES = 1048576
NOTICE = "オフライン結果です。撮影条件の真正性およびUIでの証拠検証は保証しません。"
FIXED = MappingProxyType({
    "schema_version": SCHEMA_VERSION, "record_type": "OFFLINE_RESULT",
    "source": "OFFLINE_PROJECTION", "profile_trust": "UNATTESTED",
    "eligibility": "UNKNOWN", "comparison": "NOT_RUN",
    "human_approval": "NOT_RECORDED",
})
_KEYS = set(FIXED) | {"job_id", "attempt_id", "bridge", "evidence", "unknown_reasons", "notice"}
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,127}")


class ContractError(ValueError):
    """A bounded, fixed reason; untrusted content is not echoed in errors."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _need(condition, code):
    if not condition:
        raise ContractError(code)


def _keys(value, names):
    _need(type(value) is dict, "TYPE")
    _need(all(type(key) is str for key in value) and set(value) == set(names), "KEYS")


def _text(value):
    _need(type(value) is str, "TYPE")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise ContractError("BAD_STRING") from None
    return value


def _nullable(value, pattern, code):
    if value is not None:
        _need(type(value) is str and pattern.fullmatch(value) is not None, code)


def _ref(value, job, attempt, *, manifest):
    value = _text(value)
    _need(len(value) <= 4096 and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)
          and ":" not in value and "\\" not in value, "REF")
    parts = value.split("/")
    _need(len(parts) == 3 and parts[:2] == [job, attempt]
          and all(p not in ("", ".", "..") and not p.endswith((".", " ")) for p in parts), "REF")
    _need((parts[2] == "manifest.json") is manifest, "REF")


def validate_report(value):
    """Return a defensive dict of a structurally valid UNAUTHENTICATED report.

    Exact keys/types and fixed semantics are required; no repair/defaulting or
    conversion of unsupported values. Unknown reasons must explain NOT_RUN.
    """
    _keys(value, _KEYS)
    for key, expected in FIXED.items():
        _need(type(value[key]) is str and value[key] == expected, "FIXED_VALUE")
    _need(type(value["notice"]) is str and value["notice"] == NOTICE, "NOTICE")
    job, attempt = value["job_id"], value["attempt_id"]
    _nullable(job, _ID, "ID")
    _nullable(attempt, _ID, "ID")
    bridge, evidence, reasons = value["bridge"], value["evidence"], value["unknown_reasons"]
    _keys(bridge, {"status", "reason"})
    _keys(evidence, {"status", "manifest_ref", "screenshot_ref"})
    bs, es, reason = bridge["status"], evidence["status"], bridge["reason"]
    _need(type(bs) is str and bs in ("STRUCTURALLY_CHECKED", "REJECTED", "UNKNOWN"), "ENUM")
    _need(type(es) is str and es in ("STRUCTURALLY_CHECKED", "NOT_VERIFIED"), "ENUM")
    _nullable(reason, _CODE, "REASON_CODE")
    _need(type(reasons) is list and 1 <= len(reasons) <= 128, "UNKNOWN_REASONS")
    _need(all(type(r) is str and _CODE.fullmatch(r) is not None for r in reasons), "UNKNOWN_REASONS")
    _need(len(set(reasons)) == len(reasons) and "COMPARISON_NOT_RUN" in reasons, "UNKNOWN_REASONS")
    _need(reason is None or reason in reasons, "CROSS_FIELD")
    _need((bs == "REJECTED") == (reason is not None), "CROSS_FIELD")
    _need((bs == "STRUCTURALLY_CHECKED") == (es == "STRUCTURALLY_CHECKED"), "CROSS_FIELD")
    manifest, screenshot = evidence["manifest_ref"], evidence["screenshot_ref"]
    if es == "STRUCTURALLY_CHECKED":
        _need(job is not None and attempt is not None and "PROFILE_UNATTESTED" in reasons, "CROSS_FIELD")
        _ref(manifest, job, attempt, manifest=True)
        _ref(screenshot, job, attempt, manifest=False)
    else:
        _need(manifest is None and screenshot is None, "CROSS_FIELD")
    return {**FIXED, "job_id": job, "attempt_id": attempt,
            "bridge": {"status": bs, "reason": reason},
            "evidence": {"status": es, "manifest_ref": manifest, "screenshot_ref": screenshot},
            "unknown_reasons": list(reasons), "notice": NOTICE}


def canonical_json(value):
    """Deterministic ASCII JSON of a validated report; performs no I/O."""
    clean = validate_report(value)
    result = json.dumps(clean, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    _need(len(result.encode("utf-8")) <= MAX_BYTES, "TOO_LARGE")
    return result


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, "DUPLICATE_KEY")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ContractError("UNSUPPORTED_VALUE")


def parse_report(data):
    """Parse bounded strict UTF-8 (bytes or str), reject duplicate members/BOM.

    This validates claims, NOT their author or evidence. No reference is opened.
    """
    _need(type(data) in (str, bytes), "TYPE")
    try:
        raw = data.encode("utf-8", errors="strict") if type(data) is str else data
        _need(0 < len(raw) <= MAX_BYTES, "TOO_LARGE" if raw else "EMPTY")
        text = raw.decode("utf-8", errors="strict")
        _need(not text.startswith("\ufeff"), "BOM")
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_invalid_constant)
        return validate_report(value)
    except ContractError:
        raise
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise ContractError("SYNTAX") from None
