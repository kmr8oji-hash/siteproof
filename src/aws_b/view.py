"""Read projection: what may be shown as the current monitoring state.

`UP` is shown only for a fresh, recorded PASS while monitoring is armed. A stopped
monitor, a silent monitor, a claimed-but-unrecorded slot and an unknown probe outcome are
all shown as something other than UP.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from .model import STATE_CLAIMED, STATE_RECORDED, parse_utc


def _text(item: dict[str, Any], name: str) -> Optional[str]:
    value = item.get(name)
    return value.get("S") if isinstance(value, dict) else None


def summarize(head: Optional[dict[str, Any]], runs: list[dict[str, Any]], *,
              now: datetime, interval_seconds: int, stale_after_intervals: int = 3
              ) -> dict[str, Any]:
    """`runs` are RUN# items in any order; the newest slot decides, never the last write."""
    armed = bool(head) and head.get("enabled", {}).get("BOOL") is True
    base = {"armed": armed, "observed_slot": None, "reason": None}
    dated = [(parse_utc(_text(r, "sk")), r) for r in runs]
    dated = [(when, r) for when, r in dated if when is not None]
    if not dated:
        return {**base, "state": "UNKNOWN", "reason": "NO_OBSERVATION"}
    when, latest = max(dated, key=lambda pair: pair[0])
    base["observed_slot"] = _text(latest, "sk")
    age = (now - when).total_seconds()
    if age > interval_seconds * stale_after_intervals:
        return {**base, "state": "STALE", "reason": "NO_RECENT_OBSERVATION"}
    if not armed:
        return {**base, "state": "STOPPED", "reason": "MONITORING_NOT_ARMED"}
    state = _text(latest, "state")
    if state == STATE_CLAIMED:
        return {**base, "state": "UNKNOWN", "reason": "RESULT_NOT_RECORDED"}
    if state != STATE_RECORDED:
        return {**base, "state": "UNKNOWN", "reason": "RECORD_STATE_INVALID"}
    outcome, reason = _text(latest, "outcome"), _text(latest, "reason")
    if outcome == "PASS":
        return {**base, "state": "UP", "reason": reason}
    if outcome == "FAIL":
        return {**base, "state": "DOWN", "reason": reason}
    return {**base, "state": "UNKNOWN", "reason": reason or "OUTCOME_UNKNOWN"}
