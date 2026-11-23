"""Control-plane record of one pilot run, kept in DynamoDB with conditional writes only.

Two items in one table:

    SLOT          / SINGLETON   created once; never deleted or reset by this code.
                                A second reservation therefore fails: no re-arm.
    PILOT#<run>   / STATE       state, version and timestamps of that single run.

The control record is a journal, not a safety interlock. Termination of the instance
never waits for, or depends on, any write here (see watchdog.py and the OS timer).
Worker-local job state stays in the existing SQLite store unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from src.core.model import validate_id

CONDITION_FAILED = "ConditionalCheckFailedException"

RESERVED = "RESERVED"                          # controller accepted the one pilot run
RUNNING = "RUNNING"                            # worker booted and armed its OS timer
ISOLATION_PASSED = "ISOLATION_PASSED"          # fixture-only isolation measured on EC2
ISOLATION_FAILED = "ISOLATION_FAILED"          # terminal: no capture is attempted
EVIDENCE_COMMITTED = "EVIDENCE_COMMITTED"      # run manifest published write-once
FAILED = "FAILED"                              # terminal: worker reported failure
TERMINATE_REQUESTED = "TERMINATE_REQUESTED"    # watchdog called TerminateInstances
TERMINATED_VERIFIED = "TERMINATED_VERIFIED"    # terminal: instance observed terminated
TERMINATE_UNCERTAIN = "TERMINATE_UNCERTAIN"    # terminal until a human resolves it

# Worker-driven progress. Watchdog states may be entered from any non-final state.
ALLOWED: dict[str, frozenset[str]] = {
    RESERVED: frozenset({RUNNING}),
    RUNNING: frozenset({ISOLATION_PASSED, ISOLATION_FAILED, FAILED}),
    ISOLATION_PASSED: frozenset({EVIDENCE_COMMITTED, FAILED}),
    ISOLATION_FAILED: frozenset(),
    EVIDENCE_COMMITTED: frozenset(),
    FAILED: frozenset(),
    TERMINATE_REQUESTED: frozenset({TERMINATED_VERIFIED, TERMINATE_UNCERTAIN}),
    TERMINATE_UNCERTAIN: frozenset({TERMINATED_VERIFIED}),
    TERMINATED_VERIFIED: frozenset(),
}
WATCHDOG_STATES = frozenset({TERMINATE_REQUESTED, TERMINATED_VERIFIED, TERMINATE_UNCERTAIN})


def can_transition(source: str, target: str) -> bool:
    if target == TERMINATE_REQUESTED:
        return source in ALLOWED and source not in WATCHDOG_STATES
    return target in ALLOWED.get(source, frozenset())


def _s(value: str) -> dict[str, str]:
    return {"S": value}


def _n(value: int) -> dict[str, str]:
    return {"N": str(value)}


SLOT_KEY = {"pk": _s("SLOT"), "sk": _s("SINGLETON")}


def pilot_key(run_id: str) -> dict[str, dict[str, str]]:
    return {"pk": _s("PILOT#" + validate_id(run_id, "pilot_run_id")), "sk": _s("STATE")}


def build_slot_request(table: str, run_id: str, at: str) -> dict[str, Any]:
    return {"TableName": table,
            "Item": {**SLOT_KEY, "pilot_run_id": _s(validate_id(run_id, "pilot_run_id")),
                     "consumed_at": _s(at)},
            "ConditionExpression": "attribute_not_exists(#pk)",
            "ExpressionAttributeNames": {"#pk": "pk"},
            "ReturnValuesOnConditionCheckFailure": "ALL_OLD"}


def build_reserve_request(table: str, run_id: str, deadline: str, at: str) -> dict[str, Any]:
    return {"TableName": table,
            "Item": {**pilot_key(run_id), "state": _s(RESERVED), "version": _n(1),
                     "hard_deadline_utc": _s(deadline), "reserved_at": _s(at),
                     "updated_at": _s(at)},
            "ConditionExpression": "attribute_not_exists(#pk)",
            "ExpressionAttributeNames": {"#pk": "pk"}}


def build_transition_request(table: str, run_id: str, source: str, target: str,
                             version: int, at: str, detail: str = "") -> dict[str, Any]:
    if not can_transition(source, target):
        raise ValueError(f"transition {source} -> {target} is not allowed")
    return {"TableName": table, "Key": pilot_key(run_id),
            "UpdateExpression": "SET #state = :to, #version = :next, #updated = :at, "
                                "#detail = :detail",
            "ConditionExpression": "#state = :from AND #version = :version",
            "ExpressionAttributeNames": {"#state": "state", "#version": "version",
                                         "#updated": "updated_at", "#detail": "detail"},
            "ExpressionAttributeValues": {":to": _s(target), ":from": _s(source),
                                          ":version": _n(version), ":next": _n(version + 1),
                                          ":at": _s(at), ":detail": _s(detail[:256])},
            "ReturnValuesOnConditionCheckFailure": "ALL_OLD"}


@dataclass(frozen=True)
class ControlResult:
    ok: bool
    reason: str
    state: Optional[str] = None
    version: Optional[int] = None
    error: Optional[str] = None


def _code(exc: BaseException) -> Optional[str]:
    response = getattr(exc, "response", None)
    if isinstance(response, dict) and isinstance(response.get("Error"), dict):
        return response["Error"].get("Code")
    return None


def _view(item: Optional[dict[str, Any]]) -> tuple[Optional[str], Optional[int]]:
    try:
        return item["state"]["S"], int(item["version"]["N"])
    except (TypeError, KeyError, ValueError):
        return None, None


class ControlStore:
    def __init__(self, client: Any, table: str) -> None:
        self._client, self._table = client, table

    def reserve(self, run_id: str, deadline: str, at: str) -> ControlResult:
        """Consume the singleton slot, then create the run record. Never resets either."""
        slot = build_slot_request(self._table, run_id, at)       # validates the run id
        record = build_reserve_request(self._table, run_id, deadline, at)
        try:
            self._client.put_item(**slot)
        except Exception as exc:
            if _code(exc) != CONDITION_FAILED:
                return ControlResult(False, "RESERVE_UNCERTAIN", error=type(exc).__name__)
            old = getattr(exc, "response", {}).get("Item") or {}
            if old.get("pilot_run_id", {}).get("S") != run_id:
                return ControlResult(False, "SLOT_CONSUMED_BY_OTHER_RUN")
            # Same run re-sent (retry after a lost acknowledgement): fall through and
            # return the already stored record instead of creating a second one.
        try:
            self._client.put_item(**record)
        except Exception as exc:
            if _code(exc) != CONDITION_FAILED:
                return ControlResult(False, "RESERVE_UNCERTAIN", error=type(exc).__name__)
            current = self.read(run_id)
            return ControlResult(False, "ALREADY_RESERVED", current.state, current.version)
        return ControlResult(True, RESERVED, RESERVED, 1)

    def read(self, run_id: str) -> ControlResult:
        try:
            item = self._client.get_item(TableName=self._table, Key=pilot_key(run_id),
                                         ConsistentRead=True).get("Item")
        except Exception as exc:
            return ControlResult(False, "READ_FAILED", error=type(exc).__name__)
        if not item:
            return ControlResult(False, "NOT_FOUND")
        state, version = _view(item)
        if state is None:
            return ControlResult(False, "RECORD_INVALID")
        return ControlResult(True, "OK", state, version)

    def transition(self, run_id: str, source: str, target: str, version: int, at: str,
                   detail: str = "") -> ControlResult:
        try:
            request = build_transition_request(self._table, run_id, source, target,
                                               version, at, detail)
        except ValueError:
            return ControlResult(False, "TRANSITION_NOT_ALLOWED", source, version)
        try:
            self._client.update_item(**request)
        except Exception as exc:
            if _code(exc) == CONDITION_FAILED:
                state, current = _view(getattr(exc, "response", {}).get("Item"))
                return ControlResult(False, "STATE_CHANGED", state, current)
            return ControlResult(False, "TRANSITION_UNCERTAIN", source, version,
                                 type(exc).__name__)
        return ControlResult(True, target, target, version + 1)
