"""DynamoDB control and run records for AWS-B.

Single table, two item shapes:

    CONTROL#<target> / HEAD     operator-armed switch: enabled, execution_generation,
                                policy_version, target_hostname, last_slot
    RUN#<target>     / <slot>   one record per scheduled slot: CLAIMED -> RECORDED

The *claim* is one conditional UpdateItem on HEAD. It atomically checks that monitoring is
armed, that the event's generation and policy are current, and that the slot is strictly
newer than the last claimed slot. A duplicate, an older (out-of-order) event and an event
that arrives after a stop therefore all fail the same write, with no read-then-write gap.

Request builders are pure so their expressions are testable without AWS. `DynamoStore`
needs a low-level DynamoDB client; none is created at import time.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .model import STATE_CLAIMED, STATE_RECORDED, RECORD_SCHEMA, head_key, run_key

CONDITION_FAILED = "ConditionalCheckFailedException"


def _s(value: str) -> dict[str, str]:
    return {"S": value}


def _n(value: int) -> dict[str, str]:
    return {"N": str(value)}


def _key(key: dict[str, str]) -> dict[str, dict[str, str]]:
    return {name: _s(value) for name, value in key.items()}


@dataclass(frozen=True)
class Claim:
    target_id: str
    hostname: str
    policy_version: str
    execution_generation: int
    scheduled_slot: str
    logical_run_key: str
    attempt_id: str
    claimed_at: str
    expires_at: int


@dataclass(frozen=True)
class StoreResult:
    ok: bool
    reason: str
    error: Optional[str] = None
    item: Optional[dict[str, Any]] = None      # HEAD as written by the claim (ReturnValues ALL_NEW)


def build_arm_request(table: str, *, target_id: str, hostname: str, policy_version: str,
                      execution_generation: int, armed_at: str) -> dict[str, Any]:
    """Operator action. Creates HEAD once; never overwrites an existing control item."""
    return {
        "TableName": table,
        "Item": {**_key(head_key(target_id)),
                 "enabled": {"BOOL": True},
                 "execution_generation": _n(execution_generation),
                 "policy_version": _s(policy_version),
                 "target_hostname": _s(hostname),
                 "armed_at": _s(armed_at)},
        "ConditionExpression": "attribute_not_exists(#pk)",
        "ExpressionAttributeNames": {"#pk": "pk"},
    }


def build_stop_request(table: str, *, target_id: str, expected_generation: int,
                       stopped_at: str) -> dict[str, Any]:
    """Operator action. Disables and invalidates the generation in one write, so events
    already queued for the old generation can no longer claim a slot."""
    return {
        "TableName": table,
        "Key": _key(head_key(target_id)),
        "UpdateExpression": "SET #en = :false, #gen = :next, #st = :at",
        "ConditionExpression": "attribute_exists(#pk) AND #gen = :gen",
        "ExpressionAttributeNames": {"#pk": "pk", "#en": "enabled",
                                     "#gen": "execution_generation", "#st": "stopped_at"},
        "ExpressionAttributeValues": {":false": {"BOOL": False},
                                      ":gen": _n(expected_generation),
                                      ":next": _n(expected_generation + 1),
                                      ":at": _s(stopped_at)},
        "ReturnValuesOnConditionCheckFailure": "ALL_OLD",
    }


def build_claim_request(table: str, claim: Claim) -> dict[str, Any]:
    return {
        "TableName": table,
        "Key": _key(head_key(claim.target_id)),
        "UpdateExpression": "SET #ls = :slot, #la = :attempt",
        "ConditionExpression": (
            "attribute_exists(#pk) AND #en = :true AND #gen = :gen AND #pv = :pv "
            "AND #host = :host AND (attribute_not_exists(#ls) OR #ls < :slot)"),
        "ExpressionAttributeNames": {
            "#pk": "pk", "#en": "enabled", "#gen": "execution_generation",
            "#pv": "policy_version", "#host": "target_hostname",
            "#ls": "last_slot", "#la": "last_attempt_id"},
        "ExpressionAttributeValues": {
            ":true": {"BOOL": True}, ":gen": _n(claim.execution_generation),
            ":pv": _s(claim.policy_version), ":host": _s(claim.hostname),
            ":slot": _s(claim.scheduled_slot), ":attempt": _s(claim.attempt_id)},
        "ReturnValues": "ALL_NEW",      # the probe role has no GetItem: the claim hands back HEAD
        "ReturnValuesOnConditionCheckFailure": "ALL_OLD",
    }


# Notification state lives on HEAD, separate from the run records:
#   obs_state / obs_slot   last state observed from a persisted result (PASS | FAIL | UNKNOWN)
#   ntf_pending            JSON list of events not yet published to SNS, oldest first
# Both writes below only apply while this attempt still owns the newest claim of the current
# generation, so a stop, a newer slot or a new generation silences every later notification.
_OWNER = ("attribute_exists(#pk) AND #en = :true AND #gen = :gen AND #la = :attempt")


def _owner_names_values(claim: Claim) -> tuple[dict[str, str], dict[str, Any]]:
    return ({"#pk": "pk", "#en": "enabled", "#gen": "execution_generation",
             "#la": "last_attempt_id", "#np": "ntf_pending"},
            {":true": {"BOOL": True}, ":gen": _n(claim.execution_generation),
             ":attempt": _s(claim.attempt_id)})


def build_observe_request(table: str, claim: Claim, state: str, pending: str) -> dict[str, Any]:
    """Record the observed state and queue the resulting events in one conditional write."""
    names, values = _owner_names_values(claim)
    names.update({"#os": "obs_state", "#oslot": "obs_slot"})
    values.update({":state": _s(state), ":slot": _s(claim.scheduled_slot), ":pending": _s(pending)})
    return {
        "TableName": table,
        "Key": _key(head_key(claim.target_id)),
        "UpdateExpression": "SET #os = :state, #oslot = :slot, #np = :pending",
        "ConditionExpression": _OWNER + " AND (attribute_not_exists(#oslot) OR #oslot < :slot)",
        "ExpressionAttributeNames": names,
        "ExpressionAttributeValues": values,
    }


def build_pending_request(table: str, claim: Claim, new: str, old: str) -> dict[str, Any]:
    """Drop published events from the queue. `old` must still be the stored text."""
    names, values = _owner_names_values(claim)
    values.update({":new": _s(new), ":old": _s(old)})
    return {
        "TableName": table,
        "Key": _key(head_key(claim.target_id)),
        "UpdateExpression": "SET #np = :new",
        "ConditionExpression": _OWNER + " AND #np = :old",
        "ExpressionAttributeNames": names,
        "ExpressionAttributeValues": values,
    }


def build_run_record_request(table: str, claim: Claim) -> dict[str, Any]:
    return {
        "TableName": table,
        "Item": {**_key(run_key(claim.target_id, claim.scheduled_slot)),
                 "schema": _s(RECORD_SCHEMA),
                 "state": _s(STATE_CLAIMED),
                 "logical_run_key": _s(claim.logical_run_key),
                 "execution_generation": _n(claim.execution_generation),
                 "policy_version": _s(claim.policy_version),
                 "attempt_id": _s(claim.attempt_id),
                 "claimed_at": _s(claim.claimed_at),
                 "expires_at": _n(claim.expires_at)},
        "ConditionExpression": "attribute_not_exists(#pk)",
        "ExpressionAttributeNames": {"#pk": "pk"},
    }


def build_result_request(table: str, claim: Claim, result: dict[str, Any]) -> dict[str, Any]:
    """Only the attempt that owns the CLAIMED record may record its result, once."""
    names = {"#state": "state", "#attempt": "attempt_id", "#outcome": "outcome",
             "#reason": "reason", "#finished": "finished_at"}
    values = {":claimed": _s(STATE_CLAIMED), ":recorded": _s(STATE_RECORDED),
              ":attempt": _s(claim.attempt_id), ":outcome": _s(result["outcome"]),
              ":reason": _s(result["reason"]), ":finished": _s(result["finished_at"])}
    sets = ["#state = :recorded", "#outcome = :outcome", "#reason = :reason",
            "#finished = :finished"]
    for field, kind in (("http_status", "N"), ("elapsed_ms", "N"),
                        ("selected_ip", "S"), ("tls_not_after", "S")):
        if result.get(field) is not None:
            names["#" + field] = field
            values[":" + field] = {kind: str(result[field])}
            sets.append(f"#{field} = :{field}")
    return {
        "TableName": table,
        "Key": _key(run_key(claim.target_id, claim.scheduled_slot)),
        "UpdateExpression": "SET " + ", ".join(sets),
        "ConditionExpression": "#state = :claimed AND #attempt = :attempt",
        "ExpressionAttributeNames": names,
        "ExpressionAttributeValues": values,
    }


def build_recent_query(table: str, target_id: str, limit: int = 12) -> dict[str, Any]:
    """Reader side: newest slots first. Slot text sorts chronologically."""
    return {
        "TableName": table,
        "KeyConditionExpression": "#pk = :pk",
        "ExpressionAttributeNames": {"#pk": "pk"},
        "ExpressionAttributeValues": {":pk": _s("RUN#" + target_id)},
        "ScanIndexForward": False,
        "ConsistentRead": True,
        "Limit": limit,
    }


def classify_claim_failure(old: Optional[dict[str, Any]], claim: Claim) -> str:
    """Explain a failed claim from the item DynamoDB returned with the failure.

    The explanation is diagnostic only: whatever it says, the probe does not start.
    """
    if not old:
        return "NOT_ARMED"
    try:
        if old.get("enabled", {}).get("BOOL") is not True:
            return "STOPPED"
        if old.get("execution_generation", {}).get("N") != str(claim.execution_generation):
            return "GENERATION_MISMATCH"
        if old.get("policy_version", {}).get("S") != claim.policy_version:
            return "POLICY_MISMATCH"
        if old.get("target_hostname", {}).get("S") != claim.hostname:
            return "TARGET_MISMATCH"
        last = old.get("last_slot", {}).get("S")
        if last == claim.scheduled_slot:
            return "DUPLICATE_SLOT"
        if last is not None and last > claim.scheduled_slot:
            return "OLDER_SLOT"
    except AttributeError:
        pass
    return "CLAIM_CONDITION_FAILED"


def _error_code(exc: BaseException) -> Optional[str]:
    response = getattr(exc, "response", None)
    if isinstance(response, dict) and isinstance(response.get("Error"), dict):
        code = response["Error"].get("Code")
        return code if isinstance(code, str) else None
    return None


class DynamoStore:
    """Thin adapter over a low-level DynamoDB client (boto3 `client('dynamodb')`).

    Every failure is returned as a StoreResult; nothing here retries a write itself.
    """

    def __init__(self, client: Any, table: str) -> None:
        self._client, self._table = client, table

    def claim(self, claim: Claim) -> StoreResult:
        try:
            response = self._client.update_item(**build_claim_request(self._table, claim))
        except Exception as exc:
            if _error_code(exc) == CONDITION_FAILED:
                return StoreResult(False, classify_claim_failure(
                    getattr(exc, "response", {}).get("Item"), claim))
            # Unknown outcome: the write may or may not have been applied. Fail closed.
            return StoreResult(False, "CLAIM_UNCERTAIN", type(exc).__name__)
        attributes = response.get("Attributes") if isinstance(response, dict) else None
        return StoreResult(True, "CLAIMED", item=attributes if isinstance(attributes, dict) else None)

    def observe(self, claim: Claim, state: str, pending: str) -> StoreResult:
        return self._notify_write(build_observe_request(self._table, claim, state, pending),
                                  "OBSERVED", "OBSERVE_NOT_OWNED", "OBSERVE_UNCERTAIN")

    def set_pending(self, claim: Claim, new: str, old: str) -> StoreResult:
        return self._notify_write(build_pending_request(self._table, claim, new, old),
                                  "PENDING_UPDATED", "PENDING_NOT_OWNED", "PENDING_UNCERTAIN")

    def _notify_write(self, request: dict[str, Any], ok: str, refused: str,
                      uncertain: str) -> StoreResult:
        try:
            self._client.update_item(**request)
        except Exception as exc:
            if _error_code(exc) == CONDITION_FAILED:
                return StoreResult(False, refused)
            return StoreResult(False, uncertain, type(exc).__name__)
        return StoreResult(True, ok)

    def open_run(self, claim: Claim) -> StoreResult:
        try:
            self._client.put_item(**build_run_record_request(self._table, claim))
        except Exception as exc:
            if _error_code(exc) == CONDITION_FAILED:
                return StoreResult(False, "RUN_RECORD_EXISTS")
            return StoreResult(False, "RUN_RECORD_UNCERTAIN", type(exc).__name__)
        return StoreResult(True, "RUN_OPENED")

    def record_result(self, claim: Claim, result: dict[str, Any]) -> StoreResult:
        try:
            self._client.update_item(**build_result_request(self._table, claim, result))
        except Exception as exc:
            if _error_code(exc) == CONDITION_FAILED:
                return StoreResult(False, "RESULT_NOT_OWNED")
            return StoreResult(False, "RESULT_UNPERSISTED", type(exc).__name__)
        return StoreResult(True, "RECORDED")

    # Operator / reader helpers. The probe role is not granted the reads below.
    def arm(self, **fields: Any) -> StoreResult:
        try:
            self._client.put_item(**build_arm_request(self._table, **fields))
        except Exception as exc:
            if _error_code(exc) == CONDITION_FAILED:
                return StoreResult(False, "ALREADY_ARMED")
            return StoreResult(False, "ARM_UNCERTAIN", type(exc).__name__)
        return StoreResult(True, "ARMED")

    def stop(self, **fields: Any) -> StoreResult:
        try:
            self._client.update_item(**build_stop_request(self._table, **fields))
        except Exception as exc:
            if _error_code(exc) == CONDITION_FAILED:
                return StoreResult(False, "STOP_CONDITION_FAILED")
            return StoreResult(False, "STOP_UNCERTAIN", type(exc).__name__)
        return StoreResult(True, "STOP_REQUESTED")

    def recent_runs(self, target_id: str, limit: int = 12) -> list[dict[str, Any]]:
        return list(self._client.query(
            **build_recent_query(self._table, target_id, limit)).get("Items", []))

    def head(self, target_id: str) -> Optional[dict[str, Any]]:
        return self._client.get_item(TableName=self._table, Key=_key(head_key(target_id)),
                                     ConsistentRead=True).get("Item")
