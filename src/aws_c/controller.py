"""AWS-C controller Lambda: accept the single pilot run and report its recorded state.

Deliberately small. It can reserve the one run slot (idempotently for the same run id)
and read the control record. It has no EC2 permission of any kind: the instance is
created once by a separate, separately approved deployment, and only the watchdog and
the instance's own OS timer end it. There is no start, restart or re-arm operation.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Callable

from src.aws_b.model import format_utc, parse_utc
from src.core.model import validate_id

from .control import ControlStore

ACTIONS = ("reserve", "status")


def run(event: Any, *, store: Any, pilot_run_id: str, hard_deadline_utc: str,
        now: Callable[[], datetime]) -> dict[str, Any]:
    """The run id and deadline come from deployment configuration, never from the event."""
    if type(event) is not dict or set(event) != {"action"} or event["action"] not in ACTIONS:
        return {"ok": False, "reason": "REQUEST_INVALID"}
    deadline = parse_utc(hard_deadline_utc)
    if deadline is None:
        return {"ok": False, "reason": "CONFIG_INVALID"}
    moment = now()
    if event["action"] == "status":
        result = store.read(pilot_run_id)
        return {"ok": result.ok, "reason": result.reason, "state": result.state,
                "version": result.version, "pilot_run_id": pilot_run_id,
                "hard_deadline_utc": hard_deadline_utc,
                "past_deadline": moment >= deadline}
    if moment >= deadline:
        return {"ok": False, "reason": "PAST_HARD_DEADLINE", "pilot_run_id": pilot_run_id}
    result = store.reserve(pilot_run_id, hard_deadline_utc, format_utc(moment))
    return {"ok": result.ok, "reason": result.reason, "state": result.state,
            "version": result.version, "pilot_run_id": pilot_run_id}


def lambda_handler(event: Any, context: Any) -> dict[str, Any]:
    import boto3  # provided by the Lambda runtime; never imported offline
    from botocore.config import Config
    run_id = validate_id(os.environ.get("PILOT_RUN_ID"), "PILOT_RUN_ID")
    client = boto3.client("dynamodb", config=Config(
        connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 2, "mode": "standard"}))
    return run(event, store=ControlStore(client, os.environ["TABLE_NAME"]),
               pilot_run_id=run_id, hard_deadline_utc=os.environ.get("HARD_DEADLINE_UTC", ""),
               now=lambda: datetime.now(timezone.utc))
