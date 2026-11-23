"""AWS-C external watchdog: terminate the one pilot instance at the absolute deadline.

Deployed BEFORE any instance exists (guard plane). Its target and deadline are fixed in
its own configuration, so it needs neither DynamoDB nor the worker to decide:

    exactly one instance carries the pilot-run tag  and  now >= hard deadline
        -> TerminateInstances for that single id, then re-describe and report
    zero or several tagged instances
        -> never terminate anything; report NO_TARGET / AMBIGUOUS_TARGET and alarm

The control record is updated afterwards on a best-effort basis; a failed write never
blocks or delays termination. It is the second of three independent layers:
(1) OS shutdown timer inside the instance, (2) this function, (3) cost alerts for a
human. A Budgets notification is an alert, not a stop mechanism.

Terminate (not Stop) is an implementation CANDIDATE: applying it LIVE, with EBS deletion,
needs separate USER approval. This code never calls Start/Run/Stop/Reboot.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from src.aws_b.model import format_utc, parse_utc
from src.core.model import validate_id

from . import control

TAG_KEY = "siteproof:pilot-run-id"
LIVE_STATES = ["pending", "running", "stopping", "stopped", "shutting-down"]
GONE_STATES = ("terminated",)


class WatchdogConfigError(ValueError):
    pass


@dataclass(frozen=True)
class WatchdogConfig:
    pilot_run_id: str
    hard_deadline: datetime
    metric_namespace: str = "SiteProof/Pilot"
    table_name: Optional[str] = None

    @classmethod
    def from_env(cls, env: Any) -> "WatchdogConfig":
        try:
            run_id = validate_id(env.get("PILOT_RUN_ID"), "PILOT_RUN_ID")
        except Exception as exc:
            raise WatchdogConfigError(str(exc)) from exc
        deadline = parse_utc(env.get("HARD_DEADLINE_UTC"))
        if deadline is None:
            raise WatchdogConfigError("HARD_DEADLINE_UTC must be YYYY-MM-DDTHH:MM:SSZ")
        return cls(run_id, deadline, table_name=env.get("TABLE_NAME") or None)


@dataclass
class Deps:
    config: WatchdogConfig
    ec2: Any
    now: Callable[[], datetime]
    emit: Callable[[dict[str, Any]], None]
    control_store: Optional[Any] = None


def _find(ec2: Any, run_id: str, states: list[str]) -> list[dict[str, Any]]:
    response = ec2.describe_instances(Filters=[
        {"Name": "tag:" + TAG_KEY, "Values": [run_id]},
        {"Name": "instance-state-name", "Values": states}])
    return [instance for reservation in response.get("Reservations", [])
            for instance in reservation.get("Instances", [])]


def _line(config: WatchdogConfig, moment: datetime, values: dict[str, int],
          fields: dict[str, Any]) -> dict[str, Any]:
    return {"_aws": {"Timestamp": int(moment.timestamp() * 1000),
                     "CloudWatchMetrics": [{
                         "Namespace": config.metric_namespace,
                         "Dimensions": [["PilotRunId"]],
                         "Metrics": [{"Name": n, "Unit": "Count"} for n in sorted(values)]}]},
            "PilotRunId": config.pilot_run_id, **values, **fields}


def _journal(deps: Deps, target: str, detail: str) -> str:
    """Best effort only. Returns a status string; never raises."""
    store = deps.control_store
    if store is None:
        return "NOT_CONFIGURED"
    try:
        current = store.read(deps.config.pilot_run_id)
        if not current.ok:
            return "JOURNAL_" + current.reason
        if current.state == target:
            return "JOURNAL_ALREADY_" + target
        written = store.transition(deps.config.pilot_run_id, current.state, target,
                                   current.version, format_utc(deps.now()), detail)
        return "JOURNAL_OK" if written.ok else "JOURNAL_" + written.reason
    except Exception as exc:
        return "JOURNAL_ERROR_" + type(exc).__name__


def run(event: Any, deps: Deps) -> dict[str, Any]:
    config, now = deps.config, deps.now()
    due = now >= config.hard_deadline
    out: dict[str, Any] = {"decision": None, "due": due, "terminate_called": False,
                           "now": format_utc(now),
                           "hard_deadline_utc": format_utc(config.hard_deadline)}

    def finish(decision: str, **metrics: int) -> dict[str, Any]:
        out["decision"] = decision
        values = {"WatchdogRun": 1, "WatchdogAttention": 0, **metrics}
        deps.emit(_line(config, now, values, dict(out)))
        return out

    try:
        found = _find(deps.ec2, config.pilot_run_id, LIVE_STATES)
    except Exception as exc:
        # Cannot see the target: nothing is assumed safe, nothing else is touched.
        out["error"] = type(exc).__name__
        return finish("DESCRIBE_FAILED", WatchdogAttention=1)

    ids = sorted(i["InstanceId"] for i in found)
    out["instances"] = {i["InstanceId"]: i["State"]["Name"] for i in found}
    if len(ids) > 1:
        return finish("AMBIGUOUS_TARGET", WatchdogAttention=1)
    if not ids:
        try:
            gone = _find(deps.ec2, config.pilot_run_id, list(GONE_STATES))
        except Exception:
            gone = []
        if len(gone) == 1:
            # Observed as terminated (e.g. the worker shut itself down). Visible to
            # DescribeInstances only for a limited time after termination.
            out["instances"] = {gone[0]["InstanceId"]: "terminated"}
            out["journal"] = _journal(deps, control.TERMINATE_REQUESTED, "self-terminated")
            out["journal_verified"] = _journal(deps, control.TERMINATED_VERIFIED, "observed")
            return finish("ALREADY_TERMINATED")
        # Not proof that nothing is running (eventual consistency, tag never applied).
        return finish("NO_TARGET_AFTER_DEADLINE" if due else "NO_TARGET",
                      WatchdogAttention=1 if due else 0)
    if not due:
        return finish("NOT_DUE")

    instance_id = ids[0]
    out["terminate_called"] = True
    try:
        deps.ec2.terminate_instances(InstanceIds=[instance_id])
        out["terminate_api"] = "ACCEPTED"
    except Exception as exc:
        out["terminate_api"] = "ERROR_" + type(exc).__name__
    # An accepted call is not a terminated instance: observe the state separately.
    try:
        after = _find(deps.ec2, config.pilot_run_id, LIVE_STATES + list(GONE_STATES))
        states = {i["InstanceId"]: i["State"]["Name"] for i in after}
        out["observed_after"] = states
        state = states.get(instance_id)
    except Exception as exc:
        out["observed_after_error"] = type(exc).__name__
        state = None

    if state in GONE_STATES:
        out["journal"] = _journal(deps, control.TERMINATE_REQUESTED, "deadline")
        out["journal_verified"] = _journal(deps, control.TERMINATED_VERIFIED, "observed")
        return finish("TERMINATED_VERIFIED", WatchdogTerminate=1)
    out["journal"] = _journal(deps, control.TERMINATE_REQUESTED, "deadline")
    if state == "shutting-down" and out["terminate_api"] == "ACCEPTED":
        return finish("TERMINATE_REQUESTED", WatchdogTerminate=1)
    # Still running/stopped, unknown, or the API call failed: a human must look.
    return finish("TERMINATE_UNCERTAIN", WatchdogTerminate=1, WatchdogAttention=1)


def _print_line(line: dict[str, Any]) -> None:
    print(json.dumps(line, sort_keys=True, separators=(",", ":")), flush=True)


def lambda_handler(event: Any, context: Any) -> dict[str, Any]:
    config = WatchdogConfig.from_env(os.environ)   # invalid config raises: Errors alarm
    import boto3  # provided by the Lambda runtime; never imported offline
    from botocore.config import Config
    options = Config(connect_timeout=3, read_timeout=10,
                     retries={"total_max_attempts": 3, "mode": "standard"})
    store = None
    if config.table_name:
        store = control.ControlStore(boto3.client("dynamodb", config=options),
                                     config.table_name)
    return run(event, Deps(config=config, ec2=boto3.client("ec2", config=options),
                           now=lambda: datetime.now(timezone.utc), emit=_print_line,
                           control_store=store))
