"""AWS-B Lambda entry point: decide whether one scheduled event may probe, then record.

Order of refusal (each refuses *before* any outbound connection):

    1. malformed event or wrong target
    2. now >= absolute_end_at
    3. scheduled time too old (late/queued event) or in the future
    4. conditional claim on the control item fails: not armed, stopped, generation or
       policy changed, duplicate slot, older (out-of-order) slot, or outcome uncertain
    5. the CLAIMED run record cannot be written

After a probe, a result that cannot be stored is reported as UNPERSISTED and is never
re-probed. Readers see the slot as CLAIMED-without-result, i.e. UNKNOWN.

Then the state change is notified directly (see notify.py). The ProbeCompleted heartbeat is
emitted only when the result is stored AND no notification is left unsent; a rejected event, a
failed write or an SNS failure sends none, so the aggregate heartbeat alarm sees a missing run.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from src.core.model import CheckOutcome

from .model import (ConfigError, MonitorConfig, format_utc, logical_run_key, parse_event)
from .notify import process as notify_process
from .probe import ProbeResult, TlsTransport, run_probe, socket_dialer, system_resolver
from .store import Claim, DynamoStore

# Time kept back from the Lambda timeout so the result write and metric line still happen.
RESERVE_SECONDS = 4.0


@dataclass
class Deps:
    config: MonitorConfig
    store: Any
    probe: Callable[[float], ProbeResult]      # receives a monotonic deadline
    now: Callable[[], datetime]
    emit: Callable[[dict[str, Any]], None]
    monotonic: Callable[[], float] = time.monotonic
    attempt_id: str = ""
    remaining_seconds: Callable[[], float] = lambda: 15.0
    publish: Optional[Callable[[str, str], None]] = None     # (subject, body) -> SNS; raises on failure


def _metric_line(config: MonitorConfig, values: dict[str, int], fields: dict[str, Any],
                 heartbeat_at: Optional[datetime] = None) -> dict[str, Any]:
    """One JSON log line per invocation. `values` are plain log fields (no custom metric, no cost).

    Only a completed run (`heartbeat_at` given) adds a CloudWatch Embedded Metric Format block:
    the single custom metric ProbeCompleted, dimension MonitorGroup. It is stamped with the
    scheduled slot, not the run time, so a late or slow run still lands in its own interval.
    """
    line = {"TargetId": config.target_id, **values, **fields}
    if heartbeat_at is not None:
        line["MonitorGroup"] = config.monitor_group
        line["ProbeCompleted"] = 1
        line["_aws"] = {"Timestamp": int(heartbeat_at.timestamp() * 1000),
                        "CloudWatchMetrics": [{
                            "Namespace": config.metric_namespace,
                            "Dimensions": [["MonitorGroup"]],
                            "Metrics": [{"Name": "ProbeCompleted", "Unit": "Count"}]}]}
    return line


def run(event: Any, deps: Deps) -> dict[str, Any]:
    config, now = deps.config, deps.now()
    fields: dict[str, Any] = {"attempt_id": deps.attempt_id, "decision": "REJECTED",
                              "probe_started": False}

    def reject(reason: str, **extra: Any) -> dict[str, Any]:
        fields.update(reason=reason, **extra)
        deps.emit(_metric_line(config, {"Rejected": 1}, fields))
        return dict(fields)

    scheduled, reason = parse_event(event)
    if scheduled is None:
        return reject(reason)
    fields.update(scheduled_slot=scheduled.scheduled_slot,
                  execution_generation=scheduled.execution_generation)
    if scheduled.target_id != config.target_id:
        return reject("EVENT_TARGET_MISMATCH")
    if now >= config.absolute_end_at:
        return reject("PAST_ABSOLUTE_END")
    age = (now - scheduled.scheduled_at).total_seconds()
    if age > config.max_event_age_seconds:
        return reject("EVENT_TOO_OLD", event_age_seconds=int(age))
    if age < -config.max_future_skew_seconds:
        return reject("EVENT_IN_FUTURE", event_age_seconds=int(age))

    claim = Claim(
        target_id=config.target_id, hostname=config.hostname,
        policy_version=config.policy_version,
        execution_generation=scheduled.execution_generation,
        scheduled_slot=scheduled.scheduled_slot,
        logical_run_key=logical_run_key(config.target_id, scheduled.scheduled_slot,
                                        config.policy_version,
                                        scheduled.execution_generation),
        attempt_id=deps.attempt_id, claimed_at=format_utc(now),
        expires_at=int(now.timestamp()) + config.record_ttl_days * 86400)
    fields["logical_run_key"] = claim.logical_run_key

    claimed = deps.store.claim(claim)
    if not claimed.ok:
        return reject(claimed.reason, store_error=claimed.error)
    opened = deps.store.open_run(claim)
    if not opened.ok:
        # The slot is consumed but has no record: an unobserved slot, reported as such.
        fields.update(reason=opened.reason, store_error=opened.error)
        deps.emit(_metric_line(config, {"Rejected": 1, "Unpersisted": 1, "ProbeUnknown": 1}, fields))
        return dict(fields)

    budget = min(float(config.probe_timeout_seconds),
                 deps.remaining_seconds() - RESERVE_SECONDS,
                 (config.absolute_end_at - deps.now()).total_seconds())
    fields["probe_started"] = True
    if budget <= 0:
        result = ProbeResult(CheckOutcome.UNKNOWN, "NO_TIME_BUDGET")
        fields["probe_started"] = False
    else:
        result = deps.probe(deps.monotonic() + budget)

    record = {"outcome": result.outcome.value, "reason": result.reason,
              "http_status": result.http_status, "selected_ip": result.selected_ip,
              "tls_not_after": result.tls_not_after, "elapsed_ms": result.elapsed_ms,
              "finished_at": format_utc(deps.now())}
    stored = deps.store.record_result(claim, record)
    # Reuse the existing series: unknown/saving failure belongs to monitor health.
    # Never send an HTTP OK datapoint when the result is UNKNOWN or unpersisted.
    unknown = 1 if result.outcome is CheckOutcome.UNKNOWN or not stored.ok else 0
    fields.update(decision="PROBED", reason=result.reason, outcome=result.outcome.value,
                  http_status=result.http_status, persisted=stored.ok,
                  store_reason=stored.reason, store_error=stored.error)
    metrics = {}
    if stored.ok and result.outcome is not CheckOutcome.UNKNOWN:
        metrics["ProbeFailure"] = 1 if result.outcome is CheckOutcome.FAIL else 0
    metrics.update(ProbeUnknown=unknown, Unpersisted=0 if stored.ok else 1)

    notified = {"ok": True, "reason": "NOTIFY_DISABLED", "sent": 0, "pending": 0, "dropped": 0}
    if stored.ok and deps.publish is not None:
        notified = notify_process(
            deps.store, claim, claimed.item, state=result.outcome.value, reason=result.reason,
            http_status=result.http_status, finished_at=record["finished_at"],
            hostname=config.hostname, path=config.path, publish=deps.publish, now=deps.now,
            absolute_end_at=config.absolute_end_at)
    completed = stored.ok and notified["ok"]
    fields.update(notify_reason=notified["reason"], notify_sent=notified["sent"],
                  notify_pending=notified["pending"], notify_dropped=notified["dropped"],
                  heartbeat=completed)
    deps.emit(_metric_line(config, metrics, fields,
                           heartbeat_at=scheduled.scheduled_at if completed else None))
    return dict(fields)


def _print_line(line: dict[str, Any]) -> None:
    print(json.dumps(line, sort_keys=True, separators=(",", ":")), flush=True)


def _sns_publisher(topic_arn: str) -> Callable[[str, str], None]:
    import boto3  # provided by the Lambda runtime; never imported offline
    from botocore.config import Config
    client = boto3.client("sns", region_name=topic_arn.split(":")[3], config=Config(
        connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 2, "mode": "standard"}))

    def publish(subject: str, body: str) -> None:
        client.publish(TopicArn=topic_arn, Subject=subject, Message=body)
    return publish


_STORE: Optional[DynamoStore] = None


def _dynamo_store(table: str) -> DynamoStore:
    global _STORE
    if _STORE is None:
        import boto3  # provided by the Lambda runtime; never imported offline
        from botocore.config import Config
        client = boto3.client("dynamodb", config=Config(
            connect_timeout=2, read_timeout=3,
            retries={"total_max_attempts": 2, "mode": "standard"}))
        _STORE = DynamoStore(client, table)
    return _STORE


def lambda_handler(event: Any, context: Any) -> dict[str, Any]:
    try:
        config = MonitorConfig.from_env(os.environ)
    except ConfigError as exc:
        # Unusable deployment: say so and stop. No probe, no retry-worthy exception.
        _print_line({"decision": "REJECTED", "reason": "CONFIG_INVALID", "detail": str(exc)})
        return {"decision": "REJECTED", "reason": "CONFIG_INVALID", "probe_started": False}
    transport = TlsTransport()
    timeout = float(config.probe_timeout_seconds)

    def probe(deadline: float) -> ProbeResult:
        def dial(ip: str, port: int) -> Any:
            remaining = min(timeout, deadline - time.monotonic())
            if remaining <= 0:
                raise TimeoutError("probe deadline before connect")
            return socket_dialer(remaining)(ip, port)
        return run_probe(config, resolver=system_resolver, dialer=dial,
                         transport=transport, deadline=deadline)

    deps = Deps(
        config=config, store=_dynamo_store(config.table_name), probe=probe,
        now=lambda: datetime.now(timezone.utc), emit=_print_line,
        attempt_id=str(getattr(context, "aws_request_id", "") or uuid.uuid4()),
        remaining_seconds=lambda: context.get_remaining_time_in_millis() / 1000.0,
        publish=_sns_publisher(config.alert_topic_arn) if config.alert_topic_arn else None)
    return run(event, deps)
