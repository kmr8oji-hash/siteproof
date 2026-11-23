"""AWS-B monitor: configuration, event and key contracts. Pure, no I/O.

One *logical run* is (target_id, scheduled_slot, policy_version, execution_generation).
Each Lambda invocation is one *attempt*; several attempts may carry the same logical run
(asynchronous delivery is at-least-once), but at most one may start a probe.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from src.core.model import canonical_json, sha256_hex, validate_id
from src.isolation.destination import AllowedDestination, DestinationPolicy, check_authority

EVENT_SCHEMA = "siteproof.monitor.event.v1"
RECORD_SCHEMA = "siteproof.monitor.record.v1"
SLOT_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_SLOT_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z", re.ASCII)
_TOPIC_RE = re.compile(r"arn:aws[a-z-]*:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]{1,256}\Z", re.ASCII)
_PATH_RE = re.compile(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}\Z", re.ASCII)

# Slot record lifecycle. A CLAIMED record without a result is read as UNKNOWN, never UP.
STATE_CLAIMED = "CLAIMED"
STATE_RECORDED = "RECORDED"


class ConfigError(ValueError):
    """Deployment configuration is unusable; the handler must not probe."""


def parse_utc(value: Any) -> datetime | None:
    """Exact second-resolution UTC timestamp; no offsets, fractions or repair."""
    if type(value) is not str or not _SLOT_RE.fullmatch(value):
        return None
    try:
        return datetime.strptime(value, SLOT_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def format_utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime(SLOT_FORMAT)


def _bounded_int(raw: Any, name: str, low: int, high: int) -> int:
    try:
        value = int(raw) if type(raw) is str and raw.isascii() and raw.isdigit() else None
    except ValueError:
        value = None
    if value is None or not low <= value <= high:
        raise ConfigError(f"{name} must be an integer in [{low}, {high}]")
    return value


@dataclass(frozen=True)
class MonitorConfig:
    """Fixed at deploy time. Nothing here is taken from the invocation event."""
    target_id: str
    hostname: str
    path: str
    policy_version: str
    absolute_end_at: datetime
    table_name: str
    max_event_age_seconds: int = 60
    max_future_skew_seconds: int = 5
    probe_timeout_seconds: int = 8
    record_ttl_days: int = 14
    metric_namespace: str = "SiteProof/Monitor"
    monitor_group: str = "siteproof-b"          # Heartbeat dimension shared by every page of one deployment
    alert_topic_arn: str | None = None          # existing SNS topic; None = no direct notification

    @property
    def policy(self) -> DestinationPolicy:
        return DestinationPolicy((AllowedDestination(self.hostname, 443),))

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "MonitorConfig":
        try:
            target_id = validate_id(env.get("TARGET_ID"), "TARGET_ID")
            policy_version = validate_id(env.get("POLICY_VERSION"), "POLICY_VERSION")
        except Exception as exc:
            raise ConfigError(str(exc)) from exc
        hostname = env.get("TARGET_HOSTNAME")
        probe_policy = DestinationPolicy((AllowedDestination(hostname, 443),))
        authority = check_authority(probe_policy, hostname, 443)
        if not authority.allowed:
            raise ConfigError("TARGET_HOSTNAME rejected: " + authority.reason)
        path = env.get("TARGET_PATH")
        if type(path) is not str or not _PATH_RE.fullmatch(path) or ".." in path:
            raise ConfigError("TARGET_PATH must be a plain absolute path")
        end = parse_utc(env.get("ABSOLUTE_END_AT"))
        if end is None:
            raise ConfigError("ABSOLUTE_END_AT must be YYYY-MM-DDTHH:MM:SSZ")
        table = env.get("TABLE_NAME")
        if type(table) is not str or not re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", table):
            raise ConfigError("TABLE_NAME invalid")
        namespace = env.get("METRIC_NAMESPACE", "SiteProof/Monitor")
        if not re.fullmatch(r"[A-Za-z0-9/_.-]{1,64}", namespace) or namespace.startswith("AWS/"):
            raise ConfigError("METRIC_NAMESPACE invalid")
        group = env.get("MONITOR_GROUP", "siteproof-b")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", group):
            raise ConfigError("MONITOR_GROUP invalid")
        topic = env.get("ALERT_TOPIC_ARN") or None
        if topic is not None and not _TOPIC_RE.fullmatch(topic):
            raise ConfigError("ALERT_TOPIC_ARN invalid")
        return cls(
            target_id=target_id, hostname=authority.hostname, path=path,
            policy_version=policy_version, absolute_end_at=end, table_name=table,
            max_event_age_seconds=_bounded_int(
                env.get("MAX_EVENT_AGE_SECONDS", "60"), "MAX_EVENT_AGE_SECONDS", 10, 300),
            probe_timeout_seconds=_bounded_int(
                env.get("PROBE_TIMEOUT_SECONDS", "8"), "PROBE_TIMEOUT_SECONDS", 1, 20),
            record_ttl_days=_bounded_int(
                env.get("RECORD_TTL_DAYS", "14"), "RECORD_TTL_DAYS", 1, 90),
            metric_namespace=namespace, monitor_group=group, alert_topic_arn=topic)


@dataclass(frozen=True)
class ScheduledEvent:
    target_id: str
    scheduled_slot: str          # canonical SLOT_FORMAT text; sorts chronologically
    scheduled_at: datetime
    execution_generation: int


def parse_event(event: Any) -> tuple[ScheduledEvent | None, str]:
    """Strict: exact key set, exact types. An unknown shape is rejected, not repaired."""
    if type(event) is not dict or set(event) != {
            "schema", "target_id", "scheduled_time", "execution_generation"}:
        return None, "EVENT_SHAPE_INVALID"
    if event["schema"] != EVENT_SCHEMA:
        return None, "EVENT_SCHEMA_UNSUPPORTED"
    target_id = event["target_id"]
    try:
        validate_id(target_id, "target_id")
    except Exception:
        return None, "EVENT_TARGET_INVALID"
    generation = event["execution_generation"]
    if type(generation) is not int or not 1 <= generation <= 1_000_000:
        return None, "EVENT_GENERATION_INVALID"
    # Scheduler timestamps may include a zero millisecond component. Normalize
    # only this equivalent representation; configuration timestamps remain strict.
    scheduled_time = event["scheduled_time"]
    if type(scheduled_time) is str and scheduled_time.endswith(".000Z"):
        scheduled_time = scheduled_time[:-5] + "Z"
    moment = parse_utc(scheduled_time)
    if moment is None:
        return None, "EVENT_TIME_INVALID"
    return ScheduledEvent(target_id, format_utc(moment), moment, generation), "OK"


def logical_run_key(target_id: str, scheduled_slot: str, policy_version: str,
                    execution_generation: int) -> str:
    return sha256_hex(canonical_json({
        "target_id": target_id, "scheduled_slot": scheduled_slot,
        "policy_version": policy_version,
        "execution_generation": execution_generation}).encode("utf-8"))


def head_key(target_id: str) -> dict[str, str]:
    return {"pk": "CONTROL#" + target_id, "sk": "HEAD"}


def run_key(target_id: str, scheduled_slot: str) -> dict[str, str]:
    return {"pk": "RUN#" + target_id, "sk": scheduled_slot}
