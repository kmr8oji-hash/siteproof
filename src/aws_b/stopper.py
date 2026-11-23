"""AWS-B in-AWS safe stop: the stop the Windows tasks and a human `aws login` used to provide, run by Lambda on its own IAM role.

Triggered by a one-time EventBridge Scheduler entry `at(StopAt)` (infra/aws_b/stopper.json). Same layers as the operator's
safe-stop-v4.ps1, never deleting anything (deletion stays a separate, USER-approved CloudFormation delete):

    L0  actions of the shared heartbeat alarm disabled (a planned stop must not mail missing-data; AWS-B Lite has no
        per-page alarms). The alarm is shared by every page: stop the whole deployment together, never one page alone.
    L1  CONTROL disabled and generation + 1 in one conditional write (store.build_stop_request): events already queued
        for the old generation can no longer claim a slot, so nothing probes after this point even if L2/L3 fail
    L2  the probe schedule DISABLED (UpdateSchedule with the schedule's own current definition)
    L3  probe reserved concurrency 0
    L4  independent readback of every layer

Idempotent: an already-stopped layer is not written again, so duplicate or late stop events are harmless (stopping is the
safe direction; a stop event is applied whenever it arrives). STOP_COMPLETE only when every readback matches; otherwise
STOP_INCOMPLETE is emitted as a metric and an exception is raised, so the Lambda error alarm mails and async retries run.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from .store import build_stop_request, head_key

STOP_SCHEMA = 'siteproof.stop.event.v1'
METRIC_NAMESPACE = 'SiteProof/Monitor'


class StopIncomplete(RuntimeError):
    """Raised after the record is emitted, so Lambda reports an error (alarm + async retry)."""


@dataclass(frozen=True)
class Settings:
    target_id: str
    table: str
    schedule: str
    function: str
    alarms: tuple[str, ...]

    @classmethod
    def from_env(cls, env: dict[str, str]) -> 'Settings':
        alarms = tuple(a for a in env.get('ALARM_NAMES', '').split(',') if a)
        values = {k: env.get(k, '') for k in ('TARGET_ID', 'TABLE_NAME', 'SCHEDULE_NAME', 'FUNCTION_NAME')}
        if not all(values.values()) or len(alarms) > 1:
            raise ValueError('stopper configuration incomplete')
        return cls(values['TARGET_ID'], values['TABLE_NAME'], values['SCHEDULE_NAME'], values['FUNCTION_NAME'], alarms)


@dataclass
class Clients:
    dynamodb: Any
    scheduler: Any
    lambda_: Any
    cloudwatch: Any


@dataclass
class Record:
    target_id: str
    requested_at: str | None
    started_at: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    verify: list[dict[str, Any]] = field(default_factory=list)
    result: str = 'STOP_INCOMPLETE'

    def step(self, layer: str, ok: bool, detail: str) -> None:
        self.steps.append({'layer': layer, 'ok': bool(ok), 'detail': detail[:200]})

    def check(self, layer: str, ok: bool, detail: str) -> None:
        self.verify.append({'layer': layer, 'ok': bool(ok), 'detail': detail[:200]})


def _code(exc: BaseException) -> str:
    response = getattr(exc, 'response', None)
    if isinstance(response, dict):
        return str(response.get('Error', {}).get('Code') or type(exc).__name__)
    return type(exc).__name__


def _control(clients: Clients, s: Settings) -> dict[str, Any] | None:
    key = {k: {'S': v} for k, v in head_key(s.target_id).items()}
    return clients.dynamodb.get_item(TableName=s.table, Key=key, ConsistentRead=True).get('Item')


def _disable_control(clients: Clients, s: Settings, now: str, rec: Record) -> None:
    for _ in range(2):  # one re-read if the generation moved between read and write
        try:
            item = _control(clients, s)
        except Exception as exc:  # noqa: BLE001 - recorded; the schedule / concurrency layers still run
            rec.step('L1-control', False, 'read failed: ' + _code(exc))
            return
        if item is None:
            rec.step('L1-control', True, 'absent: the target was never armed, nothing can claim a slot')
            return
        generation = int(item['execution_generation']['N'])
        if item.get('enabled', {}).get('BOOL') is not True:
            rec.step('L1-control', True, f'already disabled (generation {generation})')
            return
        try:
            clients.dynamodb.update_item(**build_stop_request(s.table, target_id=s.target_id, expected_generation=generation, stopped_at=now))
            rec.step('L1-control', True, f'disabled, generation {generation} -> {generation + 1}')
            return
        except Exception as exc:  # noqa: BLE001 - every failure is recorded, the other layers still run
            if _code(exc) != 'ConditionalCheckFailedException':
                rec.step('L1-control', False, 'write failed: ' + _code(exc))
                return
    rec.step('L1-control', False, 'generation kept changing; not written')


# Fields UpdateSchedule needs back unchanged (it replaces the whole definition).
_SCHEDULE_FIELDS = ('ScheduleExpression', 'ScheduleExpressionTimezone', 'FlexibleTimeWindow', 'Target', 'StartDate', 'EndDate',
                    'Description', 'GroupName', 'KmsKeyArn', 'ActionAfterCompletion')


def _disable_schedule(clients: Clients, s: Settings, rec: Record) -> None:
    try:
        current = clients.scheduler.get_schedule(Name=s.schedule)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) == 'ResourceNotFoundException':
            rec.step('L2-schedule', True, 'absent (deleted after completion or never created): nothing to trigger')
        else:
            rec.step('L2-schedule', False, 'read failed: ' + _code(exc))
        return
    if current.get('State') == 'DISABLED':
        rec.step('L2-schedule', True, 'already DISABLED')
        return
    try:
        clients.scheduler.update_schedule(Name=s.schedule, State='DISABLED', **{k: current[k] for k in _SCHEDULE_FIELDS if current.get(k) is not None})
        rec.step('L2-schedule', True, 'DISABLED')
    except Exception as exc:  # noqa: BLE001
        rec.step('L2-schedule', False, 'update failed: ' + _code(exc))


def _zero_concurrency(clients: Clients, s: Settings, rec: Record) -> None:
    try:
        if clients.lambda_.get_function_concurrency(FunctionName=s.function).get('ReservedConcurrentExecutions') == 0:
            rec.step('L3-concurrency', True, 'already 0')
            return
        clients.lambda_.put_function_concurrency(FunctionName=s.function, ReservedConcurrentExecutions=0)
        rec.step('L3-concurrency', True, 'reserved concurrency 0')
    except Exception as exc:  # noqa: BLE001
        rec.step('L3-concurrency', False, 'failed: ' + _code(exc))


def _alarm_actions_off(clients: Clients, s: Settings, rec: Record) -> None:
    if not s.alarms:
        rec.step('L0-alarm-actions', True, 'no alarm configured')
        return
    try:
        clients.cloudwatch.disable_alarm_actions(AlarmNames=list(s.alarms))
        rec.step('L0-alarm-actions', True, f'{len(s.alarms)} alarms: actions disabled')
    except Exception as exc:  # noqa: BLE001
        rec.step('L0-alarm-actions', False, 'failed: ' + _code(exc))


def _readback(clients: Clients, s: Settings, rec: Record) -> None:
    try:
        item = _control(clients, s)
        rec.check('L1-control', item is None or item.get('enabled', {}).get('BOOL') is not True,
                  'absent' if item is None else f'enabled={item.get("enabled", {}).get("BOOL")} generation={item["execution_generation"]["N"]}')
    except Exception as exc:  # noqa: BLE001
        rec.check('L1-control', False, 'unreadable: ' + _code(exc))
    try:
        state = clients.scheduler.get_schedule(Name=s.schedule).get('State')
        rec.check('L2-schedule', state == 'DISABLED', f'state={state}')
    except Exception as exc:  # noqa: BLE001
        rec.check('L2-schedule', _code(exc) == 'ResourceNotFoundException', 'absent' if _code(exc) == 'ResourceNotFoundException' else 'unreadable: ' + _code(exc))
    try:
        value = clients.lambda_.get_function_concurrency(FunctionName=s.function).get('ReservedConcurrentExecutions')
        rec.check('L3-concurrency', value == 0, f'reserved={value}')
    except Exception as exc:  # noqa: BLE001
        rec.check('L3-concurrency', False, 'unreadable: ' + _code(exc))
    if not s.alarms:
        return
    try:
        found = clients.cloudwatch.describe_alarms(AlarmNames=list(s.alarms)).get('MetricAlarms', [])
        rec.check('L0-alarm-actions', len(found) == len(s.alarms) and not any(a.get('ActionsEnabled') for a in found),
                  f'{sum(bool(a.get("ActionsEnabled")) for a in found)} of {len(found)} still enabled')
    except Exception as exc:  # noqa: BLE001
        rec.check('L0-alarm-actions', False, 'unreadable: ' + _code(exc))


def parse_stop_event(event: Any, target_id: str) -> tuple[str | None, str | None]:
    """-> (requested_at, refusal). Only a stop event for this very target is accepted; its age never blocks a stop."""
    if not isinstance(event, dict) or event.get('schema') != STOP_SCHEMA:
        return None, 'STOP_EVENT_INVALID'
    if event.get('target_id') != target_id:
        return None, 'STOP_EVENT_TARGET_MISMATCH'
    requested = event.get('requested_at')
    return (requested if isinstance(requested, str) else None), None


def stop(event: Any, settings: Settings, clients: Clients, *, now: Callable[[], datetime]) -> Record:
    started = now().astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    requested, refusal = parse_stop_event(event, settings.target_id)
    rec = Record(settings.target_id, requested, started)
    if refusal:
        rec.step('event', False, refusal)
        rec.result = 'STOP_REFUSED'
        return rec
    _alarm_actions_off(clients, settings, rec)
    _disable_control(clients, settings, started, rec)
    _disable_schedule(clients, settings, rec)
    _zero_concurrency(clients, settings, rec)
    _readback(clients, settings, rec)
    rec.result = 'STOP_COMPLETE' if rec.verify and all(v['ok'] for v in rec.verify) else 'STOP_INCOMPLETE'
    return rec


def metric_line(rec: Record) -> dict[str, Any]:
    """CloudWatch Embedded Metric Format line: StopComplete / StopIncomplete per target (the stopper's own alarm watches it)."""
    name = {'STOP_COMPLETE': 'StopComplete', 'STOP_INCOMPLETE': 'StopIncomplete'}.get(rec.result, 'StopRefused')
    return {'_aws': {'Timestamp': int(datetime.now(timezone.utc).timestamp() * 1000),
                     'CloudWatchMetrics': [{'Namespace': METRIC_NAMESPACE, 'Dimensions': [['TargetId']],
                                            'Metrics': [{'Name': name, 'Unit': 'Count'}]}]},
            'TargetId': rec.target_id, name: 1, 'record': {**rec.__dict__}}


def lambda_handler(event: Any, context: Any) -> dict[str, Any]:
    import boto3  # Lambda runtime only; the logic above is tested with fake clients
    settings = Settings.from_env(dict(os.environ))
    clients = Clients(boto3.client('dynamodb'), boto3.client('scheduler'), boto3.client('lambda'), boto3.client('cloudwatch'))
    rec = stop(event, settings, clients, now=lambda: datetime.now(timezone.utc))
    print(json.dumps(metric_line(rec), separators=(',', ':')))
    if rec.result == 'STOP_INCOMPLETE':
        raise StopIncomplete(json.dumps(rec.steps)[:500])
    return {'result': rec.result, 'steps': rec.steps, 'verify': rec.verify}
