"""Shared offline harness for AWS-B behaviour tests. No network, no AWS, no real clock."""
from datetime import datetime, timedelta, timezone

from src.aws_b.handler import Deps, run
from src.aws_b.model import EVENT_SCHEMA, MonitorConfig, format_utc
from src.aws_b.probe import ProbeResult
from src.aws_b.store import DynamoStore
from src.core.model import CheckOutcome
from tests.aws_fakes import FakeDynamo

T0 = datetime(2026, 11, 20, 3, 0, 0, tzinfo=timezone.utc)
ENV = {"TARGET_ID": "preview", "TARGET_HOSTNAME": "d111111abcdef8.cloudfront.net",
       "TARGET_PATH": "/home/index.html", "POLICY_VERSION": "p1",
       "ABSOLUTE_END_AT": "2026-11-21T03:00:00Z", "TABLE_NAME": "siteproof-b-test"}


def at(seconds=0):
    return T0 + timedelta(seconds=seconds)


def event(slot_offset=0, generation=1, target="preview", **override):
    body = {"schema": EVENT_SCHEMA, "target_id": target,
            "scheduled_time": format_utc(at(slot_offset)), "execution_generation": generation}
    body.update(override)
    return body


class Harness:
    """Armed monitor with a counting probe stub. `now` is advanced explicitly."""

    def __init__(self, armed=True, env=None, outcome=(CheckOutcome.PASS, "HTTP_200", 200),
                 notify=False):
        self.config = MonitorConfig.from_env({**ENV, **(env or {})})
        self.dynamo = FakeDynamo()
        self.store = DynamoStore(self.dynamo, self.config.table_name)
        self.now = at(1)
        self.lines, self.probes = [], []
        self.outcome = outcome
        self.remaining = 15.0
        self.attempts = 0
        self.notify = notify
        self.sent = []                  # (subject, body) accepted by the fake SNS
        self.publish_error = None       # set to an exception to make SNS fail
        if armed:
            self.arm()

    def arm(self, generation=1, policy="p1", hostname=None):
        return self.store.arm(target_id="preview", hostname=hostname or self.config.hostname,
                              policy_version=policy, execution_generation=generation,
                              armed_at=format_utc(self.now))

    def stop(self, generation=1):
        return self.store.stop(target_id="preview", expected_generation=generation,
                               stopped_at=format_utc(self.now))

    def _probe(self, deadline):
        self.probes.append(deadline)
        outcome, reason, status = self.outcome
        return ProbeResult(outcome, reason, http_status=status, selected_ip="93.184.216.34",
                           elapsed_ms=12)

    def _publish(self, subject, message):
        if self.publish_error is not None:
            raise self.publish_error
        self.sent.append((subject, message))

    def run_slot(self, slot_offset, outcome=None, attempt=None):
        """Run one scheduled slot 1 s after its time, with the probe returning `outcome`."""
        if outcome is not None:
            self.outcome = outcome
        self.now = at(slot_offset + 1)
        return self.invoke(event(slot_offset), attempt=attempt)

    def invoke(self, body, attempt=None):
        self.attempts += 1
        deps = Deps(config=self.config, store=self.store, probe=self._probe,
                    now=lambda: self.now, emit=self.lines.append, monotonic=lambda: 100.0,
                    attempt_id=attempt or "attempt-%d" % self.attempts,
                    remaining_seconds=lambda: self.remaining,
                    publish=self._publish if self.notify else None)
        return run(body, deps)

    def run_item(self, slot_offset=0):
        return self.dynamo.items.get(("RUN#preview", format_utc(at(slot_offset))))

    def head(self):
        return self.dynamo.items.get(("CONTROL#preview", "HEAD"))

    def metric(self, name, line=-1):
        return self.lines[line].get(name)
