"""AWS-C watchdog fault injection: deadline, ambiguity, API failures, journal independence.

Offline fakes only. EC2 API behaviour (eventual consistency, tag-scoped IAM) is
LIVE-unverified.
"""
import unittest
from datetime import timedelta

from src.aws_c import control
from src.aws_c.control import ControlStore
from src.aws_c.watchdog import TAG_KEY, Deps, WatchdogConfig, WatchdogConfigError, run
from tests.aws_c.support import DEADLINE, RUN_ID, T0
from tests.aws_fakes import FakeClientError, FakeDynamo, FakeEc2

AT = "2026-12-01T02:00:00Z"
ENV = {"PILOT_RUN_ID": RUN_ID, "HARD_DEADLINE_UTC": DEADLINE, "TABLE_NAME": "t"}


class Rig:
    def __init__(self, with_store=True, state=None):
        self.ec2, self.dynamo, self.lines = FakeEc2(), FakeDynamo(), []
        self.store = ControlStore(self.dynamo, "t") if with_store else None
        if with_store:
            self.store.reserve(RUN_ID, DEADLINE, AT)
            if state == "RUNNING":
                self.store.transition(RUN_ID, "RESERVED", "RUNNING", 1, AT)

    def tick(self, minutes):
        deps = Deps(config=WatchdogConfig.from_env(ENV), ec2=self.ec2,
                    now=lambda: T0 + timedelta(minutes=minutes), emit=self.lines.append,
                    control_store=self.store)
        return run({}, deps)

    def state(self):
        return self.store.read(RUN_ID).state


class Deadline(unittest.TestCase):
    def test_before_deadline_nothing_is_terminated(self):
        rig = Rig()
        rig.ec2.add("i-1", **{TAG_KEY: RUN_ID})
        out = rig.tick(59)
        self.assertEqual((out["decision"], out["terminate_called"]), ("NOT_DUE", False))
        self.assertEqual(rig.ec2.terminate_calls, [])
        self.assertEqual(rig.lines[-1]["WatchdogAttention"], 0)

    def test_at_deadline_terminates_exactly_the_tagged_instance(self):
        rig = Rig(state="RUNNING")
        rig.ec2.add("i-1", **{TAG_KEY: RUN_ID})
        rig.ec2.add("i-other", **{TAG_KEY: "another-run"})
        rig.ec2.add("i-untagged")
        out = rig.tick(60)
        self.assertEqual(out["decision"], "TERMINATE_REQUESTED")
        self.assertEqual(rig.ec2.terminate_calls, [["i-1"]])
        self.assertEqual(rig.ec2.instances["i-other"]["state"], "running")
        self.assertEqual(rig.ec2.instances["i-untagged"]["state"], "running")
        self.assertEqual(rig.state(), "TERMINATE_REQUESTED")

    def test_stopped_instance_is_still_terminated_at_deadline(self):
        rig = Rig()
        rig.ec2.add("i-1", state="stopped", **{TAG_KEY: RUN_ID})
        self.assertEqual(rig.tick(61)["decision"], "TERMINATE_REQUESTED")
        self.assertEqual(rig.ec2.terminate_calls, [["i-1"]])

    def test_repeat_ticks_converge_to_verified_and_stop_calling(self):
        rig = Rig(state="RUNNING")
        rig.ec2.add("i-1", **{TAG_KEY: RUN_ID})
        rig.tick(60)
        self.assertEqual(rig.tick(61)["decision"], "TERMINATE_REQUESTED")   # still shutting down
        rig.ec2.instances["i-1"]["state"] = "terminated"
        out = rig.tick(62)
        self.assertEqual((out["decision"], out["terminate_called"]), ("ALREADY_TERMINATED", False))
        self.assertEqual(rig.state(), "TERMINATED_VERIFIED")
        self.assertEqual(len(rig.ec2.terminate_calls), 2)
        self.assertEqual(rig.tick(63)["decision"], "ALREADY_TERMINATED")
        self.assertEqual(len(rig.ec2.terminate_calls), 2)

    def test_self_terminated_worker_is_journalled_without_any_terminate_call(self):
        rig = Rig(state="RUNNING")
        rig.ec2.add("i-1", state="terminated", **{TAG_KEY: RUN_ID})
        out = rig.tick(30)
        self.assertEqual(out["decision"], "ALREADY_TERMINATED")
        self.assertEqual(rig.ec2.terminate_calls, [])
        self.assertEqual(rig.state(), "TERMINATED_VERIFIED")


class Ambiguity(unittest.TestCase):
    def test_two_tagged_instances_are_never_terminated(self):
        rig = Rig()
        rig.ec2.add("i-1", **{TAG_KEY: RUN_ID})
        rig.ec2.add("i-2", **{TAG_KEY: RUN_ID})
        out = rig.tick(120)
        self.assertEqual((out["decision"], out["terminate_called"]), ("AMBIGUOUS_TARGET", False))
        self.assertEqual(rig.ec2.terminate_calls, [])
        self.assertEqual(rig.lines[-1]["WatchdogAttention"], 1)
        self.assertEqual(rig.state(), "RESERVED")

    def test_no_target_is_not_reported_as_safe_after_deadline(self):
        rig = Rig()
        self.assertEqual(rig.tick(10)["decision"], "NO_TARGET")
        self.assertEqual(rig.lines[-1]["WatchdogAttention"], 0)
        self.assertEqual(rig.tick(61)["decision"], "NO_TARGET_AFTER_DEADLINE")
        self.assertEqual(rig.lines[-1]["WatchdogAttention"], 1)

    def test_describe_failure_touches_nothing_and_raises_attention(self):
        rig = Rig()
        rig.ec2.add("i-1", **{TAG_KEY: RUN_ID})
        rig.ec2.faults.fail("describe_instances", FakeClientError("RequestLimitExceeded"))
        out = rig.tick(61)
        self.assertEqual((out["decision"], out["terminate_called"]), ("DESCRIBE_FAILED", False))
        self.assertEqual(rig.lines[-1]["WatchdogAttention"], 1)


class Failures(unittest.TestCase):
    def test_terminate_api_error_is_uncertain_and_retried_next_tick(self):
        rig = Rig(state="RUNNING")
        rig.ec2.add("i-1", **{TAG_KEY: RUN_ID})
        rig.ec2.faults.fail("terminate_instances", FakeClientError("UnauthorizedOperation"))
        out = rig.tick(60)
        self.assertEqual(out["decision"], "TERMINATE_UNCERTAIN")
        self.assertEqual(out["terminate_api"], "ERROR_FakeClientError")
        self.assertEqual(rig.lines[-1]["WatchdogAttention"], 1)
        self.assertEqual(rig.tick(65)["decision"], "TERMINATE_REQUESTED")
        self.assertEqual(rig.ec2.terminate_calls, [["i-1"], ["i-1"]])

    def test_accepted_call_but_still_running_is_uncertain(self):
        rig = Rig()
        rig.ec2.add("i-1", **{TAG_KEY: RUN_ID})
        rig.ec2.faults.fail("terminate_instances", TimeoutError(), mode="before")
        self.assertEqual(rig.tick(60)["decision"], "TERMINATE_UNCERTAIN")
        self.assertEqual(rig.ec2.instances["i-1"]["state"], "running")

    def test_second_describe_failure_does_not_claim_termination(self):
        rig = Rig()
        rig.ec2.add("i-1", **{TAG_KEY: RUN_ID})
        rig.ec2.faults.fail("describe_instances", TimeoutError(), skip=1)
        out = rig.tick(60)
        self.assertEqual(out["decision"], "TERMINATE_UNCERTAIN")
        self.assertEqual(rig.ec2.terminate_calls, [["i-1"]])

    def test_dynamodb_down_never_blocks_termination(self):
        rig = Rig(state="RUNNING")
        rig.ec2.add("i-1", **{TAG_KEY: RUN_ID})
        rig.dynamo.faults.fail("get_item", TimeoutError(), times=10)
        rig.dynamo.faults.fail("update_item", TimeoutError(), times=10)
        out = rig.tick(60)
        self.assertEqual(out["decision"], "TERMINATE_REQUESTED")
        self.assertEqual(rig.ec2.terminate_calls, [["i-1"]])
        self.assertEqual(out["journal"], "JOURNAL_READ_FAILED")

    def test_missing_control_record_or_no_table_never_blocks_termination(self):
        for rig in (Rig(with_store=False), Rig()):
            if rig.store:
                rig.dynamo.items.clear()
            rig.ec2.add("i-1", **{TAG_KEY: RUN_ID})
            out = rig.tick(60)
            self.assertEqual(out["decision"], "TERMINATE_REQUESTED")
            self.assertIn(out["journal"], ("NOT_CONFIGURED", "JOURNAL_NOT_FOUND"))

    def test_terminate_happens_before_any_journal_write(self):
        rig = Rig(state="RUNNING")
        rig.ec2.add("i-1", **{TAG_KEY: RUN_ID})
        order = []
        original = rig.ec2.terminate_instances
        rig.ec2.terminate_instances = lambda **kw: (order.append("terminate"), original(**kw))[1]
        rig.dynamo.before["update_item"] = lambda request: order.append("journal")
        rig.tick(60)
        self.assertEqual(order[0], "terminate")
        self.assertIn("journal", order)


class ConfigAndCode(unittest.TestCase):
    def test_config_requires_exact_deadline_and_run_id(self):
        for env in ({**ENV, "HARD_DEADLINE_UTC": "2026-12-01"}, {**ENV, "PILOT_RUN_ID": "a b"},
                    {"PILOT_RUN_ID": RUN_ID}, {**ENV, "HARD_DEADLINE_UTC": ""}):
            with self.assertRaises(WatchdogConfigError):
                WatchdogConfig.from_env(env)

    def test_event_content_cannot_change_target_or_deadline(self):
        rig = Rig()
        rig.ec2.add("i-1", **{TAG_KEY: RUN_ID})
        deps = Deps(config=WatchdogConfig.from_env(ENV), ec2=rig.ec2, now=lambda: T0,
                    emit=rig.lines.append)
        out = run({"force": True, "instance_id": "i-other", "deadline": "1970-01-01T00:00:00Z"},
                  deps)
        self.assertEqual(out["decision"], "NOT_DUE")

    def test_module_never_starts_runs_stops_or_reboots(self):
        import inspect
        import src.aws_c.watchdog as module
        source = inspect.getsource(module).replace("Start/Run/Stop/Reboot", "")
        for forbidden in ("start_instances", "run_instances", "stop_instances",
                          "reboot_instances", "modify_instance", "create_tags"):
            self.assertNotIn(forbidden, source)
        self.assertEqual(control.can_transition("TERMINATED_VERIFIED", "RUNNING"), False)

    def test_metric_line_shape(self):
        rig = Rig()
        rig.tick(1)
        directive = rig.lines[-1]["_aws"]["CloudWatchMetrics"][0]
        self.assertEqual((directive["Namespace"], directive["Dimensions"]),
                         ("SiteProof/Pilot", [["PilotRunId"]]))
        self.assertEqual(rig.lines[-1]["WatchdogRun"], 1)


if __name__ == "__main__":
    unittest.main()
