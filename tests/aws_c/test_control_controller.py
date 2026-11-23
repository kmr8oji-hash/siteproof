"""AWS-C control record and controller: single slot, no re-arm, conditional transitions.

Offline: FakeDynamo evaluates the real expressions. DynamoDB itself is LIVE-unverified.
"""
import unittest

from src.aws_c import control
from src.aws_c.control import ControlStore
from src.aws_c.controller import run as controller
from tests.aws_c.support import DEADLINE, RUN_ID, T0
from tests.aws_fakes import FakeClientError, FakeDynamo

AT = "2026-12-01T02:00:00Z"


def store():
    fake = FakeDynamo()
    return fake, ControlStore(fake, "siteproof-c-test")


class SlotAndReserve(unittest.TestCase):
    def test_reserve_creates_slot_and_run_record(self):
        fake, s = store()
        result = s.reserve(RUN_ID, DEADLINE, AT)
        self.assertEqual((result.ok, result.state, result.version), (True, "RESERVED", 1))
        self.assertEqual(fake.items[("SLOT", "SINGLETON")]["pilot_run_id"]["S"], RUN_ID)
        self.assertEqual(fake.items[("PILOT#" + RUN_ID, "STATE")]["hard_deadline_utc"]["S"],
                         DEADLINE)

    def test_same_run_resent_returns_existing_record_without_second_item(self):
        fake, s = store()
        s.reserve(RUN_ID, DEADLINE, AT)
        again = s.reserve(RUN_ID, DEADLINE, "2026-12-01T02:05:00Z")
        self.assertEqual((again.ok, again.reason, again.state), (False, "ALREADY_RESERVED",
                                                                 "RESERVED"))
        self.assertEqual(len(fake.items), 2)
        self.assertEqual(fake.items[("PILOT#" + RUN_ID, "STATE")]["reserved_at"]["S"], AT)

    def test_second_run_id_is_refused_forever(self):
        fake, s = store()
        s.reserve(RUN_ID, DEADLINE, AT)
        other = s.reserve("pilot-2", DEADLINE, AT)
        self.assertEqual(other.reason, "SLOT_CONSUMED_BY_OTHER_RUN")
        self.assertNotIn(("PILOT#pilot-2", "STATE"), fake.items)

    def test_slot_is_not_released_after_a_finished_run(self):
        fake, s = store()
        s.reserve(RUN_ID, DEADLINE, AT)
        version = 1
        for source, target in (("RESERVED", "RUNNING"), ("RUNNING", "ISOLATION_PASSED"),
                               ("ISOLATION_PASSED", "EVIDENCE_COMMITTED"),
                               ("EVIDENCE_COMMITTED", "TERMINATE_REQUESTED"),
                               ("TERMINATE_REQUESTED", "TERMINATED_VERIFIED")):
            version = s.transition(RUN_ID, source, target, version, AT).version
        self.assertEqual(s.read(RUN_ID).state, "TERMINATED_VERIFIED")
        self.assertEqual(s.reserve("pilot-2", DEADLINE, AT).reason, "SLOT_CONSUMED_BY_OTHER_RUN")
        self.assertEqual(s.reserve(RUN_ID, DEADLINE, AT).state, "TERMINATED_VERIFIED")

    def test_lost_acknowledgement_on_slot_write_recovers_same_run_only(self):
        fake, s = store()
        fake.faults.fail("put_item", TimeoutError(), mode="after")
        self.assertEqual(s.reserve(RUN_ID, DEADLINE, AT).reason, "RESERVE_UNCERTAIN")
        self.assertEqual(s.reserve(RUN_ID, DEADLINE, AT).ok, True)
        self.assertEqual(s.reserve("pilot-2", DEADLINE, AT).reason, "SLOT_CONSUMED_BY_OTHER_RUN")

    def test_invalid_run_id_never_reaches_the_table(self):
        fake, s = store()
        with self.assertRaises(Exception):
            s.reserve("bad id/..", DEADLINE, AT)
        self.assertEqual(fake.items, {})


class Transitions(unittest.TestCase):
    def test_table_has_no_path_back_to_reserved_or_running(self):
        for source, targets in control.ALLOWED.items():
            self.assertNotIn(control.RESERVED, targets)
            if source != control.RESERVED:
                self.assertNotIn(control.RUNNING, targets)
        for terminal in ("ISOLATION_FAILED", "EVIDENCE_COMMITTED", "FAILED",
                         "TERMINATED_VERIFIED"):
            self.assertEqual(control.ALLOWED[terminal], frozenset())

    def test_isolation_failure_cannot_reach_evidence_committed(self):
        self.assertFalse(control.can_transition("ISOLATION_FAILED", "EVIDENCE_COMMITTED"))
        self.assertFalse(control.can_transition("RUNNING", "EVIDENCE_COMMITTED"))
        self.assertFalse(control.can_transition("RESERVED", "ISOLATION_PASSED"))

    def test_watchdog_may_request_termination_from_any_worker_state(self):
        for source in ("RESERVED", "RUNNING", "ISOLATION_PASSED", "ISOLATION_FAILED",
                       "EVIDENCE_COMMITTED", "FAILED"):
            self.assertTrue(control.can_transition(source, "TERMINATE_REQUESTED"), source)
        for source in ("TERMINATE_REQUESTED", "TERMINATED_VERIFIED", "TERMINATE_UNCERTAIN"):
            self.assertFalse(control.can_transition(source, "TERMINATE_REQUESTED"), source)
        self.assertFalse(control.can_transition("TERMINATED_VERIFIED", "RUNNING"))

    def test_transition_requires_expected_state_and_version(self):
        fake, s = store()
        s.reserve(RUN_ID, DEADLINE, AT)
        stale = s.transition(RUN_ID, "RESERVED", "RUNNING", 5, AT)
        self.assertEqual((stale.ok, stale.reason, stale.state, stale.version),
                         (False, "STATE_CHANGED", "RESERVED", 1))
        self.assertTrue(s.transition(RUN_ID, "RESERVED", "RUNNING", 1, AT).ok)
        replay = s.transition(RUN_ID, "RESERVED", "RUNNING", 1, AT)
        self.assertEqual((replay.reason, replay.state, replay.version),
                         ("STATE_CHANGED", "RUNNING", 2))

    def test_disallowed_transition_makes_no_request(self):
        fake, s = store()
        s.reserve(RUN_ID, DEADLINE, AT)
        calls = len(fake.faults.calls)
        self.assertEqual(s.transition(RUN_ID, "RESERVED", "EVIDENCE_COMMITTED", 1, AT).reason,
                         "TRANSITION_NOT_ALLOWED")
        self.assertEqual(len(fake.faults.calls), calls)

    def test_store_errors_are_reported_as_uncertain(self):
        fake, s = store()
        s.reserve(RUN_ID, DEADLINE, AT)
        fake.faults.fail("update_item", FakeClientError("ProvisionedThroughputExceededException"))
        self.assertEqual(s.transition(RUN_ID, "RESERVED", "RUNNING", 1, AT).reason,
                         "TRANSITION_UNCERTAIN")
        fake.faults.fail("get_item", TimeoutError())
        self.assertEqual(s.read(RUN_ID).reason, "READ_FAILED")
        self.assertEqual(s.read("unknown-run").reason, "NOT_FOUND")

    def test_no_request_deletes_or_removes(self):
        requests = [control.build_slot_request("t", RUN_ID, AT),
                    control.build_reserve_request("t", RUN_ID, DEADLINE, AT),
                    control.build_transition_request("t", RUN_ID, "RESERVED", "RUNNING", 1, AT)]
        for request in requests:
            self.assertNotIn("REMOVE", str(request))
            self.assertIn("ConditionExpression", request)


class Controller(unittest.TestCase):
    def call(self, event, s, seconds=0):
        from datetime import timedelta
        return controller(event, store=s, pilot_run_id=RUN_ID, hard_deadline_utc=DEADLINE,
                          now=lambda: T0 + timedelta(seconds=seconds))

    def test_reserve_then_status(self):
        _, s = store()
        self.assertEqual(self.call({"action": "status"}, s)["reason"], "NOT_FOUND")
        self.assertEqual(self.call({"action": "reserve"}, s)["state"], "RESERVED")
        status = self.call({"action": "status"}, s)
        self.assertEqual((status["state"], status["past_deadline"]), ("RESERVED", False))

    def test_event_cannot_choose_run_id_deadline_or_other_actions(self):
        fake, s = store()
        for event in ({"action": "reserve", "pilot_run_id": "x"}, {"action": "start"},
                      {"action": "terminate"}, {"action": "rearm"}, {}, None, "reserve",
                      {"action": "reserve", "hard_deadline_utc": "2030-01-01T00:00:00Z"}):
            self.assertEqual(self.call(event, s)["reason"], "REQUEST_INVALID")
        self.assertEqual(fake.items, {})

    def test_reserve_refused_at_or_after_deadline(self):
        fake, s = store()
        self.assertEqual(self.call({"action": "reserve"}, s, seconds=3600)["reason"],
                         "PAST_HARD_DEADLINE")
        self.assertEqual(fake.items, {})

    def test_controller_module_has_no_ec2_code(self):
        import inspect
        import src.aws_c.controller as module
        source = inspect.getsource(module)
        for forbidden in ('client("ec2"', "run_instances", "start_instances",
                          "terminate_instances", "stop_instances"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
