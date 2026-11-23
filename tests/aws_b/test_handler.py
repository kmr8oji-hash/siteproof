"""AWS-B decision logic under duplicate, late, out-of-order, stopped and failing-store events.

Offline only: FakeDynamo evaluates the real request expressions built by src/aws_b/store.py.
These tests show what the handler decides; they do not show how EventBridge Scheduler,
Lambda or DynamoDB actually deliver or behave (LIVE-unverified).
"""
import unittest

from src.aws_b.model import STATE_CLAIMED, STATE_RECORDED
from src.core.model import CheckOutcome
from tests.aws_b.support import Harness, at, event
from tests.aws_fakes import FakeClientError


class NormalRun(unittest.TestCase):
    def test_armed_fresh_event_probes_once_and_records(self):
        h = Harness()
        out = h.invoke(event())
        self.assertEqual((out["decision"], out["outcome"], out["persisted"]),
                         ("PROBED", "PASS", True))
        self.assertEqual(len(h.probes), 1)
        item = h.run_item()
        self.assertEqual(item["state"]["S"], STATE_RECORDED)
        self.assertEqual(item["outcome"]["S"], "PASS")
        self.assertEqual(item["http_status"]["N"], "200")
        self.assertEqual(item["attempt_id"]["S"], "attempt-1")
        self.assertEqual(item["execution_generation"]["N"], "1")
        self.assertEqual(len(item["logical_run_key"]["S"]), 64)
        self.assertEqual((h.metric("ProbeFailure"), h.metric("Unpersisted")), (0, 0))

    def test_record_has_ttl_and_head_tracks_last_slot(self):
        h = Harness()
        h.invoke(event())
        self.assertEqual(int(h.run_item()["expires_at"]["N"]),
                         int(h.now.timestamp()) + 14 * 86400)
        self.assertEqual(h.head()["last_slot"]["S"], "2026-11-20T03:00:00Z")

    def test_failed_and_unknown_probe_are_failure_datapoints(self):
        for outcome, reason, status, unknown in (
                (CheckOutcome.FAIL, "HTTP_503", 503, 0),
                (CheckOutcome.UNKNOWN, "HTTP_302_UNRESOLVED", 302, 1)):
            with self.subTest(outcome=outcome):
                h = Harness(outcome=(outcome, reason, status))
                out = h.invoke(event())
                self.assertEqual(out["outcome"], outcome.value)
                self.assertEqual(h.metric("ProbeUnknown"), unknown)
                if unknown:
                    self.assertNotIn("ProbeFailure", h.lines[-1])
                else:
                    self.assertEqual(h.metric("ProbeFailure"), 1)
                self.assertEqual(h.run_item()["outcome"]["S"], outcome.value)

    def test_consecutive_slots_each_probe_once(self):
        h = Harness()
        for index in range(3):
            h.now = h.now.replace(minute=index * 5, second=1)
            self.assertEqual(h.invoke(event(index * 300))["decision"], "PROBED")
        self.assertEqual(len(h.probes), 3)


class DuplicateAndOrdering(unittest.TestCase):
    def test_duplicate_delivery_of_same_slot_probes_once(self):
        h = Harness()
        first = h.invoke(event())
        second = h.invoke(event())
        self.assertEqual(first["decision"], "PROBED")
        self.assertEqual((second["decision"], second["reason"], second["probe_started"]),
                         ("REJECTED", "DUPLICATE_SLOT", False))
        self.assertEqual(len(h.probes), 1)
        self.assertEqual(h.run_item()["attempt_id"]["S"], "attempt-1")
        self.assertEqual(h.metric("Rejected"), 1)
        self.assertNotIn("ProbeFailure", h.lines[-1])   # no datapoint for a refused event

    def test_five_duplicates_still_one_probe(self):
        h = Harness()
        decisions = [h.invoke(event())["decision"] for _ in range(5)]
        self.assertEqual(decisions.count("PROBED"), 1)
        self.assertEqual(len(h.probes), 1)

    def test_older_slot_arriving_after_newer_is_refused(self):
        h = Harness()
        h.now = h.now.replace(second=31)
        self.assertEqual(h.invoke(event(30))["decision"], "PROBED")
        # The 03:00:00 event arrives after the 03:00:30 one, still inside the age window,
        # so only the conditional write on the control item can refuse it.
        out = h.invoke(event(0))
        self.assertEqual((out["decision"], out["reason"]), ("REJECTED", "OLDER_SLOT"))
        self.assertEqual(len(h.probes), 1)
        self.assertIsNone(h.run_item(0))
        self.assertEqual(h.head()["last_slot"]["S"], "2026-11-20T03:00:30Z")

    def test_retry_of_same_attempt_after_crash_does_not_reprobe(self):
        """Lambda retries re-deliver the same payload; the claim is already consumed."""
        h = Harness()
        h.dynamo.faults.fail("update_item", RuntimeError("crash after probe"), skip=1)
        out = h.invoke(event(), attempt="req-1")
        self.assertFalse(out["persisted"])
        again = h.invoke(event(), attempt="req-1")
        self.assertEqual((again["decision"], again["reason"]), ("REJECTED", "DUPLICATE_SLOT"))
        self.assertEqual(len(h.probes), 1)


class LateAndDeadline(unittest.TestCase):
    def test_event_older_than_window_is_refused_before_any_write(self):
        h = Harness()
        h.now = h.now.replace(minute=1, second=1)          # 61 s after the slot
        out = h.invoke(event())
        self.assertEqual((out["reason"], out["event_age_seconds"]), ("EVENT_TOO_OLD", 61))
        self.assertEqual(len(h.probes), 0)
        self.assertEqual(h.dynamo.faults.calls, ["put_item"])   # only the arming write
        self.assertNotIn("last_slot", h.head())

    def test_event_exactly_at_window_edge_is_accepted(self):
        h = Harness()
        h.now = h.now.replace(minute=1, second=0)          # exactly 60 s
        self.assertEqual(h.invoke(event())["decision"], "PROBED")

    def test_future_event_is_refused(self):
        h = Harness()
        out = h.invoke(event(60))
        self.assertEqual(out["reason"], "EVENT_IN_FUTURE")
        self.assertEqual(len(h.probes), 0)

    def test_at_or_after_absolute_end_is_refused(self):
        for second in (0, 1):
            with self.subTest(second=second):
                h = Harness()
                h.now = h.config.absolute_end_at.replace(second=second)
                out = h.invoke(event(86400))
                self.assertEqual(out["reason"], "PAST_ABSOLUTE_END")
                self.assertEqual(len(h.probes), 0)

    def test_probe_budget_never_crosses_absolute_end_or_lambda_timeout(self):
        h = Harness()
        h.now = h.config.absolute_end_at.replace(day=20, hour=3, minute=0, second=1)
        h.remaining = 6.5                                  # 6.5 - 4 s reserve = 2.5 s
        h.invoke(event())
        self.assertAlmostEqual(h.probes[0] - 100.0, 2.5)

    def test_store_latency_crossing_absolute_end_does_not_probe(self):
        h = Harness(env={"ABSOLUTE_END_AT": "2026-11-20T03:00:03Z"})
        original = h.store.open_run
        def delayed(claim):
            result = original(claim)
            h.now = h.config.absolute_end_at
            return result
        h.store.open_run = delayed
        out = h.invoke(event())
        self.assertEqual((out["reason"], out["probe_started"]), ("NO_TIME_BUDGET", False))
        self.assertEqual(h.probes, [])

    def test_no_time_budget_records_unknown_without_probing(self):
        h = Harness()
        h.remaining = 3.0
        out = h.invoke(event())
        self.assertEqual((out["outcome"], out["reason"], out["probe_started"]),
                         ("UNKNOWN", "NO_TIME_BUDGET", False))
        self.assertEqual(len(h.probes), 0)
        self.assertEqual(h.run_item()["outcome"]["S"], "UNKNOWN")


class StopAndGeneration(unittest.TestCase):
    def test_unarmed_table_refuses(self):
        h = Harness(armed=False)
        out = h.invoke(event())
        self.assertEqual((out["decision"], out["reason"]), ("REJECTED", "NOT_ARMED"))
        self.assertEqual(len(h.probes), 0)

    def test_stop_refuses_events_already_queued_for_old_generation(self):
        h = Harness()
        self.assertTrue(h.stop().ok)
        out = h.invoke(event())
        self.assertEqual((out["decision"], out["reason"]), ("REJECTED", "STOPPED"))
        self.assertEqual(len(h.probes), 0)
        self.assertIsNone(h.run_item())
        head = h.head()
        self.assertEqual((head["enabled"]["BOOL"], head["execution_generation"]["N"]),
                         (False, "2"))

    def test_stop_racing_between_handler_start_and_claim_wins(self):
        h = Harness()
        fired = []

        def stop_first(request):
            if not fired and ":slot" in request.get("ExpressionAttributeValues", {}):
                fired.append(1)
                h.dynamo.items[("CONTROL#preview", "HEAD")]["enabled"] = {"BOOL": False}
        h.dynamo.before["update_item"] = stop_first
        out = h.invoke(event())
        self.assertEqual((out["decision"], out["reason"]), ("REJECTED", "STOPPED"))
        self.assertEqual(len(h.probes), 0)

    def test_old_generation_event_refused_after_rearm_with_new_generation(self):
        h = Harness()
        h.stop()
        head = h.dynamo.items[("CONTROL#preview", "HEAD")]
        head["enabled"] = {"BOOL": True}                   # operator re-arms generation 2
        out = h.invoke(event(generation=1))
        self.assertEqual(out["reason"], "GENERATION_MISMATCH")
        self.assertEqual(h.invoke(event(generation=2))["decision"], "PROBED")
        self.assertEqual(len(h.probes), 1)

    def test_policy_or_target_change_refuses_until_redeployed_consistently(self):
        h = Harness(armed=False)
        h.arm(policy="p0")
        self.assertEqual(h.invoke(event())["reason"], "POLICY_MISMATCH")
        h2 = Harness(armed=False)
        h2.arm(hostname="other.example.org")
        self.assertEqual(h2.invoke(event())["reason"], "TARGET_MISMATCH")
        self.assertEqual(len(h.probes) + len(h2.probes), 0)

    def test_stop_requires_expected_generation_and_arm_never_overwrites(self):
        h = Harness()
        self.assertEqual(h.stop(generation=7).reason, "STOP_CONDITION_FAILED")
        self.assertTrue(h.head()["enabled"]["BOOL"])
        self.assertEqual(h.arm(generation=9).reason, "ALREADY_ARMED")
        self.assertEqual(h.head()["execution_generation"]["N"], "1")


class StoreFailures(unittest.TestCase):
    def test_claim_error_fails_closed(self):
        h = Harness()
        h.dynamo.faults.fail("update_item", TimeoutError("ddb"), mode="before")
        out = h.invoke(event())
        self.assertEqual((out["decision"], out["reason"], out["store_error"]),
                         ("REJECTED", "CLAIM_UNCERTAIN", "TimeoutError"))
        self.assertEqual(len(h.probes), 0)

    def test_claim_applied_but_ack_lost_does_not_probe_now_or_on_redelivery(self):
        h = Harness()
        h.dynamo.faults.fail("update_item", TimeoutError("lost ack"), mode="after")
        self.assertEqual(h.invoke(event())["reason"], "CLAIM_UNCERTAIN")
        self.assertEqual(h.invoke(event())["reason"], "DUPLICATE_SLOT")
        self.assertEqual(len(h.probes), 0)                 # the slot stays unobserved
        self.assertIsNone(h.run_item())

    def test_access_denied_on_claim_fails_closed(self):
        h = Harness()
        h.dynamo.faults.fail("update_item", FakeClientError("AccessDeniedException"))
        out = h.invoke(event())
        self.assertEqual(out["reason"], "CLAIM_UNCERTAIN")
        self.assertEqual(len(h.probes), 0)

    def test_run_record_write_failure_means_no_probe_and_unpersisted_metric(self):
        h = Harness()
        h.dynamo.faults.fail("put_item", TimeoutError("ddb"), mode="before")
        out = h.invoke(event())
        self.assertEqual((out["decision"], out["reason"], out["probe_started"]),
                         ("REJECTED", "RUN_RECORD_UNCERTAIN", False))
        self.assertEqual(len(h.probes), 0)
        self.assertEqual(h.metric("Unpersisted"), 1)
        self.assertEqual(h.metric("ProbeUnknown"), 1)
        self.assertNotIn("ProbeFailure", h.lines[-1])

    def test_result_write_failure_is_unpersisted_and_never_reprobed(self):
        h = Harness()
        h.dynamo.faults.fail("update_item", TimeoutError("ddb"), skip=1)
        out = h.invoke(event())
        self.assertEqual((out["decision"], out["persisted"], out["store_reason"]),
                         ("PROBED", False, "RESULT_UNPERSISTED"))
        self.assertEqual(h.metric("Unpersisted"), 1)
        self.assertEqual(h.metric("ProbeUnknown"), 1)
        self.assertNotIn("ProbeFailure", h.lines[-1])
        self.assertEqual(len(h.probes), 1)
        # what a reader can see is a claim without a result, never a stored PASS
        self.assertEqual(h.run_item()["state"]["S"], STATE_CLAIMED)
        self.assertNotIn("outcome", h.run_item())
        self.assertEqual(h.invoke(event())["reason"], "DUPLICATE_SLOT")
        self.assertEqual(len(h.probes), 1)

    def test_result_from_non_owner_attempt_is_not_recorded(self):
        h = Harness()

        def steal(request):
            if ":recorded" in request.get("ExpressionAttributeValues", {}):
                h.dynamo.items[("RUN#preview", "2026-11-20T03:00:00Z")]["attempt_id"] = {
                    "S": "someone-else"}
        h.dynamo.before["update_item"] = steal
        out = h.invoke(event())
        self.assertEqual((out["persisted"], out["store_reason"]), (False, "RESULT_NOT_OWNED"))
        self.assertEqual(h.run_item()["state"]["S"], STATE_CLAIMED)


class EventValidation(unittest.TestCase):
    def test_malformed_events_are_refused_without_store_access(self):
        bad = [None, [], "x", {}, {**event(), "extra": 1}, event(schema="other"),
               event(scheduled_time="2026-11-20T03:00:00+00:00"),
               event(scheduled_time="2026-11-20 03:00:00Z"),
               event(scheduled_time="2026-13-40T03:00:00Z"), event(scheduled_time=1),
               event(execution_generation="1"), event(execution_generation=True),
               event(execution_generation=0), event(target="bad id")]
        for body in bad:
            with self.subTest(body=body):
                h = Harness()
                out = h.invoke(body)
                self.assertEqual(out["decision"], "REJECTED")
                self.assertTrue(out["reason"].startswith("EVENT_"), out["reason"])
                self.assertEqual(len(h.probes), 0)
                self.assertEqual(h.dynamo.faults.calls, ["put_item"])

    def test_event_for_another_target_is_refused(self):
        h = Harness()
        self.assertEqual(h.invoke(event(target="other"))["reason"], "EVENT_TARGET_MISMATCH")
        self.assertEqual(len(h.probes), 0)

    def test_event_cannot_supply_hostname_or_path(self):
        h = Harness()
        out = h.invoke({**event(), "hostname": "evil.example"})
        self.assertEqual(out["reason"], "EVENT_SHAPE_INVALID")


class MetricLine(unittest.TestCase):
    def test_only_a_completed_run_declares_the_single_heartbeat_metric(self):
        h = Harness()
        h.invoke(event())
        line = h.lines[-1]
        directive = line["_aws"]["CloudWatchMetrics"][0]
        self.assertEqual(directive["Namespace"], "SiteProof/Monitor")
        self.assertEqual(directive["Dimensions"], [["MonitorGroup"]])
        self.assertEqual([m["Name"] for m in directive["Metrics"]], ["ProbeCompleted"])
        self.assertEqual((line["MonitorGroup"], line["ProbeCompleted"], line["TargetId"]),
                         ("siteproof-b", 1, "preview"))
        # stamped with the scheduled slot (03:00:00Z), not the run time
        self.assertEqual(line["_aws"]["Timestamp"], int(at(0).timestamp() * 1000))
        # diagnostics stay as plain log fields: no per-page custom metrics
        self.assertEqual((line["ProbeFailure"], line["ProbeUnknown"], line["Unpersisted"]), (0, 0, 0))

    def test_rejected_and_unpersisted_runs_declare_no_metric_at_all(self):
        h = Harness()
        h.invoke(event())
        h.invoke(event())                                    # duplicate
        h.dynamo.faults.fail("update_item", TimeoutError("ddb"), skip=1)
        h.now = at(301)
        self.assertFalse(h.invoke(event(300))["persisted"])  # result write fails
        self.assertEqual(["_aws" in line for line in h.lines], [True, False, False])

    def test_every_invocation_emits_exactly_one_line(self):
        h = Harness()
        for body in (event(), event(), None, event(60)):
            h.invoke(body)
        self.assertEqual(len(h.lines), 4)


if __name__ == "__main__":
    unittest.main()
