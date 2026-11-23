"""AWS-B direct SNS notification and heartbeat, offline.

FakeDynamo evaluates the real request expressions; SNS is a list (or an exception). These
tests show what the handler decides. They do not show SNS delivery, mail arrival or how
CloudWatch aggregates the heartbeat (LIVE-unverified).
"""
import unittest

from src.aws_b.model import MonitorConfig
from src.aws_b.notify import MAX_PENDING, format_message, parse_pending, transition_event
from src.aws_b.store import Claim, build_claim_request
from src.core.model import CheckOutcome
from tests.aws_b.support import ENV, Harness, at, event

PASS = (CheckOutcome.PASS, "HTTP_200", 200)
FAIL = (CheckOutcome.FAIL, "HTTP_503", 503)
UNKNOWN = (CheckOutcome.UNKNOWN, "HTTP_302_UNRESOLVED", 302)
STEP = 3600           # slot spacing in these tests; only the order of slots matters here


def kinds(h):
    return [subject.split()[1] for subject, _ in h.sent]


def pending(h):
    return parse_pending(h.head().get("ntf_pending", {}).get("S"))[0]


class Transitions(unittest.TestCase):
    def test_pass_fail_pass_sends_failure_then_recovery_only(self):
        h = Harness(notify=True)
        outs = [h.run_slot(0, PASS), h.run_slot(STEP, FAIL), h.run_slot(2 * STEP, PASS)]
        self.assertEqual(kinds(h), ["FAIL", "RECOVERED"])
        self.assertEqual([o["heartbeat"] for o in outs], [True, True, True])
        self.assertEqual(pending(h), [])

    def test_fail_unknown_pass(self):
        h = Harness(notify=True)
        h.run_slot(0, FAIL)
        h.run_slot(STEP, UNKNOWN)
        h.run_slot(2 * STEP, PASS)
        self.assertEqual(kinds(h), ["FAIL", "UNKNOWN", "OK"])

    def test_pass_to_unknown_and_unknown_to_fail(self):
        h = Harness(notify=True)
        for index, outcome in enumerate((PASS, UNKNOWN, FAIL)):
            h.run_slot(index * STEP, outcome)
        self.assertEqual(kinds(h), ["UNKNOWN", "FAIL"])

    def test_first_observation(self):
        for outcome, expected in ((PASS, []), (FAIL, ["FAIL"]), (UNKNOWN, ["UNKNOWN"])):
            with self.subTest(outcome=outcome[0]):
                h = Harness(notify=True)
                h.run_slot(0, outcome)
                self.assertEqual(kinds(h), expected)

    def test_same_state_never_repeats_the_mail(self):
        h = Harness(notify=True)
        for index in range(5):
            self.assertTrue(h.run_slot(index * STEP, FAIL)["heartbeat"])
        self.assertEqual(kinds(h), ["FAIL"])

    def test_message_is_japanese_with_page_status_time_and_reason(self):
        item = transition_event("PASS", "FAIL", target_id="ttn-home", slot="2026-11-20T03:00:00Z",
                                reason="HTTP_503", http_status=503, at="2026-11-20T03:00:05Z")
        subject, body = format_message(item, "example.org", "/home/index.html")
        self.assertTrue(subject.isascii() and len(subject) < 100)
        for text in ("ttn-home", "https://example.org/home/index.html", "503", "HTTP_503",
                     "2026-11-20T03:00:05Z", "障害", "正常 → 障害", "再送"):
            self.assertIn(text, body)


class SnsFailureAndResend(unittest.TestCase):
    def test_failed_publish_is_kept_and_resent_by_the_next_run(self):
        h = Harness(notify=True)
        h.run_slot(0, PASS)
        h.publish_error = RuntimeError("sns down")
        out = h.run_slot(STEP, FAIL)
        self.assertEqual((out["heartbeat"], out["notify_pending"], h.sent), (False, 1, []))
        self.assertTrue(out["notify_reason"].startswith("PUBLISH_FAILED"))
        self.assertEqual(len(pending(h)), 1)
        h.publish_error = None
        out = h.run_slot(2 * STEP, FAIL)                      # still failing: resend, no second event
        self.assertEqual((kinds(h), out["heartbeat"]), (["FAIL"], True))
        self.assertIn("2026-11-20T04:00:00Z", h.sent[0][1])  # the ORIGINAL slot, not the resend slot
        self.assertEqual(pending(h), [])

    def test_failure_lost_by_sns_survives_a_later_state_change(self):
        """PASS -> FAIL (SNS fails) -> PASS: the FAIL mail must still go out."""
        h = Harness(notify=True)
        h.run_slot(0, PASS)
        h.publish_error = RuntimeError("sns down")
        h.run_slot(STEP, FAIL)
        h.publish_error = None
        out = h.run_slot(2 * STEP, PASS)
        self.assertEqual(kinds(h), ["FAIL", "RECOVERED"])
        self.assertEqual((out["notify_sent"], out["heartbeat"], pending(h)), (2, True, []))

    def test_while_sns_stays_down_every_run_retries_and_no_heartbeat_is_sent(self):
        h = Harness(notify=True)
        h.publish_error = RuntimeError("sns down")
        outs = [h.run_slot(i * STEP, FAIL) for i in range(3)]
        self.assertEqual([o["heartbeat"] for o in outs], [False] * 3)
        self.assertEqual([("_aws" in line) for line in h.lines], [False] * 3)
        self.assertEqual(len(pending(h)), 1)

    def test_backlog_over_the_limit_folds_into_one_summary_and_loses_no_event(self):
        h = Harness(notify=True)
        h.publish_error = RuntimeError("sns down")
        outcomes = [FAIL, PASS] * 6                         # 12 state changes, SNS down the whole time
        outs = [h.run_slot(i * STEP, o) for i, o in enumerate(outcomes)]
        queue = pending(h)
        self.assertEqual(len(queue), MAX_PENDING)
        self.assertEqual(queue[0]["kind"], "SUMMARY")
        self.assertEqual(queue[0]["count"], 3)              # 11th and 12th event folded in with the 1st oldest
        self.assertEqual(sum(e.get("count", 1) for e in queue), 12)
        self.assertEqual((queue[0]["first_slot"], queue[0]["slot"]), ("2026-11-20T03:00:00Z", "2026-11-20T05:00:00Z"))
        self.assertEqual([o["heartbeat"] for o in outs], [False] * 12)
        # SNS comes back: the summary and every remaining event are mailed, nothing was dropped
        h.publish_error = None
        out = h.run_slot(12 * STEP, PASS)
        self.assertEqual((out["notify_sent"], out["heartbeat"], pending(h)), (MAX_PENDING, True, []))
        self.assertEqual(kinds(h)[0], "SUMMARY")
        summary_subject, summary_body = h.sent[0]
        self.assertIn("3件", summary_body)
        self.assertIn("2026-11-20T03:00:00Z", summary_body)
        self.assertEqual(len(h.sent) - 1 + queue[0]["count"], 12)

    def test_a_queue_at_the_limit_is_not_folded_until_the_next_event_arrives(self):
        h = Harness(notify=True)
        h.publish_error = RuntimeError("sns down")
        for i, outcome in enumerate([FAIL, PASS] * (MAX_PENDING // 2)):
            h.run_slot(i * STEP, outcome)
        self.assertEqual([e["kind"] for e in pending(h)].count("SUMMARY"), 0)
        self.assertEqual(len(pending(h)), MAX_PENDING)

    def test_an_unreadable_queue_is_replaced_by_a_visible_summary_not_dropped_silently(self):
        h = Harness(notify=True)
        h.run_slot(0, PASS)
        h.head()["ntf_pending"] = {"S": "{not json"}
        out = h.run_slot(STEP, FAIL)
        self.assertEqual(kinds(h), ["SUMMARY", "FAIL"])
        self.assertIn("不明", h.sent[0][1])
        self.assertEqual((out["notify_sent"], out["heartbeat"]), (2, True))

    def test_publish_succeeded_but_the_sent_mark_failed_means_a_duplicate_never_a_loss(self):
        h = Harness(notify=True)
        h.run_slot(0, PASS)
        # update_item calls of slot 1: claim, result, observe, then the pending mark
        h.dynamo.faults.fail("update_item", TimeoutError("ddb"), skip=3)
        out = h.run_slot(STEP, FAIL)
        self.assertEqual((len(h.sent), out["heartbeat"], out["notify_reason"]),
                         (1, False, "PENDING_UNCERTAIN"))
        out = h.run_slot(2 * STEP, FAIL)
        self.assertEqual((kinds(h), out["heartbeat"]), (["FAIL", "FAIL"], True))   # duplicate, accepted
        self.assertEqual(pending(h), [])

    def test_observation_write_failure_sends_nothing_and_no_heartbeat(self):
        h = Harness(notify=True)
        h.dynamo.faults.fail("update_item", TimeoutError("ddb"), skip=2)
        out = h.run_slot(0, FAIL)
        self.assertEqual((h.sent, out["heartbeat"], out["notify_reason"]),
                         ([], False, "OBSERVE_UNCERTAIN"))
        self.assertTrue(out["persisted"])           # the HTTP result itself was stored

    def test_unpersisted_result_neither_notifies_nor_sends_a_heartbeat(self):
        h = Harness(notify=True)
        h.dynamo.faults.fail("update_item", TimeoutError("ddb"), skip=1)
        out = h.run_slot(0, FAIL)
        self.assertEqual((out["persisted"], h.sent, out["heartbeat"]), (False, [], False))
        self.assertNotIn("obs_state", h.head())


class NoNotificationWhenStoppedOrExpired(unittest.TestCase):
    def test_duplicate_slot_sends_nothing_and_no_heartbeat(self):
        h = Harness(notify=True)
        h.run_slot(0, FAIL)
        out = h.run_slot(0)
        self.assertEqual((out["reason"], kinds(h), "_aws" in h.lines[-1]),
                         ("DUPLICATE_SLOT", ["FAIL"], False))

    def test_stopped_before_the_run(self):
        h = Harness(notify=True)
        h.stop()
        out = h.run_slot(0, FAIL)
        self.assertEqual((out["reason"], h.sent, "_aws" in h.lines[-1]), ("STOPPED", [], False))

    def test_old_generation_event(self):
        h = Harness(notify=True)
        h.stop()
        h.dynamo.items[("CONTROL#preview", "HEAD")]["enabled"] = {"BOOL": True}   # re-armed, generation 2
        h.outcome = FAIL
        h.now = at(1)
        out = h.invoke(event(0, generation=1))
        self.assertEqual((out["reason"], h.sent), ("GENERATION_MISMATCH", []))

    def test_stop_during_the_probe_silences_the_notification(self):
        h = Harness(notify=True, outcome=FAIL)
        original = h._probe

        def probe_then_stop(deadline):
            result = original(deadline)
            h.stop()
            return result
        h._probe = probe_then_stop
        out = h.run_slot(0)
        self.assertEqual((out["notify_reason"], h.sent, out["heartbeat"]),
                         ("OBSERVE_NOT_OWNED", [], False))
        self.assertNotIn("obs_state", h.head())

    def test_a_newer_claim_during_the_run_silences_the_older_attempt(self):
        h = Harness(notify=True, outcome=FAIL)
        original = h._probe

        def probe_then_newer_claim(deadline):
            result = original(deadline)
            h.dynamo.items[("CONTROL#preview", "HEAD")]["last_attempt_id"] = {"S": "newer"}
            return result
        h._probe = probe_then_newer_claim
        out = h.run_slot(0)
        self.assertEqual((out["notify_reason"], h.sent), ("OBSERVE_NOT_OWNED", []))

    def test_run_that_crosses_the_absolute_end_keeps_the_event_unsent(self):
        h = Harness(notify=True, outcome=FAIL)
        original = h._probe

        def probe_past_end(deadline):
            result = original(deadline)
            h.now = h.config.absolute_end_at
            return result
        h._probe = probe_past_end
        out = h.run_slot(0)
        self.assertEqual((out["notify_reason"], h.sent, out["heartbeat"]),
                         ("PAST_ABSOLUTE_END", [], False))
        self.assertEqual(len(pending(h)), 1)

    def test_stop_after_the_first_queued_send_stops_the_second_send(self):
        h = Harness(notify=True)
        h.run_slot(0, PASS)
        h.publish_error = RuntimeError("sns down")
        h.run_slot(STEP, FAIL)                       # one queued event
        h.publish_error = None
        sends = h._publish

        def publish_then_stop(subject, message):
            sends(subject, message)
            h.stop()
        h._publish = publish_then_stop
        out = h.run_slot(2 * STEP, PASS)             # queue: FAIL, RECOVERY
        self.assertEqual((kinds(h), out["notify_reason"], out["heartbeat"]),
                         (["FAIL"], "PENDING_NOT_OWNED", False))


class ConfigurationAndCompatibility(unittest.TestCase):
    def test_topic_and_group_are_validated_and_optional(self):
        config = MonitorConfig.from_env(ENV)
        self.assertEqual((config.alert_topic_arn, config.monitor_group), (None, "siteproof-b"))
        topic = "arn:aws:sns:us-east-1:123456789012:siteproof-b-alerts"
        self.assertEqual(MonitorConfig.from_env({**ENV, "ALERT_TOPIC_ARN": topic}).alert_topic_arn, topic)
        for bad in ({"ALERT_TOPIC_ARN": "arn:aws:sqs:us-east-1:123456789012:q"},
                    {"MONITOR_GROUP": "bad group"}):
            with self.assertRaises(Exception):
                MonitorConfig.from_env({**ENV, **bad})

    def test_without_a_topic_the_probe_still_records_and_heartbeats(self):
        h = Harness()
        out = h.invoke(event())
        self.assertEqual((out["notify_reason"], out["heartbeat"]), ("NOTIFY_DISABLED", True))
        self.assertNotIn("obs_state", h.head())

    def test_claim_asks_for_head_back_so_the_probe_role_needs_no_read_permission(self):
        claim = Claim("preview", "h.example.org", "p1", 1, "2026-11-20T03:00:00Z", "k", "a", "t", 1)
        self.assertEqual(build_claim_request("t", claim)["ReturnValues"], "ALL_NEW")


def sliding_alarm(counts_by_period, expected, datapoints=2, periods=3):
    """CloudWatch-like M-of-N evaluation, newest period last. None = no data = breaching."""
    window = counts_by_period[-periods:]
    breaching = sum(1 for c in window if c is None or c < expected)
    return breaching >= datapoints


class HeartbeatAlarmModel(unittest.TestCase):
    """A model of the health alarm (Sum < pages, 2 of 3 periods, missing = breaching), NOT AWS behaviour.

    Heartbeats are stamped with the slot and the period equals the schedule interval, so a sliding
    window of one period holds one heartbeat per page. The model states what the design does and
    does not detect; real CloudWatch evaluation stays LIVE-unverified.
    """
    PAGES = 5

    def test_healthy_pages_never_alarm_even_while_the_newest_window_is_short(self):
        self.assertFalse(sliding_alarm([5, 5, 5], self.PAGES))
        # the newest window briefly lacks a page's datapoint (slot leaving / next one not ingested yet)
        self.assertFalse(sliding_alarm([5, 5, 4], self.PAGES))

    def test_one_page_missing_for_two_consecutive_runs_alarms(self):
        self.assertTrue(sliding_alarm([5, 4, 4], self.PAGES))

    def test_known_limit_a_single_isolated_missed_run_is_tolerated(self):
        self.assertFalse(sliding_alarm([5, 4, 5], self.PAGES))

    def test_one_heartbeat_per_slot_even_when_the_event_is_delivered_many_times(self):
        h = Harness(notify=True)
        for _ in range(4):
            h.run_slot(0, PASS)
        h.run_slot(STEP)
        self.assertEqual(sum("_aws" in line for line in h.lines), 2)     # slots 0 and STEP only

    def test_every_page_silent_alarms_because_missing_data_is_breaching(self):
        self.assertTrue(sliding_alarm([None, None, None], self.PAGES))

    def test_planned_stop_alarms_unless_alarm_actions_are_disabled_by_the_stopper(self):
        self.assertTrue(sliding_alarm([5, None, None], self.PAGES))

    def test_heartbeat_is_the_group_metric_of_completed_runs_never_lambda_invocations(self):
        h = Harness(notify=True)
        completed = h.run_slot(0, PASS)
        rejected = h.run_slot(0)
        directive = h.lines[0]["_aws"]["CloudWatchMetrics"][0]
        self.assertEqual((completed["heartbeat"], "heartbeat" in rejected), (True, False))
        self.assertEqual((directive["Namespace"], directive["Dimensions"]),
                         ("SiteProof/Monitor", [["MonitorGroup"]]))


if __name__ == "__main__":
    unittest.main()
