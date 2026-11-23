"""AWS-B configuration, request-builder and read-projection contracts (offline)."""
import unittest
from datetime import timedelta

from src.aws_b.model import (ConfigError, MonitorConfig, format_utc, logical_run_key,
                             parse_utc)
from src.aws_b.store import (Claim, build_claim_request, build_recent_query,
                             build_result_request, build_run_record_request,
                             build_stop_request, classify_claim_failure)
from src.aws_b.view import summarize
from src.core.model import CheckOutcome
from tests.aws_b.support import ENV, Harness, at, event


def claim(**override):
    fields = dict(target_id="preview", hostname="example.org", policy_version="p1",
                  execution_generation=1, scheduled_slot="2026-11-20T03:00:00Z",
                  logical_run_key="k" * 64, attempt_id="a1",
                  claimed_at="2026-11-20T03:00:01Z", expires_at=1)
    fields.update(override)
    return Claim(**fields)


class Config(unittest.TestCase):
    def test_valid_environment(self):
        config = MonitorConfig.from_env(ENV)
        self.assertEqual((config.hostname, config.path, config.max_event_age_seconds),
                         ("d111111abcdef8.cloudfront.net", "/home/index.html", 60))
        self.assertEqual(config.policy.allowlist[0].port, 443)

    def test_rejects_unsafe_or_ambiguous_values(self):
        bad = [("TARGET_HOSTNAME", "127.0.0.1"), ("TARGET_HOSTNAME", "localhost"),
               ("TARGET_HOSTNAME", "https://example.org"), ("TARGET_HOSTNAME", "ex ample.org"),
               ("TARGET_HOSTNAME", "0x7f.1"), ("TARGET_HOSTNAME", ""),
               ("TARGET_PATH", "home"), ("TARGET_PATH", "/a b"), ("TARGET_PATH", "/a\r\nX: y"),
               ("TARGET_PATH", "/../etc"), ("TARGET_PATH", "/a#frag"), ("TARGET_PATH", "/a?b"),
               ("ABSOLUTE_END_AT", "2026-11-21"), ("ABSOLUTE_END_AT", "2026-11-21T03:00:00+09:00"),
               ("TARGET_ID", "bad id"), ("POLICY_VERSION", ""), ("TABLE_NAME", "x"),
               ("MAX_EVENT_AGE_SECONDS", "0"), ("MAX_EVENT_AGE_SECONDS", "3600"),
               ("MAX_EVENT_AGE_SECONDS", "6e1"), ("PROBE_TIMEOUT_SECONDS", "60"),
               ("RECORD_TTL_DAYS", "-1"), ("METRIC_NAMESPACE", "AWS/Lambda")]
        for name, value in bad:
            with self.subTest(name=name, value=value):
                with self.assertRaises(ConfigError):
                    MonitorConfig.from_env({**ENV, name: value})

    def test_missing_required_values(self):
        for name in ("TARGET_ID", "TARGET_HOSTNAME", "TARGET_PATH", "POLICY_VERSION",
                     "ABSOLUTE_END_AT", "TABLE_NAME"):
            env = {k: v for k, v in ENV.items() if k != name}
            with self.subTest(name=name), self.assertRaises(ConfigError):
                MonitorConfig.from_env(env)

    def test_time_format_round_trip_and_ordering(self):
        self.assertEqual(format_utc(parse_utc("2026-11-20T03:00:00Z")), "2026-11-20T03:00:00Z")
        slots = [format_utc(at(s)) for s in (0, 59, 60, 3600, 86400, 86400 * 45)]
        self.assertEqual(slots, sorted(slots))            # text order == time order
        for bad in ("2026-11-20T03:00:00.000Z", "2026-11-20T03:00:00", "", None, 5):
            self.assertIsNone(parse_utc(bad))

    def test_logical_run_key_changes_with_every_component(self):
        base = logical_run_key("t", "2026-11-20T03:00:00Z", "p1", 1)
        self.assertEqual(base, logical_run_key("t", "2026-11-20T03:00:00Z", "p1", 1))
        others = {logical_run_key("u", "2026-11-20T03:00:00Z", "p1", 1),
                  logical_run_key("t", "2026-11-20T03:05:00Z", "p1", 1),
                  logical_run_key("t", "2026-11-20T03:00:00Z", "p2", 1),
                  logical_run_key("t", "2026-11-20T03:00:00Z", "p1", 2)}
        self.assertEqual(len(others | {base}), 5)


class RequestBuilders(unittest.TestCase):
    def test_claim_is_one_conditional_update_on_the_control_item(self):
        request = build_claim_request("tbl", claim())
        self.assertEqual(request["Key"], {"pk": {"S": "CONTROL#preview"}, "sk": {"S": "HEAD"}})
        condition = request["ConditionExpression"]
        for clause in ("attribute_exists(#pk)", "#en = :true", "#gen = :gen", "#pv = :pv",
                       "#host = :host", "(attribute_not_exists(#ls) OR #ls < :slot)"):
            self.assertIn(clause, condition)
        self.assertEqual(condition.count(" AND "), 5)
        self.assertNotIn("<=", condition)                 # equal slot must fail (duplicate)
        self.assertEqual(request["ReturnValuesOnConditionCheckFailure"], "ALL_OLD")
        self.assertEqual(request["ExpressionAttributeNames"]["#en"], "enabled")

    def test_run_record_is_create_only_and_result_requires_owner(self):
        record = build_run_record_request("tbl", claim())
        self.assertEqual(record["ConditionExpression"], "attribute_not_exists(#pk)")
        self.assertEqual(record["Item"]["state"], {"S": "CLAIMED"})
        result = build_result_request("tbl", claim(), {
            "outcome": "PASS", "reason": "HTTP_200", "finished_at": "2026-11-20T03:00:02Z",
            "http_status": 200, "selected_ip": None, "tls_not_after": None, "elapsed_ms": 5})
        self.assertEqual(result["ConditionExpression"], "#state = :claimed AND #attempt = :attempt")
        self.assertNotIn(":selected_ip", result["ExpressionAttributeValues"])
        self.assertEqual(result["ExpressionAttributeValues"][":http_status"], {"N": "200"})

    def test_stop_disables_and_bumps_generation_atomically(self):
        request = build_stop_request("tbl", target_id="preview", expected_generation=3,
                                     stopped_at="2026-11-20T03:00:00Z")
        self.assertEqual(request["ExpressionAttributeValues"][":next"], {"N": "4"})
        self.assertEqual(request["ExpressionAttributeValues"][":false"], {"BOOL": False})
        self.assertIn("#gen = :gen", request["ConditionExpression"])

    def test_no_builder_deletes_or_scans(self):
        requests = [build_claim_request("t", claim()), build_run_record_request("t", claim()),
                    build_recent_query("t", "preview")]
        for request in requests:
            text = str(request)
            self.assertNotIn("REMOVE", text)
            self.assertNotIn("DELETE", text)
        self.assertTrue(build_recent_query("t", "preview")["ConsistentRead"])
        self.assertFalse(build_recent_query("t", "preview")["ScanIndexForward"])

    def test_claim_failure_classification(self):
        armed = {"enabled": {"BOOL": True}, "execution_generation": {"N": "1"},
                 "policy_version": {"S": "p1"}, "target_hostname": {"S": "example.org"}}
        cases = [(None, "NOT_ARMED"), ({}, "NOT_ARMED"),
                 ({**armed, "enabled": {"BOOL": False}}, "STOPPED"),
                 ({k: v for k, v in armed.items() if k != "enabled"}, "STOPPED"),
                 ({**armed, "execution_generation": {"N": "2"}}, "GENERATION_MISMATCH"),
                 ({**armed, "policy_version": {"S": "p9"}}, "POLICY_MISMATCH"),
                 ({**armed, "target_hostname": {"S": "x.org"}}, "TARGET_MISMATCH"),
                 ({**armed, "last_slot": {"S": "2026-11-20T03:00:00Z"}}, "DUPLICATE_SLOT"),
                 ({**armed, "last_slot": {"S": "2026-11-20T03:05:00Z"}}, "OLDER_SLOT"),
                 (armed, "CLAIM_CONDITION_FAILED"),
                 ({"enabled": "malformed"}, "CLAIM_CONDITION_FAILED")]
        for old, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(classify_claim_failure(old, claim()), expected)


class View(unittest.TestCase):
    def _state(self, harness, seconds_later=10, **kwargs):
        runs = harness.store.recent_runs("preview")
        return summarize(harness.store.head("preview"), runs,
                         now=harness.now + timedelta(seconds=seconds_later),
                         interval_seconds=300, **kwargs)

    def test_fresh_recorded_pass_is_up(self):
        h = Harness()
        h.invoke(event())
        self.assertEqual(self._state(h)["state"], "UP")

    def test_fail_is_down_and_unknown_is_unknown(self):
        h = Harness(outcome=(CheckOutcome.FAIL, "HTTP_503", 503))
        h.invoke(event())
        self.assertEqual((self._state(h)["state"], self._state(h)["reason"]), ("DOWN", "HTTP_503"))
        h = Harness(outcome=(CheckOutcome.UNKNOWN, "DNS_ERROR", None))
        h.invoke(event())
        self.assertEqual(self._state(h)["state"], "UNKNOWN")

    def test_no_observation_is_unknown(self):
        self.assertEqual(self._state(Harness()), {
            "armed": True, "observed_slot": None, "reason": "NO_OBSERVATION",
            "state": "UNKNOWN"})

    def test_claimed_without_result_is_unknown_never_up(self):
        h = Harness()
        h.dynamo.faults.fail("update_item", TimeoutError(), skip=1)
        h.invoke(event())
        self.assertEqual((self._state(h)["state"], self._state(h)["reason"]),
                         ("UNKNOWN", "RESULT_NOT_RECORDED"))

    def test_old_up_becomes_stale_when_monitor_goes_silent(self):
        h = Harness()
        h.invoke(event())
        self.assertEqual(self._state(h, seconds_later=899)["state"], "UP")
        self.assertEqual(self._state(h, seconds_later=901)["state"], "STALE")

    def test_stopped_monitor_never_shows_up(self):
        h = Harness()
        h.invoke(event())
        h.stop()
        self.assertEqual(self._state(h)["state"], "STOPPED")
        self.assertFalse(self._state(h)["armed"])

    def test_newest_slot_decides_regardless_of_item_order(self):
        h = Harness()
        h.invoke(event(0))
        h.outcome = (CheckOutcome.FAIL, "HTTP_500", 500)
        h.now = at(31)
        h.invoke(event(30))
        runs = h.store.recent_runs("preview")
        for ordering in (runs, list(reversed(runs))):
            state = summarize(h.store.head("preview"), ordering, now=at(40), interval_seconds=300)
            self.assertEqual((state["state"], state["observed_slot"]),
                             ("DOWN", "2026-11-20T03:00:30Z"))

    def test_malformed_items_do_not_become_up(self):
        head = {"enabled": {"BOOL": True}}
        junk = [{"sk": {"S": "not-a-time"}, "state": {"S": "RECORDED"}, "outcome": {"S": "PASS"}},
                {"sk": "2026-11-20T03:00:00Z"}, {}]
        self.assertEqual(summarize(head, junk, now=at(5), interval_seconds=300)["state"], "UNKNOWN")
        odd = [{"sk": {"S": "2026-11-20T03:00:00Z"}, "state": {"S": "WEIRD"}, "outcome": {"S": "PASS"}}]
        self.assertEqual(summarize(head, odd, now=at(5), interval_seconds=300)["reason"],
                         "RECORD_STATE_INVALID")


if __name__ == "__main__":
    unittest.main()
