"""Mutation checks: weakening the claim condition must make a safety property observable.

Each case removes one clause from the real ConditionExpression and shows that the
corresponding unsafe behaviour (probe after stop, double probe, stale generation,
out-of-order probe) then actually happens in the offline harness. This guards against
behaviour tests that would pass regardless of the expression.
"""
import unittest
from unittest.mock import patch

import src.aws_b.store as store
from tests.aws_b.support import Harness, event

ORIGINAL = store.build_claim_request


def weakened(old, new, drop_names=(), drop_values=()):
    def build(table, claim):
        request = ORIGINAL(table, claim)
        assert old in request["ConditionExpression"]
        request["ConditionExpression"] = request["ConditionExpression"].replace(old, new)
        for name in drop_names:
            request["ExpressionAttributeNames"].pop(name)
        for name in drop_values:
            request["ExpressionAttributeValues"].pop(name)
        return request
    return build


class ClaimMutations(unittest.TestCase):
    def test_without_enabled_clause_a_racing_stop_no_longer_prevents_the_probe(self):
        build = weakened("#en = :true AND ", "", ("#en",), (":true",))
        with patch.object(store, "build_claim_request", build):
            h = Harness()
            h.dynamo.items[("CONTROL#preview", "HEAD")]["enabled"] = {"BOOL": False}
            self.assertEqual(h.invoke(event())["decision"], "PROBED")
        h = Harness()
        h.dynamo.items[("CONTROL#preview", "HEAD")]["enabled"] = {"BOOL": False}
        self.assertEqual(h.invoke(event())["reason"], "STOPPED")

    def test_without_strict_slot_order_a_duplicate_reaches_the_run_record_guard(self):
        build = weakened("#ls < :slot", "#ls <= :slot")
        with patch.object(store, "build_claim_request", build):
            h = Harness()
            h.invoke(event())
            second = h.invoke(event())
            # the second line of defence (create-only run record) still stops the probe
            self.assertEqual((second["reason"], len(h.probes)), ("RUN_RECORD_EXISTS", 1))

    def test_without_generation_clause_an_old_generation_event_probes(self):
        build = weakened("#gen = :gen AND ", "", ("#gen",), (":gen",))
        with patch.object(store, "build_claim_request", build):
            h = Harness(armed=False)
            h.arm(generation=2)
            self.assertEqual(h.invoke(event(generation=1))["decision"], "PROBED")
        h = Harness(armed=False)
        h.arm(generation=2)
        self.assertEqual(h.invoke(event(generation=1))["reason"], "GENERATION_MISMATCH")

    def test_without_order_clause_an_older_slot_probes_after_a_newer_one(self):
        build = weakened(" AND (attribute_not_exists(#ls) OR #ls < :slot)", "")
        with patch.object(store, "build_claim_request", build):
            h = Harness()
            h.now = h.now.replace(second=31)
            h.invoke(event(30))
            self.assertEqual(h.invoke(event(0))["decision"], "PROBED")
            self.assertEqual(len(h.probes), 2)


if __name__ == "__main__":
    unittest.main()
