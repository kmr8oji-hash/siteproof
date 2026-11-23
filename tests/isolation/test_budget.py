"""In-memory counters and fake monotonic time only; no real network."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import unittest

from src.isolation.budget import BudgetLimits, NetworkBudget


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.limits = BudgetLimits(10, 2, 2, 3, 10)

    def make(self, *, attempt=None, tunnel=None):
        budget = NetworkBudget(attempt or self.limits, tunnel or self.limits, clock=self.clock)
        self.assertTrue(budget.open_tunnel("t1").allowed)
        return budget

    def connection(self, budget, tunnel="t1"):
        decision = budget.begin_connection(tunnel)
        self.assertTrue(decision.allowed)
        self.assertTrue(budget.connected(decision.connection_id).allowed)
        return decision.connection_id

    def test_send_and_receive_sum_at_limit_then_one_over(self):
        budget = self.make()
        connection = self.connection(budget)
        self.assertTrue(budget.transfer(connection, sent=4, received=6).allowed)
        self.assertEqual(budget.snapshot().total_bytes, 10)
        self.assertEqual(budget.snapshot("t1").total_bytes, 10)
        decision = budget.transfer(connection, received=1)
        self.assertEqual((decision.allowed, decision.scope, decision.reason),
                         (False, "attempt", "TOTAL_BYTES_LIMIT"))
        self.assertEqual(budget.snapshot().total_bytes, 10)
        self.assertEqual(budget.snapshot().concurrent_connections, 0)
        self.assertFalse(budget.poll().allowed)

    def test_tunnel_byte_limit_terminates_only_that_tunnel(self):
        budget = self.make(attempt=replace(self.limits, total_bytes=100))
        budget.open_tunnel("t2")
        c1, c2 = self.connection(budget), self.connection(budget, "t2")
        self.assertTrue(budget.transfer(c1, sent=10).allowed)
        self.assertEqual(budget.transfer(c1, sent=1).scope, "t1")
        self.assertTrue(budget.poll().allowed)
        self.assertTrue(budget.transfer(c2, received=1).allowed)
        self.assertEqual(budget.snapshot().concurrent_connections, 1)

    def test_attempt_bytes_accumulate_across_tunnels(self):
        budget = self.make()
        budget.open_tunnel("t2")
        c1, c2 = self.connection(budget), self.connection(budget, "t2")
        budget.transfer(c1, sent=5)
        budget.transfer(c2, received=5)
        self.assertFalse(budget.transfer(c2, sent=1).allowed)
        self.assertEqual(budget.snapshot("t1").total_bytes, 5)
        self.assertEqual(budget.snapshot("t2").total_bytes, 5)
        self.assertEqual(budget.snapshot("t1").termination, "TOTAL_BYTES_LIMIT")
        self.assertEqual(budget.snapshot("t2").concurrent_connections, 0)

    def test_cumulative_connections_exact_then_one_over(self):
        budget = self.make()
        for _ in range(2):
            connection = self.connection(budget)
            budget.close_connection(connection)
        self.assertEqual(budget.snapshot().total_connections, 2)
        result = budget.begin_connection("t1")
        self.assertEqual(result.reason, "TOTAL_CONNECTIONS_LIMIT")
        self.assertEqual(budget.snapshot().total_connections, 2)
        self.assertEqual(budget.snapshot().concurrent_connections, 0)

    def test_tunnel_cumulative_connection_limit(self):
        budget = self.make(attempt=replace(self.limits, total_connections=10))
        for _ in range(2):
            budget.close_connection(self.connection(budget))
        self.assertEqual(budget.begin_connection("t1").scope, "t1")
        self.assertIsNone(budget.snapshot().termination)

    def test_concurrency_includes_pending_and_exact_then_one_over(self):
        budget = self.make()
        budget.begin_connection("t1")
        self.connection(budget)
        self.assertEqual(budget.snapshot().concurrent_connections, 2)
        result = budget.begin_connection("t1")
        self.assertEqual(result.reason, "CONCURRENT_CONNECTIONS_LIMIT")
        self.assertEqual(budget.snapshot().concurrent_connections, 0)
        self.assertEqual(budget.snapshot().connection_attempts, 2)

    def test_tunnel_concurrency_limit_releases_only_its_connections(self):
        budget = self.make(attempt=replace(self.limits, concurrent_connections=10,
                                         connection_attempts=10, total_connections=10),
                           tunnel=replace(self.limits, total_connections=10))
        budget.open_tunnel("t2")
        budget.begin_connection("t2")
        budget.begin_connection("t1")
        budget.begin_connection("t1")
        self.assertEqual(budget.begin_connection("t1").scope, "t1")
        self.assertEqual(budget.snapshot().concurrent_connections, 1)
        self.assertTrue(budget.poll("t2").allowed)

    def test_attempt_concurrency_aggregates_tunnels(self):
        budget = self.make()
        budget.open_tunnel("t2")
        budget.begin_connection("t1")
        budget.begin_connection("t2")
        result = budget.begin_connection("t2")
        self.assertEqual(result.scope, "attempt")
        self.assertEqual(result.reason, "CONCURRENT_CONNECTIONS_LIMIT")

    def test_attempt_count_includes_failed_connections_exact_then_one_over(self):
        budget = self.make()
        for _ in range(3):
            pending = budget.begin_connection("t1")
            self.assertTrue(pending.allowed)
            budget.close_connection(pending.connection_id)
        self.assertEqual(budget.snapshot().connection_attempts, 3)
        self.assertEqual(budget.snapshot().total_connections, 0)
        self.assertEqual(budget.begin_connection("t1").reason, "CONNECTION_ATTEMPTS_LIMIT")

    def test_tunnel_attempt_limit(self):
        budget = self.make(attempt=replace(self.limits, connection_attempts=10))
        for _ in range(3):
            budget.close_connection(budget.begin_connection("t1").connection_id)
        self.assertEqual(budget.begin_connection("t1").scope, "t1")
        self.assertIsNone(budget.snapshot().termination)

    def test_attempt_count_aggregates_tunnels(self):
        budget = self.make()
        budget.open_tunnel("t2")
        for tunnel in ("t1", "t2", "t1"):
            pending = budget.begin_connection(tunnel)
            budget.close_connection(pending.connection_id)
        self.assertEqual(budget.begin_connection("t2").scope, "attempt")
        self.assertEqual(budget.snapshot("t1").connection_attempts, 2)

    def test_deadline_before_exact_and_after_boundary(self):
        for now, allowed in ((9.999, True), (10, False), (10.001, False)):
            with self.subTest(now=now):
                self.clock.now = 0
                budget = self.make()
                self.clock.now = now
                self.assertEqual(budget.poll("t1").allowed, allowed)
                if not allowed:
                    self.assertEqual(budget.snapshot().termination, "DEADLINE")

    def test_tunnel_deadline_and_idle_reservations(self):
        budget = self.make(attempt=replace(self.limits, duration_seconds=30))
        budget.begin_connection("t1")
        self.clock.now = 5
        budget.open_tunnel("t2")
        budget.begin_connection("t2")
        self.clock.now = 10
        self.assertTrue(budget.poll().allowed)
        self.assertEqual(budget.snapshot("t1").termination, "DEADLINE")
        self.assertEqual(budget.snapshot().concurrent_connections, 1)
        self.assertTrue(budget.poll("t2").allowed)
        self.clock.now = 15
        self.assertEqual(budget.poll("t2").reason, "DEADLINE")

    def test_release_is_idempotent_and_does_not_reset_totals(self):
        budget = self.make()
        connection = self.connection(budget)
        budget.transfer(connection, sent=3)
        budget.close_connection(connection)
        self.assertEqual(budget.close_connection(connection).reason, "ALREADY_CLOSED")
        state = budget.snapshot()
        self.assertEqual((state.total_bytes, state.total_connections,
                          state.concurrent_connections, state.connection_attempts), (3, 1, 0, 1))

    def test_terminal_state_cannot_be_reset(self):
        budget = self.make()
        self.clock.now = 10
        self.assertFalse(budget.poll().allowed)
        self.assertFalse(budget.open_tunnel("t2").allowed)
        self.assertFalse(budget.begin_connection("t1").allowed)
        with self.assertRaises(ValueError):
            budget.open_tunnel("t1")

    def test_zero_limits_deny_nonzero_events(self):
        for field in ("total_bytes", "total_connections", "concurrent_connections",
                      "connection_attempts"):
            with self.subTest(field=field):
                budget = self.make(attempt=replace(self.limits, **{field: 0}))
                if field in ("concurrent_connections", "connection_attempts", "total_connections"):
                    result = budget.begin_connection("t1")
                else:
                    pending = budget.begin_connection("t1")
                    result = budget.connected(pending.connection_id)
                    if field == "total_bytes":
                        self.assertTrue(budget.transfer(pending.connection_id).allowed)
                        result = budget.transfer(pending.connection_id, sent=1)
                self.assertEqual(result.reason, field.upper() + "_LIMIT")

    def test_invalid_configuration_is_rejected(self):
        for field in ("total_bytes", "total_connections", "concurrent_connections",
                      "connection_attempts"):
            for value in (-1, True, 1.5, "2", None):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    replace(self.limits, **{field: value})
        for value in (0, -1, True, float("nan"), float("inf"), None, 10 ** 1000):
            with self.subTest(duration=value), self.assertRaises(ValueError):
                replace(self.limits, duration_seconds=value)
        with self.assertRaises(ValueError):
            NetworkBudget(None, self.limits)

    def test_invalid_transfer_cannot_decrement_or_coerce_counters(self):
        budget = self.make()
        connection = self.connection(budget)
        for kwargs in ({"sent": -1}, {"received": True}, {"sent": 1.0}, {"received": "2"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                budget.transfer(connection, **kwargs)
        self.assertEqual(budget.snapshot().total_bytes, 0)

    def test_connection_lifecycle_misuse(self):
        budget = self.make()
        pending = budget.begin_connection("t1")
        with self.assertRaises(ValueError):
            budget.transfer(pending.connection_id, sent=1)
        budget.connected(pending.connection_id)
        with self.assertRaises(ValueError):
            budget.connected(pending.connection_id)
        with self.assertRaises(ValueError):
            budget.connected(True)
        with self.assertRaises(ValueError):
            budget.begin_connection("unknown")
        for name in ("", "attempt", "t1", 123):
            with self.subTest(name=name), self.assertRaises(ValueError):
                budget.open_tunnel(name)

    def test_invalid_or_regressing_clock_fails_closed(self):
        for value in (-1, float("nan"), float("inf"), None, True, 10 ** 1000):
            with self.subTest(value=value):
                self.clock.now = 0
                budget = self.make()
                self.clock.now = value
                self.assertEqual(budget.poll().reason, "INVALID_CLOCK")
                self.assertEqual(budget.snapshot().termination, "INVALID_CLOCK")

    def test_pending_connections_reserve_cumulative_capacity_before_connect(self):
        limits = replace(self.limits, total_connections=2, concurrent_connections=10,
                         connection_attempts=10)
        budget = self.make(attempt=limits, tunnel=limits)
        budget.open_tunnel("t2")
        self.assertTrue(budget.begin_connection("t1").allowed)
        self.assertTrue(budget.begin_connection("t2").allowed)
        result = budget.begin_connection("t1")
        self.assertFalse(result.allowed)
        self.assertEqual((result.scope, result.reason), ("attempt", "TOTAL_CONNECTIONS_LIMIT"))
        self.assertEqual(budget.snapshot().total_connections, 0)

    def test_failed_pending_attempt_releases_cumulative_reservation(self):
        limits = replace(self.limits, total_connections=1)
        budget = self.make(attempt=limits, tunnel=limits)
        pending = budget.begin_connection("t1")
        budget.close_connection(pending.connection_id)
        connection = self.connection(budget)
        self.assertEqual(budget.snapshot().total_connections, 1)
        self.assertEqual(budget.snapshot().connection_attempts, 2)
        budget.close_connection(connection)

    def test_atomic_shared_attempt_byte_accounting(self):
        limits = BudgetLimits(100, 1, 1, 1, 10)
        budget = self.make(attempt=limits, tunnel=limits)
        connection = self.connection(budget)
        with ThreadPoolExecutor(max_workers=4) as pool:
            decisions = list(pool.map(lambda _: budget.transfer(connection, sent=1), range(100)))
        self.assertTrue(all(decision.allowed for decision in decisions))
        self.assertEqual(budget.snapshot().total_bytes, 100)
        self.assertEqual(budget.snapshot("t1").total_bytes, 100)
        self.assertFalse(budget.transfer(connection, sent=1).allowed)
