"""Offline cooperative deadlines, publication and ownership interleavings."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier
import unittest

from src.isolation.budget import BudgetLimits, NetworkBudget
from src.isolation.connect_dns import DnsLimits
from src.isolation.destination import AllowedDestination, DestinationPolicy
from src.isolation.quota_session import IoLimits, IoWouldBlock, QuotaSession
from src.isolation.termination import TerminationLimits
from tests.isolation import test_quota_session as fakes


class TerminationTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.clock_calls = 0
        self.config = BudgetLimits(100, 10, 10, 20, 100)
        self.budget = NetworkBudget(self.config, self.config, clock=self.clock)
        self.session = QuotaSession("job", self.budget, IoLimits(6, 12),
                                    termination_limits=TerminationLimits(10, 5))
        self.session.open_tunnel("a")
        self.session.open_tunnel("b")
        self.policy = DestinationPolicy((AllowedDestination("example.com", 443),))
        self.handle = fakes.FakeStream()

    def clock(self):
        self.clock_calls += 1
        return self.now

    def connect(self, dialer=None, tunnel="a", handle=None):
        return self.session.connect(tunnel, self.policy, "example.com", ("8.8.8.8",),
                                    dialer=dialer or (lambda *args: handle or self.handle))

    def ready(self):
        result = self.connect()
        self.assertTrue(result.allowed)
        return result.connection_id

    def target(self, resolve, dialer=None):
        resolver = fakes.Resolver()
        resolver.resolve_complete = resolve
        return self.session.connect_target("a", self.policy, b"example.com:443",
                                           resolver=resolver, dialer=dialer or (lambda *a: self.handle),
                                           limits=DnsLimits(2, 100))

    def resolution(self, hostname):
        return fakes.Resolver().resolve_complete(hostname)

    def state(self, expected):
        snap = self.session.termination_snapshot()
        self.assertEqual(snap.state, expected)
        return snap

    blocked = fakes.QuotaTests.blocked

    def test_timeout_configuration_requires_explicit_positive_finite_values(self):
        for value in (0, -1, True, None, "5", float("inf"), float("nan"), 10 ** 400):
            for args in ((value, 5), (10, value)):
                with self.subTest(args=args), self.assertRaises(ValueError):
                    TerminationLimits(*args)
        with self.assertRaises(TypeError):
            TerminationLimits()

    def test_invalid_configuration_does_not_claim_budget_owner(self):
        budget = NetworkBudget(self.config, self.config, clock=self.clock)
        with self.assertRaises(ValueError):
            QuotaSession("job", budget, IoLimits(1, 1), termination_limits={})
        self.assertIsNone(getattr(budget, "_session_owner", None))

    def test_job_deadline_exact_boundary_uses_original_budget_origin(self):
        self.now = 99
        self.assertIsNone(self.session.check_termination())
        self.now = 100
        self.assertEqual(self.session.check_termination(), "DEADLINE")
        self.state("CLOSED")

    def test_tunnel_absolute_lifetime_boundary_is_not_reset_by_io(self):
        self.budget._tunnel_limits = replace(self.config, duration_seconds=6)
        cid = self.ready()
        self.now = 4
        self.session.write(cid, b"x")
        self.now = 5.999
        self.assertIsNone(self.session.check_termination())
        self.now = 6
        self.assertEqual(self.session.check_termination(), "DEADLINE")

    def test_connection_timeout_before_boundary_allows_publication(self):
        def dial(*args):
            self.now = 9.999
            return self.handle
        self.assertTrue(self.connect(dial).allowed)
        self.assertEqual(self.session._connections[1].last_progress, 9.999)

    def test_connection_timeout_at_dial_boundary_hides_and_closes_late_handle(self):
        def dial(*args):
            self.now = 10
            return self.handle
        result = self.connect(dial)
        self.assertEqual(result.reason, "CONNECTION_TIMEOUT")
        self.assertIsNone(result.result)
        self.assertEqual(self.handle.events.count(("close",)), 1)
        self.assertEqual(self.budget.snapshot().total_connections, 1)
        self.state("CLOSED")

    def test_dns_timeout_keeps_pending_until_return_and_suppresses_dial(self):
        def inspect():
            self.now = 10
            self.assertEqual(self.session.check_termination(), "CONNECTION_TIMEOUT")
            snap = self.state("STOPPING")
            self.assertEqual((snap.pending_connects, snap.occupied_connections), (1, 0))
            self.session.run_cleanup()
            self.state("STOPPING")
        result = self.blocked(lambda pause: self.target(pause, fakes.raises(AssertionError())),
                              inspect, self.resolution)
        self.assertEqual(result.reason, "CONNECTION_TIMEOUT")
        self.assertEqual(self.budget.snapshot().connection_attempts, 0)
        self.state("CLOSED")

    def test_late_dns_without_poll_rechecks_before_dial(self):
        def resolve(host):
            self.now = 10
            return self.resolution(host)
        result = self.target(resolve, fakes.raises(AssertionError("must not dial")))
        self.assertEqual(result.reason, "CONNECTION_TIMEOUT")
        self.assertEqual(self.budget.snapshot().connection_attempts, 0)

    def test_dns_job_deadline_boundary(self):
        def resolve(host):
            self.now = 100
            return self.resolution(host)
        self.assertEqual(self.target(resolve).reason, "DEADLINE")
        self.assertEqual(self.budget.snapshot().connection_attempts, 0)

    def test_peer_verification_timeout_retains_connector_ownership(self):
        def action(pause):
            self.handle.peer_action = pause
            return self.connect()
        def inspect():
            self.now = 10
            self.session.check_termination()
            self.session.run_cleanup()
            self.assertNotIn(("close",), self.handle.events)
            self.state("STOPPING")
        result = self.blocked(action, inspect, lambda: self.handle.peer)
        self.assertIsNone(result.result)
        self.assertEqual(result.reason, "CONNECTION_TIMEOUT")
        self.assertEqual(self.handle.events.count(("close",)), 1)
        self.state("CLOSED")

    def test_publication_point_rechecks_after_prior_check(self):
        original = self.session._cleanup
        def advance():
            self.now = 10
            original()
        self.session._cleanup = advance
        result = self.connect()
        self.assertFalse(result.allowed)
        self.assertIsNone(result.result)
        self.assertEqual(result.reason, "CONNECTION_TIMEOUT")
        self.state("CLOSED")

    def test_authorization_time_is_included(self):
        def addresses():
            self.now = 10
            return ("8.8.8.8",)
        # Destination validation is injected at the existing call boundary.
        from unittest.mock import patch
        from src.isolation import quota_session
        original = quota_session.connect_pinned
        def authorize(*args, **kwargs):
            addresses()
            return original(*args, **kwargs)
        with patch.object(quota_session, "connect_pinned", authorize):
            self.assertEqual(self.connect().reason, "CONNECTION_TIMEOUT")
        self.assertEqual(self.budget.snapshot().connection_attempts, 0)

    def test_idle_exact_boundary(self):
        self.ready()
        self.now = 4.999
        self.assertIsNone(self.session.check_termination())
        self.now = 5
        self.assertEqual(self.session.check_termination(), "IDLE_TIMEOUT")
        self.state("STOPPING")
        self.assertNotIn(("close",), self.handle.events)
        self.session.run_cleanup()
        self.state("CLOSED")

    def test_idle_starts_at_success_publication(self):
        def dial(*args):
            self.now = 9
            return self.handle
        self.assertTrue(self.connect(dial).allowed)
        self.now = 13.999
        self.assertIsNone(self.session.check_termination())
        self.now = 14
        self.assertEqual(self.session.check_termination(), "IDLE_TIMEOUT")

    def progress(self, operation):
        cid = self.ready()
        if operation == "deliver":
            self.session.read(cid, 4)
        self.now = 4
        if operation == "read":
            self.handle.read_action = lambda n: b"x"
            result = self.session.read(cid, 6)
        elif operation == "write":
            self.handle.write_action = lambda data: 1
            result = self.session.write(cid, b"abc")
        else:
            writer = fakes.FakeStream()
            writer.write_action = lambda data: 1
            result = self.session.deliver(cid, writer)
        self.assertEqual(result.count, 1)
        self.now = 8.999
        self.assertIsNone(self.session.check_termination())
        self.now = 9
        self.assertEqual(self.session.check_termination(), "IDLE_TIMEOUT")

    def test_partial_read_updates_idle(self):
        self.progress("read")

    def test_partial_write_updates_idle(self):
        self.progress("write")

    def test_partial_delivery_updates_idle_without_recharge(self):
        self.progress("deliver")
        self.assertEqual(self.budget.snapshot().total_bytes, 4)

    def no_progress(self, operation, response):
        cid = self.ready()
        writer = fakes.FakeStream()
        if operation == "deliver":
            self.session.read(cid, 2)
        self.now = 4
        if operation == "read":
            self.handle.read_action = response
            self.session.read(cid, 2)
        elif operation == "write":
            self.handle.write_action = response
            self.session.write(cid, b"xx")
        else:
            writer.write_action = response
            self.session.deliver(cid, writer)
        self.assertEqual(self.session._connections[cid].last_progress, 0)
        self.now = 5
        self.assertEqual(self.session.check_termination(), "IDLE_TIMEOUT")

    def test_eof_does_not_update_idle_or_close_running_connection(self):
        self.no_progress("read", lambda n: b"")
        self.assertNotIn(("close",), self.handle.events)

    def test_zero_write_does_not_update_idle(self):
        self.no_progress("write", lambda data: 0)

    def test_zero_delivery_does_not_update_idle(self):
        self.no_progress("deliver", lambda data: 0)

    def test_would_block_read_does_not_update_idle(self):
        self.no_progress("read", fakes.raises(IoWouldBlock()))

    def test_would_block_write_does_not_update_idle(self):
        self.no_progress("write", fakes.raises(IoWouldBlock()))

    def test_would_block_delivery_does_not_update_idle(self):
        self.no_progress("deliver", fakes.raises(IoWouldBlock()))

    def test_poll_snapshot_and_reservation_do_not_update_idle(self):
        cid = self.ready()
        self.now = 4
        grant = self.budget.reserve_bytes(cid, job_id="job", tunnel_id="a",
                                          direction="send", operation="manual", requested=2)
        self.assertIsNone(self.session.poll())
        self.session.termination_snapshot()
        self.now = 5
        self.assertEqual(self.session.check_termination(), "IDLE_TIMEOUT")
        self.session.run_cleanup()
        self.state("STOPPING")
        self.assertNotIn(("close",), self.handle.events)
        self.budget.settle_bytes(grant.token, job_id="job", tunnel_id="a", connection_id=cid,
                                 direction="send", operation="manual", actual=1)
        self.assertEqual(self.session._connections[cid].last_progress, 0)
        self.assertEqual(self.budget.snapshot().concurrent_connections, 1)
        self.session.run_cleanup()
        self.assertEqual(self.handle.events.count(("close",)), 1)
        self.state("CLOSED")

    def test_snapshot_and_cancel_do_not_read_clock_or_invoke_cleanup(self):
        self.ready()
        calls = self.clock_calls
        self.now = 100
        self.state("RUNNING")
        self.assertIsNone(self.session.request_cancel())
        snap = self.state("STOPPING")
        self.assertEqual(snap.reason, "CANCELLED")
        self.assertEqual(self.clock_calls, calls)
        self.assertNotIn(("close",), self.handle.events)

    def test_check_does_not_wait_for_blocked_cleanup(self):
        self.ready()
        self.session.request_cancel()
        def action(pause):
            self.handle.close_action = pause
            return self.session.run_cleanup()
        def inspect():
            self.assertEqual(self.session.check_termination(), "CANCELLED")
            self.assertEqual(self.state("STOPPING").cleanup_in_progress, 1)
            self.session.request_cancel()
            self.session.run_cleanup()
        self.blocked(action, inspect, lambda: None)
        self.state("CLOSED")

    def test_cancel_first_then_timeout_preserves_cancel(self):
        self.ready()
        self.session.request_cancel()
        self.now = 100
        self.assertEqual(self.session.check_termination(), "CANCELLED")

    def test_timeout_first_then_cancel_preserves_timeout(self):
        self.ready()
        self.now = 5
        self.session.check_termination()
        self.session.request_cancel()
        self.assertEqual(self.session.stop_reason, "IDLE_TIMEOUT")

    def test_budget_deadline_precedes_connection_and_idle_in_one_check(self):
        self.ready()
        def inspect():
            self.now = 100
            self.assertEqual(self.session.check_termination(), "DEADLINE")
        result = self.blocked(lambda pause: self.connect(pause, "b"), inspect,
                              lambda *args: fakes.FakeStream())
        self.assertEqual(result.reason, "DEADLINE")

    def test_connection_timeout_precedes_idle_in_one_check(self):
        self.ready()
        def inspect():
            self.now = 10
            self.assertEqual(self.session.check_termination(), "CONNECTION_TIMEOUT")
        result = self.blocked(lambda pause: self.connect(pause, "b"), inspect,
                              lambda *args: fakes.FakeStream())
        self.assertEqual(result.reason, "CONNECTION_TIMEOUT")

    def test_cancel_timeout_barrier_race_retains_first_locked_reason(self):
        self.ready()
        self.now = 5
        barrier = Barrier(2)
        def cancel():
            barrier.wait(10)
            self.session.request_cancel()
        def check():
            barrier.wait(10)
            return self.session.check_termination()
        with ThreadPoolExecutor(max_workers=2) as pool:
            a, b = pool.submit(cancel), pool.submit(check)
            a.result(10)
            observed = b.result(10)
        self.assertIn(observed, ("CANCELLED", "IDLE_TIMEOUT"))
        self.assertEqual(self.session.stop_reason, observed)
        self.assertEqual(self.budget.snapshot().termination, observed)

    def late_io(self, direction, finish):
        cid = self.ready()
        def action(pause):
            if direction == "read":
                self.handle.read_action = pause
                return self.session.read(cid, 6)
            self.handle.write_action = pause
            return self.session.write(cid, b"abcdef")
        def inspect():
            self.session.request_cancel()
            self.session.run_cleanup()
            snap = self.state("STOPPING")
            self.assertEqual((snap.in_flight_io, snap.reserved_bytes), (1, 6))
            self.assertNotIn(("close",), self.handle.events)
            self.now = 4
        result = self.blocked(action, inspect, finish)
        self.assertEqual(result.reason, "CANCELLED")
        self.assertEqual(self.budget.snapshot().reserved_bytes, 0)
        self.assertEqual(self.session._connections[cid].last_progress, 0)
        self.assertEqual(self.session.connection_state(cid).buffered_bytes, 0)
        self.assertEqual(self.handle.events.count(("close",)), 1)
        self.state("CLOSED")
        return result

    def test_late_read_settles_once_and_does_not_publish_buffer(self):
        self.assertEqual(self.late_io("read", lambda n: b"abc").count, 3)
        self.assertEqual(self.budget.snapshot().confirmed_bytes, 3)
        self.assertFalse(self.budget._tokens)

    def test_late_write_settles_once_without_idle_extension(self):
        self.assertEqual(self.late_io("write", lambda data: 2).count, 2)
        self.assertEqual(self.budget.snapshot().confirmed_bytes, 2)

    def test_late_io_error_preserves_uncertain_accounting_and_cancel(self):
        result = self.late_io("write", fakes.raises(OSError()))
        self.assertEqual(result.error, "OSError")
        self.assertEqual(self.budget.snapshot().uncertain_bytes, 6)

    def test_late_dial_cancel_never_publishes_handle(self):
        def inspect():
            self.session.request_cancel()
            self.session.run_cleanup()
            self.assertEqual(self.state("STOPPING").occupied_connections, 1)
        result = self.blocked(lambda pause: self.connect(pause), inspect, lambda *a: self.handle)
        self.assertFalse(result.allowed)
        self.assertIsNone(result.result)
        self.assertTrue(self.session._results[-1].allowed)
        self.assertEqual(self.handle.events.count(("close",)), 1)
        self.state("CLOSED")

    def test_stop_denies_new_connect_read_write_and_delivery(self):
        cid = self.ready()
        self.session.read(cid, 3)
        self.session.request_cancel()
        before = list(self.handle.events)
        self.assertEqual(self.session.read(cid, 1).reason, "CANCELLED")
        self.assertEqual(self.session.write(cid, b"x").reason, "CANCELLED")
        self.assertEqual(self.session.deliver(cid, fakes.FakeStream()).reason, "CANCELLED")
        self.assertFalse(self.connect(fakes.raises(AssertionError())).allowed)
        self.assertEqual(self.handle.events, before + [("close",)])

    def test_cleanup_failure_holds_occupancy_without_retry(self):
        self.ready()
        self.handle.close_action = fakes.raises(OSError())
        self.session.request_cancel()
        self.session.run_cleanup()
        self.assertEqual(self.state("CLOSE_UNCONFIRMED").occupied_connections, 1)
        self.assertEqual(self.session.connection_state(1).cleanup_error, "OSError")
        self.now = 1000
        self.session.poll()
        self.session.run_cleanup()
        self.assertEqual(self.handle.events.count(("close",)), 1)
        self.state("CLOSE_UNCONFIRMED")

    def test_non_none_close_is_unconfirmed_and_never_time_released(self):
        self.ready()
        self.handle.close_action = lambda: False
        self.session.stop("STOP")
        self.assertEqual(self.state("CLOSE_UNCONFIRMED").occupied_connections, 1)
        self.now = 1000
        self.session.run_cleanup()
        self.assertEqual(self.handle.events.count(("close",)), 1)
        self.state("CLOSE_UNCONFIRMED")

    def test_connector_close_failure_is_never_retried_by_session(self):
        self.handle.peer = ("1.1.1.1", 443)
        self.handle.close_action = fakes.raises(OSError())
        result = self.connect()
        self.assertEqual(result.result.close_error, "OSError")
        self.state("CLOSE_UNCONFIRMED")
        self.session.run_cleanup()
        self.assertEqual(self.handle.events.count(("close",)), 1)

    def test_interrupted_dial_unknown_resource_never_becomes_closed(self):
        with self.assertRaises(KeyboardInterrupt):
            self.connect(fakes.raises(KeyboardInterrupt()))
        self.assertEqual(self.state("CLOSE_UNCONFIRMED").occupied_connections, 1)
        self.now = 1000
        self.session.run_cleanup()
        self.state("CLOSE_UNCONFIRMED")

    def test_pending_dns_interruption_is_removed_but_exception_preserved(self):
        exc = KeyboardInterrupt("dns")
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.target(fakes.raises(exc))
        self.assertIs(caught.exception, exc)
        self.assertEqual(self.state("CLOSED").pending_connects, 0)

    def test_pending_dns_dominates_other_failed_close_state(self):
        self.ready()
        self.handle.close_action = fakes.raises(OSError())
        def inspect():
            self.session.request_cancel()
            self.session.run_cleanup()
            snap = self.state("STOPPING")
            self.assertEqual((snap.pending_connects, snap.unconfirmed_handles), (1, 1))
        self.blocked(lambda pause: self.target(pause), inspect, self.resolution)
        self.state("CLOSE_UNCONFIRMED")

    def test_running_eof_preserves_buffer_drain_and_does_not_mean_success(self):
        cid = self.ready()
        self.session.read(cid, 4)
        self.handle.read_action = lambda n: b""
        self.assertEqual(self.session.read(cid, 1).reason, "EOF")
        self.state("RUNNING")
        writer = fakes.FakeStream()
        writer.write_action = lambda data: 2
        self.assertEqual(self.session.deliver(cid, writer).count, 2)
        self.assertEqual(self.session.connection_state(cid).buffered_bytes, 2)
        self.assertEqual(self.budget.snapshot().total_bytes, 4)
        self.session.request_cancel()
        self.assertEqual(self.state("STOPPING").buffered_bytes, 2)
        self.session.run_cleanup()
        snap = self.state("CLOSED")
        self.assertEqual((snap.buffered_bytes, snap.reason), (0, "CANCELLED"))

    def test_late_delivery_does_not_recharge_or_extend_idle(self):
        cid = self.ready()
        self.session.read(cid, 4)
        writer = fakes.FakeStream()
        def action(pause):
            writer.write_action = pause
            return self.session.deliver(cid, writer)
        def inspect():
            self.session.request_cancel()
            self.session.run_cleanup()
            self.state("STOPPING")
            self.now = 4
        result = self.blocked(action, inspect, lambda data: 2)
        self.assertEqual((result.reason, result.count), ("CANCELLED", 2))
        self.assertEqual(self.budget.snapshot().total_bytes, 4)
        self.assertEqual(self.session._connections[cid].last_progress, 0)
        self.state("CLOSED")

    def test_legacy_stop_and_poll_return_contracts(self):
        self.ready()
        self.assertIsNone(self.session.stop("FIRST"))
        self.assertEqual(self.session.poll(), "FIRST")
        self.assertIsNone(self.session.stop("SECOND"))
        self.state("CLOSED")

    def test_invalid_clock_uses_existing_budget_reason(self):
        self.ready()
        self.now = -1
        self.assertEqual(self.session.check_termination(), "INVALID_CLOCK")

    def test_session_creation_does_not_reset_job_origin(self):
        budget = NetworkBudget(self.config, self.config, clock=self.clock)
        self.now = 90
        session = QuotaSession("late", budget, IoLimits(6, 12),
                               termination_limits=TerminationLimits(10, 5))
        session.open_tunnel("late")
        self.now = 100
        self.assertEqual(session.check_termination(), "DEADLINE")

    def test_late_positive_read_at_idle_boundary_cannot_rescue_connection(self):
        cid = self.ready()
        def read(n):
            self.now = 5
            return b"xx"
        self.handle.read_action = read
        result = self.session.read(cid, 6)
        self.assertEqual((result.reason, result.count), ("IDLE_TIMEOUT", 2))
        self.assertEqual(self.budget.snapshot().confirmed_bytes, 2)
        self.assertEqual(self.session._connections[cid].last_progress, 0)
        self.assertEqual(self.session.connection_state(cid).buffered_bytes, 0)
        self.state("CLOSED")

    def test_progress_on_one_connection_does_not_refresh_another(self):
        first = self.ready()
        second = self.connect(tunnel="b", handle=fakes.FakeStream()).connection_id
        self.now = 4
        self.session.write(second, b"x")
        self.now = 5
        self.assertEqual(self.session.check_termination(), "IDLE_TIMEOUT")
        self.assertEqual(self.session._connections[first].last_progress, 0)
        self.assertEqual(self.session._connections[second].last_progress, 4)

    def test_read_and_write_share_one_connection_idle_clock(self):
        cid = self.ready()
        self.now = 4
        self.session.read(cid, 1)
        self.now = 8
        self.session.write(cid, b"x")
        self.now = 12.999
        self.assertIsNone(self.session.check_termination())
        self.now = 13
        self.assertEqual(self.session.check_termination(), "IDLE_TIMEOUT")

    def test_all_adapter_calls_allow_other_thread_to_observe_shared_state(self):
        def observe():
            with ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(self.session.termination_snapshot).result(10)
        def dial(*args):
            self.assertEqual(observe().pending_connects, 1)
            return self.handle
        self.handle.peer_action = lambda: (observe() and self.handle.peer)
        cid = self.connect(dial).connection_id
        self.handle.write_action = lambda data: (observe() and 1)
        self.assertEqual(self.session.write(cid, b"xx").count, 1)
        self.handle.read_action = lambda n: (observe() and b"x")
        self.session.read(cid, 1)
        self.handle.close_action = lambda: (observe() and None)
        self.session.stop("DONE")
        self.state("CLOSED")
