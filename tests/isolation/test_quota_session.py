"""Memory fakes and event-controlled ordering only; no sleeps or network."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier, Event
import unittest

from src.isolation.budget import BudgetLimits, NetworkBudget
from src.isolation.connect_dns import DnsLimits, DnsResolution
from src.isolation.destination import AllowedDestination, DestinationPolicy
from src.isolation.quota_session import IoLimits, IoWouldBlock, QuotaSession


class FakeStream:
    def __init__(self):
        self.peer = ("8.8.8.8", 443)
        self.peer_action = None
        self.close_action = None
        self.read_action = None
        self.write_action = None
        self.events = []

    def getpeername(self):
        self.events.append(("peer",))
        return self.peer_action() if self.peer_action else self.peer

    def close(self):
        self.events.append(("close",))
        return self.close_action() if self.close_action else None

    def read(self, n):
        self.events.append(("read", n))
        return self.read_action(n) if self.read_action else b"x" * n

    def write(self, data):
        self.events.append(("write", data))
        return self.write_action(data) if self.write_action else len(data)


class Resolver:
    def __init__(self):
        self.calls = []

    def resolve_complete(self, hostname):
        self.calls.append(hostname)
        return DnsResolution(hostname, "COMPLETE", True, True, ("8.8.8.8",))


def raises(exc):
    def action(*args):
        raise exc
    return action


class QuotaTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.config = BudgetLimits(10, 10, 10, 20, 100)
        self.budget = NetworkBudget(self.config, self.config, clock=lambda: self.now)
        self.session = QuotaSession("job", self.budget, IoLimits(6, 8))
        self.session.open_tunnel("a")
        self.session.open_tunnel("b")
        self.policy = DestinationPolicy((AllowedDestination("example.com", 443),))
        self.handle = FakeStream()

    def connect(self, handle=None, tunnel="a", dialer=None):
        handle = handle or self.handle
        return self.session.connect(tunnel, self.policy, "example.com", ("8.8.8.8",),
                                    dialer=dialer or (lambda ip, port: handle))

    def ready(self, handle=None, tunnel="a"):
        result = self.connect(handle, tunnel)
        self.assertTrue(result.allowed)
        return result.connection_id

    def reserve(self, cid, amount=6, **changes):
        args = dict(job_id="job", tunnel_id="a", direction="send", operation="op",
                    requested=amount)
        args.update(changes)
        return self.budget.reserve_bytes(cid, **args)

    def settle(self, token, actual=0, **changes):
        args = dict(job_id=token.job_id, tunnel_id=token.tunnel_id,
                    connection_id=token.connection_id, direction=token.direction,
                    operation=token.operation, actual=actual)
        args.update(changes)
        return self.budget.settle_bytes(token, **args)

    def invariant(self):
        for scope in (None, "a", "b"):
            s = self.budget.snapshot(scope)
            self.assertLessEqual(s.confirmed_bytes + s.uncertain_bytes + s.reserved_bytes, 10)
            self.assertEqual(s.total_bytes, s.confirmed_bytes + s.uncertain_bytes)

    def test_dial_reservation_precedes_dial_and_peer(self):
        def dial(ip, port):
            self.assertEqual((ip, port), ("8.8.8.8", 443))
            s = self.budget.snapshot()
            self.assertEqual((s.connection_attempts, s.total_connections,
                              s.concurrent_connections, s.pending_connections), (1, 0, 1, 1))
            return self.handle
        def peer():
            s = self.budget.snapshot()
            self.assertEqual((s.total_connections, s.pending_connections), (1, 0))
            return self.handle.peer
        self.handle.peer_action = peer
        result = self.connect(dialer=dial)
        self.assertTrue(result.allowed)
        self.assertIs(result.result.handle._record.handle, self.handle)
        self.assertEqual(self.session.connection_state(result.connection_id).phase, "CONNECT_READY")

    def test_peer_rejection_keeps_establishment_and_attempt(self):
        self.handle.peer = ("1.1.1.1", 443)
        result = self.connect()
        self.assertEqual(result.reason, "PEER_MISMATCH")
        self.assertEqual(result.result.reason, "PEER_MISMATCH")
        self.assertEqual(self.budget.snapshot().total_connections, 1)
        self.assertEqual(self.budget.snapshot().connection_attempts, 1)
        self.assertEqual(self.budget.snapshot().concurrent_connections, 0)
        self.assertEqual(self.handle.events, [("peer",), ("close",)])

    def test_peer_cleanup_failure_preserves_nested_diagnostics(self):
        self.handle.peer_action = raises(ValueError("private"))
        self.handle.close_action = raises(OSError("private"))
        result = self.connect()
        self.assertEqual((result.result.reason, result.result.error, result.result.close_error),
                         ("PEER_ERROR", "ValueError", "OSError"))
        self.assertEqual(self.session.stop_reason, "PEER_ERROR")
        state = self.session.connection_state(result.connection_id)
        self.assertEqual((state.cleanup, state.cleanup_error), ("FAILED", "OSError"))
        self.assertEqual(self.budget.snapshot().concurrent_connections, 1)
        self.session.stop("SECOND")
        self.assertEqual(self.handle.events.count(("close",)), 1)

    def test_dial_failure_consumes_attempt_not_establishment(self):
        result = self.connect(dialer=raises(OSError()))
        self.assertEqual((result.result.reason, result.result.error), ("DIAL_ERROR", "OSError"))
        s = self.budget.snapshot()
        self.assertEqual((s.connection_attempts, s.total_connections, s.concurrent_connections), (1, 0, 0))

    def test_invalid_none_handle_releases_pending(self):
        result = self.connect(dialer=lambda ip, port: None)
        self.assertEqual(result.reason, "DIAL_INVALID_HANDLE")
        self.assertEqual(self.budget.snapshot().pending_connections, 0)

    def test_invalid_nonempty_handle_is_established_and_close_unconfirmed(self):
        result = self.connect(handle=object())
        self.assertEqual(result.result.reason, "PEER_ERROR")
        self.assertEqual(result.result.close_error, "AttributeError")
        self.assertEqual(self.budget.snapshot().total_connections, 1)
        self.assertEqual(self.budget.snapshot().concurrent_connections, 1)

    def test_invalid_destination_does_not_consume_attempt(self):
        result = self.session.connect("a", self.policy, "bad.test", ("8.8.8.8",),
                                      dialer=raises(AssertionError()))
        self.assertEqual(result.reason, "NOT_ALLOWLISTED")
        self.assertEqual(self.budget.snapshot().connection_attempts, 0)

    def test_dns_result_preserved_with_connector_handle(self):
        resolver = Resolver()
        result = self.session.connect_target("a", self.policy, b"example.com:443",
                                             resolver=resolver, dialer=lambda *a: self.handle,
                                             limits=DnsLimits(2, 100))
        self.assertTrue(result.allowed)
        self.assertIs(result.result.connector.handle._record.handle, self.handle)
        self.assertEqual(result.result.authority.hostname, "example.com")
        self.assertIs(self.session._results[-1], result.result)

    def test_dns_exception_result_preserved(self):
        resolver = Resolver()
        resolver.resolve_complete = raises(TimeoutError())
        result = self.session.connect_target("a", self.policy, b"example.com:443",
                                             resolver=resolver, dialer=raises(AssertionError()),
                                             limits=DnsLimits(2, 100))
        self.assertEqual((result.reason, result.result.error), ("DNS_TIMEOUT", "TimeoutError"))
        self.assertEqual(self.budget.snapshot().connection_attempts, 0)

    def test_admission_quota_stops_and_cleans_existing_handles(self):
        self.budget._attempt_limits = replace(self.config, concurrent_connections=1)
        first = self.ready()
        result = self.connect(FakeStream(), "b")
        self.assertEqual(result.reason, "CONCURRENT_CONNECTIONS_LIMIT")
        self.assertEqual(self.budget.snapshot().connection_attempts, 1)
        self.assertEqual(self.session.connection_state(first).cleanup, "SUCCEEDED")

    def test_attempt_quota_does_not_refund_failed_dial(self):
        self.budget._attempt_limits = replace(self.config, connection_attempts=1)
        self.connect(dialer=raises(OSError()))
        result = self.connect(dialer=raises(AssertionError()))
        self.assertEqual(result.reason, "CONNECTION_ATTEMPTS_LIMIT")
        self.assertEqual(self.budget.snapshot().connection_attempts, 1)

    def test_cumulative_establishment_includes_peer_rejection(self):
        self.handle.peer = ("1.1.1.1", 443)
        self.connect()
        self.assertEqual(self.budget.snapshot().total_connections, 1)

    def test_write_is_bounded_by_chunk_and_remaining_quota(self):
        cid = self.ready()
        self.assertEqual(self.session.write(cid, b"a" * 50).count, 6)
        self.assertEqual(self.session.write(cid, b"b" * 50).count, 4)
        self.assertEqual(self.handle.events[1:], [("write", b"a" * 6), ("write", b"b" * 4)])
        self.assertEqual(self.session.write(cid, b"c").reason, "TOTAL_BYTES_LIMIT")
        self.assertEqual(self.handle.events.count(("close",)), 1)
        self.invariant()

    def test_partial_write_releases_unused_reservation(self):
        cid = self.ready()
        self.handle.write_action = lambda data: 2
        self.assertEqual(self.session.write(cid, b"abcdefgh").count, 2)
        s = self.budget.snapshot()
        self.assertEqual((s.confirmed_bytes, s.reserved_bytes), (2, 0))
        self.invariant()

    def test_partial_read_releases_unused_reservation(self):
        cid = self.ready()
        self.handle.read_action = lambda n: b"ab"
        self.assertEqual(self.session.read(cid, 999).count, 2)
        self.assertIn(("read", 6), self.handle.events)
        self.assertEqual(self.budget.snapshot().confirmed_bytes, 2)
        self.assertEqual(self.budget.snapshot().reserved_bytes, 0)
        self.assertEqual(self.session.connection_state(cid).buffered_bytes, 2)

    def test_both_directions_share_one_quota(self):
        cid = self.ready()
        self.session.write(cid, b"abcdef")
        self.assertEqual(self.session.read(cid, 100).count, 4)
        self.assertIn(("read", 4), self.handle.events)
        self.assertEqual(self.session.write(cid, b"x").reason, "TOTAL_BYTES_LIMIT")
        self.assertEqual(self.budget.snapshot().total_bytes, 10)

    def test_buffer_limit_is_shared_between_connections(self):
        a = self.ready()
        other = FakeStream()
        b = self.ready(other, "b")
        self.session.read(a, 100)
        self.assertEqual(self.session.read(b, 100).count, 2)
        self.assertIn(("read", 2), other.events)
        self.assertEqual(self.session.read(b, 1).reason, "WOULD_BLOCK")
        self.assertIsNone(self.session.stop_reason)
        self.assertEqual(sum(self.session.connection_state(c).buffered_bytes for c in (a, b)), 8)

    def test_delivery_is_not_charged_twice(self):
        cid = self.ready()
        self.session.read(cid, 6)
        writer = FakeStream()
        writer.write_action = lambda data: min(2, len(data))
        for _ in range(3):
            self.assertEqual(self.session.deliver(cid, writer).count, 2)
        self.assertEqual(self.session.deliver(cid, writer).reason, "EMPTY")
        self.assertEqual(self.budget.snapshot().total_bytes, 6)
        self.assertEqual(self.session.connection_state(cid).buffered_bytes, 0)

    def test_delivery_at_exact_byte_limit_is_allowed(self):
        cid = self.ready()
        self.session.write(cid, b"1234")
        self.session.read(cid, 6)
        self.assertEqual(self.session.deliver(cid, FakeStream()).count, 6)
        self.assertEqual(self.budget.snapshot().total_bytes, 10)

    def test_delivery_would_block_keeps_buffer(self):
        cid = self.ready()
        self.session.read(cid, 4)
        writer = FakeStream()
        writer.write_action = raises(IoWouldBlock())
        self.assertEqual(self.session.deliver(cid, writer).reason, "WOULD_BLOCK")
        self.assertEqual(self.session.connection_state(cid).buffered_bytes, 4)
        self.assertEqual(self.budget.snapshot().total_bytes, 4)

    def test_delivery_exception_stops_without_recharging(self):
        cid = self.ready()
        self.session.read(cid, 4)
        writer = FakeStream()
        writer.write_action = raises(OSError())
        result = self.session.deliver(cid, writer)
        self.assertEqual((result.reason, result.error), ("IO_ERROR", "OSError"))
        self.assertEqual(self.budget.snapshot().total_bytes, 4)
        self.assertEqual(self.session.connection_state(cid).cleanup, "SUCCEEDED")

    def test_delivery_invalid_count_is_adapter_violation(self):
        cid = self.ready()
        self.session.read(cid, 3)
        writer = FakeStream()
        writer.write_action = lambda data: len(data) + 1
        self.assertEqual(self.session.deliver(cid, writer).reason, "ADAPTER_VIOLATION")

    def test_unknown_write_progress_charges_full_reservation(self):
        cid = self.ready()
        self.handle.write_action = raises(OSError())
        result = self.session.write(cid, b"abcdefgh")
        self.assertEqual((result.reason, result.error), ("IO_ERROR", "OSError"))
        s = self.budget.snapshot()
        self.assertEqual((s.confirmed_bytes, s.uncertain_bytes, s.reserved_bytes), (0, 6, 0))
        self.invariant()

    def test_unknown_read_progress_charges_full_reservation(self):
        cid = self.ready()
        self.handle.read_action = raises(TimeoutError())
        self.assertEqual(self.session.read(cid, 100).reason, "IO_ERROR")
        self.assertEqual(self.budget.snapshot().uncertain_bytes, 6)
        self.assertEqual(self.session.connection_state(cid).buffered_bytes, 0)

    def test_read_would_block_releases_all(self):
        cid = self.ready()
        self.handle.read_action = raises(IoWouldBlock())
        self.assertEqual(self.session.read(cid, 3).reason, "WOULD_BLOCK")
        self.assertEqual(self.budget.snapshot().total_bytes, 0)
        self.assertEqual(self.budget.snapshot().reserved_bytes, 0)
        self.assertIsNone(self.session.stop_reason)

    def test_write_would_block_releases_all(self):
        cid = self.ready()
        self.handle.write_action = raises(IoWouldBlock())
        self.assertEqual(self.session.write(cid, b"abc").reason, "WOULD_BLOCK")
        self.assertEqual(self.budget.snapshot().total_bytes, 0)

    def test_generic_blocking_error_is_conservatively_unknown(self):
        cid = self.ready()
        self.handle.write_action = raises(BlockingIOError())
        self.assertEqual(self.session.write(cid, b"abc").reason, "IO_ERROR")
        self.assertEqual(self.budget.snapshot().uncertain_bytes, 3)

    def test_invalid_write_reports_stop_and_charge_reserved(self):
        for value in (-1, True, None, "1", 7):
            with self.subTest(value=value):
                self.setUp()
                cid = self.ready()
                self.handle.write_action = lambda data: value
                self.assertEqual(self.session.write(cid, b"abcdef").reason, "ADAPTER_VIOLATION")
                self.assertEqual(self.budget.snapshot().uncertain_bytes, 6)

    def test_invalid_reads_stop_without_buffering_oversize(self):
        for value in (b"x" * 7, bytearray(b"a"), None, "x"):
            with self.subTest(value=value):
                self.setUp()
                cid = self.ready()
                self.handle.read_action = lambda n: value
                self.assertEqual(self.session.read(cid, 6).reason, "ADAPTER_VIOLATION")
                self.assertEqual(self.budget.snapshot().uncertain_bytes, 6)
                self.assertEqual(self.session.connection_state(cid).buffered_bytes, 0)

    def test_eof_and_zero_write_do_not_consume_bytes(self):
        cid = self.ready()
        self.handle.read_action = lambda n: b""
        self.handle.write_action = lambda data: 0
        self.assertEqual(self.session.read(cid, 4).reason, "EOF")
        self.assertEqual(self.session.write(cid, b"abcd").count, 0)
        self.assertEqual(self.budget.snapshot().total_bytes, 0)

    def test_token_double_settlement_rejected(self):
        cid = self.ready()
        token = self.reserve(cid).token
        self.settle(token, 2)
        with self.assertRaises(ValueError):
            self.settle(token, 2)
        self.assertEqual(self.budget.snapshot().confirmed_bytes, 2)

    def test_token_scope_mismatch_rejected_without_consuming_token(self):
        cid = self.ready()
        token = self.reserve(cid).token
        for change in (dict(job_id="other"), dict(tunnel_id="b"), dict(connection_id=99),
                       dict(direction="receive"), dict(operation="other"), dict(connection_id=True)):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.settle(token, 1, **change)
        self.assertEqual(self.budget.snapshot().reserved_bytes, 6)
        self.settle(token, 1)

    def test_token_forgery_and_foreign_budget_rejected(self):
        cid = self.ready()
        token = self.reserve(cid).token
        with self.assertRaises(ValueError):
            self.settle(replace(token), 1)
        other = NetworkBudget(self.config, self.config)
        with self.assertRaises(ValueError):
            other.settle_bytes(token, job_id="job", tunnel_id="a", connection_id=cid,
                               direction="send", operation="op", actual=1)
        self.settle(token, 1)

    def test_overreport_does_not_release_token(self):
        cid = self.ready()
        token = self.reserve(cid).token
        for actual in (7, -1, True, 1.0):
            with self.subTest(actual=actual), self.assertRaises(ValueError):
                self.settle(token, actual)
        self.assertEqual(self.budget.snapshot().reserved_bytes, 6)
        self.settle(token, None)
        self.assertEqual(self.budget.snapshot().uncertain_bytes, 6)

    def test_duplicate_operation_rejected_until_settlement(self):
        cid = self.ready()
        token = self.reserve(cid).token
        with self.assertRaises(ValueError):
            self.reserve(cid)
        self.settle(token, 0)
        self.settle(self.reserve(cid).token, 0)

    def test_invalid_reservation_scope_and_size(self):
        cid = self.ready()
        for change in (dict(job_id="other"), dict(tunnel_id="b"), dict(direction="both"),
                       dict(operation=""), dict(requested=0), dict(requested=True), dict(requested=-1)):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.reserve(cid, **change)
        self.assertEqual(self.budget.snapshot().reserved_bytes, 0)

    def test_two_tunnels_reserve_only_shared_capacity(self):
        a = self.ready()
        b = self.ready(FakeStream(), "b")
        t1 = self.reserve(a, 6).token
        t2 = self.reserve(b, 6, tunnel_id="b").token
        self.assertEqual((t1.amount, t2.amount), (6, 4))
        denied = self.reserve(a, 1, operation="second")
        self.assertEqual(denied.reason, "WOULD_BLOCK")
        self.assertIsNone(self.budget.snapshot().termination)
        self.invariant()
        self.settle(t1, 2)
        self.settle(t2, 4)
        self.assertEqual(self.budget.snapshot().total_bytes, 6)

    def test_tunnel_byte_limit_is_enforced(self):
        self.budget._tunnel_limits = replace(self.config, total_bytes=3)
        cid = self.ready()
        self.assertEqual(self.session.write(cid, b"abcdefgh").count, 3)
        self.assertEqual(self.session.read(cid, 1).reason, "TOTAL_BYTES_LIMIT")
        self.assertEqual(self.budget.snapshot("a").total_bytes, 3)

    def test_legacy_transfer_is_compatible(self):
        b = NetworkBudget(self.config, self.config)
        b.open_tunnel("legacy")
        cid = b.begin_connection("legacy").connection_id
        b.connected(cid)
        self.assertTrue(b.transfer(cid, sent=4, received=6).allowed)
        self.assertEqual(b.snapshot().total_bytes, 10)
        self.assertEqual(b.transfer(cid, sent=1).reason, "TOTAL_BYTES_LIMIT")
        self.assertEqual(b.snapshot().concurrent_connections, 0)

    def test_transfer_cannot_double_charge_reservation_connection(self):
        cid = self.ready()
        token = self.reserve(cid).token
        self.settle(token, 2)
        with self.assertRaises(ValueError):
            self.budget.transfer(cid, sent=2)
        self.assertEqual(self.budget.snapshot().total_bytes, 2)

    def test_reservation_cannot_mix_with_legacy_on_same_connection(self):
        cid = self.ready()
        self.budget.transfer(cid, sent=1)
        with self.assertRaises(ValueError):
            self.reserve(cid)
        self.assertEqual(self.budget.snapshot().total_bytes, 1)

    def test_legacy_other_connection_respects_pending_byte_reservations(self):
        a = self.ready()
        b = self.ready(FakeStream(), "b")
        token = self.reserve(a, 6).token
        self.assertEqual(self.budget.transfer(b, sent=5).reason, "WOULD_BLOCK")
        self.assertTrue(self.budget.transfer(b, sent=4).allowed)
        self.settle(token, 6)
        self.assertEqual(self.budget.snapshot().total_bytes, 10)
        self.invariant()

    def test_close_does_not_drop_inflight_reservation(self):
        cid = self.ready()
        token = self.reserve(cid).token
        self.assertEqual(self.budget.close_connection(cid).reason, "IN_FLIGHT")
        self.assertEqual(self.budget.snapshot().concurrent_connections, 1)
        self.settle(token, 2)
        self.budget.close_connection(cid)
        self.assertEqual(self.budget.snapshot().concurrent_connections, 0)

    def test_late_settlement_after_stop_retains_reservation(self):
        cid = self.ready()
        token = self.reserve(cid).token
        self.budget.stop("STOP")
        self.assertEqual(self.budget.snapshot().reserved_bytes, 6)
        self.assertEqual(self.budget.snapshot().concurrent_connections, 1)
        self.settle(token, 3)
        self.assertEqual(self.budget.snapshot().confirmed_bytes, 3)
        self.budget.close_connection(cid)
        self.assertEqual(self.budget.snapshot().concurrent_connections, 0)

    def test_stop_forbids_new_io_and_admission(self):
        cid = self.ready()
        self.session.stop("FIRST")
        before = list(self.handle.events)
        self.assertEqual(self.session.write(cid, b"x").reason, "FIRST")
        self.assertEqual(self.session.read(cid, 1).reason, "FIRST")
        self.assertEqual(self.session.deliver(cid, FakeStream()).reason, "FIRST")
        self.assertEqual(self.connect().reason, "FIRST")
        self.assertEqual(self.session.open_tunnel("c").reason, "FIRST")
        self.assertEqual(self.handle.events, before)

    def test_cleanup_success_releases_occupancy_only(self):
        cid = self.ready()
        self.session.stop("DONE")
        self.assertEqual(self.session.connection_state(cid).cleanup, "SUCCEEDED")
        s = self.budget.snapshot()
        self.assertEqual((s.concurrent_connections, s.total_connections, s.connection_attempts), (0, 1, 1))

    def test_cleanup_failure_preserves_first_reason_and_slot(self):
        cid = self.ready()
        self.handle.close_action = raises(OSError())
        self.session.stop("FIRST")
        self.session.stop("SECOND")
        self.assertEqual(self.session.stop_reason, "FIRST")
        self.assertEqual(self.budget.snapshot().termination, "FIRST")
        self.assertEqual(self.session.connection_state(cid).cleanup, "FAILED")
        self.assertEqual(self.budget.snapshot().concurrent_connections, 1)
        self.assertEqual(self.handle.events.count(("close",)), 1)

    def test_cleanup_unconfirmed_keeps_slot(self):
        cid = self.ready()
        self.handle.close_action = lambda: False
        self.session.stop("DONE")
        self.assertEqual(self.session.connection_state(cid).cleanup, "UNCONFIRMED")
        self.assertEqual(self.budget.snapshot().concurrent_connections, 1)

    def test_cleanup_interruption_is_failure_without_hiding_reason(self):
        cid = self.ready()
        self.handle.close_action = raises(KeyboardInterrupt())
        self.session.stop("FIRST")
        state = self.session.connection_state(cid)
        self.assertEqual((state.cleanup, state.cleanup_error), ("FAILED", "KeyboardInterrupt"))
        self.assertEqual(self.session.stop_reason, "FIRST")

    def test_cleanup_continues_after_another_handle_fails(self):
        a = self.ready()
        b = self.ready(FakeStream(), "b")
        self.handle.close_action = raises(OSError())
        self.session.stop("FIRST")
        self.assertEqual(self.session.connection_state(a).cleanup, "FAILED")
        self.assertEqual(self.session.connection_state(b).cleanup, "SUCCEEDED")
        self.assertEqual(self.budget.snapshot().concurrent_connections, 1)

    def test_existing_deadline_stops_and_cleans(self):
        cid = self.ready()
        self.now = 100
        self.assertEqual(self.session.read(cid, 1).reason, "DEADLINE")
        self.assertEqual(self.session.connection_state(cid).cleanup, "SUCCEEDED")
        self.assertNotIn(("read", 1), self.handle.events)

    def test_invalid_clock_stops_and_cleans(self):
        cid = self.ready()
        self.now = -1
        self.assertEqual(self.session.write(cid, b"a").reason, "INVALID_CLOCK")
        self.assertEqual(self.session.connection_state(cid).cleanup, "SUCCEEDED")

    def test_deadline_during_io_settles_before_cleanup(self):
        cid = self.ready()
        def write(data):
            self.now = 100
            return 2
        self.handle.write_action = write
        self.assertEqual(self.session.write(cid, b"abcdef").reason, "DEADLINE")
        self.assertEqual(self.budget.snapshot().confirmed_bytes, 2)
        self.assertEqual(self.budget.snapshot().reserved_bytes, 0)

    def test_interrupted_io_is_settled_then_propagated(self):
        cid = self.ready()
        self.handle.write_action = raises(KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.session.write(cid, b"abc")
        self.assertEqual(self.budget.snapshot().uncertain_bytes, 3)
        self.assertEqual(self.session.connection_state(cid).cleanup, "SUCCEEDED")

    def test_interrupted_peer_is_not_closed_twice(self):
        self.handle.peer_action = raises(KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.connect()
        self.assertEqual(self.handle.events.count(("close",)), 1)
        self.assertEqual(self.session.connection_state(1).cleanup, "SUCCEEDED")
        self.assertEqual(self.budget.snapshot().concurrent_connections, 0)

    def test_explicit_config_and_single_job_owner(self):
        for args in ((0, 1), (1, 0), (True, 1), (1, 1.0)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                IoLimits(*args)
        with self.assertRaises(ValueError):
            QuotaSession("job", self.budget, IoLimits(1, 1))
        with self.assertRaises(ValueError):
            self.budget.bind_job("another-job")

    def test_invalid_io_arguments_never_reach_adapter(self):
        cid = self.ready()
        for payload in (b"", bytearray(b"a"), "x", None):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.session.write(cid, payload)
        for n in (0, -1, True, 1.0):
            with self.subTest(n=n), self.assertRaises(ValueError):
                self.session.read(cid, n)
        self.assertEqual(self.handle.events, [("peer",)])

    def blocked(self, action, inspect, finish):
        entered, release = Event(), Event()
        def pause(*args):
            entered.set()
            if not release.wait(10):
                raise AssertionError("test event not released")
            return finish(*args)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(action, pause)
            try:
                self.assertTrue(entered.wait(10), "operation did not enter")
                inspect()
            finally:
                release.set()
            return future.result(timeout=10)

    def test_late_dial_success_is_counted_closed_and_never_published(self):
        def action(pause):
            return self.connect(dialer=pause)
        def inspect():
            self.session.stop("STOP")
            self.assertEqual(self.budget.snapshot().concurrent_connections, 1)
            self.assertEqual(self.budget.snapshot().pending_connections, 1)
        result = self.blocked(action, inspect, lambda *args: self.handle)
        self.assertFalse(result.allowed)
        self.assertIsNone(result.result)
        self.assertEqual(result.reason, "STOP")
        self.assertTrue(self.session._results[-1].allowed)
        self.assertIs(self.session._results[-1].handle._record.handle, self.handle)
        self.assertEqual(self.budget.snapshot().total_connections, 1)
        self.assertEqual(self.budget.snapshot().concurrent_connections, 0)
        self.assertEqual(self.handle.events.count(("close",)), 1)

    def test_late_io_completion_settles_once_before_close(self):
        cid = self.ready()
        def action(pause):
            self.handle.write_action = pause
            return self.session.write(cid, b"abcdef")
        def inspect():
            self.session.stop("STOP")
            self.assertEqual(self.budget.snapshot().reserved_bytes, 6)
            self.assertEqual(self.budget.snapshot().concurrent_connections, 1)
            self.assertNotIn(("close",), self.handle.events)
        result = self.blocked(action, inspect, lambda data: 2)
        self.assertEqual((result.reason, result.count), ("STOP", 2))
        self.assertEqual(self.budget.snapshot().confirmed_bytes, 2)
        self.assertEqual(self.budget.snapshot().reserved_bytes, 0)
        self.assertEqual(self.handle.events.count(("close",)), 1)

    def test_late_read_completion_is_charged_without_delivering(self):
        cid = self.ready()
        def action(pause):
            self.handle.read_action = pause
            return self.session.read(cid, 6)
        result = self.blocked(action, lambda: self.session.stop("STOP"), lambda n: b"abc")
        self.assertEqual((result.reason, result.count), ("STOP", 3))
        self.assertEqual(self.session.connection_state(cid).buffered_bytes, 0)
        self.assertEqual(self.budget.snapshot().confirmed_bytes, 3)

    def test_inflight_close_keeps_occupancy_and_is_not_retried(self):
        cid = self.ready()
        def action(pause):
            self.handle.close_action = pause
            self.session.stop("STOP")
        def inspect():
            self.assertEqual(self.session.connection_state(cid).cleanup, "IN_PROGRESS")
            self.assertEqual(self.budget.snapshot().concurrent_connections, 1)
            self.session.stop("SECOND")
            self.assertEqual(self.handle.events.count(("close",)), 1)
        self.blocked(action, inspect, lambda: None)
        self.assertEqual(self.session.connection_state(cid).cleanup, "SUCCEEDED")
        self.assertEqual(self.budget.snapshot().concurrent_connections, 0)

    def test_temporary_reservations_block_other_tunnel_without_stopping(self):
        a = self.ready()
        b = self.ready(FakeStream(), "b")
        self.session.limits = IoLimits(10, 10)
        def action(pause):
            self.handle.write_action = pause
            return self.session.write(a, b"x" * 10)
        def inspect():
            self.assertEqual(self.session.write(b, b"x").reason, "WOULD_BLOCK")
            self.assertIsNone(self.session.stop_reason)
            self.assertEqual(self.budget.snapshot().reserved_bytes, 10)
            self.invariant()
        self.blocked(action, inspect, lambda data: 4)
        self.assertEqual(self.session.write(b, b"x" * 6).count, 6)
        self.assertEqual(self.session.write(a, b"x").reason, "TOTAL_BYTES_LIMIT")

    def test_same_connection_io_is_serialized(self):
        cid = self.ready()
        def action(pause):
            self.handle.write_action = pause
            return self.session.write(cid, b"abc")
        def inspect():
            self.assertEqual(self.session.read(cid, 1).reason, "WOULD_BLOCK")
            self.assertEqual(self.session.write(cid, b"x").reason, "WOULD_BLOCK")
        self.blocked(action, inspect, lambda data: len(data))

    def test_buffer_capacity_is_reserved_for_inflight_reads(self):
        a = self.ready()
        other = FakeStream()
        b = self.ready(other, "b")
        def action(pause):
            self.handle.read_action = pause
            return self.session.read(a, 6)
        def inspect():
            self.assertEqual(self.session.read(b, 6).count, 2)
            self.assertIn(("read", 2), other.events)
        self.blocked(action, inspect, lambda n: b"x" * n)
        self.assertEqual(sum(self.session.connection_state(c).buffered_bytes for c in (a, b)), 8)

    def test_concurrent_reservations_are_atomic_across_tunnels(self):
        a = self.ready()
        b = self.ready(FakeStream(), "b")
        barrier = Barrier(2)
        def reserve(args):
            cid, tunnel = args
            barrier.wait(timeout=10)
            return self.reserve(cid, 8, tunnel_id=tunnel)
        with ThreadPoolExecutor(max_workers=2) as pool:
            grants = list(pool.map(reserve, ((a, "a"), (b, "b"))))
        self.assertEqual(sorted(g.token.amount for g in grants), [2, 8])
        self.invariant()
        for grant in grants:
            self.settle(grant.token, grant.token.amount)
        self.assertEqual(self.budget.snapshot().confirmed_bytes, 10)

    def test_adapter_calls_run_outside_shared_lock(self):
        cid = self.ready()
        def verify(*args):
            with ThreadPoolExecutor(max_workers=1) as pool:
                self.assertEqual(pool.submit(self.budget.snapshot).result(timeout=10).concurrent_connections, 1)
            return 1
        self.handle.write_action = verify
        self.assertEqual(self.session.write(cid, b"abc").count, 1)
        self.handle.close_action = lambda: verify() and None
        self.session.stop("DONE")

    def test_connector_close_non_none_is_unconfirmed_and_keeps_slot(self):
        self.handle.peer = ("1.1.1.1", 443)
        self.handle.close_action = lambda: False
        result = self.connect()
        self.assertEqual(result.reason, "PEER_MISMATCH")
        self.assertEqual(result.result.close_error, "_CloseUnconfirmed")
        self.assertEqual(self.session.connection_state(result.connection_id).cleanup, "UNCONFIRMED")
        self.assertEqual(self.budget.snapshot().concurrent_connections, 1)
        self.session.stop("SECOND")
        self.assertEqual(self.handle.events.count(("close",)), 1)

    def test_missing_close_is_not_hidden_by_connector_facade(self):
        class NoClose:
            def getpeername(self):
                return ("8.8.8.8", 443)
        result = self.connect(NoClose())
        self.assertEqual(result.result.reason, "DIAL_INVALID_HANDLE")
        self.assertEqual(result.result.close_error, "AttributeError")
        self.assertEqual(self.session.connection_state(result.connection_id).cleanup, "FAILED")
        self.assertEqual(self.budget.snapshot().concurrent_connections, 1)

    def test_peer_interruption_with_failed_close_retains_first_failure(self):
        self.handle.peer_action = raises(KeyboardInterrupt())
        self.handle.close_action = raises(OSError())
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.connect()
        self.assertIn("connector close failed: OSError", raised.exception.__notes__)
        self.assertEqual(self.session.stop_reason, "CONNECT_INTERRUPTED")
        self.assertEqual(self.session.connection_state(1).cleanup, "FAILED")
        self.assertEqual(self.budget.snapshot().concurrent_connections, 1)
        self.assertEqual(self.handle.events.count(("close",)), 1)

    def test_idle_tunnel_deadline_propagates_through_job_poll(self):
        self.budget._tunnel_limits = replace(self.config, duration_seconds=5)
        cid = self.ready()
        self.now = 5
        self.assertEqual(self.session.poll(), "DEADLINE")
        self.assertEqual(self.session.connection_state(cid).cleanup, "SUCCEEDED")

    def test_full_buffer_does_not_mask_committed_quota_end(self):
        self.session.limits = IoLimits(10, 10)
        cid = self.ready()
        self.assertEqual(self.session.read(cid, 10).count, 10)
        self.assertEqual(self.session.read(cid, 1).reason, "TOTAL_BYTES_LIMIT")
        self.assertEqual(self.handle.events.count(("read", 10)), 1)

    def test_zero_byte_quota_never_calls_stream(self):
        self.budget._attempt_limits = replace(self.config, total_bytes=0)
        cid = self.ready()
        self.assertEqual(self.session.write(cid, b"a").reason, "TOTAL_BYTES_LIMIT")
        self.assertEqual(self.handle.events, [("peer",), ("close",)])

    def test_shared_concurrent_dial_reservations_are_atomic(self):
        self.budget._attempt_limits = replace(self.config, concurrent_connections=1)
        def action(pause):
            return self.connect(dialer=pause)
        def inspect():
            rejected = self.connect(FakeStream(), "b")
            self.assertEqual(rejected.reason, "CONCURRENT_CONNECTIONS_LIMIT")
            self.assertEqual(self.budget.snapshot().connection_attempts, 1)
            self.assertEqual(self.budget.snapshot().concurrent_connections, 1)
        late = self.blocked(action, inspect, lambda *args: self.handle)
        self.assertFalse(late.allowed)
        self.assertIsNone(late.result)
        self.assertEqual(self.budget.snapshot().total_connections, 1)
        self.assertEqual(self.budget.snapshot().concurrent_connections, 0)

    def test_failed_close_slot_cannot_be_reused_by_other_tunnel(self):
        self.budget._attempt_limits = replace(self.config, concurrent_connections=1)
        cid = self.ready()
        self.handle.close_action = raises(OSError())
        self.session.stop("STOP")
        self.assertFalse(self.budget.begin_connection("b").allowed)
        self.assertEqual(self.budget.snapshot().concurrent_connections, 1)
        self.assertEqual(self.session.connection_state(cid).cleanup, "FAILED")

    def test_stopping_during_dns_prevents_later_dial(self):
        resolver = Resolver()
        def resolve(hostname):
            self.session.stop("STOP")
            return DnsResolution(hostname, "COMPLETE", True, True, ("8.8.8.8",))
        resolver.resolve_complete = resolve
        result = self.session.connect_target("a", self.policy, b"example.com:443",
                                             resolver=resolver, dialer=raises(AssertionError()),
                                             limits=DnsLimits(2, 100))
        self.assertEqual(result.reason, "STOP")
        self.assertFalse(result.allowed)
        self.assertEqual(self.budget.snapshot().connection_attempts, 0)
        self.assertEqual(result.result.connector.reason, "DIAL_ERROR")

    def test_late_dns_connector_success_retained_without_public_handle(self):
        def action(pause):
            return self.session.connect_target("a", self.policy, b"example.com:443",
                                                resolver=Resolver(), dialer=pause,
                                                limits=DnsLimits(2, 100))
        result = self.blocked(action, lambda: self.session.stop("STOP"), lambda *args: self.handle)
        self.assertIsNone(result.result)
        original = self.session._results[-1]
        self.assertTrue(original.allowed)
        self.assertEqual(original.authority.hostname, "example.com")
        self.assertEqual(original.connector.selected_ip, "8.8.8.8")
        self.assertEqual(self.budget.snapshot().concurrent_connections, 0)

    def test_stop_during_client_delivery_defers_cleanup_without_recharge(self):
        cid = self.ready()
        self.session.read(cid, 4)
        writer = FakeStream()
        def action(pause):
            writer.write_action = pause
            return self.session.deliver(cid, writer)
        def inspect():
            self.session.stop("STOP")
            self.assertNotIn(("close",), self.handle.events)
            self.assertEqual(self.budget.snapshot().concurrent_connections, 1)
        result = self.blocked(action, inspect, lambda data: 2)
        self.assertEqual((result.reason, result.count), ("STOP", 2))
        self.assertEqual(self.budget.snapshot().total_bytes, 4)
        self.assertEqual(self.session.connection_state(cid).cleanup, "SUCCEEDED")

    def test_dial_and_peer_calls_are_outside_shared_lock(self):
        def inspect():
            with ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(self.budget.snapshot).result(timeout=10)
        def dial(ip, port):
            self.assertEqual(inspect().pending_connections, 1)
            return self.handle
        def peer():
            self.assertEqual(inspect().total_connections, 1)
            return self.handle.peer
        self.handle.peer_action = peer
        self.assertTrue(self.connect(dialer=dial).allowed)

    def test_lowlevel_legacy_overrun_preserves_active_reservation(self):
        a = self.ready()
        b = self.ready(FakeStream(), "b")
        token = self.reserve(a, 6).token
        self.assertEqual(self.budget.transfer(b, sent=11).reason, "TOTAL_BYTES_LIMIT")
        self.assertEqual(self.budget.snapshot().reserved_bytes, 6)
        self.settle(token, None)
        self.assertEqual(self.budget.snapshot().uncertain_bytes, 6)
        self.invariant()

    def test_late_io_exception_after_stop_is_charged_without_replacing_reason(self):
        cid = self.ready()
        def action(pause):
            self.handle.write_action = pause
            return self.session.write(cid, b"abcdef")
        result = self.blocked(action, lambda: self.session.stop("FIRST"), raises(OSError()))
        self.assertEqual((result.reason, result.error), ("FIRST", "OSError"))
        self.assertEqual(self.budget.snapshot().uncertain_bytes, 6)
        self.assertEqual(self.budget.snapshot().reserved_bytes, 0)
        self.assertEqual(self.session.connection_state(cid).cleanup, "SUCCEEDED")

    def test_legacy_hard_tunnel_limit_precedes_temporary_job_contention(self):
        self.budget._attempt_limits = replace(self.config, total_bytes=5)
        self.budget._tunnel_limits = replace(self.config, total_bytes=3)
        a = self.ready()
        b = self.ready(FakeStream(), "b")
        token = self.reserve(a, 3).token
        result = self.budget.transfer(b, sent=4)
        self.assertEqual((result.reason, result.scope), ("TOTAL_BYTES_LIMIT", "b"))
        self.settle(token, 0)

    def test_broken_close_descriptor_preserves_connector_error_priority(self):
        class BrokenClose(FakeStream):
            @property
            def close(self):
                raise ValueError()
        result = self.connect(BrokenClose())
        self.assertEqual((result.result.reason, result.result.error, result.result.close_error),
                         ("PEER_ERROR", "ValueError", "ValueError"))
        self.assertEqual(self.session.connection_state(result.connection_id).cleanup, "FAILED")
        self.assertEqual(self.budget.snapshot().concurrent_connections, 1)

    def test_noncallable_close_preserves_invalid_handle_diagnostics(self):
        handle = FakeStream()
        handle.close = 1
        result = self.connect(handle)
        self.assertEqual((result.result.reason, result.result.error, result.result.close_error),
                         ("DIAL_INVALID_HANDLE", None, "TypeError"))
        self.assertEqual(self.session.connection_state(result.connection_id).cleanup, "FAILED")
        self.assertEqual(self.budget.snapshot().concurrent_connections, 1)

    def test_fix_major1_blocked_transfer_keeps_state_and_allows_later_reservation(self):
        a = self.ready()
        b = self.ready(FakeStream(), "b")
        token = self.reserve(a, 6).token
        snapshots = {scope: self.budget.snapshot(scope) for scope in (None, "a", "b")}
        modes = dict(self.budget._byte_modes)
        tokens = dict(self.budget._tokens)
        operations = set(self.budget._operations)
        self.assertEqual(self.budget.transfer(b, sent=5).reason, "WOULD_BLOCK")
        self.assertEqual(self.budget._byte_modes, modes)
        self.assertEqual(self.budget._operations, operations)
        self.assertEqual(set(self.budget._tokens), set(tokens))
        for key, issued in tokens.items():
            self.assertIs(self.budget._tokens[key], issued)
        for scope, snapshot in snapshots.items():
            self.assertEqual(self.budget.snapshot(scope), snapshot)
        self.settle(token, 0)
        later = self.reserve(b, 6, tunnel_id="b", operation="after_block")
        self.assertTrue(later.allowed)
        self.settle(later.token, 2)
        self.assertEqual(self.budget.snapshot().confirmed_bytes, 2)
        with self.assertRaises(ValueError):
            self.budget.transfer(b, sent=2)
        self.invariant()

    def test_fix_major2_interrupted_peer_close_lookup_failure_never_retries(self):
        peer_error = KeyboardInterrupt("original peer interruption")
        close_error = OSError("original cleanup lookup failure")
        class LookupFailure(FakeStream):
            def __init__(self):
                super().__init__()
                self.lookups = 0
                self.peer_action = raises(peer_error)

            @property
            def close(self):
                self.lookups += 1
                if self.lookups == 1:
                    raise close_error
                return self.close_on_retry

            def close_on_retry(self):
                self.events.append(("close",))
                return None

        handle = LookupFailure()
        self.budget._attempt_limits = replace(self.config, concurrent_connections=1)
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.connect(handle)
        self.assertIs(raised.exception, peer_error)
        self.assertIn("connector close failed: OSError", raised.exception.__notes__)
        self.assertEqual(handle.lookups, 1)
        self.assertEqual(handle.events, [("peer",)])
        state = self.session.connection_state(1)
        self.assertEqual((state.phase, state.cleanup, state.cleanup_error, state.in_flight),
                         ("STOPPED", "UNCONFIRMED", "OSError", False))
        self.assertEqual(self.session.stop_reason, "CONNECT_INTERRUPTED")
        before = self.budget.snapshot()
        self.assertEqual((before.connection_attempts, before.total_connections,
                          before.concurrent_connections, before.pending_connections), (1, 1, 1, 0))
        self.session.stop("SECOND")
        self.session.poll()
        rejected = self.connect(FakeStream(), "b", dialer=raises(AssertionError("must not dial")))
        self.assertFalse(rejected.allowed)
        self.assertEqual(rejected.reason, "CONNECT_INTERRUPTED")
        self.assertEqual(self.budget.snapshot(), before)
        self.assertEqual(handle.lookups, 1)
        self.assertEqual(handle.events, [("peer",)])

    def test_fix_major2_interrupted_peer_keeps_other_unobserved_close_failures(self):
        for error_type in (AttributeError, TypeError, SystemExit):
            with self.subTest(error_type=error_type):
                self.setUp()
                peer_error = KeyboardInterrupt("peer")
                class UnobservedClose(FakeStream):
                    def __init__(self):
                        super().__init__()
                        self.lookups = 0
                        self.peer_action = raises(peer_error)

                    @property
                    def close(self):
                        self.lookups += 1
                        if error_type is TypeError:
                            return None  # Connector's attempted call raises TypeError.
                        raise error_type("close lookup")

                handle = UnobservedClose()
                with self.assertRaises(KeyboardInterrupt) as raised:
                    self.connect(handle)
                self.assertIs(raised.exception, peer_error)
                self.assertIn("connector close failed: " + error_type.__name__,
                              raised.exception.__notes__)
                self.assertEqual(handle.lookups, 1)
                state = self.session.connection_state(1)
                self.assertEqual((state.cleanup, state.cleanup_error),
                                 ("UNCONFIRMED", error_type.__name__))
                self.assertEqual(self.budget.snapshot().concurrent_connections, 1)
                self.session.stop("SECOND")
                self.assertEqual(handle.lookups, 1)

    def test_fix_major2_pre_handoff_interruption_keeps_session_cleanup_responsibility(self):
        original = self.budget.connected
        interruption = KeyboardInterrupt("before Connector acquired facade")
        def connected(cid):
            original(cid)
            raise interruption
        self.budget.connected = connected
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.connect()
        self.assertIs(raised.exception, interruption)
        self.assertEqual(self.handle.events, [("close",)])
        state = self.session.connection_state(1)
        self.assertEqual((state.phase, state.cleanup, state.cleanup_error),
                         ("STOPPED", "SUCCEEDED", None))
        snapshot = self.budget.snapshot()
        self.assertEqual((snapshot.connection_attempts, snapshot.total_connections,
                          snapshot.concurrent_connections, snapshot.pending_connections), (1, 1, 0, 0))
