"""Deterministic cross-boundary stop/DNS/peer sequences without real I/O."""

from tests.isolation.session_fixtures import (
    PACKETS, WIRE, Resolver, SessionFixture, SessionFixtureCase,
)


class SessionSequenceTests(SessionFixtureCase):
    def test_cancel_during_read_charges_late_bytes_without_delivering_them(self):
        f = self.connected()

        def cancel_during_next_frame(handle, size):
            if handle.offset == len(PACKETS[0]):
                f.session.request_cancel()

        f.handle.on_read = cancel_during_next_frame
        result = f.read_frames()
        self.assertNotEqual(result.summary.termination, "CLEAN")
        self.assert_prefix(result, 1)
        self.assertEqual(bytes(f.source.delivered), PACKETS[0])
        self.assertGreater(f.handle.offset, len(f.source.delivered))
        self.assertEqual(f.budget.snapshot().confirmed_bytes, f.handle.offset)
        self.assert_closed_once(f, "CANCELLED")

    def test_deadline_during_read_never_publishes_late_frame_bytes(self):
        f = self.connected()

        def expire_during_next_frame(handle, size):
            if handle.offset == len(PACKETS[0]):
                f.clock.now = 100

        f.handle.on_read = expire_during_next_frame
        result = f.read_frames()
        self.assertNotEqual(result.summary.termination, "CLEAN")
        self.assert_prefix(result, 1)
        self.assertEqual(bytes(f.source.delivered), PACKETS[0])
        self.assertEqual(f.budget.snapshot().confirmed_bytes, f.handle.offset)
        self.assertGreater(f.handle.offset, len(PACKETS[0]))
        self.assert_closed_once(f, "DEADLINE")

    def test_cancel_then_deadline_at_end_keeps_first_reason_and_one_close(self):
        f = self.connected()

        def stop_in_order(source, size):
            if f.handle.offset == len(WIRE):
                f.session.request_cancel()
                f.clock.now = 100
                f.session.check_termination()

        f.source.before_read = stop_in_order
        result = f.read_frames()
        self.assertNotEqual(result.summary.termination, "CLEAN")
        self.assert_prefix(result, 2)
        self.assertEqual(f.handle.eof_reads, 0)
        self.assert_closed_once(f, "CANCELLED")

    def test_deadline_then_cancel_at_end_keeps_first_reason_and_one_close(self):
        f = self.connected()

        def stop_in_order(source, size):
            if f.handle.offset == len(WIRE):
                f.clock.now = 100
                f.session.check_termination()
                f.session.request_cancel()

        f.source.before_read = stop_in_order
        result = f.read_frames()
        self.assertNotEqual(result.summary.termination, "CLEAN")
        self.assert_prefix(result, 2)
        self.assertEqual(f.handle.eof_reads, 0)
        self.assert_closed_once(f, "DEADLINE")

    def test_cancel_during_complete_dns_never_acquires_a_stream(self):
        f = SessionFixture()
        self.addCleanup(f.finish)
        resolver = Resolver(action=f.session.request_cancel)
        result = f.connect(resolver)
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "CANCELLED")
        self.assertEqual(resolver.calls, ["fixture.invalid"])
        self.assertEqual(f.dials, [])
        self.assertIsNone(f.source)
        self.assertEqual(f.budget.snapshot().connection_attempts, 0)
        self.assertEqual(f.session.termination_snapshot().state, "CLOSED")

    def test_other_approved_dns_peer_is_not_a_pin_or_a_stream_fallback(self):
        f = SessionFixture(peer=("1.1.1.1", 443))
        self.addCleanup(f.finish)
        result = f.connect(Resolver(("8.8.8.8", "1.1.1.1")))
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "PEER_MISMATCH")
        self.assertEqual(f.dials, [("8.8.8.8", 443)])
        self.assertIsNone(f.source)
        self.assertEqual(f.budget.snapshot().confirmed_bytes, 0)
        self.assert_closed_once(f, "PEER_MISMATCH")

    def test_dual_stack_dns_ipv6_pin_and_wire_quota_share_one_session(self):
        ip = "2606:4700:4700::1111"
        f = SessionFixture(byte_limit=len(PACKETS[0]), peer=(ip, 443))
        self.addCleanup(f.finish)
        resolver = Resolver(("2606:4700:4700:0:0:0:0:1111", "8.8.8.8"))
        self.assertTrue(f.connect(resolver).allowed)
        result = f.read_frames()
        self.assertEqual(resolver.calls, ["fixture.invalid"])
        self.assertEqual(f.dials, [(ip, 443)])
        self.assertNotEqual(result.summary.termination, "CLEAN")
        self.assert_prefix(result, 1)
        self.assertEqual(bytes(f.source.delivered), PACKETS[0])
        self.assertEqual(f.budget.snapshot().confirmed_bytes, len(PACKETS[0]))
        self.assert_closed_once(f, "TOTAL_BYTES_LIMIT")
