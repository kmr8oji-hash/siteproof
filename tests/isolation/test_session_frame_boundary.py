"""Real session accounting/delivery composed with the real bounded reader."""

from src.isolation.quota_session import IoWouldBlock
from tests.isolation.session_fixtures import PACKETS, RECORDS, WIRE, SessionFixtureCase, wire


class SessionFrameBoundaryTests(SessionFixtureCase):
    def test_fragmented_session_delivery_requires_end_and_observed_eof(self):
        f = self.connected()
        result = f.read_frames()
        self.assertEqual((result.summary.termination, result.reason), ("CLEAN", "COMPLETE_END"))
        self.assert_prefix(result, 2)
        self.assertEqual(bytes(f.source.delivered), WIRE)
        self.assertEqual(f.handle.eof_reads, 1)
        self.assertTrue(all(0 < n <= 11 for n in f.handle.read_sizes))
        self.assertEqual(f.budget.snapshot().confirmed_bytes, len(WIRE))
        self.assertEqual(f.budget.snapshot().reserved_bytes, 0)
        # EOF is a transport observation, not automatic session/job completion.
        self.assertEqual(f.session.termination_snapshot().state, "RUNNING")

    def test_session_eof_without_end_keeps_frames_but_never_clean(self):
        data = b"".join(PACKETS)
        f = self.connected(data)
        result = f.read_frames()
        self.assertEqual((result.summary.termination, result.reason), ("TRUNCATED", "UNEXPECTED_EOF"))
        self.assert_prefix(result, 2)
        self.assertEqual(bytes(f.source.delivered), data)
        self.assertEqual(f.budget.snapshot().confirmed_bytes, len(data))

    def test_partial_payload_is_charged_but_not_completed_as_a_frame(self):
        data = PACKETS[0] + PACKETS[1][:-2]
        f = self.connected(data)
        result = f.read_frames()
        self.assertEqual(result.summary.termination, "TRUNCATED")
        self.assert_prefix(result, 1)
        self.assertEqual(bytes(f.source.delivered), data)
        self.assertEqual(f.budget.snapshot().confirmed_bytes, len(data))

    def test_session_does_not_repair_a_missing_frame_sequence(self):
        kind, payload = RECORDS[1]
        data = PACKETS[0] + wire.packet(wire.header(2, kind, len(payload)), payload) + wire.end(3)
        f = self.connected(data)
        result = f.read_frames()
        self.assertEqual((result.summary.termination, result.reason),
                         ("PROTOCOL_ERROR", "INVALID_SEQUENCE"))
        self.assert_prefix(result, 1)
        self.assertTrue(data.startswith(bytes(f.source.delivered)))

    def test_wire_byte_quota_stops_before_end_without_filling_missing_input(self):
        f = self.connected(byte_limit=len(PACKETS[0]))
        result = f.read_frames()
        self.assertNotEqual(result.summary.termination, "CLEAN")
        self.assert_prefix(result, 1)
        self.assertEqual(bytes(f.source.delivered), PACKETS[0])
        self.assertEqual(f.budget.snapshot().confirmed_bytes, len(PACKETS[0]))
        self.assert_closed_once(f, "TOTAL_BYTES_LIMIT")

    def test_end_at_exact_wire_quota_cannot_fabricate_the_required_eof(self):
        f = self.connected(byte_limit=len(WIRE))
        result = f.read_frames()
        self.assertEqual(bytes(f.source.delivered), WIRE)
        self.assertEqual(f.handle.eof_reads, 0)
        self.assertNotEqual(result.summary.termination, "CLEAN")
        self.assert_prefix(result, 2)
        self.assertEqual(f.budget.snapshot().confirmed_bytes, len(WIRE))
        self.assert_closed_once(f, "TOTAL_BYTES_LIMIT")

    def test_cancel_between_end_and_eof_never_becomes_success(self):
        f = self.connected()

        def cancel_at_eof(source, size):
            if f.handle.offset == len(WIRE):
                f.session.request_cancel()

        f.source.before_read = cancel_at_eof
        result = f.read_frames()
        self.assertNotEqual(result.summary.termination, "CLEAN")
        self.assert_prefix(result, 2)
        self.assertEqual(bytes(f.source.delivered), WIRE)
        self.assertEqual(f.handle.eof_reads, 0)
        self.assert_closed_once(f, "CANCELLED")

    def test_temporary_would_block_is_not_substituted_with_eof(self):
        f = self.connected()

        def block_after_first(handle, size):
            if handle.offset == len(PACKETS[0]):
                raise IoWouldBlock()

        f.handle.on_read = block_after_first
        result = f.read_frames()
        self.assertEqual((result.summary.termination, result.reason),
                         ("PROTOCOL_ERROR", "SOURCE_ERROR"))
        self.assert_prefix(result, 1)
        self.assertEqual(f.handle.eof_reads, 0)
        self.assertEqual(bytes(f.source.delivered), PACKETS[0])
        self.assertIsNone(f.session.stop_reason)
        self.assertEqual(f.budget.snapshot().reserved_bytes, 0)

    def test_trailing_data_is_observed_through_accounted_delivery(self):
        f = self.connected(WIRE + b"x")
        result = f.read_frames()
        self.assertEqual((result.summary.termination, result.reason),
                         ("PROTOCOL_ERROR", "TRAILING_DATA"))
        self.assert_prefix(result, 2)
        self.assertEqual(bytes(f.source.delivered), WIRE + b"x")
        self.assertEqual(f.budget.snapshot().confirmed_bytes, len(WIRE) + 1)

    def test_reader_deadline_does_not_claim_to_cancel_the_session(self):
        f = self.connected(duration=300, idle=200)

        def advance_after_first(source, size):
            if f.handle.offset == len(PACKETS[0]):
                f.clock.now = 10

        f.source.before_read = advance_after_first
        result = f.read_frames(timeout=10)
        self.assertEqual((result.summary.termination, result.reason), ("TIMEOUT", "DEADLINE"))
        self.assert_prefix(result, 1)
        self.assertEqual(f.session.termination_snapshot().state, "RUNNING")
        self.assertEqual(f.handle.close_calls, 0)
        # The caller explicitly cleans up; the fixture invents no coupling.
        f.session.request_cancel()
        self.assert_closed_once(f, "CANCELLED")
