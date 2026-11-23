"""In-memory QuotaSession -> FrameReader composition, not a production adapter.

All reads traverse real session accounting and delivery. Session refusal or
temporary nonprogress raises OSError in this fixture; neither becomes EOF.
This test-only policy does not define production cancellation/timeout mapping.
No sockets, DNS, files, threads, sleeps, S1 imports or host configuration.
"""

import unittest

from src.isolation.budget import BudgetLimits, NetworkBudget
from src.isolation.connect_dns import DnsLimits, DnsResolution
from src.isolation.destination import AllowedDestination, DestinationPolicy
from src.isolation.frames import FrameLimits, FrameReader, TrustedContext
from src.isolation.quota_session import IoLimits, QuotaSession
from src.isolation.termination import TerminationLimits
from tests.isolation import wire_fixtures as wire


RECORDS = (("HTTP_RECORD", b"http-record"), ("LOAD_RECORD", b"load-record"))
PACKETS = tuple(wire.packet(wire.header(i, kind, len(payload)), payload)
                for i, (kind, payload) in enumerate(RECORDS))
WIRE = b"".join(PACKETS) + wire.end(len(RECORDS))


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class MemoryHandle:
    def __init__(self, data, *, peer=("8.8.8.8", 443), fragment=7):
        self.data = data
        self.peer = peer
        self.fragment = fragment
        self.offset = 0
        self.read_sizes = []
        self.eof_reads = 0
        self.close_calls = 0
        self.on_read = None

    def getpeername(self):
        return self.peer

    def read(self, size):
        assert size > 0 and not self.close_calls
        self.read_sizes.append(size)
        if self.on_read is not None:
            self.on_read(self, size)
        part = self.data[self.offset:self.offset + min(size, self.fragment)]
        self.offset += len(part)
        if not part:
            self.eof_reads += 1
        return part

    def close(self):
        self.close_calls += 1


class MemorySink:
    def __init__(self):
        self.data = bytearray()

    def write(self, data):
        self.data.extend(data)
        return len(data)


class SessionSource:
    """Bounded synchronous test source; never repairs bytes or invents EOF."""

    def __init__(self, session, connection_id):
        self.session = session
        self.connection_id = connection_id
        self.delivered = bytearray()
        self.requests = []
        self.before_read = None

    def read(self, size):
        assert type(size) is int and size > 0
        self.requests.append(size)
        if self.before_read is not None:
            self.before_read(self, size)
        result = self.session.read(self.connection_id, size)
        if result.reason == "EOF":
            assert result.count == 0
            assert self.session.connection_state(self.connection_id).buffered_bytes == 0
            return b""
        if result.reason != "ALLOW" or not result.count:
            raise OSError("test source did not receive bytes: " + result.reason)
        sink = MemorySink()
        delivery = self.session.deliver(self.connection_id, sink)
        if delivery.reason != "ALLOW" or delivery.count != result.count:
            raise OSError("test source could not deliver bytes: " + delivery.reason)
        part = bytes(sink.data)
        assert len(part) == result.count and len(part) <= size
        self.delivered.extend(part)
        return part


class Resolver:
    def __init__(self, addresses=("8.8.8.8",), action=None):
        self.addresses = addresses
        self.action = action
        self.calls = []

    def resolve_complete(self, hostname):
        self.calls.append(hostname)
        if self.action is not None:
            self.action()
        return DnsResolution(hostname, "COMPLETE", True, True, self.addresses)


class SessionFixture:
    def __init__(self, data=WIRE, *, byte_limit=4096, duration=100,
                 idle=20, peer=("8.8.8.8", 443)):
        self.clock = FakeClock()
        limits = BudgetLimits(byte_limit, 4, 4, 4, duration)
        self.budget = NetworkBudget(limits, limits, clock=self.clock)
        self.session = QuotaSession("job-1", self.budget, IoLimits(11, 13),
                                    termination_limits=TerminationLimits(10, idle))
        assert self.session.open_tunnel("stream").allowed
        self.policy = DestinationPolicy((AllowedDestination("fixture.invalid", 443),))
        self.handle = MemoryHandle(data, peer=peer)
        self.dials = []
        self.source = None

    def dial(self, ip, port):
        self.dials.append((ip, port))
        return self.handle

    def connect(self, resolver=None):
        if resolver is None:
            result = self.session.connect("stream", self.policy, "fixture.invalid",
                                          ("8.8.8.8",), dialer=self.dial)
        else:
            result = self.session.connect_target(
                "stream", self.policy, b"fixture.invalid:443", resolver=resolver,
                dialer=self.dial, limits=DnsLimits(4, 128))
        if result.allowed:
            self.source = SessionSource(self.session, result.connection_id)
        return result

    def read_frames(self, *, timeout=200):
        assert self.source is not None
        return FrameReader(self.source, TrustedContext("job-1", "attempt-1", 1),
                           FrameLimits(timeout_seconds=timeout), clock=self.clock).read()

    def finish(self):
        self.session.stop("FIXTURE_DONE")
        self.session.run_cleanup()


class SessionFixtureCase(unittest.TestCase):
    def connected(self, data=WIRE, **kwargs):
        fixture = SessionFixture(data, **kwargs)
        self.addCleanup(fixture.finish)
        self.assertTrue(fixture.connect().allowed)
        return fixture

    def assert_prefix(self, result, count):
        self.assertEqual(result.summary.frame_count, count)
        self.assertEqual([f.seq for f in result.frames], list(range(count)))
        self.assertEqual([f.payload for f in result.frames],
                         [p for _, p in RECORDS[:count]])
        self.assertEqual(result.summary.total_payload_bytes,
                         sum(len(p) for _, p in RECORDS[:count]))
        self.assertTrue(all((f.job_id, f.attempt_id, f.lease_epoch) ==
                            ("job-1", "attempt-1", 1) for f in result.frames))

    def assert_closed_once(self, fixture, reason):
        fixture.session.run_cleanup()
        fixture.session.run_cleanup()
        snap = fixture.session.termination_snapshot()
        self.assertEqual((snap.state, snap.reason), ("CLOSED", reason))
        self.assertEqual((snap.reserved_bytes, snap.in_flight_io,
                          snap.occupied_connections, snap.buffered_bytes), (0, 0, 0, 0))
        self.assertEqual(fixture.handle.close_calls, 1)
