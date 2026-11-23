"""SITEPROOF-LOCAL-TRANSPORT-01 T01..T10, real loopback TCP only.

These task-local IDs are NOT formal project T01-T21 acceptance numbers.
"""

from dataclasses import replace
import select
import socket
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src.isolation.budget import BudgetLimits, NetworkBudget
from src.isolation.connect_dns import DnsLimits, DnsResolution
from src.isolation.destination import AllowedDestination, DestinationPolicy
from src.isolation.quota_session import IoLimits, QuotaSession
from src.isolation.termination import TerminationLimits
from src.isolation.transport import ConnectTransport, SocketHandle, SystemResolver, TransportLimits
from transport_fixtures import ControlledResolver, EchoFixture, FixtureTransport


VIOLATIONS = []


def network_boundary(event, args):
    if event == "socket.getaddrinfo":
        VIOLATIONS.append(event)
        raise AssertionError("external/system DNS is forbidden in this suite")
    if event in ("socket.bind", "socket.connect"):
        address = args[1]
        if type(address) is not tuple or address[0] != "127.0.0.1":
            VIOLATIONS.append((event, address))
            raise AssertionError("only numeric 127.0.0.1 fixture traffic allowed")


sys.addaudithook(network_boundary)


def wait_for(predicate, timeout=2):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        threading.Event().wait(.005)
    return bool(predicate())


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.fixture = EchoFixture()
        self.addCleanup(self._clean_fixture)
        self.clients = []
        self.proxies = []
        self.releases = []
        self.addCleanup(self._clean_proxies)

    def _clean_fixture(self):
        self.assertTrue(self.fixture.stop(), "fixture sockets/threads leaked")

    def _clean_proxies(self):
        for release in self.releases:
            release.set()
        for client in self.clients:
            client.close()
        for proxy in self.proxies:
            self.assertTrue(proxy.stop(), "proxy/DNS thread or quota leaked")
            self.assertEqual(proxy._listener.fileno(), -1)
            self.assertEqual(len(proxy._clients), 0)
            snapshot = proxy.session.termination_snapshot()
            self.assertEqual((snapshot.reserved_bytes, snapshot.occupied_connections,
                              snapshot.in_flight_io, snapshot.buffered_bytes), (0, 0, 0, 0))
            self.assertEqual(snapshot.unconfirmed_handles, 0)
        self.assertEqual(VIOLATIONS, [])

    def proxy(self, *, byte_limit=65536, connections=8, concurrent=4, idle=1,
              connect=.3, duration=4, header=.3, max_clients=8, resolver=None,
              production=False, endpoint=None, shutdown=1):
        budget = NetworkBudget(BudgetLimits(byte_limit, connections, concurrent, 16, duration),
                               BudgetLimits(byte_limit, connections, concurrent, 16, duration))
        session = QuotaSession("transport-job", budget, IoLimits(256, 1024),
                               termination_limits=TerminationLimits(connect, idle))
        cls = ConnectTransport if production else FixtureTransport
        kwargs = {} if production else {"endpoint": endpoint or self.fixture.address}
        proxy = cls(session, DestinationPolicy((AllowedDestination("fixture.invalid", 443),)),
                    resolver or ControlledResolver(), DnsLimits(8, 512),
                    TransportLimits(1024, header, .005, max_clients, shutdown), **kwargs)
        proxy.start()
        self.proxies.append(proxy)
        return proxy

    def client(self, proxy):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(1)
        client.connect(proxy.address)
        self.clients.append(client)
        return client

    def request(self, proxy, *, authority=None, raw=None):
        client = self.client(proxy)
        authority = authority or getattr(proxy, "authority", b"fixture.invalid:443")
        data = raw or b"CONNECT " + authority + b" HTTP/1.1\r\nHost: " + authority + b"\r\n\r\n"
        client.sendall(data)
        response = bytearray()
        while not response.endswith(b"\r\n\r\n"):
            try:
                part = client.recv(1024)
            except ConnectionResetError:
                break
            if not part:
                break
            response.extend(part)
        return client, bytes(response)

    def tunnel(self, proxy):
        before = self.fixture.accepted
        client, response = self.request(proxy)
        self.assertTrue(response.startswith(b"HTTP/1.1 200 "), response)
        self.assertTrue(wait_for(lambda: self.fixture.accepted > before))
        return client

    def closed(self, client):
        try:
            return client.recv(1) == b""
        except (ConnectionResetError, ConnectionAbortedError):
            return True

    def test_T01_connect_success_after_actual_peer_verified(self):
        proxy = self.proxy()
        self.tunnel(proxy)
        self.assertEqual(self.fixture.accepted, 1)
        self.assertEqual(proxy.session.budget.snapshot().total_connections, 1)
        self.assertEqual(proxy.session.budget.snapshot().concurrent_connections, 1)

    def test_T02_bidirectional_payload_charged_once(self):
        proxy = self.proxy()
        client = self.tunnel(proxy)
        client.sendall(b"hello-world")
        received = b""
        while len(received) < 11:
            received += client.recv(11 - len(received))
        self.assertEqual(received, b"hello-world")
        self.assertEqual(proxy.session.budget.snapshot().total_bytes, 22)
        client.close()
        self.assertTrue(wait_for(lambda: proxy.session.budget.snapshot().concurrent_connections == 0))
        self.assertIsNone(proxy.session.stop_reason)

    def test_T03_production_loopback_denied_no_arrival(self):
        proxy = self.proxy(production=True)
        _, response = self.request(proxy)
        self.assertNotIn(b"200", response)
        self.assertEqual(self.fixture.accepted, 0)
        self.assertEqual(proxy.session.budget.snapshot().connection_attempts, 0)

    def test_T03_forbidden_authority_never_resolved(self):
        resolver = ControlledResolver()
        proxy = self.proxy(production=True, resolver=resolver)
        for authority in (b"127.0.0.1:443", b"169.254.169.254:443", b"other.invalid:443",
                          b"fixture.invalid:80", b"fixture.invalid.:443", b"fixture.invalid:0443"):
            with self.subTest(authority=authority):
                _, response = self.request(proxy, authority=authority)
                self.assertNotIn(b"200", response)
        self.assertEqual(resolver.calls, [])
        self.assertEqual(self.fixture.accepted, 0)

    def test_T04_invalid_multiple_and_mismatching_dns(self):
        good = DnsResolution("fixture.invalid", "COMPLETE", True, True, ("127.0.0.1",))
        cases = [replace(good, query_hostname="other.invalid"), replace(good, aaaa_complete=False),
                 replace(good, addresses=("127.0.0.1", "8.8.8.8")),
                 replace(good, addresses=("127.0.0.1", "127.0.0.1")),
                 replace(good, addresses=("bad-ip",)), replace(good, status="TIMEOUT"),
                 replace(good, addresses=()), replace(good, addresses=("::1",))]
        for result in cases:
            with self.subTest(result=result):
                proxy = self.proxy(resolver=ControlledResolver(result=result))
                _, response = self.request(proxy)
                self.assertNotIn(b"200", response)
        self.assertEqual(self.fixture.accepted, 0)

    def test_T04_production_mixed_public_private_denied_without_dial(self):
        proxy = self.proxy(production=True, resolver=ControlledResolver(("8.8.8.8", "127.0.0.1")))
        with patch.object(proxy, "_dial", side_effect=AssertionError("must not dial")):
            _, response = self.request(proxy)
        self.assertNotIn(b"200", response)
        self.assertEqual(self.fixture.accepted, 0)

    def test_T04_system_resolver_adapter_uses_both_families_without_real_dns(self):
        def lookup(host, port, family, kind, proto):
            self.assertEqual((host, port, kind, proto), ("fixture.invalid", 443, socket.SOCK_STREAM, socket.IPPROTO_TCP))
            ip = "127.0.0.1" if family == socket.AF_INET else "::1"
            return [(family, kind, proto, "", (ip, port))]
        with patch("socket.getaddrinfo", side_effect=lookup) as query:
            result = SystemResolver().resolve_complete("fixture.invalid")
        self.assertEqual(query.call_count, 2)
        self.assertEqual(result.addresses, ("127.0.0.1", "::1"))
        self.assertTrue(result.a_complete and result.aaaa_complete)

    def test_T04_actual_handle_peer_mismatch_is_closed_before_success(self):
        proxy = self.proxy()
        original_peer = SocketHandle.getpeername
        def wrong_peer(handle):
            ip, port = original_peer(handle)
            return ip, (port % 65535) + 1
        with patch.object(SocketHandle, "getpeername", wrong_peer):
            _, response = self.request(proxy)
        self.assertNotIn(b"200", response)
        self.assertEqual(proxy.session.stop_reason, "PEER_MISMATCH")
        self.assertEqual(proxy.session.budget.snapshot().concurrent_connections, 0)

    def test_T05_quota_stops_real_forwarding(self):
        proxy = self.proxy(byte_limit=20)
        client = self.tunnel(proxy)
        client.sendall(b"x" * 256)
        self.assertTrue(wait_for(lambda: proxy.session.stop_reason is not None))
        self.assertEqual(proxy.session.stop_reason, "TOTAL_BYTES_LIMIT")
        self.assertLessEqual(len(self.fixture.received), 20)
        self.assertEqual(proxy.session.budget.snapshot().total_bytes, 20)

    def test_T05_parallel_tunnels_share_atomic_job_byte_budget(self):
        proxy = self.proxy(byte_limit=100)
        clients = [self.tunnel(proxy) for _ in range(3)]
        gate = threading.Barrier(4)
        def send(client):
            gate.wait()
            try:
                client.sendall(b"x" * 100)
            except OSError:
                pass
        workers = [threading.Thread(target=send, args=(c,)) for c in clients]
        for worker in workers:
            worker.start()
        gate.wait()
        for worker in workers:
            worker.join(1)
            self.assertFalse(worker.is_alive())
        self.assertTrue(wait_for(lambda: proxy.session.stop_reason is not None))
        self.assertLessEqual(proxy.session.budget.snapshot().total_bytes, 100)
        self.assertLessEqual(len(self.fixture.received), 100)

    def test_T06_concurrency_limit_rejects_second_without_arrival(self):
        proxy = self.proxy(concurrent=1)
        self.tunnel(proxy)
        _, response = self.request(proxy)
        self.assertNotIn(b"200", response)
        self.assertEqual(self.fixture.accepted, 1)
        self.assertEqual(proxy.session.stop_reason, "CONCURRENT_CONNECTIONS_LIMIT")

    def test_T06_cumulative_connections_not_refunded_by_finish(self):
        proxy = self.proxy(connections=1)
        client = self.tunnel(proxy)
        client.close()
        self.assertTrue(wait_for(lambda: proxy.session.budget.snapshot().concurrent_connections == 0))
        _, response = self.request(proxy)
        self.assertNotIn(b"200", response)
        self.assertEqual(self.fixture.accepted, 1)
        self.assertEqual(proxy.session.budget.snapshot().total_connections, 1)

    def test_T07_idle_timeout_releases_connection(self):
        proxy = self.proxy(idle=.08)
        client = self.tunnel(proxy)
        self.assertTrue(wait_for(lambda: proxy.session.stop_reason == "IDLE_TIMEOUT"))
        self.assertTrue(self.closed(client))

    def test_T07_dns_timeout_no_success_and_late_result_not_dialed(self):
        release = threading.Event()
        self.releases.append(release)
        resolver = ControlledResolver(release=release)
        proxy = self.proxy(resolver=resolver, connect=.06)
        start = time.monotonic()
        _, response = self.request(proxy)
        self.assertLess(time.monotonic() - start, .8)
        self.assertNotIn(b"200", response)
        self.assertEqual(self.fixture.accepted, 0)
        release.set()
        self.assertTrue(wait_for(lambda: not any(t.is_alive() for t in proxy._dns)))
        self.assertEqual(self.fixture.accepted, 0)

    def test_T07_job_deadline_stops_idle_client(self):
        proxy = self.proxy(duration=.15, idle=2)
        client = self.tunnel(proxy)
        self.assertTrue(wait_for(lambda: proxy.session.stop_reason is not None))
        self.assertEqual(proxy.session.stop_reason, "DEADLINE")
        self.assertTrue(self.closed(client))

    def test_T07_stalled_connect_uses_real_dialer_deadline_and_closes_socket(self):
        proxy = self.proxy()
        # Controlled nonprogress: select never reports connect completion.
        # A real loopback socket is acquired and must close on the deadline.
        actual_socket = socket.socket
        acquired = []
        def create(*args, **kwargs):
            sock = actual_socket(*args, **kwargs)
            acquired.append(sock)
            return sock
        original_select = select.select
        def stall(read, write, errors, timeout):
            if write and not read:
                threading.Event().wait(min(timeout, .005))
                return [], [], []
            return original_select(read, write, errors, timeout)
        # Force the OS' immediate-success case into the pending branch as well.
        class PendingSocket:
            def __init__(self, *args, **kwargs):
                self.sock = create(*args, **kwargs)
            def __getattr__(self, name):
                return getattr(self.sock, name)
            def connect_ex(self, address):
                self.sock.connect_ex(address)
                return 10035 if sys.platform == "win32" else 115
        start = time.monotonic()
        socket_api = SimpleNamespace(socket=PendingSocket, SOCK_STREAM=socket.SOCK_STREAM,
                                     AF_INET=socket.AF_INET,
                                     AF_INET6=socket.AF_INET6, SOL_SOCKET=socket.SOL_SOCKET,
                                     SO_ERROR=socket.SO_ERROR)
        with patch("src.isolation.transport.socket", socket_api), patch(
                "src.isolation.transport.select", SimpleNamespace(select=stall)):
            with self.assertRaises(TimeoutError):
                proxy._dial(*self.fixture.address, time.monotonic() + .06)
        self.assertLess(time.monotonic() - start, .8)
        self.assertTrue(acquired and all(s.fileno() == -1 for s in acquired))

    def test_T08_cancel_closes_both_sockets_and_reservations(self):
        proxy = self.proxy()
        client = self.tunnel(proxy)
        proxy.cancel()
        self.assertTrue(self.closed(client))
        self.assertTrue(proxy.stop())
        self.assertEqual(proxy.session.stop_reason, "CANCELLED")

    def test_T08_uncancellable_dns_is_reported_until_fixture_releases_it(self):
        release = threading.Event()
        self.releases.append(release)
        resolver = ControlledResolver(release=release)
        proxy = self.proxy(resolver=resolver, connect=1, shutdown=.08)
        client = self.client(proxy)
        client.sendall(b"CONNECT " + proxy.authority + b" HTTP/1.1\r\nHost: " + proxy.authority + b"\r\n\r\n")
        self.assertTrue(resolver.entered.wait(1))
        self.assertFalse(proxy.stop(), "must report the still-running resolver")
        self.assertTrue(self.closed(client))
        self.assertEqual(proxy.session.termination_snapshot().state, "CLOSED")
        self.assertTrue(any(t.is_alive() for t in proxy._dns))
        self.assertEqual(self.fixture.accepted, 0)
        release.set()
        self.assertTrue(wait_for(lambda: not any(t.is_alive() for t in proxy._dns)))
        self.assertTrue(proxy.stop())

    def test_finish_connection_defers_close_until_inflight_io_settles(self):
        # Exercise the additive QuotaSession API without changing old contracts.
        proxy = self.proxy()
        session = proxy.session
        entered, release = threading.Event(), threading.Event()
        self.releases.append(release)
        class Handle:
            closed = 0
            def getpeername(self):
                return "8.8.8.8", 443
            def read(self, size):
                entered.set()
                if not release.wait(1):
                    raise TimeoutError()
                return b"x"
            def close(self):
                self.closed += 1
        handle = Handle()
        session.open_tunnel("manual")
        result = session.connect("manual", DestinationPolicy(
            (AllowedDestination("fixture.invalid", 443),)), "fixture.invalid",
            ("8.8.8.8",), dialer=lambda *args: handle)
        self.assertTrue(result.allowed)
        worker = threading.Thread(target=session.read, args=(result.connection_id, 1))
        worker.start()
        try:
            self.assertTrue(entered.wait(1))
            self.assertFalse(session.finish_connection(result.connection_id))
            self.assertEqual(handle.closed, 0)
        finally:
            release.set()
            worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertTrue(session.finish_connection(result.connection_id))
        self.assertTrue(session.finish_connection(result.connection_id))
        self.assertEqual(handle.closed, 1)
        self.assertEqual(session.budget.snapshot().concurrent_connections, 0)

    def test_T08_client_disconnect_releases_one_tunnel_only(self):
        proxy = self.proxy()
        first, second = self.tunnel(proxy), self.tunnel(proxy)
        first.close()
        self.assertTrue(wait_for(lambda: proxy.session.budget.snapshot().concurrent_connections == 1))
        second.sendall(b"ok")
        self.assertEqual(second.recv(2), b"ok")
        self.assertIsNone(proxy.session.stop_reason)

    def test_T08_upstream_disconnect_releases_tunnel(self):
        proxy = self.proxy()
        client = self.tunnel(proxy)
        self.fixture.disconnect()
        self.assertTrue(self.closed(client))
        self.assertTrue(wait_for(lambda: proxy.session.budget.snapshot().concurrent_connections == 0))

    def test_T09_malformed_headers_never_dial(self):
        proxy = self.proxy()
        a = proxy.authority
        requests = [b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
                    b"CONNECT " + a + b" HTTP/1.0\r\nHost: " + a + b"\r\n\r\n",
                    b"CONNECT  " + a + b" HTTP/1.1\r\nHost: " + a + b"\r\n\r\n",
                    b"CONNECT " + a + b" HTTP/1.1\r\nHost: wrong\r\n\r\n",
                    b"CONNECT " + a + b" HTTP/1.1\r\nHost: " + a + b"\r\nHost: " + a + b"\r\n\r\n",
                    b"CONNECT " + a + b" HTTP/1.1\r\nHost: " + a + b"\r\nContent-Length: 0\r\n\r\n",
                    b"CONNECT " + a + b" HTTP/1.1\r\nHost: " + a + b"\r\n\r\nearly",
                    b"x" * 1025]
        for raw in requests:
            with self.subTest(raw=raw):
                _, response = self.request(proxy, raw=raw)
                self.assertNotIn(b"200", response)
        self.assertEqual(self.fixture.accepted, 0)

    def test_T09_header_deadline_and_worker_capacity(self):
        proxy = self.proxy(header=.06, max_clients=1)
        slow = self.client(proxy)
        slow.sendall(b"C")
        self.assertTrue(wait_for(lambda: len(proxy._clients) == 1))
        extra = self.client(proxy)
        self.assertTrue(self.closed(extra))
        self.assertTrue(self.closed(slow))
        self.assertEqual(self.fixture.accepted, 0)

    def test_T10_upstream_refusal_no_success_no_occupancy(self):
        # Bound but non-listening endpoint prevents accidental port reassignment.
        reserved = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(reserved.close)
        reserved.bind(("127.0.0.1", 0))
        proxy = self.proxy(endpoint=reserved.getsockname())
        _, response = self.request(proxy)
        self.assertNotIn(b"200", response)
        self.assertEqual(proxy.session.budget.snapshot().concurrent_connections, 0)
        self.assertEqual(self.fixture.accepted, 0)

    def test_T10_stopped_proxy_cannot_connect_or_fallback(self):
        proxy = self.proxy()
        self.assertTrue(proxy.stop())
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(client.close)
        client.settimeout(.3)
        with self.assertRaises(OSError):
            client.connect(proxy.address)
        self.assertEqual(self.fixture.accepted, 0)


if __name__ == "__main__":
    unittest.main()
