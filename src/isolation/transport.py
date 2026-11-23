"""Bounded loopback CONNECT listener using the existing S0 policy and Job owner.

No TLS interception, browser, OS isolation, fallback, or production limit defaults.
The system resolver is trusted and synchronous: a timed-out libc DNS call can
outlive its waiter. Worker count stays bounded and shutdown reports such workers.
Loopback upstream exceptions belong exclusively to tests, never this module.
"""

from dataclasses import dataclass
import errno
import ipaddress
import math
import select
import socket
import threading
import time

from .connect_dns import DnsLimits, DnsResolution, check_connect_authority
from .ledger import ConnectLedger
from .quota_session import IoWouldBlock, QuotaSession


@dataclass(frozen=True)
class TransportLimits:
    max_header_bytes: int
    header_timeout_seconds: float
    poll_seconds: float
    max_clients: int
    shutdown_timeout_seconds: float

    def __post_init__(self):
        for n in (self.max_header_bytes, self.max_clients):
            if type(n) is not int or n <= 0:
                raise ValueError("explicit positive integer limits required")
        for n in (self.header_timeout_seconds, self.poll_seconds,
                  self.shutdown_timeout_seconds):
            if type(n) not in (int, float) or not math.isfinite(n) or n <= 0:
                raise ValueError("explicit positive finite time limits required")


# Policy refusals of the requested destination; any other refusal is an operational failure.
_POLICY_REASONS = frozenset({
    "INVALID_AUTHORITY", "AUTHORITY_TOO_LONG", "PORT_NOT_ALLOWED", "POLICY_MISSING", "POLICY_INVALID",
    "INVALID_HOSTNAME", "INVALID_PORT", "NOT_ALLOWLISTED", "DNS_ANSWERS_INVALID", "IPV4_MAPPED_IPV6"})


def _classify(allowed, reason):
    if allowed:
        return "ALLOW", "ALLOW"
    # A DNS outcome (error, incomplete, no address) is a failure to resolve, not a refusal of the destination.
    policy = (reason in _POLICY_REASONS or reason.endswith("_ADDRESS") or reason.startswith("IPV6_")) \
        and not (reason.startswith("DNS_") and reason != "DNS_ANSWERS_INVALID")
    return ("BLOCK" if policy else "FAILED"), reason


class EmptyConnection(ValueError):
    """The peer closed before sending a single byte: no request existed to parse."""


class SystemResolver:
    """Resolve both address families; terminal NODATA is a completed family.

    The OS controls DNS routing/cache. No authenticity/freshness guarantee.
    ConnectTransport bounds the waiter, not the lifetime of getaddrinfo itself.
    """

    def resolve_complete(self, hostname):
        addresses = []
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                rows = socket.getaddrinfo(hostname, 443, family, socket.SOCK_STREAM,
                                          socket.IPPROTO_TCP)
            except socket.gaierror as exc:
                if exc.errno not in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", None)):
                    raise
                rows = []
            addresses.extend(row[4][0] for row in rows)
        return DnsResolution(hostname, "COMPLETE", True, True, tuple(addresses))


class SocketHandle:
    """Nonblocking numeric-peer adapter; close is idempotent and non-waiting."""

    def __init__(self, sock):
        self.socket = sock
        sock.setblocking(False)

    def getpeername(self):
        peer = self.socket.getpeername()
        return peer[0], peer[1]

    def read(self, size):
        try:
            return self.socket.recv(size)
        except BlockingIOError:
            raise IoWouldBlock() from None

    def write(self, data):
        try:
            return self.socket.send(data)
        except BlockingIOError:
            raise IoWouldBlock() from None

    def close(self):
        self.socket.close()


def parse_connect(header):
    """Strict HTTP/1.1 CONNECT envelope; authority policy is checked downstream.

    No request body, transfer encoding, duplicate headers, folding, pipelined
    tunnel bytes or header normalization. Exactly one matching Host is required.
    """
    if type(header) is not bytes or not header.endswith(b"\r\n\r\n"):
        raise ValueError("incomplete header")
    lines = header[:-4].split(b"\r\n")
    first = lines.pop(0).split(b" ")
    if len(first) != 3 or first[0] != b"CONNECT" or first[2] != b"HTTP/1.1":
        raise ValueError("CONNECT HTTP/1.1 required")
    authority = first[1]
    if not authority or any(c < 33 or c > 126 for c in authority):
        raise ValueError("invalid authority")
    fields = {}
    token = b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for line in lines:
        key, sep, value = line.partition(b":")
        if not sep or not key or any(c not in token for c in key):
            raise ValueError("invalid header")
        key = key.lower()
        if key in fields or any(c < 32 or c > 126 for c in value):
            raise ValueError("duplicate or invalid header")
        fields[key] = value.strip(b" ")
    if fields.get(b"host") != authority:
        raise ValueError("Host mismatch")
    if b"transfer-encoding" in fields or b"content-length" in fields:
        raise ValueError("CONNECT body forbidden")
    return authority


class _ResolverWaiter:
    def __init__(self, owner, deadline):
        self.owner, self.deadline = owner, deadline

    def resolve_complete(self, hostname):
        owner = self.owner
        done = threading.Event()
        result = []

        def run():
            try:
                result.append((True, owner.resolver.resolve_complete(hostname)))
            except BaseException as exc:
                result.append((False, exc))
            finally:
                done.set()

        with owner._lock:
            owner._dns = {t for t in owner._dns if t.is_alive()}
            if len(owner._dns) >= owner.limits.max_clients or owner._halted():
                raise TimeoutError("DNS capacity or Job stopped")
            worker = threading.Thread(target=run, name="siteproof-dns", daemon=True)
            owner._dns.add(worker)
            worker.start()
        while not done.wait(min(owner.limits.poll_seconds,
                                max(0, self.deadline - time.monotonic()))):
            if owner._halted() or time.monotonic() >= self.deadline:
                raise TimeoutError("DNS wait expired")
        worker.join()
        if owner._halted() or time.monotonic() >= self.deadline:
            raise TimeoutError("late DNS result")
        success, value = result[0]
        if not success:
            raise OSError("DNS adapter failed") from value
        return value


class ConnectTransport:
    """Explicit start/stop, one shared QuotaSession and bounded client threads.

    A tunnel closes in both directions on the first EOF (no half-close drain).
    Upstream payload bytes in both directions are charged once by QuotaSession;
    HTTP handshake, kernel buffering and TCP overhead are outside that counter.
    """

    def __init__(self, session, policy, resolver, dns_limits, limits, *, listen_port=0):
        if type(session) is not QuotaSession or session.termination_limits is None:
            raise ValueError("QuotaSession with explicit termination limits required")
        if type(dns_limits) is not DnsLimits or type(limits) is not TransportLimits:
            raise ValueError("explicit DNS and transport limits required")
        if type(listen_port) is not int or not 0 <= listen_port <= 65535:
            raise ValueError("invalid loopback listen port")
        self.listen_port = listen_port
        self.session, self.policy, self.resolver = session, policy, resolver
        self.dns_limits, self.limits = dns_limits, limits
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._clients, self._workers, self._dns = set(), set(), set()
        self._listener = self._acceptor = None
        self._started = False
        self._next_tunnel = 0
        # Trusted record of every CONNECT attempt; the allowlist is never widened by it.
        self.ledger = ConnectLedger()

    def _halted(self):
        return self._stop.is_set() or self.session.check_termination() is not None

    def start(self):
        with self._lock:
            if self._started:
                raise ValueError("single-use transport")
            self._started = True
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                else:
                    # Fixed owned runtime ports can restart after TCP TIME_WAIT.
                    # SO_REUSEPORT is deliberately not enabled.
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", self.listen_port))
                sock.listen(self.limits.max_clients)
                sock.setblocking(False)
                self.address = sock.getsockname()
                self._listener = sock
                self._acceptor = threading.Thread(target=self._accept, name="siteproof-listener")
                self._acceptor.start()
            except BaseException:
                sock.close()
                raise
        return self.address

    def _accept(self):
        listener = self._listener
        try:
            while not self._halted():
                if not select.select([listener], [], [], self.limits.poll_seconds)[0]:
                    continue
                client, _ = listener.accept()
                client.setblocking(False)
                with self._lock:
                    self._workers = {t for t in self._workers if t.is_alive()}
                    if len(self._workers) >= self.limits.max_clients or self._halted():
                        client.close()
                        self.ledger.record(None, None, "FAILED", "SESSION_STOPPED" if self._halted() else "CAPACITY_REFUSED",
                                           began=False)
                        continue
                    self._clients.add(client)
                    worker = threading.Thread(target=self._serve, args=(client,),
                                              name="siteproof-client")
                    self._workers.add(worker)
                    worker.start()
        except (OSError, ValueError):
            if not self._stop.is_set():
                self.session.stop("LISTENER_ERROR")
        finally:
            listener.close()
            if not self._stop.is_set():
                self._stop.set()

    def _header(self, client):
        deadline = time.monotonic() + self.limits.header_timeout_seconds
        data = bytearray()
        while not self._halted() and time.monotonic() < deadline:
            if len(data) >= self.limits.max_header_bytes:
                raise ValueError("header limit")
            if not select.select([client], [], [], min(self.limits.poll_seconds,
                                max(0, deadline - time.monotonic())))[0]:
                continue
            part = client.recv(min(self.session.limits.max_chunk_bytes,
                                   self.limits.max_header_bytes - len(data)))
            if not part:
                # Zero bytes received is provably no request; partial bytes stay malformed.
                raise ValueError("header EOF") if data else EmptyConnection("empty connection")
            data.extend(part)
            end = data.find(b"\r\n\r\n")
            if end >= 0:
                if end + 4 != len(data):
                    raise ValueError("early tunnel bytes")
                return parse_connect(bytes(data))
        raise TimeoutError("header timeout or Job stopped")

    def _send(self, client, data, deadline):
        while data and not self._halted() and time.monotonic() < deadline:
            if select.select([], [client], [], min(self.limits.poll_seconds,
                              max(0, deadline - time.monotonic())))[1]:
                try:
                    count = client.send(data)
                except BlockingIOError:
                    continue
                if count == 0:
                    return False
                data = data[count:]
        return not data and not self._halted()

    def _dial(self, ip, port, deadline):
        # Numeric addresses only; no create_connection/getaddrinfo fallback.
        address = ipaddress.ip_address(ip)
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.setblocking(False)
            code = sock.connect_ex((str(address), port))
            pending = (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY,
                       getattr(errno, "WSAEWOULDBLOCK", 10035))
            if code not in pending:
                raise OSError(code, "connect failed")
            while code:
                if self._halted() or time.monotonic() >= deadline:
                    raise TimeoutError("connect timeout or cancel")
                _, writable, errors = select.select([], [sock], [sock], min(
                    self.limits.poll_seconds, max(0, deadline - time.monotonic())))
                if writable or errors:
                    code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    if code:
                        raise OSError(code, "connect failed")
                    break
            if self._halted() or time.monotonic() >= deadline:
                raise TimeoutError("late connect")
            return SocketHandle(sock)
        except BaseException:
            sock.close()
            raise

    def _open_target(self, tunnel, authority, deadline):
        return self.session.connect_target(
            tunnel, self.policy, authority, resolver=_ResolverWaiter(self, deadline),
            dialer=lambda ip, port: self._dial(ip, port, deadline), limits=self.dns_limits)

    def _relay(self, client, cid):
        pending = b""
        sink = SocketHandle(client)
        while not self._halted():
            if pending:
                result = self.session.write(cid, pending)
                if result.reason not in ("ALLOW", "WOULD_BLOCK"):
                    return
                pending = pending[result.count:]
            elif select.select([client], [], [], 0)[0]:
                try:
                    pending = client.recv(self.session.limits.max_chunk_bytes)
                except BlockingIOError:
                    pending = b""
                    continue
                if not pending:
                    return
            state = self.session.connection_state(cid)
            if state.buffered_bytes:
                result = self.session.deliver(cid, sink)
            else:
                result = self.session.read(cid, self.session.limits.max_chunk_bytes)
            if result.reason == "EOF":
                return
            if result.reason not in ("ALLOW", "WOULD_BLOCK", "EMPTY"):
                return
            # Nonblocking adapters bound each call; polling also covers idle/cancel.
            self._stop.wait(self.limits.poll_seconds)

    def _serve(self, client):
        cid = None
        seen = []
        self.ledger.begin()

        def note(host, port, decision, reason):
            # Recorded when the outcome is known, not when a long-lived tunnel ends.
            if not seen:
                seen.append(True)
                self.ledger.record(host, port, decision, reason)

        try:
            try:
                authority = self._header(client)
            except TimeoutError:
                note(None, None, "FAILED", "HEADER_TIMEOUT")
                raise
            except EmptyConnection:
                note(None, None, "IDLE", "EMPTY_CONNECTION")
                raise
            except ValueError:
                note(None, None, "FAILED", "MALFORMED_CONNECT")
                raise
            approved = check_connect_authority(self.policy, authority)
            host, port = approved.hostname, approved.port
            deadline = time.monotonic() + self.session.termination_limits.connection_timeout_seconds
            with self._lock:
                self._next_tunnel += 1
                tunnel = "tcp-" + str(self._next_tunnel)
            if not self.session.open_tunnel(tunnel).allowed:
                note(host, port, "FAILED", "TUNNEL_REFUSED")
                return
            result = self._open_target(tunnel, authority, deadline)
            cid = result.connection_id
            note(host, port, *_classify(result.allowed, result.reason))
            if not result.allowed:
                self._send(client, b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n", deadline)
                return
            if not self._send(client, b"HTTP/1.1 200 Connection Established\r\n\r\n", deadline):
                return
            self._relay(client, cid)
        except (OSError, ValueError):
            # No success response or direct-network retry on any failure.
            pass
        finally:
            client.close()
            note(None, None, "FAILED", "CONNECT_ABORTED")  # Only if nothing was recorded above.
            if cid is not None:
                self.session.finish_connection(cid)
            with self._lock:
                self._clients.discard(client)

    def cancel(self):
        self.session.request_cancel()
        self._stop.set()

    def stop(self):
        self.cancel()
        deadline = time.monotonic() + self.limits.shutdown_timeout_seconds
        with self._lock:
            threads = [self._acceptor, *self._workers, *self._dns]
        for worker in threads:
            if worker is not None and worker is not threading.current_thread():
                worker.join(max(0, deadline - time.monotonic()))
        self.session.run_cleanup()
        return (not any(t is not None and t.is_alive() for t in threads)
                and self.session.termination_snapshot().state == "CLOSED")
