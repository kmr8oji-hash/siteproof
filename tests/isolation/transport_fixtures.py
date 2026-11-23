"""TEST ONLY: exact dynamic loopback endpoint capability, never production policy.

The real policy rejects loopback and non-443 ports. This test subclass substitutes
only target opening, using the same DNS validation, session admission and numeric
peer check. HTTP parsing, DNS waiter, socket dialer, relay and cleanup stay real.
No synthetic public peer, global monkeypatch of policy, or external DNS is used.
"""

import select
import socket
import threading

from src.isolation.connect_dns import DnsResolution, _resolution_reason
from src.isolation.connector import ConnectorResult, _peer_reason
from src.isolation.destination import check_authority
from src.isolation.quota_session import SessionConnectResult
from src.isolation.transport import ConnectTransport, _ResolverWaiter


class ControlledResolver:
    def __init__(self, addresses=("127.0.0.1",), *, result=None, release=None):
        self.addresses, self.result, self.release = addresses, result, release
        self.entered = threading.Event()
        self.calls = []

    def resolve_complete(self, hostname):
        self.calls.append(hostname)
        self.entered.set()
        if self.release is not None:
            if not self.release.wait(3):
                raise TimeoutError("test failed to release DNS fixture")
        return self.result or DnsResolution(hostname, "COMPLETE", True, True, self.addresses)


class FixtureTransport(ConnectTransport):
    def __init__(self, *args, endpoint, **kwargs):
        if endpoint[0] != "127.0.0.1" or type(endpoint[1]) is not int or not 0 < endpoint[1] < 65536:
            raise ValueError("exact loopback fixture endpoint required")
        super().__init__(*args, **kwargs)
        self.endpoint = endpoint
        self.authority = b"fixture.invalid:" + str(endpoint[1]).encode("ascii")

    def _open_target(self, tunnel, authority, deadline):
        # Dynamic ports are accepted only for this exact fixture capability.
        if authority != self.authority or not check_authority(
                self.policy, "fixture.invalid", 443).allowed:
            return SessionConnectResult(False, "FIXTURE_AUTHORITY_DENIED")

        def invoke(dial):
            try:
                resolution = _ResolverWaiter(self, deadline).resolve_complete("fixture.invalid")
            except (TimeoutError, OSError):
                return ConnectorResult(False, "DNS_TIMEOUT_OR_ERROR")
            reason = _resolution_reason(resolution, "fixture.invalid", self.dns_limits)
            if reason != "ALLOW":
                return ConnectorResult(False, reason)
            # No additional IP, duplicate, alias, address family or endpoint allowed.
            if resolution.addresses != ("127.0.0.1",):
                return ConnectorResult(False, "FIXTURE_IP_DENIED")
            try:
                handle = dial(*self.endpoint)
            except Exception as exc:
                return ConnectorResult(False, "DIAL_ERROR", error=type(exc).__name__)
            reason = _peer_reason(handle.getpeername(), *self.endpoint)
            if reason != "ALLOW":
                handle.close()
                return ConnectorResult(False, reason)
            return ConnectorResult(True, "ALLOW", selected_ip=self.endpoint[0], handle=handle)

        return self.session._connect(tunnel, lambda ip, port: self._dial(ip, port, deadline), invoke)


class EchoFixture:
    def __init__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.setblocking(False)
        self.address = self.listener.getsockname()
        self.halt = threading.Event()
        self.lock = threading.Lock()
        self.accepted = 0
        self.received = bytearray()
        self.clients, self.workers = [], []
        self.thread = threading.Thread(target=self._accept, name="fixture-listener")
        self.thread.start()

    def _accept(self):
        while not self.halt.is_set():
            if not select.select([self.listener], [], [], .01)[0]:
                continue
            sock, _ = self.listener.accept()
            sock.settimeout(.05)
            with self.lock:
                self.accepted += 1
                self.clients.append(sock)
                worker = threading.Thread(target=self._echo, args=(sock,), name="fixture-echo")
                self.workers.append(worker)
                worker.start()

    def _echo(self, sock):
        try:
            while not self.halt.is_set():
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    return
                with self.lock:
                    self.received.extend(data)
                sock.sendall(data)
        except OSError:
            pass
        finally:
            sock.close()

    def disconnect(self):
        with self.lock:
            for sock in self.clients:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def stop(self):
        self.halt.set()
        self.thread.join(1)
        self.listener.close()
        for worker in self.workers:
            worker.join(1)
        return (not self.thread.is_alive() and not any(t.is_alive() for t in self.workers)
                and all(s.fileno() == -1 for s in self.clients))
