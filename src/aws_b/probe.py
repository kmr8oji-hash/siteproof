"""One HTTPS probe of the single deploy-time target.

Reuses the existing destination policy and pinned connector (src/isolation): the whole
DNS answer set is validated, one approved address is dialled once, and the connected peer
is compared with that address. There is no redirect following, no retry and no fallback.

This is an application-level allowlist for first-party, single-purpose code. A Lambda
function outside a VPC has no network-layer egress enforcement and none is claimed.
"""
from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, Protocol

from src.core.model import CheckOutcome
from src.core.rules import classify_http_status
from src.isolation.connector import connect_pinned

from .model import MonitorConfig

MAX_RESPONSE_HEAD_BYTES = 16 * 1024
USER_AGENT = "SiteProofMonitor/1 (+owner-operated uptime check)"


@dataclass(frozen=True)
class ProbeResult:
    outcome: CheckOutcome
    reason: str
    http_status: Optional[int] = None
    selected_ip: Optional[str] = None
    tls_not_after: Optional[str] = None
    elapsed_ms: int = 0


class Transport(Protocol):
    """Trusted adapter performing TLS and one HTTP exchange on an already pinned handle."""

    def exchange(self, handle: Any, hostname: str, path: str,
                 deadline: float) -> tuple[bytes, Optional[str]]: ...


class _Handle:
    """Socket wrapper giving the connector a (ip, port) peer for IPv4 and IPv6 alike."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock

    def getpeername(self) -> tuple[str, int]:
        peer = self.sock.getpeername()
        return peer[0], peer[1]

    def close(self) -> None:
        self.sock.close()


def system_resolver(hostname: str) -> tuple[str, ...]:
    """OS resolver; IPv4 answers first. Raises on failure; returns every address found."""
    found: dict[int, list[str]] = {socket.AF_INET: [], socket.AF_INET6: []}
    for family, _, _, _, sockaddr in socket.getaddrinfo(
            hostname, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP):
        if family in found and sockaddr[0] not in found[family]:
            found[family].append(sockaddr[0])
    return tuple(found[socket.AF_INET] + found[socket.AF_INET6])


def socket_dialer(timeout_seconds: float) -> Callable[[str, int], _Handle]:
    def dial(ip: str, port: int) -> _Handle:
        return _Handle(socket.create_connection((ip, port), timeout=timeout_seconds))
    return dial


def build_request(hostname: str, path: str) -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: {USER_AGENT}\r\n"
            "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
            ).encode("ascii")


def read_status_line(recv: Callable[[int], bytes], deadline: float,
                     clock: Callable[[], float] = time.monotonic) -> bytes:
    """Read until the first CRLF, bounded in bytes and time. The body is never read."""
    data = b""
    while b"\r\n" not in data:
        if len(data) >= MAX_RESPONSE_HEAD_BYTES:
            raise ValueError("status line too long")
        if clock() >= deadline:
            raise TimeoutError("probe deadline")
        chunk = recv(min(4096, MAX_RESPONSE_HEAD_BYTES - len(data)))
        if not chunk:
            break
        data += chunk
    return data.split(b"\r\n", 1)[0]


def parse_status_line(line: bytes) -> Optional[int]:
    parts = line.split(b" ", 2)
    if len(parts) < 2 or parts[0] not in (b"HTTP/1.1", b"HTTP/1.0"):
        return None
    code = parts[1]
    if len(code) != 3 or not code.isdigit():
        return None
    return int(code)


class TlsTransport:
    """Real adapter: certificate and hostname verification are never disabled."""

    def __init__(self) -> None:
        self._context = ssl.create_default_context()
        self._context.minimum_version = ssl.TLSVersion.TLSv1_2

    def exchange(self, handle: _Handle, hostname: str, path: str,
                 deadline: float) -> tuple[bytes, Optional[str]]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("probe deadline")
        handle.sock.settimeout(remaining)
        with self._context.wrap_socket(handle.sock, server_hostname=hostname) as tls:
            handle.sock = tls
            not_after = (tls.getpeercert() or {}).get("notAfter")
            tls.sendall(build_request(hostname, path))

            def recv(size: int) -> bytes:
                tls.settimeout(max(0.05, deadline - time.monotonic()))
                return tls.recv(size)
            return read_status_line(recv, deadline), not_after


def run_probe(config: MonitorConfig, *, resolver: Callable[[str], Any],
              dialer: Callable[[str, int], Any], transport: Transport,
              deadline: float, clock: Callable[[], float] = time.monotonic) -> ProbeResult:
    """Never raises for an expected failure; every path yields an explicit outcome."""
    started = clock()

    def done(outcome: CheckOutcome, reason: str, **extra: Any) -> ProbeResult:
        return ProbeResult(outcome, reason, elapsed_ms=int((clock() - started) * 1000),
                           **extra)

    if clock() >= deadline:
        return done(CheckOutcome.UNKNOWN, "PROBE_DEADLINE_BEFORE_START")
    try:
        answers = resolver(config.hostname)
    except TimeoutError:
        return done(CheckOutcome.UNKNOWN, "DNS_TIMEOUT")
    except Exception:
        return done(CheckOutcome.UNKNOWN, "DNS_ERROR")
    if type(answers) not in (tuple, list):
        return done(CheckOutcome.UNKNOWN, "DNS_RESULT_INVALID")

    if clock() >= deadline:
        return done(CheckOutcome.UNKNOWN, "PROBE_DEADLINE_AFTER_DNS")
    connected = connect_pinned(config.policy, config.hostname, 443, answers, dialer=dialer)
    if not connected.allowed:
        if connected.reason == "DIAL_ERROR":
            # The approved address did not accept a connection: an observed failure.
            return done(CheckOutcome.FAIL, "CONNECT_FAILED", selected_ip=connected.selected_ip)
        # Policy refusal (private/forbidden address, peer mismatch...): nothing was observed.
        return done(CheckOutcome.UNKNOWN, "DESTINATION_" + connected.reason,
                    selected_ip=connected.selected_ip)

    handle, ip = connected.handle, connected.selected_ip
    try:
        line, not_after = transport.exchange(handle, config.hostname, config.path, deadline)
    except ssl.SSLError:
        return done(CheckOutcome.FAIL, "TLS_FAILED", selected_ip=ip)
    except TimeoutError:
        return done(CheckOutcome.FAIL, "HTTP_TIMEOUT", selected_ip=ip)
    except OSError:
        return done(CheckOutcome.FAIL, "HTTP_IO_ERROR", selected_ip=ip)
    except Exception:
        return done(CheckOutcome.UNKNOWN, "HTTP_EXCHANGE_ERROR", selected_ip=ip)
    finally:
        try:
            handle.close()
        except Exception:
            pass

    status = parse_status_line(line) if type(line) is bytes else None
    if status is None:
        return done(CheckOutcome.UNKNOWN, "HTTP_MALFORMED", selected_ip=ip,
                    tls_not_after=not_after)
    # 3xx is reported as UNKNOWN (HTTP_3xx_UNRESOLVED); the Location is never followed.
    outcome, reason = classify_http_status(status, observation_reliable=True)
    return done(outcome, reason, http_status=status, selected_ip=ip, tls_not_after=not_after)
