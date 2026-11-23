"""One pinned connection attempt through an explicitly injected dialer.

No resolver, socket implementation, retry, or fallback is provided here.
"""

from dataclasses import dataclass
import ipaddress
from typing import Callable, Protocol

from .destination import DestinationDecision, DestinationPolicy, check_destination


class ConnectionHandle(Protocol):
    """Trusted adapter: a numeric peer pair and an owned, closeable resource."""

    def getpeername(self) -> tuple[str, int]: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class ConnectorResult:
    allowed: bool
    reason: str
    destination: DestinationDecision | None = None
    selected_ip: str | None = None
    handle: ConnectionHandle | None = None
    error: str | None = None
    close_error: str | None = None


def _peer_reason(peer: object, selected_ip: str, port: int) -> str:
    if type(peer) is not tuple or len(peer) != 2:
        return "INVALID_PEER"
    address, peer_port = peer
    if (type(address) is not str or "%" in address or
            type(peer_port) is not int or not 1 <= peer_port <= 65535):
        return "INVALID_PEER"
    try:
        numeric_ip = str(ipaddress.ip_address(address))
    except ValueError:
        return "INVALID_PEER"
    if numeric_ip != selected_ip or peer_port != port:
        return "PEER_MISMATCH"
    return "ALLOW"


def _close(handle: ConnectionHandle) -> str | None:
    try:
        handle.close()
    except BaseException as exc:
        # Cleanup must not hide the original failure, even if close is interrupted.
        return type(exc).__name__
    return None


def connect_pinned(
    policy: DestinationPolicy | None,
    hostname: str,
    port: int,
    resolved_addresses: tuple[str, ...] | list[str],
    *,
    dialer: Callable[[str, int], ConnectionHandle],
) -> ConnectorResult:
    """Validate all supplied answers, dial the first approved IP once, check peer.

    The caller supplies the entire DNS answer set. The dialer receives only a
    canonical numeric IP and 443. It owns partial resources until it returns a
    handle; this function owns that handle until peer verification succeeds.
    Only an allowed result transfers ownership to the caller.
    """
    if type(port) is not int or port != 443:
        return ConnectorResult(False, "PORT_NOT_ALLOWED")

    # Preserve the destination API's strict container checks; snapshot real lists
    # before validation so later caller/dialer mutations cannot alter the pin.
    answers = (tuple(resolved_addresses) if type(resolved_addresses) is list
               else resolved_addresses)
    destination = check_destination(policy, hostname, port, answers)
    if not destination.allowed:
        return ConnectorResult(False, destination.reason, destination)
    selected_ip = destination.addresses[0]

    try:
        handle = dialer(selected_ip, port)
    except Exception as exc:
        return ConnectorResult(False, "DIAL_ERROR", destination, selected_ip,
                               error=type(exc).__name__)
    if handle is None:
        return ConnectorResult(False, "DIAL_INVALID_HANDLE", destination, selected_ip)

    error = None
    try:
        reason = _peer_reason(handle.getpeername(), selected_ip, port)
        if reason == "ALLOW" and not callable(getattr(handle, "close", None)):
            reason = "DIAL_INVALID_HANDLE"
    except Exception as exc:
        reason = "PEER_ERROR"
        error = type(exc).__name__
    except BaseException as exc:
        close_error = _close(handle)
        if close_error is not None:
            BaseException.add_note(exc, "connector close failed: " + close_error)
        raise

    if reason != "ALLOW":
        return ConnectorResult(False, reason, destination, selected_ip,
                               error=error, close_error=_close(handle))
    return ConnectorResult(True, "ALLOW", destination, selected_ip, handle)
