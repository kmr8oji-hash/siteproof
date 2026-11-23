"""Offline CONNECT authority and trusted DNS-result boundary.

Only a complete authority request-target is accepted, not an HTTP message.
Resolvers and numeric-IP dialers must be explicitly injected; none is provided.
"""

from dataclasses import dataclass
from typing import Callable, Literal, Protocol

from .connector import ConnectionHandle, ConnectorResult, connect_pinned
from .destination import AuthorityDecision, DestinationPolicy, check_authority


MAX_AUTHORITY_BYTES = 253 + len(b":443")


@dataclass(frozen=True)
class DnsLimits:
    """Explicit trusted limits; no production defaults are selected here."""

    max_answers: int
    max_answer_chars: int

    def __post_init__(self):
        for value in (self.max_answers, self.max_answer_chars):
            if type(value) is not int or value <= 0:
                raise ValueError("DNS limits must be positive integers")


@dataclass(frozen=True)
class DnsResolution:
    """Trusted resolver report, not independently authenticated DNS evidence."""

    query_hostname: str
    status: Literal["COMPLETE", "TIMEOUT", "ERROR", "INCOMPLETE"]
    a_complete: bool
    aaaa_complete: bool
    addresses: tuple[str, ...]


class TrustedResolver(Protocol):
    def resolve_complete(self, hostname: str) -> DnsResolution: ...


@dataclass(frozen=True)
class ConnectDnsResult:
    reason: str
    authority: AuthorityDecision | None = None
    connector: ConnectorResult | None = None
    error: str | None = None

    @property
    def allowed(self) -> bool:
        # Authority/DNS acceptance alone must never promote a failed connection.
        return self.connector is not None and self.connector.allowed


def check_connect_authority(policy: DestinationPolicy | None,
                            authority: bytes) -> AuthorityDecision:
    """Accept exact ASCII hostname:443 without repairing the request-target."""
    if type(authority) is not bytes or not authority:
        return AuthorityDecision(False, "INVALID_AUTHORITY")
    if len(authority) > MAX_AUTHORITY_BYTES:
        return AuthorityDecision(False, "AUTHORITY_TOO_LONG")
    try:
        text = authority.decode("ascii", "strict")
    except UnicodeDecodeError:
        return AuthorityDecision(False, "INVALID_AUTHORITY")
    if text.count(":") != 1:
        return AuthorityDecision(False, "INVALID_AUTHORITY")
    hostname, port = text.split(":")
    if port != "443":
        return AuthorityDecision(False, "PORT_NOT_ALLOWED")
    return check_authority(policy, hostname, 443)


def _resolution_reason(result: object, hostname: str, limits: DnsLimits) -> str:
    if type(result) is not DnsResolution:
        return "DNS_RESULT_INVALID"
    if type(result.query_hostname) is not str or result.query_hostname != hostname:
        return "DNS_QUERY_MISMATCH"
    if (type(result.status) is not str or
            result.status not in ("COMPLETE", "TIMEOUT", "ERROR", "INCOMPLETE") or
            type(result.a_complete) is not bool or type(result.aaaa_complete) is not bool or
            type(result.addresses) is not tuple):
        return "DNS_RESULT_INVALID"
    if result.status != "COMPLETE":
        return "DNS_" + result.status
    if not result.a_complete or not result.aaaa_complete:
        return "DNS_INCOMPLETE"
    if not result.addresses:
        return "DNS_NO_ADDRESS"
    if len(result.addresses) > limits.max_answers:
        return "DNS_ANSWER_COUNT_LIMIT"
    chars = 0
    for address in result.addresses:
        if type(address) is not str:
            return "DNS_RESULT_INVALID"
        chars += len(address)
        if chars > limits.max_answer_chars:
            return "DNS_ANSWER_CHARS_LIMIT"
    # IP parsing/classification is exclusively the existing destination layer's job.
    return "ALLOW"


def open_connect_target(
    policy: DestinationPolicy | None,
    authority: bytes,
    *,
    resolver: TrustedResolver,
    dialer: Callable[[str, int], ConnectionHandle],
    limits: DnsLimits,
) -> ConnectDnsResult:
    """Preauthorize, resolve once, require complete results, then use Slice 1.

    The resolver owns any resources it uses. It must report both A and AAAA
    completion, including terminal NODATA, and the entire ordered answer set.
    Completeness, freshness, CNAME processing and RR-family correctness remain
    trusted adapter obligations. A synchronous resolver cannot be interrupted here.
    The connector retains sole responsibility for the acquired connection handle.
    """
    approved = check_connect_authority(policy, authority)
    if not approved.allowed:
        return ConnectDnsResult(approved.reason, approved)
    if type(limits) is not DnsLimits:
        return ConnectDnsResult("DNS_LIMITS_INVALID", approved)
    try:
        resolution = resolver.resolve_complete(approved.hostname)
    except TimeoutError as exc:
        return ConnectDnsResult("DNS_TIMEOUT", approved, error=type(exc).__name__)
    except Exception as exc:
        return ConnectDnsResult("DNS_ERROR", approved, error=type(exc).__name__)
    reason = _resolution_reason(resolution, approved.hostname, limits)
    if reason != "ALLOW":
        return ConnectDnsResult(reason, approved)
    connected = connect_pinned(policy, approved.hostname, 443, resolution.addresses,
                               dialer=dialer)
    return ConnectDnsResult(connected.reason, approved, connected)
