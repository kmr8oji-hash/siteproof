"""Fail-closed destination checks over caller-supplied, synthetic DNS answers.

An allowlist entry is an exact ASCII DNS hostname and port, never a URL,
wildcard, or IP literal. This module does not resolve or connect to anything.
An ALLOW result is only a decision about the supplied address set; a future
connector must bind that decision to the actual peer and prevent DNS rebinding.
"""

from dataclasses import dataclass
import ipaddress
import re


_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
_HEX_LABEL = re.compile(r"0x[0-9a-f]+\Z", re.ASCII)


@dataclass(frozen=True)
class AllowedDestination:
    hostname: str
    port: int


@dataclass(frozen=True)
class DestinationPolicy:
    allowlist: tuple[AllowedDestination, ...]


@dataclass(frozen=True)
class DestinationDecision:
    allowed: bool
    reason: str
    hostname: str | None = None
    port: int | None = None
    addresses: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthorityDecision:
    """Permission to resolve a hostname, not permission to connect to an IP."""

    allowed: bool
    reason: str
    hostname: str | None = None
    port: int | None = None


def _hostname(value: object) -> str | None:
    if type(value) is not str or not value or len(value) > 253:
        return None
    # No whitespace stripping, trailing dot removal, URL parsing, percent/zone
    # decoding, IDNA conversion, or legacy numeric-address interpretation.
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return None
    value = value.lower()
    labels = value.split(".")
    if len(labels) < 2 or any(not _LABEL.fullmatch(label) for label in labels):
        return None
    if labels[-1].isdigit() or any(_HEX_LABEL.fullmatch(label) for label in labels):
        return None
    return value


def _port(value: object) -> bool:
    return type(value) is int and 1 <= value <= 65535


def _address(value: object) -> tuple[str | None, str]:
    if type(value) is not str or not value or "%" in value:
        return None, "INVALID_DNS_ADDRESS"
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None, "INVALID_DNS_ADDRESS"
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return None, "IPV4_MAPPED_IPV6"
        if address.sixtofour is not None or address.teredo is not None:
            return None, "IPV6_TRANSITION_ADDRESS"
        if (address in ipaddress.IPv6Network("64:ff9b::/96") or
                address in ipaddress.IPv6Network("64:ff9b:1::/48")):
            return None, "IPV6_TRANSLATION_ADDRESS"
        if address.is_site_local:
            return None, "SITE_LOCAL_ADDRESS"
    for attribute, reason in (
        ("is_unspecified", "UNSPECIFIED_ADDRESS"),
        ("is_loopback", "LOOPBACK_ADDRESS"),
        ("is_link_local", "LINK_LOCAL_ADDRESS"),
        ("is_multicast", "MULTICAST_ADDRESS"),
        ("is_reserved", "RESERVED_ADDRESS"),
        ("is_private", "PRIVATE_ADDRESS"),
    ):
        if getattr(address, attribute):
            return None, reason
    if not address.is_global:
        return None, "NON_GLOBAL_ADDRESS"
    return str(address), "ALLOW"


def check_authority(
    policy: DestinationPolicy | None,
    hostname: str,
    port: int,
) -> AuthorityDecision:
    """Validate the whole policy and exact hostname/port before any resolution."""
    if policy is None:
        return AuthorityDecision(False, "POLICY_MISSING")
    if (type(policy) is not DestinationPolicy or type(policy.allowlist) is not tuple
            or not policy.allowlist):
        return AuthorityDecision(False, "POLICY_INVALID")
    entries = set()
    for entry in policy.allowlist:
        if type(entry) is not AllowedDestination:
            return AuthorityDecision(False, "POLICY_INVALID")
        name = _hostname(entry.hostname)
        if name is None or not _port(entry.port):
            return AuthorityDecision(False, "POLICY_INVALID")
        entries.add((name, entry.port))
    name = _hostname(hostname)
    if name is None:
        return AuthorityDecision(False, "INVALID_HOSTNAME")
    if not _port(port):
        return AuthorityDecision(False, "INVALID_PORT")
    if (name, port) not in entries:
        return AuthorityDecision(False, "NOT_ALLOWLISTED", name, port)
    return AuthorityDecision(True, "ALLOW", name, port)


def check_destination(
    policy: DestinationPolicy | None,
    hostname: str,
    port: int,
    resolved_addresses: tuple[str, ...] | list[str],
) -> DestinationDecision:
    """Inspect the entire supplied DNS answer set, without any network I/O.

    A malformed entry anywhere invalidates the policy. An empty, malformed,
    or mixed public/forbidden DNS answer set is denied as a whole.
    """
    authority = check_authority(policy, hostname, port)
    if not authority.allowed:
        return DestinationDecision(False, authority.reason, authority.hostname, authority.port)
    name = authority.hostname
    if type(resolved_addresses) not in (tuple, list) or not resolved_addresses:
        return DestinationDecision(False, "DNS_ANSWERS_INVALID", name, port)
    addresses = []
    for answer in resolved_addresses:
        address, reason = _address(answer)
        if address is None:
            return DestinationDecision(False, reason, name, port)
        if address not in addresses:
            addresses.append(address)
    return DestinationDecision(True, "ALLOW", name, port, tuple(addresses))
