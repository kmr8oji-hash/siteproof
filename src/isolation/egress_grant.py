"""Per-connection OS egress grants for the trusted Worker UID (S2-B-HARDEN). No OS calls and no sockets of its own.

Why: an application allowlist alone must not be the only thing between the trusted UID and the internet. The OS rule
set therefore denies the trusted UID everything on the egress interface except TCP/443 to an address that THIS broker
resolved and validated moments ago. The broker is a separate, privileged component (the only holder of NET_ADMIN, in
its own container); the Worker only ASKS it to resolve an allowlisted name, and cannot name an IP to open.

Flow per CONNECT (the Connector, DestinationPolicy and ledger are unchanged):
  Worker ConnectTransport -> BrokeredResolver.resolve_complete(host) -> GrantBroker.resolve(lease, host):
    exact-host policy check -> its OWN DNS resolution -> whole-answer validation (same functions the Connector
    uses) -> firewall.allow(first IPv4 answer) -> only then the answer set is returned.
  The Connector then validates the same answers again and dials exactly that first address, and checks the peer.
Fail closed: any refusal, resolver error, firewall error or disabled window returns no answer (the Connector records a
DNS failure and never dials). Grants are per lease (job), expire after a TTL, are reference counted when two leases
share an address, and are revoked on lease close, expiry and close(). A revoke failure is never hidden: it stays
pending, blocks new grants, and is retried.

Residual (documented, not solved here): at the OS level the allowed set is the union of active grants in this
network namespace, because the trusted UID is shared by all jobs. Per-job separation is bookkeeping in the broker.
"""
import ipaddress
import json
import re
import socket
import threading
import time
from typing import Callable, Protocol

from .connect_dns import DnsLimits, DnsResolution, _resolution_reason
from .destination import DestinationPolicy, check_authority, check_destination

LEASE = re.compile(r'[a-z0-9][a-z0-9_-]{0,31}\Z')
MAX_LINE = 4096
BROKER_ADDRESS = ('127.0.0.6', 18090)


class Firewall(Protocol):
    def allow(self, ip: str) -> None: ...   # Must raise unless the TCP/443 grant for exactly `ip` is installed AND verified.
    def revoke(self, ip: str) -> None: ...  # Must raise unless the grant for `ip` is gone.


def deny(reason):
    return {'ok': False, 'reason': reason}


class GrantBroker:
    def __init__(self, policy: DestinationPolicy, resolver, firewall: Firewall, dns_limits: DnsLimits, *,
                 ttl_seconds: float, max_grants: int, clock: Callable[[], float] = time.monotonic):
        if (type(dns_limits) is not DnsLimits or type(max_grants) is not int or max_grants <= 0
                or type(ttl_seconds) not in (int, float) or not 0 < ttl_seconds <= 300):
            raise ValueError('explicit DNS limits, positive grant bound and 0 < ttl <= 300 required')
        self.policy, self.resolver, self.firewall, self.limits = policy, resolver, firewall, dns_limits
        self.ttl, self.max_grants, self.clock = float(ttl_seconds), max_grants, clock
        self._lock = threading.RLock()
        self._leases = {}      # lease -> {'hosts': frozenset, 'grants': {ip: expiry}}
        self._installed = set()  # addresses with a verified firewall grant right now
        self._pending = set()    # addresses whose revocation failed; new grants are refused until empty
        self.enabled = False
        self.events = []       # bounded audit of every decision (no payloads)

    # ---- trusted host side (never reachable from the Worker) -------------------------------------------------
    def enable(self):
        with self._lock:
            self.enabled = True

    def open_lease(self, lease, hosts):
        if type(lease) is not str or not LEASE.fullmatch(lease) or type(hosts) is not list or not hosts:
            return deny('LEASE_INVALID')
        names = set()
        for host in hosts:
            decision = check_authority(self.policy, host, 443)  # A lease can only narrow the policy, never widen it.
            if not decision.allowed:
                return deny('LEASE_HOST_' + decision.reason)
            names.add(decision.hostname)
        with self._lock:
            if lease in self._leases:
                return deny('LEASE_EXISTS')
            self._leases[lease] = {'hosts': frozenset(names), 'grants': {}}
        return {'ok': True}

    def close_lease(self, lease):
        with self._lock:
            entry = self._leases.pop(lease, None)
            self._record('LEASE_CLOSED', lease, None, entry is not None)
            return self._reconcile()

    def disable_and_close(self):
        """End of the egress window: no new grants, every lease and grant removed. True only if nothing is left."""
        with self._lock:
            self.enabled = False
            self._leases.clear()
            return self._reconcile() and not self._pending

    # ---- Worker side ------------------------------------------------------------------------------------------
    def resolve(self, lease, hostname):
        with self._lock:
            self._reconcile()
            early = self._precheck(lease, hostname)
        if isinstance(early, dict):
            return early
        host = early
        try:
            resolution = self.resolver.resolve_complete(host)
        except Exception:
            return self._deny(lease, host, 'DNS_ERROR')
        reason = _resolution_reason(resolution, host, self.limits)
        if reason != 'ALLOW':
            return self._deny(lease, host, reason)
        destination = check_destination(self.policy, host, 443, resolution.addresses)
        if not destination.allowed:
            return self._deny(lease, host, destination.reason)
        ip = destination.addresses[0]  # Exactly the address connect_pinned will dial.
        if ipaddress.ip_address(ip).version != 4:
            return self._deny(lease, host, 'FIRST_ADDRESS_NOT_IPV4')
        with self._lock:
            self._reconcile()
            again = self._precheck(lease, host)
            if isinstance(again, dict):
                return again
            held = self._leases[lease]['grants']
            shared = any(ip in e['grants'] for e in self._leases.values())
            if not shared:
                if len({a for e in self._leases.values() for a in e['grants']}) >= self.max_grants:
                    return self._deny(lease, host, 'GRANT_LIMIT')
                try:
                    self.firewall.allow(ip)
                except Exception:
                    try:
                        self.firewall.revoke(ip)  # Whatever was half-installed must not survive.
                    except Exception:
                        self._pending.add(ip)
                    return self._deny(lease, host, 'FIREWALL_UPDATE_FAILED')
                self._installed.add(ip)
            held[ip] = self.clock() + self.ttl
            self._record('GRANTED', lease, host, True, ip)
        return {'ok': True, 'status': 'COMPLETE', 'a_complete': resolution.a_complete, 'aaaa_complete': resolution.aaaa_complete,
                'addresses': list(resolution.addresses), 'granted': ip, 'ttl_seconds': self.ttl}

    def release(self, lease):
        return self.close_lease(lease)

    def state(self):
        with self._lock:
            self._reconcile()
            return {'enabled': self.enabled, 'pending_revocations': sorted(self._pending),
                    'active_addresses': sorted({a for e in self._leases.values() for a in e['grants']}),
                    'leases': {k: {'hosts': sorted(v['hosts']), 'grants': sorted(v['grants'])} for k, v in self._leases.items()},
                    'events': list(self.events)}

    # ---- internals ------------------------------------------------------------------------------------------
    def _precheck(self, lease, hostname):
        if not self.enabled:
            return self._deny(lease, hostname, 'EGRESS_DISABLED')
        if self._pending:
            return self._deny(lease, hostname, 'REVOCATION_PENDING')
        entry = self._leases.get(lease) if type(lease) is str else None
        if entry is None:
            return self._deny(lease, hostname, 'LEASE_UNKNOWN')
        authority = check_authority(self.policy, hostname, 443)
        if not authority.allowed:
            return self._deny(lease, hostname, authority.reason)
        if authority.hostname not in entry['hosts']:
            return self._deny(lease, authority.hostname, 'HOST_NOT_IN_LEASE')
        return authority.hostname

    def _deny(self, lease, host, reason):
        self._record(reason, lease, host, False)
        return deny(reason)

    def _record(self, what, lease, host, ok, ip=None):
        self.events.append({'t': round(self.clock(), 3), 'event': what, 'lease': lease if type(lease) is str and len(lease) <= 32 else None,
                            'host': host if type(host) is str and len(host) <= 253 else None, 'ok': ok, 'ip': ip})
        del self.events[:-512]

    def _reconcile(self):
        """Drop expired grants, then revoke every address no lease holds any more. True if the firewall is clean."""
        now = self.clock()
        for entry in self._leases.values():
            for ip in [a for a, expiry in entry['grants'].items() if expiry <= now]:
                del entry['grants'][ip]
        held = {a for e in self._leases.values() for a in e['grants']}
        for ip in sorted((self._installed - held) | self._pending):
            try:
                self.firewall.revoke(ip)
            except Exception:
                if ip not in self._pending:
                    self._record('REVOKE_FAILED', None, None, False, ip)
                self._pending.add(ip)
                continue
            self._pending.discard(ip)
            self._installed.discard(ip)
            self._record('REVOKED', None, None, True, ip)
        return not self._pending


def handle_worker_line(broker, raw):
    """One Worker request line -> one response line. Only resolve/release exist on this surface."""
    try:
        if type(raw) is not bytes or len(raw) > MAX_LINE:
            raise ValueError()
        request = json.loads(raw)
        op, lease = request.get('op'), request.get('lease')
        if op == 'resolve' and type(request.get('host')) is str:
            response = broker.resolve(lease, request['host'])
        elif op == 'release':
            response = {'ok': broker.release(lease)}
        else:
            response = deny('UNKNOWN_OP')
    except Exception:
        response = deny('BAD_REQUEST')
    return json.dumps(response, separators=(',', ':')).encode() + b'\n'


class BrokeredResolver:
    """TrustedResolver for the Worker's ConnectTransport. The ONLY name resolution path of the trusted UID."""

    def __init__(self, lease, address=BROKER_ADDRESS, timeout=12):
        self.lease, self.address, self.timeout = lease, address, timeout
        self.denials = []

    def resolve_complete(self, hostname):
        with socket.create_connection(self.address, timeout=self.timeout) as s:
            s.sendall(json.dumps({'op': 'resolve', 'lease': self.lease, 'host': hostname}, separators=(',', ':')).encode() + b'\n')
            raw = b''
            while not raw.endswith(b'\n') and len(raw) < MAX_LINE:
                part = s.recv(1024)
                if not part:
                    break
                raw += part
        reply = json.loads(raw)
        if reply.get('ok') is not True:
            self.denials.append({'host': hostname, 'reason': reply.get('reason')})
            return DnsResolution(hostname, 'ERROR', False, False, ())
        return DnsResolution(hostname, reply['status'], reply['a_complete'], reply['aaaa_complete'], tuple(reply['addresses']))
