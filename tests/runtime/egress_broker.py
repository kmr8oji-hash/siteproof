"""S2-B-HARDEN privileged Grant Broker daemon: the ONLY holder of NET_ADMIN besides the setup helper.

Runs as root in its own container that shares the run's network namespace (cap-drop ALL + NET_ADMIN, read-only root,
no-new-privileges, seccomp, no mounts but read-only sources). Two surfaces:
  * Worker surface: TCP 127.0.0.6:18090 on loopback, ops `resolve` / `release` only (src/isolation/egress_grant.py).
    The Browser UID cannot reach it (its loopback access is limited to the proxy port by the OS rules).
  * Host surface: this process's stdin/stdout (the host's `docker start -a -i` pipes). Never reachable from the Worker.
    First line = configuration; then enable / lease_open / lease_close / state / inject / close / quit.
Modes: `fixture` (FIXTURE plan, table resolver, fault injection allowed) and `system` (REAL plan, SystemResolver, requires an
explicit `real_site_access: true` in the host's configuration; the module constant in site_policy is flipped in this process only).
The firewall implementation validates every address again, independently of the broker logic, before touching iptables.
"""
import ipaddress
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time

from src.isolation import site_policy
from src.isolation.connect_dns import DnsLimits, DnsResolution
from src.isolation.egress_grant import BROKER_ADDRESS, MAX_LINE, GrantBroker, handle_worker_line
from src.isolation.site_policy import SiteEntry, SiteNetworkPlan, fixture_policy, real_site_policy
from src.isolation.transport import SystemResolver
from tests.runtime.netpolicy_hardened import NONPUBLIC, devices, grant_rules, grant_spec

MAX_GRANT_RULES = 64
# Permit mode: the harness mounts the signed, hash-pinned targets.json read-only and names it here; default = the repository file.
TARGETS = os.environ.get('SITEPROOF_TARGETS') or '/opt/siteproof/src/noxiworks/targets.json'
TARGET_ID = 'noxiworks-home'


def _ipt(*args):
    return subprocess.run(['iptables', '-w', *args], capture_output=True, text=True, timeout=5)


class IptablesFirewall:
    """One verified `SP_GRANT` rule per address. allow() raises unless the rule is present afterwards; revoke() unless gone."""

    def __init__(self, device):
        if device not in devices():
            raise ValueError('egress device not found')
        self.device = device

    def _present(self, ip):
        return _ipt('-C', 'OUTPUT', *grant_spec(self.device, ip)).returncode == 0

    def allow(self, ip):
        address = ipaddress.ip_address(ip)
        if (address.version != 4 or not address.is_global or any(address in ipaddress.ip_network(n) for n in NONPUBLIC)):
            raise ValueError('only a global IPv4 address may be granted')
        if len(grant_rules()) >= MAX_GRANT_RULES:
            raise RuntimeError('grant rule bound')
        if not self._present(ip):
            result = _ipt('-I', 'OUTPUT', '1', *grant_spec(self.device, ip))
            if result.returncode:
                raise RuntimeError('iptables insert failed')
        if not self._present(ip):
            raise RuntimeError('grant not verified')

    def revoke(self, ip):
        for _ in range(8):  # A duplicate would otherwise survive a single delete.
            if not self._present(ip):
                return
            if _ipt('-D', 'OUTPUT', *grant_spec(self.device, ip)).returncode:
                break
        if self._present(ip):
            raise RuntimeError('grant still present')


class FaultyFirewall:
    """Fixture mode only: the host can make the next N allow()/revoke() calls fail, as a failing iptables would."""

    def __init__(self, inner):
        self.inner, self.fail_allow, self.fail_revoke, self.lock = inner, 0, 0, threading.Lock()

    def allow(self, ip):
        with self.lock:
            if self.fail_allow:
                self.fail_allow -= 1
                raise RuntimeError('injected allow failure')
        self.inner.allow(ip)

    def revoke(self, ip):
        with self.lock:
            if self.fail_revoke:
                if self.fail_revoke > 0:
                    self.fail_revoke -= 1
                raise RuntimeError('injected revoke failure')
        self.inner.revoke(ip)


class TableResolver:
    """FIXTURE ONLY. Fixed answers per name, advancing per resolution; never resolves anything real."""

    def __init__(self, answers, special):
        self.answers, self.special, self.calls, self.lock = answers, special, {}, threading.Lock()

    def resolve_complete(self, hostname):
        with self.lock:
            index = self.calls.get(hostname, 0)
            self.calls[hostname] = index + 1
        if hostname in self.special:
            status, a, aaaa, addresses = self.special[hostname]
            if status == 'RAISE':
                raise TimeoutError()
            return DnsResolution(hostname, status, a, aaaa, tuple(addresses))
        sequence = self.answers[hostname]
        return DnsResolution(hostname, 'COMPLETE', True, True, tuple(sequence[min(index, len(sequence) - 1)]))


class RecordingSystemResolver:
    """The production SystemResolver plus a record of every call and its complete answer set (the Broker's DNS evidence)."""

    def __init__(self):
        self.inner, self.log, self.lock = SystemResolver(), [], threading.Lock()

    def resolve_complete(self, hostname):
        started, entry = time.monotonic(), {'host': hostname}
        with self.lock:
            self.log.append(entry)
        try:
            result = self.inner.resolve_complete(hostname)
        except BaseException as exc:
            entry.update(status='EXCEPTION', error=type(exc).__name__, ms=round((time.monotonic() - started) * 1000))
            raise
        entry.update(status=result.status, a_complete=result.a_complete, aaaa_complete=result.aaaa_complete,
                     addresses=list(result.addresses), ms=round((time.monotonic() - started) * 1000))
        return result


def registered_hostname(target_id=TARGET_ID):
    """The one registered, user-owned target host. The Broker refuses any configuration that names anything else."""
    from urllib.parse import urlsplit
    config = json.load(open(TARGETS, encoding='utf-8'))
    page = next(p for p in config['pages'] if p['target_id'] == target_id)
    parts = urlsplit(page['url'])
    if parts.scheme != 'https' or parts.port not in (None, 443) or parts.path != '/' or not parts.hostname:
        raise SystemExit('registered target is not a plain https origin')
    return parts.hostname


def out(obj):
    sys.stdout.write(json.dumps(obj, separators=(',', ':')) + '\n')
    sys.stdout.flush()


def serve(broker, stop):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(BROKER_ADDRESS)
    listener.listen(16)
    listener.settimeout(.2)
    slots = threading.BoundedSemaphore(16)

    def handle(client):
        try:
            client.settimeout(15)
            raw = b''
            while not raw.endswith(b'\n') and len(raw) <= MAX_LINE:
                part = client.recv(1024)
                if not part:
                    break
                raw += part
            client.sendall(handle_worker_line(broker, raw.rstrip(b'\n') if raw.endswith(b'\n') else b'x' * (MAX_LINE + 1)))
        except OSError:
            pass
        finally:
            client.close()
            slots.release()

    def loop():
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not slots.acquire(blocking=False):
                client.close()
                continue
            threading.Thread(target=handle, args=(client,), daemon=True).start()
        listener.close()
    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    return thread


def main():
    config = json.loads(sys.stdin.readline())
    mode = config['mode']
    limits = DnsLimits(16, 1024)
    faulty = None
    if mode == 'fixture':
        policy = fixture_policy(SiteNetworkPlan('FIXTURE', (SiteEntry('s2h-fixture', tuple(config['hosts'])),)))
        resolver = TableResolver(config['answers'], {k: tuple(v) for k, v in config.get('special', {}).items()})
        firewall = faulty = FaultyFirewall(IptablesFirewall(config['device']))
    elif mode == 'system' and config.get('real_site_access') is True:
        if config['hosts'] != [registered_hostname(config.get('target_id', TARGET_ID))] or config['max_grants'] != 1:
            raise SystemExit('system mode is fixed to the single registered host and a single grant')
        site_policy.REAL_SITE_ACCESS_ENABLED = True  # This process only, for this run only.
        policy = real_site_policy(SiteNetworkPlan('REAL', (SiteEntry('registered', tuple(config['hosts'])),), enabled=True))
        resolver = RecordingSystemResolver()
        firewall = IptablesFirewall(config['device'])
        if config.get('fault_injection') is True:  # Host-controlled test hook (stdin only), off unless the host asks.
            firewall = faulty = FaultyFirewall(firewall)
    else:
        raise SystemExit('unsupported broker configuration')
    broker = GrantBroker(policy, resolver, firewall, limits, ttl_seconds=config['ttl'], max_grants=config['max_grants'])
    stop = threading.Event()
    server = serve(broker, stop)

    def ticker():  # Expiry must not depend on a request arriving.
        while not stop.wait(.5):
            broker.state()
    threading.Thread(target=ticker, daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    out({'type': 'ready', 'mode': mode, 'flag_in_process': site_policy.REAL_SITE_ACCESS_ENABLED, 'address': list(BROKER_ADDRESS), 'ttl': config['ttl'], 'max_grants': config['max_grants']})
    clean = None
    try:
        for line in sys.stdin:
            if stop.is_set():
                break
            command = json.loads(line)
            kind = command.get('type')
            if kind == 'enable':
                broker.enable()
                out({'type': 'enabled'})
            elif kind == 'lease_open':
                out({'type': 'lease_open', **broker.open_lease(command['lease'], command['hosts'])})
            elif kind == 'lease_close':
                out({'type': 'lease_close', 'clean': broker.close_lease(command['lease'])})
            elif kind == 'state':
                out({'type': 'state', 'state': broker.state(), 'resolver_calls': dict(getattr(resolver, 'calls', {})), 'resolver_log': list(getattr(resolver, 'log', []))})
            elif kind == 'inject' and faulty is not None:
                with faulty.lock:
                    faulty.fail_allow = command.get('fail_allow', faulty.fail_allow)
                    faulty.fail_revoke = command.get('fail_revoke', faulty.fail_revoke)
                out({'type': 'injected'})
            elif kind == 'close':
                clean = broker.disable_and_close()
                out({'type': 'closed', 'clean': clean, 'grant_rules': grant_rules()})
            elif kind == 'quit':
                break
            else:
                out({'type': 'error', 'reason': 'UNKNOWN_COMMAND'})
    finally:
        if clean is None:
            clean = broker.disable_and_close()
        stop.set()
        server.join(2)
        out({'type': 'exit', 'clean': clean, 'grant_rules': grant_rules()})


if __name__ == '__main__':
    main()
