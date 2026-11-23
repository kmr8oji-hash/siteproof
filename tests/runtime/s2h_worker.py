"""S2-B-HARDEN trusted Worker (UID 1001): the production Connector with the BROKERED resolver, fixture destinations only.

ConnectTransport, DestinationPolicy, the ledger and the numeric-IP `_dial` are the production code, unchanged. Differences from
s2b_worker: names are resolved ONLY through the Grant Broker (src/isolation/egress_grant.BrokeredResolver; this UID cannot even
query Docker's resolver any more) and the destinations are the fixture peers of an isolated network. Several proxies (jobs) can
run at once, each with its own lease. Nothing here reaches a real site or the internet.
"""
import io
import json
import os
import socket
import threading
import time

from tests.runtime import linux_worker as base
from src.isolation.connect_dns import DnsLimits
from src.isolation.egress_grant import BrokeredResolver
from src.isolation.site_policy import SiteEntry, SiteNetworkPlan, fixture_policy
from src.isolation.transport import TransportLimits
from tests.runtime.s2b_worker import RecordingTransport
from tests.runtime.s2h_probe import tcp

PROXIES = {}
KEEPALIVE = {}


class RecordingBrokered(BrokeredResolver):
    def __init__(self, lease):
        super().__init__(lease)
        self.log = []

    def resolve_complete(self, hostname):
        entry = {'host': hostname}
        self.log.append(entry)
        try:
            result = super().resolve_complete(hostname)
        except BaseException as exc:
            entry.update(status='EXCEPTION', error=type(exc).__name__)
            raise
        entry.update(status=result.status, addresses=list(result.addresses), denied=self.denials[-1]['reason'] if result.status == 'ERROR' else None)
        return result


def open_proxy(lease, port, hosts):
    policy = fixture_policy(SiteNetworkPlan('FIXTURE', (SiteEntry(lease, tuple(hosts)),)))
    limits = base.BudgetLimits(8 * 1024 * 1024, 32, 8, 64, 300)
    session = base.QuotaSession('s2h-' + lease, base.NetworkBudget(limits, limits), base.IoLimits(16384, 65536),
                                termination_limits=base.TerminationLimits(8, 30))
    resolver = RecordingBrokered(lease)
    proxy = RecordingTransport(session, policy, resolver, DnsLimits(16, 1024), TransportLimits(4096, 3, .01, 16, 5), listen_port=port)
    proxy.start()
    PROXIES[port] = {'lease': lease, 'lease_object': base.ProxyLease(proxy), 'resolver': resolver, 'hosts': list(hosts)}
    return {'port': port, 'lease': lease, 'hosts': list(hosts)}


def close_proxy(port):
    entry = PROXIES.pop(port, None)
    stopped = entry['lease_object'].stop() if entry else True
    return {'stopped': stopped}


def connect(port, authority):
    entry = PROXIES[port]
    proxy, resolver = entry['lease_object'].transport, entry['resolver']
    mark, calls, dials = proxy.ledger.mark(), len(resolver.log), len(proxy.dialed)
    out = {'authority': authority, 'banner': ''}
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=12) as s:
            s.sendall(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n'.encode('ascii'))
            response = b''
            while not response.endswith(b'\r\n\r\n') and len(response) < 4096:
                try:
                    part = s.recv(1024)
                except ConnectionResetError:
                    break
                if not part:
                    break
                response += part
            out['status'] = response.split(b'\r\n')[0].decode('ascii', 'replace')
            if out['status'].startswith('HTTP/1.1 200'):
                s.settimeout(3)
                try:
                    out['banner'] = s.recv(32).decode('ascii', 'replace').strip()
                except OSError:
                    pass
    except OSError as exc:
        out.update(status='', error=type(exc).__name__)
    deadline = time.monotonic() + 3
    while proxy.ledger.window(mark)['in_flight'] and time.monotonic() < deadline:
        time.sleep(.02)
    window = proxy.ledger.window(mark)
    out.update(records=[[e['host'], e['port'], e['decision'], e['reason'], e['count']] for e in window['entries']], complete=window['complete'],
               resolutions=resolver.log[calls:], dialed=proxy.dialed[dials:])
    return out


def parallel(jobs):
    """Several jobs (proxies) connecting at the same moment. Returns the results in request order."""
    results = [None] * len(jobs)
    gate = threading.Barrier(len(jobs))

    def run(index, port, authority):
        gate.wait(10)
        try:
            results[index] = connect(port, authority)
        except Exception as exc:  # pragma: no cover - reported, never hidden
            results[index] = {'authority': authority, 'error': type(exc).__name__}
    threads = [threading.Thread(target=run, args=(i, p, a)) for i, (p, a) in enumerate(jobs)]
    [t.start() for t in threads]
    [t.join(60) for t in threads]
    return results


def keepalive(lease, host, seconds):
    stop = threading.Event()
    KEEPALIVE[lease] = stop

    def run():
        resolver, end = BrokeredResolver(lease), time.monotonic() + seconds
        while not stop.wait(2) and time.monotonic() < end:
            try:
                resolver.resolve_complete(host)  # A job that keeps connecting: only refreshes its own grant.
            except OSError:
                pass
    threading.Thread(target=run, daemon=True).start()


def main():
    if os.getuid() != 1001:
        raise RuntimeError('trusted Worker UID required')
    for address, key in ((('127.0.0.2', 18555), 'tcp'), (('169.254.169.254', 80), 'metadata'), (('10.231.77.5', 18555), 'lan'),
                         (('127.0.0.4', 18555), 'host_model'), (('127.0.0.5', 2375), 'docker_api')):
        base.canary(address, key=key)
    base.canary(('127.0.0.3', 53), kind=socket.SOCK_DGRAM, key='dns')
    base.canary(('127.0.0.3', 5353), kind=socket.SOCK_DGRAM, key='udp')
    base.canary(('::1', 18555), family=socket.AF_INET6, key='ipv6')
    base.output({'type': 'ready', 'namespace': os.readlink('/proc/self/ns/net'), 'uid': os.getuid(), 'resources': vars(base.RESOURCES)})
    try:
        while True:
            command = base.command()
            kind = command.get('type')
            if kind == 'counts':
                with base.LOCK:
                    base.output({'type': 'counts', 'counts': dict(base.COUNTS)})
            elif kind == 'open_proxy':
                base.output({'type': 'proxy_opened', **open_proxy(command['lease'], command['port'], command['hosts'])})
            elif kind == 'close_proxy':
                base.output({'type': 'proxy_closed', **close_proxy(command['port'])})
            elif kind == 'connect':
                base.output({'type': 'connect', 'result': connect(command['port'], command['authority'])})
            elif kind == 'parallel':
                base.output({'type': 'parallel', 'results': parallel(command['jobs'])})
            elif kind == 'direct':
                base.output({'type': 'direct', 'results': {n: tcp(ip, port) for n, ip, port in command['targets']}})
            elif kind == 'keepalive':
                keepalive(command['lease'], command['host'], command['seconds'])
                base.output({'type': 'keepalive_started'})
            elif kind == 'keepalive_stop':
                for event in KEEPALIVE.values():
                    event.set()
                base.output({'type': 'keepalive_stopped'})
            elif kind == 'crash':
                os._exit(1)  # No cleanup of any kind: the host must still end the lease and close the window.
            elif kind == 'quit':
                break
            else:
                raise ValueError('unknown trusted command')
    finally:
        for event in KEEPALIVE.values():
            event.set()
        stopped = {str(p): close_proxy(p)['stopped'] for p in list(PROXIES)}
        for sock, t, stop in base.SERVERS:
            stop.set()
            sock.close()
            t.join(1)
        base.output({'type': 'closed', 'proxies': stopped, 'fixtures': all(not t.is_alive() for _, t, _ in base.SERVERS)})


if __name__ == '__main__':
    main()
