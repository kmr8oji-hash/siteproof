"""S2-B-VERIFY trusted Worker (UID 1001): the production Connector for the ONE registered host, resolving ONLY through the Grant Broker.

Differences to s2b_worker: its SystemResolver is replaced by BrokeredResolver (this UID cannot query Docker's resolver or open an
address itself). Everything else is reused unchanged from s2b_worker: registered_host (read from targets.json, nothing is passed in),
RecordingTransport (production `_dial` and policy), real_head (strict TLS, HEAD only, redirects never followed), deny_matrix, stop_real.
`site_policy.REAL_SITE_ACCESS_ENABLED` is flipped in THIS process only and restored by stop_real; the source file is never edited.
"""
import os
import socket

from tests.runtime import linux_worker as base
from tests.runtime import s2b_worker as s2b
from src.isolation import site_policy
from src.isolation.connect_dns import DnsLimits
from src.isolation.site_policy import SiteEntry, SiteNetworkPlan, real_site_policy
from src.isolation.transport import TransportLimits
from tests.runtime.s2h_probe import tcp
from tests.runtime.s2h_worker import RecordingBrokered

LEASE = 'verify'


class Recording(RecordingBrokered):
    def resolve_complete(self, hostname):
        result = super().resolve_complete(hostname)
        self.log[-1].update(a_complete=result.a_complete, aaaa_complete=result.aaaa_complete)
        return result


def start_brokered():
    host, url, site = s2b.registered_host()
    plan = SiteNetworkPlan('REAL', (SiteEntry(s2b.TARGET_ID, (host,)),), enabled=True)
    site_policy.REAL_SITE_ACCESS_ENABLED = True  # This process only, until stop_real.
    policy = real_site_policy(plan)
    limits = base.BudgetLimits(8 * 1024 * 1024, 32, 8, 64, 300)
    session = base.QuotaSession('s2v-real', base.NetworkBudget(limits, limits), base.IoLimits(16384, 65536),
                                termination_limits=base.TerminationLimits(8, 30))
    resolver = Recording(LEASE)
    proxy = s2b.RecordingTransport(session, policy, resolver, DnsLimits(16, 1024), TransportLimits(4096, 3, .01, 16, 5), listen_port=base.PROXY_PORT)
    proxy.start()
    s2b.STATE.update(lease=base.ProxyLease(proxy), resolver=resolver, host=host, plan=plan)
    return {'host': host, 'url': url, 'hostnames': [d.hostname for d in policy.allowlist], 'ports': [d.port for d in policy.allowlist],
            'flag_during_run': site_policy.REAL_SITE_ACCESS_ENABLED, 'resolver': type(resolver).__name__}


def deny_matrix(lease, gateway):
    """Same authorities as s2b_worker.deny_matrix. A case with NO answer and NOTHING in the ledger is a proxy stall, not a refusal:
    it is retried once and both attempts are kept (the judged one is the second); every other outcome is judged as received."""
    host = s2b.STATE['host']
    authorities = [f'www.{host}:443', f'evil.{host}:443', f'{host}.evil.invalid:443', f'*.{host}:443', f'{host}.:443',
                   f'{host}:80', f'{host}:8443', f'{host}:2375', 'unlisted-s2b.invalid:443', 'example.com:443',
                   'host.docker.internal:443', 'metadata.google.internal:443', 'localhost:443', '169.254.169.254:443',
                   '10.0.0.5:443', f'{gateway}:443', '[::1]:443', '[2001:db8::1]:443', f'{host}']
    results = []
    for authority in authorities:
        first = s2b.traced(lease, authority)
        if first.get('status', '') == '' and not first['records']:
            result = s2b.traced(lease, authority)
            result['stalled_first_attempt'] = first
        else:
            result = first
        results.append(result)
    return results


def main():
    if os.getuid() != 1001:
        raise RuntimeError('trusted Worker UID required')
    for address, key in ((('127.0.0.2', 18555), 'tcp'), (('169.254.169.254', 80), 'metadata'), (('10.231.77.5', 18555), 'lan'),
                         (('127.0.0.4', 18555), 'host_model'), (('127.0.0.5', 2375), 'docker_api')):
        base.canary(address, key=key)
    base.canary(('127.0.0.3', 53), kind=socket.SOCK_DGRAM, key='dns')
    base.canary(('127.0.0.3', 5353), kind=socket.SOCK_DGRAM, key='udp')
    base.canary(('::1', 18555), family=socket.AF_INET6, key='ipv6')
    host, url, _ = s2b.registered_host()
    base.output({'type': 'ready', 'proxy_port': base.PROXY_PORT, 'namespace': os.readlink('/proc/self/ns/net'), 'uid': os.getuid(),
                 'resources': vars(base.RESOURCES), 'registered_host': host, 'registered_url': url,
                 'flag_at_start': site_policy.REAL_SITE_ACCESS_ENABLED})
    try:
        while True:
            command = base.command()
            kind = command.get('type')
            lease = s2b.STATE['lease']
            if kind == 'counts':
                with base.LOCK:
                    base.output({'type': 'counts', 'counts': dict(base.COUNTS)})
            elif kind == 'policy_default':
                base.output({'type': 'policy_default', **s2b.policy_default()})
            elif kind == 'start_real':
                base.output({'type': 'real_started', **start_brokered()})
            elif kind == 'stop_real':
                base.output({'type': 'real_stopped', **s2b.stop_real()})
            elif kind == 'connect_raw':
                base.output({'type': 'connect_raw', 'result': s2b.traced(lease, command['authority'])})
            elif kind == 'real_head':
                base.output({'type': 'real_head', 'result': s2b.real_head(lease)})
            elif kind == 'deny_matrix':
                base.output({'type': 'deny_matrix', 'results': deny_matrix(lease, command['gateway']), 'resolver_calls': len(s2b.STATE['resolver'].log)})
            elif kind == 'direct':
                base.output({'type': 'direct', 'results': {n: tcp(ip, port) for n, ip, port in command['targets']}})
            elif kind == 'quit':
                break
            else:
                raise ValueError('unknown trusted command')
    finally:
        confirmed = s2b.stop_real()
        for sock, t, stop in base.SERVERS:
            stop.set()
            sock.close()
            t.join(1)
        base.output({'type': 'closed', **confirmed, 'fixtures': all(not t.is_alive() for _, t, _ in base.SERVERS)})


if __name__ == '__main__':
    main()
