"""S3-1-PREFLIGHT trusted Worker (UID 1001) for the OFFLINE rehearsal: the S3-1 capture pipeline against the TLS fixture peer.

Everything of the real-site Worker is reused through the s3_worker module (create_runtime, prepare, remote, run, head_path, ledger):
RuntimeService.run, ComparisonService (no authority, unattested preview), Baseline CANDIDATE registration (never approval), the
production ConnectTransport/`_dial`, BrokeredResolver. Only three things differ, all in this file:
  * the registered host/URL come from the fixture (`ttn-fixture.invalid`, path from s3_worker.PATH), not from targets.json;
  * the destination policy is a FIXTURE plan, so `REAL_SITE_ACCESS_ENABLED` is never touched (it stays False in this process);
  * TLS trust for the HEAD check is the fixture certificate (SSL_CERT_FILE set by the host for this process only).
"""
import os
import socket

from tests.runtime import linux_worker as base
from tests.runtime import s2b_worker as s2b
from tests.runtime import s3_worker as s3
from src.isolation import site_policy
from src.isolation.connect_dns import DnsLimits
from src.isolation.site_policy import SiteEntry, SiteNetworkPlan, fixture_policy
from src.isolation.transport import TransportLimits
from tests.runtime.s2v_worker import Recording

HOST = 'ttn-fixture.invalid'


def fixture_registered():
    return HOST, 'https://' + HOST + s3.PATH, {'site_id': 'ttn', 'name': 'Tokyo Trouble Navi (offline fixture)', 'origin': 'https://' + HOST}


s3.registered = fixture_registered  # create() and prepare() resolve the host through this module-level name.


def start_fixture():
    policy = fixture_policy(SiteNetworkPlan('FIXTURE', (SiteEntry('ttn-fixture', (HOST,)),)))
    limits = base.BudgetLimits(16 * 1024 * 1024, 32, 8, 64, 300)
    session = base.QuotaSession('s3p-fixture', base.NetworkBudget(limits, limits), base.IoLimits(16384, 65536),
                                termination_limits=base.TerminationLimits(8, 30))
    resolver = Recording(s3.LEASE)
    proxy = s2b.RecordingTransport(session, policy, resolver, DnsLimits(16, 1024), TransportLimits(4096, 3, .01, 16, 5), listen_port=base.PROXY_PORT)
    proxy.start()
    lease = base.ProxyLease(proxy)
    s2b.STATE.update(lease=lease, resolver=resolver, host=HOST, plan=None)
    s3.RUNTIME['lease'] = lease
    return {'host': HOST, 'hostnames': [d.hostname for d in policy.allowlist], 'ports': [d.port for d in policy.allowlist],
            'real_site_flag': site_policy.REAL_SITE_ACCESS_ENABLED, 'resolver': type(resolver).__name__}


def main():
    if os.getuid() != 1001:
        raise RuntimeError('trusted Worker UID required')
    for address, key in ((('127.0.0.2', 18555), 'tcp'), (('169.254.169.254', 80), 'metadata'), (('10.231.77.5', 18555), 'lan'),
                         (('127.0.0.4', 18555), 'host_model'), (('127.0.0.5', 2375), 'docker_api')):
        base.canary(address, key=key)
    base.canary(('127.0.0.3', 53), kind=socket.SOCK_DGRAM, key='dns')
    base.canary(('127.0.0.3', 5353), kind=socket.SOCK_DGRAM, key='udp')
    base.canary(('127.0.0.3', 443), kind=socket.SOCK_DGRAM, key='quic')  # Controlled UDP/443 target (QUIC) for the OS-level test.
    base.canary(('::1', 18555), family=socket.AF_INET6, key='ipv6')
    base.output({'type': 'ready', 'proxy_port': base.PROXY_PORT, 'namespace': os.readlink('/proc/self/ns/net'), 'uid': os.getuid(), 'resources': vars(base.RESOURCES),
                 'registered_host': HOST, 'target_url': 'https://' + HOST + s3.PATH, 'path': s3.PATH, 'flag_at_start': site_policy.REAL_SITE_ACCESS_ENABLED})
    try:
        while True:
            command = base.command()
            kind = command.get('type')
            lease = s2b.STATE['lease']
            if kind == 'counts':
                with base.LOCK:
                    base.output({'type': 'counts', 'counts': dict(base.COUNTS)})
            elif kind == 'start_fixture':
                base.output({'type': 'fixture_started', **start_fixture()})
            elif kind == 'stop_real':
                base.output({'type': 'real_stopped', **s2b.stop_real()})
            elif kind == 'ledger_window':
                base.output({'type': 'ledger_window', 'window': lease.ledger.window((0, 0, 0))})
            elif kind == 'head_path':
                saved = s3.PATH
                s3.PATH = command.get('path', saved)  # Lets the rehearsal check the STOP rule on /about.html (307) as well as /about.
                try:
                    base.output({'type': 'head_path', 'result': s3.head_path(lease)})
                finally:
                    s3.PATH = saved
            elif kind == 'top_page':  # S3-1T rehearsal: the top-page plan (path `/`, ttn-home, full-page profiles) on the fixture host.
                from tests.runtime import s3t_worker
                applied = s3t_worker.apply()
                if command.get('stability') is not None:  # OFFLINE rehearsal only (this fixture Worker): e.g. the old back-to-back timing
                    from src.runtime.stability import policy as stability_policy
                    s3.STABILITY = stability_policy(command['stability'])
                base.output({'type': 'top_page', 'path': s3.PATH, 'page_id': s3.PAGE_ID, 'target_url': fixture_registered()[1],
                             'profiles': applied['entry']['profiles'], 'plan_sha256': applied['plan_sha256'], 'stability': s3.STABILITY})
            elif kind == 'create':
                base.output({'type': 'created', **s3.create()})
            elif kind == 'prepare':
                base.output({'type': 'prepared', **s3.prepare(command['kind'])})
            elif kind == 'run':
                base.output({'type': 'result', **s3.run(command['batch'])})
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
