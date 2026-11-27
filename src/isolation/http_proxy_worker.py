"""The trusted CONNECT proxy of an isolated HTTP check (container, UID 1001): the unchanged ConnectTransport with the brokered resolver, for ONE host.

It can only ask the privileged Grant Broker to resolve that host (it cannot query DNS itself) and, by the OS rules, only reach the one address:443 the
broker granted. The Connector validates the whole answer again, dials the first address and compares the peer. Every CONNECT attempt is in the ledger
the host reads (`audit`): host, port, decision, reason -- a CONNECT proxy never sees a path. Controlled over stdin/stdout by the host only.
If this process is gone, the Worker has no way out (fail closed).
"""
import json
import os
import sys

from src.isolation import site_policy
from src.isolation.budget import BudgetLimits, NetworkBudget
from src.isolation.connect_dns import DnsLimits
from src.isolation.egress_grant import BrokeredResolver
from src.isolation.quota_session import IoLimits, QuotaSession
from src.isolation.site_policy import SiteEntry, SiteNetworkPlan, fixture_policy, real_site_policy
from src.isolation.termination import TerminationLimits
from src.isolation.transport import ConnectTransport, TransportLimits

UID = 1001
LIMITS = BudgetLimits(512 * 1024, 4, 2, 8, 60)  # bytes, connections, concurrent, attempts, seconds: a status line and a TLS handshake need far less
CONNECT_SECONDS = 5  # below the Worker's 8 s: a site that does not answer the dial is decided (and in the ledger) by the proxy before the Worker gives up


class AuditedTransport(ConnectTransport):
    """`_dial` unchanged; only records the numeric address dialled and the peer really connected."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dialed = []

    def _dial(self, ip, port, deadline):
        entry = {'ip': ip, 'port': port}
        self.dialed.append(entry)
        try:
            handle = super()._dial(ip, port, deadline)
        except BaseException as exc:
            entry['error'] = type(exc).__name__
            raise
        entry['peer'] = list(handle.getpeername())
        return handle


def policy_for(mode, host):
    if mode == 'fixture':
        return fixture_policy(SiteNetworkPlan('FIXTURE', (SiteEntry('http-fixture', (host,)),)))
    if mode != 'system':
        raise ValueError('mode')
    site_policy.REAL_SITE_ACCESS_ENABLED = True  # this process, this check only (the source stays False)
    return real_site_policy(SiteNetworkPlan('REAL', (SiteEntry('http', (host,)),), enabled=True))


def say(obj):
    sys.stdout.write(json.dumps(obj, separators=(',', ':')) + '\n')
    sys.stdout.flush()


def main():
    if os.getuid() != UID:
        raise SystemExit('trusted proxy UID required')
    cfg = json.loads(sys.stdin.buffer.readline(4097))
    session = QuotaSession('http-' + cfg['lease'], NetworkBudget(LIMITS, LIMITS), IoLimits(16384, 65536), termination_limits=TerminationLimits(CONNECT_SECONDS, 30))
    resolver = BrokeredResolver(cfg['lease'])
    proxy = AuditedTransport(session, policy_for(cfg['mode'], cfg['host']), resolver, DnsLimits(16, 1024), TransportLimits(4096, 3, .01, 4, 5), listen_port=cfg['port'])
    mark = proxy.ledger.mark()
    proxy.start()
    say({'type': 'ready', 'uid': os.getuid(), 'netns': os.readlink('/proc/self/ns/net'), 'address': list(proxy.address)})
    try:
        for line in sys.stdin:
            kind = json.loads(line).get('type')
            if kind == 'audit':
                say({'type': 'audit', 'window': proxy.ledger.window(mark), 'dialed': proxy.dialed, 'denials': resolver.denials})
            elif kind == 'quit':
                break
            else:
                say({'type': 'error', 'reason': 'UNKNOWN_COMMAND'})
    finally:
        say({'type': 'exit', 'stopped': proxy.stop()})


if __name__ == '__main__':
    main()
