"""S2-B-HARDEN: OS rules for the trusted Worker UID, in a NEW SiteProof network namespace only (short-lived NET_ADMIN helper).

Never run this on the Windows/WSL host or an existing container. netpolicy_s2b.py is kept unchanged as the S2-B record.

Difference to S2-B: there is NO blanket "UID 1001 -> TCP/443" rule any more. While the egress window is open the trusted
UID can leave the egress interface only through rules the privileged GRANT BROKER inserts one address at a time
(`SP_GRANT`: that exact IPv4 /32, TCP/443, conntrack NEW, UID 1001), plus packets of flows those grants started.
Everything else for UID 1001 on that interface is dropped and counted (non-public ranges first, then everything).

  prepare       default DROP (IPv4+IPv6); loopback for UID 1001; the broker's loopback replies (UID 0, 127.0.0.6:18090);
                the trusted Worker may NEVER query Docker's embedded resolver (its only DNS path is the broker).
  install       Browser (UID 1000) rules, unchanged from S2-A/S2-B: only the owned proxy port; everything else dropped+counted.
  egress_open   broker-only resolver path (UID 0 on loopback), non-public drops, established-flow accept, final drop.
  egress_close  removes exactly those rules AND flushes every SP_GRANT rule, whoever inserted it.
  fixture_routes (fixture networks only) on-link routes so packets to non-public / other public addresses reach the OUTPUT
                hook (otherwise "no route" would hide whether the rule or the routing table stopped them).
"""
import ipaddress
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

NONPUBLIC = ('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24',
             '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4',
             '240.0.0.0/4')
BROKER, BROKER_PORT, RESOLVER = '127.0.0.6', 18090, '127.0.0.11'
GRANT = 'SP_GRANT'
FIXTURE_ROUTES = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '12.0.0.0/8')


def call(*args, timeout=10):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout).stdout


def devices():
    return [x['ifname'] for x in json.loads(call('ip', '-j', 'link')) if x['ifname'] != 'lo']


def egress_device(obj):
    names = devices()
    device = obj.get('device') or (names[0] if len(names) == 1 else None)
    if device not in names:
        raise ValueError('exactly one explicit non-loopback egress device required')
    return device


def grant_spec(device, ip):
    return ['-o', device, '-d', ip + '/32', '-p', 'tcp', '--dport', '443', '-m', 'conntrack', '--ctstate', 'NEW',
            '-m', 'owner', '--uid-owner', '1001', '-m', 'comment', '--comment', GRANT, '-j', 'ACCEPT']


def grant_rules():
    return [line for line in call('iptables', '-w', '-S', 'OUTPUT').splitlines() if GRANT in line]


def plain(binary):
    return '\n'.join(line for line in call(binary + '-save').splitlines() if not line.startswith('#'))


def snapshot():
    try:
        conntrack = Path('/proc/net/nf_conntrack').read_text().splitlines()[:400]
    except OSError as exc:
        conntrack = 'UNAVAILABLE:' + type(exc).__name__
    return {'netns': os.readlink('/proc/self/ns/net'), 'conntrack': conntrack, 'devices': devices(),
            'ipv4': call('iptables-save', '-c'), 'ipv6': call('ip6tables-save', '-c'),
            'rules_plain': plain('iptables') + '\n' + plain('ip6tables'), 'grant_rules': grant_rules(),
            'routes': json.loads(call('ip', '-j', 'route', 'show', 'table', 'all')),
            'addresses': json.loads(call('ip', '-j', 'address')), 'links': json.loads(call('ip', '-s', '-j', 'link')),
            'status': [x for x in Path('/proc/self/status').read_text().splitlines()
                       if x.startswith(('Uid:', 'Cap', 'NoNewPrivs', 'Seccomp'))]}


def comment(label):
    return ['-m', 'comment', '--comment', label]


def egress_rules(device):
    rules = [
        # The broker (UID 0) is the only resolver client. Docker's embedded resolver forwards from outside this namespace.
        ('OUTPUT', ['-o', 'lo', '-d', RESOLVER + '/32', '-m', 'owner', '--uid-owner', '0', *comment('SP_BROKER_RESOLVER_QUERY_ACCEPT'), '-j', 'ACCEPT']),
        ('OUTPUT', ['-o', 'lo', '-s', RESOLVER + '/32', '-m', 'owner', '--uid-owner', '0', *comment('SP_BROKER_RESOLVER_REPLY_ACCEPT'), '-j', 'ACCEPT'])]
    for network in NONPUBLIC:
        rules.append(('OUTPUT', ['-o', device, '-d', network, '-m', 'owner', '--uid-owner', '1001', *comment('SP_TRUSTED_NONPUBLIC_DROP'), '-j', 'DROP']))
    rules += [('OUTPUT', ['-o', device, '-m', 'conntrack', '--ctstate', 'ESTABLISHED', '-m', 'owner', '--uid-owner', '1001',
                          *comment('SP_TRUSTED_ESTABLISHED_ACCEPT'), '-j', 'ACCEPT']),
              ('OUTPUT', ['-o', device, '-m', 'owner', '--uid-owner', '1001', *comment('SP_TRUSTED_OTHER_DROP'), '-j', 'DROP']),
              ('INPUT', ['-i', device, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', *comment('SP_EGRESS_REPLY_ACCEPT'), '-j', 'ACCEPT'])]
    return rules


def flush_grants():
    removed = 0
    for line in grant_rules():
        parts = shlex.split(line)
        if parts[:2] != ['-A', 'OUTPUT']:
            continue
        call('iptables', '-w', '-D', 'OUTPUT', *parts[2:])
        removed += 1
    return removed


def main():
    obj = json.loads(sys.stdin.buffer.readline(4097))
    if obj['netns'] != os.readlink('/proc/self/ns/net'):
        raise ValueError('namespace mismatch')
    kind = obj['type']
    if kind == 'snapshot':
        print(json.dumps(snapshot()))
        return
    if kind not in ('prepare', 'install', 'egress_open', 'egress_close', 'fixture_routes') or os.getuid() != 0:
        raise ValueError('trusted setup only')
    extra = {}
    if kind == 'prepare':
        for address in ('169.254.169.254/32', '10.231.77.5/32'):
            call('ip', 'address', 'add', address, 'dev', 'lo')
        for binary in ('iptables', 'ip6tables'):
            for chain in ('INPUT', 'OUTPUT', 'FORWARD'):
                call(binary, '-w', '-P', chain, 'DROP')
            call(binary, '-w', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT')
            if binary == 'iptables':
                call(binary, '-w', '-A', 'OUTPUT', '-o', 'lo', '-d', RESOLVER + '/32', '-m', 'owner', '--uid-owner', '1001',
                     *comment('SP_WORKER_DNS_DROP'), '-j', 'DROP')
                call(binary, '-w', '-A', 'OUTPUT', '-o', 'lo', '-s', BROKER + '/32', '-p', 'tcp', '--sport', str(BROKER_PORT),
                     '-m', 'owner', '--uid-owner', '0', *comment('SP_BROKER_REPLY_ACCEPT'), '-j', 'ACCEPT')
            call(binary, '-w', '-A', 'OUTPUT', '-o', 'lo', '-m', 'owner', '--uid-owner', '1001', '-j', 'ACCEPT')
    elif kind == 'install':
        proxies = obj['proxy_ports']
        if type(proxies) is not list or not proxies or any(type(p) is not int or not 1024 <= p <= 65535 for p in proxies):
            raise ValueError('ports')
        for proxy in proxies:
            call('iptables', '-w', '-A', 'OUTPUT', '-o', 'lo', '-d', '127.0.0.1', '-p', 'tcp', '--dport', str(proxy),
                 '-m', 'owner', '--uid-owner', '1000', '-j', 'ACCEPT')
        for proto, more, label in (('udp', ['--dport', '53'], 'SP_BROWSER_DNS_DROP'), ('udp', [], 'SP_BROWSER_UDP_DROP'),
                                   ('tcp', [], 'SP_BROWSER_TCP_DROP')):
            call('iptables', '-w', '-A', 'OUTPUT', '-p', proto, *more, '-m', 'owner', '--uid-owner', '1000', *comment(label), '-j', 'DROP')
        call('ip6tables', '-w', '-A', 'OUTPUT', '-m', 'owner', '--uid-owner', '1000', *comment('SP_BROWSER_IPV6_DROP'), '-j', 'DROP')
    elif kind == 'fixture_routes':
        device = egress_device(obj)
        if obj.get('fixture') is not True:
            raise ValueError('fixture networks only')
        for network in FIXTURE_ROUTES:
            call('ip', 'route', 'add', network, 'dev', device)
    elif kind == 'egress_open':
        for chain, spec in egress_rules(egress_device(obj)):
            call('iptables', '-w', '-A', chain, *spec)
    else:
        extra['grants_flushed'] = flush_grants()
        for chain, spec in reversed(egress_rules(egress_device(obj))):
            call('iptables', '-w', '-D', chain, *spec)
    print(json.dumps({**snapshot(), **extra}))


if __name__ == '__main__':
    main()
