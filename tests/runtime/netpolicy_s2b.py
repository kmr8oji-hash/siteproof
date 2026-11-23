"""S2-B: runs ONLY in a new SiteProof network namespace via a short-lived NET_ADMIN helper.

Never run this on the Windows/WSL host or an existing container. The host launcher verifies that the
namespace belongs to its newly created, labelled anchor before invoking it.

Same base rules as netpolicy.py (OUTPUT/INPUT/FORWARD default DROP for IPv4 and IPv6; the Browser UID may reach
only the owned loopback proxy), plus ONE temporary, reversible egress window for the trusted Worker UID:

  egress_open   UID 1001 -> TCP/443 on the bridge interface, except every non-public IPv4 range (checked first);
                loopback-only path to Docker's embedded resolver (query = UID 1001, reply = UID 0); replies in.
                The resolver forwards from OUTSIDE this namespace (measured: DNS never appears on the bridge
                interface), so while closed the baseline drops even the trusted UID's query to 127.0.0.11.
  egress_close  deletes exactly those rules again. The rule set is then identical to the closed baseline.

IPv6 stays fully dropped (no rule here ever opens it). UID 1000 (Browser) never gets a rule for the bridge
interface; it only has DROP rules (counted) and the chain policy. The application allowlist is therefore not the
only boundary: the OS rules below hold even if the proxy were bypassed.
"""
import json
import os
from pathlib import Path
import subprocess
import sys


NONPUBLIC = ('0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24',
             '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4',
             '240.0.0.0/4')


def call(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def default_route():
    routes = json.loads(call('ip', '-j', 'route', 'show', 'default'))
    if len(routes) != 1 or not routes[0].get('dev') or not routes[0].get('gateway'):
        raise ValueError('exactly one default route required')
    return routes[0]['dev'], routes[0]['gateway']


def plain(binary):
    return '\n'.join(line for line in call(binary + '-save').splitlines() if not line.startswith('#'))


def snapshot():
    try:
        device, gateway = default_route()
    except (ValueError, subprocess.CalledProcessError):
        device = gateway = None
    try:
        conntrack = Path('/proc/net/nf_conntrack').read_text().splitlines()[:400]
    except OSError as exc:
        conntrack = 'UNAVAILABLE:' + type(exc).__name__
    return {'netns': os.readlink('/proc/self/ns/net'), 'conntrack': conntrack,
            'ipv4': call('iptables-save', '-c'), 'ipv6': call('ip6tables-save', '-c'),
            'rules_plain': plain('iptables') + '\n' + plain('ip6tables'),
            'routes': json.loads(call('ip', '-j', 'route', 'show', 'table', 'all')),
            'addresses': json.loads(call('ip', '-j', 'address')), 'links': json.loads(call('ip', '-s', '-j', 'link')),
            'default_device': device, 'default_gateway': gateway,
            'status': [x for x in Path('/proc/self/status').read_text().splitlines()
                       if x.startswith(('Uid:', 'Cap', 'NoNewPrivs', 'Seccomp'))]}


def egress_rules(device):
    """(chain, spec, insert_first). Rules with insert_first must precede the closed-baseline resolver DROP."""
    rules = [
        # Docker's embedded resolver (127.0.0.11) answers from root-owned sockets and forwards from OUTSIDE this
        # namespace (measured: no packet ever left eth0 for DNS). While the window is closed the trusted UID may not even
        # send it a query (SP_RESOLVER_CLOSED_DROP in prepare); while open, query = UID 1001, reply = UID 0, loopback only.
        ('OUTPUT', ['-o', 'lo', '-d', '127.0.0.11/32', '-m', 'owner', '--uid-owner', '1001',
                    '-m', 'comment', '--comment', 'SP_RESOLVER_QUERY_ACCEPT', '-j', 'ACCEPT'], True),
        ('OUTPUT', ['-o', 'lo', '-s', '127.0.0.11/32', '-m', 'owner', '--uid-owner', '0',
                    '-m', 'comment', '--comment', 'SP_RESOLVER_REPLY_ACCEPT', '-j', 'ACCEPT'], True)]
    for proto in ('udp', 'tcp'):  # Kept in case a Docker version forwards from inside the namespace; 0 hits are expected.
        rules.append(('OUTPUT', ['-o', device, '-p', proto, '--dport', '53', '-m', 'owner', '--uid-owner', '0',
                                 '-m', 'comment', '--comment', 'SP_DNS_FORWARDER_ACCEPT', '-j', 'ACCEPT'], False))
    for network in NONPUBLIC:
        rules.append(('OUTPUT', ['-o', device, '-d', network, '-m', 'owner', '--uid-owner', '1001',
                                 '-m', 'comment', '--comment', 'SP_TRUSTED_NONPUBLIC_DROP', '-j', 'DROP'], False))
    rules.append(('OUTPUT', ['-o', device, '-p', 'tcp', '--dport', '443', '-m', 'owner', '--uid-owner', '1001',
                             '-m', 'comment', '--comment', 'SP_TRUSTED_HTTPS_ACCEPT', '-j', 'ACCEPT'], False))
    rules.append(('OUTPUT', ['-o', device, '-m', 'owner', '--uid-owner', '1001',
                             '-m', 'comment', '--comment', 'SP_TRUSTED_OTHER_DROP', '-j', 'DROP'], False))
    rules.append(('INPUT', ['-i', device, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED',
                            '-m', 'comment', '--comment', 'SP_EGRESS_REPLY_ACCEPT', '-j', 'ACCEPT'], False))
    return rules


def main():
    obj = json.loads(sys.stdin.buffer.readline(4097))
    if obj['netns'] != os.readlink('/proc/self/ns/net'):
        raise ValueError('namespace mismatch')
    kind = obj['type']
    if kind == 'snapshot':
        print(json.dumps(snapshot()))
        return
    if kind not in ('prepare', 'install', 'egress_open', 'egress_close') or os.getuid() != 0:
        raise ValueError('trusted setup only')
    if kind == 'prepare':
        for address in ('169.254.169.254/32', '10.231.77.5/32'):
            call('ip', 'address', 'add', address, 'dev', 'lo')
        for binary in ('iptables', 'ip6tables'):
            for chain in ('INPUT', 'OUTPUT', 'FORWARD'):
                call(binary, '-w', '-P', chain, 'DROP')
            call(binary, '-w', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT')
            if binary == 'iptables':  # Closed baseline: no DNS through Docker's embedded resolver (see egress_rules).
                call(binary, '-w', '-A', 'OUTPUT', '-o', 'lo', '-d', '127.0.0.11/32', '-m', 'owner', '--uid-owner', '1001',
                     '-m', 'comment', '--comment', 'SP_RESOLVER_CLOSED_DROP', '-j', 'DROP')
            call(binary, '-w', '-A', 'OUTPUT', '-o', 'lo', '-m', 'owner', '--uid-owner', '1001', '-j', 'ACCEPT')
    elif kind == 'install':
        ui, proxy = obj['ui_port'], obj['proxy_port']
        if any(type(p) is not int or not 1024 <= p <= 65535 for p in (ui, proxy)):
            raise ValueError('ports')
        call('iptables', '-w', '-A', 'OUTPUT', '-o', 'lo', '-d', '127.0.0.1', '-p', 'tcp', '--dport', str(proxy),
             '-m', 'owner', '--uid-owner', '1000', '-j', 'ACCEPT')
        for proto, extra, label in (('udp', ['--dport', '53'], 'SP_BROWSER_DNS_DROP'),
                                    ('udp', [], 'SP_BROWSER_UDP_DROP'), ('tcp', [], 'SP_BROWSER_TCP_DROP')):
            call('iptables', '-w', '-A', 'OUTPUT', '-p', proto, *extra, '-m', 'owner', '--uid-owner', '1000',
                 '-m', 'comment', '--comment', label, '-j', 'DROP')
        call('ip6tables', '-w', '-A', 'OUTPUT', '-m', 'owner', '--uid-owner', '1000',
             '-m', 'comment', '--comment', 'SP_BROWSER_IPV6_DROP', '-j', 'DROP')
    else:
        device, _ = default_route()
        rules = egress_rules(device)
        if kind == 'egress_open':
            for chain, spec, first in rules:
                call('iptables', '-w', *(['-I', chain, '1'] if first else ['-A', chain]), *spec)
        else:
            for chain, spec, _ in reversed(rules):
                call('iptables', '-w', '-D', chain, *spec)
    print(json.dumps(snapshot()))


if __name__ == '__main__':
    main()
