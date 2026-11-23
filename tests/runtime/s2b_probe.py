"""S2-B: direct-path probe from one exact identity (Browser UID 1000 or trusted UID 1001). No Chromium, no proxy use.

Every target is either a controlled loopback canary, a documentation/reserved address (RFC 5737 / 3849, never
routable), the Docker bridge gateway or Docker Desktop host-gateway model of THIS run's own namespace, Docker's
embedded resolver, or the already-resolved address of the single allowed host on a port other than 443.
A packet to any of these that the OS rules fail to stop would still not reach a third party's service.
Each result is "was a connection or reply obtained"; the errno name is kept as evidence of HOW it failed.
"""
import errno
import json
import os
from pathlib import Path
import socket
import sys


def tcp(host, port, family=socket.AF_INET):
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(.35)
        try:
            s.connect((host, port))
            return True, 'CONNECTED'
        except OSError as exc:
            return False, errno.errorcode.get(exc.errno, type(exc).__name__) if exc.errno else type(exc).__name__


def udp(host, port, payload=b'SITEPROOF-CONTROLLED-PROBE'):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(.35)
        try:
            s.sendto(payload, (host, port))
            return bool(s.recvfrom(512)[0]), 'REPLY'
        except OSError as exc:
            return False, errno.errorcode.get(exc.errno, type(exc).__name__) if exc.errno else type(exc).__name__


def main():
    config = json.loads(sys.stdin.buffer.readline(16385))
    uid = os.getuid()
    gateway = config['gateway']
    targets = {
        'canary_tcp': ('127.0.0.2', 18555), 'canary_host_model': ('127.0.0.4', 18555),
        'canary_metadata': ('169.254.169.254', 80), 'canary_lan': ('10.231.77.5', 18555),
        'docker_api_model': ('127.0.0.5', 2375), 'embedded_resolver_tcp': ('127.0.0.11', 53),
        'bridge_gateway_443': (gateway, 443), 'bridge_gateway_2375': (gateway, 2375),
        'desktop_host_model_443': ('192.168.65.254', 443), 'desktop_host_model_2375': ('192.168.65.254', 2375),
        'documentation_443': ('192.0.2.1', 443), 'documentation_80': ('192.0.2.1', 80)}
    if config.get('real_ip'):
        targets['allowed_ip_port_80'] = (config['real_ip'], 80)
        targets['allowed_ip_port_8443'] = (config['real_ip'], 8443)
        targets['allowed_ip_direct_443'] = (config['real_ip'], 443) if config.get('direct_443') else None
    results, errors = {}, {}
    for key, target in targets.items():
        if target is not None:
            results[key], errors[key] = tcp(*target)
    datagrams = {'canary_dns': ('127.0.0.3', 53, b'SITEPROOF-CONTROLLED-PROBE'),
                 'canary_udp': ('127.0.0.3', 5353, b'SITEPROOF-CONTROLLED-PROBE'),
                 'documentation_udp_53': ('192.0.2.1', 53, b'x')}
    if not config.get('skip_resolver'):  # The trusted identity must not send a real DNS query as a probe.
        datagrams['embedded_resolver_udp'] = ('127.0.0.11', 53, b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03s2b\x07invalid\x00\x00\x01\x00\x01')
    for key, (host, port, payload) in datagrams.items():
        results[key], errors[key] = udp(host, port, payload)
    for key, (host, port) in {'canary_ipv6': ('::1', 18555), 'documentation_ipv6_443': ('2001:db8::1', 443)}.items():
        results[key], errors[key] = tcp(host, port, socket.AF_INET6)
    results['proxy_port'], errors['proxy_port'] = tcp('127.0.0.1', config['proxy_port'])
    print(json.dumps({'uid': uid, 'netns': os.readlink('/proc/self/ns/net'), 'results': results, 'errors': errors,
                      'cgroup': {n: Path('/sys/fs/cgroup/' + n).read_text().strip() for n in ('memory.max', 'pids.max', 'cpu.max')},
                      'status': [x for x in Path('/proc/self/status').read_text().splitlines()
                                 if x.startswith(('Cap', 'NoNewPrivs', 'Seccomp'))]}))


if __name__ == '__main__':
    main()
