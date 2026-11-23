"""S2-B-HARDEN direct-path probe from ONE exact identity (Browser UID 1000 or trusted UID 1001). No Chromium.

  mode `connect`  : TCP connects to the given [name, ip, port] targets (0.35 s each). Reports reached/banner/errno.
  mode `udp`      : one datagram to each [name, ip, port] (reply = reached).
  mode `resolve`  : (trusted identity only) asks the broker, like the Worker's BrokeredResolver, for ONE host under ONE lease.
Every target is an address of this run's isolated fixture network, a documentation address, or a loopback address of this namespace.
"""
import errno
import json
import os
from pathlib import Path
import socket
import sys

from src.isolation.egress_grant import BrokeredResolver


def tcp(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(.35)
        try:
            s.connect((ip, port))
            try:
                banner = s.recv(32).decode('ascii', 'replace').strip()
            except OSError:
                banner = ''
            return {'reached': True, 'errno': 'CONNECTED', 'banner': banner}
        except OSError as exc:
            return {'reached': False, 'errno': errno.errorcode.get(exc.errno, type(exc).__name__) if exc.errno else type(exc).__name__, 'banner': ''}


def udp(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(.35)
        try:
            s.sendto(b'SITEPROOF-CONTROLLED-PROBE', (ip, port))
            return {'reached': bool(s.recvfrom(512)[0]), 'errno': 'REPLY', 'banner': ''}
        except OSError as exc:
            return {'reached': False, 'errno': errno.errorcode.get(exc.errno, type(exc).__name__) if exc.errno else type(exc).__name__, 'banner': ''}


def main():
    config = json.loads(sys.stdin.buffer.readline(16385))
    uid, results = os.getuid(), {}
    if config['mode'] == 'resolve':
        resolver = BrokeredResolver(config['lease'])
        try:
            answer = resolver.resolve_complete(config['host'])
            results = {'status': answer.status, 'addresses': list(answer.addresses), 'denials': resolver.denials}
        except OSError as exc:
            results = {'status': 'EXCEPTION', 'error': type(exc).__name__, 'denials': resolver.denials}
    else:
        for name, ip, port in config['targets']:
            results[name] = (tcp if config['mode'] == 'connect' else udp)(ip, port)
    print(json.dumps({'uid': uid, 'netns': os.readlink('/proc/self/ns/net'), 'results': results,
                      'cgroup': {n: Path('/sys/fs/cgroup/' + n).read_text().strip() for n in ('memory.max', 'pids.max', 'cpu.max')},
                      'status': [x for x in Path('/proc/self/status').read_text().splitlines() if x.startswith(('Cap', 'NoNewPrivs', 'Seccomp'))]}))


if __name__ == '__main__':
    main()
