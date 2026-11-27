"""The light HTTP Worker (container, UID 1000): one HTTPS request per job line through the owned proxy, then it exits. No browser, no files, no keys.

What the operating system leaves it (tests/runtime/netpolicy_hardened.py, the rules measured for the browser identity): the proxy port on loopback and
nothing else -- no DNS, no other TCP, no UDP, no IPv6. The ProcessGuard (audit hook) is a second, weaker layer inside the process: a refusal there means
this code tried something it never should, and is reported. Input: one JSON line on stdin; output: one JSON line. It decides nothing about WHETHER a
check is allowed; the host does (grant, ledger) and the proxy / broker / OS rules decide where a connection may go.
"""
import json
import os
from pathlib import Path
import ssl
import sys

from src.aws_b.probe import TlsTransport
from src.isolation.http_exchange import exchange
from src.isolation.process_guard import ProcessGuard

UID = 1000
MAX_JOB = 16 * 1024


class FixtureTls(TlsTransport):
    """Fixture runs only: additionally trusts the run's own throw-away certificate (verification stays on)."""

    def __init__(self, pem):
        super().__init__()
        self._context.load_verify_locations(cadata=pem)


def parse(raw):
    job = json.loads(raw)
    if set(job) - {'ca_pem'} != {'host', 'path', 'proxy_port', 'timeout'}:
        raise ValueError('job')
    if not (isinstance(job['host'], str) and isinstance(job['path'], str) and job['path'].startswith('/') and type(job['proxy_port']) is int
            and type(job['timeout']) in (int, float) and 0 < job['timeout'] <= 30):
        raise ValueError('job')
    if job.get('ca_pem') is not None and not job['host'].endswith('.invalid'):
        raise ValueError('an extra certificate is for fixtures only')
    return job


def identity():
    """What the host checks: who this process is and what it can see."""
    status = [x for x in Path('/proc/self/status').read_text().splitlines() if x.startswith(('Cap', 'NoNewPrivs', 'Seccomp'))]
    return {'uid': os.getuid(), 'netns': os.readlink('/proc/self/ns/net'), 'status': status,
            'sockets': [p for p in ('/var/run/docker.sock', '/run/docker.sock', '/run/containerd/containerd.sock') if os.path.exists(p)],
            'resolv': os.path.exists('/etc/resolv.conf')}


def main():
    if os.getuid() != UID:
        raise SystemExit('untrusted Worker UID required')
    out = {'identity': identity()}
    try:
        job = parse(sys.stdin.buffer.readline(MAX_JOB + 1))
        transport = FixtureTls(job['ca_pem']) if job.get('ca_pem') else TlsTransport()
        guard = ProcessGuard(None, job['proxy_port'])  # no name may be looked up here at all
        guard.pin('127.0.0.1', job['proxy_port'])
        guard.install()
        out['result'] = exchange(job['host'], job['path'], job['proxy_port'], job['timeout'], transport=transport)
        out['guard'] = {'denied': list(guard.denied), 'connects': guard.connects, 'lookups': guard.lookups}
    except (ValueError, ssl.SSLError) as exc:
        out['error'] = type(exc).__name__
    sys.stdout.write(json.dumps(out) + '\n')
    sys.stdout.flush()


if __name__ == '__main__':
    main()
