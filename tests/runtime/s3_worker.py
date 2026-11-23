"""S3-1 trusted Worker (UID 1001): real-site capture of ONE page of ONE registered host through the existing runtime pipeline.

Reused unchanged: noxiworks.capture.create_runtime (new local evidence workspace, never replaces or approves a Baseline),
RuntimeService.run (single batch deadline, CONNECT ledger window per job, cleanup supervision), ComparisonService (Baseline CANDIDATE
registration only; `approve`/`decide` is never called here), s2b_worker.RecordingTransport (production policy, ledger and `_dial`),
BrokeredResolver (the only name-resolution path of this UID). The host and path are fixed by the registered target `ttn-home`
(targets.json) plus the constant path below; nothing is passed in. `site_policy.REAL_SITE_ACCESS_ENABLED` is flipped in THIS process only.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import uuid
from urllib.parse import urlsplit

from tests.runtime import linux_worker as base
from tests.runtime import s2b_worker as s2b
from src.core.frames import CheckType
from src.core.model import JobIntent
from src.core.offline import profile_body, read_profile
from src.isolation import site_policy
from src.isolation.connect_dns import DnsLimits
from src.isolation.frames import FrameReader, TrustedContext
from src.isolation.site_policy import SiteEntry, SiteNetworkPlan, real_site_policy
from src.isolation.transport import TransportLimits
from src.noxiworks.capture import create_runtime
from src.runtime.stability import verify as verify_stability
from tests.runtime.s2h_probe import tcp
from tests.runtime.s2v_worker import Recording, deny_matrix

# Permit mode: the harness mounts the signed, hash-pinned target files read-only and names them here; default = legacy TTN.
TARGETS = os.environ.get('SITEPROOF_TARGETS') or '/opt/siteproof/src/noxiworks/targets.json'
TARGET_ID = os.environ.get('SITEPROOF_TARGET_ID') or 'ttn-home'
PATH = '/about'  # Canonical URL: /about.html answers 307 -> /about (S3-1). Same registered host; nothing else changes.
PAGE_ID = 'ttn-about'
LEASE = 'job'
RUNTIME = {}
INFO = {}
STABILITY = None  # Capture stability policy sent with every capture request (src/runtime/stability.py); None = the default policy.


def registered():
    config = json.load(open(TARGETS, encoding='utf-8'))
    page = next(p for p in config['pages'] if p['target_id'] == TARGET_ID)
    site = next(s for s in config['sites'] if s['site_id'] == page['site_id'])
    u, o = urlsplit(page['url']), urlsplit(site['origin'])
    if (u.scheme != 'https' or u.port not in (None, 443) or u.hostname != o.hostname or u.path != '/' or u.username or u.password
            or u.query or u.fragment or o.path or not u.hostname):
        raise RuntimeError('registered target is not a plain https origin')
    return u.hostname, 'https://' + u.hostname + PATH, site


def start_brokered():
    host, url, site = registered()
    plan = SiteNetworkPlan('REAL', (SiteEntry(TARGET_ID, (host,)),), enabled=True)
    site_policy.REAL_SITE_ACCESS_ENABLED = True  # This process only, until stop_real.
    policy = real_site_policy(plan)
    limits = base.BudgetLimits(16 * 1024 * 1024, 32, 8, 64, 300)
    session = base.QuotaSession('s3-real', base.NetworkBudget(limits, limits), base.IoLimits(16384, 65536),
                                termination_limits=base.TerminationLimits(8, 30))
    resolver = Recording(LEASE)
    proxy = s2b.RecordingTransport(session, policy, resolver, DnsLimits(16, 1024), TransportLimits(4096, 3, .01, 16, 5), listen_port=base.PROXY_PORT)
    proxy.start()
    lease = base.ProxyLease(proxy)
    s2b.STATE.update(lease=lease, resolver=resolver, host=host, plan=plan)
    RUNTIME['lease'] = lease
    return {'host': host, 'url': url, 'hostnames': [d.hostname for d in policy.allowlist], 'ports': [d.port for d in policy.allowlist],
            'flag_during_run': site_policy.REAL_SITE_ACCESS_ENABLED, 'resolver': type(resolver).__name__}


def head_path(lease):
    """One HEAD of the exact page through the Connector (strict TLS, redirects never followed): is it there, and is it where we expect?"""
    host = s2b.STATE['host']
    out = s2b.traced(lease, host + ':443', tls_host=host, wait=20, request=(
        f'HEAD {PATH} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {s2b.USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n\r\n').encode('ascii'))
    location = (out.get('http_headers') or {}).get('location')
    if location:
        target = urlsplit(location)
        out['redirect'] = {'followed': False, 'target_host': target.hostname, 'same_host': target.hostname in (None, host), 'target': location[:200]}
    return out


def create():
    host, url, site = registered()
    config = {'pages': [{'target_id': PAGE_ID, 'label': 'About', 'url': url, 'site_name': site['name']}]}
    runtime = create_runtime(Path('/evidence/ws'), config)
    RUNTIME.update(runtime=runtime, url=url)
    return {'site': site['name'], 'origin': 'https://' + host, 'url': url}


def prepare(kind):
    """One job (one profile kind) per batch, so each capture can have its own short window. Mirrors noxiworks.capture.prepare_batch."""
    runtime = RUNTIME['runtime']
    batch = uuid.uuid4().hex
    snapshot = runtime.store.snapshot(batch)
    pages = {p['page_id']: p for p in snapshot['pages']}
    rows = [r for r in snapshot['profiles'] if r['kind'] == kind]
    if len(rows) != 1 or set(pages) != {PAGE_ID}:
        raise ValueError('workspace does not hold exactly the expected page/profile')
    row = rows[0]
    url = snapshot['site']['origin'] + pages[PAGE_ID]['path']
    if url != RUNTIME['url']:
        raise ValueError('workspace URL mismatch')
    profile = read_profile(row['body'])
    if profile.fingerprint != row['fingerprint']:
        raise ValueError('capture profile mismatch')
    source = 'OWNER_SITE_UNATTESTED'
    plan = runtime.comparison.prepare(profile, PAGE_ID, kind, source)
    intent = JobIntent(url, PAGE_ID, profile.profile_id, tuple(CheckType), plan['baseline']['candidate_id'] if plan['baseline'] else None)
    job = runtime.repo.accept_job('s3-' + uuid.uuid4().hex, intent).job
    runtime.store.bind(job.job_id, batch, {'page': pages[PAGE_ID], 'profile': {'profile_id': profile.profile_id, 'attributes': dict(profile.attributes)},
                                           'fingerprint': profile.fingerprint, 'profile_revision': row['revision'], 'kind': kind,
                                           'snapshot_sha256': job.snapshot.sha256, 'source': source})
    runtime.comparison.bind(job, plan)
    return {'batch': batch, 'job_id': job.job_id, 'kind': kind, 'fingerprint': profile.fingerprint, 'profile': profile_body(profile), 'url': url}


def remote(req, remaining):
    runtime = RUNTIME['runtime']
    running = [j for j, _, _ in runtime.store.bindings() if runtime.repo.get_job(j).status.value == 'RUNNING']
    if len(running) != 1:
        raise RuntimeError('single active child required')
    jid = running[0]
    base.output({'type': 'capture', 'job_id': jid, 'request': {'page_id': req.page_id, 'profile': profile_body(req.profile), 'url': req.url, 'baseline_id': req.baseline_id,
                                                              'stability': STABILITY},
                 'remaining': remaining, 'resources': vars(base.RESOURCES)})
    reply = base.command()
    length, repeat_length = reply.get('length'), reply.get('repeat_length', 0)
    if (reply.get('type') != 'capture_result' or type(length) is not int or type(repeat_length) is not int
            or min(length, repeat_length) < 0 or length + repeat_length > base.RESOURCES.output_bytes):
        raise ValueError('bounded producer payload required')
    wire = base.sys.stdin.buffer.read(length)
    repeat = base.sys.stdin.buffer.read(repeat_length)
    if len(wire) != length or len(repeat) != repeat_length:
        raise EOFError()
    audit_length = reply.get('audit_length', 0)
    if type(audit_length) is not int or not 0 <= audit_length <= 262144:
        raise ValueError('bounded audit payload required')
    audit_raw = base.sys.stdin.buffer.read(audit_length)
    if len(audit_raw) != audit_length:
        raise EOFError()
    try:
        request_audit = json.loads(audit_raw) if audit_raw else None
    except ValueError:
        request_audit = {'not': 'json'}  # Recorded as INVALID by the service, never repaired.
    runtime.record_browser_audit(jid, request_audit)  # Untrusted: rebuilt and validated; it can only ever lower a verdict.
    if reply.get('reason') == 'CAPTURE_COMPLETE':
        stream = FrameReader(io.BytesIO(wire), TrustedContext(jid, 'capture-1', 1)).read()
        png = next(f.payload for f in stream.frames if f.kind == 'SCREENSHOT_PNG')
        # Trusted check of the producer's stability claim against the two PNGs received here (same rule as the M5 observer).
        stability = verify_stability((reply.get('browser_report') or {}).get('stability'), png, repeat, STABILITY)
        runtime.record_capture_stability(jid, stability)
        INFO[jid] = {'screenshot_sha256': hashlib.sha256(png).hexdigest(), 'repeat_sha256': hashlib.sha256(repeat).hexdigest() if repeat else None,
                     'repeat_identical': png == repeat if repeat else None, 'screenshot_bytes': len(png), 'stability': stability}
    return io.BytesIO(wire), reply['reason'], reply.get('cleanup') is True


def run(batch):
    runtime = RUNTIME['runtime']
    state = runtime.run(batch, remote, RUNTIME['lease'], base.RESOURCES)
    return {'state': state, 'comparison': runtime.comparison.state(), 'baselines': runtime.workspace.state()['baselines'], 'capture_info': dict(INFO)}


def main():
    if os.getuid() != 1001:
        raise RuntimeError('trusted Worker UID required')
    for address, key in ((('127.0.0.2', 18555), 'tcp'), (('169.254.169.254', 80), 'metadata'), (('10.231.77.5', 18555), 'lan'),
                         (('127.0.0.4', 18555), 'host_model'), (('127.0.0.5', 2375), 'docker_api')):
        base.canary(address, key=key)
    base.canary(('127.0.0.3', 53), kind=socket.SOCK_DGRAM, key='dns')
    base.canary(('127.0.0.3', 5353), kind=socket.SOCK_DGRAM, key='udp')
    base.canary(('::1', 18555), family=socket.AF_INET6, key='ipv6')
    host, url, _ = registered()
    base.output({'type': 'ready', 'proxy_port': base.PROXY_PORT, 'namespace': os.readlink('/proc/self/ns/net'), 'uid': os.getuid(),
                 'resources': vars(base.RESOURCES), 'registered_host': host, 'target_url': url, 'flag_at_start': site_policy.REAL_SITE_ACCESS_ENABLED})
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
            elif kind == 'ledger_window':
                base.output({'type': 'ledger_window', 'window': lease.ledger.window((0, 0, 0))})
            elif kind == 'head_path':
                base.output({'type': 'head_path', 'result': head_path(lease)})
            elif kind == 'deny_matrix':
                base.output({'type': 'deny_matrix', 'results': deny_matrix(lease, command['gateway']), 'resolver_calls': len(s2b.STATE['resolver'].log)})
            elif kind == 'direct':
                base.output({'type': 'direct', 'results': {n: tcp(ip, port) for n, ip, port in command['targets']}})
            elif kind == 'create':
                base.output({'type': 'created', **create()})
            elif kind == 'prepare':
                base.output({'type': 'prepared', **prepare(command['kind'])})
            elif kind == 'run':
                base.output({'type': 'result', **run(command['batch'])})
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
