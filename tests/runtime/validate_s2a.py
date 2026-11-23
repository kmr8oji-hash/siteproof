"""S2-A / S2-A-FIX: offline validation of the real-site network restrictions with real Chromium in the
existing isolated Docker runtime. No registry, no real site, no AWS, no image build/pull.

Derived from validate_m5 (unchanged): identical dedicated resources, the same measured
preflight and Chromium bypass checks, then a fixed list of cases. The image still holds the
pre-S1 sources, so the CURRENT worktree `src` and `tests/runtime` are bind-mounted
read-only over /opt/siteproof; no existing image tag or evidence volume is touched.
Only the labelled resources this run creates are stopped/removed (never prune).
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import time
import uuid

from src.runtime.docker_launcher import DockerLauncher, read_control, send_control


FORBIDDEN = ('tcp', 'dns', 'udp', 'metadata', 'lan', 'host_model', 'ipv6')
M5_IMAGE = 'sha256:9c88112b42070369876fdb24476af283b3908a3fdc630b66fedacf4f20c4d2c8'
NO_CHANGE, CHANGED, UNKNOWN = 'NO_VISUAL_CHANGE_DETECTED', 'VISUAL_CHANGED', 'UNKNOWN'


class IsolationLeak(RuntimeError):
    pass


class ExperimentDone(Exception):
    pass


def tree_digest(root):
    entries = {}
    for path in sorted(Path(root).rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts:
            entries[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest(), len(entries)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--image', default=M5_IMAGE)
    parser.add_argument('--experiment', help='JSON list of {label, extra_args}: launch-switch comparison only')
    args = parser.parse_args()
    evidence = Path(args.evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    root = Path.cwd()
    launch = DockerLauncher(evidence, args.image, root / 'runtime/docker/seccomp-siteproof.json')
    prefix = 'siteproof-m2-s2a-' + time.strftime('%H%M%S') + '-' + uuid.uuid4().hex[:6]
    report = {'task': 'SITEPROOF-S2A-OFFLINE-ISOLATION-01', 'passed': False, 'chromium_started': False,
              'formal_T01_T21': 'UNKNOWN', 'profile_trust': 'UNATTESTED', 'real_site_access': False}
    worker_process = None
    worker_log = None
    anchor = policy = capture_container = None
    job_ids = []
    counter = 0
    cases = {}
    checks = {}

    def name(label):
        nonlocal counter
        counter += 1
        return prefix + '-' + label + '-' + str(counter)

    def other_containers():
        return sorted(launch.call('ps', '-a', '--no-trunc', '--format', '{{.ID}}|{{.Names}}|{{.State}}').splitlines())

    original_containers = other_containers()
    launch.save('other-containers-before.json', original_containers)
    original_networks = sorted(launch.call('network', 'ls', '--format', '{{.ID}}|{{.Name}}').splitlines())
    original_volumes = sorted(launch.call('volume', 'ls', '--format', '{{.Name}}').splitlines())
    original_images = sorted(launch.call('images', '--no-trunc', '--format', '{{.Repository}}:{{.Tag}}|{{.ID}}').splitlines())
    launch.save('docker-inventory-before.json', {'networks': original_networks, 'volumes': original_volumes,
                                                  'images': original_images})

    def control(command, seconds=30):
        send_control(worker_process, command)
        return read_control(worker_process, seconds)

    def helper(label, uid, module, *, admin=False, mounts=()):
        opts = launch.options(anchor, uid, mounts=mounts)
        if admin:
            opts += ['--cap-add', 'NET_ADMIN']
        return launch.create(name(label), opts, ['python', '-m', module])

    def policy_call(kind, **kwargs):
        out, _ = launch.bounded(policy, json.dumps({'type': kind, 'netns': namespace, **kwargs}).encode() + b'\n')
        result = json.loads(out)
        launch.save('policy-' + kind + '-' + str(time.monotonic_ns()) + '.json', result)
        return result

    def drops(snap):
        result = {}
        for line in (snap['ipv4'] + snap['ipv6']).splitlines():
            match = re.match(r'\[(\d+):\d+\].*--comment (SP_BROWSER_\w+_DROP)', line)
            if match:
                result[match[2]] = int(match[1])
        return result

    def counts():
        return control({'type': 'counts'})['counts']

    def no_canary_delta(before, after, label):
        delta = {k: after.get(k, 0) - before.get(k, 0) for k in FORBIDDEN}
        launch.save(label + '-canaries.json', delta)
        if any(delta.values()):
            launch.stop_all()
            raise IsolationLeak('forbidden canary received: ' + label)
        return delta

    def probe(n, uid, label, mode=None):
        config = {k: ready[k] for k in ('proxy_port', 'ui_port', 'ca_pem')}
        if mode:
            config['mode'] = mode
        out, _ = launch.bounded(n, json.dumps(config).encode() + b'\n')
        result = json.loads(out)
        launch.save(label + '.json', result)
        assert result['netns'] == namespace and result['uid'] == uid
        assert result['cgroup']['memory.max'] == '805306368' and result['cgroup']['pids.max'] == '256'
        assert result['cgroup']['cpu.max'] == '100000 100000'
        for key, value in (('CapEff:', '0000000000000000'), ('CapBnd:', '0000000000000000'),
                           ('NoNewPrivs:', '1'), ('Seccomp:', '2')):
            assert any(line.split() == [key, value] for line in result['status']), (key, result['status'])
        return result['results']

    def summarize(result):
        """Only plain facts from the Worker's own run output; nothing synthesized here."""
        jobs = result['runtime']['jobs'][:2]
        by_job = {r['job_id']: r for r in result['comparison']['results']}
        rows = []
        for job in jobs:
            r = by_job.get(job['job_id'])
            audit = (r or {}).get('network_audit') or {}
            op = (r or {}).get('operational') or {}
            rows.append({'job_id': job['job_id'], 'kind': job['kind'], 'execution': job['execution'],
                         'quality': (r or {}).get('quality'), 'verdict': op.get('verdict'),
                         'verdict_reasons': op.get('reasons'), 'strict_reasons': (r or {}).get('reasons'),
                         'profile_trust': (r or {}).get('profile_trust'),
                         'changed_pixels': ((r or {}).get('metrics') or {}).get('changed_pixels'),
                         'threshold': ((r or {}).get('policy') or {}).get('maximum_changed_pixels'),
                         'baseline': (r or {}).get('baseline'), 'context_fingerprint': (r or {}).get('context_fingerprint'),
                         'current_sha256': (r or {}).get('current_sha256'), 'baseline_sha256': (r or {}).get('baseline_sha256'),
                         'diff_sha256': (r or {}).get('diff_sha256'), 'preview_only': (r or {}).get('preview_only'),
                         'result_id': (r or {}).get('result_id'),
                         'audit': {k: audit.get(k) for k in ('source', 'schema', 'complete', 'allowed', 'blocked', 'failed', 'idle',
                                                              'dropped', 'in_flight', 'resource_types', 'anchor', 'prelude', 't0_monotonic')},
                         'audit_entries': audit.get('entries'), 'audit_timeline': audit.get('timeline'), 'candidate_id': 'capture-' + job['job_id'],
                         # The page context's own report (untrusted, downgrade-only): summary + sanitized failure entries.
                         'browser': {k: ((r or {}).get('browser_audit') or {}).get(k) for k in (
                             'source', 'monitor', 'finalized', 'complete', 'requests', 'finished', 'pending', 'dropped',
                             'handler_errors', 'failed', 'http_errors', 'failures', 'http_error_entries', 'reason')}})
        return rows

    def run_case(label, *, variant='original', mode='normal', extra=None):
        nonlocal capture_container
        assert control({'type': 'restart_proxy'})['type'] == 'proxy_ready'
        os_before = drops(policy_call('snapshot'))
        counts_before = counts()
        send_control(worker_process, {'type': 'run', 'variant': variant, 'case': mode})
        captures = []
        while True:
            msg = read_control(worker_process, 120)
            if msg['type'] == 'result':
                result = msg
                break
            assert msg['type'] == 'capture'
            job_ids.append(msg['job_id'])
            if capture_container is None:
                capture_container = helper('capture', 1000, 'tests.runtime.s1c_browser', mounts=mounts)
            config = {'mode': 'capture', 'request': msg['request'], 'proxy_port': ready['proxy_port'],
                      'resources': msg['resources'], 'netlog': True, 'probe_seconds': 6, **(extra or {})}
            path = evidence / ('capture-' + str(len(job_ids)))

            def sink(out, err, execution, path=path):
                path.with_suffix('.stdout.bin').write_bytes(out)
                path.with_suffix('.stderr.log').write_bytes(launch._redact_log(err))
                launch.save(path.name + '-execution.json', execution)
            out, _ = launch.bounded(capture_container, json.dumps(config).encode() + b'\n',
                                    seconds=min(60, msg['remaining']), evidence_sink=sink)
            line, payload = out.split(b'\n', 1)
            meta = json.loads(line)
            assert len(payload) == meta['length'] + meta['repeat_length']
            captures.append({'job_id': msg['job_id'], 'file': path.name, 'kind': msg['request']['profile']['profile_id'],
                             'reason': meta['reason'], 'cleanup': meta['cleanup'] is True, 'sandbox': meta.get('sandbox')})
            report_for_worker = dict(meta['browser_report'])
            audit = report_for_worker.pop('request_audit', None)
            audit_raw = json.dumps(audit, separators=(',', ':')).encode() if audit is not None else b''
            send_control(worker_process, {'type': 'capture_result', 'length': meta['length'],
                                          'repeat_length': meta['repeat_length'], 'audit_length': len(audit_raw), 'reason': meta['reason'],
                                          'cleanup': meta['cleanup'] is True, 'browser_report': report_for_worker}, payload + audit_raw)
        counts_after = counts()
        rows = summarize(result)
        total = result['ledger_total']
        # Per-job windows = (job part + prelude); together they must account for every record the proxy saw.
        sums = {k: sum((r['audit'].get(k) or 0) + ((r['audit'].get('prelude') or {}).get(k) or 0) for r in rows)
                for k in ('allowed', 'blocked', 'failed')}
        cases[label] = {'variant': variant, 'mode': mode, 'captures': captures, 'jobs': rows, 'ledger_total': total, 'dialed': result.get('dialed'), 'dns_calls': result.get('dns_calls'),
                        'https_served': counts_after.get('https', 0) - counts_before.get('https', 0),
                        'per_job_sum': sums, 'sum_matches_total': all(sums[k] == total[k] for k in sums),
                        # What the browser-wide (unreachable) route and any direct attempt hit at the OS boundary.
                        'os_drop_delta': {k: v - os_before.get(k, 0) for k, v in drops(policy_call('snapshot')).items()}}
        launch.save('case-' + label + '.json', cases[label])
        launch.save('case-' + label + '-full-result.json', result)
        no_canary_delta(baseline_canaries, counts(), label)
        return result, rows

    def export_evidence():
        if not anchor:
            return True
        exported = evidence / 's1'
        exported.mkdir(exist_ok=True)
        launch.call('cp', anchor + ':/evidence/siteproof.sqlite', str(exported / 'siteproof.sqlite'))
        for jid in sorted(set(job_ids)):
            try:
                launch.call('cp', anchor + ':/evidence/' + jid, str(exported / jid))
            except RuntimeError:
                pass
        for filename in ('m5-key-events.json', 'm5-observer.json'):
            try:
                launch.call('cp', anchor + ':/evidence/' + filename, str(exported / filename))
            except RuntimeError:
                pass
        return True

    try:
        image = json.loads(launch.call('image', 'inspect', launch.image))[0]
        launch.image = image['Id']
        launch.save('runtime-image.json', {'id': image['Id'], 'os': image['Os'], 'architecture': image['Architecture'],
                                           'tags': image.get('RepoTags')})
        src_digest, src_files = tree_digest(root / 'src')
        rt_digest, rt_files = tree_digest(root / 'tests/runtime')
        head = subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
        launch.save('run-conditions.json', {
            'docker_server': launch.call('version', '--format', '{{.Server.Version}}').strip(), 'host': platform.platform(),
            'python': platform.python_version(), 'image_id': image['Id'], 'git_head': head,
            'overlay': {'src': {'sha256': src_digest, 'files': src_files}, 'tests/runtime': {'sha256': rt_digest, 'files': rt_files}},
            'overlay_note': 'worktree src and tests/runtime bind-mounted read-only over the image copy; no image modified',
            'network': 'new --internal Docker network; no published ports; no registry/pull/build',
            'fixture_hosts': {'allowed': ['fixture.invalid:443'], 'fixture_dns_failure': ['down.invalid:443'],
                              'refused_by_policy': ['blocked.invalid:443']}})
        overlay = []
        for rel in ('src', 'tests/runtime'):
            overlay += ['--mount', f'type=bind,src={(root / rel).resolve()},dst=/opt/siteproof/{rel},readonly']
        network = launch.create_network(prefix + '-network')
        volume = launch.create_volume(prefix + '-evidence')
        init = launch.create(name('volume-init'), ['--network', 'none', '--user', '0:0', '--cap-drop', 'ALL', '--cap-add', 'CHOWN',
            '--security-opt', 'no-new-privileges=true', '--read-only', '--mount', f'type=volume,src={volume},dst=/evidence'],
            ['python', '-c', "import os;os.chmod('/evidence',0o700);os.chown('/evidence',1001,1001)"])
        launch.bounded(init)
        launch.retire(init)
        anchor = launch.create(name('worker'), [*overlay, '--network', network, '--user', '1001:1001', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges=true', '--read-only', '--pids-limit', '128', '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
            '--sysctl', 'net.ipv6.conf.all.disable_ipv6=0', '--sysctl', 'net.ipv4.ip_unprivileged_port_start=0',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m,uid=1001,gid=1001', '--mount', f'type=volume,src={volume},dst=/evidence'],
            ['python', '-c', 'import time;time.sleep(86400)'])
        launch.call('start', anchor)
        namespace = launch.call('exec', anchor, 'readlink', '/proc/self/ns/net').strip()
        policy = helper('policy', 0, 'tests.runtime.netpolicy', admin=True)
        policy_call('prepare', ui_port=18081, proxy_port=18080)
        worker_log = (evidence / 'worker-stderr.log').open('wb')
        worker_process = subprocess.Popen(launch.cli + ['exec', '-i', '--user', '1001:1001', anchor, 'python', '-m', 'tests.runtime.s2a_worker'],
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=worker_log)
        ready = read_control(worker_process, 60)
        assert ready['type'] == 'ready' and ready['namespace'] == namespace
        launch.save('worker-ready.json', {k: v for k, v in ready.items() if k != 'pairing_code'})
        ca = evidence / 'fixture-ca.crt'
        ca.write_text(ready['ca_pem'], encoding='ascii')
        resolver = evidence / 'resolv.conf'
        resolver.write_text('nameserver 127.0.0.3\noptions timeout:1 attempts:1\n', encoding='ascii')
        mounts = [*overlay, '--mount', f'type=bind,src={ca},dst=/fixture-ca.crt,readonly',
                  '--mount', f'type=bind,src={resolver},dst=/etc/resolv.conf,readonly']
        policy_call('install', ui_port=ready['ui_port'], proxy_port=ready['proxy_port'])
        positive_n = helper('positive-probe', 1001, 'tests.runtime.netprobe')
        positive = probe(positive_n, 1001, 'preflight-positive')
        assert all(positive.values())
        launch.retire(positive_n)
        positive_counts = counts()
        assert all(positive_counts.get(k, 0) > 0 for k in FORBIDDEN)
        browser_probe = helper('browser-probe', 1000, 'tests.runtime.netprobe')
        before = counts()
        negative = probe(browser_probe, 1000, 'preflight-negative')
        assert negative.pop('proxy') is True
        assert not any(negative.values())
        after = counts()
        zero = no_canary_delta(before, after, 'preflight')
        ui_probe = helper('ui-probe', 1003, 'tests.runtime.netprobe')
        result = probe(ui_probe, 1003, 'preflight-ui')
        assert result.pop('ui') is True and not any(result.values())
        launch.retire(ui_probe)
        assert control({'type': 'stop_proxy'})['confirmed'] is True
        stopped = probe(browser_probe, 1000, 'preflight-proxy-stop', 'stopped')
        assert not any(stopped.values())
        assert control({'type': 'restart_proxy'})['type'] == 'proxy_ready'
        restarted = probe(browser_probe, 1000, 'preflight-proxy-restart')
        assert restarted.pop('proxy') is True and not any(restarted.values())
        launch.retire(browser_probe)
        rules = policy_call('snapshot')
        preflight = {'passed': True, 'netns': namespace, 'canary_positive': positive_counts, 'canary_zero': zero,
                     'rule_sha256': hashlib.sha256((rules['ipv4'] + rules['ipv6']).encode()).hexdigest()}
        launch.seal(preflight, namespace)
        launch.save('preflight.json', preflight)
        report['preflight'] = preflight
        probes = {}
        for label, uid in (('trusted', 1001), ('browser', 1000)):
            n = helper('s2a-probe-' + label, uid, 'tests.runtime.s2a_probe', mounts=mounts)
            out, _ = launch.bounded(n, b'{}\n')
            probes[label] = json.loads(out)
            launch.save('s2a-probe-' + label + '.json', probes[label])
            launch.retire(n)
            if label == 'trusted':
                docker_api_after_positive = counts().get('docker_api', 0)
        observations = launch.capture_profile_observations(anchor)
        image_conditions = {'image_digest': observations['image_digest']['value'], 'os': observations['os']['value'],
                            'architecture': observations['architecture']['value'], 'source': observations['image_digest']['source']}
        enabled = control({'type': 'enable_m5', 'image': image_conditions})
        assert enabled['type'] == 'enabled'
        launch.save('observer-enabled.json', enabled)
        # Actual Chromium bypass controls, as in M5.
        network_before = counts()
        rules_before = policy_call('snapshot')
        n = helper('chromium-negative', 1000, 'tests.runtime.browser_process', mounts=mounts)
        stderr = (evidence / 'network-browser-stderr.log').open('wb')
        p = subprocess.Popen(launch.cli + ['start', '-a', '-i', n], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr)
        report['chromium_started'] = True
        send_control(p, {'mode': 'network', 'proxy_port': ready['proxy_port']})
        assert read_control(p, 35)['type'] == 'need_proxy_stop'
        assert control({'type': 'stop_proxy'})['confirmed'] is True
        send_control(p, {'type': 'proxy_stopped'})
        result = read_control(p, 20)
        p.stdin.close()
        p.wait(timeout=10)
        stderr.close()
        assert p.returncode == 0
        no_canary_delta(network_before, counts(), 'chromium-negative')
        if not all(result['checks'].values()):
            raise IsolationLeak('Chromium bypass check failed')
        rules_after = policy_call('snapshot')
        old, new = drops(rules_before), drops(rules_after)
        assert len(new) == 4 and all(new[k] > old[k] for k in new)
        launch.save('chromium-network.json', {'result': result, 'protocol_drop_delta': {k: new[k] - old[k] for k in new}})
        launch.retire(n)
        control({'type': 'restart_proxy'})
        baseline_canaries = counts()

        # ---- S2-A: the production connect path against a synthetic network ------------------------------
        from src.isolation import site_policy
        PUB = {'fixture': '11.22.33.44', 'ok2': '11.22.33.45', 'badcert': '11.22.33.46', 'mismatch': '11.22.33.47',
               'rebind': '11.22.33.48', 'v6ok': '2a05:d018:1::1'}  # mirrors s2a_worker; none is ever connected to

        # (1) Raw CONNECT cases straight at the owned proxy (no Chromium): exact reason, resolutions and dials per case.
        assert control({'type': 'restart_proxy'})['type'] == 'proxy_ready'
        matrix = control({'type': 'proxy_matrix'}, 180)
        launch.save('proxy-matrix.json', matrix)
        no_canary_delta(baseline_canaries, counts(), 'proxy-matrix')
        expected = [
            # authority, status, host, decision, reason, resolutions, dialed IP, strict TLS result
            ('fixture.invalid:443', '200', 'fixture.invalid', 'ALLOW', 'ALLOW', 1, PUB['fixture'], 'OK'),
            ('FIXTURE.INVALID:443', '200', 'fixture.invalid', 'ALLOW', 'ALLOW', 1, PUB['fixture'], 'OK'),
            ('ok2.invalid:443', '200', 'ok2.invalid', 'ALLOW', 'ALLOW', 1, PUB['ok2'], 'OK'),
            ('v6ok.invalid:443', '200', 'v6ok.invalid', 'ALLOW', 'ALLOW', 1, PUB['v6ok'], 'OK'),
            ('badcert.invalid:443', '200', 'badcert.invalid', 'ALLOW', 'ALLOW', 1, PUB['badcert'], 'CERT_VERIFY_FAILED'),
            ('rebind.invalid:443', '200', 'rebind.invalid', 'ALLOW', 'ALLOW', 1, PUB['rebind'], 'OK'),
            ('rebind.invalid:443', '502', 'rebind.invalid', 'BLOCK', 'PRIVATE_ADDRESS', 1, None, None),
            ('unlisted.invalid:443', '502', 'unlisted.invalid', 'BLOCK', 'NOT_ALLOWLISTED', 0, None, None),
            ('host.docker.internal:443', '502', 'host.docker.internal', 'BLOCK', 'NOT_ALLOWLISTED', 0, None, None),
            ('fixture.invalid.:443', '502', None, 'BLOCK', 'INVALID_HOSTNAME', 0, None, None),
            ('169.254.169.254:443', '502', None, 'BLOCK', 'INVALID_HOSTNAME', 0, None, None),
            ('10.0.0.5:443', '502', None, 'BLOCK', 'INVALID_HOSTNAME', 0, None, None),
            ('[::1]:443', '502', None, 'BLOCK', 'INVALID_AUTHORITY', 0, None, None),
            ('fixture.invalid:8443', '502', None, 'BLOCK', 'PORT_NOT_ALLOWED', 0, None, None),
            ('fixture.invalid:80', '502', None, 'BLOCK', 'PORT_NOT_ALLOWED', 0, None, None),
            ('docker-api.invalid:2375', '502', None, 'BLOCK', 'PORT_NOT_ALLOWED', 0, None, None),
            ('private.invalid:443', '502', 'private.invalid', 'BLOCK', 'PRIVATE_ADDRESS', 1, None, None),
            ('loopback.invalid:443', '502', 'loopback.invalid', 'BLOCK', 'LOOPBACK_ADDRESS', 1, None, None),
            ('metadata.invalid:443', '502', 'metadata.invalid', 'BLOCK', 'LINK_LOCAL_ADDRESS', 1, None, None),
            ('v6loop.invalid:443', '502', 'v6loop.invalid', 'BLOCK', 'LOOPBACK_ADDRESS', 1, None, None),
            ('v6ula.invalid:443', '502', 'v6ula.invalid', 'BLOCK', 'PRIVATE_ADDRESS', 1, None, None),
            ('v4mapped.invalid:443', '502', 'v4mapped.invalid', 'BLOCK', 'IPV4_MAPPED_IPV6', 1, None, None),
            ('nat64.invalid:443', '502', 'nat64.invalid', 'BLOCK', 'IPV6_TRANSLATION_ADDRESS', 1, None, None),
            ('dockerhost.invalid:443', '502', 'dockerhost.invalid', 'BLOCK', 'PRIVATE_ADDRESS', 1, None, None),
            ('hostgw.invalid:443', '502', 'hostgw.invalid', 'BLOCK', 'PRIVATE_ADDRESS', 1, None, None),
            ('mixed.invalid:443', '502', 'mixed.invalid', 'BLOCK', 'PRIVATE_ADDRESS', 1, None, None),
            ('mixed2.invalid:443', '502', 'mixed2.invalid', 'BLOCK', 'PRIVATE_ADDRESS', 1, None, None),
            ('dnserr.invalid:443', '502', 'dnserr.invalid', 'FAILED', 'DNS_ERROR', 1, None, None),
            ('dnsincomplete.invalid:443', '502', 'dnsincomplete.invalid', 'FAILED', 'DNS_INCOMPLETE', 1, None, None),
            ('dnsempty.invalid:443', '502', 'dnsempty.invalid', 'FAILED', 'DNS_NO_ADDRESS', 1, None, None),
            ('mismatch.invalid:443', None, 'mismatch.invalid', 'FAILED', 'PEER_MISMATCH', 1, PUB['mismatch'], None)]  # status None: any non-200
        mismatches = []
        results, follow_up = matrix['results'][:-1], matrix['results'][-1]
        if len(results) != len(expected):
            mismatches.append('case count')
        for got, (authority, status, host, decision, reason, resolutions, dial_ip, tls) in zip(results, expected):
            seen = [(r[0], r[2], r[3]) for r in got['records']]
            problems = []
            if got['authority'] != authority or (status is None and got['status'].startswith('HTTP/1.1 200')) or (
                    status is not None and not got['status'].startswith('HTTP/1.1 ' + status)):
                problems.append('status')
            if seen != [(host, decision, reason)]:
                problems.append('record')
            if got['resolutions'] != resolutions:
                problems.append('resolutions')
            if [tuple(d) for d in got['dialed']] != ([(dial_ip, 443)] if dial_ip else []):
                problems.append('dialed')
            if got.get('tls') != tls:
                problems.append('tls')
            if not got['complete']:
                problems.append('incomplete')
            if problems:
                mismatches.append({'authority': authority, 'problems': problems, 'got': got})
        launch.save('proxy-matrix-mismatches.json', mismatches)

        # (2) Real Chromium: the S1-C three-state sequence, then the hostile pages.
        initial, rows = run_case('01-initial')
        cases['01-initial']['candidates'] = [r['candidate_id'] for r in rows]
        approved = control({'type': 'approve', 'candidates': [r['candidate_id'] for r in rows]}, 60)
        assert approved['type'] == 'approved'
        launch.save('approval-records.json', approved)
        cases['02-approval'] = approved
        def settled(label, **kwargs):
            """A browser-side proxy probe (1 s connect timeout) occasionally fails before Chromium starts. Every
            attempt stays in the evidence; the first attempt in which both jobs completed is the one judged."""
            names = []
            for attempt in range(1, 4):
                name = f'{label}-a{attempt}'
                names.append(name)
                run_case(name, **kwargs)
                if all(j['execution'] == 'COMPLETED' for j in cases[name]['jobs']):
                    break
            cases[label] = {**cases[names[-1]], 'attempts': names}
            launch.save('case-' + label + '.json', cases[label])
        settled('03-same-after-approval')
        settled('04-changed', variant='changed')
        settled('05-restored')
        settled('06-allowed-second-hosts', variant='ok2')
        settled('07-denial-matrix', variant='matrix')
        settled('08-redirects', variant='redirect')
        settled('09-page-bypass-attempts', variant='bypass')
        settled('10-bad-certificate-over-allowed-tunnel', variant='badcert')
        settled('10a-missing-resource-404', variant='notfound')
        settled('10b-pending-request-at-capture-end', variant='pending')
        settled('10c-browser-audit-withheld', mode='no_browser_audit')
        settled('11-audit-withheld', mode='no_ledger')

        settled('12-audit-incomplete-injected', mode='incomplete')
        settled('13-clean-control')
        attempt_cases = {k: cases.pop(k) for k in [k for k in cases if re.fullmatch(r'.*-a\d', k)]}
        launch.save('attempt-cases.json', {k: {'reasons': [c['reason'] for c in v['captures']], 'executions': [j['execution'] for j in v['jobs']]}
                                           for k, v in attempt_cases.items()})
        state = control({'type': 'state'}, 60)
        launch.save('final-state.json', state)
        latencies = sorted(d['ms'] for path in evidence.glob('capture-*.stderr.log') for line in path.read_text('utf-8', errors='replace').splitlines()
                           for d in [json.loads(line) if line.startswith('{') else {}] if d.get('stage') == 'probe')
        report['probe_latency_ms'] = ({'count': len(latencies), 'median': latencies[len(latencies) // 2], 'p95': latencies[int(len(latencies) * .95)],
                                       'max': latencies[-1], 'over_1000': sum(x > 1000 for x in latencies)} if latencies else None)

        def verdicts(label):
            return [r['verdict'] for r in cases[label]['jobs']]

        def reasons(label):
            return [set(r['verdict_reasons'] or []) for r in cases[label]['jobs']]

        def entries(label):
            return [{(e['host'], e['decision'], e['reason']) for e in (r['audit_entries'] or [])} for r in cases[label]['jobs']]

        def has(label, *wanted):
            return all(set(wanted) <= e for e in entries(label))

        def browser_clean(label):
            return all(r['browser']['source'] == 'BROWSER_SELF_REPORT' and r['browser']['complete'] is True
                       and r['browser']['failed'] == 0 and r['browser']['http_errors'] == 0 and (r['browser']['requests'] or 0) >= 1
                       for r in cases[label]['jobs'])

        def connect_clean(label):  # The proxy saw only allowed connections: any UNKNOWN here came from elsewhere.
            return all(r['audit']['blocked'] == 0 and r['audit']['failed'] == 0 and (r['audit']['allowed'] or 0) >= 1
                       for r in cases[label]['jobs'])

        def tcp_drops(label):
            return cases[label]['os_drop_delta'].get('SP_BROWSER_TCP_DROP', 0)

        def clean(label):
            return all(r['audit']['source'] == 'TRUSTED_CONNECT_PROXY' and r['audit']['complete'] is True
                       and (r['audit']['allowed'] or 0) >= 1 and r['audit']['blocked'] == 0 and r['audit']['failed'] == 0
                       for r in cases[label]['jobs'])
        preflight_negative = json.loads((evidence / 'preflight-negative.json').read_text('utf-8'))['results']
        preflight_positive = json.loads((evidence / 'preflight-positive.json').read_text('utf-8'))['results']
        chromium_network = json.loads((evidence / 'chromium-network.json').read_text('utf-8'))
        matrix_entries = {('unlisted.invalid', 'BLOCK', 'NOT_ALLOWLISTED'), ('host.docker.internal', 'BLOCK', 'NOT_ALLOWLISTED'),
                          ('private.invalid', 'BLOCK', 'PRIVATE_ADDRESS'), ('loopback.invalid', 'BLOCK', 'LOOPBACK_ADDRESS'),
                          ('metadata.invalid', 'BLOCK', 'LINK_LOCAL_ADDRESS'), ('v6loop.invalid', 'BLOCK', 'LOOPBACK_ADDRESS'),
                          ('v6ula.invalid', 'BLOCK', 'PRIVATE_ADDRESS'), ('v4mapped.invalid', 'BLOCK', 'IPV4_MAPPED_IPV6'),
                          ('nat64.invalid', 'BLOCK', 'IPV6_TRANSLATION_ADDRESS'), ('dockerhost.invalid', 'BLOCK', 'PRIVATE_ADDRESS'),
                          ('hostgw.invalid', 'BLOCK', 'PRIVATE_ADDRESS'), ('mixed.invalid', 'BLOCK', 'PRIVATE_ADDRESS'),
                          ('dnserr.invalid', 'FAILED', 'DNS_ERROR')}
        # Literals / odd ports / plain HTTP: either the proxy refused them (ledger) or the OS dropped and counted them.
        # Chromium chooses; both are containment, and neither may reach a canary (checked per case).
        literal_forms = {(None, 'BLOCK', 'INVALID_HOSTNAME'), (None, 'BLOCK', 'INVALID_AUTHORITY'),
                         (None, 'BLOCK', 'PORT_NOT_ALLOWED'), (None, 'FAILED', 'MALFORMED_CONNECT')}
        docker_api_final = counts().get('docker_api', 0)
        t, b = probes['trusted'], probes['browser']
        checks.update({
            'real_site_access_disabled_by_default': site_policy.REAL_SITE_ACCESS_ENABLED is False,
            'peer_mismatch_stops_the_session_fail_closed': (not follow_up['status'].startswith('HTTP/1.1 200')
                                                            and follow_up.get('tls') is None
                                                            and not any(r[2] == 'ALLOW' for r in follow_up['records'])),
            'proxy_matrix_every_case_exact': not mismatches and len(results) == len(expected),
            'proxy_matrix_strict_tls_enforced': (next(r for r in results if r['authority'] == 'badcert.invalid:443').get('tls') == 'CERT_VERIFY_FAILED'
                                                 and all(r.get('tls') == 'OK' for r in results if r['authority'] in
                                                         ('fixture.invalid:443', 'ok2.invalid:443', 'v6ok.invalid:443'))),
            'one_resolution_per_connect_and_pinned_dial': all(
                r['resolutions'] <= 1 and len(r['dialed']) <= 1 for r in results),
            'direct_paths_denied_for_browser_identity': (not any(v for k, v in preflight_negative.items() if k != 'proxy')
                                                         and preflight_negative.get('proxy') is True),
            'direct_path_positive_controls_hold': all(preflight_positive.values()),
            'chromium_direct_bypass_attempts_denied': all(chromium_network['result']['checks'].values())
                                                       and all(v > 0 for v in chromium_network['protocol_drop_delta'].values()),
            'docker_api_model_denied_for_browser': (t['modelled']['docker_api_model_127.0.0.5:2375'] is True
                                                    and b['modelled']['docker_api_model_127.0.0.5:2375'] is False
                                                    and docker_api_final == docker_api_after_positive > 0),
            'docker_sockets_and_gateways_unreachable_for_browser': (not any(b['unmodelled'].values())
                                                                    and set(b['unix_sockets'].values()) == {'ABSENT'}
                                                                    and b['mounts_with_docker'] == []),
            'browser_identity_unprivileged': any(x.split() == ['CapBnd:', '0000000000000000'] for x in b['status']),
            'canary_zero_in_every_case': all(all(v == 0 for v in json.loads((evidence / f).read_text('utf-8')).values())
                                             for f in sorted(p.name for p in evidence.glob('*-canaries.json'))),
            'every_case_has_desktop_and_mobile': all(len(c['jobs']) == 2 and {j['kind'] for j in c['jobs']} == {'Desktop', 'Mobile'}
                                                    for k, c in cases.items() if k[:2].isdigit() and 'jobs' in c),
            'all_captures_cleanup_confirmed': all(x['cleanup'] and x['reason'] == 'CAPTURE_COMPLETE'
                                                  for c in cases.values() if 'captures' in c for x in c['captures']),
            'baseline_approved_v1': all(a['after']['approval_state'] == 'APPROVED' and a['after']['version'] == 1
                                        for a in approved['approvals']),
            's1c_same_is_no_visual_change': verdicts('03-same-after-approval') == [NO_CHANGE, NO_CHANGE]
                                            and all(r['changed_pixels'] == 0 for r in cases['03-same-after-approval']['jobs']),
            's1c_changed_is_visual_changed': verdicts('04-changed') == [CHANGED, CHANGED]
                                             and all((r['changed_pixels'] or 0) > 0 and r['diff_sha256'] for r in cases['04-changed']['jobs']),
            's1c_restored_is_no_visual_change': verdicts('05-restored') == [NO_CHANGE, NO_CHANGE]
                                                and all(r['changed_pixels'] == 0 for r in cases['05-restored']['jobs']),
            'allowed_second_hosts_succeed_in_chromium': verdicts('06-allowed-second-hosts') == [NO_CHANGE, NO_CHANGE]
                and has('06-allowed-second-hosts', ('ok2.invalid', 'ALLOW', 'ALLOW'), ('v6ok.invalid', 'ALLOW', 'ALLOW'))
                and clean('06-allowed-second-hosts')
                and cases['06-allowed-second-hosts']['https_served'] >= cases['03-same-after-approval']['https_served'] + 6,
            'denial_matrix_page_is_unknown_with_every_reason': verdicts('07-denial-matrix') == [UNKNOWN, UNKNOWN]
                and has('07-denial-matrix', *matrix_entries) and all({'RESOURCE_BLOCKED', 'RESOURCE_FAILED'} <= s for s in reasons('07-denial-matrix')),
            'literal_port_and_plain_http_forms_contained': all(
                (e & literal_forms) or tcp_drops('07-denial-matrix') > 0 for e in entries('07-denial-matrix')),
            'redirects_are_revalidated': verdicts('08-redirects') == [UNKNOWN, UNKNOWN]
                and has('08-redirects', ('unlisted.invalid', 'BLOCK', 'NOT_ALLOWLISTED'), ('private.invalid', 'BLOCK', 'PRIVATE_ADDRESS'),
                        ('fixture.invalid', 'ALLOW', 'ALLOW')),
            'page_bypass_attempts_are_audited_or_dropped': verdicts('09-page-bypass-attempts') == [UNKNOWN, UNKNOWN]
                and has('09-page-bypass-attempts', ('unlisted.invalid', 'BLOCK', 'NOT_ALLOWLISTED'))
                and all(len([x for x in e if x[1] in ('BLOCK', 'FAILED')]) > 1 or tcp_drops('09-page-bypass-attempts') > 0
                        for e in entries('09-page-bypass-attempts')),
            'bad_certificate_resource_is_not_served_by_tls_validation': (
                cases['10-bad-certificate-over-allowed-tunnel']['https_served'] <= cases['03-same-after-approval']['https_served']),
            # --- S2-A-FIX: TLS and resource-load failures inside an ALLOWed tunnel -----------------------------
            'tls_failure_in_allowed_tunnel_is_now_unknown': (
                verdicts('10-bad-certificate-over-allowed-tunnel') == [UNKNOWN, UNKNOWN]
                and all('TLS_VALIDATION_FAILED' in s for s in reasons('10-bad-certificate-over-allowed-tunnel'))
                and connect_clean('10-bad-certificate-over-allowed-tunnel')),
            'tls_failure_report_names_host_type_and_error_only': all(
                any(f['host'] == 'badcert.invalid' and f['resource_type'] == 'stylesheet' and f['class'] == 'TLS_VALIDATION_FAILED'
                    and f['error'].startswith('ERR_CERT_') and set(f) == {'resource_type', 'scheme', 'host', 'port', 'error', 'navigation', 'count', 'class'}
                    for f in (r['browser']['failures'] or []))
                for r in cases['10-bad-certificate-over-allowed-tunnel']['jobs'])
                and 'a.css' not in json.dumps([r['browser'] for r in cases['10-bad-certificate-over-allowed-tunnel']['jobs']]),
            'missing_resource_is_unknown_with_clean_connect_audit': (
                verdicts('10a-missing-resource-404') == [UNKNOWN, UNKNOWN]
                and all('RESOURCE_LOAD_FAILED' in s for s in reasons('10a-missing-resource-404'))
                and connect_clean('10a-missing-resource-404')
                and all((r['browser']['http_errors'] or 0) >= 1 for r in cases['10a-missing-resource-404']['jobs'])),
            'request_pending_at_capture_end_is_incomplete': (
                verdicts('10b-pending-request-at-capture-end') == [UNKNOWN, UNKNOWN]
                and all('BROWSER_AUDIT_INCOMPLETE' in s for s in reasons('10b-pending-request-at-capture-end'))
                and connect_clean('10b-pending-request-at-capture-end')
                and all(r['execution'] == 'COMPLETED' and (r['browser']['pending'] or 0) >= 1
                        for r in cases['10b-pending-request-at-capture-end']['jobs'])),
            'browser_audit_withheld_is_unknown_and_not_confounded': (
                verdicts('10c-browser-audit-withheld') == [UNKNOWN, UNKNOWN]
                and all('BROWSER_AUDIT_UNAVAILABLE' in s for s in reasons('10c-browser-audit-withheld'))
                and connect_clean('10c-browser-audit-withheld')
                and all(r['execution'] == 'COMPLETED' for r in cases['10c-browser-audit-withheld']['jobs'])),
            'clean_runs_have_a_complete_clean_browser_audit': all(
                browser_clean(k) for k in ('03-same-after-approval', '04-changed', '05-restored', '06-allowed-second-hosts', '13-clean-control')),
            'connect_failures_still_unknown_with_browser_audit_on': all(
                verdicts(k) == [UNKNOWN, UNKNOWN] for k in ('07-denial-matrix', '08-redirects', '09-page-bypass-attempts')),
            'audit_withheld_is_unknown': verdicts('11-audit-withheld') == [UNKNOWN, UNKNOWN]
                and all('NETWORK_AUDIT_UNAVAILABLE' in s for s in reasons('11-audit-withheld')),
            'audit_incomplete_is_unknown_not_confounded': verdicts('12-audit-incomplete-injected') == [UNKNOWN, UNKNOWN]
                and all('NETWORK_AUDIT_INCOMPLETE' in s for s in reasons('12-audit-incomplete-injected'))
                and all(r['execution'] == 'COMPLETED' for r in cases['12-audit-incomplete-injected']['jobs']),
            'clean_control_after_all_hostile_cases': verdicts('13-clean-control') == [NO_CHANGE, NO_CHANGE] and clean('13-clean-control'),
            'no_cross_job_leak_after_hostile_cases': all(
                not any(x[1] in ('BLOCK', 'FAILED') for x in e) for e in entries('13-clean-control')),
            'clean_runs_have_complete_clean_audit': all(clean(k) for k in ('03-same-after-approval', '04-changed', '05-restored')),
            'strict_quality_never_pass_or_changed': all(r['quality'] in ('UNKNOWN', 'FAIL')
                                                        for c in cases.values() if 'jobs' in c for r in c['jobs']),
            'profile_unattested_retained': all(r['profile_trust'] == 'UNATTESTED' and 'PROFILE_UNATTESTED' in (r['strict_reasons'] or [])
                                               for c in cases.values() if 'jobs' in c for r in c['jobs']
                                               if r['verdict'] in (NO_CHANGE, CHANGED)),
            'same_context_fingerprint_all_cases': len({r['context_fingerprint'] for k, c in cases.items() if 'jobs' in c
                                                       for r in c['jobs'] if r['kind'] == 'Desktop'}) == 1,
        })
        # Reported, not part of the PASS: what a CONNECT proxy alone cannot see, and what now reports it.
        report['known_gaps'] = {
            'tls_failure_inside_allowed_tunnel': {
                'status': 'DETECTED_BY_BROWSER_AUDIT' if verdicts('10-bad-certificate-over-allowed-tunnel') == [UNKNOWN, UNKNOWN] else 'OPEN',
                'case': '10-bad-certificate-over-allowed-tunnel', 'verdicts': verdicts('10-bad-certificate-over-allowed-tunnel'),
                'detected_by_audit': verdicts('10-bad-certificate-over-allowed-tunnel') == [UNKNOWN, UNKNOWN],
                'https_served': cases['10-bad-certificate-over-allowed-tunnel']['https_served'],
                'baseline_https_served': cases['03-same-after-approval']['https_served']}}
        stall = control({'type': 'stall_report'}, 30)['report']
        launch.save('stall-monitor.json', stall)
        report['stall_monitor'] = {k: stall[k] for k in ('samples', 'max_accept_queue', 'max_drift_ms')} | {'anomalies': len(stall['anomalies'])}
        closed = control({'type': 'quit'})
        assert closed == {'type': 'closed', 'proxy': True, 'ui': True, 'key_revoked': True, 'fixtures': True}, closed
        worker_process.stdin.close()
        worker_process.wait(timeout=15)
        assert worker_process.returncode == 0
        worker_process = None
        report['worker_closed'] = closed
        report['checks'] = checks
        report['cases'] = {k: [r.get('verdict') for r in c.get('jobs', [])] for k, c in cases.items() if 'jobs' in c}
        report['attempts'] = {k: c['attempts'] for k, c in cases.items() if 'attempts' in c}
        report['passed'] = all(checks.values())
        report['quality'] = 'UNKNOWN'
        report['scope'] = 'S2A_OFFLINE_VALIDATED'
        report['real_site_access'] = False
        report['external_network_enabled'] = False
    except ExperimentDone:
        report.update(passed=True, scope='LAUNCH_SWITCH_EXPERIMENT', quality='UNKNOWN')
    except Exception as exc:
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)[:400] if isinstance(exc, (AssertionError, IsolationLeak)) else 'Inspect bounded fixture logs'
        report['isolation_leak'] = isinstance(exc, IsolationLeak)
        report['checks'] = checks
        raise
    finally:
        if worker_process is not None:
            try:
                send_control(worker_process, {'type': 'quit'})
                read_control(worker_process, 8)
            except Exception:
                pass
        export_ok = False
        try:
            export_ok = export_evidence()
        except Exception:
            report['export_error'] = 'EVIDENCE_EXPORT_UNCONFIRMED'
            report['passed'] = False
        report['all_owned_stopped'] = launch.stop_all()
        if worker_process is not None:
            try:
                worker_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                worker_process.terminate()
                worker_process.wait(timeout=5)
            for pipe in (worker_process.stdin, worker_process.stdout):
                try:
                    if pipe is not None and not pipe.closed:
                        pipe.close()
                except OSError:
                    pass
        if worker_log is not None and not worker_log.closed:
            worker_log.close()
        report['all_owned_removed'] = launch.cleanup() if export_ok else False
        if not report['all_owned_removed']:
            report['passed'] = False
        # Only the labelled network this run created, after an ownership recheck. Volumes stay (launcher policy).
        report['own_network_removed'] = False
        try:
            own = prefix + '-network'
            info = json.loads(launch.call('network', 'inspect', own))[0]
            if (launch.resources.get(own, {}).get('id') == info['Id'] and info['Internal'] is True
                    and (info.get('Labels') or {}).get('siteproof.task') == 'M2-RUNTIME-VALIDATION-01'
                    and not info.get('Containers')):
                launch.call('network', 'rm', info['Id'])
                report['own_network_removed'] = True
        except Exception:
            pass
        after = other_containers()
        report['other_containers_unchanged'] = after == original_containers
        launch.save('other-containers-after.json', after)
        later = {'networks': sorted(launch.call('network', 'ls', '--format', '{{.ID}}|{{.Name}}').splitlines()),
                 'volumes': sorted(launch.call('volume', 'ls', '--format', '{{.Name}}').splitlines()),
                 'images': sorted(launch.call('images', '--no-trunc', '--format', '{{.Repository}}:{{.Tag}}|{{.ID}}').splitlines())}
        launch.save('docker-inventory-after.json', later)
        owned = set(launch.resources)
        report['existing_docker_resources_unchanged'] = (
            set(original_networks) <= set(later['networks']) and set(original_volumes) <= set(later['volumes'])
            and later['images'] == original_images
            and {x.split('|')[1] for x in set(later['networks']) - set(original_networks)} <= owned
            and set(later['volumes']) - set(original_volumes) <= owned)
        if not (report['other_containers_unchanged'] and report['existing_docker_resources_unchanged']):
            report['passed'] = False
        launch.save('validation-result.json', report)
        # Sealed LAST: nothing below writes into the evidence directory. Verified by re-reading.
        manifest = {p.relative_to(evidence).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in sorted(evidence.rglob('*')) if p.is_file() and p.name != 'export-sha256.json'}
        (evidence / 'export-sha256.json').write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding='utf8')
        report['sha256_manifest'] = {'files': len(manifest), 'mismatches': sum(
            hashlib.sha256((evidence / k).read_bytes()).hexdigest() != v for k, v in manifest.items())}
        print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
