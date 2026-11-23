"""S1-C / S1-C-FIX: offline fixture E2E of the operational image verdict with real Chromium in the
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
    prefix = 'siteproof-m2-s1c-' + time.strftime('%H%M%S') + '-' + uuid.uuid4().hex[:6]
    report = {'task': 'SITEPROOF-S1C-OFFLINE-E2E-01', 'passed': False, 'chromium_started': False,
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
                         'audit_entries': audit.get('entries'), 'audit_timeline': audit.get('timeline'), 'candidate_id': 'capture-' + job['job_id']})
        return rows

    def run_case(label, *, variant='original', mode='normal', extra=None):
        nonlocal capture_container
        assert control({'type': 'restart_proxy'})['type'] == 'proxy_ready'
        os_before = drops(policy_call('snapshot'))
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
                      'resources': msg['resources'], 'netlog': True, **(extra or {})}
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
        rows = summarize(result)
        total = result['ledger_total']
        # Per-job windows = (job part + prelude); together they must account for every record the proxy saw.
        sums = {k: sum((r['audit'].get(k) or 0) + ((r['audit'].get('prelude') or {}).get(k) or 0) for r in rows)
                for k in ('allowed', 'blocked', 'failed')}
        cases[label] = {'variant': variant, 'mode': mode, 'captures': captures, 'jobs': rows, 'ledger_total': total,
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
        worker_process = subprocess.Popen(launch.cli + ['exec', '-i', '--user', '1001:1001', anchor, 'python', '-m', 'tests.runtime.s1c_worker'],
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

        if args.experiment:
            for item in json.loads(args.experiment):
                run_case(item['label'], extra={'extra_args': item.get('extra_args', []), 'netlog': True, **item.get('config', {})})
            launch.save('experiment-cases.json', cases)
            raise ExperimentDone()

        # ---- S1-C cases: every capture below is a real Chromium run -----------------------
        initial, rows = run_case('01-initial')
        cases['01-initial']['candidates'] = [r['candidate_id'] for r in rows]
        approved = control({'type': 'approve', 'candidates': [r['candidate_id'] for r in rows]}, 60)
        assert approved['type'] == 'approved'
        launch.save('approval-records.json', approved)
        cases['02-approval'] = approved
        run_case('03-same-after-approval')
        run_case('04-changed', variant='changed')
        run_case('05-restored')
        run_case('06-blocked-and-failed-subresources', variant='blocked')
        run_case('07-clean-after-blocked')
        run_case('08-audit-withheld', mode='no_ledger')

        def settled(label, **kwargs):
            """A browser-side proxy probe (1 s connect timeout) occasionally fails before Chromium starts, which
            would confound the case being tested. Every attempt stays in the evidence; the first attempt in which
            both jobs ran to completion is the one the case is judged on."""
            names = []
            for attempt in range(1, 4):
                name = f'{label}-a{attempt}'
                names.append(name)
                run_case(name, **kwargs)
                if all(j['execution'] == 'COMPLETED' for j in cases[name]['jobs']):
                    break
            cases[label] = {**cases[names[-1]], 'attempts': names}
            launch.save('case-' + label + '.json', cases[label])
        settled('09-audit-incomplete-injected', mode='incomplete')
        settled('10-repeat-clean-control')
        attempt_cases = {k: cases.pop(k) for k in [k for k in cases if re.fullmatch(r'.*-a\d', k)]}
        launch.save('attempt-cases.json', {k: {'reasons': [c['reason'] for c in v['captures']], 'executions': [j['execution'] for j in v['jobs']]}
                                           for k, v in attempt_cases.items()})
        state = control({'type': 'state'}, 60)
        launch.save('final-state.json', state)

        def stages(file):
            out = []
            for line in (evidence / (file + '.stderr.log')).read_text('utf-8', errors='replace').splitlines():
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if 'stage' in item and 't' in item:
                    out.append(item)
            return out
        guards, effective = [], []
        for path in sorted(evidence.glob('capture-*.stderr.log')):
            for line in path.read_text('utf-8', errors='replace').splitlines():
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if item.get('stage') == 'features_guard':
                    guards.append(item)
                if item.get('stage') == 'effective_features':
                    effective.append(item)
        analysis = {}
        for label, case in cases.items():
            if 'captures' not in case:
                continue
            files = {c['job_id']: c['file'] for c in case['captures']}
            for job in case['jobs']:
                marks = stages(files[job['job_id']])
                t0 = job['audit'].get('t0_monotonic')
                phases = {}
                for seq, rel, host, port, decision, reason in (job['audit_timeline'] or []):
                    absolute = (t0 or 0) + rel
                    phase = next((m['stage'] for m in reversed(marks) if m['t'] <= absolute + 0.0005), 'before_first_marker')
                    key = f'{host}:{port} {decision} {reason}'
                    phases.setdefault(phase, {}).setdefault(key, 0)
                    phases[phase][key] += 1
                analysis[f"{label}/{job['kind']}"] = {
                    'markers': [(m['stage'], round(m['t'] - (t0 or 0), 3), {k: v for k, v in m.items() if k not in ('t', 'stage')})
                                for m in marks],
                    'records_by_phase': phases, 'prelude': job['audit'].get('prelude'), 'anchor': job['audit'].get('anchor')}
        launch.save('phase-analysis.json', analysis)

        def verdicts(label):
            return [r['verdict'] for r in cases[label]['jobs']]

        def reasons(label):
            return [set(r['verdict_reasons'] or []) for r in cases[label]['jobs']]

        def all_audit_clean(label):
            return all(r['audit']['source'] == 'TRUSTED_CONNECT_PROXY' and r['audit']['complete'] is True
                       and (r['audit']['allowed'] or 0) >= 1 and r['audit']['blocked'] == 0 and r['audit']['failed'] == 0
                       for r in cases[label]['jobs'])
        two = lambda label: len(cases[label]['jobs']) == 2
        checks.update({
            'every_case_has_desktop_and_mobile': all(len(c['jobs']) == 2 and {j['kind'] for j in c['jobs']} == {'Desktop', 'Mobile'}
                                                    for k, c in cases.items() if k[:2].isdigit() and 'jobs' in c),
            'all_captures_cleanup_confirmed': all(x['cleanup'] and x['reason'] == 'CAPTURE_COMPLETE'
                                                  for c in cases.values() if 'captures' in c for x in c['captures']),
            'initial_pending_no_verdict': verdicts('01-initial') == [UNKNOWN, UNKNOWN],
            'baseline_approved_v1': all(a['after']['approval_state'] == 'APPROVED' and a['after']['version'] == 1
                                        for a in approved['approvals']),
            'same_is_no_visual_change': verdicts('03-same-after-approval') == [NO_CHANGE, NO_CHANGE]
                                        and all(r['changed_pixels'] == 0 for r in cases['03-same-after-approval']['jobs']),
            'changed_is_visual_changed': verdicts('04-changed') == [CHANGED, CHANGED]
                                         and all((r['changed_pixels'] or 0) > 0 and r['diff_sha256'] for r in cases['04-changed']['jobs']),
            'restored_is_no_visual_change': verdicts('05-restored') == [NO_CHANGE, NO_CHANGE]
                                            and all(r['changed_pixels'] == 0 for r in cases['05-restored']['jobs']),
            'clean_runs_have_complete_clean_audit': all(all_audit_clean(k) for k in ('03-same-after-approval', '04-changed', '05-restored', '07-clean-after-blocked', '10-repeat-clean-control')),
            'blocked_run_is_unknown_with_block_and_failure': verdicts('06-blocked-and-failed-subresources') == [UNKNOWN, UNKNOWN]
                and all({'RESOURCE_BLOCKED', 'RESOURCE_FAILED'} <= s for s in reasons('06-blocked-and-failed-subresources')),
            'blocked_hosts_recorded_host_port_reason_only': all(
                any(e['decision'] == 'BLOCK' and e['host'] == 'blocked.invalid' for e in (r['audit_entries'] or []))
                and any(e['decision'] == 'FAILED' and e['host'] == 'down.invalid' for e in (r['audit_entries'] or []))
                for r in cases['06-blocked-and-failed-subresources']['jobs']),
            'clean_after_blocked_has_no_leak': verdicts('07-clean-after-blocked') == [NO_CHANGE, NO_CHANGE],
            'audit_withheld_is_unknown': verdicts('08-audit-withheld') == [UNKNOWN, UNKNOWN]
                and all('NETWORK_AUDIT_UNAVAILABLE' in s for s in reasons('08-audit-withheld')),
            'audit_incomplete_is_unknown': verdicts('09-audit-incomplete-injected') == [UNKNOWN, UNKNOWN]
                and all('NETWORK_AUDIT_INCOMPLETE' in s for s in reasons('09-audit-incomplete-injected')),
            'features_cover_playwright_defaults': bool(guards) and all(g['missing'] == [] for g in guards),
            'effective_browser_command_line': bool(effective) and all(
                e['features'] is not None and 'PreconnectToSearch' in e['features'] and 'OptimizationHints' in e['features']
                and e['proxy_server'] == 'http://127.0.0.1:1' for e in effective),
            'incomplete_case_not_confounded_by_timeout': all(
                r['execution'] == 'COMPLETED' and 'EXECUTION_NOT_COMPLETED' not in (r['verdict_reasons'] or [])
                for r in cases['09-audit-incomplete-injected']['jobs']),
            'repeat_clean_control_is_no_visual_change': verdicts('10-repeat-clean-control') == [NO_CHANGE, NO_CHANGE],
            'no_connection_allowed_before_the_document': all(
                (r['audit'].get('prelude') or {}).get('allowed') == 0 and (r['audit'].get('anchor') or {}).get('seen') is True
                for k, c in cases.items() if k[:2] in ('03', '04', '05', '06', '07', '10') for r in c['jobs']),
            'prelude_is_retained_with_timeline': all(
                len(r['audit_timeline'] or []) == sum((r['audit'].get(k) or 0) for k in ('allowed', 'blocked', 'failed', 'idle'))
                + sum(((r['audit'].get('prelude') or {}).get(k) or 0) for k in ('allowed', 'blocked', 'failed', 'idle'))
                for k, c in cases.items() if k[:2] in ('03', '04', '05', '07', '10') for r in c['jobs']),
            'per_job_audits_sum_to_proxy_total': all(c['sum_matches_total'] for k, c in cases.items()
                                                     if k[:2].isdigit() and 'sum_matches_total' in c and k[:2] not in ('08', '09')),
            'strict_quality_never_pass_or_changed': all(r['quality'] in ('UNKNOWN', 'FAIL')
                                                        for c in cases.values() if 'jobs' in c for r in c['jobs']),
            'profile_unattested_retained': all(r['profile_trust'] == 'UNATTESTED' and 'PROFILE_UNATTESTED' in (r['strict_reasons'] or [])
                                               for c in cases.values() if 'jobs' in c for r in c['jobs']
                                               if r['verdict'] in (NO_CHANGE, CHANGED)),
            'same_context_fingerprint_all_cases': len({r['context_fingerprint'] for k, c in cases.items() if 'jobs' in c
                                                       for r in c['jobs'] if r['kind'] == 'Desktop'}) == 1,
        })
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
        report['scope'] = 'OFFLINE_FIXTURE_REAL_CHROMIUM'
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
