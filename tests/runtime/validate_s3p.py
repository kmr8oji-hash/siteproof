"""S3-1-PREFLIGHT: OFFLINE verification before the real-site capture is resumed. No real site, no external route, ever.

PART 1  T-A behavioural probes in throwaway containers (--network none): read-only rootfs, storage protection, enforced limits.
PART 2  an isolated --internal network (11.22.33.0/24, no gateway/NAT) with a TLS fixture peer standing in for the TTN page:
        T-A D  UDP/443 (QUIC) dropped by the OS, judged by a canary and by the peer's own log
        T-A E  Chromium stop: cooperative timeout and host-forced kill on an unresponsive page; no process, grant or resource left
        HSTS   regression of the negative browser tests + the static guard + the "no CONNECT ALLOW" tripwire
        T-B    the S3-1 capture pipeline (Desktop, then Mobile, one window each): RuntimeService.run -> evidence -> Baseline
               CANDIDATE (PENDING). No approval API is ever called; REAL_SITE_ACCESS_ENABLED is never set in any process.
Windows use the hardened per-IP grants, the Broker (fixture mode) and the independent reaper, exactly as the real run will.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import struct
import subprocess
import threading
import time
import uuid

from src.runtime.docker_launcher import TASK, read_control, send_control
from tests.runtime.browser_bundle import mount_args, stage_browser_bundle
from tests.runtime.bundle_probe import run_bundle_probe
from tests.runtime.preflight_checks import head_is_as_expected
from src.runtime.request_audit import audit_problems
from tests.runtime.validate_s2b import counters, delta, git, rule_set, tree_digest
from tests.runtime.validate_s3 import png_size
from tests.runtime.validate_s2h import FixtureLauncher

M5_IMAGE = 'sha256:9c88112b42070369876fdb24476af283b3908a3fdc630b66fedacf4f20c4d2c8'
FORBIDDEN = ('tcp', 'dns', 'udp', 'metadata', 'lan', 'host_model', 'ipv6')
CONNECTED = ('ERR_CERT', 'ERR_SSL', 'ERR_BAD_SSL', 'ERR_HTTP', 'ERR_EMPTY_RESPONSE', 'ERR_RESPONSE')
HOST, PEER_IP, GATEWAY, ANCHOR_IP = 'ttn-fixture.invalid', '11.22.33.44', '11.22.33.1', '11.22.33.10'
WINDOW_CAP, TTL = 120, 100
DESKTOP = {'viewport_width': 1440, 'viewport_height': 900, 'device_scale_factor': 1, 'color_scheme': 'light', 'locale': 'ja-JP', 'timezone': 'Asia/Tokyo',
           'user_agent': 'SiteProof synthetic fixture Desktop', 'reduced_motion': True, 'full_page': False}
RO_OK_PREFIXES = ('/etc/hosts', '/etc/hostname', '/etc/resolv.conf')  # Docker-managed, per-container files


class IsolationLeak(RuntimeError):
    pass


def peer_events(launch, name):
    events = []
    for line in launch.call('logs', name).splitlines():
        if line.startswith('{'):
            try:
                events.append(json.loads(line))
            except ValueError:
                pass
    return events


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--image', default=M5_IMAGE)
    parser.add_argument('--part1-only', action='store_true')
    parser.add_argument('--top-page', action='store_true', help='S3-1T rehearsal: T-B captures the fixture top page `/` with the plan (full-page) profiles')
    parser.add_argument('--peer-top', choices=('fixture', 'ttn', 'unstable'), default='fixture',
                        help='What the peer serves at `/` in --top-page mode: the static fixture, the TTN local build, or a never-settling page')
    parser.add_argument('--stability-override', type=json.loads, help='OFFLINE rehearsal only: a stability policy instead of the plan policy')
    parser.add_argument('--ttn-dist', type=Path, help='TTN local static build (dist-static), mounted read-only into the peer for --peer-top ttn')
    args = parser.parse_args()
    evidence = Path(args.evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    root = Path.cwd()
    launch = FixtureLauncher(evidence, args.image, root / 'runtime/docker/seccomp-siteproof.json')
    prefix = 'siteproof-m2-s3p-' + time.strftime('%H%M%S') + '-' + uuid.uuid4().hex[:6]
    report = {'task': 'SITEPROOF-S3-1T-PREFLIGHT-01' if args.top_page else 'SITEPROOF-S3-1-PREFLIGHT-01', 'passed': False, 'real_site_access': False, 'external_network_enabled': False, 'aws_touched': False,
              'baseline_approved': False, 'windows': {}, 'ta': {}, 'tb': {}}
    checks, counter = {}, [0]
    p = {'worker': None, 'broker': None, 'reaper': None}
    state = {'window': None, 'started': None}

    def name(label):
        counter[0] += 1
        return f'{prefix}-{label}-{counter[0]}'

    def inventory():
        return {'containers': sorted(launch.call('ps', '-a', '--no-trunc', '--format', '{{.ID}}|{{.Names}}|{{.State}}').splitlines()),
                'networks': sorted(launch.call('network', 'ls', '--format', '{{.ID}}|{{.Name}}').splitlines()),
                'volumes': sorted(launch.call('volume', 'ls', '--format', '{{.Name}}').splitlines()),
                'images': sorted(launch.call('images', '--no-trunc', '--format', '{{.Repository}}:{{.Tag}}|{{.ID}}').splitlines())}

    before = inventory()
    launch.save('docker-inventory-before.json', before)
    overlay = []
    for rel in ('src', 'tests/runtime'):
        overlay += ['--mount', f'type=bind,src={(root / rel).resolve()},dst=/opt/siteproof/{rel},readonly']
    # Browser-identity containers get ONLY this bundle over /opt/siteproof; trusted-identity containers keep the overlay above.
    bundle_tree, bundle_manifest = stage_browser_bundle(root, evidence / 'browser-bundle')
    bundle_mount = mount_args(bundle_tree)
    resolver_file = evidence / 'resolv.conf'
    resolver_file.write_text('nameserver 127.0.0.3\noptions timeout:1 attempts:1\n', encoding='ascii')

    def solo_options(uid, *, memory='256m', pids=64, nofile=256, tmpfs='16m', mounts=()):
        return ['--network', 'none', '--user', f'{uid}:{uid}', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true', '--security-opt', 'seccomp=' + launch.seccomp,
                '--read-only', '--pids-limit', str(pids), '--memory', memory, '--memory-swap', memory, '--cpus', '1', '--ulimit', f'nofile={nofile}:{nofile}',
                '--tmpfs', f'/tmp:rw,nosuid,nodev,size={tmpfs},uid={uid},gid={uid}', '--shm-size', '16m', '--env', 'HOME=/tmp/browser-home', *mounts]

    def solo(label, uid, mode, *, extra=None, **options):
        options.setdefault('mounts', overlay)
        container = launch.create(name(label), solo_options(uid, **options), ['python', '-m', 'tests.runtime.s3p_probe'])
        result, error = None, None
        try:
            out, _ = launch.bounded(container, json.dumps({'mode': mode, **(extra or {})}).encode() + b'\n', seconds=90)
            result = json.loads(out)
        except Exception as exc:
            error = type(exc).__name__
        info = launch.inspect(container)['State']
        record = {'result': result, 'error': error, 'exit_code': info['ExitCode'], 'oom_killed': info['OOMKilled']}
        launch.save(label + '.json', record)
        return record

    # ---- Part 2 helpers (defined here, used after the network exists) -------------------------------------------------------
    def wcontrol(command, seconds=90):
        send_control(p['worker'], command)
        return read_control(p['worker'], seconds)

    def bcontrol(command, seconds=30):
        send_control(p['broker'], command)
        return read_control(p['broker'], seconds)

    def helper(label, uid, module, *, admin=False, mounts=()):
        opts = launch.options(anchor, uid, mounts=mounts)
        if admin:
            opts += ['--cap-add', 'NET_ADMIN']
        return launch.create(name(label), opts, ['python', '-m', module])

    def policy_call(kind, **kwargs):
        out, _ = launch.bounded(policy, json.dumps({'type': kind, 'netns': namespace, **kwargs}).encode() + b'\n')
        result = json.loads(out)
        launch.save('policy-' + str(counter[0]).zfill(3) + '-' + kind + '.json', result)
        counter[0] += 1
        return result

    def snap():
        return policy_call('snapshot')

    def probe(container, uid, label, config):
        out, _ = launch.bounded(container, json.dumps(config).encode() + b'\n')
        result = json.loads(out)
        launch.save(label + '.json', result)
        assert result['netns'] == namespace and result['uid'] == uid
        return result['results']

    def browser_run(config, label, container, seconds=120):
        out, _ = launch.bounded(container, json.dumps(config).encode() + b'\n', seconds=seconds, evidence_sink=lambda o, e, x: (
            (evidence / (label + '.stderr.log')).write_bytes(launch._redact_log(e)), launch.save(label + '-execution.json', x)))
        result = json.loads(out)
        launch.save(label + '.json', result)
        return result

    def net_config(**extra):
        return {'mode': 'network', 'gateway': GATEWAY, 'proxy_port': 18080, 'host': HOST, 'url': 'https://' + HOST + '/', 'resources': ready['resources'],
                'direct_seconds': 1.0, 'proxied_seconds': 2, **extra}

    def capture_config(url, kind='Desktop', attributes=None):
        return {'request': {'page_id': 'ttn-about', 'profile': {'profile_id': kind, 'attributes': attributes or DESKTOP}, 'url': url, 'baseline_id': None},
                'proxy_port': 18080, 'host': HOST, 'resources': ready['resources'], 'fixture_ca': True}

    def reached(results, *keys):
        return [k for k in (keys or results) if results[k]['reached']]

    def untouched(result, proxied=False):
        return all(v['reached'] is False and (proxied or not (v['error'] or '').startswith(CONNECTED)) for v in result.values())

    def start_broker(ttl):
        p['broker'] = subprocess.Popen(launch.cli + ['start', '-a', '-i', broker], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=broker_log)
        send_control(p['broker'], {'mode': 'fixture', 'hosts': [HOST], 'answers': {HOST: [[PEER_IP]]}, 'special': {}, 'device': device, 'ttl': ttl, 'max_grants': 1})
        assert read_control(p['broker'], 30)['type'] == 'ready'

    def stop_broker():
        if p['broker'] is None:
            return None
        try:
            send_control(p['broker'], {'type': 'quit'})
            final = read_control(p['broker'], 20)
        except Exception:
            final = None
        try:
            p['broker'].wait(timeout=15)
        except subprocess.TimeoutExpired:
            p['broker'].kill()
        p['broker'] = None
        return final

    def start_reaper(deadline):
        p['reaper'] = subprocess.Popen(launch.cli + ['start', '-a', '-i', reaper], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=reaper_log)
        send_control(p['reaper'], {'netns': namespace, 'device': device, 'deadline': deadline})
        assert read_control(p['reaper'], 30)['type'] == 'ready'

    def cancel_reaper():
        send_control(p['reaper'], {'type': 'cancel'})
        message = read_control(p['reaper'], 15)
        p['reaper'].wait(timeout=15)
        p['reaper'] = None
        return message

    def open_window(label, reaper_deadline=110):
        start_reaper(reaper_deadline)
        state.update(window=label, started=time.monotonic())
        policy_call('egress_open', device=device)
        report['windows'][label] = {'opened_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
        assert bcontrol({'type': 'enable'})['type'] == 'enabled'
        assert bcontrol({'type': 'lease_open', 'lease': 'job', 'hosts': [HOST]})['ok'] is True

    def close_window(label):
        closed = bcontrol({'type': 'close'})
        flushed = policy_call('egress_close', device=device)
        reaper_msg = cancel_reaper()
        seconds = round(time.monotonic() - state['started'], 1)
        report['windows'][label].update(closed_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), closed_by='HOST', duration_seconds=seconds)
        state['window'] = None
        clean = (closed['clean'] is True and closed['grant_rules'] == [] and rule_set(flushed) == baseline_rules and reaper_msg['type'] == 'cancelled' and seconds <= WINDOW_CAP)
        return clean, closed, flushed

    def canary_zero(baseline, label):
        now = wcontrol({'type': 'counts'})['counts']
        d = {k: now.get(k, 0) - baseline.get(k, 0) for k in FORBIDDEN}
        launch.save(label + '-canaries.json', d)
        if any(d.values()):
            raise IsolationLeak('forbidden canary received: ' + label)

    anchor = policy = chromium = capture_c = trusted = browser = broker = reaper = peer = None
    broker_log = reaper_log = None
    try:
        head = git('rev-parse', 'HEAD').strip()
        sp_text = (root / 'src/isolation/site_policy.py').read_text('utf-8')
        launch.save('start-gate.json', {'branch': git('branch', '--show-current').strip(), 'head': head, 'uncommitted_entries': len(git('status', '--short', '-uall').splitlines()),
                                        'flag_in_source': re.search(r'^REAL_SITE_ACCESS_ENABLED = (\w+)', sp_text, re.M)[1],
                                        'overlay': {'src': tree_digest(root / 'src'), 'tests/runtime': tree_digest(root / 'tests/runtime')}})
        checks['flag_false_in_source_at_start'] = re.search(r'^REAL_SITE_ACCESS_ENABLED = False$', sp_text, re.M) is not None
        image = json.loads(launch.call('image', 'inspect', launch.image))[0]
        launch.image = image['Id']
        launch.save('run-conditions.json', {'docker_server': launch.call('version', '--format', '{{.Server.Version}}').strip(), 'host': platform.platform(), 'image_id': image['Id'],
                                            'git_head': head, 'run_prefix': prefix, 'no_pull_build': True, 'network': 'none (part 1) / --internal fixture bridge (part 2)'})

        # ================================================================== PART 1: T-A (throwaway containers, no network)
        # A. read-only rootfs. uid 0 (no capabilities, no DAC override) can write wherever file permissions allow, so only a read-only
        # filesystem can make it fail with EROFS; the Browser/Worker identities are checked as well.
        ro0, ro1000 = solo('ta-a-readonly-uid0', 0, 'readonly', mounts=overlay), solo('ta-a-readonly-uid1000', 1000, 'readonly', mounts=overlay)
        r0 = (ro0['result'] or {}).get('result', {})
        checks['TA_A_every_protected_path_refuses_writes_with_EROFS_even_for_uid0'] = bool(r0) and all(v == {'written': False, 'errno': 'EROFS'} for v in r0['protected'].values())
        checks['TA_A_root_filesystem_is_mounted_read_only'] = 'ro' in (r0.get('root_mount_options', '').split(',')) and 'ro' in ((ro1000['result'] or {}).get('result', {}).get('root_mount_options', '').split(','))
        checks['TA_A_only_the_tmpfs_areas_are_writable'] = bool(r0) and all(v == {'written': True} for v in r0['allowed'].values())
        r1000 = (ro1000['result'] or {}).get('result', {})
        checks['TA_A_browser_identity_cannot_write_any_protected_path'] = bool(r1000) and not any(v['written'] for v in r1000['protected'].values())
        # B. storage protection against a managed target that exists only where this container is not
        token = 'CANARY-' + uuid.uuid4().hex + '.txt'
        canary_volume = launch.create_volume(prefix + '-canary')
        writer = launch.create(name('ta-b-writer'), solo_options(0, mounts=['--mount', f'type=volume,src={canary_volume},dst=/evidence']),
                               ['python', '-c', f"open('/evidence/{token}','w').write('managed-test-target');print('written')"])
        out, _ = launch.bounded(writer)
        checks['TA_B_managed_target_was_created_in_a_volume_only_the_writer_mounts'] = b'written' in out
        sb = solo('ta-b-storage-browser', 1000, 'storage', extra={'canary': token}, mounts=overlay)
        sw = solo('ta-b-storage-worker', 1001, 'storage', extra={'canary': token}, mounts=overlay)
        for who, rec in (('browser', sb), ('worker', sw)):
            res = (rec['result'] or {}).get('result', {})
            rw = [m for m in res.get('mounts', []) if m['options'].split(',')[0] == 'rw' and m['fstype'] not in ('tmpfs', 'proc', 'sysfs', 'devpts', 'mqueue', 'cgroup', 'cgroup2')
                  and m['dest'] not in RO_OK_PREFIXES]
            checks[f'TA_B_{who}_cannot_see_or_reach_the_managed_target_by_any_path'] = bool(res) and res['canary_found_at'] == [] and not any(res['direct_paths_exist'].values())
            checks[f'TA_B_{who}_has_no_docker_socket_no_docker_env_and_no_writable_host_style_mount'] = bool(res) and res['docker_env'] == [] and rw == []
            report['ta'][f'storage_{who}_mount_destinations'] = sorted({m['dest'] for m in res.get('mounts', []) if m['dest'] not in ('/proc', '/sys', '/dev') and not m['dest'].startswith(('/proc/', '/sys/', '/dev/'))})
        # C. enforced limits (test-only low caps; each probe loop has a small hard bound)
        pid_r = solo('ta-c-pids', 1000, 'pids', pids=16)
        nof_r = solo('ta-c-nofile', 1000, 'nofile', nofile=32)
        mem_r = solo('ta-c-memory', 1000, 'memory', memory='64m')
        tmp_r = solo('ta-c-tmpfs', 1000, 'tmpfs', tmpfs='16m')
        pr = (pid_r['result'] or {}).get('result', {})
        checks['TA_C_pids_limit_is_enforced_by_the_kernel'] = bool(pr) and pr['failed_with'] == 'EAGAIN' and pr['forked'] < pr['attempt_cap'] and pr['forked'] <= 16 and (pid_r['result'] or {})['cgroup']['pids.max'] == '16'
        nr = (nof_r['result'] or {}).get('result', {})
        checks['TA_C_nofile_limit_is_enforced'] = bool(nr) and nr['failed_with'] == 'EMFILE' and nr['opened'] <= 32 and nr['soft'] == 32
        checks['TA_C_memory_limit_is_enforced_by_oom_kill'] = mem_r['result'] is None and mem_r['oom_killed'] is True and mem_r['exit_code'] == 137
        tr = (tmp_r['result'] or {}).get('result', {})
        checks['TA_C_tmpfs_disk_limit_is_enforced'] = bool(tr) and tr['failed_with'] == 'ENOSPC' and tr['written_mib'] <= 16
        report['ta']['limits'] = {'pids': pr, 'nofile': nr, 'memory': {k: mem_r[k] for k in ('exit_code', 'oom_killed', 'error')}, 'tmpfs': tr,
                                  'cpu_disk_note': 'CPU quota (cpu.max) read back only; image/root disk is read-only (A); only tmpfs size was enforced-tested'}
        report['ta']['cgroup_readback'] = {k: (pid_r['result'] or {}).get('cgroup') for k in ('limits',)}
        # UNBLOCK: what a real-site Browser container can see of the project, measured from inside one
        bundle_checks, bundle_record = run_bundle_probe(launch, name('ub-bundle'), bundle_tree, bundle_manifest, resolver_file, launch.save)
        for key, value in bundle_checks.items():
            checks['UB_' + key] = value
        checks['UB_bundle_is_minimal_and_staged_from_the_import_closure'] = 0 < bundle_manifest['file_count'] < 45
        report['ub'] = {'bundle_files': bundle_manifest['file_count'], 'previous_mounts': {'src_py': len(list((root / 'src').rglob('*.py'))), 'tests_runtime_py': len(list((root / 'tests/runtime').rglob('*.py')))},
                        'image_baked_dirs_hidden': bundle_record['result']['siteproof_entries']}
        if args.part1_only:
            raise SystemExit('PART1_ONLY')

        # ================================================================== PART 2: isolated network + TLS fixture peer
        network = launch.create_network(prefix + '-network')
        net_info = json.loads(launch.call('network', 'inspect', network))[0]
        checks['network_is_internal_fixture_only'] = net_info['Internal'] is True and [c['Subnet'] for c in net_info['IPAM']['Config']] == ['11.22.33.0/24']
        peer = launch.create(name('peer'), [*overlay, '--network', network, '--ip', PEER_IP, '--user', '1005:1005', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true',
                                            '--read-only', '--pids-limit', '64', '--memory', '256m', '--memory-swap', '256m', '--cpus', '1',
                                            '--sysctl', 'net.ipv4.ip_unprivileged_port_start=0', '--tmpfs', '/tmp:rw,nosuid,nodev,size=16m,uid=1005,gid=1005',
                                            '--env', 'PEER_HOST=' + HOST, '--env', 'PEER_TOP=' + args.peer_top,
                                            *(['--mount', f'type=bind,src={args.ttn_dist.resolve()},dst=/ttn,readonly'] if args.peer_top == 'ttn' else [])],
                             ['python', '-m', 'tests.runtime.s3p_peer'])
        launch.call('start', peer)
        pem = None
        for _ in range(40):
            pem = next((e['pem'] for e in peer_events(launch, peer) if e.get('event') == 'cert'), None)
            if pem:
                break
            time.sleep(.5)
        assert pem, 'peer certificate not published'
        ca = evidence / 'fixture-ca.crt'
        ca.write_text(pem, encoding='ascii')
        volume = launch.create_volume(prefix + '-evidence')
        init = launch.create(name('volume-init'), ['--network', 'none', '--user', '0:0', '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--security-opt', 'no-new-privileges=true',
                                                   '--read-only', '--mount', f'type=volume,src={volume},dst=/evidence'],
                             ['python', '-c', "import os;os.chmod('/evidence',0o700);os.chown('/evidence',1001,1001)"])
        launch.bounded(init)
        launch.retire(init)
        ca_mount = ['--mount', f'type=bind,src={ca},dst=/fixture-ca.crt,readonly']
        anchor = launch.create(name('worker'), [*overlay, *ca_mount, '--network', network, '--ip', ANCHOR_IP, '--user', '1001:1001', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges=true', '--read-only', '--pids-limit', '128', '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
            '--sysctl', 'net.ipv6.conf.all.disable_ipv6=0', '--sysctl', 'net.ipv4.ip_unprivileged_port_start=0',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m,uid=1001,gid=1001', '--mount', f'type=volume,src={volume},dst=/evidence'], ['python', '-c', 'import time;time.sleep(86400)'])
        launch.call('start', anchor)
        namespace = launch.call('exec', anchor, 'readlink', '/proc/self/ns/net').strip()
        policy = helper('policy', 0, 'tests.runtime.netpolicy_hardened', admin=True, mounts=overlay)
        prepared = policy_call('prepare')
        device = prepared['devices'][0]
        checks['namespace_has_no_default_route'] = not any(r.get('dst') == 'default' for r in prepared['routes'])
        policy_call('install', proxy_ports=[18080])
        mounts = [*bundle_mount, *ca_mount, '--mount', f'type=bind,src={resolver_file},dst=/etc/resolv.conf,readonly']  # Browser identities: bundle only
        s0 = snap()
        baseline_rules = rule_set(s0)
        privileged = launch.options(anchor, 0, mounts=overlay) + ['--cap-add', 'NET_ADMIN']
        broker = launch.create(name('broker'), privileged, ['python', '-m', 'tests.runtime.egress_broker'])
        reaper = launch.create(name('reaper'), privileged, ['python', '-m', 'tests.runtime.egress_reaper'])
        broker_log, reaper_log = (evidence / 'broker-stderr.log').open('wb'), (evidence / 'reaper-stderr.log').open('wb')
        trusted = helper('probe-trusted', 1001, 'tests.runtime.s2h_probe', mounts=overlay)
        browser = helper('probe-browser', 1000, 'tests.runtime.s2h_probe', mounts=mounts)
        chromium = helper('chromium', 1000, 'tests.runtime.s2b_browser', mounts=mounts)
        capture_c = helper('capture', 1000, 'tests.runtime.s3_browser', mounts=mounts)
        worker_log = (evidence / 'worker-stderr.log').open('wb')
        p['worker'] = subprocess.Popen(launch.cli + ['exec', '-i', '--user', '1001:1001', '--env', 'SSL_CERT_FILE=/fixture-ca.crt', anchor, 'python', '-m', 'tests.runtime.s3p_worker'],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=worker_log)
        ready = read_control(p['worker'], 60)
        assert ready['type'] == 'ready' and ready['namespace'] == namespace and ready['path'] == '/about' and ready['target_url'] == 'https://' + HOST + '/about'
        checks['TB_target_path_is_about_not_about_html'] = ready['path'] == '/about' and 'about.html' not in ready['target_url']
        checks['real_site_flag_is_false_in_the_worker_process'] = ready['flag_at_start'] is False

        # ---- T-A D + HSTS regression, in one window with a live DNS-only grant -----------------------------------------------
        start_broker(TTL)
        wcontrol({'type': 'start_fixture'})
        open_window('TA-D')
        g = probe(trusted, 1001, 'D-grant', {'mode': 'resolve', 'lease': 'job', 'host': HOST})
        checks['TA_D_grant_for_the_fixture_peer_is_live'] = g['status'] == 'COMPLETE' and len(snap()['grant_rules']) == 1
        peer0 = peer_events(launch, peer)
        canary0 = wcontrol({'type': 'counts'})['counts']
        quic_t = [['quic_canary', '127.0.0.3', 443], ['quic_peer_granted_ip', PEER_IP, 443], ['quic_documentation', '192.0.2.1', 443]]
        sD0 = snap()
        d_trusted = probe(trusted, 1001, 'D-trusted-udp', {'mode': 'udp', 'targets': quic_t})
        canary1 = wcontrol({'type': 'counts'})['counts']
        d_browser = probe(browser, 1000, 'D-browser-udp', {'mode': 'udp', 'targets': quic_t})
        canary2 = wcontrol({'type': 'counts'})['counts']
        sD1 = snap()
        peer1 = peer_events(launch, peer)
        checks['TA_D_trusted_uid_reaches_only_the_controlled_loopback_quic_canary'] = reached(d_trusted) == ['quic_canary'] and canary1.get('quic', 0) > canary0.get('quic', 0)
        checks['TA_D_browser_uid_udp_443_is_dropped_by_the_os_not_by_chromium_flags'] = (not reached(d_browser) and canary2.get('quic', 0) == canary1.get('quic', 0)
                                                                                         and delta(counters(sD1), counters(sD0)).get('SP_BROWSER_UDP_DROP', 0) >= 2)  # canary + peer reach the OUTPUT hook; the documentation address has no route
        checks['TA_D_the_peer_received_no_udp_443_datagram_from_anyone'] = sum(e.get('event') == 'udp' for e in peer1) == sum(e.get('event') == 'udp' for e in peer0) == 0
        # HSTS regression: default negatives, with the grant live and the peer reachable
        req0 = sum(e.get('event') == 'request' for e in peer_events(launch, peer))
        netD = browser_run(net_config(real_ip=PEER_IP), 'D-chromium-network', chromium)
        req1 = sum(e.get('event') == 'request' for e in peer_events(launch, peer))
        ledger = wcontrol({'type': 'ledger_window'})['window']
        checks['HSTS_negative_tests_refused_and_use_an_unregistered_invalid_host_for_plain_http'] = (
            untouched(netD['direct']) and untouched(netD['proxied_refused'], proxied=True) and 'plain_http_unregistered' in netD['proxied_refused']
            and 'plain_http_registered_host' not in netD['proxied_refused'])
        checks['HSTS_gate_tripwire_no_connect_allow_and_no_peer_request_during_the_negative_tests'] = ledger['allowed'] == 0 and req1 == req0
        try:  # The static guard: a negative test naming the registered host is refused before the browser sends anything.
            browser_run(net_config(real_ip=PEER_IP, extra_proxied={'plain_http_registered_host': 'http://' + HOST + '/'}), 'D-guard-refusal', chromium)
            guard_refused = False
        except Exception:
            guard_refused = True
        stderr_text = (evidence / 'D-guard-refusal.stderr.log').read_text('utf-8', errors='replace') if (evidence / 'D-guard-refusal.stderr.log').exists() else ''
        ledger2 = wcontrol({'type': 'ledger_window'})['window']
        req2 = sum(e.get('event') == 'request' for e in peer_events(launch, peer))
        checks['HSTS_static_guard_refuses_a_registered_host_negative_before_any_traffic'] = guard_refused and 'NegativeTestRefused' in stderr_text and ledger2['allowed'] == 0 and req2 == req1
        canary_zero(canary2, 'D')
        clean, closed, flushed = close_window('TA-D')
        checks['TA_D_window_closed_clean_baseline_restored'] = clean
        stop_broker()
        wcontrol({'type': 'stop_real'})

        # ---- T-A E: Chromium stop on an unresponsive page --------------------------------------------------------------------
        start_broker(TTL)
        wcontrol({'type': 'start_fixture'})
        open_window('TA-E')
        hang_cfg = capture_config('https://' + HOST + '/hang')
        e1_error = None
        try:
            out, _ = launch.bounded(capture_c, json.dumps(hang_cfg).encode() + b'\n', seconds=60)
            e1 = json.loads(out.split(b'\n', 1)[0])
        except Exception as exc:
            e1, e1_error = None, type(exc).__name__
        info = launch.inspect(capture_c)['State']
        top_after = subprocess.run(launch.cli + ['top', capture_c], capture_output=True, text=True)
        launch.save('E1-cooperative-timeout.json', {'meta': {k: e1[k] for k in ('reason', 'cleanup')} if e1 else None, 'error': e1_error, 'state': {k: info[k] for k in ('Running', 'Pid', 'ExitCode')},
                                                    'docker_top_rc': top_after.returncode})
        checks['TA_E1_cooperative_timeout_reports_HTTP_TIMEOUT_with_confirmed_cleanup_and_no_process'] = (
            bool(e1) and e1['reason'] == 'HTTP_TIMEOUT' and e1['cleanup'] is True and info['Running'] is False and info['Pid'] == 0 and top_after.returncode != 0)
        # forced kill: the browser's own stage timeout is lifted to 60 s, so only the launcher's stop (host deadline 8 s) can end the run
        forced_cfg = {**hang_cfg, 'resources': {**ready['resources'], 'stage_seconds': 60}}
        # E1's hung tunnel idled past the 30 s session limit, which (by design) ends that proxy session. Every real capture gets its own
        # proxy, so E2 gets a fresh one too.
        launch.save('E1-proxy-before-restart.json', wcontrol({'type': 'ledger_window'})['window'])
        wcontrol({'type': 'stop_real'})
        wcontrol({'type': 'start_fixture'})
        ledger_before = wcontrol({'type': 'ledger_window'})['window']
        outcome = {}

        def forced():
            try:
                launch.bounded(capture_c, json.dumps(forced_cfg).encode() + b'\n', seconds=8, evidence_sink=lambda o, e, x: (
                    (evidence / 'E2.stdout.bin').write_bytes(o), (evidence / 'E2.stderr.log').write_bytes(launch._redact_log(e)), launch.save('E2-execution.json', x)))
                outcome['error'] = None
            except Exception as exc:
                outcome['error'] = exc
        thread = threading.Thread(target=forced)
        thread.start()
        seen = 0
        for _ in range(40):
            top = subprocess.run(launch.cli + ['top', capture_c], capture_output=True, text=True)
            if top.returncode == 0:
                seen = max(seen, len(top.stdout.strip().splitlines()) - 1)
            if not thread.is_alive():
                break
            time.sleep(.3)
        thread.join(30)
        exc = outcome.get('error')
        info = launch.inspect(capture_c)['State']
        top_after = subprocess.run(launch.cli + ['top', capture_c], capture_output=True, text=True)
        running = launch.call('ps', '--filter', 'label=' + 'siteproof.task=' + TASK, '--filter', 'status=running', '--format', '{{.Names}}').split()
        launch.save('E2-forced-stop.json', {'max_processes_seen_while_running': seen, 'exception': type(exc).__name__ if exc else None, 'reason': getattr(exc, 'reason', None),
                                            'cleanup_confirmed': getattr(exc, 'cleanup_confirmed', None), 'ledger_entries_before': ledger_before['entries'], 'state': {k: info[k] for k in ('Running', 'Pid', 'ExitCode')},
                                            'docker_top_rc_after': top_after.returncode, 'still_running_owned_containers': running})
        checks['TA_E2_forced_stop_ends_a_hung_chromium_whole_container_with_confirmed_cleanup'] = (
            seen >= 3 and exc is not None and getattr(exc, 'reason', None) == 'TIMEOUT' and getattr(exc, 'cleanup_confirmed', None) is True
            and info['Running'] is False and info['Pid'] == 0 and top_after.returncode != 0 and not any(capture_c in r for r in running))
        reqs = [e for e in peer_events(launch, peer) if e.get('event') == 'request' and e.get('path') == '/hang']
        checks['TA_E_the_hang_page_was_actually_requested_through_the_audited_proxy'] = len(reqs) >= 1
        ledgerE = wcontrol({'type': 'ledger_window'})['window']
        launch.save('E-ledger.json', ledgerE)
        checks['TA_E_connect_audit_complete_and_allows_only_the_fixture_host'] = ledgerE['allowed'] >= 1 and all(e['host'] == HOST for e in ledgerE['entries'] if e['decision'] == 'ALLOW')
        clean, closed, flushed = close_window('TA-E')
        checks['TA_E_no_grant_or_rule_left_after_the_stop_tests'] = clean and not flushed['grant_rules']
        stop_broker()
        wcontrol({'type': 'stop_real'})

        # ================================================================== T-B: capture pipeline rehearsal
        if args.top_page:  # S3-1T: the same pipeline on `/` with the checked capture plan (ttn-home, Desktop/Mobile full page).
            top = wcontrol({'type': 'top_page', 'stability': args.stability_override})
            launch.save('top-page-plan.json', top)
            checks['TB_top_page_plan_applied_path_page_id_and_full_page_profiles'] = (
                top['path'] == '/' and top['page_id'] == 'ttn-home' and top['target_url'] == 'https://' + HOST + '/'
                and [(x['kind'], x['width'], x['height'], x['full_page']) for x in top['profiles']] == [('Desktop', 1440, 900, True), ('Mobile', 390, 844, True)])
        created = wcontrol({'type': 'create'})
        launch.save('workspace-created.json', created)
        tb_path = '/' if args.top_page else '/about'
        checks['TB_workspace_url_is_the_exact_fixture_target_url'] = created['url'] == 'https://' + HOST + tb_path
        results = {}
        for kind in ('Desktop', 'Mobile'):
            prep = wcontrol({'type': 'prepare', 'kind': kind})
            launch.save(f'{kind}-prepared.json', prep)
            start_broker(TTL)
            label = 'TB-' + kind
            open_window(label)
            wcontrol({'type': 'start_fixture'})
            s_open = snap()
            canary_k = wcontrol({'type': 'counts'})['counts']
            hd = wcontrol({'type': 'head_path'}, 90)['result']
            launch.save(f'{kind}-head.json', hd)
            checks[f'TB_{kind}_head_rule_accepts_the_target_200_without_redirect'] = head_is_as_expected(hd)
            if args.top_page:
                attrs = prep['profile']['attributes']
                checks[f'TB_{kind}_prepared_profile_is_the_planned_full_page_profile'] = (attrs['full_page'] is True and (attrs['viewport_width'], attrs['viewport_height'])
                                                                                          == ((1440, 900) if kind == 'Desktop' else (390, 844)))
            if kind == 'Desktop':
                hd_old = wcontrol({'type': 'head_path', 'path': '/about.html'}, 90)['result']
                launch.save('Desktop-head-about-html.json', hd_old)
                checks['TB_head_rule_would_STOP_on_the_307_of_about_html'] = (str(hd_old.get('http_status', '')).startswith('HTTP/1.1 307') and not head_is_as_expected(hd_old))
            send_control(p['worker'], {'type': 'run', 'batch': prep['batch']})
            metas = []
            while True:
                msg = read_control(p['worker'], 150)
                if msg['type'] == 'result':
                    break
                assert msg['type'] == 'capture'
                cfg = {'request': msg['request'], 'proxy_port': 18080, 'host': HOST, 'resources': msg['resources'], 'fixture_ca': True}
                path = evidence / f'capture-{kind}'
                out, _ = launch.bounded(capture_c, json.dumps(cfg).encode() + b'\n', seconds=min(80, msg['remaining']), limit=68 * 1024 * 1024, evidence_sink=lambda o, e, x, path=path: (
                    path.with_suffix('.stdout.bin').write_bytes(o), path.with_suffix('.stderr.log').write_bytes(launch._redact_log(e)), launch.save(path.name + '-execution.json', x)))
                first, payload = out.split(b'\n', 1)
                meta = json.loads(first)
                assert len(payload) == meta['length'] + meta['repeat_length']
                to_worker = dict(meta['browser_report'])
                audit = to_worker.pop('request_audit', None)
                audit_raw = json.dumps(audit, separators=(',', ':')).encode() if audit is not None else b''
                send_control(p['worker'], {'type': 'capture_result', 'length': meta['length'], 'repeat_length': meta['repeat_length'], 'audit_length': len(audit_raw),
                                           'reason': meta['reason'], 'cleanup': meta['cleanup'] is True, 'browser_report': to_worker}, payload + audit_raw)
                metas.append({'job_id': msg['job_id'], 'reason': meta['reason'], 'cleanup': meta['cleanup'] is True, 'sandbox': meta.get('sandbox'),
                              'runtime': meta['browser_report'].get('runtime'), 'request_audit': audit})
            launch.save(f'{kind}-run-result.json', msg)
            launch.save(f'{kind}-capture-meta.json', metas)
            stateK = bcontrol({'type': 'state'})
            launch.save(f'{kind}-broker-state.json', stateK)
            granted = {e['ip'] for e in stateK['state']['events'] if e['event'] == 'GRANTED'}
            canary_zero(canary_k, kind)
            job = next(j for j in msg['state']['jobs'] if j['job_id'] == prep['job_id'])
            audit_ev = next((e['network_audit'] for e in job['events'] if 'network_audit' in e), None)
            browser_audit = next((e['browser_audit'] for e in job['events'] if 'browser_audit' in e and isinstance(e['browser_audit'], dict)), None)
            results[kind] = {'job': job, 'network_audit': audit_ev, 'browser_audit': browser_audit, 'baselines': msg['baselines'], 'capture_info': msg['capture_info'].get(prep['job_id']), 'meta': metas,
                             'comparison': next((r for r in msg['comparison']['results'] if r.get('job_id') == prep['job_id']), None)}
            clean, closed, flushed = close_window(label)
            stopped = wcontrol({'type': 'stop_real'})
            stop_broker()
            k = kind[0]
            checks[f'TB_{k}_job_completed_with_evidence_and_all_checks'] = job['execution'] == 'COMPLETED' and bool(job['evidence']) and job['missing_checks'] == []
            checks[f'TB_{k}_capture_profile_and_fingerprint_stored'] = bool(job['profile']['attributes']) and job['fingerprint'] == prep['fingerprint'] and job['profile']['profile_id'] == kind
            checks[f'TB_{k}_connect_audit_complete_and_allows_only_the_fixture_host'] = bool(audit_ev) and audit_ev.get('complete') is True and audit_ev.get('allowed', 0) >= 1 and all(
                e['host'] == HOST for e in audit_ev.get('entries', []) if e['decision'] == 'ALLOW')
            checks[f'TB_{k}_browser_request_audit_stored'] = bool(browser_audit) and browser_audit.get('source') == 'BROWSER_SELF_REPORT'
            checks[f'TB_{k}_only_the_fixture_ip_was_granted'] = granted == {PEER_IP}
            checks[f'TB_{k}_window_closed_clean_and_flag_still_false'] = clean and stopped['flag_after_stop'] is False
            checks[f'TB_{k}_quality_stays_unknown'] = job['quality'] == 'UNKNOWN'
            checks[f'TB_{k}_candidate_pending_never_approved'] = (any(b['candidate_id'] == 'capture-' + prep['job_id'] and b['approval_state'] == 'PENDING' for b in msg['baselines'])
                                                                 and not any(b['approval_state'] == 'APPROVED' for b in msg['baselines']))
        wcontrol({'type': 'quit'})
        p['worker'].stdin.close()
        p['worker'].wait(timeout=20)
        p['worker'] = None
        launch.call('cp', anchor + ':/evidence/ws', str(evidence / 'workspace'), timeout=120)
        review = evidence / 'review'
        review.mkdir()
        for kind, v in results.items():
            ev = v['job']['evidence']
            data = (evidence / 'workspace' / ev['artifact_ref']).read_bytes() if ev else b''
            size = png_size(data)
            expected = (1440, 900) if kind == 'Desktop' else (390, 844)
            if args.top_page:  # Full page: the viewport width, and taller than the viewport (the fixture page is about 2400 px).
                checks[f'TB_{kind[0]}_png_exported_matches_digest_full_page_width_and_taller_than_viewport'] = (
                    bool(data) and hashlib.sha256(data).hexdigest() == ev['digest'] and size is not None and size[0] == expected[0] and size[1] > expected[1])
                if args.peer_top == 'fixture':
                    scripts = (v['browser_audit'] or {}).get('script_errors')
                    checks[f'TB_{kind[0]}_page_script_error_recorded_by_class_and_lowers_the_verdict'] = (
                        scripts == 1 and (v['browser_audit'] or {}).get('script_error_entries') == [{'name': 'TypeError', 'count': 1}]
                        and 'PAGE_SCRIPT_ERROR' in audit_problems(v['browser_audit']))
                stab = (v['capture_info'] or {}).get('stability') or {}
                comp = v['comparison'] or {}
                shots = stab.get('shots') or []
                if args.peer_top == 'unstable':  # never settles: UNSTABLE, carried into the comparison as CAPTURE_UNSTABLE -> UNKNOWN
                    checks[f'TB_{kind[0]}_never_settling_page_is_unstable_within_the_limits'] = (
                        stab.get('value') == 'UNSTABLE' and stab.get('reason') == 'NOT_SETTLED' and 2 <= len(shots) <= 6
                        and stab.get('elapsed_ms', 99999) <= 4500 + 1500)
                    checks[f'TB_{kind[0]}_capture_unstable_reaches_the_comparison_as_unknown'] = (
                        'CAPTURE_UNSTABLE' in comp.get('reasons', []) and 'CAPTURE_UNSTABLE' in comp['operational']['reasons']
                        and comp['operational']['verdict'] == 'UNKNOWN' and comp['quality'] == 'UNKNOWN')
                else:
                    checks[f'TB_{kind[0]}_capture_settled_by_the_stability_policy'] = (
                        stab.get('value') == 'STABLE' and len(shots) >= 3 and shots[-1]['sha256'] == ev['digest']
                        and 'CAPTURE_UNSTABLE' not in comp.get('reasons', ['CAPTURE_UNSTABLE']))
                if args.peer_top == 'ttn':  # TTN build: the evidence ends a run of >= required identical shots spanning >= min_span
                    rules = top.get('stability') or {}
                    k = rules.get('required_identical', 3)
                    checks[f'TB_{kind[0]}_ttn_evidence_ends_a_settled_time_spaced_run'] = (
                        len(shots) >= k and len({s['sha256'] for s in shots[-k:]}) == 1 and shots[-1]['sha256'] == ev['digest']
                        and shots[-1]['t_ms'] - shots[-k]['t_ms'] >= rules.get('min_span_ms', 0))
                    report.setdefault('ttn_render_states', {})[kind] = [s['sha256'][:12] for s in shots]
            else:
                checks[f'TB_{kind[0]}_png_exported_matches_digest_and_viewport_size'] = bool(data) and hashlib.sha256(data).hexdigest() == ev['digest'] and tuple(size or ()) == expected
            if data:
                (review / f'{kind.lower()}.png').write_bytes(data)
            report['tb'][kind] = {'png_sha256': ev['digest'] if ev else None, 'size': size, 'repeat_identical': (v['capture_info'] or {}).get('repeat_identical'),
                                  'candidate': next((b for b in v['baselines'] if b['candidate_id'] == 'capture-' + v['job']['job_id']), None),
                                  'chromium': ((v['meta'] or [{}])[0].get('sandbox') or {}).get('browser_version'),
                                  'browser_audit': {kk: (v['browser_audit'] or {}).get(kk) for kk in ('complete', 'requests', 'finished', 'pending', 'failed', 'http_errors', 'script_errors')},
                                  'runtime': ((v['meta'] or [{}])[0].get('runtime')), 'stability': (v['capture_info'] or {}).get('stability'),
                                  'comparison_reasons': (v['comparison'] or {}).get('reasons'),
                                  'operational': ((v['comparison'] or {}).get('operational') or {}).get('verdict')}
        checks['TB_exactly_two_candidates_both_pending_none_approved'] = len(results['Mobile']['baselines']) == 2 and all(b['approval_state'] == 'PENDING' for b in results['Mobile']['baselines'])
        checks['flag_false_in_source_at_end'] = (root / 'src/isolation/site_policy.py').read_text('utf-8') == sp_text
        report['peer_request_total'] = sum(e.get('event') == 'request' for e in peer_events(launch, peer))
    except SystemExit:
        report['stopped'] = 'PART1_ONLY'
    except Exception as exc:
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)[:400] if isinstance(exc, (AssertionError, IsolationLeak)) else 'Inspect bounded logs'
        report['isolation_leak'] = isinstance(exc, IsolationLeak)
    finally:
        if state['window'] is not None:  # Never leave a window open, whatever failed.
            for how in ('HOST', 'REAPER'):
                try:
                    if how == 'REAPER' and p['reaper'] is not None:
                        send_control(p['reaper'], {'type': 'close'})
                        report['windows'][state['window']]['finally_reaper'] = read_control(p['reaper'], 20)
                    elif how == 'HOST':
                        report['windows'][state['window']]['finally_host_flushed'] = policy_call('egress_close', device=device)['grants_flushed']
                except Exception:
                    report['windows'][state['window']]['finally_' + how.lower() + '_failed'] = True
            report['windows'][state['window']]['closed_by'] = 'FINALLY'
        for key, command in (('worker', {'type': 'quit'}), ('broker', {'type': 'quit'}), ('reaper', {'type': 'cancel'})):
            if p[key] is not None:
                try:
                    send_control(p[key], command)
                    read_control(p[key], 10)
                except Exception:
                    pass
        if anchor and not (evidence / 'workspace').exists():
            try:
                launch.call('cp', anchor + ':/evidence/ws', str(evidence / 'workspace'), timeout=120)
            except Exception:
                pass
        if peer:
            try:
                (evidence / 'peer-log.jsonl').write_text('\n'.join(json.dumps(e) for e in peer_events(launch, peer) if e.get('event') != 'cert'), encoding='utf-8')
            except Exception:
                pass
        report['all_owned_stopped'] = launch.stop_all() if launch.resources else True
        for key in p:
            if p[key] is not None:
                try:
                    p[key].wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p[key].terminate()
                    p[key].wait(timeout=5)
        report['all_owned_removed'] = launch.cleanup() if launch.resources else True
        report['own_network_removed'] = not any(r['kind'] == 'network' for r in launch.resources.values())
        for own, rec in list(launch.resources.items()):
            if rec['kind'] == 'network':
                try:
                    info = json.loads(launch.call('network', 'inspect', own))[0]
                    if (rec['id'] == info['Id'] and info['Internal'] is True and (info.get('Labels') or {}).get('siteproof.task') == TASK and not info.get('Containers')):
                        launch.call('network', 'rm', info['Id'])
                        report['own_network_removed'] = True
                except Exception:
                    report['own_network_removed'] = False
        later = inventory()
        launch.save('docker-inventory-after.json', later)
        new_volumes = sorted(set(later['volumes']) - set(before['volumes']))
        report['new_volumes_retained'] = new_volumes
        report['existing_docker_resources_unchanged'] = (later['networks'] == before['networks'] and later['images'] == before['images'] and later['containers'] == before['containers']
                                                         and set(before['volumes']) <= set(later['volumes']) and all(v.startswith(prefix) for v in new_volumes))
        report['no_run_container_or_network_left'] = not any(prefix in line for key in ('networks', 'containers') for line in later[key])
        report['checks'] = checks
        report['passed'] = (bool(checks) and all(checks.values()) and 'error' not in report and 'stopped' not in report and report.get('all_owned_stopped') is True
                            and report.get('all_owned_removed') is True and report['own_network_removed'] and report['existing_docker_resources_unchanged']
                            and not any(k.startswith('finally_') for w in report['windows'].values() for k in w))
        launch.save('validation-result.json', report)
        manifest = {x.relative_to(evidence).as_posix(): hashlib.sha256(x.read_bytes()).hexdigest()
                    for x in sorted(evidence.rglob('*')) if x.is_file() and x.name != 'export-sha256.json'}
        (evidence / 'export-sha256.json').write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding='utf8')
        report['sha256_manifest'] = {'files': len(manifest), 'mismatches': sum(hashlib.sha256((evidence / k).read_bytes()).hexdigest() != v for k, v in manifest.items())}
        print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
