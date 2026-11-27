"""S3-1: first real-site capture of ONE page (TTN /about) with Baseline CANDIDATE creation. Candidates are never approved here.

Order is the safety argument, and every step before CAPTURE is gated:
  GATE-A  OS egress closed, no window: Broker config refusal, default OFF, Browser/trusted/Broker/resolver/Docker paths, Chromium direct
          paths, 19-case refusal matrix, window stop procedures (host close, reaper EOF).                       (no external traffic possible)
  GATE-B  one egress window with a DNS-ONLY grant (the Broker resolves the TTN host; NOBODY connects): Browser and trusted-UID
          prohibited paths with a live grant, Chromium direct paths incl. the granted IP, refusal matrix, accounting: ZERO TCP flows.
  GATE-C  Broker SIGKILLed with a live grant: no new grant, the independent reaper removes the stale grant by deadline.
  Any gate failure raises GateFailed BEFORE the first navigation to the real site; the run then ends with the window closed.
  CAPTURE Desktop then Mobile, each in its own short window (fresh Broker, TTL 100 s, reaper, one proxy, one job): a HEAD of the exact
          page first (must be 200 and not redirect), then the production capture pipeline; Baseline candidate saved, never approved.
Nothing here edits the site, approves a Baseline, compares to an approved Baseline, touches AWS or Git, or starts monitoring.
"""
import argparse
import hashlib
import html
import ipaddress
import json
from pathlib import Path
import platform
import re
import struct
import subprocess
import time
import uuid

from src.runtime.docker_launcher import TASK, read_control, send_control
from tests.runtime.browser_bundle import mount_args, stage_browser_bundle
from tests.runtime.bundle_probe import run_bundle_probe
from tests.runtime.preflight_checks import head_is_as_expected
from tests.runtime.validate_s2b import S2BLauncher, counters, delta, git, rule_set, tree_digest

M5_IMAGE = 'sha256:9c88112b42070369876fdb24476af283b3908a3fdc630b66fedacf4f20c4d2c8'
FORBIDDEN = ('tcp', 'dns', 'udp', 'metadata', 'lan', 'host_model', 'ipv6')
CONNECTED = ('ERR_CERT', 'ERR_SSL', 'ERR_BAD_SSL', 'ERR_HTTP', 'ERR_EMPTY_RESPONSE', 'ERR_RESPONSE')
WINDOW_CAP = 120
TTL = 100
PATH = '/about'


class IsolationLeak(RuntimeError):
    pass


class GateFailed(RuntimeError):
    pass


def tx_packets(snapshot, device):
    for link in snapshot['links']:
        if link.get('ifname') == device:
            return (link.get('stats64') or link.get('stats'))['tx']['packets']
    raise KeyError(device)


def flows_to(snapshot, ip):
    if not isinstance(snapshot['conntrack'], list):
        return None
    return {m[1] for c in snapshot['conntrack'] if ' tcp ' in c for m in [re.search(r'dst=%s sport=(\d+) dport=443' % re.escape(ip), c)] if m}


def grant_ips(snapshot):
    return {re.search(r'-d (\S+)/32', rule)[1] for rule in snapshot['grant_rules']}


def external_tcp_flows(snapshot):
    """(destination, source port) of every non-loopback TCP flow currently tracked. A flow is identified by its source port."""
    ct = snapshot['conntrack'] if isinstance(snapshot['conntrack'], list) else None
    if ct is None:
        return None
    found = set()
    for c in ct:
        m = re.search(r'dst=(\S+) sport=(\d+)', c)
        if ' tcp ' in c and m and not m[1].startswith('127.') and m[1] not in ('169.254.169.254', '10.231.77.5'):
            found.add((m[1], m[2]))
    return found


def png_size(data):
    return struct.unpack('>II', data[16:24]) if data[:8] == b'\x89PNG\r\n\x1a\n' else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--image', default=M5_IMAGE)
    parser.add_argument('--gate-only', action='store_true', help='Run GATE-A..C and stop: no navigation, no TCP connection, ever')
    args = parser.parse_args()
    evidence = Path(args.evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    root = Path.cwd()
    launch = S2BLauncher(evidence, args.image, root / 'runtime/docker/seccomp-siteproof.json')
    prefix = 'siteproof-m2-s3-' + time.strftime('%H%M%S') + '-' + uuid.uuid4().hex[:6]
    report = {'task': 'SITEPROOF-S3-1-TTN-ABOUT-FIRST-CAPTURE-01', 'passed': False, 'baseline_approved': False, 'baseline_compared': False, 'aws_touched': False,
              'site_modified': False, 'monitoring_started': False, 'navigated_to_real_site': False, 'windows': {}, 'captures': {}}
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
        for key, value in (('CapEff:', '0000000000000000'), ('CapBnd:', '0000000000000000'), ('NoNewPrivs:', '1'), ('Seccomp:', '2')):
            assert any(line.split() == [key, value] for line in result['status']), (key, result['status'])
        return result['results']

    def api_probe(container, uid, label):
        out, _ = launch.bounded(container, b'{}\n')
        result = json.loads(out)
        launch.save(label + '.json', result)
        assert result['netns'] == namespace and result['uid'] == uid
        return result

    def browser_run(config, label, seconds=120):
        out, _ = launch.bounded(chromium, json.dumps({**config, 'gateway': gateway, 'proxy_port': 18080, 'host': host, 'url': base_url,
                                                      'resources': ready['resources'], 'direct_seconds': 1.0, 'proxied_seconds': 2}).encode() + b'\n',
                                seconds=seconds, evidence_sink=lambda o, e, x: (
                                    (evidence / (label + '.stderr.log')).write_bytes(launch._redact_log(e)), launch.save(label + '-execution.json', x)))
        result = json.loads(out)
        launch.save(label + '.json', result)
        return result

    def sandboxed(body):
        return bool(re.search(r'Layer 1 Sandbox\s+Namespace', body) and re.search(r'PID namespaces\s+Yes', body)
                    and re.search(r'Network namespaces\s+Yes', body) and re.search(r'Seccomp-BPF sandbox\s+Yes', body))

    def reached(results, *keys):
        return [k for k in (keys or results) if results[k]['reached']]

    def untouched(result, proxied=False):
        return all(v['reached'] is False and (proxied or not (v['error'] or '').startswith(CONNECTED)) for v in result.values())

    def canary_zero(baseline, label):
        now = wcontrol({'type': 'counts'})['counts']
        d = {k: now.get(k, 0) - baseline.get(k, 0) for k in FORBIDDEN}
        launch.save(label + '-canaries.json', d)
        if any(d.values()):
            raise IsolationLeak('forbidden canary received: ' + label)

    def matrix_ok(matrix, expected_calls=None, log_len=None):
        return len(matrix['results']) >= 19 and all(
            r['status'].startswith('HTTP/1.1 502') and r['resolutions'] == [] and r['dialed'] == [] and r['complete'] and r['records'] and all(x[2] == 'BLOCK' for x in r['records'])
            for r in matrix['results'])

    # ---- Broker / reaper (separate containers; the Worker has neither capability nor access) ----------------------------------
    def start_broker(ttl, fault=False):
        p['broker'] = subprocess.Popen(launch.cli + ['start', '-a', '-i', broker], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=broker_log)
        send_control(p['broker'], {'mode': 'system', 'real_site_access': True, 'target_id': 'ttn-home', 'hosts': [host], 'device': device, 'ttl': ttl,
                                   'max_grants': 1, 'fault_injection': fault})
        reply = read_control(p['broker'], 30)
        assert reply['type'] == 'ready'
        return reply

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
        assert deadline <= WINDOW_CAP - 5
        p['reaper'] = subprocess.Popen(launch.cli + ['start', '-a', '-i', reaper], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=reaper_log)
        send_control(p['reaper'], {'netns': namespace, 'device': device, 'deadline': deadline})
        assert read_control(p['reaper'], 30)['type'] == 'ready'

    def end_reaper(wait=20):
        message = read_control(p['reaper'], wait)
        p['reaper'].wait(timeout=15)
        p['reaper'] = None
        return message

    def cancel_reaper():
        send_control(p['reaper'], {'type': 'cancel'})
        return end_reaper(15)

    def open_window(label, reaper_deadline, enable=True):
        start_reaper(reaper_deadline)  # The independent controller exists BEFORE anything is opened.
        state.update(window=label, started=time.monotonic())
        policy_call('egress_open', device=device)
        report['windows'][label] = {'opened_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'reaper_deadline_seconds': reaper_deadline}
        if enable:
            assert bcontrol({'type': 'enable'})['type'] == 'enabled'
            assert bcontrol({'type': 'lease_open', 'lease': 'job', 'hosts': [host]})['ok'] is True

    def mark_closed(label, how):
        seconds = round(time.monotonic() - state['started'], 1)
        report['windows'][label].update(closed_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), closed_by=how, duration_seconds=seconds)
        state['window'] = None
        return seconds

    def close_window_by_host(label):
        closed = bcontrol({'type': 'close'})
        flushed = policy_call('egress_close', device=device)
        reaper_msg = cancel_reaper()
        return closed, flushed, reaper_msg, mark_closed(label, 'HOST')

    def client_resolve(label):
        return probe(trusted, 1001, label, {'mode': 'resolve', 'lease': 'job', 'host': host})

    broker = reaper = anchor = policy = chromium = trusted = browser = capture_c = None
    broker_log = reaper_log = None
    try:
        # ------------------------------------------------------------------ Start Gate records
        head = git('rev-parse', 'HEAD').strip()
        sp_text = (root / 'src/isolation/site_policy.py').read_text('utf-8')
        targets = json.loads((root / 'src/noxiworks/targets.json').read_text('utf-8'))
        page = next(x for x in targets['pages'] if x['target_id'] == 'ttn-home')
        site = next(x for x in targets['sites'] if x['site_id'] == page['site_id'])
        host = re.match(r'https://([a-z0-9.-]+)/\Z', page['url'])[1]
        base_url = page['url']
        target_url = 'https://' + host + PATH
        src_digest, src_files = tree_digest(root / 'src')
        rt_digest, rt_files = tree_digest(root / 'tests/runtime')
        launch.save('start-gate.json', {
            'branch': git('branch', '--show-current').strip(), 'head': head, 'uncommitted_entries': len(git('status', '--short', '-uall').splitlines()),
            'target': {'target_id': page['target_id'], 'site': {k: site.get(k) for k in ('site_id', 'name', 'origin')}, 'host': host, 'port': 443, 'path': PATH, 'url': target_url,
                       'approved_by_user': '2026-11-18'},
            'allowed_destinations': [{'hostname': host, 'port': 443}], 'wildcards': 0, 'auto_added_hosts': 0, 'credentials': 'none',
            'flag_in_source': re.search(r'^REAL_SITE_ACCESS_ENABLED = (\w+)', sp_text, re.M)[1],
            'formal_gates': {'LOCAL-ISOLATION': 'NOT VERIFIED (unchanged by this run; the pre-navigation GATE below is a run-local measurement)'},
            'overlay': {'src': {'sha256': src_digest, 'files': src_files}, 'tests/runtime': {'sha256': rt_digest, 'files': rt_files}},
            'window_cap_seconds': WINDOW_CAP, 'grant_ttl_seconds': TTL, 'max_grants': 1})
        checks['flag_false_in_source_at_start'] = re.search(r'^REAL_SITE_ACCESS_ENABLED = False$', sp_text, re.M) is not None
        checks['target_is_the_single_registered_ttn_host_and_exact_path'] = (host == 'tokyo-trouble-navi-review-ai-off-2026.kmr8oji.workers.dev' and site['origin'] == 'https://' + host
                                                                             and '*' not in host and target_url == 'https://' + host + '/about')
        image = json.loads(launch.call('image', 'inspect', launch.image))[0]
        launch.image = image['Id']
        launch.save('run-conditions.json', {'docker_server': launch.call('version', '--format', '{{.Server.Version}}').strip(), 'host': platform.platform(), 'image_id': image['Id'],
                                            'git_head': head, 'run_prefix': prefix, 'no_pull_build': True, 'no_privileged_no_host_network_no_docker_socket': True,
                                            'network': 'NEW labelled bridge (not --internal); egress only through Broker-issued per-IP OS grants in this namespace'})
        overlay = []
        for rel in ('src', 'tests/runtime'):
            overlay += ['--mount', f'type=bind,src={(root / rel).resolve()},dst=/opt/siteproof/{rel},readonly']
        network = launch.create_network(prefix + '-network')
        volume = launch.create_volume(prefix + '-evidence')
        init = launch.create(name('volume-init'), ['--network', 'none', '--user', '0:0', '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--security-opt', 'no-new-privileges=true',
                                                   '--read-only', '--mount', f'type=volume,src={volume},dst=/evidence'],
                             ['python', '-c', "import os;os.chmod('/evidence',0o700);os.chown('/evidence',1001,1001)"])
        launch.bounded(init)
        launch.retire(init)
        anchor = launch.create(name('worker'), [*overlay, '--network', network, '--user', '1001:1001', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges=true', '--read-only', '--pids-limit', '128', '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
            '--sysctl', 'net.ipv6.conf.all.disable_ipv6=0', '--sysctl', 'net.ipv4.ip_unprivileged_port_start=0',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m,uid=1001,gid=1001', '--mount', f'type=volume,src={volume},dst=/evidence'], ['python', '-c', 'import time;time.sleep(86400)'])
        launch.call('start', anchor)
        namespace = launch.call('exec', anchor, 'readlink', '/proc/self/ns/net').strip()
        policy = helper('policy', 0, 'tests.runtime.netpolicy_hardened', admin=True, mounts=overlay)
        prepared = policy_call('prepare')
        device = prepared['devices'][0]
        gateway = next(r for r in prepared['routes'] if r.get('dst') == 'default')['gateway']
        launch.save('network-config.json', {'device': device, 'default_gateway': gateway, 'addresses': prepared['addresses'], 'routes': prepared['routes']})
        policy_call('install', proxy_ports=[18080])
        resolver_file = evidence / 'resolv.conf'
        resolver_file.write_text('nameserver 127.0.0.3\noptions timeout:1 attempts:1\n', encoding='ascii')
        # Browser identities (probe-browser, api-browser, chromium, capture): ONLY the minimal code bundle over /opt/siteproof and the
        # read-only resolver file. No development tree, no fixture CA. Trusted identities keep `overlay`.
        bundle_tree, bundle_manifest = stage_browser_bundle(root, evidence / 'browser-bundle')
        mounts = [*mount_args(bundle_tree), '--mount', f'type=bind,src={resolver_file},dst=/etc/resolv.conf,readonly']
        s0 = snap()
        baseline_rules = rule_set(s0)
        launch.save('closed-baseline-rules.json', {'rules': baseline_rules, 'counters': counters(s0)})
        privileged = launch.options(anchor, 0, mounts=overlay) + ['--cap-add', 'NET_ADMIN']
        broker = launch.create(name('broker'), privileged, ['python', '-m', 'tests.runtime.egress_broker'])
        reaper = launch.create(name('reaper'), privileged, ['python', '-m', 'tests.runtime.egress_reaper'])
        broker_check = launch.create(name('broker-check'), privileged, ['python', '-m', 'tests.runtime.egress_broker'])
        broker_log, reaper_log = (evidence / 'broker-stderr.log').open('wb'), (evidence / 'reaper-stderr.log').open('wb')
        trusted = helper('probe-trusted', 1001, 'tests.runtime.s2h_probe', mounts=overlay)
        browser = helper('probe-browser', 1000, 'tests.runtime.s2h_probe', mounts=mounts)
        api_trusted = helper('api-trusted', 1001, 'tests.runtime.s2a_probe', mounts=overlay)
        api_browser = helper('api-browser', 1000, 'tests.runtime.s2a_probe', mounts=mounts)
        chromium = helper('chromium', 1000, 'tests.runtime.s2b_browser', mounts=mounts)
        capture_c = helper('capture', 1000, 'tests.runtime.s3_browser', mounts=mounts)

        # ================================================================== GATE-A: OS egress CLOSED
        ok = True
        for bad in ({'hosts': ['example.com'], 'max_grants': 1}, {'hosts': [host], 'max_grants': 2}, {'hosts': [host, 'www.' + host], 'max_grants': 1}, {'hosts': ['noxiworks.com'], 'max_grants': 1}):
            try:
                out, _ = launch.bounded(broker_check, json.dumps({'mode': 'system', 'real_site_access': True, 'target_id': 'ttn-home', 'device': device, 'ttl': TTL, **bad}).encode() + b'\n', seconds=20)
                ok &= b'"ready"' not in out
            except Exception:
                pass  # The daemon exits non-zero before announcing readiness.
        checks['A_broker_refuses_any_configuration_but_the_single_registered_host'] = ok
        # Gate: what the Browser can see of the project, measured from inside a Browser-flagged container (before any real-site contact).
        bundle_checks, _ = run_bundle_probe(launch, name('bundle-check'), bundle_tree, bundle_manifest, resolver_file, launch.save)
        for key, value in bundle_checks.items():
            checks['A_' + key] = value
        checks['A_bundle_minimal_and_no_fixture_ca_mounted_for_the_real_run'] = 0 < bundle_manifest['file_count'] < 45 and not any('fixture-ca' in str(m) for m in mounts)
        start_broker(ttl=TTL)
        worker_log = (evidence / 'worker-stderr.log').open('wb')
        p['worker'] = subprocess.Popen(launch.cli + ['exec', '-i', '--user', '1001:1001', anchor, 'python', '-m', 'tests.runtime.s3_worker'],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=worker_log)
        ready = read_control(p['worker'], 60)
        assert ready['type'] == 'ready' and ready['namespace'] == namespace and ready['registered_host'] == host and ready['target_url'] == target_url
        checks['A_default_off_in_worker_and_policy_refused'] = ready['flag_at_start'] is False and wcontrol({'type': 'policy_default'})['plan_enabled_flag_off'] == 'REFUSED'
        started = wcontrol({'type': 'start_real'})
        launch.save('A-real-started.json', started)
        checks['A_worker_allowlist_is_exactly_the_host_443_and_resolver_is_brokered'] = started['hostnames'] == [host] and started['ports'] == [443] and started['resolver'] == 'Recording'
        closed_connect = wcontrol({'type': 'connect_raw', 'authority': host + ':443'})['result']
        launch.save('A-closed-connect.json', closed_connect)
        stateA = bcontrol({'type': 'state'})
        checks['A_closed_state_connect_refused_before_any_dns_or_dial'] = (closed_connect['status'].startswith('HTTP/1.1 502') and closed_connect['dialed'] == []
                                                                           and closed_connect['resolutions'][0].get('denied') == 'EGRESS_DISABLED' and stateA['resolver_log'] == [])
        t_targets = [['gateway443', gateway, 443], ['host_model443', '192.168.65.254', 443], ['host_model2375', '192.168.65.254', 2375], ['documentation443', '192.0.2.1', 443],
                     ['broker', '127.0.0.6', 18090], ['resolver_tcp', '127.0.0.11', 53], ['canary_tcp', '127.0.0.2', 18555], ['canary_lan', '10.231.77.5', 18555],
                     ['canary_metadata', '169.254.169.254', 80], ['canary_host_model', '127.0.0.4', 18555], ['docker_api_model', '127.0.0.5', 2375], ['proxy', '127.0.0.1', 18080]]
        u_targets = [['resolver_udp', '127.0.0.11', 53], ['canary_dns', '127.0.0.3', 53], ['canary_udp', '127.0.0.3', 5353], ['documentation_udp', '192.0.2.1', 53]]
        sA0 = snap()
        a_t = probe(trusted, 1001, 'A-trusted-tcp', {'mode': 'connect', 'targets': t_targets})
        a_tu = probe(trusted, 1001, 'A-trusted-udp', {'mode': 'udp', 'targets': u_targets})
        canary_A = wcontrol({'type': 'counts'})['counts']
        checks['A_trusted_positive_controls_and_broker_reachable'] = all(a_t[k]['reached'] for k in ('broker', 'canary_tcp', 'canary_lan', 'canary_metadata', 'canary_host_model', 'docker_api_model', 'proxy')) and a_tu['canary_dns']['reached'] and a_tu['canary_udp']['reached']
        checks['A_trusted_cannot_leave_while_closed_or_use_dns'] = not reached(a_t, 'gateway443', 'host_model443', 'host_model2375', 'documentation443', 'resolver_tcp') and not reached(a_tu, 'resolver_udp', 'documentation_udp')
        b_t = probe(browser, 1000, 'A-browser-tcp', {'mode': 'connect', 'targets': t_targets})
        b_u = probe(browser, 1000, 'A-browser-udp', {'mode': 'udp', 'targets': u_targets})
        sA1 = snap()
        checks['A_browser_reaches_only_the_owned_proxy_not_the_broker_or_resolver'] = reached(b_t) == ['proxy'] and not reached(b_u)
        checks['A_browser_drops_counted_by_os'] = all(delta(counters(sA1), counters(sA0)).get(k, 0) > 0 for k in ('SP_BROWSER_TCP_DROP', 'SP_BROWSER_UDP_DROP', 'SP_BROWSER_DNS_DROP'))
        netA = browser_run({'mode': 'network'}, 'A-chromium-network')
        checks['A_chromium_direct_and_proxied_paths_denied'] = untouched(netA['direct']) and untouched(netA['proxied_refused'], proxied=True) and netA['udp_attempt_completed'] is True
        checks['A_chromium_sandbox_verified'] = sandboxed(netA['sandbox']['body'])
        matrixA = wcontrol({'type': 'deny_matrix', 'gateway': gateway}, 240)
        launch.save('A-deny-matrix.json', matrixA)
        stateA2 = bcontrol({'type': 'state'})
        checks['A_deny_matrix_blocked_before_any_dns_or_dial'] = matrix_ok(matrixA) and matrixA['resolver_calls'] == 1 and stateA2['resolver_log'] == []
        checks['A_no_connect_allow_from_any_gate_a_activity'] = wcontrol({'type': 'ledger_window'})['window']['allowed'] == 0
        apiA = {w: api_probe(c, u, 'A-docker-api-' + w) for w, c, u in (('trusted', api_trusted, 1001), ('browser', api_browser, 1000))}
        checks['A_docker_api_model_denied_for_browser_and_sockets_absent'] = (apiA['trusted']['modelled']['docker_api_model_127.0.0.5:2375'] is True
                                                                              and apiA['browser']['modelled']['docker_api_model_127.0.0.5:2375'] is False
                                                                              and not any(apiA['browser']['unmodelled'].values()) and set(apiA['browser']['unix_sockets'].values()) == {'ABSENT'})
        canary_zero(canary_A, 'A')
        open_window('A-dry-host', 30, enable=False)
        policy_call('egress_close', device=device)
        msg = cancel_reaper()
        mark_closed('A-dry-host', 'HOST')
        checks['A_window_close_by_host_restores_the_baseline'] = rule_set(snap()) == baseline_rules and msg['type'] == 'cancelled'
        open_window('A-dry-eof', 30, enable=False)
        p['reaper'].stdin.close()  # The host "dies".
        msg = end_reaper(20)
        mark_closed('A-dry-eof', 'REAPER_EOF')
        checks['A_reaper_closes_the_window_when_the_host_disappears'] = msg['reason'] == 'EOF' and not msg['errors'] and rule_set(snap()) == baseline_rules

        # ================================================================== GATE-B: window open, DNS-only grant, NO TCP
        open_window('GATE-B', 110)
        g = client_resolve('B-grant')
        sB = snap()
        stateB = bcontrol({'type': 'state'})
        launch.save('B-broker-state.json', stateB)
        real_ip = next(iter(grant_ips(sB)), None)
        log0 = (stateB['resolver_log'] or [{}])[0]
        checks['B_broker_resolved_the_ttn_host_completely_and_granted_exactly_one_ipv4_443'] = (
            g['status'] == 'COMPLETE' and log0.get('status') == 'COMPLETE' and log0.get('a_complete') is True and log0.get('aaaa_complete') is True
            and all(ipaddress.ip_address(a).is_global for a in log0.get('addresses', [])) and real_ip is not None and len(sB['grant_rules']) == 1
            and all(x in sB['grant_rules'][0] for x in ('--dport 443', '--ctstate NEW', '--uid-owner 1001', '-o ' + device, 'SP_GRANT')) and g['addresses'][:1] == [real_ip])
        siblings = [a for a in log0.get('addresses', []) if ipaddress.ip_address(a).version == 4 and a != real_ip]
        sibling = siblings[0] if siblings else None
        report['gate_sibling_ipv4_available'] = sibling is not None
        t2 = t_targets + [['granted_port80', real_ip, 80], ['granted_port8443', real_ip, 8443]] + ([['other_answer_443', sibling, 443]] if sibling else [])
        sC0 = snap()
        c_t = probe(trusted, 1001, 'B-trusted-tcp', {'mode': 'connect', 'targets': t2})
        sC1 = snap()
        dC = delta(counters(sC1), counters(sC0))
        deny_keys = ['gateway443', 'host_model443', 'host_model2375', 'documentation443', 'granted_port80', 'granted_port8443', 'resolver_tcp'] + (['other_answer_443'] if sibling else [])
        checks['B_trusted_cannot_reach_other_ips_other_ports_internal_or_dns'] = not reached(c_t, *deny_keys)
        checks['B_trusted_refusals_counted_by_os_rules'] = dC.get('SP_TRUSTED_OTHER_DROP', 0) >= (3 if sibling else 2) and dC.get('SP_TRUSTED_NONPUBLIC_DROP', 0) >= 3 and dC.get('SP_WORKER_DNS_DROP', 0) >= 1
        checks['B_trusted_positive_controls_still_hold'] = all(c_t[k]['reached'] for k in ('broker', 'canary_tcp', 'canary_lan', 'canary_metadata', 'canary_host_model', 'docker_api_model', 'proxy'))
        canary_B = wcontrol({'type': 'counts'})['counts']
        b_t2 = probe(browser, 1000, 'B-browser-tcp', {'mode': 'connect', 'targets': t2 + [['granted_port443', real_ip, 443]]})
        b_u2 = probe(browser, 1000, 'B-browser-udp', {'mode': 'udp', 'targets': u_targets})
        sC2 = snap()
        checks['B_browser_reaches_only_the_owned_proxy_even_to_the_granted_ip_443'] = reached(b_t2) == ['proxy'] and not reached(b_u2)
        checks['B_browser_cannot_reach_the_broker_or_the_resolver'] = not reached(b_t2, 'broker', 'resolver_tcp') and not reached(b_u2, 'resolver_udp')
        checks['B_browser_drops_counted_by_os'] = all(delta(counters(sC2), counters(sC1)).get(k, 0) > 0 for k in ('SP_BROWSER_TCP_DROP', 'SP_BROWSER_UDP_DROP', 'SP_BROWSER_DNS_DROP'))
        netB = browser_run({'mode': 'network', 'real_ip': real_ip}, 'B-chromium-network')
        sC3 = snap()
        checks['B_chromium_direct_attempts_denied_incl_granted_ip_and_name'] = untouched(netB['direct']) and 'allowed_host_ip_direct_https' in netB['direct'] and netB['udp_attempt_completed'] is True
        checks['B_chromium_proxied_refusals_hold'] = untouched(netB['proxied_refused'], proxied=True)
        checks['B_chromium_sandbox_verified'] = sandboxed(netB['sandbox']['body'])
        checks['B_chromium_drops_counted_by_os'] = all(delta(counters(sC3), counters(sC2)).get(k, 0) > 0 for k in ('SP_BROWSER_TCP_DROP', 'SP_BROWSER_UDP_DROP', 'SP_BROWSER_DNS_DROP', 'SP_BROWSER_IPV6_DROP'))
        resolutions_before = len(bcontrol({'type': 'state'})['resolver_log'])
        matrixB = wcontrol({'type': 'deny_matrix', 'gateway': gateway}, 240)
        launch.save('B-deny-matrix-open.json', matrixB)
        stateB2 = bcontrol({'type': 'state'})
        checks['B_unregistered_hosts_refused_without_dns_or_dial'] = matrix_ok(matrixB) and len(stateB2['resolver_log']) == resolutions_before
        report['gate_matrix_stalls'] = sum(1 for r in matrixB['results'] if r.get('stalled_first_attempt')) + sum(1 for r in matrixA['results'] if r.get('stalled_first_attempt'))
        again = client_resolve('B-re-resolution')
        stateB3 = bcontrol({'type': 'state'})
        same = again['status'] == 'COMPLETE' and again['addresses'][:1] == [real_ip]
        capped = again['status'] == 'ERROR' and again['denials'] and again['denials'][0]['reason'] == 'GRANT_LIMIT'
        checks['B_re_resolution_is_revalidated_and_never_adds_a_second_address'] = (same or capped) and stateB3['state']['active_addresses'] == [real_ip] and len(grant_ips(snap())) == 1
        checks['B_no_connect_allow_while_only_a_dns_grant_exists'] = wcontrol({'type': 'ledger_window'})['window']['allowed'] == 0  # Browser-originated ALLOW would mean a real page fetch
        apiB = {w: api_probe(c, u, 'B-docker-api-' + w) for w, c, u in (('trusted', api_trusted, 1001), ('browser', api_browser, 1000))}
        checks['B_docker_api_model_and_gateways_denied_for_browser'] = (apiB['browser']['modelled']['docker_api_model_127.0.0.5:2375'] is False and not any(apiB['browser']['unmodelled'].values())
                                                                        and set(apiB['browser']['unix_sockets'].values()) == {'ABSENT'})
        canary_zero(canary_B, 'B')
        sE = snap()
        checks['B_conntrack_readable_and_zero_external_tcp_flows'] = external_tcp_flows(sE) == set()
        closed, flushed, reaper_msg, seconds = close_window_by_host('GATE-B')
        launch.save('B-close.json', {'broker': closed, 'policy_flush': {k: v for k, v in flushed.items() if k in ('grants_flushed', 'grant_rules')}, 'reaper': reaper_msg})
        checks['B_close_leaves_no_grant_and_restores_the_baseline'] = closed['clean'] is True and closed['grant_rules'] == [] and rule_set(flushed) == baseline_rules and reaper_msg['type'] == 'cancelled' and seconds <= WINDOW_CAP

        # ================================================================== GATE-C: Broker SIGKILL with a live grant; reaper deadline
        report['broker_gate_b_final'] = stop_broker()
        start_broker(ttl=TTL)
        open_window('GATE-C', 40)
        g = client_resolve('C-grant')
        sC_a = snap()
        checks['C_grant_installed_by_the_broker_before_the_kill'] = g['status'] == 'COMPLETE' and len(grant_ips(sC_a)) == 1
        launched_ip = next(iter(grant_ips(sC_a)), None)
        launch.call('kill', broker)
        p['broker'].wait(timeout=20)
        p['broker'] = None
        dead = client_resolve('C-resolve-after-kill')
        sC_b = snap()
        checks['C_killed_broker_issues_no_new_grant_and_the_stale_one_survives_it'] = dead['status'] == 'EXCEPTION' and grant_ips(sC_b) == {launched_ip}
        reaper_final = end_reaper(60)
        mark_closed('GATE-C', 'REAPER_DEADLINE')
        launch.save('C-reaper.json', reaper_final)
        sC_c = snap()
        checks['C_reaper_deadline_removes_the_grant_and_the_window_without_the_host'] = (reaper_final['reason'] == 'DEADLINE' and reaper_final['flushed_grants'] == 1 and not reaper_final['errors']
                                                                                        and not sC_c['grant_rules'] and rule_set(sC_c) == baseline_rules)
        checks['C_no_tcp_flow_to_the_site_in_any_gate_snapshot'] = all(external_tcp_flows(s) == set() for s in (sC_a, sC_b, sC_c))
        checks['gates_all_windows_within_the_cap'] = all(w.get('duration_seconds', 0) <= WINDOW_CAP for w in report['windows'].values())
        report['gate'] = {k: v for k, v in checks.items() if k.startswith(('A_', 'B_', 'C_', 'gates_'))}
        launch.save('GATE.json', report['gate'])
        if not all(report['gate'].values()):
            raise GateFailed('PRE_NAVIGATION_GATE_FAILED: ' + ', '.join(k for k, v in report['gate'].items() if not v))
        if args.gate_only:
            raise GateFailed('STOPPED_AFTER_GATE_BY_REQUEST: no TCP connection and no navigation was ever made')

        # ================================================================== CAPTURE (Desktop, then Mobile), one short window each
        assert wcontrol({'type': 'stop_real'})['flag_after_stop'] is False
        created = wcontrol({'type': 'create'})
        launch.save('workspace-created.json', created)
        checks['S_workspace_url_is_the_exact_target'] = created['url'] == target_url
        jobs, results = {}, {}
        for kind in ('Desktop', 'Mobile'):
            prep = wcontrol({'type': 'prepare', 'kind': kind})
            launch.save(f'{kind}-prepared.json', prep)
            jobs[kind] = prep
            start_broker(ttl=TTL)
            label = 'CAPTURE-' + kind
            open_window(label, 110)
            started = wcontrol({'type': 'start_real'})
            s_open = snap()
            c_open, tx_open = counters(s_open), tx_packets(s_open, device)
            canary_k = wcontrol({'type': 'counts'})['counts']
            hd = wcontrol({'type': 'head_path'}, 90)['result']
            launch.save(f'{kind}-head.json', hd)
            tls = hd.get('tls') or {}
            if not head_is_as_expected(hd):
                raise GateFailed(f'TARGET_NOT_AS_EXPECTED ({kind}): status={hd.get("http_status")!r} redirect={hd.get("redirect")!r} tls={tls.get("result")!r}')
            report['navigated_to_real_site'] = True
            send_control(p['worker'], {'type': 'run', 'batch': prep['batch']})
            capture_meta = []
            while True:
                msg = read_control(p['worker'], 150)
                if msg['type'] == 'result':
                    break
                assert msg['type'] == 'capture'
                cfg = {'request': msg['request'], 'proxy_port': 18080, 'host': host, 'resources': msg['resources']}
                path = evidence / f'capture-{kind}'
                try:
                    out, _ = launch.bounded(capture_c, json.dumps(cfg).encode() + b'\n', seconds=min(80, msg['remaining']), evidence_sink=lambda o, e, x, path=path: (
                        path.with_suffix('.stdout.bin').write_bytes(o), path.with_suffix('.stderr.log').write_bytes(launch._redact_log(e)), launch.save(path.name + '-execution.json', x)))
                    first, payload = out.split(b'\n', 1)
                    meta = json.loads(first)
                    assert len(payload) == meta['length'] + meta['repeat_length']
                    to_worker = dict(meta['browser_report'])
                    audit = to_worker.pop('request_audit', None)
                    audit_raw = json.dumps(audit, separators=(',', ':')).encode() if audit is not None else b''
                    send_control(p['worker'], {'type': 'capture_result', 'length': meta['length'], 'repeat_length': meta['repeat_length'], 'audit_length': len(audit_raw),
                                               'reason': meta['reason'], 'cleanup': meta['cleanup'] is True, 'browser_report': to_worker}, payload + audit_raw)
                    capture_meta.append({'job_id': msg['job_id'], 'reason': meta['reason'], 'cleanup': meta['cleanup'] is True, 'sandbox': meta.get('sandbox'),
                                         'runtime': meta['browser_report'].get('runtime'), 'request_audit': audit})
                except Exception as exc:
                    send_control(p['worker'], {'type': 'capture_result', 'length': 0, 'repeat_length': 0, 'audit_length': 0, 'reason': 'CAPTURE_FAILED', 'cleanup': False, 'browser_report': {}})
                    capture_meta.append({'job_id': msg['job_id'], 'reason': 'HOST_SIDE_FAILURE:' + type(exc).__name__, 'cleanup': False})
            launch.save(f'{kind}-run-result.json', msg)
            launch.save(f'{kind}-capture-meta.json', capture_meta)
            stateK = bcontrol({'type': 'state'})
            launch.save(f'{kind}-broker-state.json', stateK)
            sK = snap()
            ips = {e['ip'] for e in stateK['state']['events'] if e['event'] == 'GRANTED'}
            dK = delta(counters(sK), c_open)
            accepted = sum(v for k, v in dK.items() if k in ('SP_GRANT', 'SP_TRUSTED_ESTABLISHED_ACCEPT'))
            flows = set()
            for ip in ips:
                flows |= {(ip, port) for port in flows_to(sK, ip) or set()}
            new_flows = (external_tcp_flows(sK) or set()) - (external_tcp_flows(s_open) or set())  # TIME_WAIT of earlier windows is not new
            ext_dsts = {d for d, _ in new_flows}
            external = sorted(new_flows)
            launch.save(f'{kind}-egress-accounting.json', {'tx_packets_delta': tx_packets(sK, device) - tx_open, 'accepted_packets': accepted, 'rule_deltas': dK,
                                                           'granted_ips': sorted(ips), 'external_tcp_destinations': sorted(ext_dsts), 'new_external_tcp_flows': external})
            canary_zero(canary_k, kind)
            job = next(j for j in msg['state']['jobs'] if j['job_id'] == prep['job_id'])
            audit_ev = next((e['network_audit'] for e in job['events'] if 'network_audit' in e), None)
            results[kind] = {'job': job, 'network_audit': audit_ev, 'granted_ips': sorted(ips), 'capture_meta': capture_meta, 'baselines': msg['baselines'], 'capture_info': msg['capture_info'].get(prep['job_id'])}
            closed, flushed, reaper_msg, seconds = close_window_by_host(label)
            launch.save(f'{kind}-close.json', {'broker': closed, 'policy_flush': {k: v for k, v in flushed.items() if k in ('grants_flushed', 'grant_rules')}, 'reaper': reaper_msg})
            stopped = wcontrol({'type': 'stop_real'})
            launch.save(f'{kind}-real-stopped.json', stopped)
            report['broker_' + kind + '_final'] = stop_broker()
            k = kind[0]
            checks[f'K{k}_head_200_tls_verified_no_redirect'] = True
            checks[f'K{k}_job_completed_with_evidence'] = job['execution'] == 'COMPLETED' and bool(job['evidence']) and job['missing_checks'] == []
            checks[f'K{k}_only_one_ipv4_443_was_ever_granted_and_it_is_the_only_external_flow_target'] = len(ips) == 1 and ext_dsts <= ips and bool(ext_dsts)
            checks[f'K{k}_tx_accounted_by_the_single_grant'] = tx_packets(sK, device) - tx_open <= accepted + 8
            checks[f'K{k}_connect_audit_complete_and_allows_only_the_ttn_host'] = bool(audit_ev) and audit_ev.get('complete') is True and all(
                e['host'] == host for e in audit_ev.get('entries', []) if e['decision'] == 'ALLOW') and audit_ev.get('allowed', 0) >= 1
            checks[f'K{k}_window_closed_clean_within_cap_and_baseline_restored'] = (closed['clean'] is True and closed['grant_rules'] == [] and rule_set(flushed) == baseline_rules
                                                                                   and reaper_msg['type'] == 'cancelled' and seconds <= WINDOW_CAP and stopped['flag_after_stop'] is False)
            checks[f'K{k}_candidate_saved_and_not_approved'] = any(b['candidate_id'] == 'capture-' + prep['job_id'] and b['approval_state'] != 'APPROVED' for b in msg['baselines']) and not any(b['approval_state'] == 'APPROVED' for b in msg['baselines'])
        report['captures'] = {k: {'job_id': v['job']['job_id'], 'execution': v['job']['execution'], 'reason': v['job']['reason'], 'quality': v['job']['quality'], 'granted_ips': v['granted_ips'],
                                  'browser_audit_summary': next(({kk: e['browser_audit'].get(kk) for kk in ('source', 'complete', 'requests', 'finished', 'pending', 'failed', 'http_errors')} for e in v['job']['events']
                                                                 if 'browser_audit' in e and isinstance(e['browser_audit'], dict)), None),
                                  'network_audit_summary': {kk: (v['network_audit'] or {}).get(kk) for kk in ('complete', 'allowed', 'blocked', 'failed', 'idle', 'in_flight', 'entries')}} for k, v in results.items()}
        checks['flag_false_in_source_at_end'] = (root / 'src/isolation/site_policy.py').read_text('utf-8') == sp_text
        # ---- export the workspace (images, evidence, candidates) and build the local review page
        wcontrol({'type': 'quit'})
        p['worker'].stdin.close()
        p['worker'].wait(timeout=20)
        p['worker'] = None
        launch.call('cp', anchor + ':/evidence/ws', str(evidence / 'workspace'), timeout=120)
        review = evidence / 'review'
        review.mkdir()
        rows = []
        for kind, v in results.items():
            ev = v['job']['evidence']
            png = (evidence / 'workspace' / ev['artifact_ref']) if ev else None
            data = png.read_bytes() if png and png.exists() else b''
            ok_png = bool(data) and hashlib.sha256(data).hexdigest() == ev['digest'] and png_size(data) is not None
            checks[f'K{kind[0]}_png_exported_and_matches_the_stored_digest'] = ok_png
            if ok_png:
                (review / f'{kind.lower()}.png').write_bytes(data)
            candidate = next((b for b in v['baselines'] if b['candidate_id'] == 'capture-' + v['job']['job_id']), {})
            rows.append((kind, v, ev, png_size(data), candidate))
        css = 'body{font:15px/1.5 system-ui,sans-serif;margin:24px;max-width:1500px}img{max-width:100%;border:1px solid #888}table{border-collapse:collapse;margin:8px 0}td,th{border:1px solid #bbb;padding:3px 8px;text-align:left}code{background:#eee;padding:0 3px}.warn{background:#fff3cd;border:1px solid #d9b95c;padding:8px 12px}'
        parts = ['<!doctype html><html lang="ja"><meta charset="utf-8"><title>S3-1 TTN /about 初回撮影（Baseline候補・未承認）</title><style>' + css + '</style>',
                 '<h1>S3-1 初回撮影：Tokyo Trouble Navi <code>/about</code></h1>',
                 '<p class="warn"><b>Baseline候補（未承認）</b>です。承認は行っていません。撮影条件は未認証（PROFILE_UNATTESTED）で、品質判定はUNKNOWN。画像が正常に描画されているかはUSERが目視で判断してください。LOCAL-ISOLATION は NOT VERIFIED のままです。</p>',
                 f'<p>対象URL: <code>{html.escape(target_url)}</code>（HTTPS/443、許可ホスト1つ）</p>']
        for kind, v, ev, size, cand in rows:
            summary = report['captures'][kind]
            parts.append(f'<h2>{kind}</h2><table>' + ''.join(f'<tr><th>{html.escape(a)}</th><td>{html.escape(str(b))}</td></tr>' for a, b in (
                ('job_id', v['job']['job_id']), ('実行結果', v['job']['execution']), ('PNG sha256', ev['digest'] if ev else None), ('PNG サイズ(px)', size),
                ('プロファイル', json.dumps(v['job']['profile']['attributes'], ensure_ascii=False)), ('fingerprint', v['job']['fingerprint']),
                ('Chromium', ((v['capture_meta'] or [{}])[0].get('sandbox') or {}).get('browser_version')),
                ('Baseline候補', cand.get('candidate_id')), ('承認状態', cand.get('approval_state')), ('品質', v['job']['quality']),
                ('接続監査(CONNECT)', json.dumps(summary['network_audit_summary'], ensure_ascii=False)), ('ブラウザ監査', json.dumps(summary['browser_audit_summary'], ensure_ascii=False)),
                ('撮影再現(2回撮影の一致)', (v['capture_info'] or {}).get('repeat_identical')))) + '</table>')
            parts.append(f'<p><img src="{kind.lower()}.png" alt="{kind} screenshot"></p>' if (review / f'{kind.lower()}.png').exists() else '<p>画像なし</p>')
        (review / 'index.html').write_text(''.join(parts), encoding='utf-8')
    except GateFailed as exc:
        report['gate_failed'] = str(exc)
    except Exception as exc:
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)[:400] if isinstance(exc, (AssertionError, IsolationLeak)) else 'Inspect bounded logs'
        report['isolation_leak'] = isinstance(exc, IsolationLeak)
    finally:
        if state['window'] is not None:  # Never leave a window open, whatever failed: the host first, then the reaper.
            for how in ('HOST', 'REAPER'):
                try:
                    if how == 'REAPER' and p['reaper'] is not None:
                        send_control(p['reaper'], {'type': 'close'})
                        report['windows'][state['window']]['finally_reaper'] = end_reaper(20)
                    elif how == 'HOST':
                        flushed = policy_call('egress_close', device=device)
                        report['windows'][state['window']]['finally_host_flushed'] = flushed['grants_flushed']
                except Exception:
                    report['windows'][state['window']]['finally_' + how.lower() + '_failed'] = True
            mark_closed(state['window'], 'FINALLY')
        for key, command in (('worker', {'type': 'quit'}), ('broker', {'type': 'quit'}), ('reaper', {'type': 'cancel'})):
            if p[key] is not None:
                try:
                    send_control(p[key], command)
                    read_control(p[key], 10)
                except Exception:
                    pass
        if anchor and not (evidence / 'workspace').exists():  # Failure path: still keep whatever was written.
            try:
                launch.call('cp', anchor + ':/evidence/ws', str(evidence / 'workspace'), timeout=120)
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
        report['own_network_removed'] = False
        try:
            own = prefix + '-network'
            net_info = json.loads(launch.call('network', 'inspect', own))[0]
            if (launch.resources.get(own, {}).get('id') == net_info['Id'] and net_info['Internal'] is False
                    and (net_info.get('Labels') or {}).get('siteproof.task') == TASK and not net_info.get('Containers')):
                launch.call('network', 'rm', net_info['Id'])
                report['own_network_removed'] = True
        except Exception:
            pass
        later = inventory()
        launch.save('docker-inventory-after.json', later)
        new_volumes = sorted(set(later['volumes']) - set(before['volumes']))
        report['new_volumes_retained'] = new_volumes
        report['existing_docker_resources_unchanged'] = (later['networks'] == before['networks'] and later['images'] == before['images'] and later['containers'] == before['containers']
                                                         and set(before['volumes']) <= set(later['volumes']) and all(v.startswith(prefix) for v in new_volumes))
        report['no_run_container_or_network_left'] = not any(prefix in line for key in ('networks', 'containers') for line in later[key])
        report['checks'] = checks
        report['passed'] = (bool(checks) and all(checks.values()) and 'error' not in report and 'gate_failed' not in report and report.get('all_owned_stopped') is True
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
