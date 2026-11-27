"""S2-B-VERIFY: real-network verification of the Grant Broker for ONE user-approved host (registered `noxiworks-home`).

Windows (each is an egress window with an independent dead-man reaper, hard cap 120 s):
  Step A  (no window, OS egress closed)  everything that must hold BEFORE any external traffic; any failure stops the run.
  W1      Step B + C: real DNS by the Broker, ONE real TCP/TLS/HTTPS HEAD through the Connector, then every prohibited path.
  W2      Broker killed with a live grant (real DNS only, NO TCP): the reaper removes it by deadline, host does nothing.
  W3      grant insert failure, revoke failure (pending, new grants refused), then the host "dies": the reaper removes it on EOF.
Never: browser navigation, page body, screenshot, baseline, image comparison, AWS, a second host, a redirect follow.
The run network is a new labelled bridge (not --internal); isolation is the OS rule set in this run's namespace, not Docker.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import platform
import re
import subprocess
import time
import uuid

from src.runtime.docker_launcher import TASK, read_control, send_control
from tests.runtime.validate_s2b import S2BLauncher, counters, delta, git, rule_set, tree_digest

M5_IMAGE = 'sha256:9c88112b42070369876fdb24476af283b3908a3fdc630b66fedacf4f20c4d2c8'
FORBIDDEN = ('tcp', 'dns', 'udp', 'metadata', 'lan', 'host_model', 'ipv6')
CONNECTED = ('ERR_CERT', 'ERR_SSL', 'ERR_BAD_SSL', 'ERR_HTTP', 'ERR_EMPTY_RESPONSE', 'ERR_RESPONSE')
WINDOW_CAP = 120


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
    """Source ports of TCP/443 conntrack flows to `ip` (original direction). A flow is identified by its source port."""
    if not isinstance(snapshot['conntrack'], list):
        return None
    return {m[1] for c in snapshot['conntrack'] if ' tcp ' in c for m in [re.search(r'dst=%s sport=(\d+) dport=443' % re.escape(ip), c)] if m}


def grant_ips(snapshot):
    return {re.search(r'-d (\S+)/32', rule)[1] for rule in snapshot['grant_rules']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--image', default=M5_IMAGE)
    parser.add_argument('--stop-after-a', action='store_true', help='Step A only: no egress window with a grant is ever opened')
    args = parser.parse_args()
    evidence = Path(args.evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    root = Path.cwd()
    launch = S2BLauncher(evidence, args.image, root / 'runtime/docker/seccomp-siteproof.json')
    prefix = 'siteproof-m2-s2v-' + time.strftime('%H%M%S') + '-' + uuid.uuid4().hex[:6]
    report = {'task': 'SITEPROOF-S2B-VERIFY-01', 'passed': False, 'screenshot_taken': False, 'baseline_touched': False, 'aws_touched': False,
              'browser_navigation': False, 'windows': {}}
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
        out, _ = launch.bounded(chromium, json.dumps({**config, 'gateway': gateway, 'proxy_port': 18080, 'host': host, 'url': url,
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

    # ---- Broker and reaper processes (separate containers; the Worker has neither capability nor access) -------------------
    def start_broker(ttl, fault=False):
        p['broker'] = subprocess.Popen(launch.cli + ['start', '-a', '-i', broker], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=broker_log)
        send_control(p['broker'], {'mode': 'system', 'real_site_access': True, 'hosts': [host], 'device': device, 'ttl': ttl, 'max_grants': 1,
                                   'fault_injection': fault})
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
        reply = read_control(p['reaper'], 30)
        assert reply['type'] == 'ready'

    def end_reaper(wait=20):
        """The reaper's final message (it exits right after)."""
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
            assert bcontrol({'type': 'lease_open', 'lease': 'verify', 'hosts': [host]})['ok'] is True

    def mark_closed(label, how):
        seconds = round(time.monotonic() - state['started'], 1)
        report['windows'][label].update(closed_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), closed_by=how, duration_seconds=seconds)
        state['window'] = None
        return seconds

    def close_window_by_host(label):
        closed = bcontrol({'type': 'close'})
        flushed = policy_call('egress_close', device=device)
        reaper_msg = cancel_reaper()
        seconds = mark_closed(label, 'HOST')
        return closed, flushed, reaper_msg, seconds

    def client_resolve(label):
        return probe(trusted, 1001, label, {'mode': 'resolve', 'lease': 'verify', 'host': host})

    broker = reaper = anchor = policy = chromium = trusted = browser = None
    broker_log = reaper_log = None
    try:
        # ------------------------------------------------------------------ Start Gate records
        head = git('rev-parse', 'HEAD').strip()
        sp_text = (root / 'src/isolation/site_policy.py').read_text('utf-8')
        targets = json.loads((root / 'src/noxiworks/targets.json').read_text('utf-8'))
        page = next(x for x in targets['pages'] if x['target_id'] == 'noxiworks-home')
        host = re.match(r'https://([a-z0-9.-]+)/\Z', page['url'])[1]
        url = page['url']
        src_digest, src_files = tree_digest(root / 'src')
        rt_digest, rt_files = tree_digest(root / 'tests/runtime')
        launch.save('start-gate.json', {
            'branch': git('branch', '--show-current').strip(), 'head': head, 'uncommitted_entries': len(git('status', '--short', '-uall').splitlines()),
            'approved_target': {'host': host, 'port': 443, 'url': url, 'approved_by_user': '2026-11-18'},
            'allowed_destinations': [{'hostname': host, 'port': 443}], 'wildcards': 0, 'auto_added_hosts': 0,
            'flag_in_source': re.search(r'^REAL_SITE_ACCESS_ENABLED = (\w+)', sp_text, re.M)[1],
            'overlay': {'src': {'sha256': src_digest, 'files': src_files}, 'tests/runtime': {'sha256': rt_digest, 'files': rt_files}},
            'window_cap_seconds': WINDOW_CAP, 'max_grants': 1, 'single_lease': 'verify'})
        checks['flag_false_in_source_at_start'] = re.search(r'^REAL_SITE_ACCESS_ENABLED = False$', sp_text, re.M) is not None
        checks['target_is_the_single_approved_host'] = host == 'noxiworks.com' and url == 'https://noxiworks.com/'
        image = json.loads(launch.call('image', 'inspect', launch.image))[0]
        launch.image = image['Id']
        launch.save('run-conditions.json', {'docker_server': launch.call('version', '--format', '{{.Server.Version}}').strip(), 'host': platform.platform(),
                                            'image_id': image['Id'], 'git_head': head, 'run_prefix': prefix, 'no_pull_build': True,
                                            'no_privileged_no_host_network_no_docker_socket': True,
                                            'network': 'NEW labelled bridge (not --internal); egress only through Broker-issued per-IP OS grants in this namespace'})
        overlay = []
        for rel in ('src', 'tests/runtime'):
            overlay += ['--mount', f'type=bind,src={(root / rel).resolve()},dst=/opt/siteproof/{rel},readonly']
        network = launch.create_network(prefix + '-network')
        anchor = launch.create(name('worker'), [*overlay, '--network', network, '--user', '1001:1001', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges=true', '--read-only', '--pids-limit', '128', '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
            '--sysctl', 'net.ipv6.conf.all.disable_ipv6=0', '--sysctl', 'net.ipv4.ip_unprivileged_port_start=0',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m,uid=1001,gid=1001'], ['python', '-c', 'import time;time.sleep(86400)'])
        launch.call('start', anchor)
        namespace = launch.call('exec', anchor, 'readlink', '/proc/self/ns/net').strip()
        policy = helper('policy', 0, 'tests.runtime.netpolicy_hardened', admin=True, mounts=overlay)
        prepared = policy_call('prepare')
        device = prepared['devices'][0]
        default = next(r for r in prepared['routes'] if r.get('dst') == 'default')
        gateway = default['gateway']
        launch.save('network-config.json', {'device': device, 'default_gateway': gateway, 'addresses': prepared['addresses'], 'routes': prepared['routes']})
        policy_call('install', proxy_ports=[18080])
        resolver_file = evidence / 'resolv.conf'
        resolver_file.write_text('nameserver 127.0.0.3\noptions timeout:1 attempts:1\n', encoding='ascii')
        mounts = [*overlay, '--mount', f'type=bind,src={resolver_file},dst=/etc/resolv.conf,readonly']
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

        # ------------------------------------------------------------------ Step A: OS egress CLOSED, no external traffic
        for bad in ({'hosts': ['example.com'], 'max_grants': 1}, {'hosts': [host], 'max_grants': 2}, {'hosts': [host, 'www.' + host], 'max_grants': 1}):
            try:
                out, _ = launch.bounded(broker_check, json.dumps({'mode': 'system', 'real_site_access': True, 'device': device, 'ttl': 30, **bad}).encode() + b'\n', seconds=20)
                refused = b'"ready"' not in out
            except Exception:
                refused = True  # The daemon exits non-zero before it announces readiness.
            checks['A_broker_refuses_any_configuration_but_the_single_registered_host'] = checks.get('A_broker_refuses_any_configuration_but_the_single_registered_host', True) and refused
        start_broker(ttl=100)
        worker_log = (evidence / 'worker-stderr.log').open('wb')
        p['worker'] = subprocess.Popen(launch.cli + ['exec', '-i', '--user', '1001:1001', anchor, 'python', '-m', 'tests.runtime.s2v_worker'],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=worker_log)
        ready = read_control(p['worker'], 60)
        assert ready['type'] == 'ready' and ready['namespace'] == namespace and ready['registered_host'] == host
        checks['A_default_off_in_worker_and_policy_refused'] = ready['flag_at_start'] is False and wcontrol({'type': 'policy_default'})['plan_enabled_flag_off'] == 'REFUSED'
        started = wcontrol({'type': 'start_real'})
        launch.save('real-started.json', started)
        checks['A_worker_allowlist_is_exactly_the_host_443_and_resolver_is_brokered'] = (started['hostnames'] == [host] and started['ports'] == [443]
                                                                                        and started['resolver'] == 'Recording')
        closed_connect = wcontrol({'type': 'connect_raw', 'authority': host + ':443'})['result']
        launch.save('A-closed-connect.json', closed_connect)
        state0 = bcontrol({'type': 'state'})
        launch.save('A-broker-state.json', state0)
        checks['A_closed_state_connect_refused_before_any_dns_or_dial'] = (closed_connect['status'].startswith('HTTP/1.1 502') and closed_connect['dialed'] == []
                                                                           and closed_connect['resolutions'][0].get('denied') == 'EGRESS_DISABLED' and state0['resolver_log'] == [])
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
        matrixA = wcontrol({'type': 'deny_matrix', 'gateway': gateway}, 180)
        launch.save('A-deny-matrix.json', matrixA)
        stateA = bcontrol({'type': 'state'})
        # resolver_calls == 1: the single closed-state connect above, which the Broker refused (EGRESS_DISABLED) without any DNS.
        checks['A_deny_matrix_blocked_before_any_dns_or_dial'] = (len(matrixA['results']) >= 19 and matrixA['resolver_calls'] == 1 and stateA['resolver_log'] == [] and all(
            r['status'].startswith('HTTP/1.1 502') and r['resolutions'] == [] and r['dialed'] == [] and r['complete'] and r['records'] and all(x[2] == 'BLOCK' for x in r['records'])
            for r in matrixA['results']))
        apiA = {w: api_probe(c, u, 'A-docker-api-' + w) for w, c, u in (('trusted', api_trusted, 1001), ('browser', api_browser, 1000))}
        checks['A_docker_api_model_denied_for_browser_and_sockets_absent'] = (apiA['trusted']['modelled']['docker_api_model_127.0.0.5:2375'] is True
                                                                              and apiA['browser']['modelled']['docker_api_model_127.0.0.5:2375'] is False
                                                                              and not any(apiA['browser']['unmodelled'].values()) and set(apiA['browser']['unix_sockets'].values()) == {'ABSENT'})
        canary_zero(canary_A, 'A')
        # Window stop procedures, with NO grant and NO enabled Broker: host close, then the reaper's EOF path.
        open_window('A-dry-host', 30, enable=False)
        policy_call('egress_close', device=device)
        msg = cancel_reaper()
        mark_closed('A-dry-host', 'HOST')
        sd = snap()
        checks['A_window_close_by_host_restores_the_baseline'] = rule_set(sd) == baseline_rules and msg['type'] == 'cancelled'
        open_window('A-dry-eof', 30, enable=False)
        p['reaper'].stdin.close()  # The host "dies".
        msg = end_reaper(20)
        mark_closed('A-dry-eof', 'REAPER_EOF')
        sd = snap()
        checks['A_reaper_closes_the_window_when_the_host_disappears'] = msg['reason'] == 'EOF' and not msg['errors'] and rule_set(sd) == baseline_rules
        report['step_a'] = {k: v for k, v in checks.items() if k.startswith('A_')}
        launch.save('A-gate.json', report['step_a'])
        if not all(report['step_a'].values()):
            raise GateFailed('STEP_A_FAILED: ' + ', '.join(k for k, v in report['step_a'].items() if not v))
        if args.stop_after_a:
            raise GateFailed('STOPPED_AFTER_STEP_A_BY_REQUEST: no external traffic was ever possible')

        # ------------------------------------------------------------------ W1: Step B + C
        open_window('W1', 110)
        sW0 = snap()
        c_open = counters(sW0)
        tx_open = tx_packets(sW0, device)
        head_result = wcontrol({'type': 'real_head'}, 90)['result']
        launch.save('B-real-head.json', head_result)
        stateB = bcontrol({'type': 'state'})
        launch.save('B-broker-state.json', stateB)
        sB = snap()
        dec = head_result.get('destination_decision') or {}
        dials = head_result.get('dialed') or []
        tls = head_result.get('tls') or {}
        real_ip = dials[0]['ip'] if dials else None
        log0 = (stateB['resolver_log'] or [{}])[0]
        san_ok = any(n == host or (n.startswith('*.') and host.split('.', 1)[1:] == [n[2:]]) for n in tls.get('san_dns', []))
        granted = [e for e in stateB['state']['events'] if e['event'] == 'GRANTED']
        checks['B_connector_established_the_tunnel_to_the_approved_host'] = head_result.get('status', '').startswith('HTTP/1.1 200') and any(r[0] == host and r[2] == 'ALLOW' for r in head_result.get('records', []))
        checks['B_broker_resolved_once_with_complete_answers_all_public'] = (len(stateB['resolver_log']) == 1 and log0.get('status') == 'COMPLETE' and log0.get('a_complete') is True and log0.get('aaaa_complete') is True
                                                                            and bool(log0.get('addresses')) and all(ipaddress.ip_address(a).is_global for a in log0['addresses']))
        checks['B_whole_answer_set_validated_by_connector_and_broker_alike'] = dec.get('allowed') is True and set(dec.get('addresses', ())) == set(log0.get('addresses', ())) and (head_result['resolutions'][0].get('addresses') == log0.get('addresses'))
        checks['B_dial_is_the_pinned_first_ipv4_and_peer_matches'] = (len(dials) == 1 and dials[0]['ip'] == dec['addresses'][0] and dials[0]['port'] == 443 and dials[0].get('peer') == [dials[0]['ip'], 443]
                                                                      and ipaddress.ip_address(dials[0]['ip']).version == 4)
        checks['B_exactly_one_os_grant_for_exactly_that_ip_443'] = (len(granted) == 1 and granted[0]['ip'] == real_ip and grant_ips(sB) == {real_ip} and len(sB['grant_rules']) == 1 and all(
            x in sB['grant_rules'][0] for x in ('--dport 443', '--ctstate NEW', '--uid-owner 1001', '-o ' + device, 'SP_GRANT')))
        checks['B_tls_verified_with_default_chain_and_hostname_checks'] = (tls.get('result') == 'OK' and (head_result.get('tls_verify') or {}).get('check_hostname') is True
                                                                          and (head_result.get('tls_verify') or {}).get('verify_mode') == 2 and san_ok)
        checks['B_https_head_response_obtained'] = bool(re.match(r'HTTP/1\.[01] \d{3}', head_result.get('http_status', '')))
        if head_result.get('redirect'):
            r = head_result['redirect']
            checks['B_redirect_not_followed_and_off_list_target_refused'] = r['followed'] is False and (r['same_host'] or (
                r['connect_result']['status'].startswith('HTTP/1.1 502') and r['connect_result']['resolutions'] == [] and r['connect_result']['dialed'] == []))
        else:
            report['redirect_observed'] = False
        siblings = [a for a in log0.get('addresses', []) if ipaddress.ip_address(a).version == 4 and a != real_ip]
        sibling = siblings[0] if siblings else None
        report['sibling_ipv4_available'] = sibling is not None
        # --- Step C: prohibited paths with the window open and the grant active
        t_targets2 = t_targets + [['granted_port80', real_ip, 80], ['granted_port8443', real_ip, 8443]] + ([['other_answer_443', sibling, 443]] if sibling else [])
        sC0 = snap()
        c_t = probe(trusted, 1001, 'C-trusted-tcp', {'mode': 'connect', 'targets': [t for t in t_targets2 if t[0] != 'resolver_tcp'] + [['resolver_tcp', '127.0.0.11', 53]]})
        sC1 = snap()
        dC = delta(counters(sC1), counters(sC0))
        deny_keys = ['gateway443', 'host_model443', 'host_model2375', 'documentation443', 'granted_port80', 'granted_port8443', 'resolver_tcp'] + (['other_answer_443'] if sibling else [])
        checks['C_trusted_cannot_reach_other_ips_other_ports_internal_or_dns'] = not reached(c_t, *deny_keys)
        checks['C_trusted_refusals_counted_by_os_rules'] = dC.get('SP_TRUSTED_OTHER_DROP', 0) >= (3 if sibling else 2) and dC.get('SP_TRUSTED_NONPUBLIC_DROP', 0) >= 3 and dC.get('SP_WORKER_DNS_DROP', 0) >= 1
        checks['C_trusted_positive_controls_still_hold'] = all(c_t[k]['reached'] for k in ('broker', 'canary_tcp', 'canary_lan', 'canary_metadata', 'canary_host_model', 'docker_api_model', 'proxy'))
        canary_C = wcontrol({'type': 'counts'})['counts']
        b_t2 = probe(browser, 1000, 'C-browser-tcp', {'mode': 'connect', 'targets': t_targets2 + [['granted_port443', real_ip, 443]]})
        b_u2 = probe(browser, 1000, 'C-browser-udp', {'mode': 'udp', 'targets': u_targets})
        sC2 = snap()
        checks['C_browser_reaches_only_the_owned_proxy_even_to_the_granted_ip_443'] = reached(b_t2) == ['proxy'] and not reached(b_u2)
        checks['C_browser_cannot_reach_the_broker_or_the_resolver'] = not reached(b_t2, 'broker', 'resolver_tcp') and not reached(b_u2, 'resolver_udp')
        checks['C_browser_drops_counted_by_os'] = all(delta(counters(sC2), counters(sC1)).get(k, 0) > 0 for k in ('SP_BROWSER_TCP_DROP', 'SP_BROWSER_UDP_DROP', 'SP_BROWSER_DNS_DROP'))
        netC = browser_run({'mode': 'network', 'real_ip': real_ip}, 'C-chromium-network')
        sC3 = snap()
        checks['C_chromium_direct_attempts_denied_incl_granted_ip_and_name'] = (untouched(netC['direct']) and 'allowed_host_ip_direct_https' in netC['direct'] and netC['udp_attempt_completed'] is True)
        checks['C_chromium_proxied_refusals_hold_incl_subdomains_ports_and_literals'] = untouched(netC['proxied_refused'], proxied=True)
        checks['C_chromium_sandbox_verified'] = sandboxed(netC['sandbox']['body'])
        checks['C_chromium_drops_counted_by_os'] = all(delta(counters(sC3), counters(sC2)).get(k, 0) > 0 for k in ('SP_BROWSER_TCP_DROP', 'SP_BROWSER_UDP_DROP', 'SP_BROWSER_DNS_DROP', 'SP_BROWSER_IPV6_DROP'))
        resolutions_before = len(bcontrol({'type': 'state'})['resolver_log'])
        matrixC = wcontrol({'type': 'deny_matrix', 'gateway': gateway}, 180)
        launch.save('C-deny-matrix-open.json', matrixC)
        stateC = bcontrol({'type': 'state'})
        checks['C_unregistered_hosts_refused_without_dns_or_dial'] = (len(matrixC['results']) >= 19 and len(stateC['resolver_log']) == resolutions_before and all(
            r['status'].startswith('HTTP/1.1 502') and r['resolutions'] == [] and r['dialed'] == [] and r['complete'] and r['records'] and all(x[2] == 'BLOCK' for x in r['records'])
            for r in matrixC['results']))
        again = client_resolve('C-re-resolution')
        stateD = bcontrol({'type': 'state'})
        launch.save('C-broker-state-after-re-resolution.json', stateD)
        same = again['status'] == 'COMPLETE' and again['addresses'][:1] == [real_ip]
        capped = again['status'] == 'ERROR' and again['denials'] and again['denials'][0]['reason'] == 'GRANT_LIMIT'
        checks['C_re_resolution_is_revalidated_and_never_adds_a_second_address'] = (same or capped) and stateD['state']['active_addresses'] == [real_ip] and len(grant_ips(snap())) == 1
        report['re_resolution_outcome'] = 'SAME_IP_REFRESHED' if same else ('DIFFERENT_IP_REFUSED_GRANT_LIMIT' if capped else 'UNEXPECTED')
        apiC = {w: api_probe(c, u, 'C-docker-api-' + w) for w, c, u in (('trusted', api_trusted, 1001), ('browser', api_browser, 1000))}
        checks['C_docker_api_model_and_gateways_denied_for_browser'] = (apiC['browser']['modelled']['docker_api_model_127.0.0.5:2375'] is False and not any(apiC['browser']['unmodelled'].values())
                                                                        and set(apiC['browser']['unix_sockets'].values()) == {'ABSENT'})
        canary_zero(canary_C, 'C')
        sE = snap()
        dE = delta(counters(sE), c_open)
        accepted = sum(v for k, v in dE.items() if k in ('SP_GRANT', 'SP_TRUSTED_ESTABLISHED_ACCEPT'))
        tx_delta = tx_packets(sE, device) - tx_open
        conntrack_E = sE['conntrack'] if isinstance(sE['conntrack'], list) else []
        checks['C_conntrack_readable'] = isinstance(sE['conntrack'], list)
        external = [c for c in conntrack_E if isinstance(c, str) and ' dst=127.' not in c and 'dst=169.254.169.254' not in c and 'dst=10.231.77.5' not in c]
        flows = {re.search(r'dst=(\S+) sport=\d+ dport=(\d+)', c).groups() for c in external if 'tcp' in c.split()[:3] or ' tcp ' in c}
        launch.save('C-egress-accounting.json', {'tx_packets_delta_on_interface': tx_delta, 'packets_accepted_by_grant_and_established_rules': accepted,
                                                 'rule_deltas': dE, 'external_conntrack_flows': sorted(flows), 'conntrack_non_loopback': external})
        checks['C_interface_tx_fully_accounted_by_the_single_grant'] = tx_delta <= accepted + 8
        checks['C_only_flow_to_the_outside_is_the_granted_ip_443'] = flows == {(real_ip, '443')}
        w1_flows = flows_to(sE, real_ip) or set()
        checks['C_exactly_one_tcp_flow_to_the_site_in_w1'] = len(w1_flows) == 1
        closed, flushed, reaper_msg, seconds = close_window_by_host('W1')
        launch.save('W1-close.json', {'broker': closed, 'policy_flush': {k: v for k, v in flushed.items() if k in ('grants_flushed', 'grant_rules')}, 'reaper': reaper_msg})
        checks['W1_normal_close_leaves_no_grant_and_restores_the_baseline'] = (closed['clean'] is True and closed['grant_rules'] == [] and flushed['grants_flushed'] == 0
                                                                              and rule_set(flushed) == baseline_rules and reaper_msg['type'] == 'cancelled')
        checks['W1_window_within_the_120_second_cap'] = seconds <= WINDOW_CAP
        after = wcontrol({'type': 'connect_raw', 'authority': host + ':443'})['result']
        launch.save('W1-closed-connect.json', after)
        t_after = probe(trusted, 1001, 'W1-trusted-after-close', {'mode': 'connect', 'targets': [['granted_ip_443', real_ip, 443], ['granted_ip_80', real_ip, 80], ['gateway443', gateway, 443]]})
        b_after = probe(browser, 1000, 'W1-browser-after-close', {'mode': 'connect', 'targets': [['granted_ip_443', real_ip, 443], ['proxy', '127.0.0.1', 18080]]})
        checks['W1_after_close_connector_trusted_and_browser_cannot_reach_the_site'] = (
            after['status'].startswith('HTTP/1.1 502') and after['dialed'] == [] and after['resolutions'][0].get('denied') == 'EGRESS_DISABLED'
            and not reached(t_after) and reached(b_after) == ['proxy'])
        stopped = wcontrol({'type': 'stop_real'})
        launch.save('W1-real-stopped.json', stopped)
        checks['W1_in_process_flag_back_to_false_and_real_policy_refused'] = stopped['flag_after_stop'] is False and stopped['real_policy_refused_after_stop'] is True and stopped['stopped'] is True
        wcontrol({'type': 'quit'})
        p['worker'].stdin.close()
        p['worker'].wait(timeout=20)
        p['worker'] = None
        report['broker_w1_final'] = stop_broker()

        # ------------------------------------------------------------------ W2: Broker killed with a live grant (real DNS only, no TCP)
        start_broker(ttl=100)
        open_window('W2', 40)
        g = client_resolve('W2-grant')
        sW2a = snap()
        checks['W2_grant_installed_by_the_broker_before_the_kill'] = g['status'] == 'COMPLETE' and len(grant_ips(sW2a)) == 1
        launched_ip = next(iter(grant_ips(sW2a)), None)
        launch.call('kill', broker)
        p['broker'].wait(timeout=20)
        p['broker'] = None
        dead = client_resolve('W2-resolve-after-kill')
        sW2b = snap()
        checks['W2_killed_broker_issues_no_new_grant'] = dead['status'] == 'EXCEPTION' and grant_ips(sW2b) == {launched_ip}
        checks['W2_stale_grant_survives_the_broker_until_the_independent_controller_acts'] = grant_ips(sW2b) == {launched_ip} and len(sW2b['grant_rules']) == 1
        reaper_final = end_reaper(60)  # Nobody else acts: the reaper's deadline removes it.
        mark_closed('W2', 'REAPER_DEADLINE')
        launch.save('W2-reaper.json', reaper_final)
        sW2c = snap()
        checks['W2_reaper_deadline_removes_the_grant_and_the_window_without_the_host'] = (reaper_final['reason'] == 'DEADLINE' and reaper_final['flushed_grants'] == 1 and not reaper_final['errors']
                                                                                        and not sW2c['grant_rules'] and rule_set(sW2c) == baseline_rules)
        checks['W2_no_new_tcp_flow_to_the_site_beyond_the_one_w1_head'] = flows_to(sW2b, launched_ip) is not None and flows_to(sW2b, launched_ip) <= w1_flows
        report['broker_w2_exit'] = 'KILLED_WITH_SIGKILL'

        # ------------------------------------------------------------------ W3: update failures, then the host disappears
        start_broker(ttl=10, fault=True)
        open_window('W3', 110)
        bcontrol({'type': 'inject', 'fail_allow': 1})
        r1 = client_resolve('W3-allow-failure')
        s3a = snap()
        checks['W3_rule_insert_failure_returns_no_answer_and_leaves_no_rule'] = r1['status'] == 'ERROR' and r1['denials'][0]['reason'] == 'FIREWALL_UPDATE_FAILED' and not grant_ips(s3a)
        r2 = client_resolve('W3-recovery')
        s3b = snap()
        checks['W3_next_independent_attempt_recovers'] = r2['status'] == 'COMPLETE' and len(grant_ips(s3b)) == 1
        ip3 = next(iter(grant_ips(s3b)), None)
        bcontrol({'type': 'inject', 'fail_revoke': -1})
        deadline = time.monotonic() + 40
        pending = []
        while time.monotonic() < deadline and pending != [ip3]:
            time.sleep(1)
            pending = bcontrol({'type': 'state'})['state']['pending_revocations']
        r3 = client_resolve('W3-while-pending')
        s3c = snap()
        checks['W3_failed_revoke_is_reported_and_new_connections_are_refused'] = pending == [ip3] and r3['status'] == 'ERROR' and r3['denials'][0]['reason'] == 'REVOCATION_PENDING' and grant_ips(s3c) == {ip3}
        p['reaper'].stdin.close()  # The host script "dies" with a stale grant and a stuck Broker.
        reaper3 = end_reaper(20)
        mark_closed('W3', 'REAPER_EOF')
        launch.save('W3-reaper.json', reaper3)
        s3d = snap()
        checks['W3_reaper_eof_removes_the_stale_grant_and_the_window'] = reaper3['reason'] == 'EOF' and reaper3['flushed_grants'] == 1 and not reaper3['errors'] and not s3d['grant_rules'] and rule_set(s3d) == baseline_rules
        checks['W3_no_new_tcp_flow_to_the_site'] = flows_to(s3d, ip3) is not None and flows_to(s3d, ip3) <= w1_flows
        bcontrol({'type': 'inject', 'fail_revoke': 0})
        final3 = stop_broker()
        launch.save('W3-broker-final.json', final3)
        checks['W3_broker_recovers_to_clean_once_the_os_is_clean'] = bool(final3) and final3.get('clean') is True and final3.get('grant_rules') == []
        checks['no_window_exceeded_the_cap'] = all(w.get('duration_seconds', 0) <= WINDOW_CAP for w in report['windows'].values())
        checks['flag_false_in_source_at_end'] = (root / 'src/isolation/site_policy.py').read_text('utf-8') == sp_text
    except GateFailed as exc:
        report['gate_failed'] = str(exc)
    except Exception as exc:
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)[:400] if isinstance(exc, (AssertionError, IsolationLeak)) else 'Inspect bounded logs'
        report['isolation_leak'] = isinstance(exc, IsolationLeak)
    finally:
        if state['window'] is not None:  # Never leave a window open, whatever failed: the reaper first, then the host.
            for how in ('HOST', 'REAPER'):  # The reaper tolerates rules the host already removed; the host's strict delete does not.
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
        report['existing_docker_resources_unchanged'] = later == before
        report['no_run_resource_left'] = not any(prefix in line for key in ('networks', 'containers') for line in later[key])
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
