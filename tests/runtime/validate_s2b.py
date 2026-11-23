"""S2-B: bounded real-site network-isolation measurement for ONE registered, user-owned host.

Derived from validate_s2a (unchanged): same dedicated labelled resources, same image, same measured preflight idea.
Differences, all stated in the evidence:
  * the run network is a NEW labelled bridge network (not --internal), because the trusted Connector needs an egress
    path; the outer Docker boundary is therefore NOT claimed. Isolation rests on OS rules inside this run's own
    network namespace (netpolicy_s2b), measured here, and never on the application allowlist alone.
  * Step A is measured with the OS egress window CLOSED; Step B/C run with it OPEN; Step D closes it and re-measures.
  * No screenshot, no baseline, no image comparison, no crawl, no login, no credential, no AWS.
Only the labelled resources this run creates are stopped/removed (never prune). The repository default
(`REAL_SITE_ACCESS_ENABLED = False`) is never edited; the worker flips it in-process for this run only.
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

from src.runtime.docker_launcher import DockerLauncher, LABEL, TASK, read_control, send_control


FORBIDDEN = ('tcp', 'dns', 'udp', 'metadata', 'lan', 'host_model', 'ipv6')
M5_IMAGE = 'sha256:9c88112b42070369876fdb24476af283b3908a3fdc630b66fedacf4f20c4d2c8'
CONNECTED = ('ERR_CERT', 'ERR_SSL', 'ERR_BAD_SSL', 'ERR_HTTP', 'ERR_EMPTY_RESPONSE', 'ERR_RESPONSE')


class IsolationLeak(RuntimeError):
    pass


class GateFailed(RuntimeError):
    pass


class S2BLauncher(DockerLauncher):
    def create_network(self, name):
        if name in self.call('network', 'ls', '--format', '{{.Name}}').splitlines():
            raise RuntimeError('network collision')
        ident = self.call('network', 'create', '--label', LABEL, name).strip()  # Bridge, NOT --internal: egress is OS-gated.
        self.record('network', name, ident)
        return name


def tree_digest(root):
    entries = {}
    for path in sorted(Path(root).rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts:
            entries[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest(), len(entries)


def git(*args):
    return subprocess.run(['git', *args], capture_output=True, text=True).stdout


def counters(snapshot):
    """SiteProof rule comment -> [packets, bytes] over IPv4+IPv6, plus the chain policy drop counters."""
    out = {}
    for line in (snapshot['ipv4'] + snapshot['ipv6']).splitlines():
        match = re.match(r'\[(\d+):(\d+)\].*--comment (SP_\w+)', line)
        if match:
            row = out.setdefault(match[3], [0, 0])
            row[0] += int(match[1])
            row[1] += int(match[2])
        match = re.match(r':(INPUT|OUTPUT|FORWARD) (\w+) \[(\d+):(\d+)\]', line)
        if match and match[2] == 'DROP':
            out['POLICY_' + match[1] + '_DROP'] = [int(match[3]), int(match[4])]
    return out


def delta(after, before):
    return {k: after.get(k, [0, 0])[0] - before.get(k, [0, 0])[0] for k in set(after) | set(before)}


def rule_set(snapshot):
    """Rules only: iptables-save prints per-chain policy counters (`:OUTPUT DROP [p:b]`) even without -c."""
    return sorted(re.sub(r' \[\d+:\d+\]\Z', '', line) for line in snapshot['rules_plain'].splitlines())


def tx_packets(snapshot):
    for link in snapshot['links']:
        if link.get('ifname') == snapshot['default_device']:
            return (link.get('stats64') or link.get('stats'))['tx']['packets']
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--image', default=M5_IMAGE)
    parser.add_argument('--stop-after-a', action='store_true', help='Step A only (egress never opened): harness debugging')
    args = parser.parse_args()
    evidence = Path(args.evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    root = Path.cwd()
    launch = S2BLauncher(evidence, args.image, root / 'runtime/docker/seccomp-siteproof.json')
    prefix = 'siteproof-m2-s2b-' + time.strftime('%H%M%S') + '-' + uuid.uuid4().hex[:6]
    report = {'task': 'SITEPROOF-S2B-REAL-SITE-ISOLATION-01', 'passed': False, 'screenshot_taken': False, 'baseline_touched': False,
              'aws_touched': False, 'egress_window': {'opened_at': None, 'closed_at': None}}
    checks, data, counter = {}, {}, [0]
    worker_process = anchor = policy = browser = None
    probes = {}
    egress_open = False

    def name(label):
        counter[0] += 1
        return prefix + '-' + label + '-' + str(counter[0])

    def inventory():
        return {'containers': sorted(launch.call('ps', '-a', '--no-trunc', '--format', '{{.ID}}|{{.Names}}|{{.State}}').splitlines()),
                'networks': sorted(launch.call('network', 'ls', '--format', '{{.ID}}|{{.Name}}').splitlines()),
                'volumes': sorted(launch.call('volume', 'ls', '--format', '{{.Name}}').splitlines()),
                'images': sorted(launch.call('images', '--no-trunc', '--format', '{{.Repository}}:{{.Tag}}|{{.ID}}').splitlines())}

    before = inventory()
    launch.save('docker-inventory-before.json', before)

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
        launch.save('policy-' + str(counter[0]).zfill(3) + '-' + kind + '.json', result)
        counter[0] += 1
        return result

    def canary_zero(baseline, label):
        now = control({'type': 'counts'})['counts']
        d = {k: now.get(k, 0) - baseline.get(k, 0) for k in FORBIDDEN}
        launch.save(label + '-canaries.json', d)
        if any(d.values()):
            raise IsolationLeak('forbidden canary received: ' + label)
        return d

    def probe(container, uid, label, **extra):
        config = {'gateway': gateway, 'proxy_port': ready['proxy_port'], **extra}
        out, _ = launch.bounded(container, json.dumps(config).encode() + b'\n')
        result = json.loads(out)
        launch.save(label + '.json', result)
        assert result['netns'] == namespace and result['uid'] == uid
        assert result['cgroup']['memory.max'] == '805306368' and result['cgroup']['pids.max'] == '256'
        for key, value in (('CapEff:', '0000000000000000'), ('CapBnd:', '0000000000000000'), ('NoNewPrivs:', '1'), ('Seccomp:', '2')):
            assert any(line.split() == [key, value] for line in result['status']), (key, result['status'])
        return result

    def api_probe(container, uid, label):
        """tests.runtime.s2a_probe (unchanged): Docker API / socket reachability from one exact identity."""
        out, _ = launch.bounded(container, b'{}\n')
        result = json.loads(out)
        launch.save(label + '.json', result)
        assert result['netns'] == namespace and result['uid'] == uid
        return result

    def sandboxed(body):
        """Chromium's own chrome://sandbox report, same criteria as browser_process.IsolatedPlaywright."""
        return bool((re.search(r'Layer 1 Sandbox\s+Namespace', body) or re.search(r'Namespace sandbox\s+Yes', body))
                    and re.search(r'PID namespaces\s+Yes', body) and re.search(r'Network namespaces\s+Yes', body)
                    and re.search(r'Seccomp-BPF sandbox\s+Yes', body))

    def browser_run(config, label, seconds=120):
        out, err = launch.bounded(browser, json.dumps({**config, 'gateway': gateway, 'proxy_port': ready['proxy_port'],
                                                       'host': host, 'url': url, 'resources': ready['resources']}).encode() + b'\n',
                                  seconds=seconds, evidence_sink=lambda o, e, x: (
                                      (evidence / (label + '.stderr.log')).write_bytes(launch._redact_log(e)),
                                      launch.save(label + '-execution.json', x)))
        result = json.loads(out)
        launch.save(label + '.json', result)
        return result

    def untouched(result, proxied=False):
        """Every attempt failed. Direct attempts must also not fail in a way that proves a TCP/TLS exchange took place;
        proxied ones talk to our own proxy only (its refusal may look like an empty response)."""
        return all(v['reached'] is False and (proxied or not (v['error'] or '').startswith(CONNECTED)) for v in result.values())

    def browser_negative(p):
        r = p['results']
        return r.pop('proxy_port') is True and not any(r.values())

    try:
        # ------------------------------------------------------------------ Start Gate records
        head = git('rev-parse', 'HEAD').strip()
        status_lines = git('status', '--short').splitlines()
        targets = json.loads((root / 'src/noxiworks/targets.json').read_text('utf-8'))
        page = next(p for p in targets['pages'] if p['target_id'] == 'noxiworks-home')
        site = next(s for s in targets['sites'] if s['site_id'] == page['site_id'])
        host, url = re.match(r'https://([a-z0-9.-]+)/\Z', page['url'])[1], page['url']
        sp_text = (root / 'src/isolation/site_policy.py').read_text('utf-8')
        src_digest, src_files = tree_digest(root / 'src')
        rt_digest, rt_files = tree_digest(root / 'tests/runtime')
        launch.save('start-gate.json', {
            'branch': git('branch', '--show-current').strip(), 'head': head, 'uncommitted_entries': len(status_lines),
            'uncommitted_status_sha256': hashlib.sha256('\n'.join(status_lines).encode()).hexdigest(),
            'registered_target': {'target_id': page['target_id'], 'url': page['url'], 'label': page['label'],
                                  'site': {k: site.get(k) for k in ('site_id', 'name', 'origin', 'registration_domain')}},
            'ownership_record': 'registered monitoring target (src/noxiworks/targets.json) with registration_domain; '
                                'owner attestation is NOT cryptographic (OWNER_SITE_UNATTESTED) — USER designated the target for S2-B',
            'allowed_destinations': [{'hostname': host, 'port': 443}], 'wildcards': 0, 'auto_added_hosts': 0,
            'real_site_access_flag_in_source': re.search(r'^REAL_SITE_ACCESS_ENABLED = (\w+)', sp_text, re.M)[1],
            'overlay': {'src': {'sha256': src_digest, 'files': src_files}, 'tests/runtime': {'sha256': rt_digest, 'files': rt_files}}})
        checks['real_site_access_flag_false_in_source_at_start'] = re.search(r'^REAL_SITE_ACCESS_ENABLED = False$', sp_text, re.M) is not None
        checks['target_is_single_exact_registered_https_host'] = (
            page['url'] == 'https://' + host + '/' and site['origin'] == 'https://' + host and '*' not in host and not host.startswith('www.'))
        image = json.loads(launch.call('image', 'inspect', launch.image))[0]
        launch.image = image['Id']
        launch.save('run-conditions.json', {
            'docker_server': launch.call('version', '--format', '{{.Server.Version}}').strip(), 'host': platform.platform(),
            'image_id': image['Id'], 'git_head': head, 'run_prefix': prefix,
            'network': 'NEW labelled bridge network (not --internal); egress gated by OS rules in the run namespace; no published ports',
            'no_pull_build': True, 'no_privileged_no_host_network_no_docker_socket': True,
            'overlay_note': 'worktree src and tests/runtime bind-mounted read-only over the image copy; no image modified'})

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
        policy = helper('policy', 0, 'tests.runtime.netpolicy_s2b', admin=True, mounts=overlay)
        prepared = policy_call('prepare')
        gateway = prepared['default_gateway']
        launch.save('network-config.json', {'default_device': prepared['default_device'], 'default_gateway': gateway,
                                            'addresses': prepared['addresses'], 'routes': prepared['routes']})
        worker_log = (evidence / 'worker-stderr.log').open('wb')
        worker_process = subprocess.Popen(launch.cli + ['exec', '-i', '--user', '1001:1001', anchor, 'python', '-m', 'tests.runtime.s2b_worker'],
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=worker_log)
        ready = read_control(worker_process, 60)
        assert ready['type'] == 'ready' and ready['namespace'] == namespace and ready['registered_host'] == host
        launch.save('worker-ready.json', ready)
        checks['real_site_access_off_at_worker_start'] = ready['flag_at_start'] is False
        installed = policy_call('install', ui_port=18081, proxy_port=ready['proxy_port'])
        resolver_file = evidence / 'resolv.conf'
        resolver_file.write_text('nameserver 127.0.0.3\noptions timeout:1 attempts:1\n', encoding='ascii')
        mounts = [*overlay, '--mount', f'type=bind,src={resolver_file},dst=/etc/resolv.conf,readonly']
        trusted_probe = helper('probe-trusted', 1001, 'tests.runtime.s2b_probe', mounts=overlay)
        browser_probe = helper('probe-browser', 1000, 'tests.runtime.s2b_probe', mounts=mounts)
        api_trusted = helper('api-trusted', 1001, 'tests.runtime.s2a_probe', mounts=overlay)
        api_browser = helper('api-browser', 1000, 'tests.runtime.s2a_probe', mounts=mounts)
        browser = helper('chromium', 1000, 'tests.runtime.s2b_browser', mounts=mounts)

        # ------------------------------------------------------------------ Step A: egress CLOSED, no real traffic
        closed_baseline = policy_call('snapshot')
        data['closed_baseline_rules'] = rule_set(closed_baseline)
        default_state = control({'type': 'policy_default'})
        launch.save('policy-default.json', default_state)
        checks['A_real_policy_refused_while_flag_off'] = (default_state['flag'] is False and default_state['plan_enabled_flag_off'] == 'REFUSED'
                                                          and default_state['plan_disabled'] == 'REFUSED')
        started = control({'type': 'start_real'})
        launch.save('real-started.json', started)
        checks['A_allowlist_is_exactly_the_registered_host_443'] = started['hostnames'] == [host] and started['ports'] == [443]
        t1 = probe(trusted_probe, 1001, 'A-trusted-closed', skip_resolver=True)
        canary_base = control({'type': 'counts'})['counts']
        checks['A_positive_controls_hold_for_trusted_identity'] = all(t1['results'][k] for k in (
            'canary_tcp', 'canary_host_model', 'canary_metadata', 'canary_lan', 'canary_dns', 'canary_udp', 'canary_ipv6', 'docker_api_model', 'proxy_port'))
        checks['A_positive_controls_counted_by_canaries'] = all(canary_base.get(k, 0) > 0 for k in FORBIDDEN)
        checks['A_trusted_cannot_reach_gateway_hostmodel_documentation_or_other_ports'] = not any(
            t1['results'][k] for k in t1['results'] if k.startswith(('bridge_gateway', 'desktop_host', 'documentation')))
        s0 = policy_call('snapshot')
        b1 = probe(browser_probe, 1000, 'A-browser-closed')
        s1 = policy_call('snapshot')
        checks['A_browser_direct_paths_denied_proxy_reachable'] = browser_negative(b1)
        checks['A_browser_probe_dropped_and_counted_by_os'] = all(delta(counters(s1), counters(s0)).get(k, 0) > 0 for k in (
            'SP_BROWSER_TCP_DROP', 'SP_BROWSER_UDP_DROP', 'SP_BROWSER_DNS_DROP', 'SP_BROWSER_IPV6_DROP'))
        canary_zero(canary_base, 'A-browser-probe')
        n1 = browser_run({'mode': 'network'}, 'A-chromium-network')
        s2 = policy_call('snapshot')
        checks['A_chromium_direct_attempts_all_denied'] = untouched(n1['direct']) and n1['udp_attempt_completed'] is True
        checks['A_chromium_proxied_unregistered_hosts_refused'] = untouched(n1['proxied_refused'], proxied=True)
        checks['A_chromium_sandbox_verified'] = sandboxed(n1['sandbox']['body'])
        checks['A_chromium_direct_dropped_and_counted_by_os'] = all(delta(counters(s2), counters(s1)).get(k, 0) > 0 for k in (
            'SP_BROWSER_TCP_DROP', 'SP_BROWSER_UDP_DROP', 'SP_BROWSER_DNS_DROP'))
        canary_zero(canary_base, 'A-chromium')
        matrix = control({'type': 'deny_matrix', 'gateway': gateway}, 180)
        launch.save('A-deny-matrix.json', matrix)
        checks['A_deny_matrix_all_blocked_before_any_dns_or_dial'] = len(matrix['results']) >= 19 and matrix['resolver_calls'] == 0 and all(
            r['status'].startswith('HTTP/1.1 502') and r['resolutions'] == [] and r['dialed'] == [] and r['complete']
            and r['records'] and all(x[2] == 'BLOCK' for x in r['records']) for r in matrix['results'])
        for who, container, uid in (('trusted', api_trusted, 1001), ('browser', api_browser, 1000)):
            probes[who] = api_probe(container, uid, 'A-docker-api-' + who)
        t, b = probes['trusted'], probes['browser']
        checks['A_docker_api_model_reachable_trusted_not_browser'] = t['modelled']['docker_api_model_127.0.0.5:2375'] is True and b['modelled']['docker_api_model_127.0.0.5:2375'] is False
        checks['A_docker_sockets_and_gateways_unreachable_for_browser'] = (not any(b['unmodelled'].values()) and set(b['unix_sockets'].values()) == {'ABSENT'}
                                                                           and b['mounts_with_docker'] == [])
        report['step_a'] = {k: v for k, v in checks.items() if k.startswith('A_')}
        launch.save('A-gate.json', report['step_a'])
        if not all(report['step_a'].values()):
            raise GateFailed('STEP_A_FAILED: ' + ', '.join(k for k, v in report['step_a'].items() if not v))
        if args.stop_after_a:
            raise GateFailed('STOPPED_AFTER_STEP_A_BY_REQUEST: no egress window was ever opened')

        # ------------------------------------------------------------------ Step B: open the egress window, one real connection
        open_snapshot_before = policy_call('snapshot')
        opened = policy_call('egress_open')
        egress_open = True
        report['egress_window']['opened_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        c_open = counters(opened)
        tx_open = tx_packets(opened)
        head_result = control({'type': 'real_head'}, 60)['result']
        launch.save('B-real-head.json', head_result)
        if not head_result.get('status', '').startswith('HTTP/1.1 200'):
            # Keep the facts needed to explain a failed connection while the window is still open.
            policy_call('snapshot')
            launch.save('B-dns-diag.json', control({'type': 'dns_diag'}, 30)['result'])
            policy_call('snapshot')
        dec = head_result.get('destination_decision') or {}
        dials = head_result.get('dialed') or []
        real_ip = dials[0]['ip'] if dials else None
        tls = head_result.get('tls') or {}
        res0 = (head_result.get('resolutions') or [{}])[0]
        san_ok = any(n == host or (n.startswith('*.') and host.split('.', 1)[1:] == [n[2:]]) for n in tls.get('san_dns', []))
        checks['B_real_connect_established_through_connector'] = head_result.get('status', '').startswith('HTTP/1.1 200') and any(
            r[0] == host and r[2] == 'ALLOW' for r in head_result.get('records', []))
        checks['B_one_resolution_all_answers_validated_public'] = (len(head_result.get('resolutions') or []) == 1 and res0.get('status') == 'COMPLETE'
                                                                  and res0.get('a_complete') is True and res0.get('aaaa_complete') is True
                                                                  and dec.get('allowed') is True and set(dec.get('addresses', ())) == set(res0.get('addresses', ())))
        checks['B_dialed_exactly_the_pinned_first_address_and_peer_matches'] = (len(dials) == 1 and dec.get('allowed') is True
                                                                               and dials[0]['ip'] == dec['addresses'][0] and dials[0]['port'] == 443
                                                                               and dials[0].get('peer') == [dials[0]['ip'], 443])
        checks['B_tls_verified_with_default_chain_and_hostname_checks'] = (tls.get('result') == 'OK' and (head_result.get('tls_verify') or {}).get('check_hostname') is True
                                                                          and (head_result.get('tls_verify') or {}).get('verify_mode') == 2 and san_ok)
        checks['B_minimal_https_response_obtained'] = bool(re.match(r'HTTP/1\.[01] \d{3}', head_result.get('http_status', '')))
        if head_result.get('redirect'):
            checks['B_redirect_not_followed_and_off_list_target_refused'] = (head_result['redirect']['followed'] is False and (
                head_result['redirect']['same_host'] or (head_result['redirect']['connect_result']['status'].startswith('HTTP/1.1 502')
                                                         and head_result['redirect']['connect_result']['resolutions'] == []
                                                         and head_result['redirect']['connect_result']['dialed'] == [])))
        report['step_b'] = {k: v for k, v in checks.items() if k.startswith('B_')}
        if not (checks['B_real_connect_established_through_connector'] and real_ip):
            raise GateFailed('STEP_B_NO_ALLOWED_CONNECTION: Step C not run; the egress window is closed in the cleanup path')

        # ------------------------------------------------------------------ Step C: isolation with egress OPEN
        s3 = policy_call('snapshot')
        b2 = probe(browser_probe, 1000, 'C-browser-open', real_ip=real_ip)
        s4 = policy_call('snapshot')
        checks['C_browser_direct_paths_denied_proxy_reachable_open'] = browser_negative(b2)
        checks['C_browser_direct_to_allowed_ip_other_ports_denied'] = (b2['results'].get('allowed_ip_port_80') is False and b2['results'].get('allowed_ip_port_8443') is False)
        checks['C_browser_probe_dropped_and_counted_by_os_open'] = all(delta(counters(s4), counters(s3)).get(k, 0) > 0 for k in (
            'SP_BROWSER_TCP_DROP', 'SP_BROWSER_UDP_DROP', 'SP_BROWSER_DNS_DROP', 'SP_BROWSER_IPV6_DROP'))
        checks['C_browser_cannot_use_embedded_resolver_or_documentation_dns'] = not any(b2['results'][k] for k in (
            'embedded_resolver_tcp', 'embedded_resolver_udp', 'documentation_udp_53'))
        t2 = probe(trusted_probe, 1001, 'C-trusted-open', real_ip=real_ip, skip_resolver=True)
        s5 = policy_call('snapshot')
        checks['C_trusted_cannot_reach_gateway_hostmodel_documentation_or_non443_open'] = not any(
            t2['results'][k] for k in t2['results'] if k.startswith(('bridge_gateway', 'desktop_host', 'documentation', 'allowed_ip')))
        d5 = delta(counters(s5), counters(s4))
        checks['C_trusted_nonpublic_and_other_port_drops_counted_by_os'] = d5.get('SP_TRUSTED_NONPUBLIC_DROP', 0) > 0 and d5.get('SP_TRUSTED_OTHER_DROP', 0) > 0
        checks['C_trusted_loopback_canaries_still_reachable'] = all(t2['results'][k] for k in ('canary_tcp', 'canary_lan', 'canary_metadata', 'canary_ipv6', 'proxy_port'))
        canary_base2 = control({'type': 'counts'})['counts']  # Trusted probes legitimately incremented the canaries: new baseline.
        n2 = browser_run({'mode': 'network', 'real_ip': real_ip}, 'C-chromium-network')
        s6 = policy_call('snapshot')
        checks['C_chromium_direct_attempts_all_denied_open_incl_allowed_ip_and_name'] = untouched(n2['direct']) and n2['udp_attempt_completed'] is True
        checks['C_chromium_proxied_refused_open_incl_subdomains_other_ports_plain_http'] = untouched(n2['proxied_refused'], proxied=True)
        canary_zero(canary_base2, 'C-chromium')
        matrix2 = control({'type': 'deny_matrix', 'gateway': gateway}, 180)
        launch.save('C-deny-matrix-open.json', matrix2)
        extra_resolutions = matrix2['resolver_calls'] - 1  # one resolution belongs to the Step B connection
        checks['C_deny_matrix_open_no_dns_no_dial_for_any_unregistered_destination'] = (len(matrix2['results']) >= 19 and extra_resolutions == 0 and all(
            r['status'].startswith('HTTP/1.1 502') and r['resolutions'] == [] and r['dialed'] == [] and r['complete']
            and r['records'] and all(x[2] == 'BLOCK' for x in r['records']) for r in matrix2['results']))
        mark = control({'type': 'mark'})
        nav = browser_run({'mode': 'navigate'}, 'C-chromium-navigate', seconds=150)
        window = control({'type': 'window', 'mark': mark['mark'], 'resolutions': mark['resolutions'], 'dials': mark['dials']})
        launch.save('C-navigate-connect-audit.json', window)
        entries = window['window']['entries']
        audit = nav.get('request_audit') or {}
        resolved = {a for r in window['resolutions'] for a in r.get('addresses', [])}
        checks['C_navigation_completed_without_screenshot'] = isinstance(nav.get('http_status'), int) and nav.get('screenshot_taken') is False and nav.get('cleanup') is True
        checks['C_connect_audit_complete_and_allows_only_the_registered_host'] = (window['window']['complete'] and window['window']['allowed'] >= 1
                                                                                 and all(e['host'] == host for e in entries if e['decision'] == 'ALLOW'))
        checks['C_every_dial_is_a_validated_answer_with_matching_peer'] = bool(window['dialed']) and all(
            d['ip'] in resolved and d.get('peer') == [d['ip'], 443] for d in window['dialed'])
        checks['C_navigation_resolved_only_the_registered_host'] = bool(window['resolutions']) and all(r['host'] == host for r in window['resolutions'])
        checks['C_browser_request_audit_available'] = audit.get('source') == 'BROWSER_SELF_REPORT' and audit.get('monitor') == 'ATTACHED' and audit.get('finalized') is True
        checks['C_chromium_sandbox_verified_for_navigation'] = sandboxed(nav['sandbox']['body'])
        s7 = policy_call('snapshot')
        dc = delta(counters(s7), c_open)
        accepted = sum(v for k, v in dc.items() if k in ('SP_DNS_FORWARDER_ACCEPT', 'SP_TRUSTED_HTTPS_ACCEPT'))
        tx_delta = tx_packets(s7) - tx_open
        launch.save('C-egress-accounting.json', {'tx_packets_delta_on_bridge_interface': tx_delta, 'packets_accepted_by_egress_rules': accepted,
                                                 'rule_deltas': dc, 'conntrack': s7['conntrack']})
        checks['C_bridge_interface_tx_fully_accounted_by_connector_and_dns_rules'] = tx_delta <= accepted + 8
        checks['C_browser_identity_never_accepted_on_bridge_interface'] = not any(k.startswith('SP_BROWSER') and 'ACCEPT' in k for k in dc)
        for who, container, uid in (('trusted', api_trusted, 1001), ('browser', api_browser, 1000)):
            probes[who + '-open'] = api_probe(container, uid, 'C-docker-api-' + who)
        checks['C_docker_gateways_unreachable_for_browser_open'] = not any(probes['browser-open']['unmodelled'].values())
        canary_zero(canary_base2, 'C-final')
        report['step_c'] = {k: v for k, v in checks.items() if k.startswith('C_')}

        # ------------------------------------------------------------------ Step D: close the window and re-measure
        closed = policy_call('egress_close')
        egress_open = False
        report['egress_window']['closed_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        checks['D_rules_identical_to_closed_baseline_after_close'] = rule_set(closed) == data['closed_baseline_rules']
        after_head = control({'type': 'real_head'}, 60)['result']
        launch.save('D-real-head-after-close.json', after_head)
        checks['D_connector_cannot_reach_the_site_after_close'] = (not after_head['status'].startswith('HTTP/1.1 200') and after_head.get('tls') is None
                                                                  and not any(r[2] == 'ALLOW' for r in after_head['records']))
        b3 = probe(browser_probe, 1000, 'D-browser-closed', real_ip=real_ip)
        checks['D_browser_direct_paths_denied_after_close'] = browser_negative(b3)
        t3 = probe(trusted_probe, 1001, 'D-trusted-closed', real_ip=real_ip, skip_resolver=True)
        checks['D_trusted_cannot_leave_loopback_after_close'] = not any(
            t3['results'][k] for k in t3['results'] if k.startswith(('bridge_gateway', 'desktop_host', 'documentation', 'allowed_ip')))
        final = policy_call('snapshot')
        launch.save('D-final-rules.json', {'rules_plain': final['rules_plain'], 'counters': counters(final)})
        stopped = control({'type': 'stop_real'})
        launch.save('D-real-stopped.json', stopped)
        checks['D_in_process_flag_back_to_false_and_real_policy_refused'] = stopped['flag_after_stop'] is False and stopped['real_policy_refused_after_stop'] is True and stopped['stopped'] is True
        closed_msg = control({'type': 'quit'})
        assert closed_msg['type'] == 'closed' and closed_msg['stopped'] is True and closed_msg['flag_after_stop'] is False, closed_msg
        worker_process.stdin.close()
        worker_process.wait(timeout=15)
        assert worker_process.returncode == 0
        worker_process = None
        sp_after = (root / 'src/isolation/site_policy.py').read_text('utf-8')
        checks['D_repository_default_still_false'] = re.search(r'^REAL_SITE_ACCESS_ENABLED = False$', sp_after, re.M) is not None and sp_after == sp_text
        report['step_d'] = {k: v for k, v in checks.items() if k.startswith('D_')}
    except GateFailed as exc:
        report['gate_failed'] = str(exc)
        report['checks_at_stop'] = dict(checks)
    except Exception as exc:
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)[:400] if isinstance(exc, (AssertionError, IsolationLeak)) else 'Inspect bounded logs'
        report['isolation_leak'] = isinstance(exc, IsolationLeak)
        report['checks_at_stop'] = dict(checks)
    finally:
        if egress_open:  # Never leave the window open, whatever failed.
            try:
                policy_call('egress_close')
                egress_open = False
                report['egress_window']['closed_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
                report['egress_window']['closed_by'] = 'FINALLY'
            except Exception:
                report['egress_window']['close_unconfirmed'] = True
        if worker_process is not None:
            try:
                send_control(worker_process, {'type': 'quit'})
                read_control(worker_process, 10)
            except Exception:
                pass
        report['all_owned_stopped'] = launch.stop_all() if launch.resources else True
        if worker_process is not None:
            try:
                worker_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                worker_process.terminate()
                worker_process.wait(timeout=5)
        report['all_owned_removed'] = launch.cleanup() if launch.resources else True
        report['own_network_removed'] = False
        try:
            own = prefix + '-network'
            info = json.loads(launch.call('network', 'inspect', own))[0]
            if (launch.resources.get(own, {}).get('id') == info['Id'] and info['Internal'] is False
                    and (info.get('Labels') or {}).get('siteproof.task') == TASK and not info.get('Containers')):
                launch.call('network', 'rm', info['Id'])
                report['own_network_removed'] = True
        except Exception:
            pass
        later = inventory()
        launch.save('docker-inventory-after.json', later)
        owned = set(launch.resources)
        report['other_containers_unchanged'] = later['containers'] == before['containers']
        report['existing_docker_resources_unchanged'] = (later['networks'] == before['networks'] and later['volumes'] == before['volumes']
                                                         and later['images'] == before['images'] and later['containers'] == before['containers'])
        report['no_run_network_or_container_left'] = not any(prefix in line for key in ('networks', 'containers') for line in later[key])
        report['checks'] = checks
        report['passed'] = (bool(checks) and all(checks.values()) and report.get('all_owned_stopped') is True and report.get('all_owned_removed') is True
                            and report.get('own_network_removed') is True and report['existing_docker_resources_unchanged']
                            and 'gate_failed' not in report and 'error' not in report and not report['egress_window'].get('close_unconfirmed'))
        launch.save('validation-result.json', report)
        manifest = {p.relative_to(evidence).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in sorted(evidence.rglob('*')) if p.is_file() and p.name != 'export-sha256.json'}
        (evidence / 'export-sha256.json').write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding='utf8')
        report['sha256_manifest'] = {'files': len(manifest), 'mismatches': sum(
            hashlib.sha256((evidence / k).read_bytes()).hexdigest() != v for k, v in manifest.items())}
        print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
