"""S2-B-HARDEN: OFFLINE measurement of per-connection OS egress grants for the trusted Worker UID. Fixture network only.

Topology (all labelled, all created and removed by this run; no pull/build, no published ports, no host network, no Docker socket):
  --internal bridge 11.22.33.0/24 (NO gateway/NAT: nothing can leave the Docker VM, and nothing here enables an external route)
    anchor   (UID 1001 Worker + the namespace owner)      11.22.33.10
    peers A/B/C: real TCP/443 listeners standing in for "public IPs that are up"  11.22.33.44 / .45 / .46
    policy helper (NET_ADMIN, short-lived calls), grant broker (NET_ADMIN, long-lived, host-controlled), Browser containers (UID 1000)
The addresses are public-range (so the production address validation accepts them) but exist only on this isolated bridge.
Peers log every accepted connection: that, not the connecting side, is the evidence that a packet really got through or not.
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
from tests.runtime.validate_s2b import counters, delta, rule_set, tree_digest, git

M5_IMAGE = 'sha256:9c88112b42070369876fdb24476af283b3908a3fdc630b66fedacf4f20c4d2c8'
FORBIDDEN = ('tcp', 'dns', 'udp', 'metadata', 'lan', 'host_model', 'ipv6')
A, B, C, GATEWAY, ANCHOR_IP = '11.22.33.44', '11.22.33.45', '11.22.33.46', '11.22.33.1', '11.22.33.10'
TTL = 15
J1_HOSTS = ['a.invalid', 'rebind.invalid', 'private.invalid', 'metadata.invalid', 'loopback.invalid', 'mixed.invalid',
            'v4mapped.invalid', 'nat64.invalid', 'dnserr.invalid', 'dnsincomplete.invalid', 'dnsempty.invalid']
J2_HOSTS = ['c.invalid']
ALL_HOSTS = sorted({*J1_HOSTS, *J2_HOSTS, 'b.invalid'})
ANSWERS = {'a.invalid': [[A]], 'b.invalid': [[B]], 'c.invalid': [[C]], 'rebind.invalid': [[A], [B], ['10.0.0.5']],
           'private.invalid': [['10.0.0.5']], 'metadata.invalid': [['169.254.169.254']], 'loopback.invalid': [['127.0.0.1']],
           'mixed.invalid': [[A, '10.0.0.5']], 'v4mapped.invalid': [['::ffff:10.0.0.5']], 'nat64.invalid': [['64:ff9b::a00:5']]}
SPECIAL = {'dnserr.invalid': ['RAISE', True, True, []], 'dnsincomplete.invalid': ['COMPLETE', True, False, [A]],
           'dnsempty.invalid': ['COMPLETE', True, True, []]}
EXPECTED_DENIAL = {'private.invalid': 'PRIVATE_ADDRESS', 'metadata.invalid': 'LINK_LOCAL_ADDRESS', 'loopback.invalid': 'LOOPBACK_ADDRESS',
                   'mixed.invalid': 'PRIVATE_ADDRESS', 'v4mapped.invalid': 'IPV4_MAPPED_IPV6', 'nat64.invalid': 'IPV6_TRANSLATION_ADDRESS',
                   'dnserr.invalid': 'DNS_ERROR', 'dnsincomplete.invalid': 'DNS_INCOMPLETE', 'dnsempty.invalid': 'DNS_NO_ADDRESS'}


class IsolationLeak(RuntimeError):
    pass


class FixtureLauncher(DockerLauncher):
    def create_network(self, name):
        if name in self.call('network', 'ls', '--format', '{{.Name}}').splitlines():
            raise RuntimeError('network collision')
        ident = self.call('network', 'create', '--internal', '--subnet', '11.22.33.0/24', '--gateway', GATEWAY, '--label', LABEL, name).strip()
        self.record('network', name, ident)
        return name


def grant_ips(snapshot):
    return {re.search(r'-d (\S+)/32', rule)[1] for rule in snapshot['grant_rules']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--image', default=M5_IMAGE)
    args = parser.parse_args()
    evidence = Path(args.evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    root = Path.cwd()
    launch = FixtureLauncher(evidence, args.image, root / 'runtime/docker/seccomp-siteproof.json')
    prefix = 'siteproof-m2-s2h-' + time.strftime('%H%M%S') + '-' + uuid.uuid4().hex[:6]
    report = {'task': 'SITEPROOF-S2B-HARDEN-OFFLINE-01', 'passed': False, 'real_site_access': False, 'external_network_enabled': False,
              'aws_touched': False, 'egress_window': {'opened_at': None, 'closed_at': None}}
    checks, counter = {}, [0]
    worker = broker_proc = anchor = policy = chromium = None
    egress_open = False

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

    def wcontrol(command, seconds=60):
        send_control(worker, command)
        return read_control(worker, seconds)

    def bcontrol(command, seconds=30):
        send_control(broker_proc, command)
        return read_control(broker_proc, seconds)

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

    def accepts(peer):
        return sum('"event":"accepted"' in line.replace(' ', '') for line in launch.call('logs', peers[peer]).splitlines())

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
        out, _ = launch.bounded(chromium, json.dumps(config).encode() + b'\n', seconds=seconds, evidence_sink=lambda o, e, x: (
            (evidence / (label + '.stderr.log')).write_bytes(launch._redact_log(e)), launch.save(label + '-execution.json', x)))
        result = json.loads(out)
        launch.save(label + '.json', result)
        return result

    def sandboxed(body):
        return bool(re.search(r'Layer 1 Sandbox\s+Namespace', body) and re.search(r'PID namespaces\s+Yes', body)
                    and re.search(r'Network namespaces\s+Yes', body) and re.search(r'Seccomp-BPF sandbox\s+Yes', body))

    def canary_zero(baseline, label):
        now = wcontrol({'type': 'counts'})['counts']
        d = {k: now.get(k, 0) - baseline.get(k, 0) for k in FORBIDDEN}
        launch.save(label + '-canaries.json', d)
        if any(d.values()):
            raise IsolationLeak('forbidden canary received: ' + label)

    def direct(targets, label):
        result = wcontrol({'type': 'direct', 'targets': targets})['results']
        launch.save(label + '.json', result)
        return result

    def reached(results, *keys):
        return [k for k in (keys or results) if results[k]['reached']]

    def wait_until(condition, seconds=20):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if condition():
                return True
            time.sleep(.5)
        return condition()

    try:
        head = git('rev-parse', 'HEAD').strip()
        sp_text = (root / 'src/isolation/site_policy.py').read_text('utf-8')
        status = git('status', '--short', '-uall').splitlines()
        src_digest, src_files = tree_digest(root / 'src')
        rt_digest, rt_files = tree_digest(root / 'tests/runtime')
        launch.save('start-gate.json', {
            'branch': git('branch', '--show-current').strip(), 'head': head, 'uncommitted_entries': len(status),
            'real_site_access_flag_in_source': re.search(r'^REAL_SITE_ACCESS_ENABLED = (\w+)', sp_text, re.M)[1],
            'preserved_s2b_policy_sha256': hashlib.sha256((root / 'tests/runtime/netpolicy_s2b.py').read_bytes()).hexdigest(),
            'overlay': {'src': {'sha256': src_digest, 'files': src_files}, 'tests/runtime': {'sha256': rt_digest, 'files': rt_files}},
            'ttl_seconds': TTL, 'destinations': 'fixture only (isolated --internal network 11.22.33.0/24)'})
        checks['flag_false_in_source_at_start'] = re.search(r'^REAL_SITE_ACCESS_ENABLED = False$', sp_text, re.M) is not None
        image = json.loads(launch.call('image', 'inspect', launch.image))[0]
        launch.image = image['Id']
        launch.save('run-conditions.json', {'docker_server': launch.call('version', '--format', '{{.Server.Version}}').strip(), 'host': platform.platform(),
                                            'image_id': image['Id'], 'git_head': head, 'run_prefix': prefix, 'no_pull_build': True,
                                            'network': '--internal bridge with fixture peers; no NAT, no gateway egress, no published ports'})
        overlay = []
        for rel in ('src', 'tests/runtime'):
            overlay += ['--mount', f'type=bind,src={(root / rel).resolve()},dst=/opt/siteproof/{rel},readonly']
        network = launch.create_network(prefix + '-network')
        info = json.loads(launch.call('network', 'inspect', network))[0]
        checks['network_is_internal_with_fixture_subnet_only'] = info['Internal'] is True and [c['Subnet'] for c in info['IPAM']['Config']] == ['11.22.33.0/24']
        anchor = launch.create(name('worker'), [*overlay, '--network', network, '--ip', ANCHOR_IP, '--user', '1001:1001', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges=true', '--read-only', '--pids-limit', '128', '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
            '--sysctl', 'net.ipv6.conf.all.disable_ipv6=0', '--sysctl', 'net.ipv4.ip_unprivileged_port_start=0',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m,uid=1001,gid=1001'], ['python', '-c', 'import time;time.sleep(86400)'])
        launch.call('start', anchor)
        namespace = launch.call('exec', anchor, 'readlink', '/proc/self/ns/net').strip()
        peers = {}
        for label, ip in (('A', A), ('B', B), ('C', C)):
            peers[label] = launch.create(name('peer-' + label.lower()), [*overlay, '--network', network, '--ip', ip, '--user', '1005:1005', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges=true', '--read-only', '--pids-limit', '32', '--memory', '128m', '--memory-swap', '128m', '--cpus', '.5',
                '--sysctl', 'net.ipv4.ip_unprivileged_port_start=0', '--env', 'PEER_NAME=' + label], ['python', '-m', 'tests.runtime.s2h_peer'])
            launch.call('start', peers[label])
        policy = helper('policy', 0, 'tests.runtime.netpolicy_hardened', admin=True, mounts=overlay)
        prepared = policy_call('prepare')
        device = prepared['devices'][0]
        checks['anchor_has_no_default_route'] = not any(r.get('dst') == 'default' for r in prepared['routes'])
        policy_call('fixture_routes', fixture=True, device=device)
        policy_call('install', proxy_ports=[18080, 18081])
        resolver_file = evidence / 'resolv.conf'
        resolver_file.write_text('nameserver 127.0.0.3\noptions timeout:1 attempts:1\n', encoding='ascii')
        mounts = [*overlay, '--mount', f'type=bind,src={resolver_file},dst=/etc/resolv.conf,readonly']
        s0 = snap()
        baseline_rules = rule_set(s0)
        launch.save('closed-baseline-counters.json', counters(s0))

        broker = launch.create(name('broker'), launch.options(anchor, 0, mounts=overlay) + ['--cap-add', 'NET_ADMIN'], ['python', '-m', 'tests.runtime.egress_broker'])
        broker_log = (evidence / 'broker-stderr.log').open('wb')
        broker_proc = subprocess.Popen(launch.cli + ['start', '-a', '-i', broker], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=broker_log)
        send_control(broker_proc, {'mode': 'fixture', 'hosts': ALL_HOSTS, 'answers': ANSWERS, 'special': SPECIAL, 'device': device, 'ttl': TTL, 'max_grants': 8})
        broker_ready = read_control(broker_proc, 30)
        assert broker_ready['type'] == 'ready'
        worker_log = (evidence / 'worker-stderr.log').open('wb')
        worker = subprocess.Popen(launch.cli + ['exec', '-i', '--user', '1001:1001', anchor, 'python', '-m', 'tests.runtime.s2h_worker'],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=worker_log)
        ready = read_control(worker, 60)
        assert ready['type'] == 'ready' and ready['namespace'] == namespace
        trusted = helper('probe-trusted', 1001, 'tests.runtime.s2h_probe', mounts=overlay)
        browser = helper('probe-browser', 1000, 'tests.runtime.s2h_probe', mounts=mounts)
        api_trusted = helper('api-trusted', 1001, 'tests.runtime.s2a_probe', mounts=overlay)
        api_browser = helper('api-browser', 1000, 'tests.runtime.s2a_probe', mounts=mounts)
        chromium = helper('chromium', 1000, 'tests.runtime.s2b_browser', mounts=mounts)
        for lease, port, hosts in (('j1', 18080, J1_HOSTS), ('j2', 18081, J2_HOSTS)):
            assert bcontrol({'type': 'lease_open', 'lease': lease, 'hosts': hosts})['ok'] is True
            assert wcontrol({'type': 'open_proxy', 'lease': lease, 'port': port, 'hosts': hosts})['type'] == 'proxy_opened'
        refused = bcontrol({'type': 'lease_open', 'lease': 'j9', 'hosts': ['www.a.invalid']})
        checks['lease_cannot_widen_the_broker_policy'] = refused['ok'] is False

        # ---------------------------------------------------------------- CLOSED: normal state is OFF
        r = wcontrol({'type': 'connect', 'port': 18080, 'authority': 'a.invalid:443'})['result']
        launch.save('closed-connect.json', r)
        checks['closed_connect_refused_before_any_dial'] = (r['status'].startswith('HTTP/1.1 502') and r['dialed'] == [] and r['resolutions'][0]['denied'] == 'EGRESS_DISABLED'
                                                            and accepts('A') == 0)
        d = direct([['A443', A, 443], ['B443', B, 443]], 'closed-direct')
        checks['closed_direct_dial_fails'] = not reached(d) and accepts('A') == 0 and accepts('B') == 0

        # ---------------------------------------------------------------- OPEN the window (host controls both halves)
        opened = policy_call('egress_open', device=device)
        egress_open = True
        report['egress_window']['opened_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        assert bcontrol({'type': 'enable'})['type'] == 'enabled'
        canary_base = wcontrol({'type': 'counts'})['counts']

        # T1: a verified IP works through the production Connector
        s1 = snap()
        r = wcontrol({'type': 'connect', 'port': 18080, 'authority': 'a.invalid:443'})['result']
        launch.save('T1-connect-a.json', r)
        s2 = snap()
        rules = s2['grant_rules']
        checks['T1_verified_ip_reached_through_connector'] = (r['status'].startswith('HTTP/1.1 200') and r['banner'] == 'PEER-A' and accepts('A') == 1
                                                              and r['dialed'] == [{'ip': A, 'port': 443, 'peer': [A, 443]}] and r['resolutions'][0]['addresses'] == [A])
        checks['T1_exactly_one_grant_rule_for_exactly_that_ip'] = (len(rules) == 1 and grant_ips(s2) == {A} and all(
            x in rules[0] for x in ('--dport 443', '--ctstate NEW', '--uid-owner 1001', '-o ' + device, 'SP_GRANT')))
        # T2: any other public IP is refused by the OS even though a live listener is there
        before_counts = counters(snap())
        d = direct([['B443', B, 443], ['C443', C, 443], ['A80', A, 80], ['A8443', A, 8443], ['offlink_public_443', '12.0.0.1', 443], ['A443_granted', A, 443]], 'T2-direct')
        after = counters(snap())
        dd = delta(after, before_counts)
        checks['T2_other_public_ips_and_ports_refused_by_os'] = reached(d) == ['A443_granted'] and accepts('B') == 0 and accepts('C') == 0
        checks['T2_refusals_counted_by_the_os_rules'] = dd.get('SP_TRUSTED_OTHER_DROP', 0) >= 5
        checks['T2_granted_address_is_usable_by_the_trusted_uid_only_on_443'] = d['A443_granted']['banner'] == 'PEER-A' and accepts('A') == 2
        # T3: non-public destinations
        before_counts = counters(snap())
        d = direct([['rfc1918_10', '10.0.0.5', 443], ['rfc1918_172', '172.16.0.5', 443], ['rfc1918_192', '192.168.1.5', 443], ['cgnat', '100.64.0.5', 443]], 'T3-direct')
        dd = delta(counters(snap()), before_counts)
        checks['T3_non_public_destinations_refused_by_os'] = not reached(d) and dd.get('SP_TRUSTED_NONPUBLIC_DROP', 0) >= 4
        grants_before = grant_ips(snap())
        denial_ok, denial_rows = True, {}
        for host, reason in EXPECTED_DENIAL.items():
            r = wcontrol({'type': 'connect', 'port': 18080, 'authority': host + ':443'})['result']
            denial_rows[host] = {'status': r['status'], 'denied': r['resolutions'][0].get('denied') if r['resolutions'] else None, 'dialed': r['dialed']}
            denial_ok &= r['status'].startswith('HTTP/1.1 502') and r['dialed'] == [] and denial_rows[host]['denied'] == reason
        launch.save('T3-broker-denials.json', denial_rows)
        checks['T3_forbidden_answer_sets_get_no_grant_and_no_dial'] = denial_ok and grant_ips(snap()) == grants_before
        r = wcontrol({'type': 'connect', 'port': 18080, 'authority': 'b.invalid:443'})['result']
        checks['T3_host_outside_the_job_policy_never_reaches_the_broker'] = r['resolutions'] == [] and r['records'][0][2:4] == ['BLOCK', 'NOT_ALLOWLISTED'] and r['dialed'] == []
        hostile = {h: probe(trusted, 1001, 'T3-hostile-' + h.split('.')[0], {'mode': 'resolve', 'lease': 'j1', 'host': h}) for h in ('b.invalid', 'c.invalid')}
        checks['T3_hostile_request_for_another_jobs_host_is_denied'] = all(v['status'] == 'ERROR' and v['denials'][0]['reason'] == 'HOST_NOT_IN_LEASE' for v in hostile.values())
        # T4: DNS re-resolution
        assert wait_until(lambda: not grant_ips(snap()))  # Start from an empty grant table.
        a_before, b_before = accepts('A'), accepts('B')
        seq = [wcontrol({'type': 'connect', 'port': 18080, 'authority': 'rebind.invalid:443'})['result'] for _ in range(3)]
        launch.save('T4-rebind.json', seq)
        checks['T4_each_resolution_is_revalidated_and_granted_separately'] = (seq[0]['banner'] == 'PEER-A' and seq[1]['banner'] == 'PEER-B'
                                                                              and seq[2]['status'].startswith('HTTP/1.1 502') and seq[2]['dialed'] == []
                                                                              and seq[2]['resolutions'][0]['denied'] == 'PRIVATE_ADDRESS')
        s = snap()
        checks['T4_private_rebind_added_no_rule'] = grant_ips(s) == {A, B}
        assert wait_until(lambda: not grant_ips(snap()), TTL + 10)
        d = direct([['A443', A, 443], ['B443', B, 443]], 'T4-after-ttl')
        checks['T4_grants_expire_and_old_ips_are_refused_again'] = not reached(d) and accepts('A') == a_before + 1 and accepts('B') == b_before + 1
        # T5: update failures
        a_before = accepts('A')
        bcontrol({'type': 'inject', 'fail_allow': 1})
        r = wcontrol({'type': 'connect', 'port': 18080, 'authority': 'a.invalid:443'})['result']
        launch.save('T5-allow-failure.json', r)
        checks['T5_rule_insert_failure_means_no_connection_and_no_rule'] = (r['status'].startswith('HTTP/1.1 502') and r['dialed'] == []
                                                                           and r['resolutions'][0]['denied'] == 'FIREWALL_UPDATE_FAILED' and accepts('A') == a_before
                                                                           and not grant_ips(snap()))
        r = wcontrol({'type': 'connect', 'port': 18080, 'authority': 'a.invalid:443'})['result']
        checks['T5_next_independent_attempt_recovers'] = r['banner'] == 'PEER-A' and accepts('A') == a_before + 1
        assert wait_until(lambda: not grant_ips(snap()), TTL + 10)
        bcontrol({'type': 'inject', 'fail_revoke': -1})
        wcontrol({'type': 'connect', 'port': 18080, 'authority': 'a.invalid:443'})
        pending = wait_until(lambda: bcontrol({'type': 'state'})['state']['pending_revocations'] == [A], TTL + 10)
        a_before = accepts('A')
        r = wcontrol({'type': 'connect', 'port': 18080, 'authority': 'a.invalid:443'})['result']
        checks['T5_failed_revoke_is_reported_and_blocks_new_connections'] = (pending and r['resolutions'][0]['denied'] == 'REVOCATION_PENDING'
                                                                            and r['dialed'] == [] and accepts('A') == a_before)
        bcontrol({'type': 'inject', 'fail_revoke': 0})
        checks['T5_pending_revocation_is_retried_until_the_os_is_clean'] = wait_until(lambda: not grant_ips(snap()) and bcontrol({'type': 'state'})['state']['pending_revocations'] == [])
        # T6: concurrent jobs
        a_before, c_before = accepts('A'), accepts('C')
        jobs = [[18080, 'a.invalid:443']] * 6 + [[18081, 'c.invalid:443']] * 6 + [[18080, 'c.invalid:443']] * 3 + [[18081, 'a.invalid:443']] * 3  # Within the Connector's concurrent-connection bound.
        results = wcontrol({'type': 'parallel', 'jobs': jobs}, 120)['results']
        launch.save('T6-parallel.json', results)
        own1, own2, cross1, cross2 = results[:6], results[6:12], results[12:15], results[15:]
        def union(items, key):
            return {(x['host'] if key == 'resolutions' else x['ip']) for r in items for x in r[key]}
        j1_all, j2_all = [x for x, job in zip(results, jobs) if job[0] == 18080], [x for x, job in zip(results, jobs) if job[0] == 18081]
        # Observation windows of concurrent requests on one proxy overlap, so judge each request on its own outcome and each proxy on the union.
        checks['T6_parallel_jobs_each_reach_only_their_own_destination'] = (
            all(x['banner'] == 'PEER-A' for x in own1) and all(x['banner'] == 'PEER-C' for x in own2)
            and all(x['status'].startswith('HTTP/1.1 502') and x['banner'] == '' for x in cross1 + cross2)
            and union(j1_all, 'resolutions') == {'a.invalid'} and union(j1_all, 'dialed') == {A}
            and union(j2_all, 'resolutions') == {'c.invalid'} and union(j2_all, 'dialed') == {C}
            and accepts('A') == a_before + 6 and accepts('C') == c_before + 6)
        state = bcontrol({'type': 'state'})
        launch.save('T6-broker-state.json', state)
        granted = [(e['lease'], e['ip']) for e in state['state']['events'] if e['event'] == 'GRANTED']
        checks['T6_broker_never_granted_across_jobs'] = bool(granted) and all((l, ip) in {('j1', A), ('j1', B), ('j2', C)} for l, ip in granted)
        checks['T6_both_jobs_held_separate_grants'] = grant_ips(snap()) == {A, C} and {k: v['grants'] for k, v in state['state']['leases'].items()} == {'j1': [A], 'j2': [C]}
        bcontrol({'type': 'lease_close', 'lease': 'j2'})
        s = snap()
        d = direct([['C443', C, 443]], 'T6-after-j2-close')
        checks['T6_closing_one_job_revokes_only_its_grant'] = grant_ips(s) == {A} and not reached(d)
        # Normal end of the window on the broker side
        closed = bcontrol({'type': 'close'})
        launch.save('T6-broker-close.json', closed)
        checks['T6_normal_close_leaves_no_grant_rule'] = closed['clean'] is True and closed['grant_rules'] == [] and not grant_ips(snap())
        assert bcontrol({'type': 'enable'})['type'] == 'enabled'
        for lease, hosts in (('j1', J1_HOSTS), ('j2', J2_HOSTS)):
            assert bcontrol({'type': 'lease_open', 'lease': lease, 'hosts': hosts})['ok'] is True

        # T7: Browser and trusted-DNS regressions, with an ACTIVE grant for A the whole time
        wcontrol({'type': 'connect', 'port': 18080, 'authority': 'a.invalid:443'})
        wcontrol({'type': 'keepalive', 'lease': 'j1', 'host': 'a.invalid', 'seconds': 120})
        assert grant_ips(snap()) == {A}
        a_before, b_before, c_before = accepts('A'), accepts('B'), accepts('C')
        s_pre = snap()
        t_tcp = probe(trusted, 1001, 'T7-trusted-tcp', {'mode': 'connect', 'targets': [['resolver_tcp', '127.0.0.11', 53], ['canary_tcp', '127.0.0.2', 18555],
                                                                                     ['canary_lan', '10.231.77.5', 18555], ['canary_metadata', '169.254.169.254', 80],
                                                                                     ['canary_host_model', '127.0.0.4', 18555], ['docker_api_model', '127.0.0.5', 2375],
                                                                                     ['proxy', '127.0.0.1', 18080], ['gateway443', GATEWAY, 443], ['documentation443', '192.0.2.1', 443]]})
        t_udp = probe(trusted, 1001, 'T7-trusted-udp', {'mode': 'udp', 'targets': [['resolver_udp', '127.0.0.11', 53], ['canary_dns', '127.0.0.3', 53], ['canary_udp', '127.0.0.3', 5353]]})
        s_trusted = snap()
        checks['T7_trusted_uid_has_no_direct_dns_path'] = not reached(t_tcp, 'resolver_tcp') and not reached(t_udp, 'resolver_udp') and delta(counters(s_trusted), counters(s_pre)).get('SP_WORKER_DNS_DROP', 0) >= 1
        checks['T7_positive_controls_hold_for_the_trusted_uid'] = (all(t_tcp[k]['reached'] for k in ('canary_tcp', 'canary_lan', 'canary_metadata', 'canary_host_model', 'docker_api_model', 'proxy'))
                                                                  and t_udp['canary_dns']['reached'] and t_udp['canary_udp']['reached'] and not reached(t_tcp, 'gateway443', 'documentation443'))
        canary_t7 = wcontrol({'type': 'counts'})['counts']  # The positive controls above are expected; everything after this must add nothing.
        targets = [[n, ip, p] for n, ip, p in (('A443', A, 443), ('B443', B, 443), ('C443', C, 443), ('A80', A, 80), ('gateway443', GATEWAY, 443),
                                              ('broker', '127.0.0.6', 18090), ('resolver_tcp', '127.0.0.11', 53), ('canary_tcp', '127.0.0.2', 18555),
                                              ('canary_lan', '10.231.77.5', 18555), ('canary_metadata', '169.254.169.254', 80), ('canary_host_model', '127.0.0.4', 18555),
                                              ('docker_api_model', '127.0.0.5', 2375), ('documentation443', '192.0.2.1', 443))]
        udp_targets = [['resolver_udp', '127.0.0.11', 53], ['canary_dns', '127.0.0.3', 53], ['canary_udp', '127.0.0.3', 5353], ['documentation_udp', '192.0.2.1', 53]]
        s_pre = snap()
        b_tcp = probe(browser, 1000, 'T7-browser-tcp', {'mode': 'connect', 'targets': targets + [['proxy', '127.0.0.1', 18080]]})
        b_udp = probe(browser, 1000, 'T7-browser-udp', {'mode': 'udp', 'targets': udp_targets})
        s_post = snap()
        checks['T7_browser_reaches_only_the_owned_proxy_even_with_an_active_grant'] = reached(b_tcp) == ['proxy'] and not reached(b_udp)
        checks['T7_browser_cannot_reach_the_broker_or_the_resolver'] = not reached(b_tcp, 'broker', 'resolver_tcp') and not reached(b_udp, 'resolver_udp')
        checks['T7_browser_drops_counted_by_the_os'] = all(delta(counters(s_post), counters(s_pre)).get(k, 0) > 0 for k in ('SP_BROWSER_TCP_DROP', 'SP_BROWSER_UDP_DROP', 'SP_BROWSER_DNS_DROP'))
        net = browser_run({'mode': 'network', 'gateway': GATEWAY, 'proxy_port': 18080, 'host': 'a.invalid', 'url': 'https://a.invalid/', 'real_ip': A, 'resources': ready['resources']}, 'T7-chromium-network')
        s_chrome = snap()
        direct_ok = all(v['reached'] is False and not (v['error'] or '').startswith(('ERR_CERT', 'ERR_SSL', 'ERR_BAD_SSL', 'ERR_HTTP', 'ERR_EMPTY', 'ERR_RESPONSE')) for v in net['direct'].values())
        checks['T7_chromium_direct_attempts_denied_incl_the_granted_ip'] = direct_ok and 'allowed_host_ip_direct_https' in net['direct'] and net['udp_attempt_completed'] is True
        checks['T7_chromium_proxied_refusals_hold'] = all(v['reached'] is False for v in net['proxied_refused'].values())
        checks['T7_chromium_sandbox_verified'] = sandboxed(net['sandbox']['body'])
        checks['T7_peers_saw_no_browser_traffic'] = (accepts('A'), accepts('B'), accepts('C')) == (a_before, b_before, c_before)
        checks['T7_chromium_drops_counted_by_the_os'] = all(delta(counters(s_chrome), counters(s_post)).get(k, 0) > 0 for k in ('SP_BROWSER_TCP_DROP', 'SP_BROWSER_UDP_DROP', 'SP_BROWSER_DNS_DROP'))
        probes = {w: api_probe(c, u, 'T7-docker-api-' + w) for w, c, u in (('trusted', api_trusted, 1001), ('browser', api_browser, 1000))}
        checks['T7_docker_api_model_reachable_trusted_not_browser'] = (probes['trusted']['modelled']['docker_api_model_127.0.0.5:2375'] is True
                                                                       and probes['browser']['modelled']['docker_api_model_127.0.0.5:2375'] is False
                                                                       and not any(probes['browser']['unmodelled'].values()) and set(probes['browser']['unix_sockets'].values()) == {'ABSENT'})
        canary_zero(canary_t7, 'T7')
        wcontrol({'type': 'keepalive_stop'})

        # T8: failure paths. (a) the Worker dies with a live grant; (b) the broker itself is killed with a live grant.
        wcontrol({'type': 'connect', 'port': 18080, 'authority': 'a.invalid:443'})
        checks['T8a_grant_exists_before_the_worker_crash'] = grant_ips(snap()) == {A}
        send_control(worker, {'type': 'crash'})
        worker.wait(timeout=20)
        worker = None
        checks['T8a_crash_leaves_the_grant_until_the_host_ends_the_lease'] = grant_ips(snap()) == {A}
        bcontrol({'type': 'lease_close', 'lease': 'j1'})
        bcontrol({'type': 'lease_close', 'lease': 'j2'})
        checks['T8a_host_lease_close_removes_it'] = not grant_ips(snap())
        bcontrol({'type': 'lease_open', 'lease': 'j1', 'hosts': ['a.invalid']})
        granted = probe(trusted, 1001, 'T8b-client-resolve', {'mode': 'resolve', 'lease': 'j1', 'host': 'a.invalid'})
        checks['T8b_grant_exists_before_the_broker_is_killed'] = granted['status'] == 'COMPLETE' and grant_ips(snap()) == {A}
        launch.call('kill', broker)
        broker_proc.wait(timeout=20)
        broker_proc = None
        stale = grant_ips(snap())
        checks['T8b_a_killed_broker_leaves_the_grant_in_place_until_the_window_is_closed'] = stale == {A}
        closed_snapshot = policy_call('egress_close', device=device)
        egress_open = False
        report['egress_window']['closed_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        checks['T8b_window_close_flushes_every_grant_rule'] = closed_snapshot['grants_flushed'] == 1 and not closed_snapshot['grant_rules']
        checks['D_rules_identical_to_the_closed_baseline_after_close'] = rule_set(closed_snapshot) == baseline_rules
        a_before = accepts('A')
        after_close = probe(trusted, 1001, 'D-trusted-after-close', {'mode': 'connect', 'targets': [['A443', A, 443], ['B443', B, 443], ['C443', C, 443]]})
        after_close_b = probe(browser, 1000, 'D-browser-after-close', {'mode': 'connect', 'targets': [['A443', A, 443], ['proxy', '127.0.0.1', 18080]]})
        checks['D_nothing_reaches_a_peer_after_close'] = not reached(after_close) and reached(after_close_b) == [] and accepts('A') == a_before
        checks['flag_false_in_source_at_end'] = (root / 'src/isolation/site_policy.py').read_text('utf-8') == sp_text
        report['peer_accepts_total'] = {k: accepts(k) for k in peers}
    except Exception as exc:
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)[:400] if isinstance(exc, (AssertionError, IsolationLeak)) else 'Inspect bounded logs'
        report['isolation_leak'] = isinstance(exc, IsolationLeak)
    finally:
        if egress_open:  # Never leave the window open, whatever failed.
            try:
                flushed = policy_call('egress_close', device=device)
                egress_open = False
                report['egress_window'].update(closed_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), closed_by='FINALLY', grants_flushed=flushed['grants_flushed'])
            except Exception:
                report['egress_window']['close_unconfirmed'] = True
        for proc, quit_command in ((worker, {'type': 'quit'}), (broker_proc, {'type': 'quit'})):
            if proc is not None:
                try:
                    send_control(proc, quit_command)
                    read_control(proc, 10)
                except Exception:
                    pass
        report['all_owned_stopped'] = launch.stop_all() if launch.resources else True
        for proc in (worker, broker_proc):
            if proc is not None:
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    proc.wait(timeout=5)
        report['all_owned_removed'] = launch.cleanup() if launch.resources else True
        report['own_network_removed'] = False
        try:
            own = prefix + '-network'
            net_info = json.loads(launch.call('network', 'inspect', own))[0]
            if (launch.resources.get(own, {}).get('id') == net_info['Id'] and net_info['Internal'] is True
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
        report['passed'] = (bool(checks) and all(checks.values()) and 'error' not in report and report.get('all_owned_stopped') is True
                            and report.get('all_owned_removed') is True and report['own_network_removed'] and report['existing_docker_resources_unchanged']
                            and not report['egress_window'].get('close_unconfirmed'))
        launch.save('validation-result.json', report)
        manifest = {p.relative_to(evidence).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in sorted(evidence.rglob('*')) if p.is_file() and p.name != 'export-sha256.json'}
        (evidence / 'export-sha256.json').write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding='utf8')
        report['sha256_manifest'] = {'files': len(manifest), 'mismatches': sum(
            hashlib.sha256((evidence / k).read_bytes()).hexdigest() != v for k, v in manifest.items())}
        print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
