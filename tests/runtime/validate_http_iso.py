"""Fixture measurement of the isolated HTTP check (src/noxiworks/http_isolation.py). Docker, existing image only, --internal network, no real site.

    py -3.15 -B -m tests.runtime.validate_http_iso --evidence <NEW folder> [--case NAME ...]      (needs the USER's approval to run Docker)

Run 2026-11-26: GREEN 18/18 (.local/http-iso-run-04). It drives the production code path (isolated_check + judge) against tests/runtime/http_iso_peer.py: same containers, same OS rules, same broker,
reaper, proxy and Worker as a real check; only the broker's answers (table), the peer and its throw-away certificate are fixtures. No grant, ledger, data
folder, pull, build or volume is involved; every container and network is this run's own and is removed at the end (the evidence says if one was not).
Each case states what must be observed. Evidence for a refusal is the OS rule counters and the peer's own log, not only what the Worker says. A case that did not
run is NOT_RUN, never a pass; one failed case stops the series (RED).
"""
import argparse
import json
from pathlib import Path
import time

from src.noxiworks import http_isolation

HOST, PEER_IP, OTHER_IP, ANCHOR_IP, SUBNET = 'check.invalid', '11.22.33.10', '11.22.33.11', '11.22.33.5', '11.22.33.0/24'
PEER, TRAP = 'A', 'B'
# direct attempts made while the window is open and the address is granted: (name, ip, port) / who must not get through
DIRECT = (('granted_443', PEER_IP, 443), ('granted_80', PEER_IP, 80), ('other_public_443', OTHER_IP, 443), ('private_443', '10.0.0.5', 443), ('lan_443', '192.168.1.5', 443),
          ('metadata', '169.254.170.2', 80), ('broker', '127.0.0.6', 18090), ('resolver', '127.0.0.11', 53))
UDP = (('dns_udp', '127.0.0.11', 53), ('public_udp', OTHER_IP, 53), ('public_quic', PEER_IP, 443))
ONE = [[PEER_IP]]
CASES = (
    # name, path, broker answers (per resolution), options, expected (outcome, reason), peer requests expected
    ('ok', '/', ONE, {}, ('PASS', 'HTTP_200'), 1),
    ('redirect_not_followed', '/redirect', ONE, {}, ('UNKNOWN', None), 1),
    ('server_error', '/error', ONE, {}, ('FAIL', 'HTTP_503'), 1),
    ('status_line_over_the_cap', '/long', ONE, {}, ('UNKNOWN', 'HTTP_EXCHANGE_ERROR'), 1),
    ('drip_feeding_server', '/drip', ONE, {}, ('FAIL', 'HTTP_TIMEOUT'), 1),
    ('hanging_server', '/hang', ONE, {}, ('FAIL', 'HTTP_TIMEOUT'), 1),
    ('certificate_of_another_name', '/', ONE, {'cert_name': 'other.invalid'}, ('FAIL', 'TLS_FAILED'), 0),
    ('certificate_not_trusted', '/', ONE, {'trust': False}, ('FAIL', 'TLS_FAILED'), 0),
    ('private_answer', '/', [['10.0.0.5']], {}, ('UNKNOWN', 'DESTINATION_PRIVATE_ADDRESS'), 0),
    ('metadata_answer', '/', [['169.254.169.254']], {}, ('UNKNOWN', 'DESTINATION_LINK_LOCAL_ADDRESS'), 0),
    ('loopback_answer', '/', [['127.0.0.1']], {}, ('UNKNOWN', 'DESTINATION_LOOPBACK_ADDRESS'), 0),
    ('mixed_answer', '/', [[PEER_IP, '10.0.0.5']], {}, ('UNKNOWN', 'DESTINATION_PRIVATE_ADDRESS'), 0),
    ('ipv6_only_answer', '/', [['2606:4700::1111']], {}, ('UNKNOWN', 'DESTINATION_FIRST_ADDRESS_NOT_IPV4'), 0),
    ('unresolvable', '/', ONE, {'special': {HOST: ['COMPLETE', True, True, []]}}, ('UNKNOWN', 'DESTINATION_DNS_NO_ADDRESS'), 0),
    ('nothing_listening', '/', [['11.22.33.77']], {}, ('FAIL', ('CONNECT_FAILED', 'CONNECT_TIMEOUT')), 0),  # refused / unreachable or no answer: both are the site
    ('proxy_stopped', '/', ONE, {'stop': 'proxy'}, ('UNKNOWN', None), 0),
    ('broker_killed', '/', ONE, {'stop': 'broker'}, ('UNKNOWN', None), 0),
    ('direct_attempts_while_granted', '/', ONE, {'direct': True}, ('PASS', 'HTTP_200'), 1),
)


def evaluate(case, verdict, rec, requests, trap_accepts):
    """-> {check: bool} for one case. Pure; the series is green only if every value is True."""
    name, _, _, options, (outcome, reason), expected = case
    stopped = options.get('stop')
    checks = {'outcome': verdict['outcome'] == outcome, 'reason': reason is None or verdict['reason'] in (reason if type(reason) is tuple else (reason,)), 'peer_requests': requests == expected,
              'nothing_reached_the_other_address': trap_accepts == 0, 'nothing_left_behind': rec.get('left_behind') == [],
              'window_closed': (rec.get('window') or {}).get('closed_by') in ('HOST', 'NAMESPACE_REMOVED')}
    if not stopped:
        checks['rules_restored_exactly'] = rec.get('rules_restored') is True
        checks['no_violation'] = verdict.get('violations') == [] or bool(options.get('direct'))
        checks['at_most_one_grant'] = len(rec.get('grants') or []) <= 1
    if options.get('direct'):  # the attempts are made on purpose by separate probes: counted by the OS, none got through, and judge() sees the counters
        d = rec.get('direct') or {}
        worker, proxy = d.get('worker_tcp') or {}, d.get('proxy_tcp') or {}
        checks.update(outcome=verdict['reason'] == 'ISOLATION_VIOLATION', reason=True, no_violation=any(v.startswith('DROP:') for v in verdict.get('violations') or []),
                      worker_reaches_nothing=bool(worker) and not any(v['reached'] for v in worker.values()),
                      worker_udp_reaches_nothing=bool(d.get('worker_udp')) and not any(v['reached'] for v in d['worker_udp'].values()),
                      proxy_reaches_only_the_granted_address=bool(proxy) and [k for k, v in proxy.items() if v['reached']] in (['granted_443', 'broker'], ['granted_443']),
                      proxy_udp_reaches_nothing=bool(d.get('proxy_udp')) and not any(v['reached'] for v in d['proxy_udp'].values()),
                      ipv6_dropped=d.get('ipv6_reached') is False)
    return checks


def run_case(case, folder):
    name, path, answers, options, _, _ = case
    run_dir = folder / name
    run_dir.mkdir(parents=True)
    docker = http_isolation.launcher(run_dir / 'ev', internal_subnet=SUBNET)
    if docker.image_id() != http_isolation.pinned_image():
        raise RuntimeError('the pinned image is not present')
    job, peers = {}, {}
    overlay = http_isolation.mount(http_isolation.ROOT / 'tests/runtime', '/opt/siteproof/tests/runtime')  # the fixture peers only

    def peer(label, ip, network, prefix, env):
        return docker.create(f'{prefix}-peer-{label.lower()}', [*overlay, '--network', network, '--ip', ip, '--user', '1005:1005', '--cap-drop', 'ALL', '--security-opt',
                             'no-new-privileges=true', '--read-only', '--pids-limit', '32', '--memory', '128m', '--memory-swap', '128m', '--cpus', '.5',
                             '--sysctl', 'net.ipv4.ip_unprivileged_port_start=0', '--tmpfs', '/tmp:rw,nosuid,nodev,size=8m,uid=1005,gid=1005', *env],
                             ['python', '-m', 'tests.runtime.http_iso_peer'])

    def lines(label):
        return [json.loads(x) for x in docker.call('logs', peers[label]).splitlines() if x.startswith('{')]

    def start(docker_, network, prefix, rec):
        for label, ip, env in ((PEER, PEER_IP, ['--env', 'PEER_HOST=' + HOST] + (['--env', 'PEER_CERT_NAME=' + options['cert_name']] if options.get('cert_name') else [])),
                               (TRAP, OTHER_IP, ['--env', 'PEER_HOST=trap.invalid'])):
            peers[label] = peer(label, ip, network, prefix, env)
            docker.call('start', peers[label])
        end = time.monotonic() + 30
        while time.monotonic() < end and not all(any(x['event'] == 'listening' for x in lines(p)) for p in peers):
            time.sleep(.3)
        if options.get('trust', True):
            job['ca_pem'] = next(x['pem'] for x in lines(PEER) if x['event'] == 'cert')

    def during(docker_, create, tmounts, held, rec, policy):
        if options.get('stop'):
            docker.call('kill', next(n for n in docker.resources if f"-{options['stop']}-" in n))
        if options.get('direct'):
            held['broker'].ask({'type': 'state'})
            found = rec['direct'] = {}
            extra = http_isolation.mount(http_isolation.ROOT / 'tests/runtime', '/opt/siteproof/tests/runtime')
            for who, uid in (('proxy', 1001), ('worker', 1000)):
                probe = create('probe-' + who, uid, 'tests.runtime.s2h_probe', [*tmounts, *extra])
                if who == 'proxy':  # a grant exists only after the broker resolved the name for the lease
                    docker.bounded(probe, json.dumps({'mode': 'resolve', 'lease': 'http', 'host': HOST}).encode() + b'\n')
                for mode, targets in (('connect', DIRECT), ('udp', UDP)):
                    out, _ = docker.bounded(probe, json.dumps({'mode': mode, 'targets': targets}).encode() + b'\n')
                    found[f"{who}_{'tcp' if mode == 'connect' else 'udp'}"] = json.loads(out)['results']
            found['ipv6_reached'] = 'SP_BROWSER_IPV6_DROP' not in policy('snapshot')['ipv6']  # the rule is there; no IPv6 route exists on this network
    broker = {'mode': 'fixture', 'hosts': [HOST], 'answers': {HOST: answers}, 'special': options.get('special', {}), 'device': None, 'ttl': http_isolation.GRANT_TTL, 'max_grants': 1}
    requests = trap = None
    peer_log = []

    def remove_all(original=docker.remove_all):  # read the peers' logs before they are removed
        nonlocal requests, trap
        if peers:
            requests, trap = (sum(x['event'] == 'request' for x in lines(PEER)), sum(x['event'] == 'accepted' for x in lines(TRAP)))
            peer_log[:] = [x for x in lines(PEER) if x['event'] != 'cert']
        return original()
    docker.remove_all = remove_all
    rec = http_isolation.isolated_check(docker, run_dir, host=HOST, path=path, reserve=lambda: 'fixture', mode='fixture', broker=broker, worker_job=job,
                                        peers={'anchor': ('--ip', ANCHOR_IP), 'start': start, 'during': during})
    verdict = http_isolation.judge(rec)
    checks = evaluate(case, verdict, rec, requests, trap)
    (run_dir / 'result.json').write_text(json.dumps({'case': name, 'checks': checks, 'verdict': verdict, 'record': rec, 'peer_requests': requests, 'trap_accepts': trap, 'peer_log': peer_log},
                                                    ensure_ascii=False, indent=1), encoding='utf-8')
    return checks


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--case', action='append', choices=[c[0] for c in CASES])
    args = parser.parse_args(argv)
    args.evidence.mkdir(parents=True, exist_ok=False)
    results = {c[0]: 'NOT_RUN' for c in CASES}
    for case in CASES:
        if args.case and case[0] not in args.case:
            continue
        try:
            checks = run_case(case, args.evidence)
            results[case[0]] = 'PASS' if all(checks.values()) else 'FAIL:' + ','.join(k for k, v in checks.items() if not v)
        except Exception as exc:
            results[case[0]] = 'ERROR:' + type(exc).__name__ + ':' + str(exc)[:200]
        print(case[0], results[case[0]], flush=True)
        if results[case[0]] != 'PASS':
            break  # RED: the rest stays NOT_RUN
    green = all(v == 'PASS' for v in results.values())
    (args.evidence / 'summary.json').write_text(json.dumps({'results': results, 'green': green, 'image': http_isolation.pinned_image(), 'real_site': False}, indent=1), encoding='utf-8')
    print('GREEN' if green else 'NOT GREEN')
    return 0 if green else 1


if __name__ == '__main__':
    raise SystemExit(main())
