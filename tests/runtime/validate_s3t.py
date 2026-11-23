"""S3-1T: first real-site capture of the TTN TOP PAGE `/` (target ttn-home), Desktop + Mobile, FULL PAGE, with PENDING Baseline
CANDIDATE creation. Candidates are never approved here. Derived from the S3-1 harness (validate_s3.py, unchanged); the differences are:
  * path `/`, page id = the registered target `ttn-home`, Worker module tests.runtime.s3t_worker (capture_plan.json, checked);
  * an IDENTITY gate before any container runs: image ID, Browser bundle manifest, OS rule / Broker / reaper / Worker files, capture
    plan and targets must equal the values recorded in the USER-approved limited exception (`--expect` JSON). Any difference: STOP;
  * the prepared profiles must be exactly Desktop 1440x900 / Mobile 390x844 full page before a capture window opens;
  * the exported PNG must have the viewport width and at least the viewport height (full page).


Order is the safety argument, and every step before CAPTURE is gated:
  GATE-A  OS egress closed, no window: Broker config refusal, default OFF, Browser/trusted/Broker/resolver/Docker paths, Chromium direct
          paths, 19-case refusal matrix, window stop procedures (host close, reaper EOF).                       (no external traffic possible)
  GATE-B  one egress window with a DNS-ONLY grant (the Broker resolves the TTN host; NOBODY connects): Browser and trusted-UID
          prohibited paths with a live grant, Chromium direct paths incl. the granted IP, refusal matrix, accounting: ZERO TCP flows.
  GATE-C  Broker SIGKILLed with a live grant: no new grant, the independent reaper removes the stale grant by deadline.
  Any gate failure raises GateFailed BEFORE the first navigation to the real site; the run then ends with the window closed.
  CAPTURE Desktop then Mobile, each in its own short window (fresh Broker, TTL 100 s, reaper, one proxy, one job): a HEAD of the exact
          page first (must be 200 and not redirect), then the production capture pipeline; Baseline candidate saved, never approved.
Nothing here edits the site, approves a Baseline, touches AWS or Git, or starts monitoring.

COMPARE mode (`--baseline-registry`, required exactly when the `--expect` identity pins a registry; see expected_baseline()):
  * before any container, the registry must equal its export-sha256.json and every value the identity pins (manifest digest, page,
    per-profile pin / Baseline job / image digest); it is mounted read-only into the trusted Worker only and the Worker stages it as
    /evidence/ws (noxiworks.baseline_runtime). The Worker's `created` reply must report exactly those pins BEFORE the first window opens,
    or STOP: there is no capture without its Baseline and no fallback to an empty workspace;
  * after each capture: the job's comparison must use that profile's formal Baseline (pin, Baseline job, image digest), quality is never
    promoted, the new candidate stays PENDING and the only APPROVED records are the registry's own; the diff PNG the Worker exported must
    match the comparison's diff digest. Instability, source mismatch and audit problems stay UNKNOWN exactly as the comparison decided.
An identity file without a registry (SP-D52) can never authorise this configuration: the pinned file hashes differ.

PERMIT mode (`--permit P --trust T --target-dir D`, all three or none): the target comes from a SIGNED monitoring permit
(src/noxiworks/permit.py; OpenSSH `ssh-keygen -Y verify`, namespace siteproof-monitoring-permit), never from a settings file alone.
Before any container: the signature must verify against T; the permit must be inside its validity window; D/targets.json and
D/capture_plan.json must have exactly the SHA-256 the permit pins; the page / site / host they describe must equal the permit's target
(top page `/`, one host); and --expect must be exactly the permit's identity (+ the Baseline pins in compare mode, which the permit must
allow). Those two pinned files are then copied into the evidence and bind-mounted read-only into the trusted containers only (Worker,
Broker, reaper, broker-check), with SITEPROOF_TARGETS / SITEPROOF_CAPTURE_PLAN / SITEPROOF_TARGET_ID pointing at them; the Worker
re-checks both hashes. Even earlier, before the Docker launcher exists (permit_preflight): the signature and the signed ownership record
(permit.ownership_problems; CLOUDFLARE_ACCOUNT_CONTROL also D/real/ownership-evidence.json, byte for byte as pinned) -- a refusal
writes permit-preflight.json, exits 2 and touches no Docker at all. Every gate, window, grant, audit and check below is unchanged; only
the target they are applied to is now the signed one. Without --permit the run is the original TTN top-page configuration, unchanged (legacy exception path).
"""
import argparse
from datetime import datetime, timezone
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
from tests.runtime.browser_bundle import mount_args, stage_browser_bundle, staged_path_problem
from tests.runtime.bundle_probe import run_bundle_probe
from tests.runtime.preflight_checks import head_is_as_expected
from tests.runtime.validate_s2b import S2BLauncher, counters, delta, git, rule_set, tree_digest
from src.noxiworks import permit as permits
from src.noxiworks.baseline_runtime import (BaselineConnectionRefused, candidates_match, comparison_matches, created_matches,
                                            expected_baseline, read_registry)

M5_IMAGE = 'sha256:9c88112b42070369876fdb24476af283b3908a3fdc630b66fedacf4f20c4d2c8'
FORBIDDEN = ('tcp', 'dns', 'udp', 'metadata', 'lan', 'host_model', 'ipv6')
CONNECTED = ('ERR_CERT', 'ERR_SSL', 'ERR_BAD_SSL', 'ERR_HTTP', 'ERR_EMPTY_RESPONSE', 'ERR_RESPONSE')
WINDOW_CAP = 120
TTL = 100
PATH = '/'
IDENTITY_FILES = ('tests/runtime/netpolicy_hardened.py', 'tests/runtime/egress_broker.py', 'tests/runtime/egress_reaper.py',
                  'tests/runtime/s3_worker.py', 'tests/runtime/s3t_worker.py', 'tests/runtime/validate_s3t.py',
                  'src/noxiworks/capture_plan.json', 'src/noxiworks/targets.json', 'src/noxiworks/capture.py', 'src/isolation/site_policy.py',
                  'src/runtime/stability.py', 'src/runtime/service.py', 'src/comparison/service.py', 'src/noxiworks/baseline_runtime.py',
                  'src/noxiworks/permit.py', 'src/noxiworks/product.py')
REGISTRY_MOUNT = '/opt/siteproof-registry'
TARGET_MOUNT = '/opt/siteproof-target'  # permit mode: the two signed-and-pinned target files, read-only, trusted containers only
LEGACY_TARGET_ID, LEGACY_HOST = 'ttn-home', 'ttn-sample.test'


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


CAPTURE_OUTPUT_LIMIT = 68 * 1024 * 1024  # the capture container's stdout: two full-page PNGs (<= RESOURCES.output_bytes) + metadata


# The only profiles ever approved (identical to s3t_worker.APPROVED_PROFILES). A plan may use any subset, in this order.
APPROVED_VIEWPORTS = {'Desktop': (1440, 900), 'Mobile': (390, 844)}


def plan_profile_kinds(page):
    """The capture kinds of a (signed) plan page, in the approved order. Every profile must be exactly an approved full-page profile, once;
    an empty list, an unknown kind, another viewport or a non-full-page profile is refused (ValueError) -- never widened, never guessed."""
    found = {}
    for profile in (page or {}).get('profiles') or []:
        kind = profile.get('kind')
        if (kind not in APPROVED_VIEWPORTS or kind in found or (profile.get('width'), profile.get('height')) != APPROVED_VIEWPORTS[kind]
                or profile.get('full_page') is not True):
            raise ValueError(f'PROFILE_NOT_THE_APPROVED_FULL_PAGE_PROFILE ({kind})')
        found[kind] = profile
    if not found:
        raise ValueError('PLAN_HAS_NO_APPROVED_PROFILE')
    return [kind for kind in APPROVED_VIEWPORTS if kind in found]


def plan_problems(target_dir, target_id):
    try:
        plan = json.loads((Path(target_dir) / 'capture_plan.json').read_text('utf-8'))
        plan_profile_kinds(next(pg for s in plan['sites'] for pg in s['pages'] if pg['page_id'] == target_id))
    except ValueError as exc:  # includes JSON errors
        return [str(exc)]
    except (OSError, StopIteration, KeyError, TypeError):
        return ['capture plan unreadable or the target page is not in it']
    return []


def permit_preflight(permit_file, trust, target_dir, now):
    """Permit mode, before any Docker call: the signature and the signed ownership record (the same permit.py checks the app uses).
    -> list of problems (empty = go on to the Start Gate, which re-verifies the permit and checks everything else)."""
    try:
        permit = permits.verify_signature(permit_file, trust)
    except permits.PermitRefused as exc:
        return [str(exc)]
    problems = permits.ownership_problems(permit, (permit.get('site') or {}).get('host'), target_dir, now)
    # The plan must name only approved profiles: refused here, before any Docker call and before the run is counted against the permit.
    return problems or plan_problems(target_dir, (permit.get('target') or {}).get('target_id'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--image', default=M5_IMAGE)
    parser.add_argument('--gate-only', action='store_true', help='Run GATE-A..C and stop: no navigation, no TCP connection, ever')
    parser.add_argument('--expect', required=True, type=Path, help='Identity values recorded in the limited exception (JSON)')
    parser.add_argument('--baseline-registry', type=Path, help='Formal Baseline registry (compare mode); required iff the identity pins one')
    parser.add_argument('--permit', type=Path, help='Signed monitoring permit (permit.json; permit.json.sig next to it)')
    parser.add_argument('--trust', type=Path, help='OpenSSH allowed_signers file holding the trusted permit signer key')
    parser.add_argument('--target-dir', type=Path, help='Folder holding the targets.json / capture_plan.json the permit pins')
    args = parser.parse_args()
    permit_mode = args.permit is not None
    if permit_mode != (args.trust is not None) or permit_mode != (args.target_dir is not None):
        parser.error('--permit, --trust and --target-dir go together')
    expect = json.loads(args.expect.read_text('utf-8'))
    compare = 'baseline' in expect
    if compare != (args.baseline_registry is not None):
        parser.error('--baseline-registry is required exactly when the identity file pins a Baseline registry')
    evidence = Path(args.evidence).resolve()
    too_long = staged_path_problem(Path.cwd(), evidence)  # before anything is created or counted: a bad placement costs no permit run
    if too_long:
        print('EVIDENCE_PATH_TOO_LONG: ' + too_long)
        raise SystemExit(2)
    evidence.mkdir(parents=True, exist_ok=False)
    if permit_mode:
        refused = permit_preflight(args.permit, args.trust, args.target_dir, datetime.now(timezone.utc))
        (evidence / 'permit-preflight.json').write_text(json.dumps({'refused': refused}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        if refused:
            print('PERMIT_PREFLIGHT_REFUSED: ' + '; '.join(refused))
            raise SystemExit(2)
    root = Path.cwd()
    launch = S2BLauncher(evidence, args.image, root / 'runtime/docker/seccomp-siteproof.json')
    prefix = 'siteproof-m2-s3-' + time.strftime('%H%M%S') + '-' + uuid.uuid4().hex[:6]
    report = {'task': 'SITEPROOF-S3-1C-TTN-TOP-BASELINE-COMPARE-01' if compare else 'SITEPROOF-S3-1T-TTN-TOP-FIRST-CAPTURE-01', 'passed': False, 'baseline_approved': False, 'baseline_compared': False, 'aws_touched': False,
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
        send_control(p['broker'], {'mode': 'system', 'real_site_access': True, 'target_id': target_id, 'hosts': [host], 'device': device, 'ttl': ttl,
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
        permit = None
        if permit_mode:  # the target is the SIGNED one; the files it is read from must be the exact ones the permit pins
            try:
                permit = permits.verify_signature(args.permit, args.trust)
            except permits.PermitRefused as exc:
                raise GateFailed('PERMIT_REFUSED: ' + str(exc)) from None
            now = time.time()
            start, end = permits.parse_utc(permit.get('valid_from') or ''), permits.parse_utc(permit.get('valid_until') or '')
            pins = permit.get('target_files') or {}
            if (permit.get('schema') != permits.SCHEMA or not (start and end and start.timestamp() <= now < end.timestamp())
                    or any(pins.get(n) != (permits.sha(args.target_dir / n) if (args.target_dir / n).is_file() else None) for n in permits.TARGET_FILES)):
                raise GateFailed('PERMIT_SCOPE_REFUSED: schema, validity window or pinned target files differ')
            target_id, targets = permit['target']['target_id'], json.loads((args.target_dir / 'targets.json').read_text('utf-8'))
        else:
            target_id, targets = LEGACY_TARGET_ID, json.loads((root / 'src/noxiworks/targets.json').read_text('utf-8'))
        page = next(x for x in targets['pages'] if x['target_id'] == target_id)
        if permit_mode:  # the policy the Worker must report is the pinned plan's own (normalised as the Worker's loader does)
            from src.runtime.stability import policy as stability_policy
            plan_doc = json.loads((args.target_dir / 'capture_plan.json').read_text('utf-8'))
            plan_page = next(pg for s in plan_doc['sites'] for pg in s['pages'] if pg['page_id'] == target_id)
            expected_stability = stability_policy(plan_page.get('stability'))
            try:
                kinds = plan_profile_kinds(plan_page)  # the signed plan's profiles only (Desktop, Mobile, or both): nothing else is ever captured
            except ValueError as exc:
                raise GateFailed(str(exc)) from None
        else:
            expected_stability = expect['stability_policy']
            kinds = list(APPROVED_VIEWPORTS)  # the legacy exceptions captured both
        site = next(x for x in targets['sites'] if x['site_id'] == page['site_id'])
        host = re.match(r'https://([a-z0-9.-]+)/\Z', page['url'])[1]
        expected_host = permit['site']['host'] if permit_mode else LEGACY_HOST
        if permit_mode and (page['url'] != permit['target']['url'] or site['site_id'] != permit['site']['site_id']
                            or site['origin'] != permit['site']['origin'] or host != expected_host):
            raise GateFailed('PERMIT_TARGET_DIFFERS_FROM_THE_TARGET_FILES')
        base_url = page['url']
        target_url = 'https://' + host + PATH
        src_digest, src_files = tree_digest(root / 'src')
        rt_digest, rt_files = tree_digest(root / 'tests/runtime')
        launch.save('start-gate.json', {
            'branch': git('branch', '--show-current').strip(), 'head': head, 'uncommitted_entries': len(git('status', '--short', '-uall').splitlines()),
            'target': {'target_id': page['target_id'], 'site': {k: site.get(k) for k in ('site_id', 'name', 'origin')}, 'host': host, 'port': 443, 'path': PATH, 'url': target_url,
                       'approved_by_user': (f"signed permit {permit['permit_id']} by {permit['issued_by']}" if permit_mode else '2026-11-18')},
            'allowed_destinations': [{'hostname': host, 'port': 443}], 'wildcards': 0, 'auto_added_hosts': 0, 'credentials': 'none',
            'flag_in_source': re.search(r'^REAL_SITE_ACCESS_ENABLED = (\w+)', sp_text, re.M)[1],
            'formal_gates': {'LOCAL-ISOLATION': 'NOT VERIFIED (unchanged by this run; the pre-navigation GATE below is a run-local measurement)'},
            'overlay': {'src': {'sha256': src_digest, 'files': src_files}, 'tests/runtime': {'sha256': rt_digest, 'files': rt_files}},
            'window_cap_seconds': WINDOW_CAP, 'grant_ttl_seconds': TTL, 'max_grants': 1})
        files_now = {rel: hashlib.sha256((root / rel).read_bytes()).hexdigest() for rel in IDENTITY_FILES}
        launch.save('identity-files.json', files_now)
        if files_now != expect['files']:
            raise GateFailed('CONFIGURATION_DIFFERS_FROM_THE_EXCEPTION: ' + ', '.join(k for k in files_now if files_now[k] != expect['files'].get(k)))
        registry_mount = []
        if compare:
            try:
                record = read_registry(args.baseline_registry)
            except BaselineConnectionRefused as exc:
                raise GateFailed('BASELINE_REGISTRY_REFUSED: ' + str(exc)) from None
            pinned = {**expected_baseline(record),
                      'registry_export_sha256': hashlib.sha256((args.baseline_registry / 'export-sha256.json').read_bytes()).hexdigest()}
            launch.save('baseline-registry.json', pinned)
            if pinned != expect['baseline']:
                raise GateFailed('BASELINE_REGISTRY_DIFFERS_FROM_THE_EXCEPTION')
            checks['I_baseline_registry_identical_to_the_recorded_exception'] = True
            registry_mount = ['--mount', f'type=bind,src={args.baseline_registry.resolve()},dst={REGISTRY_MOUNT},readonly']
        if permit_mode:
            try:
                derived = permits.check_expect(permit, expect, pinned if compare else None)
            except permits.PermitRefused as exc:
                raise GateFailed('PERMIT_REFUSED: ' + str(exc)) from None
            if not derived:
                raise GateFailed('EXPECT_IS_NOT_THE_PERMIT_IDENTITY')
            checks['P_signed_permit_target_files_and_expect_verified'] = True
            # Count this run against the permit (shared, locked ledger next to the trust file) BEFORE any container or network: a direct
            # invocation of this harness cannot exceed max_runs, and a run that fails later stays counted (fail-closed).
            try:
                runs_used = permits.reserve_run(args.trust, permit, evidence.name, time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
            except permits.PermitRefused as exc:
                raise GateFailed('PERMIT_RUNS_REFUSED: ' + str(exc)) from None
            launch.save('permit-run.json', {'permit_id': permit['permit_id'], 'runs_used': runs_used, 'max_runs': permit['max_runs']})
            checks['P_run_counted_against_the_permit_before_any_container'] = True
        checks['I_files_identical_to_the_recorded_exception'] = True
        checks['flag_false_in_source_at_start'] = re.search(r'^REAL_SITE_ACCESS_ENABLED = False$', sp_text, re.M) is not None
        checks['target_is_the_single_registered_ttn_host_and_exact_path'] = (host == expected_host and site['origin'] == 'https://' + host
                                                                             and '*' not in host and target_url == 'https://' + host + '/' and target_url == page['url'])
        image = json.loads(launch.call('image', 'inspect', launch.image))[0]
        launch.image = image['Id']
        if image['Id'] != expect['image_id'] or image['Id'] != M5_IMAGE:
            raise GateFailed('IMAGE_DIFFERS_FROM_THE_EXCEPTION')
        checks['I_image_identical_to_the_recorded_exception'] = True
        launch.save('run-conditions.json', {'docker_server': launch.call('version', '--format', '{{.Server.Version}}').strip(), 'host': platform.platform(), 'image_id': image['Id'],
                                            'git_head': head, 'run_prefix': prefix, 'no_pull_build': True, 'no_privileged_no_host_network_no_docker_socket': True,
                                            'network': 'NEW labelled bridge (not --internal); egress only through Broker-issued per-IP OS grants in this namespace'})
        overlay = []
        for rel in ('src', 'tests/runtime'):
            overlay += ['--mount', f'type=bind,src={(root / rel).resolve()},dst=/opt/siteproof/{rel},readonly']
        target_env = []
        if permit_mode:  # a frozen copy of exactly the pinned files (re-hashed), never the live folder
            staged = evidence / 'permit-target'
            staged.mkdir()
            for n in permits.TARGET_FILES:
                (staged / n).write_bytes((args.target_dir / n).read_bytes())
                if permits.sha(staged / n) != permit['target_files'][n]:
                    raise GateFailed('PERMIT_TARGET_FILE_CHANGED_WHILE_STAGING')
            (staged / 'permit.json').write_bytes(args.permit.read_bytes())
            overlay += ['--mount', f'type=bind,src={staged.resolve()},dst={TARGET_MOUNT},readonly']
            target_env = ['--env', f'SITEPROOF_TARGETS={TARGET_MOUNT}/targets.json', '--env', f'SITEPROOF_CAPTURE_PLAN={TARGET_MOUNT}/capture_plan.json',
                          '--env', f'SITEPROOF_TARGET_ID={target_id}', '--env', f"SITEPROOF_TARGET_SHA256={permit['target_files']['targets.json']}",
                          '--env', f"SITEPROOF_PLAN_SHA256={permit['target_files']['capture_plan.json']}"]
        network = launch.create_network(prefix + '-network')
        volume = launch.create_volume(prefix + '-evidence')
        init = launch.create(name('volume-init'), ['--network', 'none', '--user', '0:0', '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--security-opt', 'no-new-privileges=true',
                                                   '--read-only', '--mount', f'type=volume,src={volume},dst=/evidence'],
                             ['python', '-c', "import os;os.chmod('/evidence',0o700);os.chown('/evidence',1001,1001)"])
        launch.bounded(init)
        launch.retire(init)
        anchor = launch.create(name('worker'), [*overlay, *registry_mount, '--network', network, '--user', '1001:1001', '--cap-drop', 'ALL',
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
        bundle_sha = hashlib.sha256((evidence / 'browser-bundle' / 'MANIFEST.json').read_bytes()).hexdigest()
        launch.save('identity-bundle.json', {'manifest_sha256': bundle_sha, 'file_count': bundle_manifest['file_count']})
        if bundle_sha != expect['bundle_manifest_sha256']:
            raise GateFailed('BROWSER_BUNDLE_DIFFERS_FROM_THE_EXCEPTION')  # Before any window and any Browser container start.
        checks['I_browser_bundle_identical_to_the_recorded_exception'] = True
        mounts = [*mount_args(bundle_tree), '--mount', f'type=bind,src={resolver_file},dst=/etc/resolv.conf,readonly']
        s0 = snap()
        baseline_rules = rule_set(s0)
        launch.save('closed-baseline-rules.json', {'rules': baseline_rules, 'counters': counters(s0)})
        privileged = launch.options(anchor, 0, mounts=overlay) + ['--cap-add', 'NET_ADMIN'] + target_env
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
        other = 'noxiworks-sample.test' if host != 'noxiworks-sample.test' else 'example.org'  # a real, registered-elsewhere host that must still be refused
        for bad in ({'hosts': ['example.com'], 'max_grants': 1}, {'hosts': [host], 'max_grants': 2}, {'hosts': [host, 'www.' + host], 'max_grants': 1}, {'hosts': [other], 'max_grants': 1}):
            try:
                out, _ = launch.bounded(broker_check, json.dumps({'mode': 'system', 'real_site_access': True, 'target_id': target_id, 'device': device, 'ttl': TTL, **bad}).encode() + b'\n', seconds=20)
                ok &= b'"ready"' not in out
            except Exception:
                pass  # The daemon exits non-zero before announcing readiness.
        checks['A_broker_refuses_any_configuration_but_the_single_registered_host'] = ok
        # Gate: what the Browser can see of the project, measured from inside a Browser-flagged container (before any real-site contact).
        bundle_checks, bundle_record = run_bundle_probe(launch, name('bundle-check'), bundle_tree, bundle_manifest, resolver_file, launch.save)
        for key, value in bundle_checks.items():
            checks['A_' + key] = value
        checks['A_bundle_minimal_and_no_fixture_ca_mounted_for_the_real_run'] = 0 < bundle_manifest['file_count'] < 45 and not any('fixture-ca' in str(m) for m in mounts)
        if compare:
            # The registry is a trusted-side input only: never mounted into a Browser-UID container, read-only in the Worker container.
            registry_tail = str(args.baseline_registry.resolve()).replace('\\', '/').split(':')[-1].lower()

            def registry_mounts(container):
                found = json.loads(launch.call('inspect', container))[0].get('Mounts') or []
                return [m for m in found if m.get('Destination') == REGISTRY_MOUNT or registry_tail in str(m.get('Source', '')).replace('\\', '/').lower()]
            in_browser = [m for c in (browser, api_browser, chromium, capture_c) for m in registry_mounts(c)]
            in_worker = registry_mounts(anchor)
            launch.save('registry-mounts.json', {'browser_containers': in_browser, 'worker_container': in_worker,
                                                 'bundle_probe_mount_points': sorted({m['dest'] for m in bundle_record['result']['mounts']})})
            checks['A_registry_never_mounted_into_a_browser_container'] = (in_browser == [] and REGISTRY_MOUNT not in
                                                                          {m['dest'] for m in bundle_record['result']['mounts']})
            checks['A_registry_mounted_read_only_into_the_trusted_worker_only'] = (len(in_worker) == 1 and in_worker[0].get('RW') is False
                                                                                  and in_worker[0].get('Destination') == REGISTRY_MOUNT)
        start_broker(ttl=TTL)
        worker_log = (evidence / 'worker-stderr.log').open('wb')
        registry_env = ['--env', 'SITEPROOF_BASELINE_REGISTRY=' + REGISTRY_MOUNT] if compare else []
        p['worker'] = subprocess.Popen(launch.cli + ['exec', '-i', '--user', '1001:1001', *registry_env, *target_env, anchor, 'python', '-m', 'tests.runtime.s3t_worker'],
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

        # ================================================================== CAPTURE (the signed plan's profiles: Desktop, then Mobile), one short window each
        assert wcontrol({'type': 'stop_real'})['flag_after_stop'] is False
        created = wcontrol({'type': 'create'})
        launch.save('workspace-created.json', created)
        checks['S_workspace_url_is_the_exact_target'] = created['url'] == target_url
        plan_pin = permit['target_files']['capture_plan.json'] if permit_mode else expect['files']['src/noxiworks/capture_plan.json']
        targets_pin = permit['target_files']['targets.json'] if permit_mode else expect['files']['src/noxiworks/targets.json']
        checks['S_workspace_is_ttn_home_with_the_checked_plan'] = (created['page_id'] == target_id and created['plan_sha256'] == plan_pin
                                                                    and created['targets_sha256'] == targets_pin)
        if not (checks['S_workspace_url_is_the_exact_target'] and checks['S_workspace_is_ttn_home_with_the_checked_plan']):
            raise GateFailed('WORKSPACE_NOT_THE_APPROVED_TOP_PAGE')
        if compare:
            checks['S_workspace_staged_from_the_pinned_registry_and_every_profile_bound'] = created_matches(created.get('baseline'), expect['baseline'])
            if not checks['S_workspace_staged_from_the_pinned_registry_and_every_profile_bound']:
                raise GateFailed('BASELINE_NOT_BOUND: no capture without the formal Baseline')
        elif created.get('baseline') is not None:
            raise GateFailed('UNEXPECTED_BASELINE_STAGING')
        jobs, results = {}, {}
        for kind in kinds:
            prep = wcontrol({'type': 'prepare', 'kind': kind})
            launch.save(f'{kind}-prepared.json', prep)
            jobs[kind] = prep
            attrs = prep['profile']['attributes']
            if not (prep['url'] == target_url and attrs['full_page'] is True
                    and (attrs['viewport_width'], attrs['viewport_height']) == APPROVED_VIEWPORTS[kind]):
                raise GateFailed(f'PROFILE_NOT_THE_APPROVED_FULL_PAGE_PROFILE ({kind})')  # Before this capture window opens.
            checks[f'K{kind[0]}_prepared_profile_is_the_approved_full_page_profile'] = True
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
                    out, _ = launch.bounded(capture_c, json.dumps(cfg).encode() + b'\n', seconds=min(80, msg['remaining']), limit=CAPTURE_OUTPUT_LIMIT, evidence_sink=lambda o, e, x, path=path: (
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
                                         'runtime': meta['browser_report'].get('runtime'), 'request_audit': audit, 'diagnostics': meta.get('diagnostics')})
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
            results[kind] = {'job': job, 'network_audit': audit_ev, 'granted_ips': sorted(ips), 'capture_meta': capture_meta, 'baselines': msg['baselines'], 'capture_info': msg['capture_info'].get(prep['job_id']),
                             'comparison': next((r for r in msg['comparison']['results'] if r.get('job_id') == prep['job_id']), None),
                             'exports': msg.get('comparison_exports') or {}}
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
            # Stability (SP-D52): the trusted check ran and reached the comparison. UNSTABLE is a valid, recorded outcome (UNKNOWN), never re-run.
            stab = (results[kind]['capture_info'] or {}).get('stability') or {}
            comp = results[kind]['comparison'] or {}
            checks[f'K{k}_stability_verified_by_the_trusted_side_with_the_plan_policy'] = (
                stab.get('value') in ('STABLE', 'UNSTABLE') and stab.get('source') == 'worker:stability-policy-v1'
                and stab.get('policy') == expected_stability and comp.get('capture_stability') == stab
                and (stab['value'] == 'STABLE') == ('CAPTURE_UNSTABLE' not in comp.get('reasons', [])))
            if compare:
                checks[f'K{k}_candidate_saved_pending_and_only_the_registry_baselines_approved'] = candidates_match(msg['baselines'], prep['job_id'], expect['baseline'])
                checks[f'K{k}_compared_with_the_formal_baseline_of_this_profile'] = comparison_matches(comp, kind, expect['baseline'])
            else:
                checks[f'K{k}_candidate_saved_and_not_approved'] = any(b['candidate_id'] == 'capture-' + prep['job_id'] and b['approval_state'] != 'APPROVED' for b in msg['baselines']) and not any(b['approval_state'] == 'APPROVED' for b in msg['baselines'])
        report['captures'] = {k: {'job_id': v['job']['job_id'], 'execution': v['job']['execution'], 'reason': v['job']['reason'], 'quality': v['job']['quality'], 'granted_ips': v['granted_ips'],
                                  'runtime': ((v['capture_meta'] or [{}])[0].get('runtime')),
                                  'stability': (v['capture_info'] or {}).get('stability'),
                                  'comparison_reasons': (v['comparison'] or {}).get('reasons'),
                                  'operational_verdict': ((v['comparison'] or {}).get('operational') or {}).get('verdict'),
                                  'operational_reasons': ((v['comparison'] or {}).get('operational') or {}).get('reasons'),
                                  'baseline': (v['comparison'] or {}).get('baseline'), 'metrics': (v['comparison'] or {}).get('metrics'),
                                  'browser_audit_summary': next(({kk: e['browser_audit'].get(kk) for kk in ('source', 'complete', 'requests', 'finished', 'pending', 'failed', 'http_errors', 'script_errors')} for e in v['job']['events']
                                                                 if 'browser_audit' in e and isinstance(e['browser_audit'], dict)), None),
                                  'network_audit_summary': {kk: (v['network_audit'] or {}).get(kk) for kk in ('complete', 'allowed', 'blocked', 'failed', 'idle', 'in_flight', 'entries')}} for k, v in results.items()}
        checks['flag_false_in_source_at_end'] = (root / 'src/isolation/site_policy.py').read_text('utf-8') == sp_text
        # ---- export the workspace (images, evidence, candidates) and build the local review page
        wcontrol({'type': 'quit'})
        p['worker'].stdin.close()
        p['worker'].wait(timeout=20)
        p['worker'] = None
        launch.call('cp', anchor + ':/evidence/ws', str(evidence / 'workspace'), timeout=120)
        if compare:
            for kind, v in results.items():
                diff_sha = (v['comparison'] or {}).get('diff_sha256')
                names = [n for n, x in v['exports'].items() if x['job_id'] == v['job']['job_id']]
                ok = names == ([f'{kind}-diff.png'] if diff_sha else [])
                for n in names:
                    launch.call('cp', anchor + ':/evidence/exports/' + n, str(evidence / n), timeout=60)
                    ok = ok and hashlib.sha256((evidence / n).read_bytes()).hexdigest() == v['exports'][n]['sha256'] == diff_sha
                checks[f'K{kind[0]}_diff_exported_and_matches_the_comparison'] = ok
            report['baseline_compared'] = all(comparison_matches(v['comparison'], kind, expect['baseline']) for kind, v in results.items())
        review = evidence / 'review'
        review.mkdir()
        rows = []
        for kind, v in results.items():
            ev = v['job']['evidence']
            png = (evidence / 'workspace' / ev['artifact_ref']) if ev else None
            data = png.read_bytes() if png and png.exists() else b''
            size = png_size(data)
            vw, vh = APPROVED_VIEWPORTS[kind]
            ok_png = bool(data) and hashlib.sha256(data).hexdigest() == ev['digest'] and size is not None and size[0] == vw and size[1] >= vh
            checks[f'K{kind[0]}_png_exported_and_matches_the_stored_digest'] = ok_png
            if ok_png:
                (review / f'{kind.lower()}.png').write_bytes(data)
            candidate = next((b for b in v['baselines'] if b['candidate_id'] == 'capture-' + v['job']['job_id']), {})
            rows.append((kind, v, ev, png_size(data), candidate))
        css = 'body{font:15px/1.5 system-ui,sans-serif;margin:24px;max-width:1500px}img{max-width:100%;border:1px solid #888}table{border-collapse:collapse;margin:8px 0}td,th{border:1px solid #bbb;padding:3px 8px;text-align:left}code{background:#eee;padding:0 3px}.warn{background:#fff3cd;border:1px solid #d9b95c;padding:8px 12px}'
        parts = ['<!doctype html><html lang="ja"><meta charset="utf-8"><title>S3-1T TTN トップページ 初回撮影（Baseline候補・未承認）</title><style>' + css + '</style>',
                 '<h1>S3-1T 初回撮影：Tokyo Trouble Navi トップページ <code>/</code>（ページ全体）</h1>',
                 '<p class="warn"><b>Baseline候補（未承認）</b>です。承認は行っていません。撮影条件は未認証（PROFILE_UNATTESTED）で、品質判定はUNKNOWN。画像が正常に描画されているかはUSERが目視で判断してください。LOCAL-ISOLATION は NOT VERIFIED のままです。</p>',
                 f'<p>対象URL: <code>{html.escape(target_url)}</code>（HTTPS/443、許可ホスト1つ）</p>']
        for kind, v, ev, size, cand in rows:
            summary = report['captures'][kind]
            parts.append(f'<h2>{kind}</h2><table>' + ''.join(f'<tr><th>{html.escape(a)}</th><td>{html.escape(str(b))}</td></tr>' for a, b in (
                ('job_id', v['job']['job_id']), ('実行結果', v['job']['execution']), ('PNG sha256', ev['digest'] if ev else None), ('PNG サイズ(px)', size),
                ('プロファイル', json.dumps(v['job']['profile']['attributes'], ensure_ascii=False)), ('fingerprint', v['job']['fingerprint']),
                ('Chromium', ((v['capture_meta'] or [{}])[0].get('sandbox') or {}).get('browser_version')),
                ('Baseline候補', cand.get('candidate_id')), ('承認状態', cand.get('approval_state')), ('品質', v['job']['quality']),
                ('正式Baselineとの比較', json.dumps({kk: summary.get(kk) for kk in ('baseline', 'operational_verdict', 'operational_reasons', 'metrics')}, ensure_ascii=False) if compare else '比較なし（比較モードではありません）'),
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
