"""One isolated HTTP check: a one-shot set of small containers whose network is closed by the operating system except for ONE granted address:443.

The only way HTTP monitoring may reach a real site (the in-process / child-process probe of Sprint 02 is not used for real requests any more). No
browser and no image comparison: the existing pieces of the measured image-capture boundary are reused UNCHANGED, with a tiny Worker in place of Chromium:
  netns anchor    a sleeping container that owns the run's network namespace (it ends by itself; removing it destroys the namespace)
  OS rules        tests/runtime/netpolicy_hardened.py (short-lived NET_ADMIN helper): default DROP IPv4+IPv6; UID 1000 reaches only the proxy port;
                  UID 1001 reaches nothing but broker-granted /32:443; resolver and broker separated; every drop counted
  Grant Broker    tests/runtime/egress_broker.py: the only resolver, the only one that can open an address (one, IPv4, global, 443, TTL)
  Reaper          tests/runtime/egress_reaper.py: closes the window on deadline / host death / command, independent of everything else
  CONNECT proxy   src/isolation/http_proxy_worker.py (UID 1001): ConnectTransport + brokered resolver for this ONE host; its ledger is the audit
  HTTP Worker     src/isolation/http_probe_worker.py (UID 1000): one TLS request end to end, status line only

Order: kill switch -> engine + exact image -> bundle staged -> everything started CLOSED and the OS rule set checked -> Grant v2 + ledger reservation
(http_authority.authorize; counted before any window) -> reaper -> window -> lease -> one request -> proxy audit, broker state, OS counters -> window closed,
rule set equal to the closed one again -> containers and network removed. judge() turns the records into the result: anything that is not exactly the
expected record (a drop counted for the Worker, more than one grant, another address, an unconfirmed close or removal ...) is ISOLATION_VIOLATION: no
observation of the site, and the monitor stops. The engine or image missing is not a check at all: nothing is counted, nothing is asked.
The container gets: the staged import closure (read-only), no repository, no data folder, no key, no Docker socket, no capability (broker, reaper and policy
helper: NET_ADMIN only). A CONNECT proxy cannot see a path: the path is fixed by the grant and this code, the host:443 by the network boundary.
Fixture measurement (tests/runtime/validate_http_iso.py, --internal network, no real site): GREEN 18/18 on 2026-11-26 (.local/http-iso-run-04). NOT measured
against a real site yet (docs/HTTP_BOUNDARY.md M3); results of the image capture are no evidence here.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid

from src.aws_b.model import format_utc
from src.noxiworks import filelock, http_authority

ROOT = Path(__file__).resolve().parents[2]
PROXY_PORT = 18080
PROBE_TIMEOUT = 8
GRANT_TTL, REAPER_DEADLINE, ANCHOR_SECONDS = 30, 40, 180
SLOTS = 3  # isolated checks at the same time per data folder
ENTRIES = ('src/isolation/http_probe_worker.py', 'src/isolation/http_proxy_worker.py', 'tests/runtime/egress_broker.py', 'tests/runtime/egress_reaper.py',
           'tests/runtime/netpolicy_hardened.py')
WORKER_ENTRIES = ('src/isolation/http_probe_worker.py',)
TARGETS_IN = '/opt/siteproof-target/targets.json'
NEVER_COUNTED = ('SP_BROWSER_TCP_DROP', 'SP_BROWSER_UDP_DROP', 'SP_BROWSER_DNS_DROP', 'SP_BROWSER_IPV6_DROP', 'SP_WORKER_DNS_DROP', 'SP_TRUSTED_NONPUBLIC_DROP')
REQUIRED_RULES = ('SP_BROWSER_TCP_DROP', 'SP_BROWSER_UDP_DROP', 'SP_BROWSER_DNS_DROP', 'SP_BROWSER_IPV6_DROP', 'SP_WORKER_DNS_DROP')
CAPS = {'CapEff:': '0000000000000000', 'CapBnd:': '0000000000000000', 'NoNewPrivs:': '1', 'Seccomp:': '2'}


class NotRun(RuntimeError):
    """Nothing was asked of the site and nothing was counted. code: EXTERNAL_DISABLED | ENGINE_UNAVAILABLE | IMAGE_UNAVAILABLE | BUSY | SETUP_FAILED."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


def pinned_image():
    """The image ID the capture harness is pinned to (read from its source): the same, already present image. Never pulled, built or tagged here."""
    from tools.permit_draft import harness_constants
    return harness_constants()[1]


# ---- Docker (the existing launcher; its own resources are removed again: a check every 5 minutes must not leave anything behind)
class Attached:
    """A container started with its stdin/stdout held by the host: closing it is EOF for the container (the reaper then closes the window)."""

    def __init__(self, cli, name, log):
        self.log = open(log, 'wb')
        self.p = subprocess.Popen(cli + ['start', '-a', '-i', name], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log,
                                  creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))

    def ask(self, obj, seconds=30):
        from src.runtime.docker_launcher import read_control, send_control
        send_control(self.p, obj)
        return read_control(self.p, seconds)

    def read(self, seconds=30):
        from src.runtime.docker_launcher import read_control
        return read_control(self.p, seconds)

    def close(self, wait=15):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(timeout=wait)
        except subprocess.TimeoutExpired:
            self.p.kill()
        self.log.close()


def launcher(evidence, internal_subnet=None):
    """DockerLauncher with a bridge (or, for fixtures, --internal) network and removal of exactly its own recorded containers and network."""
    from src.runtime.docker_launcher import DockerLauncher, LABEL

    class HttpLauncher(DockerLauncher):
        def create_network(self, name):
            extra = ['--internal', '--subnet', internal_subnet] if internal_subnet else []
            ident = self.call('network', 'create', *extra, '--label', LABEL, '--label', 'siteproof.http=1', name).strip()
            self.record('network', name, ident)
            return name

        def attach(self, name):
            return Attached(self.cli, name, self.evidence / (name[-24:] + '.stderr.log'))

        def remove_all(self):
            """-> names that could not be confirmed as gone. Only IDs recorded by this run are touched; images and volumes never."""
            left = []
            for name, record in reversed(list(self.resources.items())):
                try:
                    if record['kind'] == 'container':
                        self.stop(name)
                        self.call('rm', record['id'])
                    elif record['kind'] == 'network':
                        self.call('network', 'rm', record['id'])
                except Exception:
                    left.append(name)
            return left

        def image_id(self):
            return json.loads(self.call('image', 'inspect', self.image))[0]['Id']
    return HttpLauncher(evidence, pinned_image(), ROOT / 'runtime/docker/seccomp-siteproof.json')


# ---- the run
def closed_problems(snapshot, device):
    """The closed rule set must be what netpolicy_hardened prepares: default DROP everywhere, the drop rules present, no way out on the egress device."""
    problems = []
    for family in ('ipv4', 'ipv6'):
        text = snapshot.get(family) or ''
        for chain in ('INPUT', 'OUTPUT', 'FORWARD'):
            if not re.search(r'^:%s DROP ' % chain, text, re.M):
                problems.append(f'{family}:{chain}:POLICY')
    both = (snapshot.get('ipv4') or '') + chr(10) + (snapshot.get('ipv6') or '')
    problems += ['MISSING:' + r for r in REQUIRED_RULES if r not in both]
    if snapshot.get('grant_rules'):
        problems.append('GRANT_PRESENT')
    for line in both.splitlines():
        if re.search(r'-A (OUTPUT|INPUT) ', line) and re.search(r'-[oi] %s\b' % re.escape(device), line) and line.rstrip().endswith('-j ACCEPT'):
            problems.append('EGRESS_ACCEPT_PRESENT')
    return problems


def stage(run_dir):
    """Two read-only trees: the Worker's own closure, and the trusted side's (proxy, broker, reaper, rules). Nothing else of the repository is mounted."""
    from tests.runtime.browser_bundle import MAX_STAGED_PATH, import_closure, stage_browser_bundle
    trusted, _ = stage_browser_bundle(ROOT, run_dir / 't', ENTRIES)
    worker, _ = stage_browser_bundle(ROOT, run_dir / 'w', WORKER_ENTRIES)
    longest = max(len(str(p)) for tree in (trusted, worker) for p in tree.rglob('*'))
    if longest > MAX_STAGED_PATH:
        raise NotRun('SETUP_FAILED', f'データフォルダのパスが長すぎます（{longest}文字、上限{MAX_STAGED_PATH}文字）。短いパスに移してください')
    return trusted, worker


def mount(src, dst):
    return ['--mount', f'type=bind,src={Path(src).resolve()},dst={dst},readonly']


def isolated_check(docker, run_dir, *, host, path, reserve, mode='system', broker=None, worker_job=None, peers=None, clock=time.monotonic):
    """Run one check. `reserve()` is called once, with everything closed and checked, right before the window (raises Refused -> nothing is opened).
    `broker` / `worker_job` / `peers` carry the fixture parts of tests/runtime/validate_http_iso.py. -> record (dict); never raises after the reservation."""
    from tests.runtime.validate_s2b import counters, delta, rule_set
    prefix = 'siteproof-m2-http-' + uuid.uuid4().hex[:10]
    rec = {'schema': 'siteproof.http-isolation.v1', 'prefix': prefix, 'host': host, 'mode': mode, 'step': 'START', 'window': None, 'reserved': None, 'problems': []}
    held, names = {}, {}
    n = [0]

    def create(label, uid, module, mounts, admin=False, env=()):
        n[0] += 1
        options = docker.options(anchor, uid, memory='256m', pids=64, mounts=mounts) + (['--cap-add', 'NET_ADMIN'] if admin else []) + list(env)
        names[label] = docker.create(f'{prefix}-{label}-{n[0]}', options, ['python', '-m', module])
        return names[label]

    def policy(kind, **kw):
        out, _ = docker.bounded(names['policy'], json.dumps({'type': kind, 'netns': rec['netns'], **kw}).encode() + b'\n')
        return json.loads(out)

    try:
        rec['step'] = 'STAGE'
        trusted, worker = stage(run_dir)
        target_dir = run_dir / 'target'
        target_dir.mkdir()
        # The broker's own check is "exactly the registered host": it gets a file that names this one host and nothing else (never a path).
        (target_dir / 'targets.json').write_text(json.dumps({'pages': [{'target_id': 'http', 'url': f'https://{host}/'}]}), encoding='utf-8')
        tmounts, wmounts = mount(trusted, '/opt/siteproof'), mount(worker, '/opt/siteproof')
        (run_dir / 'resolv.conf').write_text('nameserver 127.0.0.3\noptions timeout:1 attempts:1\n', encoding='ascii')
        rec['step'] = 'NETWORK'
        network = docker.create_network(prefix + '-net')
        anchor = docker.create(prefix + '-anchor', ['--network', network, '--user', '1001:1001', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true', '--read-only',
                                                    '--pids-limit', '16', '--memory', '64m', '--memory-swap', '64m', '--cpus', '.5', '--sysctl', 'net.ipv6.conf.all.disable_ipv6=0',
                                                    '--sysctl', 'net.ipv4.ip_unprivileged_port_start=0', *(peers['anchor'] if peers else ())],
                               ['python', '-c', f'import time;time.sleep({ANCHOR_SECONDS})'])  # ends by itself even if this host process is gone
        docker.call('start', anchor)
        if peers:
            peers['start'](docker, network, prefix, rec)
        rec['netns'] = docker.call('exec', anchor, 'readlink', '/proc/self/ns/net').strip()
        rec['step'] = 'RULES'
        create('policy', 0, 'tests.runtime.netpolicy_hardened', tmounts, admin=True)
        prepared = policy('prepare')
        if len(prepared['devices']) != 1:
            raise RuntimeError('exactly one egress device expected')
        device = prepared['devices'][0]
        if peers:
            policy('fixture_routes', fixture=True, device=device)
        closed = policy('install', proxy_ports=[PROXY_PORT])
        rec['problems'] += ['CLOSED:' + p for p in closed_problems(closed, device)]
        if rec['problems']:
            raise RuntimeError('closed rule set is not the expected one')
        base_rules, c0 = rule_set(closed), counters(closed)
        rec['step'] = 'CONTROLS'
        admin_env = [*mount(target_dir, '/opt/siteproof-target'), '--env', 'SITEPROOF_TARGETS=' + TARGETS_IN]
        create('broker', 0, 'tests.runtime.egress_broker', [*tmounts, *admin_env], admin=True)
        create('reaper', 0, 'tests.runtime.egress_reaper', tmounts, admin=True)
        create('proxy', 1001, 'src.isolation.http_proxy_worker', tmounts)
        create('worker', 1000, 'src.isolation.http_probe_worker', [*wmounts, *mount(run_dir / 'resolv.conf', '/etc/resolv.conf')])
        rec['worker_mounts'] = sorted((m.get('Destination'), bool(m.get('RW'))) for m in docker.inspect(names['worker']).get('Mounts') or [])
        held['broker'] = docker.attach(names['broker'])
        ready = held['broker'].ask({**(broker or {'mode': 'system', 'real_site_access': True, 'target_id': 'http', 'hosts': [host], 'ttl': GRANT_TTL, 'max_grants': 1}), 'device': device})
        if ready.get('type') != 'ready':
            raise RuntimeError('broker not ready')
        held['proxy'] = docker.attach(names['proxy'])
        proxy_ready = held['proxy'].ask({'mode': mode, 'host': host, 'lease': 'http', 'port': PROXY_PORT})
        if proxy_ready.get('type') != 'ready' or proxy_ready.get('netns') != rec['netns'] or proxy_ready.get('uid') != 1001:
            raise RuntimeError('proxy not ready')
        before = policy('snapshot')
        if rule_set(before) != base_rules or before.get('grant_rules'):
            raise RuntimeError('rules changed before the window')
        rec['step'] = 'RESERVE'
        rec['reserved'] = reserve()  # Refused leaves everything closed
        rec['step'] = 'WINDOW'
        held['reaper'] = docker.attach(names['reaper'])
        if held['reaper'].ask({'netns': rec['netns'], 'device': device, 'deadline': REAPER_DEADLINE}).get('type') != 'ready':
            raise RuntimeError('reaper not ready')
        opened = clock()
        rec['window'] = {'opened_at': format_utc(datetime.now(timezone.utc).replace(microsecond=0)), 'closed_by': None}
        policy('egress_open', device=device)
        if held['broker'].ask({'type': 'enable'}).get('type') != 'enabled' or held['broker'].ask({'type': 'lease_open', 'lease': 'http', 'hosts': [host]}).get('ok') is not True:
            raise RuntimeError('lease refused')
        rec['step'] = 'PROBE'
        if peers and peers.get('during'):
            peers['during'](docker, create, tmounts, held, rec, policy)  # fixture runs only: the negative probes, with the window open
        try:
            out, _ = docker.bounded(names['worker'], json.dumps({'host': host, 'path': path, 'proxy_port': PROXY_PORT, 'timeout': PROBE_TIMEOUT, **(worker_job or {})}).encode() + b'\n',
                                    seconds=PROBE_TIMEOUT + 10, limit=64 * 1024)
            rec['worker'] = json.loads(out)
        except Exception as exc:
            rec['worker'] = {'error': type(exc).__name__}
        rec['step'] = 'AUDIT'
        rec['proxy'] = held['proxy'].ask({'type': 'audit'})
        during = policy('snapshot')
        rec['grants'] = [m[1] for r in during.get('grant_rules') or [] for m in [re.search(r'-d (\S+)/32', r)] if m]
        rec['broker'] = held['broker'].ask({'type': 'state'}).get('state')
        rec['step'] = 'CLOSE'
        rec['broker_close'] = held['broker'].ask({'type': 'close'})
        after = policy('egress_close', device=device)
        rec['reaper'] = held['reaper'].ask({'type': 'cancel'}, 15)
        final = policy('snapshot')
        seen = [delta(counters(s), c0) for s in (during, final)]  # the window's own rules (and their counters) are gone after the close
        rec['drops'] = {k: v for k in {*seen[0], *seen[1]} for v in [max(s.get(k, 0) for s in seen)] if v > 0 and k.startswith('SP_') and k.endswith('_DROP')}
        rec['rules_restored'] = rule_set(final) == base_rules and not final.get('grant_rules') and not after.get('grant_rules')
        rec['window'].update(closed_by='HOST', seconds=round(clock() - opened, 1))
        rec['step'] = 'DONE'
    except http_authority.Refused:
        raise
    except Exception as exc:
        rec['error'] = type(exc).__name__ + ': ' + str(exc)[:160]
    finally:
        for key in ('reaper', 'proxy', 'broker'):  # EOF: a reaper that is still armed closes the window by itself
            if key in held:
                try:
                    held[key].close()
                except Exception:
                    rec['problems'].append('CONTROL_CLOSE:' + key)
        try:
            rec['left_behind'] = docker.remove_all()  # the anchor with it: without its namespace nothing can be reached any more
        except Exception:
            rec['left_behind'] = ['UNCONFIRMED']
        if rec['window'] and rec['window']['closed_by'] is None:
            rec['window']['closed_by'] = 'NAMESPACE_REMOVED' if not rec['left_behind'] else 'UNCONFIRMED'
    return rec


def judge(rec):
    """-> the observation (outcome / reason / ...) the monitor stores. Anything but the exact expected record is no observation and stops the monitor."""
    result = dict((rec.get('worker') or {}).get('result') or {})
    base = {'http_status': None, 'tls_not_after': None, 'elapsed_ms': result.get('elapsed_ms'), 'selected_ip': None}
    violations = list(rec.get('problems') or [])
    if rec.get('window') is None:  # nothing was ever opened: a setup failure, not a check
        return {**base, 'outcome': 'UNKNOWN', 'reason': 'ISOLATION_SETUP_FAILED:' + str(rec.get('step')), 'violations': violations}
    identity, proxy = (rec.get('worker') or {}).get('identity') or {}, rec.get('proxy') or {}
    window, dialed, grants = proxy.get('window') or {}, proxy.get('dialed') or [], rec.get('grants') or []
    if rec['window'].get('closed_by') not in ('HOST', 'NAMESPACE_REMOVED') or (rec['window']['closed_by'] == 'HOST' and rec.get('rules_restored') is not True):
        violations.append('CLOSE_UNCONFIRMED')
    if rec.get('left_behind'):
        violations.append('LEFT_BEHIND')
    if rec.get('step') == 'DONE':
        if identity.get('uid') != 1000 or identity.get('netns') != rec.get('netns') or identity.get('sockets') or any(
                f'{k} {v}' not in [' '.join(x.split()) for x in identity.get('status') or []] for k, v in CAPS.items()):
            violations.append('WORKER_IDENTITY')
        seen = [(d, rw) for d, rw in rec.get('worker_mounts') or [] if d != '/tmp']  # /tmp: the bounded tmpfs
        if any(rw for _, rw in seen) or {d for d, _ in seen} != {'/opt/siteproof', '/etc/resolv.conf'}:
            violations.append('WORKER_MOUNTS')
        guard = (rec.get('worker') or {}).get('guard') or {}
        if guard.get('denied') or guard.get('lookups') or guard.get('connects', 0) > 1:
            violations.append('WORKER_GUARD')
        violations += ['DROP:' + k for k in NEVER_COUNTED if (rec.get('drops') or {}).get(k)]
        entries = window.get('entries') or []
        if window.get('complete') is not True or len(entries) > 1 or any(e.get('count') != 1 or (e.get('host'), e.get('port')) != (rec['host'], 443) for e in entries):
            violations.append('PROXY_LEDGER')
        if len(grants) > 1 or len(dialed) > 1 or any(d.get('port') != 443 for d in dialed):
            violations.append('MORE_THAN_ONE_DESTINATION')
        if dialed and dialed[0].get('peer') and (dialed[0]['peer'] != [dialed[0]['ip'], 443] or (grants and dialed[0]['ip'] not in grants)):
            violations.append('PEER_MISMATCH')
        if not (rec.get('broker_close') or {}).get('clean') or (rec.get('reaper') or {}).get('type') != 'cancelled':
            violations.append('CLOSE_UNCONFIRMED')
    if violations:
        return {**base, 'outcome': 'UNKNOWN', 'reason': 'ISOLATION_VIOLATION', 'violations': sorted(set(violations))}
    if rec.get('step') != 'DONE' or not result:
        return {**base, 'outcome': 'UNKNOWN', 'reason': 'ISOLATION_INCOMPLETE:' + str(rec.get('step')), 'violations': []}
    entry = (window.get('entries') or [{}])[0]
    if result.get('outcome') == 'UNKNOWN' and str(result.get('reason', '')).startswith('PROXY_'):  # why, from the proxy's own record
        reason = str(entry.get('reason') or result['reason'])
        denied = [d.get('reason') for d in proxy.get('denials') or []]
        failed = connect_failure(rec, entry, dialed, grants)
        if failed:
            return {**base, 'outcome': 'FAIL', 'reason': failed, 'selected_ip': dialed[0]['ip'], 'violations': []}
        return {**base, 'outcome': 'UNKNOWN', 'reason': ('DESTINATION_' + denied[0] if denied and denied[0] else reason)[:80], 'violations': []}
    if entry.get('decision') != 'ALLOW' or not dialed:
        return {**base, 'outcome': 'UNKNOWN', 'reason': 'ISOLATION_VIOLATION', 'violations': ['RESULT_WITHOUT_CONNECTION']}
    return {**base, **{k: result.get(k) for k in ('outcome', 'reason', 'http_status', 'tls_not_after', 'elapsed_ms')}, 'selected_ip': dialed[0]['ip'], 'violations': []}


def connect_failure(rec, entry, dialed, grants):
    """'CONNECT_TIMEOUT' / 'CONNECT_FAILED' when the site itself did not take the connection, else None (no observation of the site).
    Only when the whole path worked: the broker granted the address (the OS rule was there), the proxy dialled exactly that address once and the
    dial itself failed, and no rule of the trusted side dropped anything. A broker, proxy or rule problem never ends here: it is UNKNOWN."""
    if entry.get('decision') != 'FAILED' or entry.get('reason') not in ('DIAL_ERROR', 'CONNECTION_TIMEOUT') or len(dialed) != 1 or len(grants) != 1:
        return None
    dial = dialed[0]
    if dial.get('peer') or not dial.get('error') or dial.get('ip') != grants[0] or dial.get('port') != 443:
        return None
    if any(k.startswith('SP_TRUSTED_') for k in rec.get('drops') or {}):
        return None
    return 'CONNECT_TIMEOUT' if dial['error'] == 'TimeoutError' else 'CONNECT_FAILED'


def audit_line(rec, verdict, grant):
    """The communication record kept per check (<unit>/http-audit.jsonl): where, when, how much was opened and refused -- never a header, body or query."""
    proxy, broker = rec.get('proxy') or {}, rec.get('broker') or {}
    return {'at': (rec.get('window') or {}).get('opened_at') or format_utc(datetime.now(timezone.utc).replace(microsecond=0)), 'run': rec['prefix'], 'host': rec['host'], 'port': 443,
            'mode': rec['mode'], 'grant_id': (grant or {}).get('grant_id'), 'window': rec.get('window'), 'granted': rec.get('grants'), 'dialed': proxy.get('dialed'),
            'proxy': [(e.get('host'), e.get('port'), e.get('decision'), e.get('reason'), e.get('count')) for e in (proxy.get('window') or {}).get('entries') or []],
            'broker_events': [(e.get('event'), e.get('host'), e.get('ok')) for e in broker.get('events') or []][-16:], 'drops': rec.get('drops'), 'rules_restored': rec.get('rules_restored'),
            'left_behind': rec.get('left_behind'), 'outcome': verdict['outcome'], 'reason': verdict['reason'], 'violations': verdict.get('violations'), 'error': rec.get('error'), 'step': rec.get('step')}


# ---- the host entry the monitor uses
def ready(make=None):
    """The engine answers and has exactly the pinned image (read-only; nothing is started, pulled or built). Raises NotRun."""
    from src.noxiworks import real_capture
    if not real_capture.docker_engine_answers(max_age=15):
        raise NotRun('ENGINE_UNAVAILABLE', 'Docker Desktopが動いていないため、HTTPの検査をしていません（通信も回数の消費もしていません）')
    if real_capture.docker_image_id(pinned_image(), max_age=60) != pinned_image():
        raise NotRun('IMAGE_UNAVAILABLE', '検査用のDockerイメージがこのPCにありません（取得はしません。導入手順を確認してください）')


def launch(unit_root, trigger, interval, *, check_ready=ready, make_launcher=launcher, run=isolated_check):
    """One real check of a registered unit. -> the raw result for HttpMonitor, {'refused': code, 'message'} when nothing was requested."""
    from src.noxiworks import http_monitor, notifications, sites
    unit_root = Path(unit_root).resolve()
    if http_monitor.HTTP_EXTERNAL_ENABLED is not True:
        return {'refused': 'EXTERNAL_DISABLED', 'message': 'HTTP監視の外部通信は無効です'}
    info = json.loads((unit_root / 'site.json').read_text('utf-8'))
    host, path = http_authority.target(info)
    data, granted = sites.data_of(unit_root), {}

    def reserve():  # the authoritative decision, fresh: target, signature, scope, period, ownership, count and frequency
        granted.update(http_authority.authorize(unit_root, datetime.now(timezone.utc).replace(microsecond=0), trigger, interval))
        if (granted['host'], granted['path']) != (host, path):
            raise http_authority.Refused('TARGET', '検査の対象が許可と一致しません')
        return granted['reserved_at']
    run_dir = data / 'http-run' / uuid.uuid4().hex[:8]
    try:
        http_authority.precheck(unit_root, datetime.now(timezone.utc).replace(microsecond=0), interval)  # cheap refusal before any container
        check_ready()
        with slot(data):
            run_dir.mkdir(parents=True)
            try:
                docker = make_launcher(run_dir / 'ev')
            except Exception as exc:
                raise NotRun('ENGINE_UNAVAILABLE', 'Dockerを利用できません（' + type(exc).__name__ + '）') from None
            rec = run(docker, run_dir, host=host, path=path, reserve=reserve)
    except http_authority.Refused as exc:
        shutil.rmtree(run_dir, ignore_errors=True)
        return {'refused': exc.code, 'message': exc.message, 'not_before': exc.not_before}
    except NotRun as exc:
        shutil.rmtree(run_dir, ignore_errors=True)
        return {'refused': exc.code, 'message': exc.message}
    verdict = judge(rec)
    notifications.append_jsonl(unit_root / 'http-audit.jsonl', audit_line(rec, verdict, granted.get('grant')), sync=True)
    if verdict['reason'] != 'ISOLATION_VIOLATION' and not rec.get('left_behind'):
        shutil.rmtree(run_dir, ignore_errors=True)  # this run's own staged copies and logs; kept when there is something to look at
    if rec.get('window') is None and rec.get('reserved') is None:
        return {'refused': 'SETUP_FAILED', 'message': '隔離環境を用意できなかったため、検査していません（' + verdict['reason'] + '）'}
    return {**{k: v for k, v in verdict.items() if k != 'violations'}, 'grant_id': granted['grant']['grant_id'], 'reserved_at': granted['reserved_at']}


class slot:
    """One of SLOTS places per data folder; NotRun(BUSY) when all are taken (tried again on the next pass, nothing is counted)."""

    def __init__(self, data):
        self.data = Path(data)

    def __enter__(self):
        for i in range(SLOTS):
            self.held = filelock.held(self.data / f'http-slot-{i}.lock')
            try:
                self.held.__enter__()
                return self
            except filelock.LockBusy:
                continue
        raise NotRun('BUSY', '別のHTTP検査を実行中です')

    def __exit__(self, *exc):
        return self.held.__exit__(*exc)
