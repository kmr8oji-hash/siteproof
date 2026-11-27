"""The isolated HTTP check (src/noxiworks/http_isolation.py), offline: the order of the steps, fail-closed behaviour and the verdict, against a FakeDocker that
stands in for the engine; the Worker / exchange parts against local sockets. Nothing here starts Docker and nothing is a measurement of the OS boundary (that is
tests/runtime/validate_http_iso.py, NOT RUN); its pure part (evaluate) is checked too."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest import mock

from src.isolation import http_exchange, http_probe_worker, http_proxy_worker
from src.noxiworks import http_authority, http_isolation as iso, http_monitor
from tests.runtime import validate_http_iso
from tests.runtime.browser_bundle import import_closure
from tests.ui import test_http_boundary as boundary
from tests.ui.test_real_capture import CF_HOST, needs_ssh

ROOT = Path(__file__).resolve().parents[2]
NS = 'net:[4026532999]'
IP = '104.16.0.1'


def rules(drops=None, grants=(), opened=False):
    drops = drops or {}
    lines = [':INPUT DROP [0:0]', ':FORWARD DROP [0:0]', ':OUTPUT DROP [0:0]', '[0:0] -A INPUT -i lo -j ACCEPT']
    lines += [f'[{drops.get(r, 0)}:0] -A OUTPUT -p tcp -m comment --comment {r} -j DROP' for r in iso.REQUIRED_RULES]
    if opened:
        lines.append(f"[{drops.get('SP_TRUSTED_NONPUBLIC_DROP', 0)}:0] -A OUTPUT -o eth0 -m comment --comment SP_TRUSTED_NONPUBLIC_DROP -j DROP")
        lines.append(f"[{drops.get('SP_TRUSTED_OTHER_DROP', 0)}:0] -A OUTPUT -o eth0 -m comment --comment SP_TRUSTED_OTHER_DROP -j DROP")
    lines += list(grants)
    return '\n'.join(lines)


class FakeDocker:
    """The engine as isolated_check sees it. Records every step in order; each part can be made to misbehave."""

    def __init__(self, **over):
        self.log, self.resources, self.over, self.open, self.granted, self.left = [], {}, over, False, False, []
        self.worker_result = {'outcome': 'PASS', 'reason': 'HTTP_200', 'http_status': 200, 'tls_not_after': None, 'elapsed_ms': 50}

    def create_network(self, name):
        self.log.append('network')
        self.resources[name] = {'kind': 'network', 'id': name}
        return name

    def create(self, name, options, command):
        self.log.append('create:' + name.split('-')[4 if '-anchor' not in name else -1])
        self.resources[name] = {'kind': 'container', 'id': name, 'options': options, 'command': command}
        return name

    def call(self, *args, **kw):
        return NS + '\n' if args[0] == 'exec' else ''

    def inspect(self, name):
        return {'Mounts': self.over.get('mounts', [{'Destination': '/opt/siteproof', 'RW': False}, {'Destination': '/etc/resolv.conf', 'RW': False}])}

    def options(self, anchor, uid, *, memory, pids, mounts=()):
        return ['--network', 'container:' + anchor, '--user', f'{uid}:{uid}', '--cap-drop', 'ALL', *mounts]

    def snapshot(self):
        grants = [f'-A OUTPUT -d {ip}/32 -o eth0 -p tcp --dport 443 --comment SP_GRANT -j ACCEPT' for ip in self.over.get('grants', [IP])] if self.granted else []
        drops = self.over.get('drops', {}) if self.over.get('probed') else {}
        ipv4 = rules(drops, grants, self.open)
        if self.over.get('open_at_start') and not self.over.get('was_open'):
            ipv4 += '\n[0:0] -A OUTPUT -o eth0 -j ACCEPT'
        return {'ipv4': ipv4, 'ipv6': rules(), 'rules_plain': ipv4.replace('[0:0] ', ''), 'grant_rules': grants, 'devices': self.over.get('devices', ['eth0'])}

    def bounded(self, name, payload=b'', **kw):
        job = json.loads(payload)
        if '-policy-' in name:
            self.log.append('policy:' + job['type'])
            if job['type'] == self.over.get('policy_fails'):
                raise RuntimeError('policy')
            if job['type'] == 'egress_open':
                self.open = self.over['was_open'] = True
            if job['type'] == 'egress_close':
                self.open = self.over.get('stays_open', False)
                self.granted = False
            return json.dumps(self.snapshot()).encode(), b''
        self.log.append('worker')
        self.job, self.over['probed'] = job, True
        if self.over.get('worker_raises'):
            raise TimeoutError()
        self.granted = True
        return json.dumps({'identity': {'uid': 1000, 'netns': NS, 'sockets': [], 'status': ['CapEff:\t0000000000000000', 'CapBnd:\t0000000000000000', 'NoNewPrivs:\t1', 'Seccomp:\t2'],
                                        **self.over.get('identity', {})},
                           'result': self.worker_result, 'guard': {'denied': [], 'connects': 1, 'lookups': 0, **self.over.get('guard', {})}}).encode(), b''

    def attach(self, name):
        part = next(p for p in ('broker', 'proxy', 'reaper') if f'-{p}-' in name)
        self.log.append('attach:' + part)
        return Control(self, part)

    def remove_all(self):
        self.log.append('remove_all')
        return list(self.over.get('left', []))


class Control:
    def __init__(self, docker, part):
        self.docker, self.part = docker, part

    def ask(self, obj, seconds=30):
        d, kind = self.docker, obj.get('type')
        d.log.append(f'{self.part}:{kind or "config"}')
        if f'{self.part}:{kind or "config"}' in d.over.get('dies_at', ()):
            raise RuntimeError('invalid Worker control frame')
        if self.part == 'broker':
            d.broker_config = obj if kind is None else getattr(d, 'broker_config', None)
            return {None: {'type': 'ready'}, 'enable': {'type': 'enabled'}, 'lease_open': {'ok': True}, 'close': {'clean': d.over.get('broker_clean', True)},
                    'state': {'state': {'events': [{'event': 'GRANTED', 'host': CF_HOST, 'ok': True}]}}}[kind]
        if self.part == 'reaper':
            return {None: {'type': 'ready'}, 'cancel': {'type': d.over.get('reaper', 'cancelled')}}[kind]
        if kind is None:
            return {'type': 'ready', 'netns': NS, 'uid': 1001}
        entry = {'host': CF_HOST, 'port': 443, 'decision': 'ALLOW', 'reason': 'ALLOW', 'count': 1}
        return {'type': 'audit', 'window': {'complete': True, 'entries': d.over.get('entries', [entry])}, 'dialed': d.over.get('dialed', [{'ip': IP, 'port': 443, 'peer': [IP, 443]}]),
                'denials': d.over.get('denials', [])}

    def close(self, wait=15):
        self.docker.log.append('eof:' + self.part)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sp-iso-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.n = 0

    def run_fake(self, docker=None, reserve=None, **over):
        docker = docker or FakeDocker(**over)
        self.n += 1
        folder = self.tmp / str(self.n)
        folder.mkdir()
        rec = iso.isolated_check(docker, folder, host=CF_HOST, path='/status', reserve=reserve or (lambda: docker.log.append('RESERVE') or 'at'))
        return rec, iso.judge(rec), docker


class Order(Base):
    def test_a_normal_check_in_exactly_this_order(self):
        rec, verdict, docker = self.run_fake()
        self.assertEqual((verdict['outcome'], verdict['reason'], verdict['selected_ip'], verdict['violations']), ('PASS', 'HTTP_200', IP, []))
        steps = [x for x in docker.log if not x.startswith(('create:', 'eof:'))]
        self.assertEqual(steps, ['network', 'policy:prepare', 'policy:install', 'attach:broker', 'broker:config', 'attach:proxy', 'proxy:config', 'policy:snapshot', 'RESERVE',
                                 'attach:reaper', 'reaper:config', 'policy:egress_open', 'broker:enable', 'broker:lease_open', 'worker', 'proxy:audit', 'policy:snapshot',
                                 'broker:state', 'broker:close', 'policy:egress_close', 'reaper:cancel', 'policy:snapshot', 'remove_all'])
        self.assertEqual(docker.job, {'host': CF_HOST, 'path': '/status', 'proxy_port': 18080, 'timeout': 8})
        self.assertEqual({k: docker.broker_config[k] for k in ('mode', 'hosts', 'max_grants', 'real_site_access')}, {'mode': 'system', 'hosts': [CF_HOST], 'max_grants': 1, 'real_site_access': True})

    def test_the_worker_gets_the_small_bundle_and_nothing_else(self):
        _, _, docker = self.run_fake()
        worker = next(v for k, v in docker.resources.items() if '-worker-' in k)
        text = ' '.join(worker['options'])
        self.assertIn('--user 1000:1000', text)
        self.assertNotIn('NET_ADMIN', text)
        self.assertNotIn('docker.sock', text)
        self.assertEqual(text.count('--mount'), 2)
        self.assertEqual(text.count(',readonly'), 2)
        closure = list(import_closure(ROOT, iso.WORKER_ENTRIES))
        self.assertLess(len(closure), 20)
        self.assertFalse([f for f in closure if f.startswith(('src/noxiworks', 'src/runtime', 'src/worker', 'tests', 'tools'))])  # no app, no browser, no keys, no grants
        trusted = list(import_closure(ROOT, iso.ENTRIES))
        self.assertFalse([f for f in trusted if f.startswith(('src/noxiworks', 'src/runtime', 'src/comparison', 'src/baseline'))])
        admins = sorted(k.split('-')[4] for k, v in docker.resources.items() if 'NET_ADMIN' in v.get('options', ()))
        self.assertEqual(admins, ['broker', 'policy', 'reaper'])

    def test_a_refused_reservation_opens_nothing_and_cleans_up(self):
        def refuse():
            raise http_authority.Refused('RATE_LIMITED', 'x')
        docker = FakeDocker()
        with self.assertRaises(http_authority.Refused):
            self.run_fake(docker, refuse)
        self.assertFalse({'policy:egress_open', 'worker', 'attach:reaper'} & set(docker.log))
        self.assertEqual(docker.log[-1], 'remove_all')


class FailClosed(Base):
    def test_a_closed_state_that_is_not_the_expected_one_is_never_opened_or_counted(self):
        for over in ({'open_at_start': True}, {'devices': ['eth0', 'eth1']}, {'policy_fails': 'install'}, {'dies_at': ('broker:config',)}, {'dies_at': ('proxy:config',)}):
            with self.subTest(over):
                rec, verdict, docker = self.run_fake(**dict(over))
                self.assertNotIn('RESERVE', docker.log)
                self.assertNotIn('policy:egress_open', docker.log)
                self.assertEqual((verdict['outcome'], rec['window'], rec['reserved']), ('UNKNOWN', None, None))
                self.assertTrue(verdict['reason'].startswith('ISOLATION_SETUP_FAILED'))
                self.assertEqual(docker.log[-1], 'remove_all')

    def test_a_dead_proxy_broker_or_reaper_is_no_observation_and_everything_is_removed(self):
        for over in ({'dies_at': ('proxy:audit',)}, {'dies_at': ('broker:enable',)}, {'dies_at': ('broker:state',)}, {'dies_at': ('reaper:cancel',)}, {'worker_raises': True},
                     {'policy_fails': 'egress_close'}):
            with self.subTest(over):
                rec, verdict, docker = self.run_fake(**dict(over))
                self.assertEqual(verdict['outcome'], 'UNKNOWN')
                self.assertTrue(verdict['reason'].startswith('ISOLATION_'), verdict['reason'])
                self.assertIsNone(verdict['http_status'])
                self.assertEqual(docker.log[-1], 'remove_all')
                self.assertIn('eof:broker', docker.log)

    def test_every_deviation_is_a_violation_whatever_the_worker_says(self):
        entry = {'host': CF_HOST, 'port': 443, 'decision': 'ALLOW', 'reason': 'ALLOW', 'count': 1}
        for label, over in (('direct tcp', {'drops': {'SP_BROWSER_TCP_DROP': 1}}), ('udp', {'drops': {'SP_BROWSER_UDP_DROP': 2}}), ('dns', {'drops': {'SP_BROWSER_DNS_DROP': 1}}),
                            ('proxy dns', {'drops': {'SP_WORKER_DNS_DROP': 1}}), ('private', {'drops': {'SP_TRUSTED_NONPUBLIC_DROP': 1}}),
                            ('two grants', {'grants': [IP, '104.16.0.2']}), ('two dials', {'dialed': [{'ip': IP, 'port': 443, 'peer': [IP, 443]}] * 2}),
                            ('another peer', {'dialed': [{'ip': IP, 'port': 443, 'peer': ['104.16.0.9', 443]}]}), ('not the granted', {'grants': ['104.16.0.9']}),
                            ('other port', {'dialed': [{'ip': IP, 'port': 80, 'peer': [IP, 80]}]}), ('other host', {'entries': [{**entry, 'host': 'evil.example'}]}),
                            ('two connects', {'entries': [{**entry, 'count': 2}]}), ('a second authority', {'entries': [entry, {**entry, 'port': 8443, 'decision': 'BLOCK'}]}),
                            ('guard', {'guard': {'denied': ['socket.sendto']}}), ('uid', {'identity': {'uid': 0}}), ('capabilities', {'identity': {'status': ['CapEff: 00000000a80425fb']}}),
                            ('other namespace', {'identity': {'netns': 'net:[1]'}}), ('docker socket', {'identity': {'sockets': ['/var/run/docker.sock']}}),
                            ('writable mount', {'mounts': [{'Destination': '/opt/siteproof', 'RW': True}, {'Destination': '/etc/resolv.conf', 'RW': False}]}),
                            ('extra mount', {'mounts': [{'Destination': '/opt/siteproof', 'RW': False}, {'Destination': '/etc/resolv.conf', 'RW': False}, {'Destination': '/data', 'RW': False}]}),
                            ('left behind', {'left': ['x']}), ('still open', {'stays_open': True}), ('broker not clean', {'broker_clean': False}), ('reaper closed it', {'reaper': 'closed'}),
                            ('a result without a connection', {'entries': [], 'dialed': []})):
            with self.subTest(label):
                _, verdict, _ = self.run_fake(**over)
                self.assertEqual((verdict['outcome'], verdict['reason'], verdict['http_status']), ('UNKNOWN', 'ISOLATION_VIOLATION', None), verdict)

    def test_refusals_of_the_boundary_are_not_outages_and_a_refused_connection_is(self):
        docker = FakeDocker(entries=[{'host': CF_HOST, 'port': 443, 'decision': 'FAILED', 'reason': 'DNS_ERROR', 'count': 1}], dialed=[], grants=[], denials=[{'reason': 'PRIVATE_ADDRESS'}])
        docker.worker_result = {'outcome': 'UNKNOWN', 'reason': 'PROXY_REFUSED', 'elapsed_ms': 3}
        self.assertEqual(self.run_fake(docker)[1]['reason'], 'DESTINATION_PRIVATE_ADDRESS')
        for ledger, error, expected in (('DIAL_ERROR', 'ConnectionRefusedError', 'CONNECT_FAILED'), ('DIAL_ERROR', 'TimeoutError', 'CONNECT_TIMEOUT'),
                                        ('CONNECTION_TIMEOUT', 'TimeoutError', 'CONNECT_TIMEOUT')):
            with self.subTest(ledger + ' ' + error):
                docker = FakeDocker(entries=[{'host': CF_HOST, 'port': 443, 'decision': 'FAILED', 'reason': ledger, 'count': 1}], dialed=[{'ip': IP, 'port': 443, 'error': error}])
                docker.worker_result = {'outcome': 'UNKNOWN', 'reason': 'PROXY_CLOSED', 'elapsed_ms': 3}
                verdict = self.run_fake(docker)[1]
                self.assertEqual((verdict['outcome'], verdict['reason'], verdict['selected_ip']), ('FAIL', expected, IP))

    def test_a_timeout_is_an_outage_only_when_the_whole_path_worked(self):
        timeout = {'host': CF_HOST, 'port': 443, 'decision': 'FAILED', 'reason': 'CONNECTION_TIMEOUT', 'count': 1}
        dial = {'ip': IP, 'port': 443, 'error': 'TimeoutError'}
        for label, over in (('the broker never answered: nothing was dialled', {'dialed': [], 'grants': []}), ('granted, but no OS rule for it', {'dialed': [dial], 'grants': []}),
                            ('dialled an address that was not granted', {'dialed': [{**dial, 'ip': '104.16.0.9'}]}),
                            ('a rule of the trusted side dropped the dial', {'dialed': [dial], 'drops': {'SP_TRUSTED_OTHER_DROP': 1}}),
                            ('the dial did not fail', {'dialed': [{'ip': IP, 'port': 443}]})):
            with self.subTest(label):
                docker = FakeDocker(entries=[timeout], **{'dialed': [dial], **over})
                docker.worker_result = {'outcome': 'UNKNOWN', 'reason': 'PROXY_CLOSED', 'elapsed_ms': 5000}
                verdict = self.run_fake(docker)[1]
                self.assertEqual(verdict['outcome'], 'UNKNOWN', verdict)
                self.assertNotIn(verdict['reason'], ('CONNECT_TIMEOUT', 'CONNECT_FAILED'))


@needs_ssh
class Launch(boundary.Base):
    def launch(self, docker=None, enabled=True, ready=lambda: None, trigger='SCHEDULE', run=None):
        with mock.patch.object(http_monitor, 'HTTP_EXTERNAL_ENABLED', enabled):
            return iso.launch(self.site.root, trigger, 900, check_ready=ready, make_launcher=lambda ev: docker or FakeDocker(), run=run or iso.isolated_check)

    def granted(self):
        self.keys()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        boundary.evidence(self.site.root, http_authority.format_utc(now - timedelta(days=1)))
        from tools import permit_draft
        own = permit_draft.cloudflare_ownership(self.site.root, self.site.info, now)
        self.sign(self.grant(valid_from=http_authority.format_utc(now - timedelta(hours=1)), valid_until=http_authority.format_utc(now + timedelta(days=1)),
                             issued_at=http_authority.format_utc(now), ownership=own))

    def test_the_kill_switch_comes_first(self):
        self.assertFalse(http_monitor.HTTP_EXTERNAL_ENABLED)
        boom = mock.MagicMock(side_effect=AssertionError('asked'))
        self.assertEqual(iso.launch(self.site.root, 'MANUAL', 900, check_ready=boom, make_launcher=boom, run=boom)['refused'], 'EXTERNAL_DISABLED')

    def test_without_a_grant_engine_or_image_nothing_starts_and_nothing_is_counted(self):
        boom = mock.MagicMock(side_effect=AssertionError('started'))
        self.assertEqual(self.launch(run=boom, ready=boom)['refused'], 'GRANT_INVALID')
        self.granted()
        for code in ('ENGINE_UNAVAILABLE', 'IMAGE_UNAVAILABLE'):
            def absent(code=code):
                raise iso.NotRun(code, 'x')
            self.assertEqual(self.launch(ready=absent, run=boom)['refused'], code)
        self.assertFalse(self.ledger().exists())
        with mock.patch('src.noxiworks.real_capture.docker_engine_answers', return_value=False), self.assertRaises(iso.NotRun) as e:
            iso.ready()
        self.assertEqual(e.exception.code, 'ENGINE_UNAVAILABLE')
        with mock.patch('src.noxiworks.real_capture.docker_engine_answers', return_value=True), mock.patch('src.noxiworks.real_capture.docker_image_id', return_value=''), \
                self.assertRaises(iso.NotRun) as e:
            iso.ready()
        self.assertEqual(e.exception.code, 'IMAGE_UNAVAILABLE')

    def test_one_check_is_counted_once_audited_and_leaves_no_run_folder(self):
        self.granted()
        out = self.launch()
        self.assertEqual((out['outcome'], out['http_status'], out['grant_id']), ('PASS', 200, 'http-g1'))
        self.assertEqual(len(http_authority.entries(self.site.root)), 1)
        audit = [json.loads(x) for x in (self.site.root / 'http-audit.jsonl').read_text('utf-8').splitlines()]
        self.assertEqual((len(audit), audit[0]['proxy'], audit[0]['granted'], audit[0]['violations'], audit[0]['window']['closed_by']),
                         (1, [[CF_HOST, 443, 'ALLOW', 'ALLOW', 1]], [IP], [], 'HOST'))
        self.assertNotIn('/status', json.dumps(audit))  # a network record: never a path, header or body
        self.assertEqual(list((self.data / 'http-run').iterdir()), [])
        again = self.launch(trigger='MANUAL')  # at once: refused before any container
        self.assertEqual(again['refused'], 'RATE_LIMITED')
        self.assertEqual(len(http_authority.entries(self.site.root)), 1)

    def test_a_setup_failure_is_not_counted_and_a_violation_keeps_its_folder(self):
        self.granted()
        self.assertEqual(self.launch(FakeDocker(open_at_start=True))['refused'], 'SETUP_FAILED')
        self.assertFalse(self.ledger().exists())
        out = self.launch(FakeDocker(drops={'SP_BROWSER_TCP_DROP': 3}))
        self.assertEqual((out['outcome'], out['reason']), ('UNKNOWN', 'ISOLATION_VIOLATION'))
        self.assertEqual(len(list((self.data / 'http-run').iterdir())), 1)
        self.assertEqual(len(http_authority.entries(self.site.root)), 1)

    def test_three_at_a_time(self):
        with iso.slot(self.data), iso.slot(self.data), iso.slot(self.data):
            with self.assertRaises(iso.NotRun) as e, iso.slot(self.data):
                pass
            self.assertEqual(e.exception.code, 'BUSY')
        with iso.slot(self.data):
            pass


class Exchange(unittest.TestCase):
    def proxy(self, reply, then=b''):
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        self.addCleanup(theirs.close)
        seen = []

        def serve():
            theirs.settimeout(5)
            try:
                seen.append(theirs.recv(4096))
                theirs.sendall(reply + then)
            except OSError:
                pass
        threading.Thread(target=serve, daemon=True).start()
        sock = mock.MagicMock(wraps=ours)
        sock.connect = lambda address: seen.append(address)
        return sock, seen

    def test_one_connect_to_the_owned_proxy_for_this_host_only(self):
        sock, seen = self.proxy(b'HTTP/1.1 200 Connection Established\r\n\r\n', b'TLS')
        out = http_exchange.connect_through(18080, 'a.example.com', time.monotonic() + 5, make=lambda: sock)
        self.assertEqual(seen, [('127.0.0.1', 18080), b'CONNECT a.example.com:443 HTTP/1.1\r\nHost: a.example.com:443\r\n\r\n'])
        self.assertEqual(out.recv(3), b'TLS')  # not a byte of the tunnel was read as part of the proxy's answer

    def test_a_refusing_closing_or_endless_proxy_is_no_observation(self):
        for reply in (b'HTTP/1.1 502 Bad Gateway\r\n\r\n', b'x' * 5000, b'HTTP/1.1 200 half'):
            sock, _ = self.proxy(reply)
            result = http_exchange.exchange('a.example.com', '/', 18080, 1, connect=lambda p, h, d, sock=sock: http_exchange.connect_through(p, h, d, make=lambda: sock))
            self.assertEqual(result['outcome'], 'UNKNOWN')
            self.assertTrue(result['reason'].startswith('PROXY_'), result)

    def result(self, line=b'HTTP/1.1 200 OK', error=None):
        transport = mock.MagicMock()
        transport.exchange.side_effect = error
        transport.exchange.return_value = (line, 'Jan  5 12:00:00 2027 GMT')
        out = http_exchange.exchange('a.example.com', '/p', 18080, 2, transport=transport, connect=lambda *a: mock.MagicMock())
        return out['outcome'], out['reason']

    def test_outcomes(self):
        self.assertEqual(self.result(), ('PASS', 'HTTP_200'))
        self.assertEqual(self.result(b'HTTP/1.1 503 x'), ('FAIL', 'HTTP_503'))
        self.assertEqual(self.result(b'HTTP/1.1 302 x')[0], 'UNKNOWN')
        self.assertEqual(self.result(b'garbage'), ('UNKNOWN', 'HTTP_MALFORMED'))
        self.assertEqual(self.result(error=ssl.SSLCertVerificationError()), ('FAIL', 'TLS_FAILED'))
        self.assertEqual(self.result(error=TimeoutError()), ('FAIL', 'HTTP_TIMEOUT'))
        self.assertEqual(self.result(error=ValueError('too long')), ('UNKNOWN', 'HTTP_EXCHANGE_ERROR'))

    def test_incomplete_and_timeout_are_different_outcomes(self):
        from src.aws_b.probe import IncompleteStatusLine
        self.assertEqual(self.result(error=IncompleteStatusLine('cut')), ('UNKNOWN', 'HTTP_INCOMPLETE'))
        self.assertEqual(self.result(error=TimeoutError()), ('FAIL', 'HTTP_TIMEOUT'))
        self.assertEqual(self.result(b'HTTP/1.1 503 x'), ('FAIL', 'HTTP_503'))
        self.assertEqual(self.result(), ('PASS', 'HTTP_200'))

    def test_a_result_that_arrives_after_the_hard_end_fired_is_a_timeout(self):
        class Late:  # looks like a clean end: the cut made recv return EOF and the inner transport returned normally
            def exchange(self, handle, hostname, path, deadline):
                time.sleep(0.5)
                return b'HTTP/1.1 200 OK', 'Jan  5 12:00:00 2027 GMT'
        with self.assertRaises(TimeoutError):
            http_exchange.DeadlineTransport(Late()).exchange(mock.MagicMock(), 'a.example.com', '/', time.monotonic() + 0.1)

        class Quick:
            def exchange(self, handle, hostname, path, deadline):
                return b'HTTP/1.1 200 OK', 'x'
        self.assertEqual(http_exchange.DeadlineTransport(Quick()).exchange(mock.MagicMock(), 'a.example.com', '/', time.monotonic() + 5), (b'HTTP/1.1 200 OK', 'x'))

    def test_a_server_that_drips_an_unterminated_status_line_is_a_timeout_not_a_pass(self):
        """The case the HTTP isolation measurement caught (drip_feeding_server): some bytes, no CRLF ever, then the hard end cuts the blocked read.
        On Linux shutdown() wakes the blocked recv with EOF (an SSL socket reports it as b''): this socket does exactly that."""
        from src.aws_b.probe import read_status_line

        class CutSocket:
            def __init__(self):
                self.cut, self.sent = threading.Event(), False

            def recv(self, size):
                if not self.sent:
                    self.sent = True
                    return b'HTTP/1.1 200 OK'
                self.cut.wait(10)  # the peer says nothing more; only the hard end ends this read
                return b''

            def shutdown(self, how):
                self.cut.set()

            def close(self):
                pass

        class Reads:  # what TlsTransport does after the handshake: read the status line until CRLF or the deadline
            def exchange(self, handle, hostname, path, deadline):
                return read_status_line(handle.sock.recv, deadline), None
        started = time.monotonic()
        out = http_exchange.exchange('a.example.com', '/', 18080, 0.5, transport=Reads(), connect=lambda *a: CutSocket())
        self.assertEqual((out['outcome'], out['reason']), ('FAIL', 'HTTP_TIMEOUT'))  # before the fix: PASS / HTTP_200 at exactly the deadline
        self.assertLess(time.monotonic() - started, 3)

    def test_a_peer_that_closes_inside_the_status_line_is_incomplete_not_pass(self):
        from src.aws_b.probe import read_status_line
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        theirs.sendall(b'HTTP/1.1 200 OK')  # no CRLF, then the peer goes away (no deadline involved)
        theirs.close()

        class Reads:
            def exchange(self, handle, hostname, path, deadline):
                return read_status_line(lambda size: handle.sock.recv(size), deadline), None
        out = http_exchange.exchange('a.example.com', '/', 18080, 5, transport=Reads(), connect=lambda *a: ours)
        self.assertEqual((out['outcome'], out['reason']), ('UNKNOWN', 'HTTP_INCOMPLETE'))

    def test_a_drip_feeding_server_cannot_stretch_the_deadline(self):
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        self.addCleanup(theirs.close)
        stop = threading.Event()
        self.addCleanup(stop.set)

        def drip():
            while not stop.wait(0.05):
                try:
                    theirs.send(b'H')
                except OSError:
                    return
        threading.Thread(target=drip, daemon=True).start()

        class Drip:
            def exchange(self, handle, hostname, path, deadline):
                handle.sock.settimeout(5)
                while handle.sock.recv(1):
                    pass
                raise OSError('closed')
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            http_exchange.DeadlineTransport(Drip()).exchange(http_exchange.Handle(ours), 'a.example.com', '/', time.monotonic() + 0.4)
        self.assertLess(time.monotonic() - started, 3)

    def test_the_worker_takes_exactly_one_kind_of_job(self):
        good = {'host': 'a.example.com', 'path': '/', 'proxy_port': 18080, 'timeout': 8}
        self.assertEqual(http_probe_worker.parse(json.dumps(good)), good)
        for bad in ({**good, 'extra': 1}, {**good, 'path': 'x'}, {**good, 'timeout': 3600}, {**good, 'ca_pem': 'x'}, {k: v for k, v in good.items() if k != 'host'}):
            with self.subTest(bad), self.assertRaises(ValueError):
                http_probe_worker.parse(json.dumps(bad))
        self.assertIn('ca_pem', http_probe_worker.parse(json.dumps({**good, 'host': 'x.invalid', 'ca_pem': 'y'})))

    def test_the_proxy_allows_one_host_and_a_fixture_can_never_be_real(self):
        policy = http_proxy_worker.policy_for('fixture', 'x.invalid')
        self.assertEqual([(a.hostname, a.port) for a in policy.allowlist], [('x.invalid', 443)])
        with self.assertRaises(ValueError):
            http_proxy_worker.policy_for('fixture', 'real-site.com')
        with self.assertRaises(ValueError):
            http_proxy_worker.policy_for('anything', 'x.invalid')


class FixturePlan(unittest.TestCase):
    """validate_http_iso.py is not run here; what it would accept as green is."""

    def test_every_required_negative_case_is_in_the_plan(self):
        names = {c[0] for c in validate_http_iso.CASES}
        self.assertLessEqual({'ok', 'redirect_not_followed', 'private_answer', 'metadata_answer', 'loopback_answer', 'mixed_answer', 'ipv6_only_answer', 'certificate_of_another_name',
                              'certificate_not_trusted', 'status_line_over_the_cap', 'drip_feeding_server', 'proxy_stopped', 'broker_killed', 'direct_attempts_while_granted'}, names)
        self.assertTrue(validate_http_iso.HOST.endswith('.invalid'))

    def test_a_case_is_green_only_with_every_record(self):
        case = validate_http_iso.CASES[0]
        rec = {'left_behind': [], 'window': {'closed_by': 'HOST'}, 'rules_restored': True, 'grants': [validate_http_iso.PEER_IP]}
        verdict = {'outcome': 'PASS', 'reason': 'HTTP_200', 'violations': []}
        self.assertTrue(all(validate_http_iso.evaluate(case, verdict, rec, 1, 0).values()))
        for change in ({'left_behind': ['x']}, {'rules_restored': False}, {'window': {'closed_by': 'UNCONFIRMED'}}, {'grants': ['a', 'b']}):
            self.assertFalse(all(validate_http_iso.evaluate(case, verdict, {**rec, **change}, 1, 0).values()), change)
        self.assertFalse(all(validate_http_iso.evaluate(case, verdict, rec, 2, 0).values()))
        self.assertFalse(all(validate_http_iso.evaluate(case, verdict, rec, 1, 1).values()))
        direct = validate_http_iso.CASES[-1]
        none = {k: {'reached': False} for k, _, _ in validate_http_iso.DIRECT}
        seen = {**rec, 'direct': {'worker_tcp': none, 'worker_udp': {'x': {'reached': False}}, 'proxy_udp': {'x': {'reached': False}}, 'proxy_tcp': {**none, 'granted_443': {'reached': True}},
                                  'ipv6_reached': False}}
        bad = {'outcome': 'UNKNOWN', 'reason': 'ISOLATION_VIOLATION', 'violations': ['DROP:SP_BROWSER_TCP_DROP']}
        self.assertTrue(all(validate_http_iso.evaluate(direct, bad, seen, 1, 0).values()))
        leak = {**seen, 'direct': {**seen['direct'], 'worker_tcp': {**none, 'granted_443': {'reached': True}}}}
        self.assertFalse(all(validate_http_iso.evaluate(direct, bad, leak, 1, 0).values()))
        self.assertFalse(all(validate_http_iso.evaluate(direct, bad, rec, 1, 0).values()))  # not attempted is not passed


if __name__ == '__main__':
    unittest.main()
