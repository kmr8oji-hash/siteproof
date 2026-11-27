"""The app's long-term operation and e-mail routes over several sites: switches, one test message, tidy-up (moves, never deletes), history limit,
verified local backups, expiry guidance. Offline: MockSmtpProvider, injected HTTP probe, synthetic keys, temporary folders."""
from datetime import timedelta
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from src.aws_b.model import format_utc
from src.noxiworks import backup, filelock, http_monitor, notifications, retention, smtp_notify
from src.noxiworks import permit as permits
from src.noxiworks.app import App, utc_now
from src.noxiworks.http_monitor import HttpMonitor
from tests.ui.test_real_capture import keypair, needs_ssh


def ok(host, path, timeout):
    return {'outcome': 'PASS', 'reason': 'HTTP_200', 'http_status': 200, 'elapsed_ms': 12, 'selected_ip': None, 'tls_not_after': None}


def down(host, path, timeout):
    return {'outcome': 'FAIL', 'reason': 'HTTP_503', 'http_status': 503, 'elapsed_ms': 12, 'selected_ip': None, 'tls_not_after': None}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='siteproof-ops-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.app = App(self.tmp / 'data')
        self.app.docker_found = False
        self.app.background_query = mock.MagicMock(return_value=False)
        self.app.launcher = mock.MagicMock()
        self.app.http_probe = ok
        self.app.notify_provider = smtp_notify.MockSmtpProvider()
        self.app.setup()
        self.a, self.b = (self.app.site_action('register', {'name': n, 'url': u, 'kinds': ['Desktop'], 'owner_confirmed': True})['site_id']
                          for n, u in (('Alpha', 'https://alpha-site.com/'), ('Beta', 'https://beta-site.com/')))

    def act(self, action, site_id=None, **body):
        return self.app.site_action(action, {**({'site_id': site_id} if site_id else {}), **body})

    def root(self, site_id):
        return self.app.sites[site_id].site.root

    def check(self, site_id, probe, when):
        self.app.http_probe = probe
        with mock.patch.object(HttpMonitor, 'grant_problems', return_value=[]):
            return self.app.sites[site_id].http_monitor().run(when, 'MANUAL')


class Mail(Base):
    def grant(self, **over):
        keys = self.tmp / 'keys'
        if not keys.exists():
            keys.mkdir()
            self.key = keypair(keys, 'user')
            pub = (keys / 'user.pub').read_text('utf-8').split()
            (self.app.data / 'trust').mkdir(exist_ok=True)
            (self.app.data / 'trust' / 'allowed_signers').write_text(f'site-owner namespaces="{permits.NAMESPACE}" {pub[0]} {pub[1]}\n', encoding='ascii')
        now = utc_now()
        body = {'schema': smtp_notify.GRANT_SCHEMA, 'grant_id': 'notify-t1', 'issued_by': 'site-owner', 'issued_at': format_utc(now),
                'smtp': {'host': 'smtp.mail-service.com', 'port': 587, 'security': 'STARTTLS'}, 'sender': 'from@mail-service.com', 'recipients': ['owner@mail-service.com'],
                'credential_ref': 'SiteProof-SMTP-test', 'valid_from': format_utc(now - timedelta(hours=1)), 'valid_until': format_utc(now + timedelta(days=30)),
                'max_messages_total': 50, 'max_messages_per_day': 20, **over}
        folder = self.app.data / 'notify'
        folder.mkdir(exist_ok=True)
        f = folder / 'notify-grant.json'
        f.with_name(f.name + '.sig').unlink(missing_ok=True)
        f.write_text(json.dumps(body), encoding='utf-8')
        subprocess.run([permits.ssh_keygen(), '-Y', 'sign', '-n', permits.NAMESPACE, '-f', str(self.key), str(f)], check=True, capture_output=True)

    def test_nothing_can_be_switched_on_without_a_signed_notify_grant(self):
        for body in ({'what': 'channel', 'enabled': True}, {'what': 'site', 'enabled': True}, {'what': 'test'}, {'what': 'kinds', 'kinds': ['NO']}, {'what': 'x'},
                     {'what': 'channel', 'enabled': 'yes'}):
            with self.subTest(body), self.assertRaises(ValueError):
                self.act('notify', self.a, **body)
        self.assertEqual(self.app.notify_provider.calls, [])
        status = self.app.status(self.a)
        self.assertEqual((status['site']['notify']['enabled'], status['site']['notify']['can_enable']), (False, False))
        json.dumps(status)

    @needs_ssh
    def test_the_real_provider_stays_off(self):
        self.grant()
        self.app.notify_provider = None  # what the app itself runs with
        self.assertFalse(smtp_notify.NOTIFY_EXTERNAL_ENABLED)
        with mock.patch('socket.create_connection', side_effect=AssertionError('network')), mock.patch('socket.getaddrinfo', side_effect=AssertionError('dns')), \
                mock.patch.object(smtp_notify, 'read_credential', side_effect=AssertionError('credential')):
            for body in ({'what': 'channel', 'enabled': True}, {'what': 'test'}):
                with self.assertRaises(ValueError):
                    self.act('notify', self.a, **body)
            self.app.notify_pass()

    @needs_ssh
    def test_failure_and_recovery_of_one_site_are_mailed_once_and_the_other_site_stays_silent(self):
        self.grant()
        now = utc_now()
        self.check(self.a, down, now - timedelta(minutes=30))  # before it was switched on: never mailed late
        self.act('notify', self.a, what='channel', enabled=True)
        self.act('notify', self.a, what='site', enabled=True)
        self.check(self.a, ok, now + timedelta(seconds=1))      # recovery
        self.check(self.b, down, now + timedelta(seconds=1))    # the other site is not switched on
        with mock.patch('src.noxiworks.site_app.utc_now', return_value=now + timedelta(seconds=5)):
            self.app.notify_pass()
            self.app.notify_pass()
        mails = self.app.notify_provider.calls
        self.assertEqual(len(mails), 1)
        self.assertIn('復旧', mails[0]['body'])
        self.assertIn('alpha-site.com', mails[0]['body'])
        self.assertNotIn('beta-site.com', json.dumps(mails, ensure_ascii=False))
        recent = self.app.status(self.a)['site']['notify']['recent']
        self.assertEqual([r['label'] for r in recent], ['送信受付済み（受信は未確認）'])
        self.assertEqual(self.app.status(self.b)['site']['notify']['recent'], [])
        self.act('notify', self.a, what='site', enabled=False)
        self.check(self.a, down, now + timedelta(seconds=10))
        with mock.patch('src.noxiworks.site_app.utc_now', return_value=now + timedelta(seconds=15)):
            self.app.notify_pass()
        self.assertEqual(len(mails), 1)
        self.assertIsNone(self.app.sites[self.a].notify_error)

    @needs_ssh
    def test_the_test_message_is_an_explicit_action(self):
        self.grant()
        self.assertEqual(self.act('notify', self.b, what='test')['label'], '送信受付済み（受信は未確認）')
        with self.assertRaises(ValueError):
            self.act('notify', self.b, what='test')  # at most one a minute
        self.assertEqual(len(self.app.notify_provider.calls), 1)

    @needs_ssh
    def test_an_expired_grant_sends_nothing_and_says_so(self):
        self.grant()
        self.act('notify', self.a, what='channel', enabled=True)
        self.act('notify', self.a, what='site', enabled=True)
        later = utc_now() + timedelta(days=40)
        self.check(self.a, down, later)
        with mock.patch('src.noxiworks.site_app.utc_now', return_value=later + timedelta(minutes=1)):
            self.app.notify_pass()
            self.assertIn('有効期間外', self.app.sites[self.a].notify_status()['block_reason'])
        self.assertEqual(self.app.notify_provider.calls, [])


class Maintenance(Base):
    def test_tidying_up_needs_a_confirmation_moves_the_file_and_announces_nothing_again(self):
        now = utc_now()
        old = now - timedelta(days=3)
        self.check(self.a, down, old)
        text = (self.root(self.a) / 'http-history.jsonl').read_text('utf-8')
        for body in ({'what': 'archive-http'}, {'what': 'archive-http', 'confirmed': 'yes'}, {'what': 'delete', 'confirmed': True}):
            with self.subTest(body), self.assertRaises(ValueError):
                self.act('maintenance', self.a, **body)
        self.assertEqual((self.root(self.a) / 'http-history.jsonl').read_text('utf-8'), text)
        done = self.act('maintenance', self.a, what='archive-http', confirmed=True)
        self.assertEqual((self.root(self.a) / done['to']).read_text('utf-8'), text)
        self.act('maintenance', self.a, what='archive-notifications', confirmed=True)
        self.assertEqual(notifications.Outbox(self.root(self.a)).all(), [])
        self.check(self.a, down, old + timedelta(minutes=5))  # still down: the same failure is not a new event
        self.assertEqual(notifications.Outbox(self.root(self.a)).all(), [])
        self.check(self.a, ok, old + timedelta(minutes=10))
        self.assertEqual([n['kind'] for n in notifications.Outbox(self.root(self.a)).all()], ['RECOVERY'])
        self.assertEqual(len((self.root(self.a) / 'maintenance-log.jsonl').read_text('utf-8').splitlines()), 2)
        self.assertFalse((self.root(self.b) / 'history-archive').exists())

    def test_nothing_is_tidied_while_a_check_is_running(self):
        self.check(self.a, ok, utc_now())
        with filelock.held(self.root(self.a) / 'http-monitor.lock'), self.assertRaises(BlockingIOError):
            self.act('maintenance', self.a, what='archive-http', confirmed=True)

    def test_a_full_history_stops_before_a_request_and_drops_nothing(self):
        now, calls = utc_now(), []
        self.check(self.a, ok, now)
        size = (self.root(self.a) / 'http-history.jsonl').stat().st_size
        with mock.patch.object(HttpMonitor, 'grant_problems', return_value=[]), mock.patch.object(retention, 'HISTORY_MAX_BYTES', size + http_monitor.HISTORY_RESERVE):
            monitor = self.app.sites[self.a].http_monitor()
            monitor.probe = lambda *a: calls.append(a) or ok(*a)
            monitor.change(lambda s: s.update(enabled=True, next_due_at=format_utc(now)))
            self.assertIn('保存の上限', monitor.run_if_due(now)['blocked'])
            self.assertEqual((monitor.load()['enabled'], monitor.load()['paused_reason']), (False, 'HISTORY_FULL'))
            with self.assertRaises(ValueError):
                monitor.start(now)
            self.assertIn('整理', monitor.status(now)['stop_text'])
        self.assertEqual((calls, (self.root(self.a) / 'http-history.jsonl').stat().st_size), ([], size))

    def test_gaps_and_days_without_observation_are_shown(self):
        now = utc_now()
        with mock.patch.object(HttpMonitor, 'grant_problems', return_value=[]):
            monitor = self.app.sites[self.a].http_monitor()
            monitor.start(now - timedelta(days=5))
            monitor.run(now - timedelta(days=5), 'SCHEDULE')
            monitor.run(now - timedelta(days=2), 'SCHEDULE')
            s = monitor.status(now)
        self.assertEqual((s['state'], s['days_unobserved'], [g['open'] for g in s['gaps']]), ('STALE', 2, [True, False]))
        self.assertIn('STALE', [x['http']['state'] for x in self.app.status()['sites']])
        self.assertTrue(any('HTTP監視' in t for t in self.app.status()['sites'][0]['attention']))


class Backups(Base):
    def test_a_verified_copy_next_to_the_data_folder_and_nothing_else_changes(self):
        before = {p: p.stat().st_mtime_ns for p in self.app.data.rglob('*') if p.is_file() and p.suffix != '.lock'}
        done = self.act('backup', scope='all')
        self.assertEqual((done['ok'], done['verified']), (True, True))
        path = Path(done['path'])
        self.assertEqual(path.parent, self.app.data.with_name('data-backups'))
        self.assertEqual({p: p.stat().st_mtime_ns for p in before}, before)
        self.assertTrue(backup.verify(path)['ok'])
        for s in (self.a, self.b):
            self.assertTrue((path / 'sites' / s / 'site.json').is_file())
        self.app._storage = None
        self.assertEqual(self.app.status()['storage']['backups'], 1)
        restored = App(self.tmp / 'restored')  # documented restore: into a NEW folder
        shutil.copytree(path, self.tmp / 'restored')
        restored.docker_found, restored.background_query = False, mock.MagicMock(return_value=False)
        restored.setup()
        self.assertEqual(set(restored.sites), {self.a, self.b})

    def test_one_site_only_bad_scopes_and_a_running_inspection(self):
        done = self.act('backup', self.b, scope='site')
        names = {p.name for p in (Path(done['path']) / 'sites').iterdir()}
        self.assertEqual(names, {self.b})
        for body in ({}, {'scope': 'site'}, {'scope': 'x'}, {'scope': 'site', 'site_id': 'site-00000000'}, {'scope': 'site', 'site_id': '../data'}):
            with self.subTest(body), self.assertRaises(ValueError):
                self.app.site_action('backup', body)
        with self.app.lock, self.assertRaises(BlockingIOError):
            self.act('backup', scope='all')


if __name__ == '__main__':
    unittest.main()
