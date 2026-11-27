"""Local HTTP monitoring, notifications and their integration (offline: injected probes, synthetic keys, temporary data; no network, no Docker).

The real probe (src/aws_b/probe.run_probe) keeps its own tests (tests/aws_b/test_probe.py); here it is only reached through http_monitor.live_probe,
which must stay off while HTTP_EXTERNAL_ENABLED is False. The grant, the request ledger and the guarded probe process: tests/ui/test_http_boundary.py.
"""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import tempfile
import threading
import time
import unittest
from unittest import mock

from src.aws_b.model import format_utc
from src.noxiworks import filelock, http_monitor, notifications
from src.noxiworks import permit as permits
from src.noxiworks.http_monitor import HttpMonitor
from src.noxiworks.site_workflow import Site
from tools import background_monitor

NOW = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)


def at(minutes=0):
    return NOW + timedelta(minutes=minutes)


def ok(**extra):
    return {'outcome': 'PASS', 'reason': 'HTTP_200', 'http_status': 200, 'elapsed_ms': 120, 'tls_not_after': format_utc(NOW + timedelta(days=60)), 'selected_ip': '93.184.216.34', **extra}


def down(**extra):
    return {'outcome': 'FAIL', 'reason': 'HTTP_503', 'http_status': 503, 'elapsed_ms': 90, 'tls_not_after': format_utc(NOW + timedelta(days=60)), **extra}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='siteproof-http-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = self.tmp / 'data'
        (self.data / 'sites').mkdir(parents=True)
        self.site = Site.register(self.data / 'sites', 'S', 'https://my-site.com/', ['Desktop'], True, NOW)

    def probe(self, *results):
        queue, calls = list(results), []

        def fake(host, path, timeout):
            calls.append((host, path))
            item = queue.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        fake.calls = calls
        return fake

    def monitor(self, *results, grant=lambda now, interval: [], **kw):
        probe = self.probe(*results) if results else None
        m = HttpMonitor(self.site, probe=probe, grant=grant, **kw)
        m.fake = probe
        return m


class Cycle(Base):
    def test_up_down_still_down_recovered(self):
        m = self.monitor(ok(), down(), down(), ok())
        self.assertEqual(m.status(at()), {**m.status(at()), 'state': 'NOT_MONITORED', 'enabled': False})  # off by default: nothing is monitored
        self.assertFalse(m.configured())
        m.start(at())
        states = []
        for i in range(4):
            obs = m.run(at(i * 15), 'SCHEDULE')
            states.append((obs['state'], m.status(at(i * 15 + 1))['state']))
        self.assertEqual(states, [('OK', 'OK'), ('DOWN', 'DOWN'), ('DOWN', 'DOWN'), ('OK', 'OK')])
        self.assertEqual([e['type'] for e in m.events()], ['RECOVERED', 'DOWN', 'OK'])  # the second DOWN is no new event
        kinds = [n['kind'] for n in m.outbox.all()]  # chronological
        self.assertEqual(kinds, ['FAILURE', 'RECOVERY'])  # one announcement per transition: the first PASS and the continuing failure say nothing
        self.assertEqual(len(m.history()), 4)
        self.assertEqual(len(m.fake.calls), 4)  # exactly one request per check: no retry
        self.assertTrue(all(c == ('my-site.com', '/') for c in m.fake.calls))
        for n in m.outbox.all():
            self.assertEqual(n['delivery'], {'app': 'RECORDED', 'sink': None, 'received': 'UNKNOWN'})

    def test_settings_and_history_survive_a_reload(self):
        m = self.monitor(ok(), down())
        m.start(at())
        m.set_interval(1800, at())
        m.run(at(), 'SCHEDULE')
        m.run(at(30), 'SCHEDULE')
        again = HttpMonitor(self.site, grant=lambda now, interval: [])  # a new process: nothing in memory
        s = again.status(at(31))
        self.assertEqual((s['interval_seconds'], s['enabled'], s['state'], s['http_status']), (1800, True, 'DOWN', 503))
        self.assertEqual(len(again.history()), 2)
        self.assertEqual([n['kind'] for n in again.outbox.all()], ['FAILURE'])
        self.assertEqual(again.load()['next_due_at'], format_utc(at(60)))
        with self.assertRaises(ValueError):
            again.set_interval(60, at())  # only 5 / 15 / 30 / 60 minutes
        self.assertEqual(again.load()['interval_seconds'], 1800)

    def test_stale_stopped_and_unmonitored_are_never_shown_as_normal(self):
        m = self.monitor(ok())
        m.start(at())
        m.run(at(), 'SCHEDULE')
        self.assertEqual(m.status(at(10))['state'], 'OK')
        late = m.status(at(31))  # more than two 15-minute intervals without an observation
        self.assertEqual((late['state'], late['last_is_current']), ('STALE', False))
        m.stop(at(32))
        stopped = m.status(at(33))
        self.assertEqual((stopped['state'], stopped['enabled'], stopped['next_due_at']), ('STOPPED', False, None))
        self.assertIsNotNone(stopped['last'])  # shown only as the last observation before it was stopped

    def test_an_exception_or_a_nonsense_result_is_undecided_and_not_retried(self):
        m = self.monitor(RuntimeError('boom'), {'outcome': 'GREAT'}, {'outcome': 'PASS', 'http_status': 99999, 'elapsed_ms': -4})
        m.start(at())
        a, b, c = (m.run(at(i * 15), 'SCHEDULE') for i in range(3))
        self.assertEqual((a['state'], a['reason']), ('UNKNOWN', 'PROBE_ERROR:RuntimeError'))
        self.assertEqual((b['state'], b['reason']), ('UNKNOWN', 'PROBE_RESULT_INVALID'))
        self.assertEqual((c['state'], c['http_status'], c['elapsed_ms']), ('OK', None, None))  # impossible numbers are dropped, not shown
        self.assertEqual(len(m.fake.calls), 3)
        self.assertEqual([n['kind'] for n in m.outbox.all()], ['UNKNOWN', 'CONFIRMED'])  # undecided twice in a row is announced once; then the confirmation

    def test_a_3xx_is_reported_not_followed(self):
        m = self.monitor({'outcome': 'UNKNOWN', 'reason': 'HTTP_301_UNRESOLVED', 'http_status': 301, 'elapsed_ms': 50})
        m.start(at())
        obs = m.run(at(), 'SCHEDULE')
        self.assertEqual((obs['state'], obs['http_status'], obs['reason']), ('UNKNOWN', 301, 'HTTP_301_UNRESOLVED'))
        self.assertEqual(len(m.fake.calls), 1)

    def test_scheduling_only_when_due_and_next_due_follows_the_interval(self):
        m = self.monitor(ok(), ok())
        m.start(at())
        self.assertIsNotNone(m.run_if_due(at()))
        self.assertEqual(m.load()['next_due_at'], format_utc(at(15)))
        self.assertIsNone(m.run_if_due(at(14)))
        self.assertIsNotNone(m.run_if_due(at(15)))
        m.stop(at(16))
        self.assertIsNone(m.run_if_due(at(500)))  # stopped: nothing is due, whatever the clock says
        self.assertEqual(len(m.fake.calls), 2)

    def test_a_running_check_holds_its_own_lock_only(self):
        m = self.monitor(ok())
        m.start(at())
        with filelock.held(m.lock_path):
            self.assertTrue(m.running())
            with self.assertRaises(http_monitor.Busy):
                m.run(at(), 'MANUAL')
        self.assertFalse(m.running())  # released with its holder: the file that stays means nothing, so nothing can go stale
        self.assertEqual(m.run(at(), 'MANUAL')['state'], 'OK')
        self.assertFalse((self.site.root / 'monitor.lock').exists())  # the image monitor's lock is a different file


class Tls(Base):
    def test_expiry_levels_are_shown_and_announced_once_per_certificate_and_level(self):
        m = self.monitor(ok(tls_not_after=format_utc(NOW + timedelta(days=10))), ok(tls_not_after=format_utc(NOW + timedelta(days=10))),
                         ok(tls_not_after=format_utc(NOW + timedelta(days=2))), ok(tls_not_after=format_utc(NOW - timedelta(days=1))))
        m.start(at())
        m.run(at(), 'SCHEDULE')
        s = m.status(at(1))
        self.assertEqual((s['tls']['level'], s['tls']['days_left']), ('WARN', 9))
        m.run(at(15), 'SCHEDULE')  # the same certificate, the same level: no second notice
        self.assertEqual([n['kind'] for n in m.outbox.all()], ['TLS_WARN'])
        m.run(at(30), 'SCHEDULE')
        m.run(at(45), 'SCHEDULE')
        self.assertEqual([n['kind'] for n in m.outbox.all()], ['TLS_WARN', 'TLS_CRITICAL', 'TLS_EXPIRED'])

    def test_a_healthy_certificate_is_quiet_and_an_openssl_date_is_understood(self):
        m = self.monitor(ok(tls_not_after='Jan  5 12:00:00 2027 GMT'))
        m.start(at())
        obs = m.run(at(), 'SCHEDULE')
        self.assertEqual((obs['tls_not_after'], obs['tls_days_left']), ('2027-01-05T12:00:00Z', 41))
        self.assertEqual(m.status(at(1))['tls']['level'], 'OK')
        self.assertEqual(m.outbox.all(), [])

    def test_no_certificate_information_is_unknown_not_ok(self):
        m = self.monitor({'outcome': 'FAIL', 'reason': 'CONNECT_FAILED', 'elapsed_ms': 10})
        m.start(at())
        m.run(at(), 'SCHEDULE')
        self.assertEqual(m.status(at(1))['tls'], {'not_after': None, 'days_left': None, 'level': 'UNKNOWN', 'label': None})


class Safety(Base):
    def test_not_allowed_targets_are_refused(self):
        for url in ('https://10.0.0.1/', 'https://169.254.169.254/', 'https://localhost/', 'https://printer.local/', 'https://my-site.com/a/../b'):
            with self.subTest(url):
                fake = mock.MagicMock(root=self.site.root, info={**self.site.info, 'url': url})
                m = HttpMonitor(fake, probe=self.probe(ok()), grant=lambda now, interval: [])
                self.assertTrue(m.target_problems(), url)
                with self.assertRaises(ValueError):
                    m.start(at())

    def test_without_the_approval_nothing_leaves_the_pc(self):
        m = HttpMonitor(self.site, grant=lambda now, interval: [])  # no probe injected: the real one, and its switch is off
        self.assertFalse(http_monitor.HTTP_EXTERNAL_ENABLED)
        self.assertIn('USERの承認', m.start_block(at()))
        with self.assertRaises(ValueError):
            m.start(at())
        with mock.patch('socket.create_connection', side_effect=AssertionError('network touched')), mock.patch('socket.getaddrinfo', side_effect=AssertionError('dns touched')):
            with self.assertRaises(http_monitor.ExternalDisabled):
                http_monitor.live_probe(self.site.root, 'SCHEDULE', 900)
            s = m.load()
            s['enabled'] = True
            m.save(s)  # even a settings file edited by hand cannot make it request
            self.assertEqual(m.run(at(), 'SCHEDULE')['blocked'], http_monitor.DISABLED_TEXT)
        self.assertEqual((m.load()['enabled'], m.load()['paused_reason']), (False, 'BLOCKED'))
        self.assertEqual(m.history(), [])  # nothing was observed

    def test_a_missing_or_ended_grant_stops_the_monitor_without_a_request(self):
        state = {'problems': []}
        m = self.monitor(ok(), ok(), grant=lambda now, interval: state['problems'])
        m.start(at())
        m.run(at(), 'SCHEDULE')
        state['problems'] = ['HTTP監視の許可が有効期間外です']  # the grant ended
        blocked = m.run(at(15), 'SCHEDULE')
        self.assertIn('有効期間外', blocked['blocked'])
        self.assertEqual((m.load()['enabled'], m.load()['paused_reason']), (False, 'BLOCKED'))
        self.assertEqual(len(m.fake.calls), 1)
        with self.assertRaises(ValueError):
            m.start(at(20))

    def test_the_image_permit_is_not_an_http_grant_and_stopping_one_channel_does_not_start_the_other(self):
        self.assertNotEqual(http_monitor.GRANT_SCHEMA, permits.SCHEMA)
        image = self.site.root / 'monitor.json'
        image.write_text(json.dumps({'enabled': False, 'marker': 1}), encoding='utf-8')
        m = self.monitor(ok())
        m.start(at())
        m.run(at(), 'SCHEDULE')
        m.stop(at(1))
        self.assertEqual(json.loads(image.read_text('utf-8')), {'enabled': False, 'marker': 1})  # the image monitor's file was never touched

    def test_the_live_probe_hands_over_the_unit_folder_only(self):
        from src.noxiworks import http_isolation
        with mock.patch.object(http_monitor, 'HTTP_EXTERNAL_ENABLED', True), mock.patch.object(http_isolation, 'launch', return_value=ok()) as launch:
            http_monitor.live_probe(self.site.root, 'SCHEDULE', 900)
        launch.assert_called_once_with(self.site.root, 'SCHEDULE', 900)  # no host, path or address can be passed: the isolated run derives them itself

    def test_a_refusal_in_the_run_is_no_observation_and_stops_only_when_it_must(self):
        answers = [{'refused': 'RATE_LIMITED', 'message': 'まだ', 'not_before': format_utc(at(3))}, {'refused': 'GRANT_EXHAUSTED', 'message': '使い切り'}]
        m = self.monitor()
        with mock.patch.object(http_monitor, 'HTTP_EXTERNAL_ENABLED', True), mock.patch.object(http_monitor, 'live_probe', side_effect=lambda *a: answers.pop(0)):
            m.start(at())
            self.assertEqual(m.run(at(), 'SCHEDULE')['code'], 'RATE_LIMITED')
            self.assertEqual((m.load()['enabled'], m.load()['next_due_at']), (True, format_utc(at(3))))  # only postponed
            self.assertEqual(m.run(at(3), 'SCHEDULE')['code'], 'GRANT_EXHAUSTED')
        self.assertEqual((m.load()['enabled'], m.load()['paused_reason'], m.load()['next_due_at']), (False, 'GRANT_EXHAUSTED', None))
        self.assertEqual((m.history(), m.outbox.all()), ([], []))

    def test_a_manual_check_pressed_too_early_never_brings_the_scheduled_one_forward(self):
        # seen in the field: a scheduled check, then 今すぐ検査 within the grant's 60 s -> refused (nothing requested), and the schedule must stay at +interval
        answers = [ok(), {'refused': 'RATE_LIMITED', 'message': 'まだ', 'not_before': format_utc(at(1))}]
        m = self.monitor()
        with mock.patch.object(http_monitor, 'HTTP_EXTERNAL_ENABLED', True), mock.patch.object(http_monitor, 'live_probe', side_effect=lambda *a: answers.pop(0)):
            m.start(at())
            m.run(at(), 'SCHEDULE')
            scheduled = m.load()['next_due_at']
            self.assertEqual(scheduled, format_utc(at(15)))
            self.assertEqual(m.run(at(0.5), 'MANUAL')['code'], 'RATE_LIMITED')
        self.assertEqual(m.load()['next_due_at'], scheduled)
        self.assertEqual(len(m.history()), 1)

    def test_a_violation_of_the_boundary_stops_monitoring_until_the_user_looks(self):
        m = self.monitor({'outcome': 'UNKNOWN', 'reason': 'ISOLATION_VIOLATION'})
        m.start(at())
        self.assertEqual(m.run(at(), 'SCHEDULE')['state'], 'UNKNOWN')
        self.assertEqual((m.load()['enabled'], m.load()['paused_reason']), (False, 'BOUNDARY'))

    def test_without_docker_nothing_is_observed_and_monitoring_is_not_stopped(self):
        answers = [{'refused': 'ENGINE_UNAVAILABLE', 'message': 'Docker Desktopが動いていない'}, ok()]
        m = self.monitor()
        with mock.patch.object(http_monitor, 'HTTP_EXTERNAL_ENABLED', True), mock.patch.object(http_monitor, 'live_probe', side_effect=lambda *a: answers.pop(0)):
            m.start(at())
            self.assertEqual(m.run(at(), 'SCHEDULE')['code'], 'ENGINE_UNAVAILABLE')
            s = m.status(at(1))
            self.assertEqual((s['enabled'], s['state'], s['not_run']['code'], s['next_due_at']), (True, 'NOT_MONITORED', 'ENGINE_UNAVAILABLE', format_utc(at(5))))
            self.assertEqual((m.history(), m.outbox.all()), ([], []))  # not an outage, not "normal"
            m.run(at(5), 'SCHEDULE')
        self.assertIsNone(m.status(at(6))['not_run'])

    def test_a_manual_check_neither_starts_nor_stops_monitoring(self):
        state = {'problems': []}
        m = self.monitor(ok(), grant=lambda now, interval: state['problems'])
        self.assertEqual(m.check_now(at())['trigger'], 'MANUAL')
        self.assertEqual((m.load()['enabled'], m.load()['next_due_at'], m.status(at(1))['state']), (False, None, 'NOT_MONITORED'))
        state['problems'] = ['HTTP監視の許可が有効期間外です']
        with self.assertRaises(ValueError):
            m.check_now(at(5))
        self.assertEqual(len(m.fake.calls), 1)

    def test_a_stop_during_a_check_is_never_overwritten_and_a_second_process_does_not_check_again(self):
        m = self.monitor(ok())
        m.start(at())

        def stopping(host, path, timeout):  # the USER presses stop while the request is running
            HttpMonitor(self.site, grant=lambda now, interval: []).stop(at())
            return ok()
        m.probe = stopping
        m.run(at(), 'SCHEDULE')
        self.assertEqual((m.load()['enabled'], m.load()['next_due_at'], m.load()['paused_reason']), (False, None, 'USER'))
        self.assertIsNone(m.run_if_due(at(600)))  # stays stopped
        m2 = self.monitor(ok())
        m2.start(at(700))
        with mock.patch.object(HttpMonitor, 'is_due', side_effect=[True, False]):  # due when asked, done by someone else once the lock is held
            self.assertIsNone(m2.run_if_due(at(700)))
        self.assertEqual(m2.fake.calls, [])

    def test_missed_checks_are_not_made_up_for(self):
        m = self.monitor(ok(), ok())
        m.start(at())
        m.run_if_due(at())
        self.assertIsNotNone(m.run_if_due(at(60 * 24 * 3)))  # the PC was off for three days: one check, not 288
        self.assertIsNone(m.run_if_due(at(60 * 24 * 3)))
        self.assertEqual(len(m.fake.calls), 2)


class Notices(Base):
    def test_a_sink_gets_one_message_and_a_send_is_never_a_receipt(self):
        sink_file = self.tmp / 'mock-sink.jsonl'
        m = self.monitor(down(), down(), ok(), sink=notifications.MockFileSink(sink_file))
        m.start(at())
        for i in range(3):
            m.run(at(i * 15), 'SCHEDULE')
        sent = [json.loads(x) for x in sink_file.read_text('utf-8').splitlines()]
        self.assertEqual(len(sent), 2)  # failure once (not twice), then recovery
        self.assertIn('障害', sent[0]['body'])
        self.assertIn('復旧', sent[1]['body'])
        self.assertEqual({n['delivery']['sink'] for n in m.outbox.all()}, {'SENT'})
        self.assertEqual({n['delivery']['received'] for n in m.outbox.all()}, {'UNKNOWN'})

    def test_a_failing_sink_is_recorded_not_retried_and_does_not_lose_the_observation(self):
        calls = []

        def broken(subject, body):
            calls.append(subject)
            raise ConnectionError('refused')
        m = self.monitor(down(), down(), sink=broken)
        m.start(at())
        m.run(at(), 'SCHEDULE')
        m.run(at(15), 'SCHEDULE')
        self.assertEqual(len(calls), 1)
        self.assertEqual(m.outbox.all()[0]['delivery']['sink'], 'FAILED:ConnectionError')
        self.assertEqual(len(m.history()), 2)

    def test_the_same_event_is_never_announced_twice_even_across_restarts(self):
        box = notifications.Outbox(self.site.root)
        first = box.add('k1', 'FAILURE', 't', 'T', 'B', 'http')
        again = notifications.Outbox(self.site.root).add('k1', 'FAILURE', 't', 'T', 'B', 'http')
        self.assertIsNotNone(first)
        self.assertIsNone(again)

    def test_image_events_only_when_the_result_becomes_a_change_or_a_problem(self):
        box = notifications.Outbox(self.site.root)
        run = lambda outcome, prev, n: notifications.image_event(box, {'outcome': outcome, 'run_id': 'r%d' % n, 'finished_at': 't%d' % n}, prev, target_id='p', label='S')
        self.assertIsNone(run('UNCHANGED', None, 1))
        self.assertEqual(run('CHANGED', 'UNCHANGED', 2)['kind'], 'IMAGE_CHANGED')
        self.assertIsNone(run('CHANGED', 'CHANGED', 3))  # still changed: not announced again
        self.assertIsNone(run('UNCHANGED', 'CHANGED', 4))
        self.assertEqual(run('UNKNOWN', 'UNCHANGED', 5)['kind'], 'IMAGE_UNKNOWN')
        self.assertEqual(run('FAILED', 'UNKNOWN', 6)['kind'], 'IMAGE_FAILED')
        self.assertEqual(len(box.all()), 3)

    def test_the_image_monitor_announces_a_change_once(self):
        from src.noxiworks.site_monitor import Monitor
        monitor = Monitor.create(self.site, NOW)
        monitor.fixture_capture = True  # the offline fixture engine (no browser, no network)
        monitor.update(NOW, offline_fixture='same')
        self.assertEqual(monitor.run(at(0), 'MANUAL')['outcome'], 'BASELINE_CREATED')
        monitor.update(at(1), offline_fixture='changed')
        self.assertEqual(monitor.run(at(2), 'MANUAL')['outcome'], 'CHANGED')
        self.assertEqual(monitor.run(at(3), 'MANUAL')['outcome'], 'CHANGED')  # the Baseline was not replaced: still changed
        self.assertEqual([n['kind'] for n in notifications.Outbox(self.site.root).all()], ['IMAGE_CHANGED'])


class Background(Base):
    def tick_data(self, http_enabled):
        s = http_monitor.default_settings()
        s.update(enabled=http_enabled, ever_enabled=True, next_due_at=format_utc(datetime.now(timezone.utc) - timedelta(minutes=1)))  # tick uses the real clock
        (self.site.root / 'http-monitor.json').write_text(json.dumps(s), encoding='utf-8')

    def patches(self):
        return (mock.patch.object(http_monitor, 'HTTP_EXTERNAL_ENABLED', True), mock.patch.object(HttpMonitor, 'grant_problems', return_value=[]),
                mock.patch.object(http_monitor, 'live_probe', return_value=ok()))

    def test_http_only_never_starts_the_browser_docker_or_the_image_monitor(self):
        (self.site.root / 'monitor.json').write_text(json.dumps({'enabled': False, 'next_due_at': None, 'interval_seconds': 86400}), encoding='utf-8')
        self.tick_data(True)
        a, b, c = self.patches()
        with a, b, c, mock.patch('src.noxiworks.site_monitor.main') as image, mock.patch.object(background_monitor, 'ensure_docker') as docker:
            self.assertEqual(background_monitor.http_tick(self.data), 0)
        image.assert_not_called()
        docker.assert_not_called()
        self.assertEqual(len(HttpMonitor(self.site).history()), 1)
        self.assertEqual(json.loads((self.site.root / 'monitor.json').read_text('utf-8'))['enabled'], False)

    def test_a_stopped_http_monitor_checks_nothing_and_does_not_start_anything_else(self):
        (self.site.root / 'monitor.json').write_text(json.dumps({'enabled': False, 'next_due_at': None, 'interval_seconds': 86400}), encoding='utf-8')
        self.tick_data(False)
        a, b, c = self.patches()
        with a, b, c as probe, mock.patch('src.noxiworks.site_monitor.main') as image:
            background_monitor.http_tick(self.data)
        probe.assert_not_called()
        image.assert_not_called()

    def test_the_image_tick_never_runs_the_http_check(self):
        (self.site.root / 'monitor.json').write_text(json.dumps({'enabled': True, 'next_due_at': format_utc(NOW - timedelta(days=1)), 'interval_seconds': 86400}), encoding='utf-8')
        self.tick_data(True)  # enabled and due
        a, b, c = self.patches()
        with a, b, c as probe, mock.patch('src.noxiworks.site_monitor.main', return_value=0) as image, mock.patch.object(background_monitor, 'due', return_value=True):
            background_monitor.tick(self.data, now=NOW, docker=mock.MagicMock(return_value=True))
        image.assert_called_once()
        probe.assert_not_called()
        self.assertEqual(HttpMonitor(self.site).history(), [])

    def test_a_long_capture_does_not_hold_back_the_http_check(self):
        (self.site.root / 'monitor.json').write_text(json.dumps({'enabled': True, 'next_due_at': format_utc(NOW - timedelta(days=1)), 'interval_seconds': 86400}), encoding='utf-8')
        self.tick_data(True)
        seen = {}

        def long_capture(argv):  # the image inspection: returns only once the HTTP check has been made meanwhile
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and not HttpMonitor(self.site).history():
                time.sleep(0.05)
            seen['http_during_capture'] = len(HttpMonitor(self.site).history())
            return 0
        a, b, c = self.patches()
        with a, b, c, mock.patch('src.noxiworks.site_monitor.main', side_effect=long_capture), mock.patch.object(background_monitor, 'due', return_value=True):
            image = threading.Thread(target=background_monitor.tick, kwargs={'data': self.data, 'now': NOW, 'docker': mock.MagicMock(return_value=True)})
            image.start()  # the image task ...
            self.assertEqual(background_monitor.http_tick(self.data), 0)  # ... and the HTTP task run in parallel, as two Windows tasks would
            image.join(30)
        self.assertFalse(image.is_alive())
        self.assertEqual(seen['http_during_capture'], 1)


class AppIntegration(Base):
    def app(self):
        from src.noxiworks.app import App
        app = App(self.data)
        app.setup()
        app.site = self.site
        app.http_probe = self.probe(ok(), down())
        return app

    def test_status_start_stop_interval_and_isolation_from_the_image_monitor(self):
        app = self.app()
        http = app.http_status()
        self.assertEqual((http['state'], http['enabled'], http['can_start']), ('NOT_MONITORED', False, False))
        self.assertIn('許可', http['start_block'])  # no signed grant yet
        with mock.patch.object(HttpMonitor, 'grant_problems', return_value=[]):
            self.assertEqual(app.site_action('http', {'what': 'start'})['state'], 'NOT_MONITORED')  # started, nothing observed yet
            app.http_monitor().run(NOW, 'MANUAL')
            app.site_action('http', {'what': 'interval', 'interval_seconds': 300})
            http = app.http_status()
            self.assertEqual((http['enabled'], http['interval_seconds'], http['last']['state']), (True, 300, 'OK'))
            json.dumps(http)  # the session JSON must be serialisable
            self.assertEqual(app.site_action('http', {'what': 'stop'})['state'], 'STOPPED')
        with self.assertRaises(ValueError):
            app.site_action('http', {'what': 'explode'})
        with self.assertRaises(ValueError):
            app.site_action('http', {'what': 'interval', 'interval_seconds': 10})

    def test_the_http_route_is_a_site_route_and_the_panel_is_wired_into_the_screens(self):
        from src.noxiworks import app as app_module
        self.assertIn('/app/api/site/http', app_module.SITE_ROUTES)
        js = (Path(app_module.__file__).with_name('app_assets') / 'app.js').read_text('utf-8')
        for needle in ("function httpPanel", "'/app/api/site/http'", 'httpPanel(state)', '停止前の最後の観測', '最後の観測が古いため、現在の状態は不明です', 'qualityText',
                       '比較に使えます（正式な品質認証は未確認）', '受信は未確認'):
            self.assertIn(needle, js)



class ReasonLabels(unittest.TestCase):
    def test_every_reason_the_check_can_give_reads_as_japanese_and_unknown_codes_stay_visible(self):
        label = http_monitor.reason_label
        for code in ('CONNECT_TIMEOUT', 'CONNECT_FAILED', 'HTTP_TIMEOUT', 'TLS_FAILED', 'HTTP_503', 'HTTP_200', 'HTTP_302_UNRESOLVED', 'ISOLATION_VIOLATION',
                     'ISOLATION_SETUP_FAILED:RULES', 'ISOLATION_INCOMPLETE:AUDIT', 'DESTINATION_PRIVATE_ADDRESS', 'DESTINATION_DNS_NO_ADDRESS', 'DNS_ERROR',
                     'DESTINATION_FIRST_ADDRESS_NOT_IPV4', 'PROBE_ERROR:OSError', 'HTTP_INCOMPLETE'):
            with self.subTest(code):
                self.assertNotEqual(label(code), code)
                self.assertNotRegex(label(code), r'^[A-Z_:0-9]+$')
        self.assertIn('503', label('HTTP_503'))
        self.assertEqual(label('SOMETHING_NEW'), 'SOMETHING_NEW')
        self.assertEqual(label(None), '')


if __name__ == '__main__':
    unittest.main()
