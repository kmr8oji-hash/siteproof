"""The two background channels of tools/background_monitor.py (offline: schtasks, Docker, the image monitor and the HTTP probe are all replaced; nothing is
registered, nothing is requested, no browser starts). Image = `tick` every 15 min, HTTP = `http-tick` every 5 min, separate tasks, names, launchers and logs."""
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from src.aws_b.model import format_utc
from src.noxiworks import http_monitor
from src.noxiworks.http_monitor import HttpMonitor
from src.noxiworks.site_workflow import Site
from tools import background_monitor as bm

NOW = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)


def ok():
    return {'outcome': 'PASS', 'reason': 'HTTP_200', 'http_status': 200, 'elapsed_ms': 90, 'tls_not_after': format_utc(NOW + timedelta(days=60)), 'selected_ip': '93.184.216.34'}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='siteproof-channels-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = self.tmp / 'data'
        (self.data / 'sites').mkdir(parents=True)
        self.a = Site.register(self.data / 'sites', 'A', 'https://my-site.com/', ['Desktop'], True, NOW)
        self.b = Site.register(self.data / 'sites', 'B', 'https://other-site.com/', ['Desktop'], True, NOW + timedelta(seconds=1))
        self.python = self.tmp / 'py' / 'python.exe'
        self.python.parent.mkdir()
        self.python.write_bytes(b'')
        (self.python.parent / 'pythonw.exe').write_bytes(b'')
        patch = mock.patch.object(bm.sys, 'executable', str(self.python))
        patch.start()
        self.addCleanup(patch.stop)

    def one_site(self):
        shutil.rmtree(self.b.root)
        return self.a

    def set_image(self, site, enabled=True, due=NOW):
        (site.root / 'monitor.json').write_text(json.dumps({'enabled': enabled, 'next_due_at': format_utc(due), 'interval_seconds': 900}), encoding='utf-8')

    def set_http(self, site, enabled=True, due=NOW, **extra):
        s = http_monitor.default_settings()
        s.update(enabled=enabled, ever_enabled=True, next_due_at=format_utc(due) if enabled else None, **extra)
        (site.root / 'http-monitor.json').write_text(json.dumps(s), encoding='utf-8')

    def http_patches(self, stack, probe=None, grant=()):
        """HTTP external communication 'on' with a fake request function and a grant verdict; -> the fake request."""
        probe = probe or mock.MagicMock(return_value=ok())
        stack.enter_context(mock.patch.object(http_monitor, 'HTTP_EXTERNAL_ENABLED', True))
        stack.enter_context(mock.patch.object(HttpMonitor, 'grant_problems', return_value=list(grant)))
        stack.enter_context(mock.patch.object(http_monitor, 'live_probe', probe))
        return probe

    def quiet_dispatch(self, stack):
        return stack.enter_context(mock.patch('src.noxiworks.notify_dispatch.Dispatcher'))

    def history(self, site):
        return HttpMonitor(site).history()

    def fake_clock(self, start=NOW):
        state = {'t': start, 'sleeps': []}

        def sleep(seconds):
            state['sleeps'].append(seconds)
            state['t'] += timedelta(seconds=seconds)
        return state, (lambda: state['t']), sleep


class Names(Base):
    def test_names_differ_per_data_folder_site_and_channel_and_the_old_name_is_never_made(self):
        other = self.tmp / 'data2'
        (other / 'sites').mkdir(parents=True)
        names = {bm.task_name(self.data, s.root.name, c) for s in (self.a, self.b) for c in ('image', 'http')} | {bm.task_name(other, self.a.root.name, c) for c in ('image', 'http')}
        self.assertEqual(len(names), 6)
        for name in names:
            self.assertRegex(name, r'^SiteProof-(Image|Http)-site-[0-9a-f]{8}-[0-9a-f]{8}$')
            self.assertFalse(name.startswith('SiteProof-Monitor-'))
        self.assertEqual(bm.task_name(self.data, self.a.root.name, 'http'), bm.task_name(self.data, self.a.root.name, 'http'))  # stable
        self.assertEqual(bm.data_hash(self.data), bm.data_hash(str(self.data).replace('data', 'data')))
        with self.assertRaises(ValueError):
            bm.task_name(self.data, self.a.root.name, 'monitor')
        with mock.patch.object(bm, 'schtasks') as schtasks, mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            for channel in ('image', 'http'):
                bm.install(self.data, None, True, self.a.root.name, channel)
        schtasks.assert_not_called()
        self.assertNotIn('SiteProof-Monitor-', out.getvalue())

    def test_the_site_may_be_left_out_only_with_exactly_one_site(self):
        with mock.patch.object(bm, 'schtasks') as schtasks:
            with self.assertRaises(SystemExit) as stop:
                bm.main(['install', '--data', str(self.data), '--channel', 'image', '--dry-run'])
            self.assertIn('--site', str(stop.exception))
            with self.assertRaises(SystemExit) as stop:
                bm.main(['install', '--data', str(self.data), '--site', 'site-00000000', '--channel', 'http', '--dry-run'])
            self.assertIn('登録されていない', str(stop.exception))
            schtasks.assert_not_called()
        shutil.rmtree(self.b.root)
        with mock.patch.object(bm, 'schtasks') as schtasks, mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(bm.main(['install', '--data', str(self.data), '--channel', 'http', '--dry-run']), 0)
        schtasks.assert_not_called()
        self.assertIn('/TN ' + bm.task_name(self.data, self.a.root.name, 'http'), out.getvalue())
        with mock.patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit):
            bm.main(['install', '--data', str(self.data), '--dry-run'])  # a channel is always named
        with mock.patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit):
            bm.main(['remove', '--data', str(self.data)])  # remove needs a channel (or --legacy)


class Install(Base):
    def test_each_channel_has_its_own_launcher_log_interval_and_command(self):
        done = mock.MagicMock(returncode=0, stdout='ok', stderr='')
        with mock.patch.object(bm, 'schtasks', return_value=done) as schtasks, mock.patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(bm.install(self.data, None, False, self.a.root.name, 'image'), 0)
            self.assertEqual(bm.install(self.data, None, False, self.a.root.name, 'http'), 0)
        image, http = (c[0] for c in schtasks.call_args_list)
        self.assertEqual((image[image.index('/MO') + 1], http[http.index('/MO') + 1]), ('15', '5'))
        self.assertEqual((image[image.index('/TN') + 1], http[http.index('/TN') + 1]), (bm.task_name(self.data, self.a.root.name, 'image'), bm.task_name(self.data, self.a.root.name, 'http')))
        folder = self.data.resolve() / 'background'
        for name, action in (('image', 'tick'), ('http', 'http-tick')):
            cmd = (folder / f'{self.a.root.name}-{name}.cmd').read_text('ascii')
            line = next(x for x in cmd.splitlines() if 'background_monitor.py' in x)
            self.assertIn(f'background_monitor.py {action} --data "{self.data.resolve()}" --site {self.a.root.name}', line)
            self.assertTrue(line.endswith(f'>> "{folder / (self.a.root.name + "-" + name + ".log")}" 2>&1'))
            self.assertTrue(line.startswith('"' + str((self.python.parent / 'pythonw.exe').resolve()) + '" -B '))
            args = image if name == 'image' else http
            self.assertEqual(args[args.index('/TR') + 1], '"' + str(folder / (self.a.root.name + '-' + name + '.cmd')) + '"')
        self.assertIn('--every 5', (folder / f'{self.a.root.name}-http.cmd').read_text('ascii'))
        self.assertNotIn('--every', (folder / f'{self.a.root.name}-image.cmd').read_text('ascii'))
        self.assertFalse((folder / 'tick.cmd').exists())
        with mock.patch.object(bm, 'schtasks', return_value=done), mock.patch('sys.stdout', new_callable=io.StringIO), self.assertRaises(SystemExit):
            bm.install(self.data, 0, False, self.a.root.name, 'http')

    def test_dry_run_registers_nothing_and_no_python_writes_nothing(self):
        with mock.patch.object(bm, 'schtasks') as schtasks, mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            bm.install(self.data, None, True, self.a.root.name, 'http')
        schtasks.assert_not_called()
        self.assertTrue(out.getvalue().startswith('schtasks /Create'))
        shutil.rmtree(self.data / 'background')
        with mock.patch.object(bm.sys, 'executable', str(self.tmp / 'nowhere' / 'python.exe')), mock.patch.object(bm, 'schtasks') as schtasks:
            with self.assertRaises(SystemExit):
                bm.install(self.data, None, False, self.a.root.name, 'http')
        schtasks.assert_not_called()
        self.assertFalse((self.data / 'background').exists())

    def test_remove_deletes_only_its_own_task_and_the_old_name_only_on_request(self):
        done = mock.MagicMock(returncode=0, stdout='gone', stderr='')
        site = self.a.root.name
        with mock.patch.object(bm, 'schtasks', return_value=done) as schtasks, mock.patch('sys.stdout', new_callable=io.StringIO):
            bm.remove(self.data, site, 'http')
            self.assertEqual([c[0] for c in schtasks.call_args_list], [('/Delete', '/F', '/TN', bm.task_name(self.data, site, 'http'))])
            schtasks.reset_mock()
            bm.remove(self.data, site, 'image')
            self.assertEqual([c[0][3] for c in schtasks.call_args_list], [bm.task_name(self.data, site, 'image')])
            schtasks.reset_mock()
            bm.remove(self.data, site, None, legacy=True)
            self.assertEqual([c[0] for c in schtasks.call_args_list], [('/Delete', '/F', '/TN', 'SiteProof-Monitor-' + site)])
            schtasks.reset_mock()
            bm.remove(self.data, site, 'http', legacy=True)
            self.assertEqual([c[0][3] for c in schtasks.call_args_list], [bm.task_name(self.data, site, 'http'), 'SiteProof-Monitor-' + site])

    def test_status_shows_both_channels_asks_read_only_and_mentions_the_old_task(self):
        site = self.a.root.name
        (self.data / 'background').mkdir()
        (self.data / 'background' / f'{site}-http.log').write_text('one\ntwo\n', encoding='utf-8')

        def ask(*args):
            self.assertEqual(args[0], '/Query')  # never anything but a question
            found = args[2] == 'SiteProof-Monitor-' + site
            return mock.MagicMock(returncode=0 if found else 1, stdout='TaskName: x' if found else '', stderr='')
        with mock.patch.object(bm, 'schtasks', side_effect=ask) as schtasks, mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(bm.main(['status', '--data', str(self.data), '--site', site]), 0)
        asked = [c[0][2] for c in schtasks.call_args_list]
        self.assertEqual(asked, [bm.task_name(self.data, site, 'image'), bm.task_name(self.data, site, 'http'), 'SiteProof-Monitor-' + site])
        text = out.getvalue()
        self.assertIn(bm.task_name(self.data, site, 'image') + ': 登録されていません', text)
        self.assertIn('古い名前のタスク', text)
        self.assertIn('two', text)
        with mock.patch.object(bm, 'schtasks', side_effect=ask) as schtasks, mock.patch('sys.stdout', new_callable=io.StringIO):
            bm.main(['status', '--data', str(self.data), '--site', site, '--channel', 'http'])
        self.assertEqual([c[0][2] for c in schtasks.call_args_list], [bm.task_name(self.data, site, 'http'), 'SiteProof-Monitor-' + site])


class ImageTick(Base):
    def test_the_image_tick_never_runs_http_and_goes_through_every_due_site_even_when_one_fails(self):
        for site in (self.a, self.b):
            self.set_image(site)
            self.set_http(site)
        calls = []

        def monitor(argv):
            calls.append(argv)
            if argv[-1] == self.a.root.name:
                raise RuntimeError('boom')
            return 0
        with ExitStack() as stack:
            probe = self.http_patches(stack)
            self.quiet_dispatch(stack)
            stack.enter_context(mock.patch('src.noxiworks.site_monitor.main', side_effect=monitor))
            stack.enter_context(mock.patch('sys.stdout', new_callable=io.StringIO))
            code = bm.tick(self.data, now=NOW, docker=mock.MagicMock())
        self.assertEqual([c[-1] for c in calls], [self.a.root.name, self.b.root.name])  # the second one ran although the first raised
        self.assertEqual(code, 1)
        probe.assert_not_called()
        self.assertEqual((self.history(self.a), self.history(self.b)), ([], []))

    def test_docker_is_asked_once_and_only_for_a_due_site_with_a_permit(self):
        for site in (self.a, self.b):
            self.set_image(site)
        docker = mock.MagicMock(return_value=True)
        with ExitStack() as stack:
            self.quiet_dispatch(stack)
            stack.enter_context(mock.patch('src.noxiworks.site_monitor.main', return_value=0))
            bm.tick(self.data, now=NOW, docker=docker)
            docker.assert_not_called()
            for site in (self.a, self.b):
                (site.root / 'real').mkdir()
                (site.root / 'real' / 'permit.json').write_text('{}', encoding='utf-8')
            self.set_image(self.b, enabled=False)
            self.set_image(self.a, due=NOW + timedelta(hours=1))
            bm.tick(self.data, now=NOW, docker=docker)
            docker.assert_not_called()  # the one with a permit is not due, the due one is stopped
            self.set_image(self.a)
            self.set_image(self.b)
            bm.tick(self.data, now=NOW, docker=docker)
            docker.assert_called_once()

    def test_an_installed_old_launcher_without_site_still_runs_image_only(self):
        self.set_image(self.a)
        self.set_http(self.a)
        with ExitStack() as stack:
            probe = self.http_patches(stack)
            self.quiet_dispatch(stack)
            image = stack.enter_context(mock.patch('src.noxiworks.site_monitor.main', return_value=0))
            stack.enter_context(mock.patch.object(bm, 'due', return_value=True))
            stack.enter_context(mock.patch('sys.stdout', new_callable=io.StringIO))
            self.assertEqual(bm.main(['tick', '--data', str(self.data)]), 0)
        self.assertEqual(image.call_count, 2)  # both sites
        probe.assert_not_called()


class HttpTick(Base):
    def test_it_never_starts_docker_a_browser_or_the_image_monitor(self):
        for site in (self.a, self.b):
            self.set_http(site, due=datetime.now(timezone.utc) - timedelta(minutes=1))
            self.set_image(site)
            (site.root / 'real').mkdir()
            (site.root / 'real' / 'permit.json').write_text('{}', encoding='utf-8')
        with ExitStack() as stack:
            probe = self.http_patches(stack)
            self.quiet_dispatch(stack)
            image = stack.enter_context(mock.patch('src.noxiworks.site_monitor.main'))
            docker = stack.enter_context(mock.patch.object(bm, 'ensure_docker'))
            browser = stack.enter_context(mock.patch('subprocess.Popen'))
            run = stack.enter_context(mock.patch('subprocess.run'))
            self.assertEqual(bm.main(['http-tick', '--data', str(self.data)]), 0)
        self.assertEqual(probe.call_count, 2)
        for fake in (image, docker, browser, run):
            fake.assert_not_called()
        self.assertEqual([len(self.history(s)) for s in (self.a, self.b)], [1, 1])

    def test_it_waits_for_the_due_time_in_short_steps_and_makes_one_check(self):
        self.set_http(self.a, due=NOW + timedelta(seconds=32))
        state, now_fn, sleep = self.fake_clock()
        with ExitStack() as stack:
            probe = self.http_patches(stack)
            self.quiet_dispatch(stack)
            bm.http_tick(self.data, 5, self.a.root.name, now_fn=now_fn, sleep=sleep)
        self.assertEqual(probe.call_count, 1)
        self.assertTrue(all(0 < x <= 5 for x in state['sleeps']), state['sleeps'])
        self.assertEqual(sum(state['sleeps']), 32)
        self.assertEqual(len(self.history(self.a)), 1)

    def test_a_check_that_is_not_due_within_the_window_is_left_alone_silently(self):
        self.set_http(self.a, due=NOW + timedelta(seconds=bm.CHANNELS['http']['every'] * 60 - bm.WINDOW_MARGIN + 1))
        self.set_http(self.b, enabled=False)
        state, now_fn, sleep = self.fake_clock()
        with ExitStack() as stack:
            probe = self.http_patches(stack)
            self.quiet_dispatch(stack)
            out = stack.enter_context(mock.patch('sys.stdout', new_callable=io.StringIO))
            self.assertEqual(bm.http_tick(self.data, 5, now_fn=now_fn, sleep=sleep), 0)
        probe.assert_not_called()
        self.assertEqual((state['sleeps'], out.getvalue()), ([], ''))
        shutil.rmtree(self.b.root)  # not configured at all: the same
        (self.a.root / 'http-monitor.json').unlink()
        with ExitStack() as stack:
            probe = self.http_patches(stack)
            self.quiet_dispatch(stack)
            self.assertEqual(bm.http_tick(self.data, 5, now_fn=now_fn, sleep=sleep), 0)
        probe.assert_not_called()

    def test_a_stop_during_the_wait_is_honoured_at_once(self):
        self.set_http(self.a, due=NOW + timedelta(seconds=60))
        state, now_fn, sleep = self.fake_clock()

        def stopping_sleep(seconds):
            sleep(seconds)
            if len(state['sleeps']) == 3:  # the USER presses 停止 in the app while the task waits
                HttpMonitor(self.a).stop(state['t'])
        with ExitStack() as stack:
            probe = self.http_patches(stack)
            self.quiet_dispatch(stack)
            bm.http_tick(self.data, 5, self.a.root.name, now_fn=now_fn, sleep=stopping_sleep)
        probe.assert_not_called()
        self.assertEqual(len(state['sleeps']), 3)
        settings = json.loads((self.a.root / 'http-monitor.json').read_text('utf-8'))
        self.assertEqual((settings['enabled'], settings['paused_reason']), (False, 'USER'))

    def test_a_missing_or_expired_grant_makes_no_request_stops_the_monitor_and_is_never_reenabled(self):
        self.set_http(self.a, due=datetime.now(timezone.utc) - timedelta(seconds=1))
        with ExitStack() as stack:
            probe = self.http_patches(stack, grant=['HTTP監視の許可が有効期間外です'])
            self.quiet_dispatch(stack)
            out = stack.enter_context(mock.patch('sys.stdout', new_callable=io.StringIO))
            self.assertEqual(bm.http_tick(self.data), 0)
        probe.assert_not_called()
        self.assertIn('blocked', out.getvalue())
        settings = json.loads((self.a.root / 'http-monitor.json').read_text('utf-8'))
        self.assertEqual((settings['enabled'], settings['paused_reason']), (False, 'BLOCKED'))
        with ExitStack() as stack:  # the grant is fine again: the task still does not start what the monitor stopped
            probe = self.http_patches(stack)
            self.quiet_dispatch(stack)
            out = stack.enter_context(mock.patch('sys.stdout', new_callable=io.StringIO))
            bm.http_tick(self.data)
        probe.assert_not_called()
        self.assertEqual(out.getvalue(), '')
        self.assertFalse(json.loads((self.a.root / 'http-monitor.json').read_text('utf-8'))['enabled'])

    def test_no_catch_up_after_days_without_the_pc(self):
        self.set_http(self.a, due=datetime.now(timezone.utc) - timedelta(days=4), interval_seconds=300)
        with ExitStack() as stack:
            probe = self.http_patches(stack)
            self.quiet_dispatch(stack)
            bm.http_tick(self.data, 5, self.a.root.name)
            bm.http_tick(self.data, 5, self.a.root.name)  # straight away again
        self.assertEqual(probe.call_count, 1)  # one check, not a thousand
        self.assertEqual(len(self.history(self.a)), 1)
        self.assertGreater(HttpMonitor(self.a).load()['next_due_at'], format_utc(datetime.now(timezone.utc)))

    def test_one_slow_or_broken_site_never_holds_another_back(self):
        past = datetime.now(timezone.utc) - timedelta(minutes=2)
        self.set_http(self.a, due=past - timedelta(minutes=1))  # A is due first
        self.set_http(self.b, due=past)
        b_done = threading.Event()
        original = HttpMonitor.run_if_due

        def run(monitor, now, clock=None):
            if monitor.root == self.a.root:
                b_done.wait(10)  # A hangs until B has finished: sequential handling would run into the timeout
                raise RuntimeError('A is broken')
            result = original(monitor, now, clock)
            b_done.set()
            return result
        with ExitStack() as stack:
            self.http_patches(stack)
            self.quiet_dispatch(stack)
            stack.enter_context(mock.patch.object(HttpMonitor, 'run_if_due', run))
            out = stack.enter_context(mock.patch('sys.stdout', new_callable=io.StringIO))
            started = datetime.now(timezone.utc)
            self.assertEqual(bm.http_tick(self.data), 0)
        self.assertLess((datetime.now(timezone.utc) - started).total_seconds(), 8)
        self.assertEqual(len(self.history(self.b)), 1)
        self.assertIn(self.a.root.name + ' HTTP check error: RuntimeError', out.getvalue())

    def test_one_check_per_site_per_run_and_a_named_site_only(self):
        for site in (self.a, self.b):
            self.set_http(site, due=datetime.now(timezone.utc) - timedelta(minutes=1), interval_seconds=300)
        with ExitStack() as stack:
            probe = self.http_patches(stack)
            self.quiet_dispatch(stack)
            bm.http_tick(self.data, 5, self.b.root.name)
        self.assertEqual((probe.call_count, len(self.history(self.a)), len(self.history(self.b))), (1, 0, 1))
        with self.assertRaises(SystemExit):
            bm.http_tick(self.data, 5, 'site-00000000')

    def test_stopping_one_channel_leaves_the_other_running(self):
        self.set_image(self.a, due=NOW)
        self.set_http(self.a, due=datetime.now(timezone.utc) - timedelta(seconds=1))
        HttpMonitor(self.a).stop(NOW)  # HTTP stopped by the USER
        with ExitStack() as stack:
            probe = self.http_patches(stack)
            self.quiet_dispatch(stack)
            image = stack.enter_context(mock.patch('src.noxiworks.site_monitor.main', return_value=0))
            bm.http_tick(self.data, 5, self.a.root.name)
            bm.tick(self.data, now=NOW, docker=mock.MagicMock(), site_id=self.a.root.name)
        probe.assert_not_called()
        image.assert_called_once()  # image monitoring did not notice
        self.set_http(self.a, due=datetime.now(timezone.utc) - timedelta(seconds=1))
        self.set_image(self.a, enabled=False)  # now the other way round
        with ExitStack() as stack:
            probe = self.http_patches(stack)
            self.quiet_dispatch(stack)
            image = stack.enter_context(mock.patch('src.noxiworks.site_monitor.main', return_value=0))
            bm.tick(self.data, now=NOW, docker=mock.MagicMock(), site_id=self.a.root.name)
            bm.http_tick(self.data, 5, self.a.root.name)
        image.assert_not_called()
        probe.assert_called_once()


class Dispatch(Base):
    def test_the_dispatcher_runs_for_every_site_after_either_tick_and_its_failure_is_harmless(self):
        self.set_image(self.a)
        self.set_http(self.a, due=datetime.now(timezone.utc) - timedelta(seconds=1))
        with ExitStack() as stack:
            self.http_patches(stack)
            stack.enter_context(mock.patch('src.noxiworks.site_monitor.main', return_value=0))
            dispatcher = stack.enter_context(mock.patch('src.noxiworks.notify_dispatch.Dispatcher'))
            dispatcher.return_value.run.side_effect = RuntimeError('mail server on fire')
            out = stack.enter_context(mock.patch('sys.stdout', new_callable=io.StringIO))
            self.assertEqual(bm.tick(self.data, now=NOW, docker=mock.MagicMock()), 0)
            self.assertEqual(bm.http_tick(self.data), 0)
        self.assertEqual(dispatcher.return_value.run.call_count, 4)  # 2 sites x 2 ticks
        self.assertEqual(out.getvalue().count('メール通知のエラー：RuntimeError'), 4)
        self.assertEqual(len(self.history(self.a)), 1)  # the check itself was not lost

    def test_the_real_dispatcher_is_quiet_while_e_mail_is_off(self):
        self.set_http(self.a, enabled=False)
        with mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(bm.http_tick(self.data), 0)
        self.assertEqual(out.getvalue(), '')
        with ExitStack() as stack:
            dispatcher = stack.enter_context(mock.patch('src.noxiworks.notify_dispatch.Dispatcher'))
            dispatcher.return_value.run.return_value = 'busy'
            out = stack.enter_context(mock.patch('sys.stdout', new_callable=io.StringIO))
            bm.http_tick(self.data, site_id=self.a.root.name)
        self.assertIn('別の処理が動いています', out.getvalue())


if __name__ == '__main__':
    unittest.main()
