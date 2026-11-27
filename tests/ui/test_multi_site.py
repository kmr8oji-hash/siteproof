"""Several registered sites in one data folder: separate settings / permits / grants / Baselines / history / notifications, explicit addressing of every
action, per-site stop, per-site failure, the overview, and the unchanged one-site data folder. Offline (fixture captures, injected HTTP probe)."""
import hashlib
import http.client
import io
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from src.noxiworks import filelock, notifications, site_monitor, sites
from src.noxiworks.app import App, serve, utc_now
from src.noxiworks.http_monitor import HttpMonitor
from src.noxiworks.site_monitor import Busy, Monitor
from src.noxiworks.site_workflow import Site
from tools import permit_draft, setup_monitoring

A, B = 'https://alpha-site.com/', 'https://beta-site.com/news'


def ok(host, path, timeout):
    return {'outcome': 'PASS', 'reason': 'HTTP_200', 'http_status': 200, 'elapsed_ms': 12, 'selected_ip': '93.184.216.34', 'tls_not_after': None}


def tree(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(root).rglob('*')) if p.is_file() and p.suffix != '.lock'}


class TwoSites(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='siteproof-multi-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.app = App(self.tmp / 'data')
        self.app.fixture_capture = True
        self.app.docker_found = False
        self.app.background_query = mock.MagicMock(return_value=False)
        self.app.launcher = mock.MagicMock()
        self.app.http_probe = ok
        self.app.setup()
        self.a = self.register('Alpha', A)
        self.b = self.register('Beta', B)

    def register(self, name, url, **kw):
        return self.app.site_action('register', {'name': name, 'url': url, 'kinds': ['Desktop'], 'owner_confirmed': True, **kw})['site_id']

    def act(self, action, site_id=None, **body):
        return self.app.site_action(action, {**({'site_id': site_id} if site_id else {}), **body})

    def root(self, site_id):
        return self.app.sites[site_id].site.root

    def test_each_site_has_its_own_folder_settings_and_pages(self):
        self.assertNotEqual(self.a, self.b)
        self.assertEqual({p.name for p in sites.folders(self.app.data)}, set(self.app.sites))
        self.act('monitor', self.a, interval_seconds=900)
        self.act('monitor', self.b, interval_seconds=86400)
        self.assertEqual([self.app.site_status(s)['monitor']['interval_seconds'] for s in (self.a, self.b)], [900, 86400])
        for s, url in ((self.a, A), (self.b, B)):
            view = json.loads((self.app.sites[s].ui / 'view.json').read_text('utf-8'))
            self.assertEqual([p['url'] for p in view['pages']], [url])  # a page shows its own site only

    def test_an_action_without_a_site_is_refused_while_there_are_several(self):
        before = tree(self.app.data / 'sites')
        for action, body in (('monitor', {'enabled': False}), ('confirm', {}), ('inspect', {}), ('http', {'what': 'stop'}), ('setup', {'step': 'docker'}),
                             ('baseline-update', {'run_id': 'x', 'expected_versions': {'Desktop': 1}, 'confirmed': True}),
                             ('baseline-approve', {'expected': {'Desktop': {}}, 'confirmed': True})):
            with self.subTest(action):
                with self.assertRaises(ValueError):
                    self.app.site_action(action, body)
                with self.assertRaises(ValueError):
                    self.app.site_action(action, {**body, 'site_id': 'site-00000000'})
                with self.assertRaises(ValueError):
                    self.app.site_action(action, {**body, 'site_id': ['site-00000000']})
        self.assertEqual(tree(self.app.data / 'sites'), before)
        self.app.launcher.assert_not_called()

    def test_stopping_one_site_leaves_the_other_running(self):
        self.act('monitor', self.a, enabled=False)
        self.assertEqual([self.app.site_status(s)['monitor']['enabled'] for s in (self.a, self.b)], [False, True])
        with mock.patch.object(HttpMonitor, 'grant_problems', return_value=[]):
            self.act('http', self.a, what='start')
            self.act('http', self.b, what='start')
            self.act('http', self.a, what='stop')
        self.assertEqual([self.app.sites[s].http_monitor().load()['enabled'] for s in (self.a, self.b)], [False, True])
        self.assertEqual([self.app.site_status(s)['monitor']['enabled'] for s in (self.a, self.b)], [False, True])  # HTTP and image are separate switches
        self.app.tick()
        self.assertEqual([len(self.app.sites[s].site.runs()) for s in (self.a, self.b)], [0, 1])  # only the running one was inspected
        for one in self.app.sites.values():
            with mock.patch.object(HttpMonitor, 'grant_problems', return_value=[]):
                one.http_tick()
        self.assertEqual([len(self.app.sites[s].http_monitor().history()) for s in (self.a, self.b)], [0, 1])

    def test_baseline_history_and_notifications_never_meet(self):
        self.app.tick()
        self.assertEqual([self.app.sites[s].site.baseline_state()['state'] for s in (self.a, self.b)], ['AUTO', 'AUTO'])
        untouched = tree(self.root(self.b))
        self.act('confirm', self.a)
        self.act('monitor', self.a, offline_fixture='changed')
        self.act('inspect', self.a)
        self.assertEqual(self.app.sites[self.a].site.baseline_state()['state'], 'CONFIRMED')
        self.assertEqual([n['kind'] for n in notifications.Outbox(self.root(self.a)).all()], ['IMAGE_CHANGED'])
        self.assertEqual(notifications.Outbox(self.root(self.b)).all(), [])
        self.assertEqual(tree(self.root(self.b)), untouched)  # nothing at all changed in the other site
        bodies = json.dumps(notifications.Outbox(self.root(self.a)).all(), ensure_ascii=False)
        self.assertNotIn('Beta', bodies)
        self.assertEqual([r.name.split('-')[-1] for r in self.app.sites[self.b].site.runs()], ['same'])

    def test_setup_tools_are_started_for_the_named_site_only(self):
        for step, want in (('background', ['install', '--channel', 'image']), ('background-http', ['install', '--channel', 'http']),
                           ('background-remove', ['remove', '--channel', 'image']), ('background-http-remove', ['remove', '--channel', 'http'])):
            self.act('setup', self.b, step=step)
            argv = [str(a) for a in self.app.launcher.call_args[0][0]]
            self.assertEqual([argv[argv.index('--site') + 1], argv[3], argv[argv.index('--channel') + 1]], [self.b, want[0], want[2]])
        with self.assertRaises(ValueError):  # no ownership evidence for this site: no signing window
            self.act('setup', self.a, step='http-grant')

    def test_the_tools_never_pick_a_site_by_themselves(self):
        with self.assertRaises(sites.SiteUnknown):
            sites.resolve(self.app.data)
        with self.assertRaises(permit_draft.DraftRefused):
            permit_draft.registered_site(self.app.data)
        self.assertEqual(permit_draft.registered_site(self.app.data, self.b)[1]['name'], 'Beta')
        with self.assertRaises(setup_monitoring.SetupFailed):
            setup_monitoring.ensure_site(self.app.data, 'https://third.com/', 'Third', 86400)  # --url never adds a site silently next to others
        self.assertEqual(len(sites.folders(self.app.data)), 2)

    def test_one_broken_site_never_stops_or_hides_the_others(self):
        (self.root(self.a) / 'monitor.json').write_text('{broken', encoding='utf-8')
        self.app.tick()
        self.assertIn('scheduler', self.app.sites[self.a].error)
        self.assertEqual(len(self.app.sites[self.b].site.runs()), 1)
        status = self.app.status()
        self.assertEqual([('error' in s and bool(s['error'])) for s in status['sites']], [True, False])
        json.dumps(status)

    def test_the_scheduler_pass_for_windows_runs_every_due_site_once(self):
        with mock.patch.object(site_monitor, 'Monitor', lambda site: Monitor(site, fixture_capture=True, docker_found=False)), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(site_monitor.main(['--data', str(self.app.data), '--site', self.b]), 0)
            self.assertEqual([len(self.app.sites[s].site.runs()) for s in (self.a, self.b)], [0, 1])
            self.assertEqual(site_monitor.main(['--data', str(self.app.data)]), 0)
        self.assertEqual([len(self.app.sites[s].site.runs()) for s in (self.a, self.b)], [1, 1])  # b was not due again
        self.assertIn(self.b + ' not due', out.getvalue())

    def test_one_real_capture_at_a_time_over_all_sites(self):
        monitor = Monitor(self.app.sites[self.a].site, fixture_capture=False, docker_found=False)
        due = monitor.load()['next_due_at']
        with mock.patch('src.noxiworks.real_capture.RealCapture.ready', return_value=True), mock.patch('src.noxiworks.real_capture.RealCapture.capture') as capture:
            with filelock.held(self.app.data / 'capture.lock'):
                with self.assertRaises(Busy):
                    monitor.run(utc_now(), 'SCHEDULE')
        capture.assert_not_called()
        self.assertFalse(monitor.running())
        self.assertEqual((monitor.load()['next_due_at'], monitor.log()), (due, []))  # still due, nothing recorded, no permit run used

    def test_a_stop_made_while_a_worker_saves_its_result_is_kept(self):
        monitor = self.app.sites[self.a].monitor()
        with monitor.settings_lock():
            t = threading.Thread(target=lambda: self.act('monitor', self.a, enabled=False))
            t.start()
            s = monitor.load()  # the worker's own load-modify-save
            s['last'] = {'outcome': 'UNCHANGED'}
            t.join(0.3)
            self.assertTrue(t.is_alive())  # the stop waits for its turn instead of being overwritten
            monitor.save(s)
        t.join(10)
        self.assertEqual((monitor.load()['enabled'], monitor.load()['last']['outcome']), (False, 'UNCHANGED'))

    def test_the_overview_lists_every_site_with_both_channels(self):
        self.app.tick()
        listed = {s['site_id']: s for s in self.app.status()['sites']}
        self.assertEqual({s['name'] for s in listed.values()}, {'Alpha', 'Beta'})
        self.assertIsNone(self.app.status()['site'])  # several: the page is about none of them until one is named
        self.assertEqual(self.app.status(self.b)['site']['site_id'], self.b)
        for s in listed.values():
            self.assertEqual((s['href'], s['http']['state'], s['image']['enabled']), (f"/site/{s['site_id']}/", 'NOT_MONITORED', True))

    def test_limits_and_duplicates(self):
        with self.assertRaises(ValueError):
            self.register('Again', A)
        with mock.patch('src.noxiworks.app.MAX_SITES', 2), self.assertRaises(ValueError):
            self.register('Third', 'https://third.com/')
        with self.assertRaises(ValueError):
            self.register('Bad interval', 'https://third.com/', interval_seconds=5)
        self.assertEqual(len(sites.folders(self.app.data)), 2)

    def test_a_restart_finds_the_same_sites_and_a_renamed_copy_is_not_one(self):
        self.act('monitor', self.a, enabled=False)
        shutil.copytree(self.root(self.a), self.app.data / 'sites' / 'site-12345678')
        again = App(self.app.data)
        again.docker_found = False
        again.background_query = mock.MagicMock(return_value=False)
        again.setup()
        self.assertEqual(set(again.sites), {self.a, self.b})
        self.assertEqual([again.site_status(s)['monitor']['enabled'] for s in (self.a, self.b)], [False, True])
        self.assertEqual([p['folder'] for p in again.status()['site_problems']], ['site-12345678'])


class OneSiteData(unittest.TestCase):
    """A data folder made by the one-site app: read as it is, served at /, actions without a site id still mean that site."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='siteproof-one-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = self.tmp / 'data'
        (self.data / 'sites').mkdir(parents=True)
        self.site = Site.register(self.data / 'sites', 'Only', A, ['Desktop'], True, utc_now())  # as the earlier app left it (no monitor.json yet either)

    def start(self):
        server, app = serve(self.data, 0, scheduler=False, fixture_capture=True)
        app.background_query, app.docker_found, app.launcher = mock.MagicMock(return_value=False), False, mock.MagicMock()
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1], app

    def call(self, port, method, path, body=None):
        c = http.client.HTTPConnection('127.0.0.1', port, timeout=60)
        c.request(method, path, None if body is None else json.dumps(body),
                  {'Host': f'127.0.0.1:{port}', 'X-SiteProof-App': '1', 'Origin': f'http://127.0.0.1:{port}', 'Content-Type': 'application/json'})
        r = c.getresponse()
        return r.status, r.read(), dict(r.getheaders())

    def test_the_signed_and_saved_files_are_not_rewritten_and_the_site_is_served_as_before(self):
        before = {n: v for n, v in tree(self.site.root).items()}
        port, app = self.start()
        after = tree(self.site.root)
        self.assertEqual({n for n in before if after.get(n) != before[n]} - {'targets.json'}, set())  # targets.json: the interval, exactly as the earlier app wrote it
        state = json.loads(self.call(port, 'GET', '/app/api/session')[1])
        self.assertEqual((state['site']['name'], len(state['sites'])), ('Only', 1))
        self.assertIn(b'alpha-site.com', self.call(port, 'GET', '/view.json')[1])
        self.assertEqual(self.call(port, 'POST', '/app/api/site/monitor', {'token': app.token, 'enabled': False})[0], 200)  # no site id needed
        self.assertFalse(app.site_status()['monitor']['enabled'])

    def test_a_site_whose_pages_cannot_be_made_still_opens_and_says_why(self):
        # e.g. an earlier run that can no longer be checked against its Baseline: the app must open (no crash at start) and show the reason
        real = App.generate
        with mock.patch.object(App, 'generate', side_effect=lambda ui_dir, runs, *a, **kw: (_ for _ in ()).throw(RuntimeError('page generation failed: refused'))
                               if Path(ui_dir).parent.name.startswith('site-') else real(ui_dir, runs, *a, **kw)):
            port, app = self.start()
        state = json.loads(self.call(port, 'GET', '/app/api/session')[1])
        self.assertEqual(state['site']['name'], 'Only')
        self.assertIn('page generation failed', state['site']['error'])
        self.assertEqual(self.call(port, 'GET', '/')[0], 200)  # the empty dashboard, with the app's panels

    def test_after_a_second_site_the_addresses_are_explicit(self):
        port, app = self.start()
        status, raw, _ = self.call(port, 'POST', '/app/api/site/register', {'token': app.token, 'name': 'New', 'url': B, 'kinds': ['Desktop'], 'owner_confirmed': True})
        self.assertEqual(status, 200, raw)
        new = json.loads(raw)['result']['site_id']
        old = self.site.info['site_id']
        for site_id, mine, other in ((old, b'alpha-site.com', b'beta-site.com'), (new, b'beta-site.com', b'alpha-site.com')):
            status, raw, _ = self.call(port, 'GET', f'/site/{site_id}/view.json')
            self.assertEqual((status, mine in raw, other in raw), (200, True, False))
            self.assertEqual(json.loads(self.call(port, 'GET', '/app/api/session?site=' + site_id)[1])['site']['site_id'], site_id)
            status, _, headers = self.call(port, 'GET', '/site/' + site_id)
            self.assertEqual((status, headers['Location']), (302, f'/site/{site_id}/'))
        root = self.call(port, 'GET', '/view.json')[1]
        self.assertFalse(b'alpha-site.com' in root or b'beta-site.com' in root)  # / is the list; no site's data on it
        state = json.loads(self.call(port, 'GET', '/app/api/session')[1])
        self.assertEqual((state['site'], len(state['sites'])), (None, 2))
        self.assertEqual(self.call(port, 'POST', '/app/api/site/monitor', {'token': app.token, 'enabled': False})[0], 422)  # a tab opened before the second site
        self.assertTrue(all(s['image']['enabled'] for s in state['sites']))
        self.assertEqual(self.call(port, 'POST', '/app/api/site/monitor', {'token': app.token, 'enabled': False, 'site_id': new})[0], 200)
        self.assertEqual([app.site_status(s)['monitor']['enabled'] for s in (old, new)], [True, False])
        for bad in ('/site/site-00000000/', f'/site/{old}/../{new}/site.json', f'/site/{old}/..%2f..%2fsite.json', '/site/', f'/site/{old}/..\\..\\site.json'):
            self.assertEqual(self.call(port, 'GET', bad)[0], 404, bad)


if __name__ == '__main__':
    unittest.main()
