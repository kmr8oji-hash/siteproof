"""src/noxiworks/app.py: start, run an offline inspection over HTTP, refuse foreign requests, keep history across a restart."""
import http.client
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from src.noxiworks.app import serve


class LocalApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='siteproof-app-')
        cls.data = Path(cls.tmp.name) / 'data'

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    interval = None
    fixture_capture = False

    def start(self):
        server, app = serve(self.data, 0, self.interval, fixture_capture=self.fixture_capture)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(app.stop)
        return server.server_address[1], app

    def call(self, port, method, path, body=None, headers=None):
        c = http.client.HTTPConnection('127.0.0.1', port, timeout=120)
        c.request(method, path, body=None if body is None else json.dumps(body), headers={'Host': f'127.0.0.1:{port}', **(headers or {})})
        r = c.getresponse()
        return r.status, r.read()

    def test_inspection_is_saved_shown_and_survives_a_restart(self):
        port, app = self.start()
        status, html = self.call(port, 'GET', '/')
        self.assertEqual(status, 200)
        self.assertIn(b'/app/app.js', html)
        self.assertIn(b"connect-src 'self'", html)  # only the served copy; the generated file keeps connect-src 'none'
        self.assertIn(b"connect-src 'none'", (app.ui / 'index.html').read_bytes())
        token = json.loads(self.call(port, 'GET', '/app/api/session', headers={'X-SiteProof-App': '1'})[1])['token']
        ok = {'Origin': f'http://127.0.0.1:{port}', 'X-SiteProof-App': '1', 'Content-Type': 'application/json'}
        refused = [self.call(port, 'POST', '/app/api/run', {'fixture': 'changed'}, ok)[0],
                   self.call(port, 'POST', '/app/api/run', {'fixture': 'changed', 'token': token}, {**ok, 'Origin': 'http://evil.invalid'})[0],
                   self.call(port, 'POST', '/app/api/run', {'fixture': 'changed', 'token': token}, {**ok, 'X-SiteProof-App': ''})[0],
                   self.call(port, 'GET', '/app/api/session', headers={'X-SiteProof-App': '1', 'Sec-Fetch-Site': 'cross-site'})[0],
                   self.call(port, 'GET', '/', headers={'Host': 'evil.invalid'})[0],
                   self.call(port, 'GET', '/../registry/APPROVAL-RECORD.json')[0]]
        self.assertEqual(refused, [403, 403, 403, 403, 421, 404])
        self.assertEqual(self.call(port, 'POST', '/app/api/run', {'fixture': 'nope', 'token': token}, ok)[0], 422)
        status, raw = self.call(port, 'POST', '/app/api/run', {'fixture': 'changed', 'token': token}, ok)
        self.assertEqual(status, 200, raw)
        result = json.loads(raw)['result']
        self.assertEqual({k: p['verdict'] for k, p in result['profiles'].items()}, {'Desktop': 'VISUAL_CHANGED', 'Mobile': 'VISUAL_CHANGED'})
        status, raw = self.call(port, 'POST', '/app/api/run', {'fixture': 'unstable', 'token': token}, ok)
        self.assertEqual(status, 200, raw)
        self.assertEqual(json.loads(self.call(port, 'GET', '/view.json')[1])['source'], 'EMPTY')  # / never shows the synthetic demo
        view = json.loads(self.call(port, 'GET', '/demo/view.json')[1])
        self.assertEqual(view['source'], 'FIXTURE')
        self.assertEqual(sorted(h['class'] for h in view['monitoring']['history']), ['CHANGED', 'CHANGED', 'UNKNOWN', 'UNKNOWN'])
        self.assertIn('撮影が安定していません'.encode(), self.call(port, 'GET', '/demo/activity.html')[1])
        # restart: a new process state on the same folder shows the same history and the newest result
        port2, app2 = self.start()
        view2 = json.loads(self.call(port2, 'GET', '/demo/view.json')[1])
        self.assertEqual(view2['monitoring']['history'], view['monitoring']['history'])
        self.assertEqual(app2.state['last']['fixture'], 'unstable')
        self.assertNotEqual(app2.token, token)  # a new launch never accepts the old token
        self.assertEqual(self.call(port2, 'POST', '/app/api/run', {'fixture': 'changed', 'token': token},
                                   {**ok, 'Origin': f'http://127.0.0.1:{port2}'})[0], 403)


class SiteWorkflow(LocalApp):
    """Register one site -> the app inspects on its own: initial Baseline (automatic, marked unconfirmed) -> scheduled compared
    inspections -> change shown, Baseline untouched -> pause / resume -> restart keeps settings and history."""
    interval = 5
    fixture_capture = True  # engine test: synthetic captures on (a normal site never gets them)

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='siteproof-app-site-')
        cls.data = Path(cls.tmp.name) / 'data'

    test_inspection_is_saved_shown_and_survives_a_restart = None

    def wait(self, app, cond, seconds=90):
        end = time.time() + seconds
        while time.time() < end:
            s = app.site_status()
            if s and cond(s):
                return s
            time.sleep(0.5)
        self.fail('timed out: ' + json.dumps(app.site_status(), ensure_ascii=False)[:500])

    def test_register_then_everything_runs_by_itself(self):
        port, app = self.start()
        token = json.loads(self.call(port, 'GET', '/app/api/session', headers={'X-SiteProof-App': '1'})[1])['token']
        ok = {'Origin': f'http://127.0.0.1:{port}', 'X-SiteProof-App': '1', 'Content-Type': 'application/json'}

        def post(route, body):
            status, raw = self.call(port, 'POST', '/app/api/site/' + route, {'token': token, **body}, ok)
            return status, json.loads(raw)
        self.assertEqual(post('inspect', {})[0], 422)  # nothing registered yet
        self.assertEqual(self.call(port, 'POST', '/app/api/site/capture', {'token': token}, ok)[0], 403)  # no manual capture route
        for bad in ({'url': 'http://my-site.com/'}, {'url': 'https://192.168.0.1/'}, {'url': 'https://intranet.local/'},
                    {'url': 'https://u:p@my-site.com/'}, {'url': 'https://my-site.com:8443/'}, {'owner_confirmed': False}, {'kinds': []}):
            body = {'name': 'S', 'url': 'https://my-site.com/', 'kinds': ['Desktop', 'Mobile'], 'owner_confirmed': True, **bad}
            self.assertEqual(post('register', body)[0], 422, bad)
        site = {'name': 'マイサイト', 'url': 'https://my-site.com/', 'kinds': ['Desktop', 'Mobile'], 'owner_confirmed': True}
        self.assertEqual(post('register', site)[0], 200)
        self.assertEqual(post('register', site)[0], 422)  # one site in MVP v1.0
        s = self.wait(app, lambda s: s['baseline']['state'] == 'AUTO')  # no click: initial inspection + automatic Baseline
        self.assertEqual(s['monitor']['last']['outcome'], 'BASELINE_CREATED')
        source = s['baseline']['source_run']
        s = self.wait(app, lambda s: (s['monitor']['last'] or {}).get('outcome') == 'UNCHANGED')  # the next one, on schedule
        self.assertEqual(post('monitor', {'offline_fixture': 'changed'})[0], 200)
        s = self.wait(app, lambda s: (s['monitor']['last'] or {}).get('outcome') == 'CHANGED')
        self.assertEqual((s['baseline']['state'], s['baseline']['source_run']), ('AUTO', source))  # a change never replaces the Baseline
        self.assertEqual(post('monitor', {'enabled': False})[0], 200)
        time.sleep(1)
        runs = app.site_status()['runs']
        time.sleep(8)
        self.assertEqual(app.site_status()['runs'], runs)  # paused: nothing runs
        self.assertEqual(post('monitor', {'interval_seconds': 123})[0], 422)
        self.assertEqual(post('confirm', {})[0], 200)
        self.assertEqual(app.site_status()['baseline']['state'], 'CONFIRMED')
        self.assertEqual(post('confirm', {})[0], 422)
        view = json.loads(self.call(port, 'GET', '/view.json')[1])
        page = view['pages'][0]
        self.assertEqual(([p['target_id'] for p in view['pages']], view['source']), ([s['page_id']], 'FIXTURE'))
        self.assertEqual((page['change']['state'], page['change']['baseline_approved']), ('CHANGED', True))
        self.assertEqual(sorted(set(h['class'] for h in view['monitoring']['history'])), ['CHANGED', 'NOT_COMPARED', 'UNCHANGED'])
        self.assertNotIn(s['page_id'], [p['target_id'] for p in json.loads(self.call(port, 'GET', '/demo/view.json')[1])['pages']])
        self.assertFalse(app.site_status()['real_capture_available'])
        port2, app2 = self.start()  # restart: still paused, same history, same Baseline
        s2 = app2.site_status()
        self.assertEqual((s2['monitor']['enabled'], s2['baseline']['state'], s2['runs']), (False, 'CONFIRMED', runs))
        self.assertEqual(json.loads(self.call(port2, 'GET', '/view.json')[1])['monitoring']['history'], view['monitoring']['history'])


if __name__ == '__main__':
    unittest.main()
