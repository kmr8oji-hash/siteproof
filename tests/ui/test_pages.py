"""Several pages of one site, offline: a further page is a complete unit folder of its own (<site>/pages/<site id>-p2..p5) and shares nothing with the first page or
any other page -- settings, Baseline, history, notices, permits and grants stay apart -- except the site's ownership evidence and e-mail switch. Addressing
(site_id + unit), per-page and whole-site stop, the schedulers, the aggregate, the unchanged one-page / multi-site data folders, backup, restart, URLs.
No network, no Docker, no real key (the signed-grant test uses a synthetic key). Page generation is replaced by a stub except where the served pages are checked."""
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from src.aws_b.model import format_utc
from src.noxiworks import domain_ownership, http_authority, notifications, retention, sites
from src.noxiworks import permit as permits
from src.noxiworks.app import App, serve, utc_now
from src.noxiworks.http_monitor import HttpMonitor
from src.noxiworks.site_app import SiteApp, rollup
from src.noxiworks.site_monitor import Monitor
from src.noxiworks.site_workflow import Site, SiteRefused
from tests.ui.test_real_capture import keypair, needs_ssh
from tools import http_grant

A, B = 'https://alpha-site.com/', 'https://beta-site.com/news'
NOW = datetime(2026, 11, 25, 12, 0, 0, tzinfo=timezone.utc)


def ok(host, path, timeout):
    return {'outcome': 'PASS', 'reason': 'HTTP_200', 'http_status': 200, 'elapsed_ms': 12, 'selected_ip': '93.184.216.34', 'tls_not_after': None}


def down(host, path, timeout):
    return {'outcome': 'FAIL', 'reason': 'HTTP_503', 'http_status': 503, 'elapsed_ms': 9, 'selected_ip': '93.184.216.34', 'tls_not_after': None}


def tree(root, skip=('pages',)):
    root = Path(root)
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*'))
            if p.is_file() and p.suffix != '.lock' and p.relative_to(root).parts[0] not in skip}


def fast_generate(ui_dir, runs, registry, env=None, schedule=None, archive=None, older=()):
    """Stands in for the page generator (a subprocess of ~1.5 s): a numbered folder with an index page."""
    ui_dir = Path(ui_dir)
    ui_dir.mkdir(parents=True, exist_ok=True)
    out = ui_dir / str(max([int(p.name) for p in ui_dir.iterdir() if p.name.isdigit()], default=0) + 1)
    out.mkdir()
    (out / 'index.html').write_text('<html><head></head><body></body></html>', encoding='utf-8')
    return out


def make_app(data, stub=True):
    data = Path(data)
    (data / 'registry').mkdir(parents=True, exist_ok=True)
    if stub:  # the synthetic demo Baseline is not under test here
        (data / 'registry' / 'APPROVAL-RECORD.json').write_text('{}', encoding='utf-8')
    app = App(data)
    app.fixture_capture, app.docker_found = True, False
    app.background_query, app.launcher, app.http_probe = mock.MagicMock(return_value=False), mock.MagicMock(), ok
    return app


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='siteproof-pages-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patch = mock.patch.object(App, 'generate', staticmethod(fast_generate))
        patch.start()
        self.addCleanup(patch.stop)
        self.app = make_app(self.tmp / 'data')
        self.app.setup()
        self.a = self.register('Alpha', A)
        self.b = self.register('Beta', B)

    def register(self, name, url):
        return self.app.site_action('register', {'name': name, 'url': url, 'kinds': ['Desktop'], 'owner_confirmed': True})['site_id']

    def add(self, site, path, label=None, kinds=('Desktop',)):
        return self.app.site_action('add-page', {'site_id': site, 'path': path, 'label': label or path, 'kinds': list(kinds)})['unit']

    def act(self, action, site=None, unit=None, **body):
        return self.app.site_action(action, {**({'site_id': site} if site else {}), **({'unit': unit} if unit else {}), **body})

    def root(self, site, unit=None):
        one = self.app.sites[site]
        return (one.pages[unit] if unit and unit != site else one).site.root

    def refused(self, *args, **kw):
        before = tree(self.app.data / 'sites', skip=())
        with self.assertRaises(ValueError) as caught:
            self.act(*args, **kw)
        self.assertEqual(tree(self.app.data / 'sites', skip=()), before)  # a refusal changes nothing
        return str(caught.exception)

    def fresh(self):
        for u in self.app.units():
            u._overview = None


class Registration(Base):
    def test_a_further_page_is_a_complete_unit_folder_that_shares_nothing(self):
        first = tree(self.root(self.a))
        p2 = self.add(self.a, '/about', '会社概要')
        root = self.root(self.a, p2)
        self.assertEqual(root, self.app.data.resolve() / 'sites' / self.a / 'pages' / p2)
        self.assertEqual(p2, self.a + '-p2')
        for name in ('site.json', 'targets.json', 'capture_plan.json', 'monitor.json'):
            self.assertTrue((root / name).is_file(), name)
        for name in ('workspace', 'runs', 'ui'):
            self.assertTrue((root / name).is_dir(), name)
        for name in ('http-monitor.json', 'http-grant.json', 'real', 'registry', 'email-notify.json'):  # nothing is made, copied or inherited
            self.assertFalse((root / name).exists(), name)
        info = json.loads((root / 'site.json').read_text('utf-8'))
        self.assertEqual((info['site_id'], info['page_id'], info['origin'], info['url'], info['label']), (self.a, p2, 'https://alpha-site.com', 'https://alpha-site.com/about', '会社概要'))
        self.assertEqual(json.loads((root / 'targets.json').read_text('utf-8'))['pages'][0]['target_id'], p2)
        self.assertEqual(json.loads((root / 'capture_plan.json').read_text('utf-8'))['sites'][0]['pages'][0]['page_id'], p2)
        monitor = json.loads((root / 'monitor.json').read_text('utf-8'))
        self.assertEqual((monitor['enabled'], monitor['next_due_at']), (False, None))  # image monitoring starts OFF
        self.assertEqual(sites.pages(self.root(self.a))[0], [root])
        self.assertEqual(sites.units(self.root(self.a)), [self.root(self.a), root])
        self.assertEqual(tree(self.root(self.a)), first)  # the first page is as it was
        self.assertEqual(self.app.sites[self.a].status()['http']['configured'], False)
        self.assertEqual(self.app.site_status(self.a, p2)['http']['configured'], False)

    def test_ids_are_never_reused_and_the_site_holds_at_most_five_pages(self):
        stray = self.root(self.a) / 'pages' / (self.a + '-p2')  # a folder that is no usable page still occupies its id
        stray.mkdir(parents=True)
        ids = [self.add(self.a, '/p' + str(n)) for n in range(3)]
        self.assertEqual(ids, [self.a + '-p3', self.a + '-p4', self.a + '-p5'])
        self.assertIn('使い切りました', self.refused('add-page', self.a, path='/more', label='x', kinds=['Desktop']))  # first page + 3 = 4 usable, but every id p2..p5 is taken
        self.assertEqual(len(sites.units(self.root(self.a))), 4)

    def test_the_limit_counts_the_first_page(self):
        for n in range(4):
            self.add(self.a, '/p' + str(n))
        self.assertEqual(len(sites.units(self.root(self.a))), sites.MAX_PAGES)
        message = self.refused('add-page', self.a, path='/p9', label='x', kinds=['Desktop'])
        self.assertIn('5つまで', message)
        self.add(self.b, '/ok')  # the other site has its own count

    def test_what_cannot_be_added(self):
        self.add(self.a, '/about')
        for label, body, text in (
                ('other origin', {'path': 'https://beta-site.com/x'}, '同じホスト'), ('subdomain', {'path': 'https://www.alpha-site.com/x'}, '同じホスト'),
                ('http', {'path': 'http://alpha-site.com/x'}, 'https://'), ('query', {'path': '/x?y=1'}, 'URL'), ('fragment', {'path': '/x#y'}, 'URL'),
                ('first page again', {'path': '/'}, 'すでに'), ('same page again', {'path': '/about'}, 'すでに'), ('same page as URL', {'path': 'https://alpha-site.com/about'}, 'すでに'),
                ('dot segments', {'path': '/a/../b'}, '追加できません'), ('scheme-relative', {'path': '//evil.com/x'}, 'URL'), ('bad characters', {'path': '/a b'}, '使えない文字'),
                ('too long', {'path': '/' + 'a' * 300}, '使えない文字'), ('no path', {'path': ''}, 'URL'), ('no path at all', {'path': None}, 'URL'),
                ('label too long', {'path': '/l', 'label': 'x' * 61}, 'ページ名'), ('no size', {'path': '/s', 'kinds': []}, 'Desktop'), ('bad size', {'path': '/s', 'kinds': ['Tablet']}, 'Desktop'),
                ('sizes not a list', {'path': '/s', 'kinds': 'Desktop'}, 'Desktop')):
            with self.subTest(label):
                body = {'label': 'x', 'kinds': ['Desktop'], **body}
                self.assertIn(text, self.refused('add-page', self.a, **body))
        self.assertEqual(len(sites.units(self.root(self.a))), 2)

    def test_a_page_can_only_be_added_to_a_site_and_from_its_first_page(self):
        p2 = self.add(self.a, '/about')
        with self.assertRaises(SiteRefused):
            Site.register_page(self.app.sites[self.a].pages[p2].site, '/x', 'x', ['Desktop'], NOW)
        self.assertIn('サイト', self.refused('add-page', 'site-00000000', path='/x', label='x', kinds=['Desktop']))
        self.assertIn('サイト', self.refused('add-page', path='/x', label='x', kinds=['Desktop']))  # two sites: never a guess

    def test_the_same_page_number_on_two_sites_is_two_pages(self):
        pa, pb = self.add(self.a, '/about'), self.add(self.b, '/about')
        self.assertEqual((pa[-3:], pb[-3:]), ('-p2', '-p2'))
        self.assertNotEqual(pa, pb)
        self.act('monitor', self.a, pa, interval_seconds=900)
        self.act('monitor', self.b, pb, interval_seconds=86400)
        self.assertEqual([self.app.site_status(s, p)['monitor']['interval_seconds'] for s, p in ((self.a, pa), (self.b, pb))], [900, 86400])
        self.assertFalse(set(self.app.sites[self.a].pages) & set(self.app.sites[self.b].pages))
        # a page id of another site is not an address at all
        self.assertIn('ページ', self.refused('monitor', self.a, pb, enabled=False))
        self.assertIn('ページ', self.refused('monitor', self.b, pa, enabled=False))

    def test_the_pages_of_a_site_are_in_its_status_and_overview(self):
        p2 = self.add(self.a, '/about', 'About')
        status = self.app.site_status(self.a, p2)
        self.assertEqual((status['unit'], status['unit_label'], status['site_id'], status['page_id']), (p2, 'About', self.a, p2))
        self.assertEqual(status['pages'], [{'unit': self.a, 'label': 'トップページ', 'url': A, 'href': f'/site/{self.a}/', 'current': False},
                                           {'unit': p2, 'label': 'About', 'url': 'https://alpha-site.com/about', 'href': f'/site/{self.a}/page/{p2}/', 'current': True}])
        first = self.app.site_status(self.a)
        self.assertEqual((first['unit'], [p['current'] for p in first['pages']]), (self.a, [True, False]))
        listed = {s['site_id']: s for s in self.app.status()['sites']}
        self.assertEqual([p['unit'] for p in listed[self.a]['pages']], [self.a, p2])
        self.assertEqual([p['unit'] for p in listed[self.b]['pages']], [self.b])  # a one-page site lists its first page
        self.assertEqual(listed[self.a]['aggregate']['units'], 2)
        self.assertEqual(self.app.status(self.a, p2)['site']['unit'], p2)
        self.assertEqual(self.app.status(self.a, 'site-00000000-p2')['site']['unit'], self.a)  # an unknown page falls back to the first (a screen, not an action)
        json.dumps(self.app.status())


class Addressing(Base):
    def setUp(self):
        super().setUp()
        self.p2 = self.add(self.a, '/about')

    def test_an_action_on_a_site_with_several_pages_must_name_its_page(self):
        for action, body in (('monitor', {'enabled': False}), ('confirm', {}), ('inspect', {}), ('http', {'what': 'stop'}), ('setup', {'step': 'docker'}),
                             ('notify', {'what': 'site', 'enabled': False}), ('maintenance', {'what': 'archive-http', 'confirmed': True}),
                             ('baseline-update', {'run_id': 'x', 'expected_versions': {'Desktop': 1}, 'confirmed': True}), ('baseline-approve', {'expected': {'Desktop': {}}, 'confirmed': True})):
            with self.subTest(action):
                self.assertIn('ページ', self.refused(action, self.a, **body))  # a tab opened before the page was added
                for bad in ('site-00000000-p2', self.b, self.a + '-p3', ['x'], ''):
                    before = tree(self.app.data / 'sites', skip=())
                    with self.assertRaises(ValueError) as caught:
                        self.app.site_action(action, {**body, 'site_id': self.a, 'unit': bad})
                    self.assertIn('ページ', str(caught.exception))
                    self.assertEqual(tree(self.app.data / 'sites', skip=()), before)
        self.app.launcher.assert_not_called()

    def test_with_one_page_the_unit_may_be_left_out_and_with_several_it_is_the_folder_name(self):
        self.assertEqual(self.act('monitor', self.b, enabled=False)['enabled'], False)  # beta has one page
        self.assertEqual(self.act('monitor', self.b, self.b, enabled=True)['enabled'], True)
        self.assertEqual(self.act('monitor', self.a, self.a, interval_seconds=900)['interval_seconds'], 900)  # the first page: the site id
        self.assertEqual(self.act('monitor', self.a, self.p2, interval_seconds=21600)['interval_seconds'], 21600)
        self.assertEqual([self.app.site_status(self.a, u)['monitor']['interval_seconds'] for u in (self.a, self.p2)], [900, 21600])

    def test_several_sites_and_no_site_id_is_still_refused(self):
        with self.assertRaises(ValueError):
            self.app.site_action('monitor', {'unit': self.p2, 'enabled': False})

    def test_a_page_cannot_be_given_the_image_permit_or_the_site_wide_steps_of_the_first_page(self):
        with self.assertRaises(ValueError):
            self.act('setup', self.a, self.p2, step='setup', ownership='dns')
        self.app.launcher.assert_not_called()
        self.act('setup', self.a, self.p2, step='background-http')  # a Windows task is per site and channel: done for the site
        argv = [str(x) for x in self.app.launcher.call_args[0][0]]
        self.assertEqual((argv[argv.index('--site') + 1], '--page' in argv), (self.a, False))


class Separation(Base):
    def setUp(self):
        super().setUp()
        self.p2 = self.add(self.a, '/about', 'About')
        self.p3 = self.add(self.a, '/contact', 'Contact')

    def test_settings_baseline_history_and_notices_of_two_pages_never_meet(self):
        first, second, third = self.root(self.a), self.root(self.a, self.p2), self.root(self.a, self.p3)
        before = {'first': tree(first), 'third': tree(third), 'b': tree(self.root(self.b))}
        self.act('inspect', self.a, self.p2)  # an AUTO Baseline of this page only
        self.act('confirm', self.a, self.p2)
        self.act('monitor', self.a, self.p2, offline_fixture='changed')
        self.act('inspect', self.a, self.p2)
        self.assertEqual(self.app.sites[self.a].pages[self.p2].site.baseline_state()['state'], 'CONFIRMED')
        self.assertEqual([n['kind'] for n in notifications.Outbox(second).all()], ['IMAGE_CHANGED'])
        self.assertEqual(len(self.app.sites[self.a].pages[self.p2].site.runs()), 2)
        self.assertEqual(notifications.Outbox(first).all(), [])
        self.assertEqual(notifications.Outbox(third).all(), [])
        self.assertEqual((tree(first), tree(third), tree(self.root(self.b))), (before['first'], before['third'], before['b']))  # nothing at all changed elsewhere
        self.assertEqual(self.app.sites[self.a].site.runs(), [])
        self.assertEqual(self.app.sites[self.a].site.baseline_state()['state'], 'NONE')
        self.assertTrue(all((first / n).exists() is False for n in ('registry', 'baseline-confirmation.json')))
        bodies = json.dumps(notifications.Outbox(second).all(), ensure_ascii=False)
        self.assertNotIn('Beta', bodies)

    def test_http_settings_and_history_are_per_page(self):
        with mock.patch.object(HttpMonitor, 'grant_problems', return_value=[]):
            self.act('http', self.a, self.p2, what='start')
            self.act('http', self.a, self.p2, what='interval', interval_seconds=300)
            self.act('http', self.a, self.p2, what='check')
        self.assertEqual([self.app.sites[self.a].http_monitor().configured(), self.app.sites[self.a].pages[self.p2].http_monitor().configured(),
                          self.app.sites[self.a].pages[self.p3].http_monitor().configured()], [False, True, False])
        page = self.app.sites[self.a].pages[self.p2].http_monitor()
        self.assertEqual((page.load()['interval_seconds'], len(page.history())), (300, 1))
        self.assertEqual(page.target(), ('alpha-site.com', '/about'))
        self.assertEqual(self.app.sites[self.a].http_monitor().target(), ('alpha-site.com', '/'))

    def test_a_page_has_no_image_capture_and_says_so(self):
        self.app.fixture_capture = False
        harness = {c['key']: c for c in self.app.site_status(self.a, self.p2)['readiness']}['harness']
        self.assertFalse(harness['ok'])
        self.assertIn('トップページ（/）以外', harness['state'])
        self.assertIn('追加したページ', harness['guide'])
        self.assertIn('開始できません', self.refused('monitor', self.a, self.p2, enabled=True))  # no start, no substitute image
        self.assertFalse(json.loads((self.root(self.a, self.p2) / 'monitor.json').read_text('utf-8'))['enabled'])
        self.assertEqual(self.app.sites[self.a].pages[self.p2].site.runs(), [])

    def test_disk_usage_of_a_site_does_not_count_its_pages_twice(self):
        first = Monitor(self.app.sites[self.a].site)
        before = first.disk()['used']
        junk = self.root(self.a, self.p2) / 'workspace' / 'junk.bin'
        junk.write_bytes(b'x' * 50_000)
        self.assertEqual(first.disk()['used'], before)
        self.assertGreaterEqual(Monitor(self.app.sites[self.a].pages[self.p2].site).disk()['used'], 50_000)
        usage = {x['key']: x['bytes'] for x in retention.disk_usage(self.root(self.a))['areas']}
        self.assertGreaterEqual(usage['pages'], 50_000)
        self.assertEqual({x['key']: x['bytes'] for x in retention.disk_usage(self.root(self.a, self.p2))['areas']}['pages'], 0)
        self.assertGreaterEqual({x['site_id']: x['bytes'] for x in retention.data_usage(self.app.data)['sites']}[self.a], 50_000)  # the site's folder total still holds its pages

    def test_the_ownership_evidence_is_the_sites_and_shared(self):
        root = self.root(self.a)
        c = domain_ownership.issue(root, utc_now())
        domain_ownership.check(root, utc_now(), [('system', lambda record: [c['record_value']])])
        states = [self.app.site_status(self.a, u)['ownership'] for u in (self.a, self.p2, self.p3)]
        self.assertEqual([s['status'] for s in states], ['VERIFIED'] * 3)
        self.assertEqual(states[0]['host'], 'alpha-site.com')
        self.assertEqual(self.app.site_status(self.b)['ownership']['status'], 'NONE')
        self.assertTrue(all(self.app.site_status(self.a, u)['ownership_evidence'] for u in (self.a, self.p2)))
        self.assertFalse((self.root(self.a, self.p2) / 'real').exists())
        self.act('setup', self.a, self.p2, step='http-grant')  # the evidence is found through the site; the window is for THIS page
        argv = [str(x) for x in self.app.launcher.call_args[0][0]]
        self.assertEqual((argv[argv.index('--page') + 1], argv[argv.index('--site') + 1], 'tools/http_grant.py' in argv), (self.p2, self.a, True))
        self.act('setup', self.a, self.a, step='http-grant')
        self.assertNotIn('--page', [str(x) for x in self.app.launcher.call_args[0][0]])
        issued = self.act('setup', self.a, self.p2, step='dns-issue')  # a site-level step, from any of its pages
        self.assertEqual(issued['record_name'], '_siteproof-challenge.alpha-site.com')


class Authority(Base):
    """What one page's permit or grant says never covers another page."""

    def setUp(self):
        super().setUp()
        self.p2, self.p3 = self.add(self.a, '/about'), self.add(self.a, '/contact')
        root = self.root(self.a)
        c = domain_ownership.issue(root, NOW)
        domain_ownership.check(root, NOW, [('system', lambda record: [c['record_value']])])
        self.later = NOW + timedelta(hours=1)

    def grant_of(self, unit):
        site = self.app.sites[self.a]
        one = site if unit == self.a else site.pages[unit]
        return http_grant.draft(one.site.root, one.site.info, self.later, seconds=86400, min_interval=300, max_requests=10, purpose='MONITOR'), one

    def test_the_grant_of_one_page_names_that_page_and_is_refused_for_every_other(self):
        grants = {u: self.grant_of(u) for u in (self.a, self.p2, self.p3)}
        for u, (grant, one) in grants.items():
            self.assertEqual(http_authority.grant_problems(grant, one.site.info, one.site.root, self.later), [])  # fine for its own page
            self.assertEqual(grant['grant_id'][:len('http-' + u)], 'http-' + u)
            self.assertEqual(grant['ownership'], grants[self.a][0]['ownership'])  # the same site evidence, never a copy of anything else
        for u, (grant, _) in grants.items():
            for v, (_, other) in grants.items():
                if u != v:
                    with self.subTest(f'{u} for {v}'):
                        problems = http_authority.grant_problems(grant, other.site.info, other.site.root, self.later)
                        self.assertTrue(any('許可された対象' in m for _, m in problems), problems)
        self.assertEqual(len({http_authority.ledger_file(one.site.root) for _, one in grants.values()}), 3)  # a ledger per page

    def test_an_image_permit_of_one_page_is_refused_for_another(self):
        site_a, site_p2 = self.app.sites[self.a].site, self.app.sites[self.a].pages[self.p2].site
        permit = {'schema': permits.SCHEMA, 'permit_id': 'p-1', 'site': {'site_id': self.a, 'origin': site_p2.info['origin'], 'host': 'alpha-site.com'},
                  'target': {'target_id': site_p2.page_id, 'url': site_p2.info['url']}, 'target_files': {}, 'valid_from': format_utc(NOW - timedelta(hours=1)),
                  'valid_until': format_utc(NOW + timedelta(days=1)), 'max_runs': 3, 'identity': {}, 'baseline_policy': 'NONE'}
        problems = permits.check_scope(permit, site_info=site_a.info, page_id=site_a.page_id, target_dir=site_a.root, now=NOW, used_runs=0)
        self.assertIn('許可されたページが登録内容と一致しません', problems)
        self.assertTrue(any('対象設定' in p for p in problems))  # the pinned target files are the page's own
        self.assertIn('撮影ハーネスが扱えるのはトップページ（/）だけです', permits.check_scope(permit, site_info=site_p2.info, page_id=site_p2.page_id, target_dir=site_p2.root,
                                                                                     now=NOW, used_runs=0))

    @needs_ssh
    def test_a_signed_grant_copied_to_another_page_authorises_nothing(self):
        keys = self.tmp / 'keys'
        keys.mkdir()
        key = keypair(keys, 'user')
        pub = (keys / 'user.pub').read_text('utf-8').split()
        (self.app.data / 'trust').mkdir(exist_ok=True)
        (self.app.data / 'trust' / 'allowed_signers').write_text(f'site-owner namespaces="{permits.NAMESPACE}" {pub[0]} {pub[1]}\n', encoding='ascii')
        grant, one = self.grant_of(self.p2)
        grant.update(valid_from=format_utc(NOW), valid_until=format_utc(NOW + timedelta(days=1)))  # the evidence was written at NOW: the grant is used at the fixed moment `later`
        target = one.site.root
        (target / 'http-grant.json').write_text(json.dumps(grant), encoding='utf-8')
        subprocess.run([permits.ssh_keygen(), '-Y', 'sign', '-n', permits.NAMESPACE, '-f', str(key), str(target / 'http-grant.json')], check=True, capture_output=True)
        self.assertEqual(http_authority.authorize(target, self.later, 'MANUAL')['path'], '/about')
        for other in (self.root(self.a), self.root(self.a, self.p3)):
            for name in ('http-grant.json', 'http-grant.json.sig'):
                shutil.copyfile(target / name, other / name)
            with self.assertRaises(http_authority.Refused) as caught:
                http_authority.authorize(other, self.later + timedelta(minutes=10), 'MANUAL')
            self.assertEqual(caught.exception.code, 'GRANT_INVALID')
            self.assertIn('許可された対象', caught.exception.message)
        self.assertEqual(len(http_authority.entries(target)), 1)
        self.assertEqual(http_authority.entries(self.root(self.a)), [])


class StopAndSchedule(Base):
    def setUp(self):
        super().setUp()
        self.p2 = self.add(self.a, '/about', 'About')
        self.grant = mock.patch.object(HttpMonitor, 'grant_problems', return_value=[])
        self.grant.start()
        self.addCleanup(self.grant.stop)

    def states(self, site, unit):
        s = self.app.site_status(site, unit)
        return s['monitor']['enabled'], s['http']['enabled']

    def run_all(self):
        self.act('monitor', self.a, self.p2, enabled=True)
        for site, unit in ((self.a, self.a), (self.a, self.p2), (self.b, self.b)):
            self.act('http', site, unit, what='start')

    def test_one_page_can_be_stopped_alone(self):
        self.run_all()
        self.act('monitor', self.a, self.p2, enabled=False)
        self.act('http', self.a, self.p2, what='stop')
        self.assertEqual([self.states(self.a, self.a), self.states(self.a, self.p2), self.states(self.b, self.b)], [(True, True), (False, False), (True, True)])

    def test_stopping_the_site_needs_the_confirmation_and_stops_every_page_of_that_site_only(self):
        self.run_all()
        before = [self.states(self.a, self.a), self.states(self.a, self.p2), self.states(self.b, self.b)]
        self.assertEqual(before, [(True, True)] * 3)
        for body in ({}, {'confirmed': False}, {'confirmed': 'true'}, {'confirmed': 1}):
            with self.subTest(body):
                with self.assertRaises(ValueError):
                    self.act('stop-site', self.a, **body)
        with self.assertRaises(ValueError):
            self.app.site_action('stop-site', {'confirmed': True})  # two sites: never a guess
        with self.assertRaises(ValueError):
            self.act('stop-site', 'site-00000000', confirmed=True)
        self.assertEqual([self.states(self.a, self.a), self.states(self.a, self.p2), self.states(self.b, self.b)], before)
        done = self.act('stop-site', self.a, confirmed=True)
        self.assertEqual(done['stopped'], [self.a, self.p2])
        self.assertEqual([self.states(self.a, self.a), self.states(self.a, self.p2), self.states(self.b, self.b)], [(False, False), (False, False), (True, True)])
        self.assertEqual(self.app.sites[self.a].http_monitor().load()['paused_reason'], 'USER')
        self.assertEqual(self.act('stop-site', self.a, confirmed=True)['stopped'], [self.a, self.p2])  # stopping what is stopped is fine
        self.fresh()
        agg = self.app.sites[self.a].overview()['aggregate']
        self.assertEqual((agg['state'], agg['stopped'], agg['units']), ('STOPPED', 2, 2))
        self.assertEqual(self.app.sites[self.b].overview()['aggregate']['units'], 1)

    def test_stop_site_has_no_start_counterpart(self):
        for route in ('/app/api/site/start-site', '/app/api/site/start-all'):
            self.assertNotIn(route, __import__('src.noxiworks.app', fromlist=['x']).SITE_ROUTES)
        with self.assertRaises(ValueError):
            self.act('start-site', self.a, confirmed=True)

    def test_a_page_that_cannot_be_stopped_is_reported_and_the_others_are_stopped(self):
        self.run_all()
        (self.root(self.a, self.p2) / 'monitor.json').write_text('{broken', encoding='utf-8')
        with self.assertRaises(ValueError) as caught:
            self.act('stop-site', self.a, confirmed=True)
        self.assertIn('About', str(caught.exception))
        self.assertEqual([self.states(self.a, self.a)[0], self.states(self.b, self.b)], [False, (True, True)])
        self.assertFalse(self.app.sites[self.a].http_monitor().load()['enabled'])  # the first page's HTTP was stopped before / after the broken page

    def test_the_schedulers_cover_every_page(self):
        self.run_all()
        self.app.tick()
        self.assertEqual([len(self.app.sites[self.a].site.runs()), len(self.app.sites[self.a].pages[self.p2].site.runs()), len(self.app.sites[self.b].site.runs())], [1, 1, 1])
        self.app.http_pass()
        for u in self.app.units():
            u.http_thread.join(60)
        self.assertEqual([len(u.http_monitor().history()) for u in self.app.units()], [1, 1, 1])
        with mock.patch.object(SiteApp, 'notify_tick') as notify:
            self.app.notify_pass()
        self.assertEqual(notify.call_count, 3)
        self.assertEqual([u.unit for u in self.app.units()], [self.a, self.p2, self.b])

    def test_a_broken_page_never_stops_the_others(self):
        self.act('monitor', self.a, self.p2, enabled=True)
        (self.root(self.a, self.p2) / 'monitor.json').write_text('{broken', encoding='utf-8')
        self.app.tick()
        self.assertIn('scheduler', self.app.sites[self.a].pages[self.p2].error)
        self.assertEqual([len(self.app.sites[self.a].site.runs()), len(self.app.sites[self.b].site.runs())], [1, 1])
        self.fresh()
        listed = {s['site_id']: s for s in self.app.status()['sites']}
        page = [p for p in listed[self.a]['pages'] if p['unit'] == self.p2][0]
        self.assertTrue(page['error'])
        agg = listed[self.a]['aggregate']
        self.assertNotEqual(agg['state'], 'OK')  # an unreadable page is never part of a normal site
        self.assertTrue(any('About' in t for t in agg['attention']))
        json.dumps(self.app.status())
        self.assertEqual(self.app.sites[self.a].status()['unit'], self.a)  # the first page still answers


class Aggregate(Base):
    def setUp(self):
        super().setUp()
        self.p2 = self.add(self.a, '/about', 'About')
        self.app.fixture_capture = False  # a site that cannot be captured for real: image monitoring is "on" but waits (nothing is captured)
        self.grant = mock.patch.object(HttpMonitor, 'grant_problems', return_value=[])
        self.grant.start()
        self.addCleanup(self.grant.stop)

    def aggregate(self):
        self.fresh()
        return self.app.sites[self.a].overview()['aggregate']

    def test_nothing_monitored_is_never_normal(self):
        agg = self.aggregate()
        self.assertEqual((agg['state'], agg['state_label'], agg['units']), ('NOT_MONITORED', '未監視', 2))  # the first page waits for its capture conditions
        self.assertNotEqual(agg['state_label'], '正常')

    def test_the_worst_state_of_the_enabled_pages_wins_and_names_its_page(self):
        self.act('http', self.a, self.a, what='start')
        self.act('http', self.a, self.p2, what='start')
        self.act('http', self.a, self.a, what='check')
        self.act('http', self.a, self.p2, what='check')
        self.assertEqual(self.aggregate()['state'], 'OK')
        self.app.http_probe = down
        self.act('http', self.a, self.p2, what='check')
        agg = self.aggregate()
        self.assertEqual((agg['state'], agg['state_label']), ('DOWN', '障害'))
        self.assertTrue(any(t.startswith('About：') and 'HTTP監視' in t for t in agg['attention']), agg['attention'])
        listed = self.app.sites[self.a].overview()
        self.assertEqual([p['state'] for p in listed['pages']], ['OK', 'DOWN'])
        self.assertEqual(self.app.sites[self.b].overview()['aggregate']['state'], 'NOT_MONITORED')  # the other site is not affected

    def test_a_started_page_that_has_not_been_checked_yet_is_undecided(self):
        self.act('http', self.a, self.p2, what='start')
        self.assertEqual(self.aggregate()['state'], 'UNKNOWN')

    def test_rollup_rules(self):
        def line(state, **kw):
            return {'unit_label': kw.pop('label', 'P'), 'state': state, 'stopped': state == 'STOPPED', **kw}
        for states, want in ((['OK', 'OK'], 'OK'), (['OK', 'DOWN'], 'DOWN'), (['OK', 'UNKNOWN'], 'UNKNOWN'), (['OK', 'STALE'], 'STALE'), (['STALE', 'UNKNOWN'], 'UNKNOWN'),
                             (['DOWN', 'UNKNOWN', 'STALE', 'OK'], 'DOWN'), (['OK', 'NOT_MONITORED'], 'OK'), (['OK', 'STOPPED'], 'OK'),
                             (['NOT_MONITORED', 'STOPPED'], 'NOT_MONITORED'), (['STOPPED', 'STOPPED'], 'STOPPED'), (['NOT_MONITORED'], 'NOT_MONITORED')):
            with self.subTest(states):
                self.assertEqual(rollup([line(s) for s in states])['state'], want)
        broken = rollup([line('OK'), {'unit_label': 'Q', 'error': 'OSError: x'}])
        self.assertEqual((broken['state'], broken['attention']), ('UNKNOWN', ['Q：OSError: x']))
        out = rollup([line('DOWN', label='Top', attention=['HTTP監視：障害']), line('STOPPED', label='About')])
        self.assertEqual((out['attention'], out['units'], out['stopped']), (['Top：HTTP監視：障害'], 2, 1))
        self.assertEqual(rollup([line('OK')])['state_label'], '正常')


class DataFolders(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='siteproof-pages-data-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        patch = mock.patch.object(App, 'generate', staticmethod(fast_generate))
        patch.start()
        self.addCleanup(patch.stop)
        self.data = self.tmp / 'data'
        (self.data / 'sites').mkdir(parents=True)

    def test_a_one_page_data_folder_is_read_as_it_is(self):
        site = Site.register(self.data / 'sites', 'Only', A, ['Desktop'], True, utc_now())
        before = tree(site.root, skip=())
        app = make_app(self.data)
        app.setup()
        after = tree(site.root, skip=())
        self.assertEqual({n for n in before if after.get(n) != before[n]} - {'targets.json'}, set())  # no file rewritten but the interval, as before
        self.assertFalse((site.root / 'pages').exists())  # nothing is created for pages
        self.assertEqual(app.sites[site.info['site_id']].pages, {})
        self.assertEqual(app.site_action('monitor', {'enabled': False})['enabled'], False)  # no site id, no unit: the only page
        self.assertEqual(app.site_status()['pages'], [{'unit': site.info['site_id'], 'label': 'トップページ', 'url': A, 'href': f"/site/{site.info['site_id']}/", 'current': True}])

    def test_a_restart_keeps_the_pages_and_their_own_settings(self):
        app = make_app(self.data)
        app.setup()
        a = app.site_action('register', {'name': 'Alpha', 'url': A, 'kinds': ['Desktop'], 'owner_confirmed': True})['site_id']
        b = app.site_action('register', {'name': 'Beta', 'url': B, 'kinds': ['Desktop'], 'owner_confirmed': True})['site_id']
        p2 = app.site_action('add-page', {'site_id': a, 'path': '/about', 'label': 'About', 'kinds': ['Desktop', 'Mobile']})['unit']
        app.site_action('monitor', {'site_id': a, 'unit': p2, 'interval_seconds': 900})
        again = make_app(self.data)
        again.setup()
        self.assertEqual((set(again.sites), list(again.sites[a].pages), list(again.sites[b].pages), again.site_problems), ({a, b}, [p2], [], []))
        status = again.site_status(a, p2)
        self.assertEqual((status['monitor']['interval_seconds'], status['monitor']['enabled'], status['kinds'], status['label']), (900, False, ['Desktop', 'Mobile'], 'About'))
        self.assertEqual(again.site_status(a)['monitor']['interval_seconds'], 3600)

    def test_a_broken_or_foreign_page_folder_is_listed_and_the_rest_is_served(self):
        app = make_app(self.data)
        app.setup()
        a = app.site_action('register', {'name': 'Alpha', 'url': A, 'kinds': ['Desktop'], 'owner_confirmed': True})['site_id']
        p2 = app.site_action('add-page', {'site_id': a, 'path': '/about', 'label': 'About', 'kinds': ['Desktop']})['unit']
        p3 = app.site_action('add-page', {'site_id': a, 'path': '/two', 'label': 'Two', 'kinds': ['Desktop']})['unit']
        p4 = app.site_action('add-page', {'site_id': a, 'path': '/three', 'label': 'Three', 'kinds': ['Desktop']})['unit']
        root = self.data / 'sites' / a / 'pages'
        (root / p3 / 'site.json').write_text('{broken', encoding='utf-8')
        info = json.loads((root / p4 / 'site.json').read_text('utf-8'))
        (root / p4 / 'site.json').write_text(json.dumps({**info, 'origin': 'https://evil.com', 'url': 'https://evil.com/x'}), encoding='utf-8')
        shutil.copytree(root / p2, root / (a + '-p9'))  # a copied folder whose name is not its page id
        (root / '.tmp-leftover').mkdir()
        again = make_app(self.data)
        again.setup()
        self.assertEqual(list(again.sites[a].pages), [p2])
        self.assertEqual(sorted(f for f, _ in again.site_problems), sorted(f'{a}/pages/{n}' for n in (p3, p4, a + '-p9')))
        self.assertTrue(all(why for _, why in again.site_problems))
        self.assertEqual(again.site_status(a, p2)['unit'], p2)
        self.assertFalse((root / '.tmp-leftover').exists())  # an interrupted registration is cleaned
        problems = again.status()['site_problems']
        self.assertEqual(len(problems), 3)

    def test_backup_of_one_site_contains_its_pages_and_nothing_of_another_site(self):
        app = make_app(self.data)
        app.setup()
        a = app.site_action('register', {'name': 'Alpha', 'url': A, 'kinds': ['Desktop'], 'owner_confirmed': True})['site_id']
        b = app.site_action('register', {'name': 'Beta', 'url': B, 'kinds': ['Desktop'], 'owner_confirmed': True})['site_id']
        p2 = app.site_action('add-page', {'site_id': a, 'path': '/about', 'label': 'About', 'kinds': ['Desktop']})['unit']
        done = app.site_action('backup', {'scope': 'site', 'site_id': a})
        self.assertTrue(done['verified'])
        files = set(json.loads((Path(done['path']) / 'MANIFEST.json').read_text('utf-8'))['files'])
        self.assertIn(f'sites/{a}/pages/{p2}/site.json', files)
        self.assertIn(f'sites/{a}/pages/{p2}/targets.json', files)
        self.assertIn(f'sites/{a}/site.json', files)
        self.assertFalse([f for f in files if f.startswith(f'sites/{b}/')])
        self.assertFalse([f for f in files if '/ui/' in f])  # regenerated, not copied
        shutil.rmtree(Path(done['path']).parent, ignore_errors=True)


class Served(unittest.TestCase):
    """The real pages and addresses (the real page generator, once)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix='siteproof-pages-served-'))
        data = cls.tmp / 'data'
        with mock.patch.object(App, 'generate', staticmethod(fast_generate)):
            app = make_app(data)
            app.setup()
            cls.a = app.site_action('register', {'name': 'Alpha', 'url': A, 'kinds': ['Desktop'], 'owner_confirmed': True})['site_id']
            cls.b = app.site_action('register', {'name': 'Beta', 'url': B, 'kinds': ['Desktop'], 'owner_confirmed': True})['site_id']
            cls.p2 = app.site_action('add-page', {'site_id': cls.a, 'path': '/about', 'label': 'About', 'kinds': ['Desktop']})['unit']
            cls.pb = app.site_action('add-page', {'site_id': cls.b, 'path': '/about', 'label': 'About', 'kinds': ['Desktop']})['unit']
        cls.server, cls.app = serve(data, 0, scheduler=False, fixture_capture=True)
        cls.app.background_query, cls.app.docker_found, cls.app.launcher = mock.MagicMock(return_value=False), False, mock.MagicMock()
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.app.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def call(self, method, path, body=None):
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=60)
        c.request(method, path, None if body is None else json.dumps({'token': self.app.token, **body}),
                  {'Host': f'127.0.0.1:{self.port}', 'X-SiteProof-App': '1', 'Origin': f'http://127.0.0.1:{self.port}', 'Content-Type': 'application/json'})
        r = c.getresponse()
        return r.status, r.read(), dict(r.getheaders())

    def urls(self, path):
        status, raw, _ = self.call('GET', path)
        self.assertEqual(status, 200, path)
        return [p['url'] for p in json.loads(raw)['pages']]

    def test_each_page_serves_its_own_pages_only(self):
        self.assertEqual(self.urls(f'/site/{self.a}/view.json'), [A])
        self.assertEqual(self.urls(f'/site/{self.a}/page/{self.p2}/view.json'), ['https://alpha-site.com/about'])
        self.assertEqual(self.urls(f'/site/{self.b}/page/{self.pb}/view.json'), ['https://beta-site.com/about'])
        for path in (f'/site/{self.a}/page/{self.p2}/', f'/site/{self.a}/page/{self.p2}/index.html', f'/site/{self.a}/page/{self.p2}/review.html'):
            status, raw, _ = self.call('GET', path)
            self.assertEqual(status, 200, path)
            self.assertIn(b'/app/app.js', raw)
        status, _, headers = self.call('GET', f'/site/{self.a}/page/{self.p2}')
        self.assertEqual((status, headers['Location']), (302, f'/site/{self.a}/page/{self.p2}/'))

    def test_addresses_that_are_not_a_page_of_this_site_are_not_found(self):
        for bad in (f'/site/{self.a}/page/', f'/site/{self.a}/page', f'/site/{self.a}/page/site-00000000-p2/', f'/site/{self.a}/page/{self.pb}/', f'/site/{self.a}/page/{self.a}/',
                    f'/site/{self.a}/page/{self.p2}/../../site.json', f'/site/{self.a}/page/{self.p2}/..%2f..%2fsite.json', f'/site/{self.a}/page/{self.p2}/..' + chr(92) + '..' + chr(92) + 'site.json',
                    f'/site/{self.a}/page/{self.p2}/site.json', f'/site/{self.a}/page/{self.p2}/targets.json', f'/site/{self.a}/page/../site.json', f'/site/{self.a}/page/%2e%2e/site.json',
                    f'/site/{self.a}/page/{self.p2}/page/{self.p2}/', f'/site/{self.a}/pages/{self.p2}/', '/site/site-00000000/page/site-00000000-p2/', f'/page/{self.p2}/'):
            with self.subTest(bad):
                self.assertEqual(self.call('GET', bad)[0], 404, bad)

    def test_the_session_names_the_page(self):
        state = json.loads(self.call('GET', f'/app/api/session?site={self.a}&page={self.p2}')[1])
        self.assertEqual((state['site']['unit'], [p['unit'] for p in state['site']['pages']], [p['current'] for p in state['site']['pages']]), (self.p2, [self.a, self.p2], [False, True]))
        state = json.loads(self.call('GET', f'/app/api/session?site={self.a}')[1])
        self.assertEqual(state['site']['unit'], self.a)
        self.assertEqual(json.loads(self.call('GET', f'/app/api/session?site={self.a}&page={self.pb}')[1])['site']['unit'], self.a)  # not this site's page: the first page, never another site's

    def test_a_stale_tab_without_its_page_is_refused_over_http_too(self):
        self.assertEqual(self.call('POST', '/app/api/site/monitor', {'site_id': self.a, 'enabled': True})[0], 422)
        self.assertEqual(self.call('POST', '/app/api/site/monitor', {'site_id': self.a, 'unit': self.pb, 'enabled': True})[0], 422)
        self.assertEqual(self.call('POST', '/app/api/site/monitor', {'site_id': self.a, 'unit': self.p2, 'interval_seconds': 900})[0], 200)
        self.assertEqual(self.call('POST', '/app/api/site/stop-site', {'site_id': self.b})[0], 422)  # not confirmed
        status, raw, _ = self.call('POST', '/app/api/site/add-page', {'site_id': self.b, 'path': '/more', 'label': 'More', 'kinds': ['Desktop']})
        self.assertEqual(status, 200, raw)
        self.assertTrue(json.loads(raw)['result']['href'].startswith(f'/site/{self.b}/page/'))


if __name__ == '__main__':
    unittest.main()
