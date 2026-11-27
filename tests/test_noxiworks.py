"""Small offline product acceptance set. No browser, AWS, DNS, VM or Docker."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from src.aws_b.handler import Deps
from src.aws_b.model import EVENT_SCHEMA, format_utc
from src.aws_b.probe import ProbeResult
from src.aws_b.store import DynamoStore
from src.core.model import CheckOutcome
from src.noxiworks.home import build, render
from src.noxiworks.product import (settings, monitor_config, run_page, dashboard, empty_snapshot,
    deployment_plan, expiry_view, collect_comparison, export_http)
from src.noxiworks.sample import make_sample
from tests.aws_fakes import FakeDynamo

NOW = datetime(2026, 11, 11, 12, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]


class NoxiWorks(unittest.TestCase):
    def test_two_pages_probe_duplicate_stop_and_separate_results(self):
        pages = settings()['pages']
        store = DynamoStore(FakeDynamo(), 'noxiworks-test')
        probes, lines = [], []
        configs, deps = [], []
        for i, page in enumerate(pages):
            cfg = monitor_config(page, table='noxiworks-test', absolute_end_at=format_utc(NOW + timedelta(hours=1)))
            configs.append(cfg)
            store.arm(target_id=cfg.target_id, hostname=cfg.hostname, policy_version='p1', execution_generation=1, armed_at=format_utc(NOW))
            def probe(deadline, tid=page['target_id'], i=i):
                probes.append(tid)
                return ProbeResult(CheckOutcome.PASS if i == 0 else CheckOutcome.FAIL, 'HTTP_200' if i == 0 else 'HTTP_503', http_status=200 if i == 0 else 503, elapsed_ms=23)
            deps.append(Deps(cfg, store, probe, lambda: NOW, lines.append, attempt_id='a' + str(i)))
        def event(i):
            return {'schema': EVENT_SCHEMA, 'target_id': pages[i]['target_id'], 'scheduled_time': format_utc(NOW), 'execution_generation': 1}
        for i in range(len(pages)):
            self.assertTrue(run_page(pages[i], event(i), deps[i])['persisted'])
        self.assertEqual(run_page(pages[0], event(0), deps[0])['reason'], 'DUPLICATE_SLOT')
        store.stop(target_id=pages[0]['target_id'], expected_generation=1, stopped_at=format_utc(NOW))
        self.assertEqual(run_page(pages[0], event(0), deps[0])['reason'], 'STOPPED')
        snapshot = export_http({p['target_id']: store for p in pages})
        view = dashboard(snapshot, now=NOW)
        self.assertEqual([p['http']['state'] for p in view['pages']], ['STOPPED'] + ['DOWN'] * (len(pages)-1))
        self.assertEqual([p['http']['http_status'] for p in view['pages']], [None] + [503] * (len(pages)-1))
        self.assertEqual(probes, [p['target_id'] for p in pages])
        with self.assertRaises(ValueError):
            run_page(pages[1], event(1), deps[0])
        template = json.loads((ROOT / 'infra/aws_b/template.json').read_text('utf-8'))
        plans = deployment_plan(template)
        self.assertEqual([p['parameters']['ScheduleExpression'] for p in plans], ['rate(6 hours)']*len(pages))
        self.assertEqual(template['Parameters']['ScheduleExpression']['Default'], 'rate(6 hours)')   # AWS-B Lite default
        self.assertTrue(all('AlarmPeriodSeconds' not in p['parameters'] for p in plans))        # no per-page alarm any more

    def test_shared_expiry_stale_unknown_and_renewal_is_not_completion(self):
        observation = {'scope': 'noxiworks.com', 'source': 'manual registrar export',
            'observed_at': format_utc(NOW), 'expires_at': format_utc(NOW - timedelta(days=1)), 'auto_renew_expected': True}
        self.assertEqual(expiry_view(observation, scope='noxiworks.com', now=NOW, max_age=60)['state'], 'EXPIRED')
        for bad in ({}, {**observation, 'expires_at': None}, {**observation, 'source': ''},
                    {**observation, 'observed_at': format_utc(NOW - timedelta(days=3))},
                    {**observation, 'observed_at': format_utc(NOW + timedelta(seconds=1))}):
            self.assertEqual(expiry_view(bad, scope='noxiworks.com', now=NOW, max_age=60)['state'], 'UNKNOWN')
        with tempfile.TemporaryDirectory() as tmp:
            sample = make_sample(Path(tmp) / 'sample', NOW)
            with self.assertRaises(ValueError):
                export_http({}, sample)
            with self.assertRaises(ValueError):
                dashboard({**sample, 'source': 'AWS_EXPORT'}, now=NOW)
            view = dashboard(sample, now=NOW)
            self.assertEqual(len([x for x in view['expiry'] if x['kind'] == 'TLS証明書']), 3)
            owned = next(x for x in view['expiry'] if x['kind'] == 'ドメイン登録' and x['scope'] == 'noxiworks.com')
            self.assertEqual(owned['state'], 'EXPIRED')
            sample['domains']['workers.dev'] = {**observation, 'scope': 'workers.dev'}
            managed = [x for x in dashboard(sample, now=NOW)['expiry'] if x['state'] == 'PROVIDER_MANAGED']
            self.assertEqual(len(managed), 2)
            self.assertTrue(all(x['expires_at'] is None and x['remaining_days'] is None for x in managed))

    def test_history_staleness_future_and_cross_page_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = make_sample(Path(tmp) / 'sample', NOW)
            view = dashboard(sample, now=NOW)
            self.assertIn('復旧を確認', [h['event'] for h in view['history']])
            self.assertEqual([p['http']['state'] for p in dashboard(sample, now=NOW+timedelta(days=2))['pages']], ['STALE']*len(settings()['pages']))
            ids = [p['target_id'] for p in settings()['pages']]
            wrong = deepcopy(sample)
            wrong['http'][ids[0]]['runs'] = sample['http'][ids[1]]['runs']
            with self.assertRaises(ValueError):
                dashboard(wrong, now=NOW)
            wrong = deepcopy(sample)
            wrong['http'][ids[0]]['runs'][-1]['finished_at']['S'] = format_utc(NOW+timedelta(seconds=1))
            self.assertEqual(dashboard(wrong, now=NOW)['pages'][0]['http']['state'], 'UNKNOWN')

    def test_existing_m5_baseline_diff_manifest_and_page_boundary(self):
        from src.noxiworks.capture import create_runtimes, prepare_batches
        with tempfile.TemporaryDirectory() as tmp:
            runtimes = create_runtimes(Path(tmp) / 'new-owner-workspaces')
            batches = prepare_batches(runtimes)
            self.assertEqual(len(runtimes), 3)
            jobs = [j for key, runtime in runtimes.items() for j in runtime.state(batches[key])['jobs']]
            self.assertEqual({j['page_id'] for j in jobs}, {p['target_id'] for p in settings()['pages']})
            self.assertEqual({j['execution'] for j in jobs}, {'ACCEPTED'})
            self.assertEqual({j['source'] for j in jobs}, {'OWNER_SITE_UNATTESTED'})
            for key, runtime in runtimes.items():
                for item in runtime.state(batches[key])['jobs']:
                    _, plan, job = runtime.comparison.plan(item['job_id'])
                    self.assertIsNone(plan['baseline'])
                    page = next(p for p in settings()['pages'] if p['target_id'] == item['page_id'])
                    self.assertEqual(job.snapshot.intent.target_url, page['url'])
                    self.assertEqual(page['site_id'], key)
        from tests.comparison.support import Fixture
        f = Fixture()
        self.addCleanup(f.close)
        page = {'target_id': 'p', 'url': 'https://fixture.invalid/'}
        state = f.run()
        job = state['jobs'][0]['job_id']
        pending, _ = collect_comparison(f.comparison, page, job, format_utc(NOW))
        self.assertFalse(pending['baseline_approved'])
        self.assertIsNone(pending['metrics'])
        for item in state['jobs']:
            f.approve(item['candidate'])  # Explicit synthetic human decision; no product auto-approval.
        state = f.run(changed=True)
        changed, assets = collect_comparison(f.comparison, page, state['jobs'][0]['job_id'], format_utc(NOW))
        self.assertEqual(changed['metrics']['changed_pixels'], 1)
        self.assertEqual(set(assets), {'current.png', 'baseline.png', 'diff.png'})
        self.assertEqual(set(changed['manifests']), {'current', 'baseline'})
        self.assertEqual(changed['quality'], 'UNKNOWN')
        with self.assertRaises(ValueError):
            collect_comparison(f.comparison, settings()['pages'][0], job, format_utc(NOW))

    def test_readonly_home_sample_and_real_unknown_evidence_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = make_sample(root / 'assets', NOW)
            view = build(root / 'home', sample, now=NOW, assets=root / 'assets')
            html = (root / 'home/index.html').read_text('utf-8')
            self.assertIn('デモ', html)
            self.assertNotIn('不具合の確定ではありません', html)
            self.assertIn('diff.png', (root / 'home/details.html').read_text('utf-8'))
            self.assertIn('<script src="folders.js" defer></script>', html)
            self.assertNotIn('<script>', html)
            self.assertNotIn('unsafe-inline', html)
            self.assertEqual([p['change']['state'] for p in view['pages']], ['UNKNOWN', 'CHANGED'] + ['UNKNOWN']*(len(settings()['pages'])-2))
            with self.assertRaises(ValueError):
                build(root / 'home', sample, now=NOW)
            empty = dashboard(empty_snapshot(), now=NOW)
            self.assertTrue(all(p['http']['state'] == 'NOT_FETCHED' for p in empty['pages']))
            self.assertNotIn('badge-sample', render(empty))
            (root / 'assets/noxiworks-taxi/diff.png').write_bytes(b'tampered')
            with self.assertRaises(ValueError):
                build(root / 'bad', sample, now=NOW, assets=root / 'assets')



class CaptureFixtureExport(unittest.TestCase):
    """OFFLINE-01: synthetic S1 -> M5 -> actual local HOME files, no browser/network."""

    def test_fixture_states_s1_bindings_and_local_links(self):
        import hashlib
        from unittest.mock import patch
        from tools.export_capture_fixture import prepare_fixture, export_fixture, verify_links, main
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.assertEqual(root.drive.upper(), 'D:')
            with patch('socket.socket', side_effect=AssertionError('network forbidden')), \
                    patch('subprocess.Popen', side_effect=AssertionError('browser/process forbidden')):
                fixture = prepare_fixture(root / 'fixture', now=NOW)
                summary = export_fixture(fixture)
            self.assertEqual(summary['source'], 'FIXTURE')
            self.assertEqual(summary['quality'], 'UNKNOWN')
            self.assertEqual(summary['profile_trust'], 'PROFILE_UNATTESTED')
            self.assertTrue(all(v['status'] == 'CONSISTENT' for v in summary['s1_verification'].values()))
            pages = {p['page_id']: p for p in summary['pages']}
            self.assertEqual(set(pages), {p['target_id'] for p in settings()['pages']})
            for tid in ('noxiworks-home', 'ttn-home'):
                self.assertEqual(pages[tid]['change'], 'UNCHANGED')
                self.assertEqual(pages[tid]['metrics']['changed_pixels'], 0)
            for tid in ('noxiworks-taxi', 'hms-concierge'):
                self.assertEqual(pages[tid]['change'], 'CHANGED')
                self.assertEqual(pages[tid]['metrics']['changed_pixels'], 1)
            self.assertEqual(pages['hms-home']['change'], 'UNKNOWN')
            self.assertFalse(pages['hms-home']['baseline_approved'])
            self.assertIsNone(pages['hms-home']['metrics'])
            self.assertNotIn('baseline_manifest', pages['hms-home']['evidence_links'])
            home = fixture['root'] / 'home'
            self.assertIn('デモ', (home / 'index.html').read_text('utf-8'))
            self.assertTrue((home / 'review.html').is_file())
            self.assertIn('review.html', (home / 'index.html').read_text('utf-8'))
            from src.noxiworks.review import page_view
            exported_view = json.loads((home / 'view.json').read_text('utf-8'))
            review_pages = {p['target_id']: page_view(p, exported_view['source']) for p in exported_view['pages']}
            self.assertEqual(review_pages['noxiworks-taxi']['kind'], 'changed')
            self.assertEqual(review_pages['hms-home']['baseline'], 'pending')
            self.assertIsNone(review_pages['hms-home']['images']['diff'])
            for tid, page in review_pages.items():
                for path in page['images'].values():
                    if path:
                        self.assertTrue(path.startswith('evidence/' + tid + '/'))
                        self.assertTrue((home / path).is_file())
            self.assertEqual(verify_links(home), summary['verified_local_html_links'])
            self.assertGreater(summary['verified_local_html_links'], 0)
            view = json.loads((home / 'view.json').read_text('utf-8'))
            self.assertTrue(all(p['http']['state'] == 'NOT_FETCHED' for p in view['pages']))
            for page in view['pages']:
                tid, change = page['target_id'], page['change']
                self.assertEqual(change['quality'], 'UNKNOWN')
                self.assertEqual(change['result']['quality'], 'UNKNOWN')
                self.assertEqual(change['result']['source'], 'OFFLINE_FIXTURE_UNATTESTED')
                detail = json.loads((home / 'evidence' / tid / 'details.json').read_text('utf-8'))
                self.assertEqual(detail['source'], 'FIXTURE')
                self.assertEqual(detail['page']['target_id'], tid)
                for role in page['available_assets']:
                    raw = (home / 'evidence' / tid / (role + '.png')).read_bytes()
                    self.assertEqual(hashlib.sha256(raw).hexdigest(), change['result'][role + '_sha256'])
                for role, pin in change['manifests'].items():
                    source = fixture['runtimes'][fixture['jobs'][tid]['site_id']].workspace.storage_root / pin['manifest']['artifact_ref']
                    exported = home / change['evidence_links'][role + '_manifest']
                    self.assertEqual(exported.read_bytes(), source.read_bytes())
                    self.assertEqual(hashlib.sha256(exported.read_bytes()).hexdigest(), pin['manifest']['sha256'])
                    self.assertEqual(json.loads(exported.read_text('utf-8'))['page_id'], tid)
            before = {str(p.relative_to(fixture['root'])): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in fixture['root'].rglob('*') if p.is_file()}
            self.assertEqual(main(['--out', str(fixture['root'])]), 1)
            after = {str(p.relative_to(fixture['root'])): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in fixture['root'].rglob('*') if p.is_file()}
            self.assertEqual(before, after)

    def test_tampered_missing_and_cross_page_evidence_rejected(self):
        from unittest.mock import patch
        from tools.export_capture_fixture import prepare_fixture, export_fixture
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.assertEqual(root.drive.upper(), 'D:')
            with patch('socket.socket', side_effect=AssertionError('network forbidden')), \
                    patch('subprocess.Popen', side_effect=AssertionError('browser/process forbidden')):
                for failure in ('manifest', 'missing_png', 'cross_page'):
                    with self.subTest(failure=failure):
                        fixture = prepare_fixture(root / failure, now=NOW)
                        binding = fixture['jobs']['noxiworks-home']
                        service = fixture['runtimes'][binding['site_id']].comparison
                        if failure == 'cross_page':
                            fixture['jobs']['noxiworks-home'] = fixture['jobs']['noxiworks-taxi']
                            message = 'capture target mismatch'
                        else:
                            pin = service.evidence_pin(service.observe(binding['job_id'])[2])
                            role = 'manifest' if failure == 'manifest' else 'screenshot'
                            path = service.workspace.storage_root / pin[role]['artifact_ref']
                            if failure == 'manifest':
                                path.write_bytes(path.read_bytes() + b'\n')  # Only this new disposable fixture.
                            else:
                                path.unlink()  # Only this new disposable fixture's synthetic PNG.
                            message = 'S1_EVIDENCE_REJECTED'
                        with self.assertRaisesRegex(ValueError, message):
                            export_fixture(fixture)
                        self.assertFalse((fixture['root'] / 'home').exists())
                        self.assertFalse((fixture['root'] / 'home.incomplete').exists())


class HomeFolders(unittest.TestCase):
    def test_native_folders_real_counts_csp_and_existing_brand_assets(self):
        from html.parser import HTMLParser
        from src.noxiworks.home import render, page_attention, EXTRA_CSS
        class Nodes(HTMLParser):
            def __init__(self, html):
                super().__init__(); self.nodes = []; self.feed(html)
            def handle_starttag(self, tag, attrs): self.nodes.append((tag, dict(attrs)))
        view = dashboard(empty_snapshot(), now=NOW)
        view['pages'][0]['http']['state'] = 'UP'
        view['pages'][0]['change'].update(state='UNCHANGED', baseline_approved=True, source_availability='VERIFIED')
        view['pages'][1]['change'].update(state='CHANGED', observed_at=format_utc(NOW))
        self.assertFalse(page_attention(view['pages'][0]))
        self.assertTrue(page_attention(view['pages'][1]))
        self.assertTrue(page_attention(view['pages'][2]))
        html = render(view); nodes = Nodes(html).nodes
        folders = [a for t,a in nodes if t == 'details' and 'data-project' in a]
        self.assertEqual([a['data-project'] for a in folders], ['noxiworks','hms','ttn'])
        self.assertEqual(sum('open' in a for a in folders), 1)
        rows = [a for t,a in nodes if t == 'article' and 'data-page-id' in a]
        self.assertEqual(len(rows), 5)
        self.assertEqual(sum(a['data-changed']=='true' for a in rows), 1)
        self.assertEqual(sum(a['data-attention']=='true' for a in rows), 4)
        self.assertIn('変更あり 1', html)
        self.assertEqual(folders[0]['data-level'], 'changed')
        self.assertEqual(folders[0]['data-changed'], '1')
        self.assertEqual([f['data-level'] for f in folders[1:]], ['unknown', 'unknown'])
        self.assertIn('要確認 1', html)  # NoxiWorks has one healthy and one changed page.
        self.assertEqual([a for t,a in nodes if t=='script'], [{'src':'folders.js','defer':None},{'src':'scrollcard.js','defer':None},{'src':'nav.js','defer':None}])
        csp = next(a['content'] for t,a in nodes if t=='meta' and a.get('http-equiv')=='Content-Security-Policy')
        self.assertIn("script-src 'self'", csp)
        self.assertIn("connect-src 'none'", csp)
        self.assertNotIn('unsafe-inline', csp)
        self.assertFalse(any(k.lower().startswith('on') for _,a in nodes for k in a))
        self.assertTrue(any(t=='noscript' for t,_ in nodes))
        self.assertIn('id="folder-tools" hidden', html)
        self.assertNotIn('max-height:', EXTRA_CSS)
        # Inner scrolling is allowed only for the two overview cards (.scroll-body, with up/down buttons), nowhere else.
        self.assertEqual(EXTRA_CSS.count('overflow-y: auto'), 1)
        self.assertIn('.scroll-card .scroll-body { height: 340px; overflow-y: auto', EXTRA_CSS)
        self.assertIn('.dashboard-home .status-card { background: #062959', EXTRA_CSS)
        self.assertIn('overflow-wrap: anywhere', EXTRA_CSS)
        self.assertNotIn('font-family:', EXTRA_CSS)
        original = (ROOT/'web/home/index.html').read_text('utf-8')
        import re
        self.assertIn(re.search(r'<svg class="brand-mark".*?</svg>', original, re.S)[0], html)
        self.assertEqual(len([a for t,a in nodes if t=='a' and a.get('class','').startswith('launcher')]),0)   # the in-page menu was replaced by the shared top menu
        for page in view['pages']:
            self.assertIn('details.html#'+page['target_id'], html)

    def test_dynamic_groups_and_escaped_page_text(self):
        from src.noxiworks.home import render
        view = dashboard(empty_snapshot(), now=NOW)
        page = deepcopy(view['pages'][0])
        page.update(target_id='future-page', site_id='future', site_name='Future <Project>',
                    domain='example.invalid', label='<img src=x onerror=alert(1)>',
                    url='https://example.invalid/'+'very-long-path/'*50)
        view['pages'].append(page)
        html = render(view)
        self.assertEqual(html.count('class="project-folder"'),4)
        self.assertIn('表示 6 / 6 ページ', html)
        self.assertIn('Future &lt;Project&gt;', html)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', html)
        self.assertNotIn('<img src=x', html)
        self.assertIn('href="'+page['url']+'" target="_blank" rel="noopener noreferrer"', html)
        self.assertIn('data-project="future"', html)


class Home04Integration(unittest.TestCase):
    def test_priorities_unknown_and_independent_state_contracts(self):
        from src.noxiworks.home import folder_status
        view = dashboard(empty_snapshot(), now=NOW)
        before = deepcopy(view)
        html = render(view)
        self.assertEqual(view, before)
        self.assertEqual(html.count('data-level="unknown"'), 3)
        self.assertNotIn('data-level="danger"', html)
        self.assertNotIn('data-level="action"', html)
        self.assertIn('総合品質：未評価', html)
        self.assertNotIn('badge-sample', html)
        pages = deepcopy(view['pages'][:2])
        for p in pages:
            p['http']['state'] = 'UP'
            p['change'].update(state='UNCHANGED', baseline_approved=True,
                               source_availability='VERIFIED', observed_at=format_utc(NOW))
        self.assertEqual(folder_status(pages)[0], 'normal')
        # Job/check results cannot substitute for verified evidence or quality.
        pages[0]['job'] = {'execution': 'COMPLETED', 'checks': [
            {'outcome': 'PASS'}, {'outcome': 'FAIL'}, {'outcome': 'SKIPPED'}]}
        pages[0]['change']['source_availability'] = 'UNAVAILABLE'
        self.assertEqual(folder_status(pages)[0], 'unknown')
        pages[1]['change']['state'] = 'CHANGED'
        self.assertEqual(folder_status(pages)[0], 'changed')
        pages[0]['change']['baseline_approved'] = False
        self.assertEqual(folder_status(pages)[0], 'action')
        pages[1]['http']['state'] = 'DOWN'
        level, counts = folder_status(pages)
        self.assertEqual(level, 'danger')
        self.assertEqual(counts, {'http_down': 1, 'action': 1, 'changed': 1, 'attention': 2})
        view['pages'][:2] = pages
        saved = deepcopy(view)
        html = render(view)
        self.assertEqual(view, saved)
        self.assertIn('data-http-down="1" data-action="1" data-changed="1" data-review="2"', html)
        self.assertIn('HTTP異常 1件', html)
        self.assertIn('Baseline承認待ち 1件', html)
        self.assertIn('画像変更 1件', html)
        view['expiry'][0]['state'] = 'EXPIRED'
        view['expiry'][0]['remaining_days'] = -1
        self.assertIn('期限の確認 1件', render(view))

    def test_visual_polish_unknown_symbols_reasoned_notices_and_background(self):
        import re
        from src.noxiworks.home import EXTRA_CSS
        view = dashboard(empty_snapshot(), now=NOW)
        before = deepcopy(view)
        html = render(view)
        self.assertEqual(view, before)
        self.assertNotIn('class="priority-symbol"', html)
        self.assertNotIn('>?</span>', html)
        self.assertIn('現在の稼働状態は確認できません', html)
        self.assertIn('画像の比較と証拠は未検証です', html)
        self.assertIn('の期限が未取得です', html)
        self.assertIn('⚠', html)
        for anchor in ('scope','expiry'):
            self.assertIn('href="details.html#'+anchor+'"', html)
        view['source']='AWS_EXPORT'
        self.assertIn('保存済みのデータで、リアルタイムではありません。',render(view))
        for page in view['pages']:
            page['http']['state']='UP'
            page['change'].update(state='UNCHANGED',baseline_approved=True,source_availability='VERIFIED')
        view['source']='FIXTURE'
        html=render(view)
        self.assertNotIn('現在の稼働状態は確認できません',html)
        self.assertNotIn('画像の比較と証拠は未検証です',html)
        self.assertIn('の期限が未取得です',html)
        view['pages'][0]['http']['state']='DOWN'
        html=render(view)
        self.assertIn('aria-label="HTTP異常あり">!</span>',html)
        self.assertIn('data-state="DOWN"',html)
        self.assertIn('class="notice danger"',html)
        self.assertIn('--danger-bg: #fff0f3',EXTRA_CSS)
        self.assertIn('--warning-bg: #fff3cc',EXTRA_CSS)
        base=ROOT/'src/noxiworks'
        approved=(base/'operations_assets/prototype.css').read_text('utf-8')
        shared=(base/'site-background.css').read_text('utf-8')
        paper=re.search(r'--paper\s*:([^;}]+)',approved)[1].strip()
        layer=re.search(r'body:before\{([^{}]+)\}',approved)[1]
        self.assertIn('background: '+paper+';',shared)
        self.assertIn(layer,shared)
        self.assertNotIn('repeating-linear-gradient',shared)
        self.assertIn('body.monitor-home::before, body.aws-operations::before',shared)
        self.assertIn('href="site-background.css"',render(view))
        self.assertIn('href="site-background.css"',(base/'operations_assets/aws-operations.html').read_text('utf-8'))

    def test_portfolio_warning_colors_safe_site_links_and_operations(self):
        from html.parser import HTMLParser
        from src.noxiworks.home import safe_site_url, tag, EXTRA_CSS
        from src.noxiworks.operations import ASSETS, SERVICES, console_links
        class Nodes(HTMLParser):
            def __init__(self, text):
                super().__init__(); self.nodes = []; self.feed(text)
            def handle_starttag(self, tag, attrs): self.nodes.append((tag, dict(attrs)))
        for value in (None, '', 'javascript:alert(1)', 'data:text/html,test', '//example.com/',
                      'file:///D:/secret', 'https://user:password@example.com/',
                      'https://@example.com/', 'https://example.com:bad/', 'http://',
                      'https://example.com/\nnext', 'https://example.com\\@evil.invalid/',
                      'https://bad..example/', 'https://example.com:0/'):
            self.assertIsNone(safe_site_url(value))
        self.assertEqual(safe_site_url('http://example.com/'), 'http://example.com/')
        view = dashboard(empty_snapshot(), now=NOW)
        for page, state in zip(view['pages'], ('UP','DOWN','STALE','UNKNOWN','STOPPED')):
            page['http']['state'] = state
        before = deepcopy(view)
        html = render(view); nodes = Nodes(html).nodes
        self.assertEqual(view, before)
        for state, style in [('UP','st-pass'),('DOWN','st-alert'),('STALE','st-unknown'),
                             ('UNKNOWN','st-unknown'),('NOT_FETCHED','st-unknown'),('STOPPED','st-stopped')]:
            self.assertIn(style, tag(state)); self.assertIn('data-state="'+state+'"', tag(state))
        self.assertIn('--warning-bg: #fff3cc', EXTRA_CSS)
        self.assertIn('--danger-bg: #fff0f3', EXTRA_CSS)
        self.assertIn('--success-bg: #e2f7ee', EXTRA_CSS)
        self.assertIn('background: var(--warning-bg)', EXTRA_CSS)
        self.assertIn('HTTP異常 1件', html)
        self.assertEqual(html.count('id="aws-operations"'), 1)
        self.assertIn('現在のAWS稼働状態：', html)
        self.assertIn('AWS運用の状況', html)
        links = [a for tag_,a in nodes if tag_=='a']
        for page in view['pages']:
            link = next(a for a in links if a.get('href')==page['url'])
            self.assertEqual(link['target'],'_blank')
            self.assertEqual(set(link['rel'].split()), {'noopener','noreferrer'})
            self.assertTrue(any(a.get('href')=='details.html#'+page['target_id'] for a in links))
        invalid = deepcopy(view); invalid['pages'][0]['url']='javascript:alert(1)'
        self.assertNotIn('href="javascript:', render(invalid))
        quoted = deepcopy(view); quoted['pages'][0]['url']="https://example.com/?q='&x=1"
        escaped = render(quoted)
        self.assertIn('href="https://example.com/?q=&#x27;&amp;x=1"', escaped)
        registry=console_links()
        for name in SERVICES:
            self.assertTrue(any(a.get('href')==registry[name] for a in links))
        operations=(ASSETS/'aws-operations.html').read_text('utf-8')
        opnodes=Nodes(operations).nodes
        self.assertEqual([a['data-service'] for tag_,a in opnodes if 'data-service' in a],list(SERVICES))
        op_links=[a for tag_,a in opnodes if tag_=='a' and 'data-external-console' in a]
        self.assertEqual({a['href'] for a in op_links},set(registry.values()))
        self.assertTrue(all(a.get('target')=='_blank' and {'noopener','noreferrer'} <= set(a.get('rel','').split()) for a in op_links))
        self.assertIn('href="index.html"',operations)
        for text in ['HISTORICAL','UNKNOWN','AWS-C LIVE NO-GO','1バケットを意図的に保持','AWS-A：公開実証済み']:
            self.assertIn(text,operations)
        self.assertNotRegex(operations,r'(?<!\d)\d{12}(?!\d)')
        self.assertIn('<span>AWSアカウント</span><strong>非公開</strong>',operations)

    def test_stale_http_is_history_and_navigation_stays_local(self):
        from html.parser import HTMLParser
        from urllib.parse import urlsplit
        view = dashboard(empty_snapshot(), now=NOW)
        view['source'] = 'AWS_EXPORT'
        p = view['pages'][0]
        p['http'].update(state='UNKNOWN', http_status=200, elapsed_ms=138,
                         last_checked_at=format_utc(NOW - timedelta(days=3)))
        html = render(view)
        self.assertIn('過去の観測 · HTTP 200 · 138 ms', html)
        self.assertIn('未確認', html)
        self.assertIn('保存済みの監視結果', html)
        self.assertNotIn('>デモ</span>', html)
        class Links(HTMLParser):
            def __init__(self):
                super().__init__(); self.links = []; self.ids = set()
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if 'id' in attrs: self.ids.add(attrs['id'])
                if tag == 'a': self.links.append(attrs.get('href', ''))
        parsed = Links(); parsed.feed(html)
        for href in parsed.links:
            link = urlsplit(href)
            if link.scheme or link.netloc:
                from src.noxiworks.operations import console_links
                self.assertIn(href, {p['url'] for p in settings()['pages']} | set(console_links().values()))
                self.assertEqual(link.scheme, 'https')
            else:
                self.assertIn(link.path, ('', 'index.html', 'details.html', 'review.html', 'activity.html', 'evidence.html', 'aws-operations.html'))
                if not link.path: self.assertIn(link.fragment, parsed.ids)
        for implemented in ('activity.html', 'evidence.html'):
            self.assertIn(implemented, html)
        self.assertIn("connect-src 'none'", html)



class ReviewIntegration(unittest.TestCase):
    def test_export_page_binding_missing_assets_and_readonly_evidence(self):
        from src.noxiworks.review import page_view, render as render_review
        from tools.export_capture_fixture import verify_links
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            sample = make_sample(root / 'sample-assets', NOW)
            import hashlib
            def hashes():
                return {str(p.relative_to(root / 'sample-assets')): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in (root / 'sample-assets').rglob('*') if p.is_file()}
            before = hashes()
            view = build(root / 'home', sample, now=NOW, assets=root / 'sample-assets')
            self.assertEqual(before, hashes())
            home = root / 'home'
            self.assertTrue(all((home / f).is_file() for f in ('review.html', 'review.css', 'review.js')))
            self.assertIn('href="review.html"', (home / 'index.html').read_text('utf-8'))
            self.assertGreater(verify_links(home), 0)
            records = {p['target_id']: page_view(p, view['source']) for p in view['pages']}
            self.assertEqual(records['noxiworks-taxi']['kind'], 'changed')
            self.assertEqual(records['noxiworks-home']['baseline_label'], '未承認')
            self.assertIsNone(records['noxiworks-home']['images']['baseline'])
            for tid, record in records.items():
                self.assertTrue(record['detail'].endswith('#' + tid))
                for path in record['images'].values():
                    if path: self.assertTrue(path.startswith('evidence/' + tid + '/') and (home / path).is_file())
            original = deepcopy(view)
            html = render_review(view)
            self.assertEqual(view, original)
            self.assertIn('デモ', html)
            self.assertIn('script-src \'self\'', html)
            self.assertIn('connect-src \'none\'', html)
            self.assertNotIn('unsafe-inline', html)
            self.assertNotIn('<script>', html)
            self.assertIn('activity.html', html)
            missing = build(root / 'without-assets', sample, now=NOW)
            m = page_view(missing['pages'][1], missing['source'])
            self.assertEqual(m['change'], 'CHANGED')  # Preserve result; do not invent available images.
            self.assertEqual(m['kind'], 'pending')
            self.assertTrue(all(path is None for path in m['images'].values()))
            self.assertEqual(before, hashes())

    def test_unknown_escape_unapproved_and_cross_page_refusal(self):
        from html.parser import HTMLParser
        from src.noxiworks.review import page_view, render as render_review
        view = dashboard(empty_snapshot(), now=NOW)
        view['pages'][0].update(site_name='<Site>', label='<img src=x onerror=alert(1)>')
        html = render_review(view)
        self.assertIn('&lt;Site&gt;', html)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', html)
        self.assertNotIn('<img src=x', html)
        self.assertNotIn('デモ</span>', html)
        self.assertIn('比較未実施', html)
        self.assertIn('総合品質：未評価', html)
        class Images(HTMLParser):
            def __init__(self): super().__init__(); self.sources = []
            def handle_starttag(self, tag, attrs):
                if tag == 'img': self.sources.append(dict(attrs).get('src'))
        images = Images(); images.feed(html)
        self.assertEqual(images.sources, [None] * 6)  # stage + comparison (Baseline, current, slider x2, diff): no image without evidence
        for page in view['pages']:
            record = page_view(page, view['source'])
            self.assertEqual(record['kind'], 'pending')
            self.assertEqual(record['baseline_label'], '未取得')
            self.assertEqual(record['state_label'], '未確認')
        page = deepcopy(view['pages'][0])
        page['change'].update(observed_at=format_utc(NOW), baseline_approved=True)
        self.assertIn('比較結果なし', page_view(page, view['source'])['message'])
        page['change']['page_id'] = 'another-page'
        with self.assertRaisesRegex(ValueError, 'cross-page'):
            page_view(page, view['source'])


class IntervalLabel(unittest.TestCase):
    def test_http_interval_is_not_rounded_down_to_zero_hours(self):
        from src.noxiworks.home import every
        self.assertEqual(every(900), '15分')
        self.assertEqual(every(300), '5分')
        self.assertEqual(every(3600), '1時間')
        self.assertEqual(every(21600), '6時間')
        self.assertEqual(every(86400), '24時間')


if __name__ == '__main__':
    unittest.main()
