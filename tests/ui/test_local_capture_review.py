"""Saved S3-1 capture run -> REVIEW. Synthetic run directory only: no real site, no Docker, no AWS, no network."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import tempfile
import unittest
import zlib

from src.noxiworks.home import build, render_details, render_evidence
from src.noxiworks.local_capture import LocalCaptureRefused, attach, load
from src.noxiworks.product import PLAN, capture_plan, dashboard, empty_snapshot, settings
from src.noxiworks.review import page_view, render as render_review

NOW = datetime(2026, 11, 18, 6, 0, tzinfo=timezone.utc)
ORIGIN = 'https://tokyo-trouble-navi-review-ai-off-2026.kmr8oji.workers.dev'
KINDS = {'Desktop': (1440, 900, '7fac617a79e84cec9a1084d2c840b742', (250, 250, 250)),
         'Mobile': (390, 844, 'e54b6f48ba7041f48ab72259815eae14', (240, 244, 255))}


def png(width, height, color):
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    rows = b''.join(b'\x00' + bytes(color) * width for _ in range(height))
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b'')


def write_run(root, *, fail=(), approved=False, origin=ORIGIN, mutate=None, page_id='ttn-about', path='/about', full_page=False):
    """A run directory shaped like .local/s3-run-02 (only what the adapter reads), with a correct export-sha256.json."""
    files = {}
    windows = {}
    for n, (kind, (w, h, job, color)) in enumerate(KINDS.items()):
        data = png(w // 10, h // 10, color)  # small stand-in; the recorded viewport stays 1440x900 / 390x844
        sha = hashlib.sha256(data).hexdigest()
        ref, manifest = f'{job}/capture-1/000002_screenshot_png.png', f'{job}/capture-1/manifest.json'
        ok = kind not in fail
        files[f'workspace/{ref}'] = data
        files[f'workspace/{manifest}'] = b'{"manifest": true}'
        attrs = {'viewport_width': w, 'viewport_height': h, 'locale': 'ja-JP', 'timezone': 'Asia/Tokyo', 'color_scheme': 'light',
                 'device_scale_factor': 1, 'full_page': full_page, 'user_agent': 'SiteProof synthetic fixture ' + kind}
        operational = {'schema': 'siteproof.operational-verdict.v1', 'verdict': 'UNKNOWN', 'reasons': ['BASELINE_PENDING', 'COMPARISON_NOT_RUN'],
                       'profile_trust': 'UNATTESTED', 'metrics': None}
        job_row = {'job_id': job, 'kind': kind, 'page_id': page_id, 'profile': {'attributes': attrs}, 'fingerprint': (kind[0].lower()) * 64,
                   'execution': 'COMPLETED' if ok else 'FAILED', 'reason': None if ok else 'CAPTURE_FAILED', 'profile_reason': 'PROFILE_UNATTESTED',
                   'source': 'OWNER_SITE_UNATTESTED', 'checks': [{'type': 'HTTP', 'outcome': 'PASS', 'reason': 'HTTP_OBSERVED'}],
                   'evidence': {'artifact_ref': ref, 'digest': sha, 'manifest_ref': manifest} if ok else None}
        run = {'state': {'jobs': [job_row], 'quality': 'UNKNOWN', 'isolation': 'NOT VERIFIED'},
               'comparison': {'results': [{'kind': kind, 'job_id': job, 'page_id': page_id, 'current_sha256': sha if ok else None, 'metrics': None,
                                           'operational': operational, 'network_audit': None, 'browser_audit': None, 'profile_trust': 'UNATTESTED',
                                           'source': 'OWNER_SITE_UNATTESTED', 'result_id': 'r' + job[:6], 'execution': job_row['execution']}]},
               'baselines': [{'candidate_id': 'capture-' + job, 'approval_state': 'APPROVED' if approved else 'PENDING', 'digest': 'd' * 64}],
               'capture_info': {job: {'repeat_identical': True}}}
        files[f'{kind}-run-result.json'] = json.dumps(run).encode()
        files[f'{kind}-head.json'] = json.dumps({'http_status': 'HTTP/1.1 200 OK', 'tls': {'result': 'OK', 'verified_against': 'x'}, 'http_headers': {}, 'redirect': None}).encode()
        files[f'{kind}-capture-meta.json'] = json.dumps([{'sandbox': {'browser_version': '156.0.8078.4'}}]).encode()
        windows['CAPTURE-' + kind] = {'opened_at': f'2026-11-18T02:46:{30 + 6 * n}Z', 'closed_at': f'2026-11-18T02:46:{35 + 6 * n}Z'}
    files['validation-result.json'] = json.dumps({'passed': True, 'baseline_approved': False, 'baseline_compared': False, 'aws_touched': False,
                                                  'site_modified': False, 'monitoring_started': False, 'task': 'TEST-RUN', 'windows': windows}).encode()
    files['workspace-created.json'] = json.dumps({'origin': origin, 'url': origin + path}).encode()
    if mutate:
        mutate(files)
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (root / 'export-sha256.json').write_text(json.dumps({rel: hashlib.sha256(d).hexdigest() for rel, d in files.items()}), encoding='utf-8')
    return root


def tree_hashes(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(root).rglob('*')) if p.is_file()}


class Adapter(unittest.TestCase):
    def test_reads_both_profiles_as_pending_and_changes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = write_run(Path(tmp) / 's3-run-xx')
            before = tree_hashes(run)
            local, changes, assets = load(run)
            self.assertEqual(tree_hashes(run), before)  # read-only
            change = changes['ttn-about']
            self.assertIs(change['baseline_approved'], False)
            self.assertIsNone(change['metrics'])
            self.assertEqual([c['kind'] for c in change['captures']], ['Desktop', 'Mobile'])
            self.assertTrue(all(c['candidate']['approval_state'] == 'PENDING' for c in change['captures']))
            self.assertEqual(set(assets['ttn-about']), {'current', 'mobile'})
            self.assertEqual(change['result']['mobile_sha256'], hashlib.sha256(assets['ttn-about']['mobile']).hexdigest())
            self.assertEqual(local['run_id'], 's3-run-xx')
            self.assertNotIn(str(run), json.dumps([local, changes], ensure_ascii=False))  # no absolute path leaves the adapter
            self.assertEqual(len(settings()['pages']), 5)  # targets.json is untouched

    def test_refusals_fail_closed(self):
        for label, kwargs in (('approved candidate', {'approved': True}), ('unregistered origin', {'origin': 'https://example.invalid'})):
            with self.subTest(label), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(LocalCaptureRefused):
                    load(write_run(Path(tmp) / 'r', **kwargs))
        with self.subTest('png differs from its record'), tempfile.TemporaryDirectory() as tmp:
            run = write_run(Path(tmp) / 'r')
            png_path = next((run / 'workspace').rglob('*.png'))
            png_path.write_bytes(png_path.read_bytes() + b'x')  # now differs from export-sha256.json
            with self.assertRaises(LocalCaptureRefused):
                load(run)
        with self.subTest('unlisted file'), tempfile.TemporaryDirectory() as tmp:
            run = write_run(Path(tmp) / 'r')
            manifest = json.loads((run / 'export-sha256.json').read_text('utf-8'))
            del manifest['Desktop-head.json']
            (run / 'export-sha256.json').write_text(json.dumps(manifest), encoding='utf-8')
            with self.assertRaises(LocalCaptureRefused):
                load(run)
        with self.subTest('not a clean run'), tempfile.TemporaryDirectory() as tmp:
            def dirty(files):
                report = json.loads(files['validation-result.json']); report['baseline_approved'] = True
                files['validation-result.json'] = json.dumps(report).encode()
            with self.assertRaises(LocalCaptureRefused):
                load(write_run(Path(tmp) / 'r', mutate=dirty))

    def test_cannot_be_added_to_fixture_data_or_twice(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = write_run(Path(tmp) / 'r')
            with self.assertRaises(LocalCaptureRefused):
                attach({**empty_snapshot(), 'source': 'FIXTURE'}, run)
            once, _ = attach(empty_snapshot(), run)
            self.assertEqual(once['source'], 'LOCAL_CAPTURE')
            with self.assertRaises(LocalCaptureRefused):
                attach(once, run)

    def test_dashboard_refuses_a_page_outside_registered_sites(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, _ = attach(empty_snapshot(), write_run(Path(tmp) / 'r'))
            bad = deepcopy(snapshot)
            bad['local_capture']['pages'][0]['url'] = 'https://example.invalid/about'
            with self.assertRaises(ValueError):
                dashboard(bad, now=NOW)
            clash = deepcopy(snapshot)
            clash['local_capture']['pages'][0]['target_id'] = 'ttn-home'
            with self.assertRaises(ValueError):
                dashboard(clash, now=NOW)


class Screens(unittest.TestCase):
    def built(self, tmp, **kwargs):
        snapshot, assets = attach(empty_snapshot(), write_run(Path(tmp) / 'run', **kwargs))
        staging = Path(tmp) / 'staging'
        for tid, roles in assets.items():
            (staging / tid).mkdir(parents=True)
            for role, raw in roles.items():
                (staging / tid / (role + '.png')).write_bytes(raw)
        out = Path(tmp) / 'out'
        return out, build(out, snapshot, now=NOW, assets=staging)

    def test_review_shows_real_images_and_five_separate_states(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, view = self.built(tmp)
            page = next(p for p in view['pages'] if p['target_id'] == 'ttn-about')
            record = page_view(page, view['source'])
            self.assertEqual((record['capture_label'], record['baseline_label'], record['compare_label'], record['change_label']),
                             ('撮影成功', '未承認', '未実施', '判定なし'))
            self.assertEqual(record['kind'], 'pending')
            self.assertEqual(record['list_label'], 'Baseline未承認')
            self.assertEqual(record['images']['current'], 'evidence/ttn-about/current.png')
            self.assertEqual(record['images']['mobile'], 'evidence/ttn-about/mobile.png')
            self.assertIsNone(record['images']['baseline'])
            self.assertIsNone(record['images']['diff'])
            self.assertEqual([(c['label'], c['size'], c['viewport']) for c in record['cards']], [('Desktop', '144×90', '1440×900'), ('Mobile', '39×84', '390×844')])
            self.assertTrue(all((out / path).is_file() for path in (record['images']['current'], record['images']['mobile'])))
            html = render_review(view)
            self.assertIn('data-selected-id="ttn-about"', html)  # opens on the page that has a saved screenshot
            self.assertIn('src="evidence/ttn-about/current.png"', html)
            # stage + comparison (Baseline, current, slider x2, diff); the enlarged view creates its own image in script
            self.assertEqual(html.count('<img '), 6)
            self.assertNotRegex(html, r'id="review-image-(?:baseline|after|diff)" src=')  # nothing to compare before approval
            self.assertIn('Baselineが未承認のため、比較はまだ行っていません（比較未実施）', html)
            self.assertIn('id="review-tab-desktop"', html)
            self.assertIn('id="review-tab-mobile"', html)
            self.assertIn('撮影は成功しました', html)
            self.assertNotIn('Baseline承認済み', html)
            self.assertNotRegex(html, r'品質(?:：|:)?\s*PASS(?!ではありません)')
            self.assertNotRegex(html, r'<strong class="review-status[^"]*" id="review-baseline">承認済み')
            for cap in page['change']['captures']:  # SHA-256 / fingerprint values belong to DETAIL and EVIDENCE, not to REVIEW
                self.assertNotIn(cap['sha256'], html)
                self.assertNotIn(cap['fingerprint'], html)
            self.assertNotIn('PROFILE_UNATTESTED', html)
            self.assertNotIn('<script>', html)
            self.assertNotIn('unsafe-inline', html)

    def test_technical_records_live_in_detail_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, view = self.built(tmp)
            page = next(p for p in view['pages'] if p['target_id'] == 'ttn-about')
            sha = page['change']['captures'][0]['sha256']
            for html in (render_details(view), render_evidence(view)):
                self.assertIn(sha, html)
                self.assertIn('撮影条件fingerprint', html)
                self.assertIn('CaptureProfile', html)
                self.assertIn('PENDING（USER未承認）', html)
                self.assertIn('Mobile の撮影記録', html)
            self.assertIn('Mobile画像', render_details(view))

    def test_home_flags_the_pending_baseline_and_no_aws_plan_is_made_for_the_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, view = self.built(tmp)
            home = (out / 'index.html').read_text('utf-8')
            self.assertIn('Baseline承認待ち 1件', home)
            self.assertIn('ローカルに保存した撮影結果', home)
            self.assertFalse((out / 'plans' / 'ttn-about').exists())
            self.assertEqual(sorted(p.name for p in (out / 'plans').iterdir()), sorted(p['target_id'] for p in settings()['pages']))
            self.assertEqual(sum(p['http']['state'] == 'NOT_FETCHED' for p in view['pages']), 6)  # no HTTP data is invented

    def test_exported_files_hold_no_internal_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, _ = self.built(tmp)
            for path in out.rglob('*'):
                if path.is_file() and path.suffix in ('.html', '.json'):
                    text = path.read_text('utf-8')
                    self.assertNotRegex(text, r'[A-Za-z]:\\\\[A-Za-z]', path.name)
                    self.assertNotIn(tmp.replace('\\', '/'), text.replace('\\\\', '/'))

    def test_failed_capture_is_not_shown_as_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, view = self.built(tmp, fail=('Mobile',))
            page = next(p for p in view['pages'] if p['target_id'] == 'ttn-about')
            record = page_view(page, view['source'])
            self.assertEqual(record['capture_label'], '一部の撮影が失敗')
            self.assertEqual([c['status'] for c in record['cards']], ['SUCCEEDED', 'FAILED'])
            self.assertIsNone(record['images']['mobile'])
            self.assertEqual(record['kind'], 'pending')
            self.assertEqual(record['list_label'], '撮影に失敗')

    def test_other_pages_stay_not_captured_and_approval_is_never_shown(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, view = self.built(tmp)
            for page in view['pages']:
                record = page_view(page, view['source'])
                self.assertNotEqual(record['baseline_label'], '承認済み')
                if page['target_id'] != 'ttn-about':
                    self.assertEqual((record['capture_label'], record['list_label'], record['compare_label']), ('未撮影', '未撮影', '未実施'))
                    # The planned top page keeps its Desktop / Mobile tabs, without any image; the other pages have no plan.
                    expected = [('desktop', 'PLANNED', None), ('mobile', 'PLANNED', None)] if page['target_id'] == 'ttn-home' else []
                    self.assertEqual([(c['key'], c['status'], c['image']) for c in record['cards']], expected)

    def test_command_line_builds_into_a_new_directory_only(self):
        import sys
        from unittest import mock
        from src.noxiworks.__main__ import main
        with tempfile.TemporaryDirectory() as tmp:
            run = write_run(Path(tmp) / 'run')
            before, out = tree_hashes(run), Path(tmp) / 'out'
            with mock.patch.object(sys, 'argv', ['noxiworks', '--local-capture', str(run), '--out', str(out)]):
                main()
            self.assertTrue((out / 'review.html').is_file())
            self.assertTrue((out / 'evidence' / 'ttn-about' / 'mobile.png').is_file())
            self.assertEqual(tree_hashes(run), before)
            with mock.patch.object(sys, 'argv', ['noxiworks', '--local-capture', str(run), '--out', str(out)]):
                with self.assertRaises(ValueError):
                    main()  # build() never overwrites
            with mock.patch.object(sys, 'argv', ['noxiworks', '--local-capture', str(run), '--sample', '--out', str(Path(tmp) / 'x')]):
                with self.assertRaises(SystemExit):
                    main()


class TopPage(unittest.TestCase):
    """TTN top page `/` as the primary monitoring target. Synthetic runs only; nothing here is a real capture."""

    def build_with(self, tmp, *runs):
        snapshot, assets = attach(empty_snapshot(), list(runs))
        staging = Path(tmp) / 'staging'
        for tid, roles in assets.items():
            (staging / tid).mkdir(parents=True)
            for role, raw in roles.items():
                (staging / tid / (role + '.png')).write_bytes(raw)
        return build(Path(tmp) / 'out', snapshot, now=NOW, assets=staging)

    def test_plan_names_the_top_page_primary_and_a_feature_candidate(self):
        plan = capture_plan()
        home, disaster, about = (plan['pages'][k] for k in ('ttn-home', 'ttn-disaster', 'ttn-about'))
        self.assertEqual((home['role'], home['url'], home['registered']), ('PRIMARY', ORIGIN + '/', True))
        self.assertEqual([(p['kind'], p['full_page']) for p in home['profiles']], [('Desktop', True), ('Mobile', True)])
        self.assertEqual((disaster['role'], disaster['real_capture']), ('FEATURE_CANDIDATE', 'NOT_CAPTURABLE'))
        self.assertEqual((about['role'], about['real_capture']), ('SUPPLEMENTAL', 'CAPTURED_ONCE'))
        self.assertTrue(plan['sites']['ttn'])

    def test_plan_refuses_an_unregistered_primary_or_a_malformed_page(self):
        raw = json.loads(PLAN.read_text('utf-8'))
        with tempfile.TemporaryDirectory() as tmp:
            for label, change in (('primary not registered', lambda p: p['sites'][0]['pages'][1].update(role='PRIMARY')),
                                  ('primary moved', lambda p: p['sites'][0]['pages'][0].update(path='/other')),
                                  ('unknown site', lambda p: p['sites'][0].update(site_id='nope')),
                                  ('foreign host', lambda p: p['sites'][0]['pages'][2].update(path='//evil.invalid/')),
                                  ('bad profile', lambda p: p['sites'][0]['pages'][0]['profiles'][0].update(full_page='yes'))):
                with self.subTest(label):
                    broken = deepcopy(raw)
                    change(broken)
                    path = Path(tmp) / 'plan.json'
                    path.write_text(json.dumps(broken), encoding='utf-8')
                    with self.assertRaises((ValueError, KeyError)):
                        capture_plan(path=path)

    def test_new_capture_workspaces_use_the_planned_full_page_profiles(self):
        from src.core.offline import read_profile
        from src.noxiworks.capture import create_runtime
        with tempfile.TemporaryDirectory() as tmp:
            page = next(p for p in settings()['pages'] if p['target_id'] == 'ttn-home')
            runtime = create_runtime(Path(tmp) / 'ws', {'pages': [page]})
            rows = runtime.store.snapshot('b')['profiles']
            attrs = {r['kind']: read_profile(r['body']).attributes for r in rows}
            self.assertEqual({k: (a['viewport_width'], a['viewport_height'], a['full_page']) for k, a in attrs.items()},
                             {'Desktop': (1440, 900, True), 'Mobile': (390, 844, True)})

    def test_unobserved_top_page_shows_planned_tabs_and_why_nothing_is_compared(self):
        with tempfile.TemporaryDirectory() as tmp:
            view = self.build_with(tmp, write_run(Path(tmp) / 'about'))
            home = page_view(next(p for p in view['pages'] if p['target_id'] == 'ttn-home'), view['source'])
            self.assertTrue(home['primary'])
            self.assertEqual((home['capture_label'], home['baseline_label'], home['compare_label']), ('未撮影', '未取得', '未実施'))
            self.assertIn('実サイトの撮影はUSERの承認後に行います', home['message'])
            self.assertEqual(home['compare_reason'], '未撮影のため、比較する画像がありません。')
            self.assertEqual([c['label'] for c in home['plan']['candidates']], ['防災（主要機能）'])
            html = render_review(view)
            self.assertIn('data-selected-id="ttn-about"', html)  # the only page with a picture opens first
            ttn = html[html.index('data-review-project="ttn"'):]
            self.assertLess(ttn.index('data-id="ttn-home"'), ttn.index('data-id="ttn-about"'))  # primary first in its project
            self.assertIn('<span class="review-primary" title="主要監視対象">主要</span>', html)
            details = render_details(view)
            self.assertIn('画像監視の計画', details)
            self.assertIn('撮影ごとに変わりうる要素と扱い（マスクはしません）', details)
            index = (Path(tmp) / 'out' / 'index.html').read_text('utf-8')
            self.assertIn('主要監視対象</strong><span>画像：未撮影 ／ 実サイト撮影：未承認（未実施）', index)

    def test_a_top_page_run_lands_on_its_registered_target_and_opens_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            top = write_run(Path(tmp) / 'top', page_id='ttn-home', path='/', full_page=True)
            local, changes, assets = load(top)
            self.assertEqual((local['pages'], list(changes), set(assets['ttn-home'])), ([], ['ttn-home'], {'current', 'mobile'}))
            view = self.build_with(tmp, write_run(Path(tmp) / 'about'), top)
            self.assertEqual(sorted(p['target_id'] for p in view['pages'] if p.get('local_capture')), ['ttn-about'])
            record = page_view(next(p for p in view['pages'] if p['target_id'] == 'ttn-home'), view['source'])
            self.assertEqual((record['capture_label'], record['baseline_label'], record['list_label']), ('撮影成功', '未承認', 'Baseline未承認'))
            self.assertTrue(all(c['range'].startswith('ページ全体（') for c in record['cards']))  # with the fixed-menu note
            self.assertEqual([c['change'] for c in record['cards']], ['none', 'none'])
            self.assertIn('data-selected-id="ttn-home"', render_review(view))  # the primary page with a picture wins
            self.assertEqual(len(settings()['pages']), 5)  # targets.json is untouched

    def test_top_page_run_must_match_its_registered_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(LocalCaptureRefused):
                load(write_run(Path(tmp) / 'a', page_id='ttn-top', path='/'))  # `/` only as the registered target
            with self.assertRaises(LocalCaptureRefused):
                load(write_run(Path(tmp) / 'b', page_id='ttn-home', path='/about'))  # registered id, other URL
            with self.assertRaises(LocalCaptureRefused):
                run = write_run(Path(tmp) / 'c')
                attach(empty_snapshot(), [run, run])  # the same page twice


if __name__ == '__main__':
    unittest.main()
