"""S1-B: operational image verdict shown in HOME / DETAIL / REVIEW. Synthetic, offline, no browser."""
import copy
import json
import re
import unittest
from datetime import datetime, timezone

from src.aws_b.model import format_utc
from src.noxiworks.home import render, render_details, visual_view
from src.noxiworks.product import change_view, collect_comparison, dashboard, empty_snapshot, settings
from src.noxiworks.review import page_view, render as render_review
from tests.comparison.support import Fixture

NOW = datetime(2026, 11, 15, 3, 0, tzinfo=timezone.utc)
PAGES = settings()['pages']


class VisualVerdictDisplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        f = Fixture(trusted=False); cls.f = f
        f.comparison.allow_unattested_preview = True
        for job in f.run()['jobs']: f.approve(job['candidate'])
        page = {'target_id': 'p', 'url': 'https://fixture.invalid/'}

        def collect(**run):
            state = f.run(**run)
            return collect_comparison(f.comparison, page, next(j['job_id'] for j in state['jobs'] if j['kind'] == 'Desktop'),
                                      format_utc(NOW))[0]
        cls.collected = {'same': collect(), 'changed': collect(changed=True),
                         'blocked': collect(changed=True, net='blocked'), 'noledger': collect(ledger=False)}

    @classmethod
    def tearDownClass(cls):
        cls.f.close()

    def snapshot(self, mapping, source='FIXTURE'):
        snap = empty_snapshot(); snap['source'] = source
        for tid, key in mapping.items():
            page = next(p for p in PAGES if p['target_id'] == tid)
            snap['changes'][tid] = {**copy.deepcopy(self.collected[key]), 'page_id': tid, 'url': page['url']}
        return snap

    def view(self, mapping):
        return dashboard(self.snapshot(mapping), now=NOW)

    def mapping(self):
        ids = [p['target_id'] for p in PAGES]
        return dict(zip(ids, ['same', 'changed', 'blocked', 'noledger']))

    def test_four_states_and_counts_agree_across_home_detail_and_review(self):
        view = self.view(self.mapping()); ids = [p['target_id'] for p in PAGES]
        states = {p['target_id']: p['change']['state'] for p in view['pages']}
        self.assertEqual([states[i] for i in ids[:4]], ['UNCHANGED', 'CHANGED', 'UNKNOWN', 'UNKNOWN'])
        verdicts = {p['target_id']: p['change']['visual']['verdict'] for p in view['pages']}
        self.assertEqual([verdicts[i] for i in ids[:4]], ['NO_VISUAL_CHANGE_DETECTED', 'VISUAL_CHANGED', 'UNKNOWN', 'UNKNOWN'])
        home, detail, review = render(view), render_details(view), render_review(view)
        n_changed = sum(s == 'CHANGED' for s in states.values())
        n_unknown = sum(s == 'UNKNOWN' for s in states.values())
        self.assertEqual(n_changed, 1)
        self.assertIn(f'変更 {n_changed}', home)
        self.assertIn(f'未確認 {n_unknown}ページ', home)  # Blocked / unaudited pages are counted as unknown, not normal.
        for label in ('設定条件では変化未検出', '画像の変化あり・要確認', '画像検査の判定不能'):
            self.assertIn(label, home); self.assertIn(label, detail); self.assertIn(label, review)
        self.assertIn('撮影環境の真正性未確認', home)
        self.assertIn('id="review-visual"', review)
        self.assertEqual(home.count('class="visual-note unknown"'), 2)
        self.assertEqual(home.count('class="visual-note unchanged"'), 1)
        self.assertEqual(home.count('class="visual-note changed"'), 1)

    def test_blocked_and_unaudited_pages_explain_why_and_show_the_audit(self):
        view = self.view(self.mapping()); ids = [p['target_id'] for p in PAGES]
        blocked = visual_view(view['pages'][ids.index(ids[2])]['change'])
        self.assertEqual(blocked['kind'], 'unknown')
        self.assertIn('撮影に必要な通信が遮断されました', blocked['detail'])
        self.assertIn('遮断 1', blocked['audit']); self.assertIn('cdn.fixture.invalid:443', blocked['audit'])
        missing = visual_view(view['pages'][3]['change'])
        self.assertIn('通信記録を取得できませんでした', missing['detail'])
        self.assertIn('遮断0件の意味ではありません', missing['audit'])
        record = page_view(view['pages'][2], 'FIXTURE')
        self.assertEqual(record['kind'], 'pending')
        self.assertIsNone(record['images']['diff'])  # No confirmed diff image for an undecidable inspection.
        self.assertIn('画像検査は判定不能', record['message'])
        self.assertIn('画像検査は判定不能', render_review(view))

    def test_http_state_and_image_state_stay_separate_and_nothing_claims_quality_pass(self):
        view = self.view(self.mapping())
        home, review = render(view), render_review(view)
        # Every page here is HTTP NOT_FETCHED; image states must not leak into the HTTP column.
        self.assertTrue(all(p['http']['state'] == 'NOT_FETCHED' for p in view['pages']))
        for html in (home, review, render_details(view)):
            self.assertNotRegex(html, r'品質(?:：|:)?\s*PASS')
            for m in re.finditer('品質PASS', html):
                self.assertTrue(html[m.start():].startswith('品質PASSではありません'))
        self.assertIn('運用判定は品質保証ではありません', review)
        self.assertIn('総合品質：未評価', review)

    def test_unobserved_pages_keep_the_not_fetched_display(self):
        view = self.view({PAGES[0]['target_id']: 'same'})
        other = view['pages'][1]
        self.assertEqual(visual_view(other['change'])['kind'], 'none')
        self.assertEqual(visual_view(other['change'])['label'], '未取得')
        home = render(view)
        self.assertEqual(home.count('class="visual-note'), 1)
        self.assertIn('未取得', render_review(view))

    def test_legacy_results_without_audit_are_flagged_not_invented(self):
        # Pre-S1-A result (no `operational`): state kept for the demo, explicitly "not recorded".
        snap = self.snapshot({PAGES[1]['target_id']: 'changed'})
        result = snap['changes'][PAGES[1]['target_id']]['result']
        result.pop('operational'); result.pop('network_audit')
        view = dashboard(snap, now=NOW)
        change = view['pages'][1]['change']
        self.assertEqual(change['state'], 'CHANGED')
        self.assertFalse(change['visual']['recorded']); self.assertIsNone(change['visual']['verdict'])
        self.assertEqual(change['visual']['audit']['state'], 'MISSING')
        self.assertIn('運用判定の記録なし（旧データ）', render(view))
        self.assertIn('記録なし（旧データ）', render_details(view))
        # Imported real data cannot keep a "changed/unchanged" without the record.
        page = PAGES[1]
        raw = snap['changes'][page['target_id']]
        imported = change_view(raw, page, NOW, settings()['capture_interval_seconds'], require_operational=True)
        self.assertEqual(imported['state'], 'UNKNOWN')
        self.assertIn('旧データ', imported['reason'])

    def test_s1a_era_result_without_network_audit_is_downgraded_never_trusted(self):
        snap = self.snapshot({PAGES[0]['target_id']: 'same'})
        result = snap['changes'][PAGES[0]['target_id']]['result']
        self.assertEqual(result['operational']['verdict'], 'NO_VISUAL_CHANGE_DETECTED')
        result.pop('network_audit')  # Saved by S1-A: verdict exists, audit never recorded.
        change = dashboard(snap, now=NOW)['pages'][0]['change']
        self.assertEqual(change['state'], 'UNKNOWN')
        self.assertEqual(change['visual']['verdict'], 'UNKNOWN')
        self.assertIn('NETWORK_AUDIT_MISSING', change['visual']['reasons'])

    def test_tampered_verdict_cannot_promote_and_stale_results_stay_unknown(self):
        snap = self.snapshot({PAGES[2]['target_id']: 'blocked'})
        snap['changes'][PAGES[2]['target_id']]['result']['operational']['verdict'] = 'NO_VISUAL_CHANGE_DETECTED'
        change = dashboard(snap, now=NOW)['pages'][2]['change']
        self.assertEqual((change['state'], change['visual']['verdict']), ('UNKNOWN', 'UNKNOWN'))
        self.assertIn('RESOURCE_BLOCKED', change['visual']['reasons'])
        stale = self.snapshot({PAGES[0]['target_id']: 'same'})
        stale['changes'][PAGES[0]['target_id']]['observed_at'] = format_utc(NOW.replace(day=1))
        change = dashboard(stale, now=NOW)['pages'][0]['change']
        self.assertEqual((change['state'], change['visual']['verdict']), ('UNKNOWN', 'UNKNOWN'))

    def test_strict_fields_and_profile_unattested_are_untouched_in_the_view(self):
        view = self.view(self.mapping())
        for p in view['pages'][:4]:
            change = p['change']
            self.assertEqual(change['quality'], 'UNKNOWN')
            self.assertEqual(change['profile_trust'], 'UNATTESTED')
            self.assertIn('PROFILE_UNATTESTED', change['reasons'])
            self.assertTrue(change['visual']['unattested'])

    def test_no_credentials_or_cookie_material_in_rendered_html_or_view_json(self):
        view = self.view(self.mapping())
        text = json.dumps(view, ensure_ascii=False) + render(view) + render_details(view) + render_review(view)
        for leak in ('Cookie', 'Authorization', 'Set-Cookie', 'password', 'token=', 'secret', 'api_key'):
            self.assertNotIn(leak, text)


if __name__ == '__main__':
    unittest.main()
