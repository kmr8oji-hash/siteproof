"""Three state wordings found in the real-site comparison E2E: permit exhausted vs expired, automatic vs formal Baseline, profiles captured.

Offline: the app flow runs through the same test double the other real-capture tests use (no Docker, no network, no real site).
Display only: no capture condition, permit check or comparison is touched here, and the tests re-assert that.
"""
from datetime import timedelta
import json
from pathlib import Path
import re
import tempfile
import unittest

from src.noxiworks.app import App, utc_now
from src.noxiworks.baseline_registry import STANDING_LABELS, baseline_standing, standing
from src.noxiworks.captures import instruction_text
from tests.ui.test_real_capture import SignedPermit, needs_ssh

ROOT = Path(__file__).resolve().parents[2]
APP_JS = (ROOT / 'src/noxiworks/app_assets/app.js').read_text('utf-8')


class PermitStates(unittest.TestCase):
    def info(self, delta, max_runs, used):
        now = utc_now()

        class Real:
            def permit(self):
                return {'permit_id': 'p', 'valid_until': (now + delta).strftime('%Y-%m-%dT%H:%M:%SZ'), 'max_runs': max_runs}, None

            def used(self, permit):
                return used
        return App.permit_info(type('A', (), {})(), Real(), now)

    def test_active_expired_exhausted_are_told_apart_and_expired_keeps_its_old_meaning(self):
        active = self.info(timedelta(days=30), 100, 0)
        self.assertEqual((active['state'], active['expired']), ('ACTIVE', False))
        exhausted = self.info(timedelta(days=30), 100, 100)          # runs used up, the period is still open
        self.assertEqual((exhausted['state'], exhausted['expired'], exhausted['remaining_runs']), ('EXHAUSTED', True, 0))
        over = self.info(timedelta(seconds=-1), 100, 0)
        self.assertEqual((over['state'], over['expired']), ('EXPIRED', True))
        both = self.info(timedelta(seconds=-1), 100, 100)            # period over wins: waiting cannot renew it
        self.assertEqual(both['state'], 'EXPIRED')

    def test_the_summary_is_display_only(self):
        # nothing that decides a capture reads permit_info()'s state or expired
        for name in ('real_capture.py', 'permit.py', 'site_monitor.py'):
            text = (ROOT / 'src/noxiworks' / name).read_text('utf-8')
            self.assertNotIn('permit_info', text, name)
            self.assertNotIn("['expired']", text, name)

    def test_the_screen_says_which_it_is(self):
        self.assertIn("pm.state === 'EXHAUSTED'", APP_JS)
        self.assertIn('許可回数を使い切りました', APP_JS)
        self.assertIn("pm.expired ? '：期限切れです。", APP_JS)
        self.assertIn("s.display === 'EXPIRED' && s.permit && s.permit.state === 'EXHAUSTED'", APP_JS)  # the headline too
        self.assertNotIn('期限切れまたは回数を使い切りました', APP_JS)


class StandingOfABaseline(unittest.TestCase):
    def registry_folder(self, tmp, *, origin=None, confirmed=False):
        base = Path(tmp) / 'real'
        (base / 'registry').mkdir(parents=True)
        if origin:
            (base / 'registry-origin.json').write_text(json.dumps({'origin': origin}), encoding='utf-8')
        if confirmed:
            (base / 'baseline-confirmation.json').write_text(json.dumps({'confirmed_at': 'x'}), encoding='utf-8')
        return base / 'registry'

    def test_automatic_unconfirmed_confirmed_and_formal(self):
        auto = {'actor': 'SiteProof自動作成（初回の安定した撮影・利用者は未確認）'}
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(standing(self.registry_folder(Path(tmp) / 'a', origin='AUTO_INITIAL'), auto), 'AUTO_UNCONFIRMED')
            self.assertEqual(standing(self.registry_folder(Path(tmp) / 'b', origin='AUTO_INITIAL', confirmed=True), auto), 'AUTO_CONFIRMED')
            self.assertEqual(standing(self.registry_folder(Path(tmp) / 'c'), {'actor': 'USER local'}), 'USER')
            # an automatic actor is never formal, even when the origin note is missing; a confirmation file does not make a USER one auto
            self.assertEqual(standing(self.registry_folder(Path(tmp) / 'd'), auto), 'AUTO_UNCONFIRMED')
            self.assertEqual(standing(self.registry_folder(Path(tmp) / 'e', confirmed=True), {'actor': 'USER local'}), 'USER')

    def test_the_snapshot_record_decides_the_wording_and_an_automatic_actor_is_never_formal(self):
        self.assertIsNone(baseline_standing({}))
        self.assertIsNone(baseline_standing({'baseline_registry': None}))
        self.assertEqual(baseline_standing({'baseline_registry': {'standing': 'AUTO_CONFIRMED'}}), 'AUTO_CONFIRMED')
        self.assertEqual(baseline_standing({'baseline_registry': {'actor': 'SiteProof自動作成x', 'baselines': []}}), 'AUTO_UNCONFIRMED')
        self.assertEqual(baseline_standing({'baseline_registry': {'actor': 'USER', 'baselines': [{'actor': 'USER'}]}}), 'USER')
        self.assertEqual([STANDING_LABELS[k][0] for k in ('AUTO_UNCONFIRMED', 'AUTO_CONFIRMED', 'USER')],
                         ['自動作成・未確認', '自動作成・USER確認済み', '正式承認済み'])
        for k in ('AUTO_UNCONFIRMED', 'AUTO_CONFIRMED'):
            self.assertIn('正式な承認ではありません', STANDING_LABELS[k][1])

    def test_the_old_fixed_wording_is_shown_with_the_profiles_really_captured(self):
        record = lambda kinds: {'instruction': '監視許可 p の範囲内で、初回の安定した実撮影（Desktop・Mobileとも完了・STABLE）から自動作成。利用者は未確認',
                                'baselines': [{'kind': k} for k in kinds]}
        self.assertIn('（Desktop完了・STABLE）', instruction_text(record(['Desktop'])))
        self.assertIn('（Mobile完了・STABLE）', instruction_text(record(['Mobile'])))
        self.assertIn('（Desktop・Mobile完了・STABLE）', instruction_text(record(['Desktop', 'Mobile'])))
        self.assertNotIn('とも完了', instruction_text(record(['Desktop'])))
        self.assertEqual(instruction_text({'instruction': 'USERが承認', 'baselines': [{'kind': 'Desktop'}]}), 'USERが承認')


@needs_ssh
class RealFlowShowsTheTruth(unittest.TestCase):
    def setUp(self):
        self.h = SignedPermit()
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)

    def pages(self, app):
        app.rebuild_site()
        ui = app.site_ui
        return {name: (ui / name).read_text('utf-8') for name in ('index.html', 'review.html', 'details.html', 'evidence.html')}

    def run_flow(self, kinds, max_runs=2):
        h = self.h
        app = h.app(kinds=kinds)
        h.permit(app, max_runs=max_runs)
        self.assertEqual(h.outcome(app), ('REAL', 'BASELINE_CREATED'))
        self.assertEqual(h.outcome(app), ('REAL', 'UNCHANGED'))
        return app

    def test_desktop_only_automatic_baseline_compared_is_not_called_approved(self):
        app = self.run_flow(('Desktop',))
        pages = self.pages(app)
        review = pages['review.html']
        self.assertIn('自動作成・未確認', review)
        self.assertNotRegex(review, r'id="review-baseline"[^>]*>承認済み')
        self.assertNotIn('data-baseline-label="承認済み"', review)
        self.assertIn('Baseline 自動作成・未確認', pages['index.html'])
        self.assertNotIn('Baseline 承認済み', pages['index.html'])
        self.assertIn('自動作成・未確認', pages['details.html'])
        self.assertIn('Desktop完了・STABLE', pages['details.html'])           # fix 3: only what was captured
        self.assertNotIn('Mobileとも完了', pages['details.html'])
        self.assertNotIn('Mobile完了', pages['details.html'])

    def test_after_the_users_confirmation_it_says_confirmed_and_still_not_formal(self):
        app = self.run_flow(('Desktop',))
        app.site.confirm_baseline(utc_now())
        pages = self.pages(app)
        self.assertIn('自動作成・USER確認済み', pages['review.html'])
        self.assertIn('Baseline 自動作成・USER確認済み', pages['index.html'])
        self.assertNotIn('正式承認済み', pages['review.html'] + pages['index.html'])
        self.assertIn('正式な承認ではありません', pages['details.html'])

    def test_desktop_and_mobile_keep_their_existing_wording(self):
        app = self.run_flow(('Desktop', 'Mobile'))
        details = self.pages(app)['details.html']
        self.assertIn('Desktop・Mobile完了・STABLE', details)
        self.assertNotIn('とも完了', details)

    def test_displaying_does_not_touch_the_registry_or_the_ledger(self):
        app = self.run_flow(('Desktop',))
        registry = app.site.real_registry()
        before = {p.relative_to(registry).as_posix(): p.read_bytes() for p in registry.rglob('*') if p.is_file()}
        ledger = {p.name: p.read_bytes() for p in (app.data / 'trust' / 'permit-ledger').glob('*.jsonl')}
        self.pages(app)
        app.site.confirm_baseline(utc_now())
        self.pages(app)
        self.assertEqual({p.relative_to(registry).as_posix(): p.read_bytes() for p in registry.rglob('*') if p.is_file()}, before)
        self.assertEqual({p.name: p.read_bytes() for p in (app.data / 'trust' / 'permit-ledger').glob('*.jsonl')}, ledger)

    def test_exhausted_permit_says_so_and_still_refuses_to_capture(self):
        h = self.h
        app = self.run_flow(('Desktop',), max_runs=2)                       # 2 of 2 used, the period is open
        status = app.site_status()
        self.assertEqual((status['permit']['state'], status['permit']['expired'], status['permit']['remaining_runs']), ('EXHAUSTED', True, 0))
        self.assertEqual(status['display'], 'EXPIRED')                      # the API value is unchanged (compatibility)
        self.assertFalse(status['real_capture_available'])
        calls = len(h.fake.calls)
        self.assertEqual(app.monitor().run(utc_now(), 'SCHEDULE')['outcome'], 'REAL_NOT_READY')
        self.assertEqual(len(h.fake.calls), calls)                          # nothing reached the harness: the refusal is unchanged

    def test_an_active_permit_is_active(self):
        h = self.h
        app = h.app(kinds=('Desktop',))
        h.permit(app, max_runs=3)
        self.assertEqual(app.site_status()['permit']['state'], 'ACTIVE')


if __name__ == '__main__':
    unittest.main()
