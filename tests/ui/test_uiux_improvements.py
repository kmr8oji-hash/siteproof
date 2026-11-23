"""HOME / REVIEW usability pass after the live E2E: the monitoring control and its state in plain view, background monitoring apart, the two
Baseline decisions, plain-language errors (original text kept), the profile wording, and one-request-at-a-time feedback.

Offline: pure view logic, the app with the capture test double, and the shipped app.js text. No Docker, network or real site. The browser side
(real clicks in headless Firefox, 1440 / 390 px) is driven by .local/uiux/browser_ui.py and is NOT part of this unit run.
"""
from datetime import timedelta
import json
from pathlib import Path
import unittest

from src.noxiworks.app import utc_now
from src.noxiworks.site_workflow import ACTOR
from src.noxiworks.uiview import KNOWN_FAILURES, UNKNOWN_FAILURE, explain_failure, monitor_view
from tests.ui.test_real_capture import SignedPermit, needs_ssh

ROOT = Path(__file__).resolve().parents[2]
JS = (ROOT / 'src/noxiworks/app_assets/app.js').read_text('utf-8')
OK = [{'key': k, 'label': k, 'ok': True, 'state': 'OK'} for k in ('owner', 'permission', 'identity', 'environment', 'harness')]
BAD = [dict(g, ok=False, state='未確認') if g['key'] == 'environment' else g for g in OK]
ACTIVE = {'state': 'ACTIVE'}
BASELINE_HOLD = '自動作成のBaselineの正式承認待ちです（REVIEWで承認してください）'
CHANGE_HOLD = '変更の確認待ちです（内容を確認してください）'


def view(**over):
    base = dict(enabled=False, running=False, paused_reason=None, last=None, readiness=OK, permit=ACTIVE, setup=None, hold=None)
    return monitor_view(**{**base, **over})


class StateTable(unittest.TestCase):
    def test_every_state_is_told_apart_with_a_japanese_reason(self):
        cases = {
            'MONITORING': view(enabled=True),
            'RUNNING': view(enabled=True, running=True),
            'STOPPED': view(),
            'WAIT_BASELINE': view(paused_reason='DECISION:BASELINE_CREATED', hold=BASELINE_HOLD),
            'WAIT_CHANGE': view(paused_reason='DECISION:CHANGED', hold=CHANGE_HOLD),
            'FAILED': view(paused_reason='ANOMALY:FAILED', last={'outcome': 'FAILED', 'error': 'KD_candidate_saved_pending_and_only_the_registry_baselines_approved'}),
            'COMPLETE': view(paused_reason='COMPLETE'),
            'PERMIT_EXHAUSTED': view(permit={'state': 'EXHAUSTED'}, readiness=BAD),
            'PERMIT_EXPIRED': view(permit={'state': 'EXPIRED'}, readiness=BAD),
            'NOT_READY': view(readiness=BAD),
            'SETUP_RUNNING': view(setup={'state': 'RUNNING'}),
            'WAITING': view(enabled=True, readiness=BAD),
        }
        for state, v in cases.items():
            with self.subTest(state=state):
                self.assertEqual(v['state'], state)
                self.assertTrue(v['label'] and v['reason'])
                self.assertRegex(v['label'] + v['reason'], r'[ぁ-んァ-ヶ一-龥]')
        self.assertEqual(len({v['label'] for v in cases.values()}), len(cases))      # no two states share a label

    def test_what_can_be_done_in_each_state(self):
        self.assertEqual((view()['can_start'], view()['can_stop']), (True, False))
        self.assertEqual((view(enabled=True)['can_start'], view(enabled=True)['can_stop']), (False, True))
        running = view(enabled=True, running=True)
        self.assertEqual((running['can_start'], running['can_stop']), (False, False))           # "検査中です": nothing to press
        self.assertTrue(view(paused_reason='COMPLETE')['can_start'])                              # the USER may start again, never automatic
        self.assertTrue(view(paused_reason='ANOMALY:FAILED')['can_start'])

    def test_start_is_not_offered_when_a_capture_could_not_run(self):
        for v in (view(permit={'state': 'EXHAUSTED'}, readiness=BAD), view(permit={'state': 'EXPIRED'}, readiness=BAD), view(readiness=BAD),
                  view(paused_reason='COMPLETE', readiness=BAD), view(paused_reason='ANOMALY:FAILED', readiness=BAD)):
            self.assertFalse(v['can_start'], v['state'])
            self.assertTrue(v['start_block'], v['state'])                                          # and it says why, in Japanese
        self.assertIn('使い切りました', view(permit={'state': 'EXHAUSTED'}, readiness=BAD)['start_block'])
        self.assertIn('期限', view(permit={'state': 'EXPIRED'}, readiness=BAD)['start_block'])

    def test_a_pending_decision_blocks_start_and_points_to_the_review(self):
        for reason, hold in (('DECISION:BASELINE_CREATED', BASELINE_HOLD), ('DECISION:CHANGED', CHANGE_HOLD)):
            v = view(paused_reason=reason, hold=hold)
            self.assertFalse(v['can_start'])
            self.assertIn('差分レビュー', v['start_block'])
        hold = view(paused_reason='ON_HOLD', hold='自動作成のBaselineの正式承認待ちです')
        self.assertEqual(hold['state'], 'WAIT_BASELINE')

    def test_a_stopped_monitor_never_promises_an_automatic_next_run(self):
        for v in (view(), view(paused_reason='COMPLETE'), view(paused_reason='ANOMALY:FAILED'), view(paused_reason='DECISION:CHANGED', hold=CHANGE_HOLD),
                  view(paused_reason='DECISION:BASELINE_CREATED', hold=BASELINE_HOLD), view(readiness=BAD), view(permit={'state': 'EXHAUSTED'}, readiness=BAD)):
            self.assertNotIn('次回自動', v['reason'])
            self.assertNotIn('自動で検査します', v['reason'])
            self.assertNotIn('次の予定時刻に', v['reason'])
        self.assertIn('自動では', view()['reason'])

    def test_finishing_is_not_a_quality_verdict(self):
        for v in (view(paused_reason='COMPLETE'), view(enabled=True)):
            self.assertNotIn('品質PASS', v['label'] + v['reason'])
            self.assertNotIn('品質は問題', v['label'] + v['reason'])


class ErrorText(unittest.TestCase):
    def test_the_known_internal_code_becomes_a_sentence_and_the_original_is_kept(self):
        raw = 'RealCaptureRefused: 確認項目が成立しませんでした（KD_candidate_saved_pending_and_only_the_registry_baselines_approved）。撮影ハーネスの結果が…'
        e = explain_failure(raw)
        self.assertEqual(e['message'], 'Baselineの検証に失敗しました。安全のため監視を停止しました。')
        self.assertTrue(e['known'])
        self.assertEqual(e['detail'], raw)                                                    # the original text is not lost
        self.assertEqual(e['code'], 'KD_candidate_saved_pending_and_only_the_registry_baselines_approved')
        self.assertNotIn('KD_', e['message'])

    def test_an_unknown_error_gets_no_invented_cause(self):
        e = explain_failure('RuntimeError: Some_Strange_Code appeared')
        self.assertFalse(e['known'])
        self.assertEqual(e['message'], UNKNOWN_FAILURE)
        self.assertEqual(e['detail'], 'RuntimeError: Some_Strange_Code appeared')
        self.assertEqual(e['code'], 'Some_Strange_Code')
        self.assertNotIn('Baseline', e['message'])
        self.assertIsNone(explain_failure(None))
        self.assertIsNone(explain_failure(''))

    def test_only_certain_codes_are_classified(self):
        for code, message in KNOWN_FAILURES:
            self.assertTrue(message.endswith('。'))
            self.assertEqual(explain_failure('x ' + code + ' y')['message'], message)


class ShippedScript(unittest.TestCase):
    def test_start_and_stop_are_in_the_main_area_not_in_the_fold(self):
        control = JS.split('function controlBlock', 1)[1].split('function backgroundBlock', 1)[0]
        for text in ("'監視を停止'", "'監視を開始'", "'検査中です'", 'site-toggle-button', 'mv.can_start', 'start_block'):
            self.assertIn(text, control)
        aux = JS.split("el('details', {'class': 'app-ready', id: 'site-aux'}", 1)[1].split("p.appendChild(aux)", 1)[0]
        self.assertNotIn('監視を停止', aux)
        self.assertNotIn('監視を開始', aux)
        self.assertNotIn('補助操作（通常は不要です）', JS)
        self.assertIn("p.appendChild(controlBlock(s, state));", JS)

    def test_background_monitoring_is_its_own_block_and_says_it_does_not_start_monitoring(self):
        block = JS.split('function backgroundBlock', 1)[1].split('function cell', 1)[0]
        self.assertIn('アプリを閉じている間の監視（バックグラウンド監視）', block)
        self.assertIn('別の設定です', block)
        self.assertIn('勝手に始まることはありません', block)
        self.assertIn("'/app/api/site/setup'", block)
        self.assertLess(JS.index('p.appendChild(controlBlock(s, state))'), JS.index('p.appendChild(backgroundBlock(s))'))
        readiness = JS.split("var rl = el('ul', {});", 1)[1].split("add(ready, rl,", 1)[0]
        self.assertNotIn('アプリを閉じている間の監視', readiness)                                  # no longer buried in the readiness list

    def test_feedback_is_working_done_or_failed_and_one_request_at_a_time(self):
        action = JS.split('function action(', 1)[1].split('// ---- 1. no site yet', 1)[0] if '// ---- 1. no site yet' in JS else JS.split('function action(', 1)[1][:2500]
        self.assertIn("form.dataset.busy === '1'", action)                                       # a second click is ignored
        self.assertIn("'⏳ '", action)
        self.assertIn("'✓ '", action)
        self.assertIn("'✗ 失敗しました：'", action)
        self.assertLess(action.index('await post('), action.index("'✓ '"))                      # "done" only after the server answered
        self.assertIn('aria-busy', action)

    def test_the_two_decisions_are_two_sections_with_clear_headings(self):
        for text in ("'初回Baselineを承認する'", "'変更を確認してBaselineを更新する'", "'このBaselineを正式承認'", "'新しい基準にする'", 'app-bigcheck'):
            self.assertIn(text, JS)
        panel = JS.split('function updatePanel', 1)[1]
        self.assertLess(panel.index('初回Baselineを承認する'), panel.index('変更を確認してBaselineを更新する'))
        # the "nothing to approve" line is only shown when there is no first approval waiting
        self.assertIn('} else if (!shown) {', panel)

    def test_the_profile_wording_comes_from_the_plan(self):
        self.assertIn("function kindsLabel(s)", JS)
        self.assertIn("kindsLabel(s) + '検査中です…'", JS)
        self.assertNotIn("検査中です…（Desktop・Mobile）", JS)

    def test_errors_show_the_sentence_with_the_original_text_folded(self):
        self.assertIn('詳細を見る（技術情報）', JS)
        self.assertIn('mv.failure.detail', JS)
        self.assertNotIn("(last.error || '')", JS)                                                # the raw error is no longer the main message


@needs_ssh
class WithTheApp(unittest.TestCase):
    def setUp(self):
        self.h = SignedPermit()
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
        self.app = self.h.app(kinds=('Desktop',))
        self.h.permit(self.app, max_runs=3)
        self.monitor = self.app.monitor()
        self.monitor.update(utc_now(), None, enabled=False)

    def status(self):
        return self.app.site_status()

    def toggle(self, enabled):
        return self.app.site_action('monitor', {'enabled': enabled})

    def test_start_and_stop_through_the_existing_monitor_route(self):
        v = self.status()['monitor_view']
        self.assertEqual((v['state'], v['can_start']), ('STOPPED', True))
        self.toggle(True)
        v = self.status()['monitor_view']
        self.assertEqual((v['state'], v['can_stop']), ('MONITORING', True))
        self.toggle(False)
        self.assertEqual(self.status()['monitor_view']['state'], 'STOPPED')

    def test_the_server_refuses_a_start_the_screen_would_not_offer(self):
        self.h.permit(self.app, max_runs=1, permit_id='permit-small')
        self.h.fake.variant = 'same'
        self.monitor.run(utc_now(), 'MANUAL')                                                     # the one permitted run
        v = self.status()['monitor_view']
        self.assertFalse(v['can_start'])
        self.assertIn('使い切りました', v['start_block'])
        with self.assertRaises(ValueError) as caught:
            self.toggle(True)
        self.assertIn('監視を開始できません', str(caught.exception))
        self.assertIn('使い切りました', str(caught.exception))
        self.assertFalse(self.monitor.load()['enabled'])                                          # nothing started
        calls = len(self.h.fake.calls)
        self.assertIsNone(self.monitor.run_if_due(utc_now() + timedelta(days=1), None))
        self.assertEqual(len(self.h.fake.calls), calls)

    def test_a_site_that_is_not_ready_cannot_be_started(self):
        self.app.docker_found = False                                                             # an unmet gate: the environment
        self.monitor = self.app.monitor()
        v = self.status()['monitor_view']
        self.assertFalse(v['can_start'])
        with self.assertRaises(ValueError):
            self.toggle(True)
        self.assertFalse(self.monitor.load()['enabled'])

    def test_running_is_shown_while_the_monitor_lock_is_held_and_stop_is_not_offered(self):
        self.toggle(True)
        self.monitor._lock(utc_now())
        try:
            v = self.status()['monitor_view']
            self.assertEqual((v['state'], v['can_stop'], v['can_start']), ('RUNNING', False, False))
        finally:
            self.monitor.lock_path.unlink(missing_ok=True)

    def test_the_stop_reasons_of_a_bounded_run_are_shown_in_words(self):
        policy = {'halt_on': ['FAILED', 'UNKNOWN', 'REAL_NOT_READY', 'NO_BASELINE', 'DISK_FULL'], 'pause_after': ['BASELINE_CREATED', 'CHANGED'],
                  'stop_after_runs': 3, 'hold_for_decisions': True}
        self.monitor.update(utc_now(), None, stop_policy=policy)
        self.h.fake.variant = 'same'
        self.monitor.update(utc_now(), None, enabled=True)
        self.monitor.run(utc_now(), 'SCHEDULE')
        v = self.status()['monitor_view']
        self.assertEqual(v['state'], 'WAIT_BASELINE')
        self.assertFalse(v['can_start'])
        self.assertIn('Baseline', v['label'])
        with self.assertRaises(ValueError):                                                       # the server holds the same line
            self.toggle(True)
        self.monitor.approve_baseline(json.loads(json.dumps(self.app.site.baseline_state()['targets'])), utc_now(), ACTOR)
        self.assertEqual(self.status()['monitor_view']['state'], 'STOPPED')                       # decided: may be started again (by the USER)

    def test_a_failed_inspection_is_explained_and_its_original_text_is_in_the_status(self):
        raw = 'RealCaptureRefused: 確認項目が成立しませんでした（KD_candidate_saved_pending_and_only_the_registry_baselines_approved）。'
        settings = self.monitor.load()
        settings.update(enabled=False, paused_reason='ANOMALY:FAILED', last={'outcome': 'FAILED', 'error': raw, 'trigger': 'SCHEDULE', 'finished_at': '2026-11-22T00:00:00Z'})
        self.monitor.save(settings)
        status = self.status()
        v = status['monitor_view']
        self.assertEqual(v['state'], 'FAILED')
        self.assertIn('安全のため監視を停止しました', v['reason'])
        self.assertNotIn('KD_', v['reason'])
        self.assertEqual(v['failure']['detail'], raw)
        self.assertEqual(status['monitor']['last']['error'], raw)                                 # the stored record is unchanged

    def test_the_profile_label_follows_the_registered_profiles(self):
        self.assertEqual(self.status()['kinds'], ['Desktop'])


class TopSummary(unittest.TestCase):
    """The top line of HOME (running / problem / last inspection / what the USER does next) is built from monitor_view."""

    def test_every_monitoring_state_tells_the_user_what_to_do_next(self):
        import re
        from src.noxiworks import uiview
        states = set(re.findall(r"return view\('([A-Z_]+)'", (ROOT / 'src/noxiworks/uiview.py').read_text('utf-8')))
        self.assertGreaterEqual(len(states), 13)
        self.assertEqual(states - set(uiview.NEXT_STEPS), set())
        self.assertTrue(all(uiview.NEXT_STEPS[x] for x in states))
        self.assertEqual(view(enabled=True)['next'], uiview.NEXT_STEPS['MONITORING'])

    def test_the_summary_strip_is_shown_and_does_not_hide_the_controls(self):
        for key in ('site-summary-running', 'site-summary-problem', 'site-summary-last', 'site-summary-next'):
            self.assertIn(key, JS)
        self.assertLess(JS.index('summaryBar(s, state)'), JS.index('controlBlock(s, state)'))   # above the buttons, which stay in place


if __name__ == '__main__':
    unittest.main()
