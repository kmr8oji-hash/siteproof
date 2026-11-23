"""The optional stop policy of a bounded monitoring run (the live lifecycle check): monitoring pauses instead of scheduling the next
inspection after an anomaly, after an outcome that waits for the USER, and after the planned number of good inspections; and an
inspection does not start while a Baseline decision is open. Offline: the capture test double, the real permit/ledger/Baseline code.
No Docker, no network, no real site. Without a policy nothing changes (also tested).
"""
from datetime import timedelta
import json
import unittest
from unittest import mock

from src.noxiworks.app import utc_now
from src.noxiworks.site_monitor import DEFAULT_HALT_ON
from src.noxiworks.site_workflow import ACTOR, IMAGE_HEIGHTS, page_image
from tests.ui.test_real_capture import SignedPermit, needs_ssh

POLICY = {'halt_on': list(DEFAULT_HALT_ON), 'pause_after': ['BASELINE_CREATED', 'CHANGED'], 'stop_after_runs': 3, 'hold_for_decisions': True}


@needs_ssh
class StopPolicy(unittest.TestCase):
    def setUp(self):
        self.h = SignedPermit()
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
        self.app = self.h.app(kinds=('Desktop',))
        self.h.permit(self.app, max_runs=5)
        self.site, self.monitor = self.app.site, self.app.monitor()
        self.real = self.site.root / 'real'

    def policy(self, **over):
        self.monitor.update(utc_now(), None, stop_policy={**POLICY, **over})

    def settings(self):
        return self.monitor.load()

    offset = timedelta(0)

    def scheduled(self, variant='same'):
        """One scheduler pass, 70 minutes after the previous (the interval is 60): runs only if monitoring is enabled and due, the way the
        app's thread does. All times stay inside the permit's day."""
        self.h.fake.variant = variant
        self.offset += timedelta(minutes=70)
        at = utc_now() + self.offset
        return self.monitor.run_if_due(at, None, lambda: at)

    def resume(self):
        self.monitor.update(utc_now() + self.offset, None, enabled=True)

    def used(self):
        return self.monitor.real().used(self.monitor.real().permit()[0])

    # ---- the whole planned road, one scheduler at a time
    def test_the_planned_road_pauses_where_the_user_decides_and_stops_after_three(self):
        self.policy()
        self.assertEqual(self.scheduled()['outcome'], 'BASELINE_CREATED')                    # capture 1
        self.assertEqual((self.settings()['enabled'], self.settings()['paused_reason']), (False, 'DECISION:BASELINE_CREATED'))
        harness = len(self.h.fake.calls)
        self.assertIsNone(self.scheduled())                                                  # paused: the scheduler starts nothing
        self.assertEqual(len(self.h.fake.calls), harness)
        # resumed without the USER's formal approval: the inspection does not start (no capture, no permit run)
        self.resume()
        ledger_before = self.used()
        entry = self.scheduled()
        self.assertEqual(entry['outcome'], 'ON_HOLD')
        self.assertIn('正式承認待ち', entry['error'])
        self.assertEqual((self.settings()['enabled'], self.settings()['paused_reason']), (False, 'ON_HOLD'))
        self.assertEqual((len(self.h.fake.calls), self.used()), (harness, ledger_before))
        self.monitor.approve_baseline(json.loads(json.dumps(self.site.baseline_state()['targets'])), utc_now(), ACTOR)   # the USER decides
        self.resume()
        self.assertEqual(self.scheduled('changed')['outcome'], 'CHANGED')                    # capture 2
        self.assertEqual(self.settings()['paused_reason'], 'DECISION:CHANGED')
        self.resume()
        entry = self.scheduled('changed')
        self.assertEqual(entry['outcome'], 'ON_HOLD')                                        # the change waits for "新しい基準にする"
        self.assertIn('変更の確認待ち', entry['error'])
        self.assertEqual(self.used(), 2)
        state = self.monitor.real().baseline_update_state()
        self.monitor.update_baseline(state['run_id'], state['versions'], utc_now(), ACTOR)  # the USER decides: v2
        self.assertEqual(self.used(), 2)                                                     # a decision never counts a run
        self.assertEqual(self.settings()['interval_seconds'], 3600)                          # settings are as they were
        self.resume()
        entry = self.scheduled('changed')
        self.assertEqual(entry['outcome'], 'UNCHANGED')                                      # capture 3 against v2
        self.assertEqual((self.settings()['enabled'], self.settings()['paused_reason']), (False, 'COMPLETE'))
        # nothing more is ever started: not by the scheduler, not by a stray tick, and the two spare permit runs stay unused
        self.assertEqual(self.used(), 3)
        calls = len(self.h.fake.calls)
        for _ in range(3):
            self.assertIsNone(self.scheduled('changed'))
        self.app.tick()
        self.assertEqual((len(self.h.fake.calls), self.used()), (calls, 3))
        self.assertEqual(self.settings()['stop_policy']['completed'], 3)

    # ---- anomalies stop the schedule; nothing retries
    def anomaly(self, reason):
        self.assertEqual((self.settings()['enabled'], self.settings()['paused_reason']), (False, 'ANOMALY:' + reason))
        calls = len(self.h.fake.calls)
        for _ in range(3):
            self.assertIsNone(self.scheduled())
        self.assertEqual(len(self.h.fake.calls), calls)                                      # no retry, no tight loop, no spare run used

    def test_a_failed_inspection_stops_the_schedule(self):
        self.policy()
        self.app.real_runner = lambda args, env: 1                                           # the harness did not finish
        self.monitor = self.app.monitor()
        entry = self.scheduled()
        self.assertEqual(entry['outcome'], 'FAILED')
        self.anomaly('FAILED')

    def test_a_timeout_is_a_failure_and_stops_the_schedule(self):
        self.policy()
        import subprocess
        def timeout(args, env):
            raise subprocess.TimeoutExpired(args, 1)
        self.app.real_runner = timeout
        self.monitor = self.app.monitor()
        self.assertEqual(self.scheduled()['outcome'], 'FAILED')
        self.anomaly('FAILED')

    def test_an_undecided_result_stops_the_schedule_and_is_never_offered_as_an_approval(self):
        self.policy(pause_after=[])
        self.assertEqual(self.scheduled()['outcome'], 'BASELINE_CREATED')
        self.monitor.approve_baseline(json.loads(json.dumps(self.site.baseline_state()['targets'])), utc_now(), ACTOR)
        self.resume()
        odd = lambda base: page_image(1440, IMAGE_HEIGHTS['Desktop'] + 40, (40, 60, 90, 255))   # not comparable: UNKNOWN
        with mock.patch('tools.offline_baseline_demo.changed_image', odd):
            self.assertEqual(self.scheduled('changed')['outcome'], 'UNKNOWN')
        self.anomaly('UNKNOWN')
        self.assertEqual(self.monitor.real().baseline_update_state()['state'], 'BLOCKED')

    def test_not_ready_stops_the_schedule(self):
        self.policy()
        self.h.permit(self.app, max_runs=1, permit_id='permit-small')                          # one run: used by the first inspection
        self.assertEqual(self.scheduled()['outcome'], 'BASELINE_CREATED')
        self.monitor.approve_baseline(json.loads(json.dumps(self.site.baseline_state()['targets'])), utc_now(), ACTOR)
        self.resume()
        self.assertEqual(self.scheduled()['outcome'], 'REAL_NOT_READY')                        # the permit has no run left
        self.anomaly('REAL_NOT_READY')

    # ---- the permit's own limit still decides how many runs there can be
    def test_the_permit_limit_is_not_exceeded_even_when_the_user_keeps_resuming(self):
        self.policy(stop_after_runs=99, pause_after=[], hold_for_decisions=False)
        self.h.permit(self.app, max_runs=2, permit_id='permit-two')
        outcomes = []
        for _ in range(4):
            self.resume()
            entry = self.scheduled()
            outcomes.append(entry['outcome'] if entry else None)
        self.assertEqual(outcomes[:2], ['BASELINE_CREATED', 'UNCHANGED'])
        self.assertEqual(self.used(), 2)                                                     # never above the permit
        self.assertEqual(outcomes[2], 'REAL_NOT_READY')

    # ---- without a policy nothing changed
    def test_without_a_policy_monitoring_goes_on_as_before(self):
        self.assertIsNone(self.settings().get('stop_policy'))
        self.assertEqual(self.scheduled()['outcome'], 'BASELINE_CREATED')
        self.assertTrue(self.settings()['enabled'])
        self.assertNotIn('paused_reason', self.settings())
        self.assertEqual(self.scheduled()['outcome'], 'UNCHANGED')
        self.assertTrue(self.settings()['enabled'])

    def test_a_malformed_policy_is_refused_and_the_policy_can_be_removed(self):
        for bad in ({'nope': 1}, {'stop_after_runs': '3'}, {'halt_on': 'FAILED'}, 'x', {'hold_for_decisions': 1}):
            with self.assertRaises(ValueError):
                self.monitor.update(utc_now(), None, stop_policy=bad)
        self.policy()
        self.monitor.update(utc_now(), None, stop_policy=None)
        self.assertIsNone(self.settings()['stop_policy'])

    def test_the_policy_is_never_set_from_an_inspection_or_the_gui_route(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[2] / 'src/noxiworks'
        app = (root / 'app.py').read_text('utf-8')
        self.assertIn("for k in ('enabled', 'interval_seconds', 'offline_fixture') if k in body", app)   # the GUI route cannot set it
        self.assertNotIn('stop_policy=', app)                                  # nothing in the app passes a policy to update(); it only reads one


if __name__ == '__main__':
    unittest.main()
