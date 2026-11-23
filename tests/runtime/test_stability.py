"""Capture stability: the bounded time-spaced capture loop, the trusted re-check, and how CAPTURE_UNSTABLE reaches the verdict.

Offline: a fake clock and fake screenshots (no browser), and the synthetic comparison fixture (temporary SQLite). The TTN case is
modelled on what the 2026-11-18 evidence showed: the first full-page screenshot differs (fixed footer re-rasterised once), then
every later one is identical.
"""
import hashlib
import unittest

from src.runtime.stability import DEFAULT_POLICY, SCHEMA, policy, settled, stable_capture, verify
from tests.comparison.support import Fixture

TTN = {'settle_ms': 300, 'interval_ms': 400, 'required_identical': 3, 'min_span_ms': 800, 'max_attempts': 6, 'max_total_ms': 4500}


class FakePage:
    """`frames(n)` -> PNG bytes of the n-th screenshot. Each shot costs `shot_ms` on the fake clock; sleep advances it too."""

    def __init__(self, frames, shot_ms=250):
        self.frames, self.shot_ms, self.now, self.n, self.timeouts = frames, shot_ms, 0.0, 0, []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds

    def take(self, timeout):
        self.timeouts.append(timeout)
        self.now += self.shot_ms / 1000
        self.n += 1
        return self.frames(self.n)


def run(frames, rules, budget=5.0, shot_ms=250):
    page = FakePage(frames, shot_ms)
    evidence, previous, report = stable_capture(page.take, rules, budget, clock=page.clock, sleep=page.sleep)
    return page, evidence, previous, report


class CaptureLoop(unittest.TestCase):
    def test_a_page_whose_first_render_differs_settles_on_the_later_identical_shots(self):
        page, evidence, previous, report = run(lambda n: b'early' if n == 1 else b'settled', TTN)
        self.assertEqual(report['value'], 'STABLE')
        self.assertEqual((evidence, previous), (b'settled', b'settled'))  # the first (early) render is never the evidence
        self.assertEqual(report['attempts'], 4)
        self.assertNotEqual(report['shots'][0]['sha256'], report['shots'][-1]['sha256'])
        self.assertGreaterEqual(report['shots'][-1]['t_ms'] - report['shots'][-3]['t_ms'], TTN['min_span_ms'])
        self.assertLessEqual(report['elapsed_ms'], TTN['max_total_ms'])
        self.assertEqual(verify(report, evidence, previous, TTN)['value'], 'STABLE')

    def test_the_default_policy_takes_no_fixed_long_wait(self):
        page, evidence, previous, report = run(lambda n: b'same', None)
        self.assertEqual((report['value'], report['attempts']), ('STABLE', 2))
        self.assertLess(page.now, 1.0)  # an already stable page costs two shots and one short interval, nothing more
        self.assertEqual(report['policy'], DEFAULT_POLICY)

    def test_never_settling_page_is_unstable_at_the_attempt_limit(self):
        page, evidence, previous, report = run(lambda n: b'frame%d' % n, TTN)
        self.assertEqual((report['value'], report['reason'], report['attempts']), ('UNSTABLE', 'MAX_ATTEMPTS', TTN['max_attempts']))
        record = verify(report, evidence, previous, TTN)
        self.assertEqual((record['value'], record['reason']), ('UNSTABLE', 'NOT_SETTLED'))

    def test_the_time_budget_is_a_hard_bound(self):
        slow = dict(TTN, max_attempts=10, max_total_ms=30000)
        page, evidence, previous, report = run(lambda n: b'frame%d' % n, slow, budget=2.0, shot_ms=600)
        self.assertEqual((report['value'], report['reason']), ('UNSTABLE', 'TIME_BUDGET'))
        self.assertLessEqual(page.now, 2.0 + 0.6)  # never more than one shot past the stage budget
        self.assertLess(report['attempts'], 10)


class EarlyPair(unittest.TestCase):
    def test_two_identical_early_shots_close_together_do_not_count_as_stable(self):
        # Shots 1 and 2 are the same early render taken 0.65 s apart: below the 0.8 s span and below 3 identical shots.
        frames = lambda n: b'early' if n <= 2 else b'settled'
        rules = dict(TTN, required_identical=2)  # even with only 2 required, the span rule rejects the close early pair
        page, evidence, previous, report = run(frames, rules)
        self.assertFalse(settled([(0, 'a'), (650, 'a')], rules))
        self.assertEqual(evidence, b'settled')
        self.assertEqual(report['value'], 'STABLE')
        self.assertNotEqual(report['shots'][-1]['sha256'], hashlib.sha256(b'early').hexdigest())


class TrustedCheck(unittest.TestCase):
    def good(self):
        _, evidence, previous, report = run(lambda n: b'early' if n == 1 else b'settled', TTN)
        return evidence, previous, report

    def test_missing_forged_or_inconsistent_reports_are_unstable(self):
        evidence, previous, report = self.good()
        self.assertEqual(verify(None, evidence, previous)['reason'], 'NOT_REPORTED')
        self.assertEqual(verify({'schema': 'x'}, evidence, previous)['reason'], 'NOT_REPORTED')
        self.assertEqual(verify(report, evidence, previous, DEFAULT_POLICY)['reason'], 'POLICY_MISMATCH')
        self.assertEqual(verify(report, b'other', previous, TTN)['reason'], 'RECEIVED_IMAGES_DIFFER_FROM_REPORT')
        early_pair = {**report, 'shots': report['shots'][:1] + [dict(report['shots'][1], t_ms=report['shots'][0]['t_ms'] + 10)] + report['shots'][2:]}
        self.assertEqual(verify(dict(report, shots=[]), evidence, previous, TTN)['reason'], 'REPORT_INVALID')
        claimed = dict(report, shots=[dict(s, t_ms=i) for i, s in enumerate(report['shots'])])  # identical shots 1 ms apart
        self.assertEqual(verify(claimed, evidence, previous, TTN)['reason'], 'NOT_SETTLED')
        self.assertEqual(verify(dict(report, value='UNSTABLE'), evidence, previous, TTN)['value'], 'UNSTABLE')
        self.assertEqual(verify(early_pair, evidence, previous, TTN)['value'], 'STABLE')  # timing still spans the run
        self.assertEqual(verify(report, evidence, previous, TTN)['source'], 'worker:stability-policy-v1')

    def test_policy_bounds_are_enforced(self):
        for bad in ({'interval_ms': 10}, {'required_identical': 1}, {'max_total_ms': 60000}, {'max_attempts': 2, 'required_identical': 3},
                    {'unknown': 1}, {'settle_ms': '300'}):
            with self.subTest(bad), self.assertRaises(ValueError):
                policy(bad)
        self.assertEqual(policy(TTN), TTN)


class VerdictFlow(unittest.TestCase):
    """CAPTURE_UNSTABLE reaches the comparison and makes it UNKNOWN; stable captures still detect a real change."""

    def fixture(self):
        f = Fixture(trusted=False); self.addCleanup(f.close)
        f.comparison.allow_unattested_preview = True  # the real-site (S3) configuration
        return f

    def approved(self, f, stability='STABLE'):
        for job in f.run(stability=stability)['jobs']:
            f.approve(job['candidate'])

    def test_unstable_current_capture_is_unknown_not_changed(self):
        f = self.fixture(); self.approved(f)
        results = f.run(changed=True, stability='UNSTABLE')['results'][:2]
        for r in results:
            self.assertEqual(r['operational']['verdict'], 'UNKNOWN')
            self.assertIn('CAPTURE_UNSTABLE', r['operational']['reasons'])
            self.assertIsNone(r['operational']['changed_pixels'])
            self.assertEqual(r['quality'], 'UNKNOWN')
            self.assertEqual(r['capture_stability']['value'], 'UNSTABLE')

    def test_unstable_baseline_is_unknown_with_a_baseline_reason(self):
        f = self.fixture(); self.approved(f, stability='UNSTABLE')
        for r in f.run(stability='STABLE')['results'][:2]:
            self.assertEqual(r['operational']['verdict'], 'UNKNOWN')
            self.assertIn('BASELINE_CAPTURE_UNSTABLE', r['operational']['reasons'])

    def test_stable_captures_still_detect_a_real_change_and_no_change(self):
        f = self.fixture(); self.approved(f)
        changed = f.run(changed=True, stability='STABLE')['results'][:2]
        self.assertEqual({r['operational']['verdict'] for r in changed}, {'VISUAL_CHANGED'})
        self.assertTrue(all(r['operational']['changed_pixels'] == 1 for r in changed))
        same = f.run(stability='STABLE')['results'][:2]
        self.assertEqual({r['operational']['verdict'] for r in same}, {'NO_VISUAL_CHANGE_DETECTED'})

    def test_a_malformed_record_is_stored_as_unstable(self):
        f = self.fixture(); self.approved(f)
        for r in f.run(changed=True, stability={'schema': SCHEMA, 'value': 'MAYBE'})['results'][:2]:
            self.assertEqual(r['capture_stability']['reason'], 'RECORD_INVALID')
            self.assertEqual(r['operational']['verdict'], 'UNKNOWN')

    def test_jobs_without_a_record_are_neither_promoted_nor_marked_stable(self):
        f = self.fixture(); self.approved(f, stability=None)
        for r in f.run(stability=None)['results'][:2]:
            self.assertIsNone(r['capture_stability'])  # older data: no claim either way (shown as 未確認 in the product UI)
            self.assertNotIn('CAPTURE_UNSTABLE', r['reasons'])


if __name__ == '__main__':
    unittest.main()
