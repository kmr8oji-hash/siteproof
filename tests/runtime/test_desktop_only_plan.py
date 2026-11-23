"""The real-capture harness captures exactly the profiles of the SIGNED capture plan (Desktop only, Mobile only, or both).

Offline: the harness helpers are exercised directly, the harness process is run only up to its pre-Docker refusal, and the app flow
(Baseline, then compare, run limit) runs through the same test double the other real-capture tests use. No Docker, no network.

What this does NOT show: the real harness running Desktop-only inside Docker against the real site (that is the next, approved run).
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from src.noxiworks import permit as permits
from src.noxiworks.app import utc_now
from tests.runtime import validate_s3t as harness
from tests.ui.test_real_capture import SignedPermit, needs_ssh

ROOT = Path(__file__).resolve().parents[2]
DESKTOP = {'kind': 'Desktop', 'width': 1440, 'height': 900, 'full_page': True}
MOBILE = {'kind': 'Mobile', 'width': 390, 'height': 844, 'full_page': True}


class ProfileKinds(unittest.TestCase):
    def kinds(self, *profiles):
        return harness.plan_profile_kinds({'profiles': list(profiles)})

    def test_the_plan_decides_and_the_order_is_fixed(self):
        self.assertEqual(self.kinds(DESKTOP), ['Desktop'])
        self.assertEqual(self.kinds(MOBILE), ['Mobile'])
        self.assertEqual(self.kinds(DESKTOP, MOBILE), ['Desktop', 'Mobile'])  # the existing behaviour
        self.assertEqual(self.kinds(MOBILE, DESKTOP), ['Desktop', 'Mobile'])

    def test_anything_that_is_not_an_approved_full_page_profile_is_refused(self):
        for bad in ({**DESKTOP, 'width': 1441}, {**DESKTOP, 'height': 901}, {**DESKTOP, 'full_page': False}, {**MOBILE, 'width': 400},
                    {'kind': 'Tablet', 'width': 768, 'height': 1024, 'full_page': True}, {'kind': 'Desktop'}, {}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.kinds(bad)
        with self.assertRaises(ValueError):
            self.kinds(DESKTOP, DESKTOP)   # a kind twice
        with self.assertRaises(ValueError):
            self.kinds()                   # nothing to capture
        with self.assertRaises(ValueError):
            harness.plan_profile_kinds(None)

    def test_the_harness_loop_uses_the_signed_plans_kinds_not_a_fixed_pair(self):
        source = (ROOT / 'tests/runtime/validate_s3t.py').read_text('utf-8')
        self.assertIn('for kind in kinds:', source)
        self.assertNotIn("for kind in ('Desktop', 'Mobile'):", source)

    def test_the_preflight_refuses_an_unapproved_plan_before_docker_and_before_a_run_is_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            for profiles, refused in (([DESKTOP], False), ([DESKTOP, MOBILE], False), ([{**DESKTOP, 'width': 1500}], True), ([], True)):
                folder = Path(tmp) / f'plan-{len(profiles)}-{refused}'
                folder.mkdir()
                (folder / 'capture_plan.json').write_text(json.dumps({'sites': [{'pages': [{'page_id': 'p1', 'profiles': profiles}]}]}), encoding='utf-8')
                with mock.patch.object(permits, 'verify_signature', return_value={'site': {'host': 'h'}, 'target': {'target_id': 'p1'}}), \
                        mock.patch.object(permits, 'ownership_problems', return_value=[]):
                    problems = harness.permit_preflight(Path('permit.json'), Path('trust'), folder, None)
                self.assertEqual(bool(problems), refused, (profiles, problems))
            self.assertEqual(harness.plan_problems(Path(tmp) / 'missing', 'p1'), ['capture plan unreadable or the target page is not in it'])


@needs_ssh
class DesktopOnlyFlow(unittest.TestCase):
    def setUp(self):
        self.h = SignedPermit()
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)

    def test_desktop_only_baseline_then_compare_and_the_run_limit_holds(self):
        h = self.h
        app = h.app(kinds=('Desktop',))
        self.assertEqual(h.outcome(app), ('REAL_NOT_READY', 'REAL_NOT_READY'))
        h.permit(app, max_runs=2)
        self.assertEqual(h.outcome(app), ('REAL', 'BASELINE_CREATED'))           # run 1: the Baseline of the only profile
        self.assertNotIn('--baseline-registry', h.fake.calls[-1][0])
        registry = app.site.real_registry()
        record = json.loads((registry / 'APPROVAL-RECORD.json').read_text('utf-8'))
        self.assertEqual(record['page_id'], app.site.page_id)
        self.assertEqual(h.outcome(app), ('REAL', 'UNCHANGED'))                  # run 2: compared with it, no new approval
        self.assertIn('--baseline-registry', h.fake.calls[-1][0])
        calls = len(h.fake.calls)
        self.assertEqual(app.monitor().run(utc_now(), 'SCHEDULE')['outcome'], 'REAL_NOT_READY')
        self.assertEqual(len(h.fake.calls), calls)                               # 2 of 2 used: nothing more reaches the harness
        plan = json.loads((app.site.root / 'capture_plan.json').read_text('utf-8'))
        self.assertEqual([p['kind'] for s in plan['sites'] for pg in s['pages'] for p in pg['profiles']], ['Desktop'])

    def test_a_changed_page_is_detected_with_only_desktop(self):
        h = self.h
        app = h.app(kinds=('Desktop',))
        h.permit(app, max_runs=3)
        self.assertEqual(h.outcome(app), ('REAL', 'BASELINE_CREATED'))
        h.fake.variant = 'changed'
        self.assertEqual(h.outcome(app), ('REAL', 'CHANGED'))

    def test_the_harness_process_refuses_a_plan_with_an_unapproved_profile_before_anything_runs(self):
        h = self.h
        app = h.app(kinds=('Desktop',))
        plan_file = app.site.root / 'capture_plan.json'
        plan = json.loads(plan_file.read_text('utf-8'))
        plan['sites'][0]['pages'][0]['profiles'][0]['width'] = 1500          # not an approved viewport; the permit below pins THIS plan
        plan_file.write_text(json.dumps(plan), encoding='utf-8')
        h.permit(app, max_runs=2)
        expect = Path(h.root) / 'expect.json'
        expect.write_text('{}', encoding='utf-8')
        evidence = Path(h.root) / 'ev' / 'run'
        done = subprocess.run([sys.executable, '-B', '-m', 'tests.runtime.validate_s3t', '--evidence', str(evidence), '--expect', str(expect),
                               '--permit', str(app.site.root / 'real' / 'permit.json'), '--trust', str(app.data / 'trust' / 'allowed_signers'),
                               '--target-dir', str(app.site.root)], cwd=ROOT, capture_output=True, text=True, encoding='utf-8', timeout=120)
        self.assertEqual(done.returncode, 2, done.stdout[-500:] + done.stderr[-500:])
        self.assertIn('PERMIT_PREFLIGHT_REFUSED', done.stdout)
        self.assertIn('PROFILE_NOT_THE_APPROVED_FULL_PAGE_PROFILE', done.stdout)
        self.assertFalse((app.data / 'trust' / 'permit-ledger').exists())    # no run was counted: refused before the ledger


if __name__ == '__main__':
    unittest.main()
