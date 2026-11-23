"""The harness's host-side check KD ("the new capture is saved PENDING and only the registry's own Baselines are APPROVED") after a Baseline
update. Found in the live E2E: capture #3 compared correctly with Baseline v2 (0 px, STABLE) but the check failed, because the workspace a
v2 registry stages still holds v1's approved candidate. The check now accepts exactly the registry's WHOLE approved version chain, and
nothing else. Offline: unit cases, plus the real workspace records of a v1 -> v2 -> v3 run made with the capture test double (the test
double does not run this check itself, which is why no earlier offline test caught it).
"""
import json
from pathlib import Path
import unittest

from src.noxiworks.app import utc_now
from src.noxiworks.baseline_runtime import candidates_match, expected_baseline, read_registry
from src.noxiworks.site_workflow import ACTOR
from tests.ui.test_real_capture import SignedPermit, needs_ssh

FP = 'f' * 64


def rec(cid, state, version=None, fp=FP, digest=None, page='p1'):
    return {'candidate_id': cid, 'page_id': page, 'profile_fingerprint': fp, 'approval_state': state, 'candidate_version': version,
            'revision': 1 if state == 'APPROVED' else 0, 'digest': digest or ('d-' + cid)}


def expect(version, top):
    return {'pins': {'Desktop': {'candidate_id': top, 'version': version, 'digest': 'd-' + top, 'fingerprint': FP}}}


class ChainUnit(unittest.TestCase):
    def test_version_1_registry_is_unchanged(self):
        e = expect(1, 'capture-a')
        self.assertTrue(candidates_match([rec('capture-a', 'APPROVED', 1), rec('capture-new', 'PENDING')], 'new', e))
        self.assertFalse(candidates_match([rec('capture-a', 'APPROVED', 1), rec('capture-new', 'APPROVED', 2)], 'new', e))   # the run approved itself
        self.assertFalse(candidates_match([rec('capture-new', 'PENDING')], 'new', e))                                          # the pin is not approved
        self.assertFalse(candidates_match([rec('capture-a', 'APPROVED', 1), rec('capture-x', 'APPROVED', 1, fp='e' * 64), rec('capture-new', 'PENDING')], 'new', e))

    def test_the_whole_version_chain_of_the_registry_is_accepted(self):
        e = expect(2, 'capture-b')
        chain = [rec('capture-a', 'APPROVED', 1), rec('capture-b', 'APPROVED', 2)]
        self.assertTrue(candidates_match(chain + [rec('capture-new', 'PENDING')], 'new', e))                                  # the case that failed live
        e3 = expect(3, 'capture-c')
        self.assertTrue(candidates_match(chain + [rec('capture-c', 'APPROVED', 3), rec('capture-new', 'PENDING')], 'new', e3))

    def test_anything_beyond_the_chain_is_refused(self):
        e = expect(2, 'capture-b')
        chain = [rec('capture-a', 'APPROVED', 1), rec('capture-b', 'APPROVED', 2)]
        new = rec('capture-new', 'PENDING')
        self.assertFalse(candidates_match(chain + [rec('capture-c', 'APPROVED', 3), new], 'new', e))                         # a version above the pin
        self.assertFalse(candidates_match(chain + [rec('capture-new', 'APPROVED', 3)], 'new', e))                              # the run approved its own candidate
        self.assertFalse(candidates_match(chain[1:] + [new], 'new', e))                                                        # v1 missing from the chain
        self.assertFalse(candidates_match(chain[:1] + [rec('capture-z', 'APPROVED', 2)] + [new], 'new', e))                    # version 2 is not the pinned candidate
        self.assertFalse(candidates_match(chain + [rec('capture-dup', 'APPROVED', 1), new], 'new', e))                         # two records claim version 1
        self.assertFalse(candidates_match(chain + [rec('capture-o', 'APPROVED', 1, page='other')], 'new', e))                  # another page's approval
        self.assertFalse(candidates_match([rec('capture-a', 'APPROVED', 1), rec('capture-b', 'PENDING'), new], 'new', e))     # the pinned version is not approved
        self.assertFalse(candidates_match(chain, 'new', e))                                                                    # no PENDING candidate saved
        self.assertFalse(candidates_match(chain + [rec('capture-new', 'APPROVED', None)], 'new', e))                           # approved without a version: strict rule

    def test_a_wrong_digest_on_the_pinned_version_is_refused(self):
        e = expect(2, 'capture-b')
        chain = [rec('capture-a', 'APPROVED', 1), rec('capture-b', 'APPROVED', 2, digest='other')]
        self.assertFalse(candidates_match(chain + [rec('capture-new', 'PENDING')], 'new', e))

    def test_records_without_version_information_keep_the_strict_rule(self):
        e = {'pins': {'Desktop': {'candidate_id': 'capture-a', 'version': 1, 'digest': 'x', 'fingerprint': FP}}}
        legacy = lambda cid, state: {'candidate_id': cid, 'approval_state': state}
        self.assertTrue(candidates_match([legacy('capture-a', 'APPROVED'), legacy('capture-new', 'PENDING')], 'new', e))
        self.assertFalse(candidates_match([legacy('capture-a', 'APPROVED'), legacy('capture-old', 'APPROVED'), legacy('capture-new', 'PENDING')], 'new', e))


@needs_ssh
class ChainOnRealWorkspaces(unittest.TestCase):
    """v1 -> change -> v2 -> unchanged -> change -> v3: every inspection's saved workspace records satisfy KD against the registry it pinned."""
    def setUp(self):
        self.h = SignedPermit()
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
        self.app = self.h.app(kinds=('Desktop',))
        self.h.permit(self.app, max_runs=12)
        self.real = self.app.site.root / 'real'

    def inspect(self, variant):
        self.h.fake.variant = variant
        return self.h.outcome(self.app)

    def update(self):
        monitor = self.app.monitor()
        state = monitor.real().baseline_update_state()
        monitor.update_baseline(state['run_id'], state['versions'], utc_now(), ACTOR)

    def kd_of_latest(self, registry_dir):
        run = sorted(self.app.site.real_runs())[-1]
        result = json.loads((run / 'Desktop-run-result.json').read_text('utf-8'))
        job = result['state']['jobs'][0]['job_id']
        return candidates_match(result['baselines'], job, expected_baseline(read_registry(registry_dir))), [(b['candidate_version'], b['approval_state']) for b in result['baselines']]

    def test_every_inspection_passes_the_check_against_its_own_registry_and_an_unapproved_candidate_is_refused(self):
        self.assertEqual(self.inspect('same'), ('REAL', 'BASELINE_CREATED'))
        self.assertEqual(self.inspect('changed'), ('REAL', 'CHANGED'))
        self.assertTrue(self.kd_of_latest(self.real / 'registry')[0])                       # compared with v1: a one-version chain
        self.update()                                                                       # v2 (the USER approves)
        self.assertEqual(self.inspect('changed'), ('REAL', 'UNCHANGED'))
        ok, records = self.kd_of_latest(self.real / 'registry')
        self.assertEqual(sorted(r for r in records if r[1] == 'APPROVED'), [(1, 'APPROVED'), (2, 'APPROVED')])   # the shape that failed live
        self.assertTrue(ok)
        self.assertEqual(self.inspect('same'), ('REAL', 'CHANGED'))
        self.update()                                                                       # v3
        self.assertEqual(self.inspect('same'), ('REAL', 'UNCHANGED'))
        ok, records = self.kd_of_latest(self.real / 'registry')
        self.assertEqual(sorted(r for r in records if r[1] == 'APPROVED'), [(1, 'APPROVED'), (2, 'APPROVED'), (3, 'APPROVED')])
        self.assertTrue(ok)
        # the same workspace with the new, unapproved candidate approved behind the registry's back, or a version missing, is refused
        run = sorted(self.app.site.real_runs())[-1]
        result = json.loads((run / 'Desktop-run-result.json').read_text('utf-8'))
        job = result['state']['jobs'][0]['job_id']
        pins = expected_baseline(read_registry(self.real / 'registry'))
        sneaky = [dict(b, approval_state='APPROVED', candidate_version=4) if b['candidate_id'] == 'capture-' + job else b for b in result['baselines']]
        self.assertFalse(candidates_match(sneaky, job, pins))
        self.assertFalse(candidates_match([b for b in result['baselines'] if b.get('candidate_version') != 1], job, pins))


if __name__ == '__main__':
    unittest.main()
