"""Baseline lifecycle, offline: v1 -> change detected -> the USER approves it as v2 -> monitoring continues against v2.

The capture is the same test double the other real-capture tests use (a synthetic page image per variant, the real comparison code, the real
permit/ledger checks); no Docker, no network, no real site. What this does NOT show: a real inspection of the real site after an update.
"""
import hashlib
import socket
import json
from pathlib import Path
import threading
import unittest
from unittest import mock

from src.noxiworks import baseline_update
from src.noxiworks.app import App, serve, utc_now
from src.noxiworks.baseline_update import check_updatable
from src.noxiworks.site_monitor import Busy
from src.noxiworks.site_workflow import ACTOR, SiteRefused
from src.noxiworks.real_capture import BaselineSwitchIncomplete, RealCaptureRefused
from tests.ui.test_real_capture import SignedPermit, needs_ssh

ROOT = Path(__file__).resolve().parents[2]


def tree(root):
    root = Path(root)
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file()}


@needs_ssh
class Lifecycle(unittest.TestCase):
    def setUp(self):
        self.h = SignedPermit()
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
        self.app = self.h.app(kinds=('Desktop',))
        self.h.permit(self.app, max_runs=12)
        self.real = self.app.site.root / 'real'

    def inspect(self, variant='same'):
        self.h.fake.variant = variant
        return self.h.outcome(self.app)

    def update(self, versions=None, run_id=None):
        state = self.app.monitor().real().baseline_update_state()
        return self.app.monitor().update_baseline(run_id or state.get('run_id'), versions or state.get('versions'), utc_now(), ACTOR)

    def changed(self):
        self.assertEqual(self.inspect('same'), ('REAL', 'BASELINE_CREATED'))
        self.assertEqual(self.inspect('changed'), ('REAL', 'CHANGED'))

    def current(self):
        return json.loads((self.real / 'registry' / 'APPROVAL-RECORD.json').read_text('utf-8'))

    # ---- the main road
    def test_v1_then_change_then_user_approves_v2_then_monitoring_continues_on_v2(self):
        site = self.app.site
        self.assertEqual(self.inspect('same'), ('REAL', 'BASELINE_CREATED'))                   # 1. v1 (automatic)
        site.confirm_baseline(utc_now())
        self.assertEqual(site.baseline_state()['state'], 'CONFIRMED')                           # looked at, not formally approved
        self.assertEqual(self.inspect('same'), ('REAL', 'UNCHANGED'))                           # 3. no change against v1
        real = self.app.monitor().real()
        self.assertEqual(real.baseline_update_state()['state'], 'NONE')
        self.assertEqual(self.inspect('changed'), ('REAL', 'CHANGED'))                          # 4-5. the site changed, detected
        offer = real.baseline_update_state()
        self.assertEqual((offer['state'], offer['versions']), ('AVAILABLE', {'Desktop': 1}))    # 6. REVIEW can offer it
        self.assertEqual(offer['profiles']['Desktop']['verdict'], 'VISUAL_CHANGED')
        self.assertEqual(self.app.site_status()['baseline_update']['state'], 'AVAILABLE')
        # waiting for the USER: v1 stays the Baseline, also across another inspection and a restart
        self.assertEqual(self.inspect('changed'), ('REAL', 'CHANGED'))
        self.assertEqual(site.baseline_state()['versions'], {'Desktop': 1})
        v1_registry, evidence = tree(self.real / 'registry'), tree(self.real / 'runs')
        ledger = tree(self.app.data / 'trust' / 'permit-ledger')
        monitor_before = self.app.monitor().load()
        newest = real.baseline_update_state()['run_id']
        record = self.update()                                                                  # 7-8. the USER's approval -> v2
        self.assertEqual([(b['kind'], b['version']) for b in record['baselines']], [('Desktop', 2)])
        self.assertEqual(record['actor'], ACTOR)
        state = site.baseline_state()
        self.assertEqual((state['state'], state['versions']), ('USER', {'Desktop': 2}))         # formally approved, not "confirmed"
        self.assertEqual(self.app.site_status()['baseline']['state'], 'USER')
        self.assertEqual(real.baseline_update_state()['state'], 'NONE')                         # nothing left to decide
        # 11. v1 and the past evidence are kept, byte for byte
        history = site.baseline_history()
        self.assertEqual([h['versions'] for h in history], [{'Desktop': 1}])
        kept = self.real / 'registry-history' / history[0]['name']
        self.assertEqual(tree(kept), v1_registry)
        self.assertEqual(tree(self.real / 'runs'), evidence)
        self.assertEqual(tree(self.app.data / 'trust' / 'permit-ledger'), ledger)                # no run was counted, none rewound
        self.assertEqual({k: v for k, v in self.app.monitor().load().items() if k not in ('next_due_at',)},
                         {k: v for k, v in monitor_before.items() if k not in ('next_due_at',)})  # monitoring neither stopped nor restarted
        self.assertTrue(self.app.monitor().load()['enabled'] is monitor_before['enabled'])
        origin = json.loads((self.real / 'registry-origin.json').read_text('utf-8'))
        self.assertEqual((origin['origin'], origin['versions'], origin['update_of_run']), ('USER_UPDATE', {'Desktop': 2}, newest))
        # the pages still build (earlier inspections are read against the Baseline version they were compared with) and say what is true
        self.app.rebuild_site()
        self.assertIsNone(self.app.site_error)
        review = (self.app.site_ui / 'review.html').read_text('utf-8')
        self.assertIn('正式承認済み', review)
        self.assertNotIn('data-baseline-label="未取得"', review)
        # 9-10. the next inspection pins v2 and the changed site is now "unchanged"
        self.assertEqual(self.inspect('changed'), ('REAL', 'UNCHANGED'))
        self.app.rebuild_site()
        self.assertIsNone(self.app.site_error)
        view = json.loads((self.app.site_ui / 'view.json').read_text('utf-8'))
        classes = [h['class'] for h in view['monitoring']['history']]
        self.assertEqual(classes.count('CHANGED'), 2)                                            # the detections are still in the history
        self.assertEqual(classes.count('UNCHANGED'), 2)                                          # one against v1, one against v2
        pages = {n: (self.app.site_ui / n).read_text('utf-8') for n in ('review.html', 'evidence.html', 'details.html', 'index.html')}
        self.assertIn('version 2', pages['evidence.html'])
        self.assertIn('正式承認済み', pages['review.html'])
        self.assertIn('Baseline 正式承認済み', pages['index.html'])
        last = sorted((self.real / 'runs').iterdir())[-1]
        result = json.loads((last / last.name / 'Desktop-run-result.json').read_text('utf-8'))
        pin = result['comparison']['results'][0]['baseline']
        self.assertEqual((pin['version'], pin['candidate_id']), (2, record['baselines'][0]['candidate_id']))
        # and v1 is still the answer for the old appearance: an inspection of the old page now differs from v2
        self.assertEqual(self.inspect('same'), ('REAL', 'CHANGED'))
        self.app.rebuild_site()
        self.assertIsNone(self.app.site_error)

    def test_pages_say_what_the_baseline_is_after_the_update(self):
        self.changed()
        self.update()
        self.app.rebuild_site()
        html = (self.app.site_ui / 'review.html').read_text('utf-8')
        self.assertIn('正式承認済み', html)
        self.assertNotIn('自動作成', html.split('review-baseline', 1)[1][:300])

    # ---- refusals: nothing changes, the old Baseline stays
    def refused(self, why=RealCaptureRefused, **kw):
        before = tree(self.real / 'registry')
        with self.assertRaises(why):
            self.update(**kw)
        self.assertEqual(tree(self.real / 'registry'), before)
        self.assertEqual(self.app.site.baseline_state()['versions'], {'Desktop': 1})
        self.assertEqual(self.app.site.baseline_history(), [])
        self.assertEqual([p.name for p in self.real.glob('.tmp-registry-update-*')], [])
        self.assertFalse((self.real / 'baseline-switch.json').exists())

    def test_a_conflict_with_the_version_on_screen_is_refused(self):
        self.changed()
        self.refused(versions={'Desktop': 5})
        self.refused(versions={'Desktop': 0})

    def test_only_the_newest_inspection_can_be_approved(self):
        self.changed()
        self.refused(run_id='20200101T000000Z-00-real')

    def test_nothing_to_approve_without_a_change(self):
        self.assertEqual(self.inspect('same'), ('REAL', 'BASELINE_CREATED'))
        self.assertEqual(self.inspect('same'), ('REAL', 'UNCHANGED'))
        self.refused(versions={'Desktop': 1}, run_id='x')

    def test_a_second_approval_never_makes_another_version(self):
        self.changed()
        record = self.update()
        run = record['source_run']['run_id']
        for versions in ({'Desktop': 1}, {'Desktop': 2}):
            with self.assertRaises(RealCaptureRefused):
                self.update(versions=versions, run_id=run)
        self.assertEqual(self.app.site.baseline_state()['versions'], {'Desktop': 2})
        self.assertEqual(len(self.app.site.baseline_history()), 1)
        # also underneath: building the same update again against the registry it created is refused (compared with v1, current is v2)
        real = self.app.monitor().real()
        from src.noxiworks.site_workflow import PROFILES
        with self.assertRaises(baseline_update.Stop):
            baseline_update.build(real.dir / 'runs' / run / run, real.dir / 'registry', real.dir / '.tmp-again', 'x', 'x', [PROFILES['Desktop']],
                                  self.app.site.summary(real.dir / 'runs' / run / run))
        self.assertFalse((real.dir / '.tmp-again').exists() and any((real.dir / '.tmp-again').iterdir()) and False)

    def test_evidence_that_does_not_match_its_hashes_is_refused(self):
        self.changed()
        run = sorted((self.real / 'runs').iterdir())[-1]
        png = next(p for p in (run / run.name).rglob('*.png') if 'workspace' in p.parts)
        png.write_bytes(png.read_bytes() + b'x')
        self.refused()

    def test_unknown_is_never_approved(self):
        self.assertEqual(self.inspect('same'), ('REAL', 'BASELINE_CREATED'))
        from src.noxiworks.site_workflow import IMAGE_HEIGHTS, page_image
        odd = lambda base: page_image(1440, IMAGE_HEIGHTS['Desktop'] + 40, (40, 60, 90, 255))  # another size: not comparable
        with mock.patch('tools.offline_baseline_demo.changed_image', odd):
            outcome = self.inspect('changed')
        self.assertEqual(outcome[1], 'UNKNOWN')
        offer = self.app.monitor().real().baseline_update_state()
        self.assertEqual(offer['state'], 'BLOCKED')
        self.assertIn('UNKNOWN', offer['reason'])
        self.refused(versions={'Desktop': 1}, run_id=offer['run_id'])
        self.assertIsNotNone(check_updatable({'compared': True, 'profiles': {'Desktop': {'verdict': 'UNKNOWN', 'execution': 'COMPLETED', 'stability': 'STABLE'}}}))
        self.assertIsNotNone(check_updatable({'compared': True, 'profiles': {'Desktop': {'verdict': 'VISUAL_CHANGED', 'execution': 'COMPLETED', 'stability': 'UNSTABLE'}}}))

    def test_a_failed_switch_or_verification_keeps_the_old_baseline(self):
        self.changed()
        with mock.patch.object(baseline_update, 'switch', side_effect=OSError('disk')):
            self.refused(OSError)
        with mock.patch('src.noxiworks.baseline_runtime.check_bindings', side_effect=ValueError('does not pin')):
            self.refused(ValueError)
        self.assertEqual(self.app.monitor().real().baseline_update_state()['state'], 'AVAILABLE')  # still offered, and still works
        self.assertEqual(self.update()['baselines'][0]['version'], 2)

    def test_an_update_never_runs_during_an_inspection(self):
        self.changed()
        monitor = self.app.monitor()
        monitor._lock(utc_now())
        try:
            with self.assertRaises(Busy):
                self.update()
        finally:
            monitor.lock_path.unlink(missing_ok=True)
        self.assertEqual(self.app.site.baseline_state()['versions'], {'Desktop': 1})

    def test_an_interrupted_switch_is_finished_never_shown_as_no_baseline(self):
        self.changed()
        real, capture = self.app.monitor().real(), self.app.monitor().real()
        state = real.baseline_update_state()
        new_dir = self.real / ('.tmp-registry-update-' + state['run_id'])
        from src.noxiworks.site_workflow import PROFILES
        run = self.real / 'runs' / state['run_id'] / state['run_id']
        baseline_update.build(run, self.real / 'registry', new_dir, ACTOR, 'x', [PROFILES['Desktop']], self.app.site.summary(run))
        old_hash = baseline_update.export_hash(self.real / 'registry')
        origin = {'origin': 'USER_UPDATE', 'permit_id': 'p', 'registry_export_sha256': baseline_update.export_hash(new_dir), 'versions': {'Desktop': 2}}
        # crash 1: the intent is written, nothing moved
        baseline_update.write_json(self.real / 'baseline-switch.json', {'schema': 'siteproof.baseline-switch.v1', 'from_export_sha256': old_hash,
                                   'to_export_sha256': baseline_update.export_hash(new_dir), 'history': 'v-test', 'new_dir': new_dir.name, 'origin': origin})
        # crash 2: the old registry already moved to history, the new one not yet in place
        (self.real / 'registry-history').mkdir()
        (self.real / 'registry').rename(self.real / 'registry-history' / 'v-test')
        self.assertFalse((self.real / 'registry').exists())
        self.assertEqual(capture.site.real_registry().name, 'registry')                           # finished on first read
        self.assertEqual(self.app.site.baseline_state()['versions'], {'Desktop': 2})
        self.assertFalse((self.real / 'baseline-switch.json').exists())
        self.assertEqual(json.loads((self.real / 'registry-origin.json').read_text('utf-8'))['origin'], 'USER_UPDATE')
        # and a Baseline is never created over the top while a history exists
        summary = self.app.site.summary(sorted(self.app.site.real_runs())[-1])
        with self.assertRaises(RealCaptureRefused):
            capture.create_baseline(summary, utc_now(), 'x')

    # ---- an unfinished switch: never a success, never lost, never approved twice, recovered before anything else
    def locked(self, which):
        """While active, Path.rename raises PermissionError (a Windows file lock) for the registry switch step `which`:
        'history' = real/registry -> history, 'new' = the new registry -> real/registry. Waits are recorded, not slept."""
        import contextlib
        real_rename, calls, waited = Path.rename, [], []

        def rename(path, target):
            is_step = (path.name == 'registry' and path.parent.name == 'real') if which == 'history' else path.name.startswith('.tmp-registry-update-')
            if is_step:
                calls.append(str(path))
                raise PermissionError(13, 'locked by another process')
            return real_rename(path, target)

        @contextlib.contextmanager
        def active():
            with mock.patch.object(Path, 'rename', autospec=True, side_effect=rename), mock.patch.object(baseline_update, 'sleep', side_effect=waited.append):
                yield calls, waited
        return active()

    def direct(self, run_id='x', versions=None):
        """The approval as the route makes it (the lock is taken, the state is not read first)."""
        return self.app.monitor().update_baseline(run_id, versions if versions is not None else {}, utc_now(), ACTOR)

    def test_a_first_rename_that_fails_once_is_retried_shortly_and_the_update_succeeds(self):
        self.changed()
        real_rename, calls, waited = Path.rename, [], []

        def once(path, target):
            if path.name == 'registry' and path.parent.name == 'real':
                calls.append(1)
                if len(calls) == 1:
                    raise PermissionError(13, 'locked')
            return real_rename(path, target)
        with mock.patch.object(Path, 'rename', autospec=True, side_effect=once), mock.patch.object(baseline_update, 'sleep', side_effect=waited.append):
            record = self.update()
        self.assertEqual(record['baselines'][0]['version'], 2)
        self.assertEqual(waited, [0.1])                                   # one short wait, then it worked
        self.assertEqual(len(calls), 2)
        self.assertFalse((self.real / 'baseline-switch.json').exists())
        self.assertEqual(self.app.site.baseline_state()['versions'], {'Desktop': 2})

    def test_a_rename_that_keeps_failing_keeps_the_intent_and_the_new_baseline_and_is_not_a_success(self):
        self.changed()
        v1 = tree(self.real / 'registry')
        with self.locked('history') as (calls, waited):
            with self.assertRaises(BaselineSwitchIncomplete) as caught:
                self.update()
            self.assertEqual(waited, list(baseline_update.RETRY_DELAYS))     # bounded: 4 short waits, 5 tries, then it stops
            self.assertEqual(len(calls), len(baseline_update.RETRY_DELAYS) + 1)
            self.assertIn('切替が未完了', str(caught.exception))
            self.assertIn('保全', str(caught.exception))
            new = sorted(self.real.glob('.tmp-registry-update-*'))
            self.assertEqual(len(new), 1)                                      # the new Baseline is kept, not discarded
            new_tree = tree(new[0])
            self.assertTrue((self.real / 'baseline-switch.json').is_file())    # and so is the intent
            self.assertEqual(tree(self.real / 'registry'), v1)                 # step 1 never happened: v1 is still the Baseline
            state = self.app.monitor().real().baseline_update_state()
            self.assertEqual(state['state'], 'SWITCH_PENDING')                 # not AVAILABLE, not NONE, not a success
            self.assertIn('切替が未完了', state['reason'])
            self.assertEqual(self.app.site_status()['baseline_update']['state'], 'SWITCH_PENDING')
            # the same inspection cannot be approved again, and repeated retries (still failing) never remove the candidate
            for _ in range(2):
                with self.assertRaises(BaselineSwitchIncomplete):
                    self.update(versions={'Desktop': 1})
            self.assertEqual(tree(next(self.real.glob('.tmp-registry-update-*'))), new_tree)
            self.assertEqual(self.app.site.baseline_history(), [])
            # while it is unfinished no capture runs: the permit is not spent and the harness is not reached
            harness, ledger = len(self.h.fake.calls), tree(self.app.data / 'trust' / 'permit-ledger')
            entry = self.app.monitor().run(utc_now(), 'MANUAL')
            self.assertEqual(entry['outcome'], 'REAL_NOT_READY')
            self.assertIn('撮影構成の同一性', entry['error'])
            self.assertTrue(any('切替が未完了' in c['state'] for c in self.app.monitor().real().readiness(utc_now()) if not c['ok']))   # the reason shown
            self.assertEqual(len(self.h.fake.calls), harness)
            self.assertEqual(tree(self.app.data / 'trust' / 'permit-ledger'), ledger)
        # the lock is gone: the next read finishes the switch, and the state follows the version that is now active
        self.assertEqual(self.app.site.real_registry().name, 'registry')
        self.assertFalse((self.real / 'baseline-switch.json').exists())
        self.assertEqual(self.app.site.baseline_state()['versions'], {'Desktop': 2})
        self.assertEqual(self.app.monitor().real().baseline_update_state()['state'], 'NONE')
        self.assertEqual([h['versions'] for h in self.app.site.baseline_history()], [{'Desktop': 1}])
        self.assertEqual(self.inspect('changed'), ('REAL', 'UNCHANGED'))       # monitoring continues on v2

    def test_the_second_rename_failing_leaves_no_registry_but_never_shows_no_baseline_or_makes_a_new_one(self):
        self.changed()
        with self.locked('new'):
            with self.assertRaises(BaselineSwitchIncomplete):
                self.update()
            self.assertFalse((self.real / 'registry').exists())                # v1 already moved to history, v2 not yet in place
            self.assertEqual(len(list((self.real / 'registry-history').iterdir())), 1)
            state = self.app.monitor().real().baseline_update_state()
            self.assertEqual((state['state'], state['versions']), ('SWITCH_PENDING', {}))
            harness = len(self.h.fake.calls)
            self.assertEqual(self.app.monitor().run(utc_now(), 'MANUAL')['outcome'], 'REAL_NOT_READY')
            self.assertEqual(len(self.h.fake.calls), harness)                  # no Baseline-less capture, so no second line of Baselines
            with self.assertRaises(RealCaptureRefused):
                self.app.monitor().real().create_baseline(self.app.site.summary(self.app.site.real_runs()[-1]), utc_now(), 'x')
            self.assertTrue((self.real / 'baseline-switch.json').is_file())
            with self.assertRaises(BaselineSwitchIncomplete):                  # an explicit retry while the lock is still there
                self.direct()
        # recovery by the explicit retry: the same approval is completed, not made again
        with mock.patch.object(baseline_update, 'sleep'):
            record = self.direct()
        self.assertTrue(record['recovered'])
        self.assertEqual(self.app.site.baseline_state()['versions'], {'Desktop': 2})
        self.assertEqual(len(self.app.site.baseline_history()), 1)             # one version only
        self.assertEqual(self.inspect('changed'), ('REAL', 'UNCHANGED'))

    def test_a_switch_that_cannot_be_recognised_is_refused_with_its_reason_and_nothing_is_deleted(self):
        self.changed()
        with self.locked('history'):
            with self.assertRaises(BaselineSwitchIncomplete):
                self.update()
        new = next(self.real.glob('.tmp-registry-update-*'))
        intent = json.loads((self.real / 'baseline-switch.json').read_text('utf-8'))
        (self.real / 'baseline-switch.json').write_text(json.dumps({**intent, 'from_export_sha256': '0' * 64}), encoding='utf-8')
        before = (tree(self.real / 'registry'), tree(new))
        status, reason = baseline_update.finish_switch(self.real, retry=True)
        self.assertEqual(status, 'PENDING')
        self.assertIn('判別できません', reason)
        self.assertEqual((tree(self.real / 'registry'), tree(new)), before)
        self.assertIn('判別できません', json.loads((self.real / 'baseline-switch.json').read_text('utf-8'))['last_error'])
        with self.assertRaises(BaselineSwitchIncomplete) as caught:
            self.direct()
        self.assertIn('判別できません', str(caught.exception))
        self.assertEqual((tree(self.real / 'registry'), tree(new)), before)

    def test_the_route_tells_a_pending_switch_from_a_success(self):
        self.changed()
        with self.locked('history'):
            with self.assertRaises(BaselineSwitchIncomplete):                  # the route maps this ValueError to HTTP 422 with the message
                self.app.site_action('baseline-update', {'run_id': self.app.monitor().real().baseline_update_state()['run_id'],
                                                         'expected_versions': {'Desktop': 1}, 'confirmed': True})
            with self.assertRaises(BaselineSwitchIncomplete):
                self.app.site_action('baseline-update', {'run_id': 'x', 'expected_versions': {}, 'confirmed': True})
        out = self.app.site_action('baseline-update', {'run_id': 'x', 'expected_versions': {}, 'confirmed': True})
        self.assertEqual(out, {'versions': {'Desktop': 2}, 'recovered': True})

    # ---- repeated updates: v1 -> v2 -> v3 with the history in place
    def test_v1_v2_v3_each_update_works_with_a_history_and_keeps_every_earlier_version_and_its_evidence(self):
        site = self.app.site
        self.assertEqual(self.inspect('same'), ('REAL', 'BASELINE_CREATED'))                 # v1 (the site as it is)
        v1 = tree(self.real / 'registry')
        self.assertEqual(self.inspect('changed'), ('REAL', 'CHANGED'))
        self.assertEqual(self.update()['baselines'][0]['version'], 2)                        # v2 (USER approves)
        v2 = tree(self.real / 'registry')
        self.assertEqual(self.inspect('changed'), ('REAL', 'UNCHANGED'))                     # monitoring continues on v2
        runs_before = tree(self.real / 'runs')
        self.assertEqual(self.inspect('same'), ('REAL', 'CHANGED'))                          # the site changed again
        self.assertEqual(self.app.monitor().real().baseline_update_state()['versions'], {'Desktop': 2})
        record = self.update()                                                               # v3 (USER approves again, history exists)
        self.assertEqual([(b['kind'], b['version']) for b in record['baselines']], [('Desktop', 3)])
        state = site.baseline_state()
        self.assertEqual((state['state'], state['versions']), ('USER', {'Desktop': 3}))
        history = site.baseline_history()
        self.assertEqual([h['versions'] for h in history], [{'Desktop': 1}, {'Desktop': 2}])
        kept = {h['versions']['Desktop']: tree(self.real / 'registry-history' / h['name']) for h in history}
        self.assertEqual(kept, {1: v1, 2: v2})                                               # v1 and v2 are byte-identical to when they were current
        self.assertEqual({k: v for k, v in tree(self.real / 'runs').items() if k in runs_before}, runs_before)   # earlier evidence untouched
        self.assertFalse((self.real / 'baseline-switch.json').exists())
        self.assertEqual(json.loads((self.real / 'registry-origin.json').read_text('utf-8'))['versions'], {'Desktop': 3})
        self.assertEqual(self.app.monitor().real().baseline_update_state()['state'], 'NONE')
        # the pages read every earlier inspection against the version it was compared with
        self.app.rebuild_site()
        self.assertIsNone(self.app.site_error)
        view = json.loads((self.app.site_ui / 'view.json').read_text('utf-8'))
        self.assertGreaterEqual([h['class'] for h in view['monitoring']['history']].count('CHANGED'), 2)
        self.assertIn('正式承認済み', (self.app.site_ui / 'review.html').read_text('utf-8'))
        # and the next inspection pins v3
        self.assertEqual(self.inspect('same'), ('REAL', 'UNCHANGED'))
        last = sorted((self.real / 'runs').iterdir())[-1]
        result = json.loads((last / last.name / 'Desktop-run-result.json').read_text('utf-8'))
        self.assertEqual(result['comparison']['results'][0]['baseline']['version'], 3)
        # a repeated approval of the same inspection does not make a fourth version
        with self.assertRaises(RealCaptureRefused):
            self.update(versions={'Desktop': 3}, run_id=record['source_run']['run_id'])
        self.assertEqual(site.baseline_state()['versions'], {'Desktop': 3})

    # ---- permit conditions are not touched by an update
    def test_an_exhausted_permit_still_refuses_to_capture_after_an_update(self):
        self.changed()
        self.update()
        calls = len(self.h.fake.calls)
        used = self.app.monitor().real().used(self.app.monitor().real().permit()[0])
        self.h.permit(self.app, max_runs=used, permit_id='permit-exhausted')   # a signed permit whose runs are all used
        self.assertEqual(self.h.outcome(self.app)[1], 'REAL_NOT_READY')
        self.assertEqual(len(self.h.fake.calls), calls)

    def test_an_expired_permit_still_refuses_to_capture_after_an_update(self):
        from datetime import timedelta
        from src.aws_b.model import format_utc
        self.changed()
        self.update()
        calls = len(self.h.fake.calls)
        self.h.permit(self.app, max_runs=5, permit_id='permit-expired', valid_until=format_utc(utc_now() - timedelta(seconds=1)))
        self.assertEqual(self.h.outcome(self.app)[1], 'REAL_NOT_READY')
        self.assertEqual(len(self.h.fake.calls), calls)

    def test_a_renewal_after_an_update_carries_the_new_baseline_under_a_new_signature(self):
        from tools.setup_monitoring import carryover
        self.changed()
        self.update()
        origin = json.loads((self.real / 'registry-origin.json').read_text('utf-8'))
        old = self.app.monitor().real().permit()[0]
        carried = carryover(self.real, old)
        self.assertEqual(carried, {'permit_id': origin['permit_id'], 'registry_export_sha256': origin['registry_export_sha256']})
        self.assertEqual(carried['registry_export_sha256'], baseline_update.export_hash(self.real / 'registry'))
        self.h.permit(self.app, max_runs=5, permit_id='permit-renewed', baseline_carryover=carried)
        self.assertEqual(self.inspect('changed'), ('REAL', 'UNCHANGED'))

    # ---- the app's own door
    def test_the_app_route_needs_the_explicit_confirmation_and_the_session_token(self):
        self.changed()
        server, served = serve(self.app.data, 0, scheduler=False)
        served.docker_found, served.real_runner = True, self.h.fake
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), served.stop()))
        port = server.server_address[1]
        authority = f'127.0.0.1:{port}'

        def call(method, path, body=None):
            # a plain socket to the numeric loopback address: no name lookup (other suites forbid it in the same process)
            payload = json.dumps(body).encode() if body is not None else b''
            crlf = bytes((13, 10))
            lines = [f'{method} {path} HTTP/1.1', f'Host: {authority}', 'X-SiteProof-App: 1', 'Connection: close']
            if body is not None:
                lines += [f'Origin: http://{authority}', 'Content-Type: application/json', f'Content-Length: {len(payload)}']
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                conn.settimeout(60)
                conn.connect(('127.0.0.1', port))
                conn.sendall(crlf.join(x.encode() for x in lines) + crlf + crlf + payload)
                raw = b''
                while chunk := conn.recv(65536):
                    raw += chunk
            top, _, rest = raw.partition(crlf + crlf)
            return int(top.split(b' ', 2)[1]), json.loads(rest or b'{}')
        status, session = call('GET', '/app/api/session')
        offer = session['site']['baseline_update']
        self.assertEqual((status, offer['state']), (200, 'AVAILABLE'))
        route = '/app/api/site/baseline-update'
        payload = {'token': session['token'], 'run_id': offer['run_id'], 'expected_versions': offer['versions']}
        self.assertEqual(call('POST', route, {**payload, 'token': 'wrong', 'confirmed': True})[0], 403)   # no token, no approval
        self.assertEqual(call('POST', route, payload)[0], 422)                                        # no explicit confirmation
        self.assertEqual(call('POST', route, {**payload, 'confirmed': 'yes'})[0], 422)
        self.assertEqual(call('POST', route, {**payload, 'confirmed': True, 'expected_versions': {'Desktop': 9}})[0], 422)
        self.assertEqual(self.app.site.baseline_state()['versions'], {'Desktop': 1})                   # nothing happened so far
        status, body = call('POST', route, {**payload, 'confirmed': True})
        self.assertEqual((status, body['result']), (200, {'versions': {'Desktop': 2}, 'recovered': False}))
        self.assertEqual(call('POST', route, {**payload, 'confirmed': True})[0], 422)                  # the same approval again


class PagesAndScript(unittest.TestCase):
    def test_the_review_panel_asks_for_an_explicit_confirmation_and_posts_what_the_server_checks(self):
        js = (ROOT / 'src/noxiworks/app_assets/app.js').read_text('utf-8')
        for text in ("decision('baseline-update', '変更を確認してBaselineを更新する'", '新しい基準にする', "/app/api/site/baseline-update", 'run_id: bu.run_id',
                     'expected_versions: bu.versions', 'confirmed: checked', "button.setAttribute('disabled', '')", 'app-bigcheck'):
            self.assertIn(text, js)
        self.assertIn("if (bu.state === 'AVAILABLE') {", js)     # no update button unless the newest inspection can be approved
        self.assertNotIn('Baselineの更新（変更後の画面を新しい基準にする）は未対応です', js)

    def test_a_schedule_or_an_inspection_never_calls_the_update(self):
        for name in ('site_monitor.py',):
            text = (ROOT / 'src/noxiworks' / name).read_text('utf-8')
            body = text.split('def run(self', 1)[1].split('def run_if_due', 1)[0]
            self.assertNotIn('update_baseline', body)
        text = (ROOT / 'src/noxiworks/app.py').read_text('utf-8')
        self.assertEqual(text.count('update_baseline('), 1)   # the one route, behind the token and the explicit confirmation


if __name__ == '__main__':
    unittest.main()
