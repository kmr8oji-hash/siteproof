"""Formal Baseline registry -> next capture's runtime -> comparison -> REVIEW. Offline only: synthetic producer, tiny images,
temporary workspaces. No real site, browser, Docker, AWS or network; the real registry under .local is never touched."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from src.baseline.model import BaselineStatus
from src.comparison import preview
from src.noxiworks import baseline_registry
from src.noxiworks.baseline_runtime import (POLICY, BaselineConnectionRefused, check_bindings, comparison_export, open_runtime,
                                            prepare_job, read_registry, stage, tree)
from src.noxiworks.capture import create_runtime
from src.noxiworks.home import build
from src.noxiworks.local_capture import LocalCaptureRefused, attach
from src.noxiworks.product import capture_plan, empty_snapshot, settings
from src.noxiworks.review import page_view
from src.runtime.stability import policy
from src.worker.capture import capture, MemoryChannel
from tests.comparison.support import synthetic_browser_audit
from tools.offline_baseline_demo import RESOURCES, DemoLease, StoredImageDriver, stability_record

PAGE = next(p for p in settings()['pages'] if p['target_id'] == 'ttn-home')
ORIGIN = PAGE['url'].rstrip('/')
PROFILES = [{'kind': 'Desktop', 'width': 24, 'height': 16, 'full_page': True}, {'kind': 'Mobile', 'width': 12, 'height': 20, 'full_page': True}]
RULES = policy(capture_plan()['pages']['ttn-home']['stability'])
NOW = datetime.now(timezone.utc).replace(microsecond=0)


def image(kind, color):
    p = next(p for p in PROFILES if p['kind'] == kind)
    return preview.png(p['width'], p['height'], bytes(color) * (p['width'] * p['height']))


ORIGINAL = {'Desktop': image('Desktop', (238, 238, 238, 255)), 'Mobile': image('Mobile', (230, 240, 255, 255))}
EDITED = {'Desktop': image('Desktop', (211, 47, 47, 255)), 'Mobile': image('Mobile', (211, 47, 47, 255))}


def run_capture(runtime, kind, png, *, unstable=None, source='OWNER_SITE_UNATTESTED'):
    """One synthetic capture of one profile through RuntimeService.run -> (batch, job_id, saved comparison result)."""
    batch, job_id, _ = prepare_job(runtime, 'ttn-home', kind, source)
    lease = DemoLease(runtime.repo.get_job(job_id).snapshot.intent.target_url)

    def factory(request, remaining):
        out = capture(request, StoredImageDriver(png, lease.ledger), lease, RESOURCES)
        runtime.record_browser_audit(job_id, synthetic_browser_audit('ok'))
        runtime.record_capture_stability(job_id, stability_record(png, unstable, RULES))
        return MemoryChannel(out.wire), out.reason, out.cleanup_confirmed

    runtime.run(batch, factory, lease, RESOURCES)
    rows = runtime.comparison.store.rows('results', job_id=job_id, limit=1)
    return batch, job_id, runtime.comparison.result(rows[0]['result_id'])


def make_registry(root):
    """A registry shaped like tools/register_baseline.py output, approved through the same SQLiteBaselineStore.decide."""
    config = {'pages': [{'target_id': 'ttn-home', 'label': 'トップページ', 'url': PAGE['url'], 'site_name': 'Tokyo Trouble Navi', 'profiles': PROFILES}]}
    runtime = create_runtime(root / 'source-ws', config)
    store = runtime.comparison.baselines
    baselines = []
    for kind in ('Desktop', 'Mobile'):
        _, job_id, _ = run_capture(runtime, kind, ORIGINAL[kind])
        cid = 'capture-' + job_id
        record = store.get(cid)
        store.decide(cid, decision=BaselineStatus.APPROVED, actor='offline-test-operator', expected_revision=0,
                     reviewed_digest=record.registered_digest, expected_current_version=0)
        c = record.candidate
        baselines.append({'kind': kind, 'page_id': 'ttn-home', 'candidate_id': cid, 'job_id': job_id, 'version': 1, 'status': 'APPROVED',
                          'revision': 1, 'candidate_digest': record.registered_digest, 'png_sha256': c.artifact_sha256,
                          'artifact_ref': c.artifact_ref, 'profile_fingerprint': c.profile_fingerprint,
                          'viewport': [next(p for p in PROFILES if p['kind'] == kind)[k] for k in ('width', 'height')], 'full_page': True,
                          'captured_at': NOW.isoformat().replace('+00:00', 'Z'), 'stability': {'value': 'STABLE'}, 'quality': 'UNKNOWN',
                          'profile_reason': 'PROFILE_UNATTESTED', 'source': 'OWNER_SITE_UNATTESTED',
                          'approved_at': NOW.isoformat().replace('+00:00', 'Z'), 'actor': 'offline-test-operator'})
    registry = root / 'registry'
    shutil.copytree(root / 'source-ws', registry / 'workspace')
    record = {'schema': 'siteproof.baseline-registry.v1', 'registry_id': 'registry', 'page_id': 'ttn-home', 'url': PAGE['url'],
              'decision': 'APPROVED', 'approved_at': baselines[0]['approved_at'], 'actor': 'offline-test-operator', 'instruction': 'offline test',
              'mechanism': 'SQLiteBaselineStore.decide', 'source_run': {'run_id': 'synthetic-source', 'task': 'TEST', 'export_sha256_json': 'x'},
              'distinct_from': [], 'baselines': baselines}
    (registry / 'APPROVAL-RECORD.json').write_text(json.dumps(record, ensure_ascii=False), encoding='utf-8')
    (registry / 'export-sha256.json').write_text(json.dumps(tree(registry)), encoding='utf-8')
    return registry


def write_run(root, runtime, batches, *, mutate=None):
    """A run directory in the S3-1T export shape, from the runtime's own state (as the trusted worker returns it) + its diff PNGs."""
    files, windows = {}, {}
    for n, (kind, (batch, job_id)) in enumerate(batches.items()):
        files[f'{kind}-run-result.json'] = json.dumps({'type': 'result', 'state': runtime.state(batch), 'comparison': runtime.comparison.state(),
                                                       'baselines': runtime.workspace.state()['baselines'],
                                                       'capture_info': {job_id: {'repeat_identical': True}}}).encode()
        files[f'{kind}-head.json'] = json.dumps({'http_status': 'HTTP/1.1 200 OK', 'tls': {'result': 'OK'}, 'http_headers': {}, 'redirect': None}).encode()
        files[f'{kind}-capture-meta.json'] = json.dumps([{'sandbox': {'browser_version': 'synthetic'}}]).encode()
        files.update(comparison_export(runtime, job_id))
        at = NOW - timedelta(hours=1, seconds=-10 * n)
        windows['CAPTURE-' + kind] = {'opened_at': at.isoformat().replace('+00:00', 'Z'), 'closed_at': (at + timedelta(seconds=5)).isoformat().replace('+00:00', 'Z')}
    files['validation-result.json'] = json.dumps({'passed': True, 'baseline_approved': False, 'baseline_compared': True, 'aws_touched': False,
                                                  'site_modified': False, 'monitoring_started': False, 'task': 'TEST-CONNECTION', 'windows': windows}).encode()
    files['workspace-created.json'] = json.dumps({'origin': ORIGIN, 'url': PAGE['url']}).encode()
    if mutate:
        mutate(files)
    for rel, data in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)
    shutil.copytree(runtime.workspace.storage_root, root / 'workspace')
    (root / 'export-sha256.json').write_text(json.dumps(tree(root)), encoding='utf-8')
    return root


class Connection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='siteproof-connection-')
        cls.root = Path(cls.tmp.name)
        cls.registry = make_registry(cls.root)
        cls.record = read_registry(cls.registry)
        cls.registry_tree = tree(cls.registry)
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def staged(self):
        type(self).n += 1
        ws = self.root / f'run-ws-{self.n}'
        stage(self.registry, ws)
        return open_runtime(ws)

    def tearDown(self):
        self.assertEqual(tree(self.registry), self.registry_tree)  # the registry is only ever read

    def test_same_policy_as_every_live_run(self):
        fresh = create_runtime(self.root / f'policy-{id(self)}', {'pages': [{'target_id': 'ttn-home', 'label': 'x', 'url': PAGE['url'], 'profiles': PROFILES}]})
        self.assertEqual(fresh.comparison.policy.body(), POLICY.body())
        self.assertIs(fresh.comparison.allow_unattested_preview, True)

    def test_a_fresh_live_workspace_has_no_baseline(self):
        # The gap this connection closes: create_runtime's new workspace binds the next job with no Baseline at all.
        fresh = create_runtime(self.root / f'fresh-{id(self)}', {'pages': [{'target_id': 'ttn-home', 'label': 'x', 'url': PAGE['url'], 'profiles': PROFILES}]})
        _, _, plan = prepare_job(fresh, 'ttn-home', 'Desktop')
        self.assertIsNone(plan['baseline'])

    def test_each_profile_pins_its_own_approved_baseline(self):
        runtime = self.staged()
        pins = check_bindings(runtime, self.record, PROFILES)
        by_kind = {b['kind']: b for b in self.record['baselines']}
        for kind in ('Desktop', 'Mobile'):
            self.assertEqual(pins[kind]['candidate_id'], by_kind[kind]['candidate_id'])
            _, _, plan = prepare_job(runtime, 'ttn-home', kind)
            self.assertEqual(plan['baseline'], pins[kind])
        self.assertNotEqual(pins['Desktop']['candidate_id'], pins['Mobile']['candidate_id'])

    def test_new_captures_compare_with_the_formal_baseline(self):
        runtime = self.staged()
        jobs = {b['kind']: b['job_id'] for b in self.record['baselines']}
        cases = (('Desktop', ORIGINAL['Desktop'], None, 'OWNER_SITE_UNATTESTED', 'NO_VISUAL_CHANGE_DETECTED', None),
                 ('Mobile', EDITED['Mobile'], None, 'OWNER_SITE_UNATTESTED', 'VISUAL_CHANGED', None),
                 ('Desktop', ORIGINAL['Desktop'], EDITED['Desktop'], 'OWNER_SITE_UNATTESTED', 'UNKNOWN', 'CAPTURE_UNSTABLE'),
                 # Not loosened: a capture of another source category is never compared as if it were the owner site.
                 ('Mobile', ORIGINAL['Mobile'], None, 'OFFLINE_FIXTURE_UNATTESTED', 'UNKNOWN', 'BASELINE_SOURCE_MISMATCH'))
        for kind, png, unstable, source, verdict, reason in cases:
            with self.subTest(kind=kind, verdict=verdict, reason=reason):
                _, _, result = run_capture(runtime, kind, png, unstable=unstable, source=source)
                self.assertEqual(result['baseline_job_id'], jobs[kind])
                self.assertEqual(result['operational']['verdict'], verdict)
                self.assertEqual(result['quality'], 'UNKNOWN')  # strict quality is never upgraded by the operational verdict
                self.assertIn('PROFILE_UNATTESTED', result['reasons'])
                if reason:
                    self.assertIn(reason, result['operational']['reasons'])

    def test_refusals(self):
        with self.subTest('tampered registry'):
            broken = self.root / 'broken'
            shutil.copytree(self.registry, broken)
            (broken / 'APPROVAL-RECORD.json').write_text((broken / 'APPROVAL-RECORD.json').read_text('utf-8') + ' ', encoding='utf-8')
            with self.assertRaises(BaselineConnectionRefused):
                read_registry(broken)
        with self.subTest('existing run workspace'):
            with self.assertRaises(BaselineConnectionRefused):
                stage(self.registry, self.registry / 'workspace')
        runtime = self.staged()
        with self.subTest('changed capture plan'):
            with self.assertRaises(BaselineConnectionRefused):
                check_bindings(runtime, self.record, [{**PROFILES[0], 'width': 25}, PROFILES[1]])
        with self.subTest('profiles swapped in the record'):
            d, m = self.record['baselines']
            swapped = {**self.record, 'baselines': [{**d, 'kind': 'Mobile'}, {**m, 'kind': 'Desktop'}]}
            with self.assertRaises(BaselineConnectionRefused):
                check_bindings(runtime, swapped)

    def test_review_shows_the_comparison_with_the_formal_baseline(self):
        runtime = self.staged()
        batches = {}
        for kind, png in (('Desktop', ORIGINAL['Desktop']), ('Mobile', EDITED['Mobile'])):
            batch, job_id, _ = run_capture(runtime, kind, png)
            batches[kind] = (batch, job_id)
        run = write_run(self.root / f'run-{self.n}', runtime, batches)
        registry = baseline_registry.read(self.registry)
        with self.assertRaises(LocalCaptureRefused):  # a compared run is never shown without the registry it was compared with
            attach(empty_snapshot(), [run])
        snapshot, assets = attach(empty_snapshot(), [run], registry)
        change = snapshot['changes']['ttn-home']
        self.assertIs(change['baseline_approved'], True)
        self.assertGreater(change['metrics']['changed_pixels'], 0)  # the changed profile speaks for the page
        self.assertEqual(set(assets['ttn-home']), {'current', 'mobile', 'baseline', 'mobile_baseline', 'diff', 'mobile_diff'})
        self.assertEqual(assets['ttn-home']['mobile_baseline'], registry['pngs']['Mobile'])
        staging = self.root / f'assets-{self.n}'
        for role, raw in assets['ttn-home'].items():
            (staging / 'ttn-home').mkdir(parents=True, exist_ok=True)
            (staging / 'ttn-home' / (role + '.png')).write_bytes(raw)
        view = build(self.root / f'ui-{self.n}', snapshot, now=NOW, assets=staging)
        page = next(p for p in view['pages'] if p['target_id'] == 'ttn-home')
        record = page_view(page, view['source'])
        self.assertEqual((record['kind'], record['baseline'], record['compare_label']), ('changed', 'approved', '実施済み'))
        self.assertEqual({c['key']: c['change'] for c in record['cards']}, {'desktop': 'unchanged', 'mobile': 'changed'})
        self.assertEqual(record['images']['mobile_baseline'], 'evidence/ttn-home/mobile_baseline.png')
        with self.subTest('pin of another Baseline version is refused'):
            def other_version(files):
                body = json.loads(files['Mobile-run-result.json'])
                for r in body['comparison']['results']:
                    if r.get('baseline'):
                        r['baseline']['version'] = 2
                files['Mobile-run-result.json'] = json.dumps(body).encode()
            with self.assertRaises(LocalCaptureRefused):
                attach(empty_snapshot(), [write_run(self.root / f'run-bad-{self.n}', runtime, batches, mutate=other_version)], registry)


if __name__ == '__main__':
    unittest.main()
