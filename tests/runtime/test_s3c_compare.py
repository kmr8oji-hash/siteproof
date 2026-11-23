"""Compare mode of the live harness (S3-1C), offline: Worker staging/binding/export, host checks, identity gate, REVIEW. No network,
Docker or AWS. The formal registry under .local is used only through read-only copies; tests needing it skip when it is absent."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from src.noxiworks.baseline_runtime import (BaselineConnectionRefused, candidates_match, comparison_matches, created_matches,
                                            expected_baseline, read_registry)
from src.noxiworks.local_capture import LocalCaptureRefused, attach
from src.noxiworks.product import empty_snapshot
from tests.runtime import s3t_worker, validate_s3t
from tools.offline_capture_compare import CASES, StandIn, integrate, read_only_copy, worker_container

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / '.local' / 'baseline-ttn-home-01'
SP_D52 = ROOT / '.local' / 's3t-exception' / 'SP-D52-IDENTITY.json'
REAL_RUN = ROOT / '.local' / 's3-run-02'
needs_registry = unittest.skipUnless((REGISTRY / 'APPROVAL-RECORD.json').is_file(), 'formal Baseline registry not present')


def expect_for(registry):
    return {**expected_baseline(read_registry(registry)),
            'registry_export_sha256': hashlib.sha256((Path(registry) / 'export-sha256.json').read_bytes()).hexdigest()}


@needs_registry
class Integration(unittest.TestCase):
    """The three cases end to end through the compare-mode Worker, the host checks and REVIEW (one shared run, ~30 s)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='siteproof-s3c-')
        cls.before = {p.relative_to(REGISTRY).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in REGISTRY.rglob('*') if p.is_file()}
        cls.report = integrate(REGISTRY, Path(cls.tmp.name) / 'out')

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_three_cases_compare_with_the_formal_baseline_of_each_profile(self):
        self.assertTrue(self.report['passed'], self.report['failures'])
        pins = self.report['expect']['pins']
        for case, verdict in CASES.items():
            for kind, p in self.report['cases'][case]['profiles'].items():
                with self.subTest(case=case, kind=kind):
                    self.assertEqual(p['verdict'], verdict)
                    self.assertEqual(p['baseline'], pins[kind])  # Desktop -> Desktop Baseline, Mobile -> Mobile Baseline
                    self.assertEqual(p['quality'], 'UNKNOWN')   # never promoted
                    self.assertIn('PROFILE_UNATTESTED', p['strict_reasons'])
        self.assertIn('CAPTURE_UNSTABLE', self.report['cases']['unstable']['profiles']['Desktop']['operational_reasons'])
        self.assertEqual(self.report['cases']['changed']['profiles']['Desktop']['changed_pixels'], 1440 * 80)

    def test_every_host_check_passes_and_the_registry_is_untouched(self):
        for case in CASES:
            self.assertTrue(all(self.report['cases'][case]['checks'].values()), self.report['cases'][case]['checks'])
            self.assertTrue(self.report['cases'][case]['baseline_compared'])
        self.assertTrue(self.report['registry_copy_unchanged'] and self.report['registry_unchanged'])
        after = {p.relative_to(REGISTRY).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in REGISTRY.rglob('*') if p.is_file()}
        self.assertEqual(after, self.before)

    def test_review_shows_comparisons_as_demo_data_only(self):
        expected = {'unchanged': ('UNCHANGED', {'baseline', 'diff', 'mobile_baseline', 'mobile_diff'}),
                    'changed': ('CHANGED', {'baseline', 'diff', 'mobile_baseline', 'mobile_diff'}),
                    'unstable': ('UNKNOWN', {'baseline', 'mobile_baseline'})}
        for case, (state, compare_roles) in expected.items():
            review = self.report['cases'][case]['review']
            with self.subTest(case=case):
                self.assertEqual(review['source'], 'FIXTURE')  # synthetic: shown with the demo labelling, never as LOCAL_CAPTURE
                self.assertEqual(review['change_state'], state)
                self.assertIs(review['baseline_approved'], True)
                self.assertTrue(compare_roles <= set(review['assets']))
        unstable = set(self.report['cases']['unstable']['review']['assets'])
        self.assertTrue({'diff', 'mobile_diff'} <= unstable)  # exported and digest-checked; REVIEW only shows it when the result is decided

    @unittest.skipUnless((REAL_RUN / 'export-sha256.json').is_file(), 'real S3-1 run not present')
    def test_a_synthetic_run_is_never_shown_with_real_captures(self):
        from src.noxiworks import baseline_registry
        run = Path(self.tmp.name) / 'out' / 'changed' / 'run'
        registry = baseline_registry.read(Path(self.tmp.name) / 'out' / 'registry-read-only-copy')
        with self.assertRaises(LocalCaptureRefused):
            attach(empty_snapshot(), [REAL_RUN, run], registry)


@needs_registry
class FailClosed(unittest.TestCase):
    def test_a_tampered_registry_gives_no_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / 'registry'
            shutil.copytree(REGISTRY, copy)
            record = copy / 'APPROVAL-RECORD.json'
            record.write_text(record.read_text('utf-8').replace('"version": 1', '"version": 2', 1), encoding='utf-8')
            evidence = Path(tmp) / 'evidence'
            with worker_container(StandIn('unchanged'), copy, evidence) as s3:
                with self.assertRaises(BaselineConnectionRefused):
                    s3.create()
            self.assertFalse((evidence / 'ws').exists())  # nothing to capture into, no empty-workspace fallback

    def test_without_the_registry_the_worker_keeps_the_original_new_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / 'evidence'
            with worker_container(StandIn('unchanged'), REGISTRY, evidence) as s3:
                os.environ.pop(s3t_worker.REGISTRY_ENV)
                created = s3.create()
                self.assertIsNone(created['baseline'])
                prep = s3.prepare('Desktop')
                self.assertIsNone(prep['baseline'])  # SP-D52 behaviour: candidates only, nothing compared


@needs_registry
class HostChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expect = expect_for(REGISTRY)

    def test_created_must_report_exactly_the_pinned_registry(self):
        good = {k: self.expect[k] for k in ('registry_export_sha256', 'page_id', 'pins', 'baseline_jobs', 'baseline_png_sha256')}
        self.assertTrue(created_matches(good, self.expect))
        self.assertFalse(created_matches(None, self.expect))
        self.assertFalse(created_matches({**good, 'registry_export_sha256': '0' * 64}, self.expect))
        self.assertFalse(created_matches({**good, 'pins': {'Desktop': good['pins']['Mobile'], 'Mobile': good['pins']['Desktop']}}, self.expect))

    def test_comparison_must_use_this_profiles_baseline_and_never_promote(self):
        comp = {'baseline': self.expect['pins']['Desktop'], 'baseline_job_id': self.expect['baseline_jobs']['Desktop'],
                'baseline_sha256': self.expect['baseline_png_sha256']['Desktop'], 'quality': 'UNKNOWN', 'operational': {'verdict': 'UNKNOWN'}}
        self.assertTrue(comparison_matches(comp, 'Desktop', self.expect))
        self.assertFalse(comparison_matches(comp, 'Mobile', self.expect))
        self.assertFalse(comparison_matches({**comp, 'quality': 'PASS'}, 'Desktop', self.expect))
        self.assertFalse(comparison_matches({**comp, 'baseline': None}, 'Desktop', self.expect))

    def test_only_the_registry_baselines_may_be_approved(self):
        registry = [{'candidate_id': p['candidate_id'], 'approval_state': 'APPROVED'} for p in self.expect['pins'].values()]
        self.assertTrue(candidates_match(registry + [{'candidate_id': 'capture-new', 'approval_state': 'PENDING'}], 'new', self.expect))
        self.assertFalse(candidates_match(registry + [{'candidate_id': 'capture-new', 'approval_state': 'APPROVED'}], 'new', self.expect))
        self.assertFalse(candidates_match(registry[:1] + [{'candidate_id': 'capture-new', 'approval_state': 'PENDING'}], 'new', self.expect))


class IdentityGate(unittest.TestCase):
    def run_main(self, expect, *extra):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'expect.json'
            path.write_text(json.dumps(expect), encoding='utf-8')
            evidence = Path(tmp) / 'evidence'
            with mock.patch.object(sys, 'argv', ['validate_s3t', '--evidence', str(evidence), '--expect', str(path), *extra]), \
                    mock.patch('sys.stderr'), self.assertRaises(SystemExit) as stop:
                validate_s3t.main()
            self.assertEqual(stop.exception.code, 2)
            self.assertFalse(evidence.exists())  # refused before anything is created

    def test_registry_argument_is_required_exactly_when_the_identity_pins_one(self):
        self.run_main({'files': {}, 'baseline': {'pins': {}}})
        self.run_main({'files': {}}, '--baseline-registry', 'x')

    def test_the_new_dependency_is_pinned(self):
        self.assertIn('src/noxiworks/baseline_runtime.py', validate_s3t.IDENTITY_FILES)

    @unittest.skipUnless(SP_D52.is_file(), 'SP-D52 identity not present')
    def test_the_sp_d52_identity_cannot_authorise_this_configuration(self):
        files_now = {rel: hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() for rel in validate_s3t.IDENTITY_FILES}
        old = json.loads(SP_D52.read_text('utf-8'))
        self.assertNotEqual(files_now, old['files'])
        self.assertNotIn('baseline', old)


if __name__ == '__main__':
    unittest.main()
