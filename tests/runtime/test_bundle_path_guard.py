"""A placement that Docker Desktop on Windows cannot mount is refused BEFORE a run is counted against a permit (offline: path arithmetic only).

Regression for the 2026-11-22 real-capture attempt: the Browser bundle's longest file path was 282 characters and the container got
EIO on /opt/siteproof after the permit run had already been counted.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.runtime.browser_bundle import BROWSER_ENTRIES, MAX_STAGED_PATH, import_closure, staged_path_problem

ROOT = Path(__file__).resolve().parents[2]
RUN = '00000000T000000Z-00-real'
NOW = datetime(2026, 11, 22, 6, 0, 0, tzinfo=timezone.utc)


class PathGuard(unittest.TestCase):
    def test_a_short_placement_is_accepted_and_the_failed_one_is_refused(self):
        short = Path('C:/spe/d/sites/site-900ec136/real/runs/.tmp-' + RUN + '/' + RUN)
        self.assertIsNone(staged_path_problem(ROOT, short, windows=True))
        deep = Path('C:/' + 'x' * 140 + '/sites/site-900ec136/real/runs/.tmp-' + RUN + '/' + RUN)  # about the length of the failed run (282)
        message = staged_path_problem(ROOT, deep, windows=True)
        self.assertIn('短いパス', message)
        self.assertIn('消費していません', message)
        self.assertIn(str(MAX_STAGED_PATH), message)

    def test_other_systems_have_no_such_limit(self):
        self.assertIsNone(staged_path_problem(ROOT, Path('/' + 'x' * 300 + '/' + RUN), windows=False))

    def test_the_limit_is_exact_for_the_longest_file(self):
        base = Path('C:/spe/' + RUN)
        longest = max(len(str(base / 'browser-bundle' / 'opt-siteproof' / rel)) for rel in import_closure(ROOT, BROWSER_ENTRIES))
        self.assertIsNone(staged_path_problem(ROOT, base, limit=longest, windows=True))
        self.assertIsNotNone(staged_path_problem(ROOT, base, limit=longest - 1, windows=True))

    def test_the_harness_refuses_before_creating_anything_or_touching_a_permit(self):
        with tempfile.TemporaryDirectory() as tmp:
            expect = Path(tmp) / 'expect.json'
            expect.write_text(json.dumps({'files': {}}), encoding='utf-8')
            evidence = Path(tmp) / ('d' * 150) / ('e' * 60) / RUN  # not created: the harness must exit before mkdir
            done = subprocess.run([sys.executable, '-B', '-m', 'tests.runtime.validate_s3t', '--evidence', str(evidence), '--expect', str(expect)],
                                  cwd=ROOT, capture_output=True, text=True, encoding='utf-8', timeout=120)
            if sys.platform == 'win32':
                self.assertEqual(done.returncode, 2, done.stdout[-400:] + done.stderr[-400:])
                self.assertIn('EVIDENCE_PATH_TOO_LONG', done.stdout)
                self.assertFalse((Path(tmp) / ('d' * 150)).exists())

    def test_the_apps_readiness_shows_the_reason_and_is_not_ready(self):
        from src.noxiworks.real_capture import RealCapture
        from src.noxiworks.site_workflow import Site
        with tempfile.TemporaryDirectory() as tmp:
            deep = Site.register(Path(tmp) / ('x' * 90) / 'sites', 'MySite', 'https://www.example.com/', ['Desktop'], True, NOW)
            near = Site.register(Path(tmp) / 'sites', 'MySite', 'https://www.example.com/', ['Desktop'], True, NOW)
            for site, expected in ((deep, sys.platform != 'win32'), (near, True)):
                checks = {c['key']: c for c in RealCapture(site, docker_found=True).readiness(NOW)}
                self.assertEqual(checks['harness']['ok'], expected, checks['harness']['state'])
            if sys.platform == 'win32':
                self.assertIn('短いパス', {c['key']: c for c in RealCapture(deep, docker_found=True).readiness(NOW)}['harness']['state'])
            self.assertFalse((deep.root / 'real' / 'runs').exists() and any((deep.root / 'real' / 'runs').iterdir()))


if __name__ == '__main__':
    unittest.main()
