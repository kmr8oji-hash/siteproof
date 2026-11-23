"""S3-1-UNBLOCK: the Browser code bundle is minimal, self-contained, secret-free and tamper-evident. Offline (stdlib only)."""
import json
from pathlib import Path
import tempfile
import unittest

from tests.runtime.browser_bundle import BROWSER_ENTRIES, BundleError, import_closure, stage_browser_bundle, verify_bundle

ROOT = Path(__file__).resolve().parents[2]


class BrowserBundleTests(unittest.TestCase):
    def test_closure_contains_what_the_browser_imports_including_relative_imports(self):
        closure = import_closure(ROOT)
        for needed in BROWSER_ENTRIES + ('src/runtime/browser.py', 'src/worker/capture.py', 'src/isolation/transport.py', 'src/isolation/connect_dns.py',
                                         'src/isolation/quota_session.py', 'src/core/model.py', 'src/runtime/request_audit.py', 'src/isolation/egress_grant.py',
                                         'tests/runtime/negative_guard.py', 'tests/__init__.py', 'src/isolation/__init__.py'):
            self.assertIn(needed, closure, needed)

    def test_closure_excludes_everything_a_real_site_driven_browser_must_not_read(self):
        closure = set(import_closure(ROOT))
        forbidden = ('src/noxiworks', 'src/storage', 'src/bff', 'src/aws_b', 'src/aws_c', 'src/baseline', 'src/bridge', 'src/offline_view', 'src/profile_context',
                     'tests/runtime/validate', 'tests/runtime/s2a_worker', 'tests/runtime/s3_worker', 'tests/runtime/s3p_worker', 'tests/runtime/netpolicy',
                     'tests/runtime/egress_broker', 'tests/runtime/egress_reaper', 'src/comparison/service.py', 'src/runtime/service.py', 'src/runtime/docker_launcher.py')
        for path in closure:
            self.assertFalse(path.startswith(forbidden), path)
        self.assertTrue(all(p.endswith('.py') for p in closure))
        self.assertLess(len(closure), 45)  # was: 99 src + 51 tests/runtime files mounted

    def test_staged_bundle_is_exactly_the_closure_with_a_matching_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree, manifest = stage_browser_bundle(ROOT, Path(tmp) / 'bundle')
            staged = sorted(p.relative_to(tree).as_posix() for p in tree.rglob('*') if p.is_file())
            self.assertEqual(staged, sorted(import_closure(ROOT)))
            self.assertEqual(manifest['file_count'], len(staged))
            self.assertTrue(all(v['why'] for v in manifest['files'].values()))
            self.assertTrue(verify_bundle(Path(tmp) / 'bundle'))

    def test_extra_file_symlink_or_altered_content_is_refused_by_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'bundle'
            tree, _ = stage_browser_bundle(ROOT, dest)
            (tree / 'src' / 'extra.py').write_text('x = 1\n')
            with self.assertRaises(BundleError):
                verify_bundle(dest)
            (tree / 'src' / 'extra.py').unlink()
            (tree / 'src' / 'targets.json').write_text('{}')
            with self.assertRaises(BundleError):
                verify_bundle(dest)
            (tree / 'src' / 'targets.json').unlink()
            target = tree / 'src' / 'runtime' / 'browser.py'
            target.write_text(target.read_text(encoding='utf-8') + '\n# tampered\n', encoding='utf-8')
            with self.assertRaises(BundleError):
                verify_bundle(dest)

    def test_secret_like_content_is_refused_before_anything_is_staged(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / 'repo'
            (fake / 'src').mkdir(parents=True)
            (fake / 'tests' / 'runtime').mkdir(parents=True)
            for name in ('src/__init__.py', 'tests/__init__.py', 'tests/runtime/__init__.py'):
                (fake / name).write_text('')
            for entry in BROWSER_ENTRIES:
                (fake / entry).write_text('')
            (fake / BROWSER_ENTRIES[0]).write_text("KEY = 'AKIA" + 'A' * 16 + "'\n")
            with self.assertRaises(BundleError):
                stage_browser_bundle(fake, Path(tmp) / 'bundle')

    def test_a_symlinked_source_file_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / 'repo'
            (fake / 'tests' / 'runtime').mkdir(parents=True)
            for name in ('tests/__init__.py', 'tests/runtime/__init__.py'):
                (fake / name).write_text('')
            real = Path(tmp) / 'outside.py'
            real.write_text('')
            for entry in BROWSER_ENTRIES:
                (fake / entry).write_text('')
            (fake / BROWSER_ENTRIES[0]).unlink()
            try:
                (fake / BROWSER_ENTRIES[0]).symlink_to(real)
            except OSError:
                self.skipTest('symlinks unavailable on this host')
            with self.assertRaises(BundleError):
                stage_browser_bundle(fake, Path(tmp) / 'bundle')

    def test_fixture_ca_is_never_bundled(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree, manifest = stage_browser_bundle(ROOT, Path(tmp) / 'bundle')
            self.assertFalse([p for p in tree.rglob('*') if p.is_file() and p.suffix != '.py'])
            self.assertNotIn('crt', json.dumps(manifest['files']))


if __name__ == '__main__':
    unittest.main()
