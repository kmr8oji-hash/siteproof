"""Deployment bundles: explicit allowlists, deterministic bytes, importable closure.

Builds into a temporary directory only. Nothing is uploaded; no AWS call is made.
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("build_bundles", ROOT / "tools" / "build_bundles.py")
build_bundles = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_bundles)


class Bundles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="siteproof-bundle-test-")
        cls.out = Path(cls._tmp.name) / "a"
        cls.manifest = build_bundles.build(cls.out)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def names(self, archive):
        with zipfile.ZipFile(self.out / archive) as handle:
            return handle.namelist()

    def test_same_inputs_give_byte_identical_archives(self):
        second = build_bundles.build(Path(self._tmp.name) / "b")
        for name in ("lambda-bundle.zip", "worker-bundle.zip"):
            self.assertEqual(second["archives"][name]["sha256"],
                             self.manifest["archives"][name]["sha256"])

    def test_existing_output_is_never_overwritten(self):
        with self.assertRaises(SystemExit):
            build_bundles.build(self.out)

    def test_manifest_matches_archive_bytes_and_states_its_limits(self):
        import hashlib
        stored = json.loads((self.out / "bundle-manifest.json").read_text("utf-8"))
        for name, details in stored["archives"].items():
            raw = (self.out / name).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), details["sha256"])
            with zipfile.ZipFile(self.out / name) as handle:
                for member, meta in details["files"].items():
                    self.assertEqual(hashlib.sha256(handle.read(member)).hexdigest(),
                                     meta["sha256"])
        self.assertIn("NOT UPLOADED", stored["status"])
        self.assertIn("NOT USER-APPROVED", stored["status"])

    def test_lambda_bundle_is_minimal(self):
        names = self.names("lambda-bundle.zip")
        self.assertTrue(all(n.startswith(("src/aws_b/", "src/aws_c/", "src/core/",
                                          "src/isolation/")) for n in names))
        for excluded in ("src/aws_c/worker_entry.py", "src/aws_c/linux_launcher.py",
                         "src/aws_c/evidence.py", "src/isolation/transport.py"):
            self.assertNotIn(excluded, names)
        self.assertFalse(any(n.startswith(("tests/", "web/", "infra/", "docs/")) for n in names))

    def test_worker_bundle_contains_harness_and_seccomp_but_no_data(self):
        names = self.names("worker-bundle.zip")
        for required in ("src/aws_c/worker_entry.py", "src/aws_c/linux_launcher.py",
                         "src/runtime/docker_launcher.py", "src/storage/recovery.py",
                         "tests/runtime/validate.py", "tests/runtime/netpolicy.py",
                         "runtime/docker/seccomp-siteproof.json", "tests/__init__.py"):
            self.assertIn(required, names)
        for name in names:
            self.assertFalse(name.endswith((".sqlite", ".db", ".pem", ".key", ".log", ".png",
                                            ".env", ".pyc")), name)
            self.assertFalse(any(part in (".local", ".git", "private", "secrets")
                                 for part in name.split("/")), name)
        self.assertFalse(any(n.startswith(("web/", "infra/", "docs/", "tests/aws_",
                                           "tests/storage", "tests/ui")) for n in names))

    def test_text_members_use_lf_and_fixed_timestamps(self):
        with zipfile.ZipFile(self.out / "lambda-bundle.zip") as handle:
            for info in handle.infolist():
                self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0))
                self.assertNotIn(b"\r\n", handle.read(info))

    def test_lambda_handlers_import_from_the_archive_alone(self):
        # -I: isolated mode, so neither the repository nor the working directory is on
        # sys.path; project modules can only come from the archive.
        script = ("import sys; sys.path.insert(0, sys.argv[1]); "
                  "import src.aws_b.handler as b, src.aws_c.watchdog as w, src.aws_c.controller as c; "
                  "assert all('lambda-bundle.zip' in m.__file__ for m in (b, w, c)); "
                  "print(callable(b.lambda_handler) and callable(w.lambda_handler) "
                  "and callable(c.lambda_handler))")
        with tempfile.TemporaryDirectory() as elsewhere:
            result = subprocess.run(
                [sys.executable, "-B", "-I", "-c", script, str(self.out / "lambda-bundle.zip")],
                cwd=elsewhere, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.stdout.strip(), "True", result.stderr[-800:])

    def test_policy_refuses_forbidden_names(self):
        for name in (".local/x.py", "src/../.git/config", "secrets/a.py", "data/a.sqlite"):
            with self.assertRaises(SystemExit):
                build_bundles._read(name)


if __name__ == "__main__":
    unittest.main()
