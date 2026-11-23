"""AWS-C worker entry: start gate, isolation gate, evidence preservation, journalling.

The Docker harness itself is replaced by a stub that writes a real S1 export with the
existing storage code. Docker, Chromium and EC2 are NOT RUN offline.
"""
import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from src.aws_c.control import ControlStore
from src.aws_c.linux_launcher import LinuxDockerLauncher
from src.aws_c.s3_publisher import S3Publisher
from src.aws_c.signer import UnsignedSigner
from src.aws_c.worker_entry import Deps, run_pilot, run_validation_harness
from src.aws_b.model import parse_utc
from src.runtime.docker_launcher import DockerLauncher
from tests.aws_c.support import (DEADLINE, RUN_ID, T0, make_export,
                                 write_validation_result)
from tests.aws_fakes import FakeClientError, FakeDynamo, FakeS3

AT = "2026-12-01T02:00:00Z"
ROOT = Path(__file__).resolve().parents[2]


class Rig:
    def __init__(self, test, reserve=True, minutes=0):
        tmp = tempfile.TemporaryDirectory(prefix="siteproof-awsc-worker-")
        test.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name) / "evidence"
        self.dynamo, self.s3 = FakeDynamo(), FakeS3()
        self.store = ControlStore(self.dynamo, "t")
        if reserve:
            self.store.reserve(RUN_ID, DEADLINE, AT)
        self.harness_calls = 0
        self.mode = dict(passed=True, isolation=True, leak=0, raises=None, export=True)
        self.now = T0 + timedelta(minutes=minutes)

    def harness(self, directory):
        self.harness_calls += 1
        if self.mode["export"]:
            make_export(Path(directory) / "s1")
        write_validation_result(directory, self.mode["passed"], self.mode["isolation"],
                                self.mode["leak"])
        if self.mode["raises"]:
            raise self.mode["raises"]

    def run(self):
        return run_pilot(Deps(
            pilot_run_id=RUN_ID, hard_deadline=parse_utc(DEADLINE), evidence_dir=self.dir,
            store=self.store, publisher=S3Publisher(self.s3, "bucket", "runs/%s/" % RUN_ID),
            signer=UnsignedSigner(), harness=self.harness, now=lambda: self.now,
            source={"bundle_sha256": "0" * 64}))

    def state(self):
        return self.store.read(RUN_ID).state

    def keys(self):
        return sorted(k for (_, k) in self.s3.objects)


class StartGate(unittest.TestCase):
    def test_without_reservation_nothing_runs(self):
        rig = Rig(self, reserve=False)
        out = rig.run()
        self.assertEqual((out["outcome"], out["harness_started"]), ("NOT_RESERVED", False))
        self.assertEqual((rig.harness_calls, rig.s3.objects), (0, {}))

    def test_control_table_unreachable_means_no_run(self):
        rig = Rig(self)
        rig.dynamo.faults.fail("get_item", TimeoutError())
        self.assertEqual(rig.run()["outcome"], "NOT_RESERVED")
        self.assertEqual(rig.harness_calls, 0)

    def test_a_second_boot_of_the_same_run_does_not_run_again(self):
        rig = Rig(self)
        self.assertEqual(rig.run()["outcome"], "EVIDENCE_COMMITTED")
        again = rig.run()                                   # e.g. an unintended reboot
        self.assertEqual((again["outcome"], again["control_state"]),
                         ("NOT_RESERVED", "EVIDENCE_COMMITTED"))
        self.assertEqual(rig.harness_calls, 1)

    def test_not_enough_time_before_deadline_skips_the_run(self):
        rig = Rig(self, minutes=46)                         # 14 minutes left
        out = rig.run()
        self.assertEqual((out["outcome"], out["harness_started"]), ("INSUFFICIENT_TIME", False))
        self.assertEqual((rig.harness_calls, rig.state()), (0, "RESERVED"))

    def test_unconfirmed_running_transition_means_no_run(self):
        rig = Rig(self)
        rig.dynamo.faults.fail("update_item", TimeoutError())
        self.assertEqual(rig.run()["outcome"], "START_NOT_CONFIRMED")
        self.assertEqual(rig.harness_calls, 0)


class Outcomes(unittest.TestCase):
    def test_successful_fixture_run_commits_evidence(self):
        rig = Rig(self)
        out = rig.run()
        self.assertEqual(out["outcome"], "EVIDENCE_COMMITTED")
        self.assertEqual(rig.state(), "EVIDENCE_COMMITTED")
        self.assertEqual(out["journal"], ["RUNNING->ISOLATION_PASSED:ISOLATION_PASSED",
                                          "ISOLATION_PASSED->EVIDENCE_COMMITTED:EVIDENCE_COMMITTED"])
        keys = rig.keys()
        prefix = "runs/%s/" % RUN_ID
        self.assertIn(prefix + "run-manifest.json", keys)
        self.assertIn(prefix + "s1/siteproof.sqlite", keys)
        self.assertIn(prefix + "run/validation-result.json", keys)
        self.assertTrue(all(k.startswith(prefix) for k in keys))
        self.assertFalse(any(k.endswith(".log") for k in keys))     # logs are not collected

    def test_isolation_leak_fails_the_run_but_preserves_evidence(self):
        rig = Rig(self)
        rig.mode.update(leak=1)
        out = rig.run()
        self.assertEqual((out["outcome"], out["isolation_passed"]), ("ISOLATION_FAILED", False))
        self.assertEqual(rig.state(), "ISOLATION_FAILED")
        self.assertIn("runs/%s/run-manifest.json" % RUN_ID, rig.keys())
        self.assertIn("runs/%s/run/preflight.json" % RUN_ID, rig.keys())

    def test_harness_exception_before_export_is_isolation_failed_with_reports_kept(self):
        rig = Rig(self)
        rig.mode.update(isolation=False, passed=False, export=False,
                        raises=RuntimeError("measured preflight required"))
        out = rig.run()
        self.assertEqual((out["outcome"], out["harness_error"]),
                         ("ISOLATION_FAILED", "RuntimeError"))
        self.assertFalse(out["publication"]["committed"])
        self.assertEqual(out["publication"]["verification_status"], "UNVERIFIED")
        self.assertIn("runs/%s/run/validation-result.json" % RUN_ID, rig.keys())

    def test_missing_harness_report_is_never_a_pass(self):
        rig = Rig(self)
        rig.harness = lambda directory: make_export(Path(directory) / "s1")
        out = rig.run()
        self.assertEqual((out["harness_passed"], out["isolation_passed"], out["outcome"]),
                         (False, False, "ISOLATION_FAILED"))

    def test_harness_failure_after_isolation_pass_is_failed(self):
        rig = Rig(self)
        rig.mode.update(passed=False)
        out = rig.run()
        self.assertEqual((out["outcome"], rig.state()), ("FAILED", "FAILED"))
        self.assertTrue(out["publication"]["all_objects_published"])

    def test_publication_failure_is_failed_not_committed(self):
        rig = Rig(self)
        rig.s3.faults.fail("put_object", FakeClientError("AccessDenied"), times=100)
        out = rig.run()
        self.assertEqual((out["outcome"], rig.state()), ("FAILED", "FAILED"))
        self.assertFalse(out["publication"]["committed"])

    def test_journal_failure_does_not_block_publication(self):
        rig = Rig(self)
        rig.dynamo.faults.fail("update_item", TimeoutError(), times=10, skip=1)
        out = rig.run()
        self.assertTrue(out["publication"]["committed"])
        self.assertIn("runs/%s/run-manifest.json" % RUN_ID, rig.keys())
        self.assertEqual(rig.state(), "RUNNING")            # journal is behind; S3 is the truth
        self.assertTrue(all("UNCERTAIN" in entry for entry in out["journal"]))

    def test_published_manifest_says_fixture_scope_and_unknown_quality(self):
        rig = Rig(self)
        rig.run()
        body = rig.s3.objects[("bucket", "runs/%s/run-manifest.json" % RUN_ID)]["Body"]
        document = json.loads(body)
        self.assertEqual(document["claims"]["target_scope"], "CONTROLLED_FIXTURE_ONLY")
        self.assertEqual(document["source"], {"bundle_sha256": "0" * 64})
        self.assertEqual(document["local_verification"]["status"], "CONSISTENT")


class LinuxAdapter(unittest.TestCase):
    SECCOMP = ROOT / "runtime" / "docker" / "seccomp-siteproof.json"

    def launcher(self, tmp, endpoint="unix:///var/run/docker.sock\n", docker="/usr/bin/docker"):
        calls = []

        def fake_call(self_, *args, **kwargs):
            calls.append((list(self_.cli), args))
            return endpoint
        with patch.object(DockerLauncher, "call", fake_call):
            return LinuxDockerLauncher(tmp, "image@sha256:" + "a" * 64, self.SECCOMP,
                                       docker=docker), calls

    def test_sets_every_attribute_the_base_constructor_sets(self):
        with tempfile.TemporaryDirectory() as tmp:
            linux, calls = self.launcher(tmp)
            with patch.object(DockerLauncher, "call",
                              lambda self_, *a, **k: "npipe:////./pipe/dockerDesktopLinuxEngine\n"):
                base = DockerLauncher(Path(tmp) / "base", "image", self.SECCOMP)
            self.assertEqual(set(vars(linux)), set(vars(base)))
            self.assertEqual(linux.cli, ["/usr/bin/docker"])
            self.assertEqual(calls[0][1][:2], ("context", "inspect"))
            self.assertEqual((linux.boundary, linux.resources, linux.retired), (None, {}, {}))

    def test_isolation_options_are_inherited_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            linux, _ = self.launcher(tmp)
            self.assertIs(LinuxDockerLauncher.options, DockerLauncher.options)
            for name in ("seal", "browser", "bounded", "cleanup", "retire", "stop", "create"):
                self.assertIs(getattr(LinuxDockerLauncher, name), getattr(DockerLauncher, name))
            options = linux.options("anchor", 1000)
            for required in ("--cap-drop", "ALL", "no-new-privileges=true", "--read-only",
                             "container:anchor", "1000:1000"):
                self.assertIn(required, options)
            self.assertTrue(any(o.startswith("seccomp=") for o in options))
            self.assertNotIn("--privileged", options)

    def test_browser_is_blocked_before_measured_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            linux, _ = self.launcher(tmp)
            with self.assertRaises(RuntimeError):
                linux.browser("siteproof-m2-x", "anchor", 1000, ["true"], b"")
            with self.assertRaises(RuntimeError):
                linux.seal({"passed": True, "netns": "n", "canary_positive": {},
                            "canary_zero": {}}, "n")

    def test_remote_engine_endpoint_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            for endpoint in ("tcp://203.0.113.5:2375\n", "ssh://host\n", "\n",
                             "npipe:////./pipe/dockerDesktopLinuxEngine\n"):
                with self.assertRaises(RuntimeError):
                    self.launcher(tmp, endpoint=endpoint)

    def test_existing_launcher_file_is_unmodified(self):
        import subprocess
        result = subprocess.run(["git", "status", "--porcelain", "--", "src/runtime",
                                 "src/storage", "src/core", "src/isolation", "src/worker",
                                 "src/bridge", "src/comparison", "src/baseline", "src/bff",
                                 "runtime", "web", "infra/public_web"],
                                cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "")

    def test_harness_wrapper_substitutes_and_restores_the_launcher(self):
        import tests.runtime.validate as validate
        seen = {}

        def fake_main():
            seen["argv"] = list(sys.argv)
            seen["launcher"] = validate.DockerLauncher
        original, argv = validate.DockerLauncher, list(sys.argv)
        with patch.object(validate, "main", fake_main):
            run_validation_harness(Path("/tmp/e"), image="img", docker="/usr/bin/docker")
        self.assertEqual(seen["argv"][1:], ["--evidence", str(Path("/tmp/e")), "--image", "img"])
        self.assertIsNot(seen["launcher"], original)
        self.assertIs(validate.DockerLauncher, original)
        self.assertEqual(sys.argv, argv)

        def failing_main():
            raise RuntimeError("docker unavailable")
        with patch.object(validate, "main", failing_main), self.assertRaises(RuntimeError):
            run_validation_harness(Path("/tmp/e"), image="img", docker="/usr/bin/docker")
        self.assertIs(validate.DockerLauncher, original)


if __name__ == "__main__":
    unittest.main()
