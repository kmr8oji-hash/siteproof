"""The Docker engine is never queried merely because a site is registered or a page is opened (offline: the probe is a counter)."""
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from src.noxiworks import real_capture
from src.noxiworks.real_capture import RealCapture
from src.noxiworks.site_workflow import Site

NOW = datetime(2026, 11, 22, 6, 0, 0, tzinfo=timezone.utc)


class DockerProbe(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.site = Site.register(Path(self.tmp.name) / 'sites', 'MySite', 'https://www.example.com/', ['Desktop'], True, NOW)

    def readiness(self):
        probe = mock.Mock(return_value=True)
        with mock.patch.object(real_capture.shutil, 'which', return_value='C:/fake/docker.exe'), \
                mock.patch.object(real_capture, 'docker_engine_answers', probe):
            checks = RealCapture(self.site).readiness(NOW)
        return {c['key']: c for c in checks}, probe

    def test_a_registered_site_without_a_permit_never_queries_the_engine(self):
        checks, probe = self.readiness()
        probe.assert_not_called()
        self.assertFalse(checks['environment']['ok'])
        self.assertIn('確認していません', checks['environment']['state'])
        self.assertFalse(checks['permission']['ok'])

    def test_the_engine_is_queried_only_when_every_other_gate_holds(self):
        probe = mock.Mock(return_value=True)
        with mock.patch.object(real_capture.shutil, 'which', return_value='C:/fake/docker.exe'), \
                mock.patch.object(real_capture, 'docker_engine_answers', probe):
            capture = RealCapture(self.site)
            self.assertIsNone(capture._engine(False))
            probe.assert_not_called()
            self.assertTrue(capture._engine(True))
            probe.assert_called_once()

    def test_without_a_docker_cli_nothing_is_run_either(self):
        probe = mock.Mock(return_value=True)
        with mock.patch.object(real_capture.shutil, 'which', return_value=None), mock.patch.object(real_capture, 'docker_engine_answers', probe):
            self.assertFalse(RealCapture(self.site)._engine(True))
        probe.assert_not_called()

    def test_an_injected_value_is_used_as_is(self):
        self.assertTrue(RealCapture(self.site, docker_found=True)._engine(False))
        self.assertFalse(RealCapture(self.site, docker_found=False)._engine(True))


class ImageProbe(unittest.TestCase):
    """docker_image_id: one read-only inspect, in the harness's own context; every doubtful answer is fail-closed (subprocess is a stand-in)."""

    IMAGE = 'sha256:' + 'a' * 64

    def setUp(self):
        self.addCleanup(real_capture._IMAGE.update, at=0.0, asked=None, id=None)
        real_capture._IMAGE.update(at=0.0, asked=None, id=None)

    def ask(self, run, max_age=0):
        with mock.patch.object(real_capture.subprocess, 'run', run):
            return real_capture.docker_image_id(self.IMAGE, max_age)

    def test_only_a_read_only_inspect_is_run(self):
        run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, (self.IMAGE + '\n').encode(), b''))
        self.assertEqual(self.ask(run), self.IMAGE)
        self.assertEqual(run.call_args.args[0], ['docker', '--context', 'desktop-linux', 'image', 'inspect', '--format', '{{.Id}}', self.IMAGE])
        self.assertEqual(run.call_count, 1)

    def test_absent_and_unanswered_are_told_apart(self):
        cases = [('', subprocess.CompletedProcess([], 1, b'', b'Error response from daemon: No such image: ' + self.IMAGE.encode())),
                 (None, subprocess.CompletedProcess([], 1, b'', b'error during connect: the docker daemon is not running')),
                 (None, subprocess.CompletedProcess([], 0, b'\n', b''))]
        for expected, done in cases:
            self.assertEqual(self.ask(mock.Mock(return_value=done)), expected)
        for error in (OSError('no docker'), subprocess.TimeoutExpired('docker', 15)):
            self.assertIsNone(self.ask(mock.Mock(side_effect=error)))

    def test_the_screen_uses_a_short_cache_and_a_decision_never_does(self):
        run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, self.IMAGE.encode(), b''))
        for _ in range(3):
            self.ask(run, 60)
        self.assertEqual(run.call_count, 1)
        gone = mock.Mock(return_value=subprocess.CompletedProcess([], 1, b'', b'No such image'))
        self.assertEqual(self.ask(gone, 0), '')  # removed meanwhile: seen at once


if __name__ == '__main__':
    unittest.main()
