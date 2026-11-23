"""The Docker engine is never queried merely because a site is registered or a page is opened (offline: the probe is a counter)."""
from datetime import datetime, timezone
from pathlib import Path
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


if __name__ == '__main__':
    unittest.main()
