"""Partial launcher provenance uses owned immutable image IDs. No Docker calls."""
import json
import unittest
from unittest.mock import Mock

from src.runtime.docker_launcher import DockerLauncher


class ImageObservationsTests(unittest.TestCase):
    def launcher(self):
        launch=object.__new__(DockerLauncher)
        launch.inspect=Mock(return_value={'Image':'sha256:'+'a'*64})
        launch.call=Mock(return_value=json.dumps([{'Id':'sha256:'+'a'*64,'Os':'linux','Architecture':'amd64'}]))
        return launch

    def test_only_measured_fields_no_browser_self_attestation(self):
        launch=self.launcher()
        result=launch.capture_profile_observations('owned')
        self.assertEqual(set(result),{'os','architecture','image_digest'})
        self.assertEqual(result['image_digest']['value'],'a'*64)
        self.assertTrue(all(x['source'].startswith('launcher:') for x in result.values()))
        launch.call.assert_called_once_with('image','inspect','sha256:'+'a'*64)
        self.assertEqual(launch.inspect.call_count,2)

    def test_changed_image_or_unowned_container_cannot_attest(self):
        launch=self.launcher()
        launch.inspect.side_effect=[{'Image':'sha256:'+'a'*64},{'Image':'sha256:'+'b'*64}]
        with self.assertRaises(RuntimeError): launch.capture_profile_observations('owned')
        launch=self.launcher(); launch.inspect.side_effect=RuntimeError('ownership rejected')
        with self.assertRaises(RuntimeError): launch.capture_profile_observations('other-project')
        launch.call.assert_not_called()

    def test_missing_image_metadata_is_not_guessed(self):
        launch=self.launcher(); launch.call.return_value=json.dumps([{'Id':'sha256:'+'a'*64}])
        with self.assertRaises(RuntimeError): launch.capture_profile_observations('owned')
