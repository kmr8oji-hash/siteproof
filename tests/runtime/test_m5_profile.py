"""M5 classification/key/sink contracts. No Docker, browser, DNS or downloads."""
import json
import secrets
import sys
import unittest
from unittest.mock import Mock, patch

from src.comparison.provenance import complete
from src.core.offline import profile
from src.runtime.docker_launcher import DockerLauncher
from src.runtime.profile_observer import WorkerProfileObserver, EphemeralFixtureSigner
from tests.comparison.support import Fixture


class ObserverTests(unittest.TestCase):
    def observer(self):
        observer=object.__new__(WorkerProfileObserver)
        observer.measured={'image_digest':{'value':'a'*64,'source':'launcher:owned-image-id'},
                           'browser_version':{'value':'Chromium measured','source':'worker:binary-version'}}
        observer.browser_reports={};observer.repetitions={};observer.binary_sha256='b'*64;observer.font_files=10
        return observer

    def test_matching_instructions_and_browser_reports_remain_unattested(self):
        observer=self.observer();p=profile('Mobile')
        observer.record_browser_report('j',{'viewport_width':390,'browser_version':'claim'})
        settings=observer(p,'captured','j')
        settings.pop('stability_result')
        self.assertFalse(complete(p,settings))
        self.assertEqual(settings['viewport_width']['source'],'configured:worker-instruction-only')
        self.assertEqual(settings['browser_version']['value'],'Chromium measured')
        self.assertEqual(observer.report()['browser_self_reports']['j']['browser_version'],'claim')
        classes=observer.report()['field_classes']
        self.assertEqual(classes['browser_version'],'TRUSTED_OBSERVED')
        self.assertEqual(classes['viewport_width'],'CONFIGURED_ONLY')
        self.assertEqual(classes['browser_self_reports'],'BROWSER_REPORTED')
        self.assertEqual(classes['actual_renderer_fonts'],'UNKNOWN')

    def test_repeated_bytes_only_prove_received_byte_equality(self):
        from src.runtime.stability import stable_capture
        clock=[0.0]
        _,_,report=stable_capture(lambda t:b'png',None,5,clock=lambda:clock[0],sleep=lambda s:clock.__setitem__(0,clock[0]+s))
        observer=self.observer();observer.record_repetition('j',b'png',b'png',report)
        self.assertEqual(observer(profile('Desktop'),'stability','j')['stability_result']['value'],'STABLE')
        self.assertEqual(observer.report()['profile_trust'],'UNATTESTED')
        # Two equal PNGs alone (no settled, time-spaced run reported) are no longer enough: same rule as the S3 path.
        observer.record_repetition('j',b'png',b'png')
        self.assertIsNone(observer(profile('Desktop'),'stability','j')['stability_result'])
        observer.record_repetition('j',b'png',b'changed',report)
        self.assertIsNone(observer(profile('Desktop'),'stability','j')['stability_result'])

    def test_ephemeral_key_generation_replay_tamper_and_revocation(self):
        signer=EphemeralFixtureSigner(self.observer());other=EphemeralFixtureSigner(self.observer())
        self.addCleanup(other.destroy)
        key=signer.authority._key
        self.assertEqual(len(key),32);self.assertNotEqual(key,other.authority._key)
        signed=signer.authority.sign({'job_id':'one','digest':'a'*64})
        self.assertTrue(signer.authority.verifies(signed));self.assertFalse(other.authority.verifies(signed))
        modified={**signed,'body':{'job_id':'two','digest':'a'*64}}
        self.assertFalse(signer.authority.verifies(modified));signer.verification('tampered',False)
        signer.destroy();self.assertFalse(signer.authority.verifies(signed))
        with self.assertRaises(ValueError):signer.authority.sign({'job_id':'one'})
        self.assertNotIn(key.hex(),json.dumps(signer.events));self.assertIsNone(signer.authority._key)
        self.assertEqual(signer.events[-1]['event'],'KEY_REVOKED')

    def test_capped_failure_output_is_observed_after_stop_and_pipe_cleanup(self):
        launcher=object.__new__(DockerLauncher)
        launcher.cli=[sys.executable,'-B','-c',"print('partial-public-fixture');raise SystemExit(7)"]
        launcher.inspect=Mock();launcher.stop=Mock(return_value=True)
        received=[]
        def sink(out,err,report):
            self.assertTrue(report['cleanup_confirmed']);self.assertTrue(report['pipes_closed'])
            self.assertTrue(launcher.stop.called);received.append(out)
        with self.assertRaises(RuntimeError):launcher.bounded('owned',evidence_sink=sink)
        self.assertIn(b'partial-public-fixture',received[0])


class UnattestedPreviewTests(unittest.TestCase):
    def test_explicit_preview_keeps_unknown_and_revalidates_before_cached_pixels(self):
        f=Fixture(trusted=False);self.addCleanup(f.close)
        f.comparison.allow_unattested_preview=True
        for job in f.run()['jobs']:f.approve(job['candidate'])
        same=f.run()['results'][0]
        self.assertEqual(same['quality'],'UNKNOWN');self.assertTrue(same['preview_only'])
        self.assertEqual(same['metrics']['changed_pixels'],0)
        changed=f.run(changed=True)['results'][0]
        self.assertEqual(changed['quality'],'UNKNOWN');self.assertTrue(changed['preview_changed'])
        self.assertIsNotNone(changed['diff_sha256'])
        with patch('src.comparison.preview.compare',side_effect=AssertionError('pure work should be reused')):
            cached=f.comparison.compare(changed['job_id'])
        self.assertEqual(cached['metrics'],changed['metrics']);self.assertEqual(cached['quality'],'UNKNOWN')
        binding=f.comparison.store.body('candidates','capture-'+changed['job_id'])
        (f.root/binding['evidence']['manifest']['artifact_ref']).write_bytes(b'fixture corruption')
        rejected=f.comparison.compare(changed['job_id'])
        self.assertEqual(rejected['quality'],'UNKNOWN');self.assertIsNone(rejected['metrics'])


if __name__=='__main__':unittest.main()
