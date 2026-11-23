"""Container archival/removal contracts. No daemon, browser or network required."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from src.runtime.docker_launcher import DockerLauncher, TASK


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.launch=object.__new__(DockerLauncher)
        self.launch.evidence=Path(self.temp.name)
        self.launch.retired={}
        self.name='siteproof-m2-lifecycle-fixture';self.identifier='a'*64
        self.launch.resources={self.name:{'kind':'container','id':self.identifier}}
        self.obj={'Id':self.identifier,'Image':'sha256:'+'b'*64,'Created':'fixture',
            'State':{'Running':False,'Pid':0,'ExitCode':9},'Mounts':[],
            'Config':{'Labels':{'siteproof.task':TASK},'Image':'fixture-image',
                'User':'1000:1000','Cmd':['python','secret-argument'],
                'Env':['SECRET=secret-environment']},
            'NetworkSettings':{'Networks':{}},
            'HostConfig':dict(ReadonlyRootfs=True,NetworkMode='none',CapAdd=[],CapDrop=['ALL'],
                SecurityOpt=[],Memory=1024,MemorySwap=1024,PidsLimit=16,NanoCpus=1,
                Ulimits=[],PortBindings={})}
        self.launch.inspect=Mock(side_effect=lambda name:copy.deepcopy(self.obj))
        self.launch.call=Mock(return_value='')
        self.launch._container_logs=Mock(return_value=b'synthetic failure\nBearer secret-token\n' + b'z'*32)

    def test_archive_hashes_and_nonforced_exact_id_removal(self):
        result=self.launch.retire(self.name)
        directory=Path(result['archive']);hashes=json.loads((directory/'sha256.json').read_text())
        for name,digest in hashes.items():
            self.assertEqual(hashlib.sha256((directory/name).read_bytes()).hexdigest(),digest)
        metadata=json.loads((directory/'metadata.json').read_text())
        self.assertEqual(metadata['state']['ExitCode'],9)
        self.assertEqual(metadata['image_id'],self.obj['Image'])
        self.launch.call.assert_any_call('rm',self.identifier)
        self.assertNotIn('secret-token',(directory/'docker.log').read_text())
        self.assertIn('synthetic failure',(directory/'docker.log').read_text())
        self.assertNotIn('secret-argument',(directory/'metadata.json').read_text())
        self.assertNotIn('secret-environment',(directory/'metadata.json').read_text())

    def test_retirement_is_idempotent_within_run(self):
        self.launch.retire(self.name);count=self.launch.call.call_count
        self.launch.retire(self.name)
        self.assertEqual(self.launch.call.call_count,count)

    def test_running_or_unreaped_container_never_removed(self):
        for state in ({'Running':True,'Pid':1},{'Running':False,'Pid':1}):
            with self.subTest(state=state):
                self.obj['State']=state
                with self.assertRaises(RuntimeError):self.launch.retire(self.name)
        self.launch.call.assert_not_called()

    def test_writable_root_requires_manual_data_export(self):
        self.obj['HostConfig']['ReadonlyRootfs']=False
        with self.assertRaises(RuntimeError):self.launch.retire(self.name)
        self.launch._container_logs.assert_not_called()
        self.launch.call.assert_not_called()

    def test_writable_bind_never_removed(self):
        self.obj['Mounts']=[{'Type':'bind','RW':True}]
        with self.assertRaises(RuntimeError):self.launch.retire(self.name)
        self.launch.call.assert_not_called()

    def test_shared_volume_never_removed(self):
        self.obj['Mounts']=[{'Type':'volume','RW':True,'Name':'shared'}]
        self.launch.call.return_value=json.dumps([{'Labels':{'project':'other'}}])
        with self.assertRaises(RuntimeError):self.launch.retire(self.name)
        self.assertFalse(any(c.args[0]=='rm' for c in self.launch.call.call_args_list))

    def test_owned_volume_preserved_without_rm_v(self):
        self.obj['Mounts']=[{'Type':'volume','RW':True,'Name':'owned'}]
        self.launch.call.side_effect=lambda *a:json.dumps([{'Labels':{'siteproof.task':TASK}}]) if a[0]=='volume' else ''
        self.launch.retire(self.name)
        self.launch.call.assert_any_call('rm',self.identifier)
        self.assertFalse(any('-v' in c.args or '-f' in c.args for c in self.launch.call.call_args_list))

    def test_archival_failure_preserves_container(self):
        self.launch._container_logs.side_effect=RuntimeError('private detail')
        with self.assertRaises(RuntimeError):self.launch.retire(self.name)
        self.launch.call.assert_not_called()

    def test_archive_write_failure_preserves_container(self):
        with patch.object(Path,'write_bytes',side_effect=OSError('disk unavailable')):
            with self.assertRaises(OSError):self.launch.retire(self.name)
        self.launch.call.assert_not_called()

    def test_state_race_rechecked_before_rm(self):
        running=copy.deepcopy(self.obj);running['State']={'Running':True,'Pid':20}
        self.launch.inspect.side_effect=[copy.deepcopy(self.obj),running]
        with self.assertRaises(RuntimeError):self.launch.retire(self.name)
        self.launch.call.assert_not_called()

    def test_label_and_id_mismatch_refused_even_with_matching_name(self):
        self.launch.inspect=DockerLauncher.inspect.__get__(self.launch)
        for mismatch in ('label','id'):
            obj=copy.deepcopy(self.obj)
            if mismatch=='label':obj['Config']['Labels']['siteproof.task']='other'
            else:obj['Id']='c'*64
            self.launch.call.return_value=json.dumps([obj])
            with self.assertRaises(RuntimeError):self.launch.retire(self.name)
        self.assertFalse(any(c.args[0]=='rm' for c in self.launch.call.call_args_list))

    def test_restart_and_exit_during_archival_also_refuses_rm(self):
        changed=copy.deepcopy(self.obj);changed['State']['FinishedAt']='new-execution'
        self.launch.inspect.side_effect=[copy.deepcopy(self.obj),changed]
        with self.assertRaises(RuntimeError):self.launch.retire(self.name)
        self.launch.call.assert_not_called()

    def test_cleanup_failure_reported_without_private_exception(self):
        self.launch.stop_all=Mock(return_value=True)
        self.launch._container_logs.side_effect=RuntimeError('private detail')
        self.assertFalse(self.launch.cleanup())
        report=(self.launch.evidence/'cleanup.json').read_text()
        self.assertNotIn('private detail',report)
        self.assertFalse(json.loads(report)['passed'])

    def test_stop_failure_prevents_deletion(self):
        self.launch.stop_all=Mock(return_value=False)
        self.assertFalse(self.launch.cleanup())
        self.launch._container_logs.assert_not_called()

    def test_log_reader_preserves_failure_output_and_rejects_overflow(self):
        del self.launch._container_logs
        self.launch.cli=[sys.executable,'-B','-c',"print('synthetic abnormal result')"]
        self.assertIn(b'synthetic abnormal result',self.launch._container_logs(self.identifier))
        self.launch.cli=[sys.executable,'-B','-c',"import os;os.write(1,b'x'*131072)"]
        with self.assertRaises(RuntimeError):self.launch._container_logs(self.identifier,limit=1024)

    def test_log_reader_deadline_is_bounded(self):
        del self.launch._container_logs
        self.launch.cli=[sys.executable,'-B','-c','import time;time.sleep(30)']
        with self.assertRaises(RuntimeError):self.launch._container_logs(self.identifier,seconds=.03)


if __name__=='__main__':unittest.main()
