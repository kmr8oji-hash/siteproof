"""Offline regression for the exact runtime additions; no Docker/browser/network."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock,patch

from src.runtime.browser import PlaywrightDriver
from src.runtime.docker_launcher import DockerLauncher,BoundedExecutionError
from src.isolation.budget import BudgetLimits,NetworkBudget
from src.isolation.quota_session import QuotaSession,IoLimits
from src.isolation.termination import TerminationLimits
from src.isolation.transport import ConnectTransport,TransportLimits
from src.isolation.destination import DestinationPolicy,AllowedDestination
from src.isolation.connect_dns import DnsLimits


class RuntimeContractTests(unittest.TestCase):
    def test_playwright_timeout_normalised_without_dependency(self):
        timeout=type('TimeoutError',(Exception,),{'__module__':'playwright._impl._errors'})
        with self.assertRaises(TimeoutError):
            PlaywrightDriver._call(Mock(side_effect=timeout('private details')))

    def test_other_browser_failure_not_reclassified(self):
        with self.assertRaises(ValueError):PlaywrightDriver._call(Mock(side_effect=ValueError()))

    def test_listen_port_validation_does_not_bind(self):
        b=BudgetLimits(1024,4,2,4,10)
        s=QuotaSession('test',NetworkBudget(b,b),IoLimits(64,128),termination_limits=TerminationLimits(1,1))
        args=(s,DestinationPolicy((AllowedDestination('fixture.invalid',443),)),Mock(),DnsLimits(8,512),TransportLimits(1024,1,.01,4,1))
        for value in (-1,65536,True,'18080'):
            with self.assertRaises(ValueError):ConnectTransport(*args,listen_port=value)
        p=ConnectTransport(*args,listen_port=18080)
        self.assertIsNone(p._listener)
        self.assertEqual(p.listen_port,18080)

    def report(self):
        keys=('tcp','dns','udp','metadata','lan','host_model','ipv6')
        return {'passed':True,'netns':'net:[test]','canary_positive':dict.fromkeys(keys,1),
                'canary_zero':dict.fromkeys(keys,0)}

    def launcher(self):
        result=object.__new__(DockerLauncher);result.boundary=None;return result

    def test_positive_and_zero_observations_required(self):
        launch=self.launcher();launch.seal(self.report(),'net:[test]')
        self.assertIsNotNone(launch.boundary)

    def test_any_canary_arrival_refuses_browser_gate(self):
        r=self.report();r['canary_zero']['dns']=1
        with self.assertRaises(RuntimeError):self.launcher().seal(r,'net:[test]')

    def test_missing_positive_control_refuses_browser_gate(self):
        r=self.report();r['canary_positive']['metadata']=0
        with self.assertRaises(RuntimeError):self.launcher().seal(r,'net:[test]')

    def test_namespace_change_refuses_browser_gate(self):
        with self.assertRaises(RuntimeError):self.launcher().seal(self.report(),'net:[other]')

    def test_boolean_pass_alone_cannot_open_browser_gate(self):
        with self.assertRaises(RuntimeError):self.launcher().seal({'passed':True},'net:[test]')

    def test_browser_call_before_preflight_does_not_invoke_docker(self):
        launch=self.launcher();launch.call=Mock()
        with self.assertRaises(RuntimeError):launch.browser('x','anchor',1000,[],b'')
        launch.call.assert_not_called()

    def test_derived_seccomp_only_adds_sandbox_chroot(self):
        root=Path(__file__).resolve().parents[2]/'runtime/docker'
        original=json.loads((root/'seccomp-playwright.json').read_text())
        derived=json.loads((root/'seccomp-siteproof.json').read_text())
        extra=derived['syscalls'].pop(1)
        self.assertEqual(extra['names'],['chroot'])
        self.assertEqual(extra['action'],'SCMP_ACT_ALLOW')
        self.assertEqual(derived,original)
        self.assertEqual(derived['defaultAction'],'SCMP_ACT_ERRNO')


class BoundedExecutionTests(unittest.TestCase):
    """Real local pipes/child processes; Docker stop is the injected boundary."""
    def run_child(self,code,*,seconds=2,limit=4096,stop_error=False,stop_child=False):
        launch=object.__new__(DockerLauncher)
        launch.cli=[sys.executable,'-B','-c',code]
        launch.inspect=Mock(return_value={})
        processes=[];real_popen=subprocess.Popen
        def spawn(*args,**kwargs):
            p=real_popen(*args,**kwargs);processes.append(p);return p
        def stop(name):
            if stop_error:raise RuntimeError('private internal detail')
            p=processes[0]
            if stop_child and p.poll() is None:p.terminate()
            # The finite flood must drain before this acknowledgement can arrive.
            p.wait(timeout=2)
            return True
        launch.stop=Mock(side_effect=stop)
        result=error=None
        try:
            with patch('src.runtime.docker_launcher.subprocess.Popen',side_effect=spawn):
                try:result=launch.bounded('owned',seconds=seconds,limit=limit)
                except BaseException as exc:error=exc
            return launch,processes[0],result,error
        finally:
            for p in processes:
                if p.poll() is None:p.kill();p.wait(timeout=2)

    def assert_closed(self,p,launch):
        self.assertIsNotNone(p.poll())
        self.assertTrue(all(s.closed for s in (p.stdin,p.stdout,p.stderr)))
        self.assertTrue(launch.last_execution['readers_joined'])
        self.assertTrue(launch.last_execution['pipes_closed'])

    def test_stdout_overflow_drains_until_stop_ack_without_retaining_excess(self):
        launch,p,result,error=self.run_child("import os;os.write(1,b'x'*(512*1024))")
        self.assertIsNone(result)
        self.assertIsInstance(error,BoundedExecutionError)
        self.assertEqual(error.reason,'OUTPUT_LIMIT')
        self.assertTrue(error.cleanup_confirmed)
        self.assertEqual(error.report['stdout_retained'],4096)
        self.assertEqual(error.report['received'][0],512*1024)
        self.assert_closed(p,launch)

    def test_stderr_overflow_also_drains_and_remains_bounded(self):
        launch,p,result,error=self.run_child("import os;os.write(2,b'x'*(512*1024))")
        self.assertIsInstance(error,BoundedExecutionError)
        self.assertEqual(error.reason,'OUTPUT_LIMIT')
        self.assertTrue(error.cleanup_confirmed)
        self.assertEqual(error.report['stderr_retained'],65536)
        self.assertEqual(error.report['received'][1],512*1024)
        self.assert_closed(p,launch)

    def test_success_at_exact_limit_preserves_bytes_and_closes_pipes(self):
        launch,p,result,error=self.run_child("import os;os.write(1,b'x'*4096)")
        self.assertIsNone(error)
        self.assertEqual(result,(b'x'*4096,b''))
        self.assertTrue(launch.last_execution['cleanup_confirmed'])
        self.assert_closed(p,launch)

    def test_deadline_stops_child_and_returns_confirmed_abnormal_result(self):
        launch,p,result,error=self.run_child('import time;time.sleep(30)',seconds=.05,stop_child=True)
        self.assertIsInstance(error,BoundedExecutionError)
        self.assertEqual(error.reason,'TIMEOUT')
        self.assertTrue(error.cleanup_confirmed)
        self.assertIsNone(result)
        self.assert_closed(p,launch)

    def test_stop_exception_cannot_skip_pipe_cleanup_or_become_success(self):
        launch,p,result,error=self.run_child("print('fixture')",stop_error=True)
        self.assertIsNone(result)
        self.assertIsInstance(error,BoundedExecutionError)
        self.assertEqual(error.reason,'CLEANUP_UNCONFIRMED')
        self.assertFalse(error.cleanup_confirmed)
        self.assertNotIn('private internal detail',json.dumps(error.report))
        self.assert_closed(p,launch)

    def test_false_stop_acknowledgement_cannot_become_success(self):
        launch=object.__new__(DockerLauncher)
        launch.cli=[sys.executable,'-B','-c',"print('fixture')"]
        launch.inspect=Mock();launch.stop=Mock(return_value=False)
        with self.assertRaises(BoundedExecutionError) as caught:
            launch.bounded('owned',seconds=2)
        self.assertFalse(caught.exception.cleanup_confirmed)
        self.assertEqual(caught.exception.reason,'CLEANUP_UNCONFIRMED')
        self.assertTrue(caught.exception.report['pipes_closed'])

    def test_nonzero_exit_is_not_success_even_when_cleanup_is_confirmed(self):
        launch,p,result,error=self.run_child('raise SystemExit(9)')
        self.assertIsNone(result)
        self.assertIsInstance(error,RuntimeError)
        self.assertNotIsInstance(error,BoundedExecutionError)
        self.assertTrue(launch.last_execution['cleanup_confirmed'])
        self.assert_closed(p,launch)

    def test_wait_timeout_reaps_attach_cli_but_keeps_cleanup_unconfirmed(self):
        launch=object.__new__(DockerLauncher)
        launch.cli=[sys.executable,'-B','-c','import time;time.sleep(30)']
        launch.inspect=Mock();launch.stop=Mock(return_value=True)
        real_popen=subprocess.Popen;processes=[]
        def spawn(*args,**kwargs):
            p=real_popen(*args,**kwargs);processes.append(p)
            original=p.wait;first=True
            def wait(timeout=None):
                nonlocal first
                if first:first=False;raise subprocess.TimeoutExpired('fixture',timeout)
                return original(timeout=timeout)
            p.wait=wait
            return p
        with patch('src.runtime.docker_launcher.subprocess.Popen',side_effect=spawn):
            with self.assertRaises(BoundedExecutionError) as caught:
                launch.bounded('owned',seconds=.03)
        self.assertFalse(caught.exception.cleanup_confirmed)
        self.assertIn('wait:TimeoutExpired',caught.exception.report['cleanup_errors'])
        self.assert_closed(processes[0],launch)


if __name__=='__main__':unittest.main()
