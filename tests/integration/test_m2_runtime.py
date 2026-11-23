"""M2 software contracts only: fake browser, temp S1/M1, numeric loopback proxy.

Audit guard refuses real DNS/network/browser/subprocess. No attested fixture flag.
"""
from dataclasses import replace
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock
from unittest.mock import patch
import sqlite3

from src.bridge.adapter import EvidenceBridge
from src.comparison import preview
from src.core.offline import OfflineWorkspace, profile
from src.isolation.budget import NetworkBudget, BudgetLimits
from src.isolation.connect_dns import DnsLimits
from src.isolation.destination import DestinationPolicy, AllowedDestination
from src.isolation.frames import FrameLimits
from src.isolation.quota_session import QuotaSession, IoLimits
from src.isolation.termination import TerminationLimits
from src.isolation.transport import ConnectTransport, TransportLimits
from src.runtime.browser import (UNREACHABLE_BROWSER_PROXY, ProxyLease, ResourceLimits, LaunchPlan, PlaywrightDriver,
                                 UnconfiguredIsolation, RuntimeRefused)
from src.runtime.service import RuntimeService
from src.storage.artifacts import ArtifactStore
from src.storage.failpoints import Failpoints
from src.storage.finalizer import EvidenceFinalizer
from src.storage.repository import Repository
from src.storage.runtime import initialize
from src.storage.recovery import plan_recovery
from src.worker.capture import capture, CaptureRequest, FrameWriter, MemoryChannel
from src.worker.trusted import TrustedWorker, DeadlineSource


VIOLATIONS = []
def boundary(event, args):
    if event in ('socket.getaddrinfo', 'socket.gethostbyname', 'subprocess.Popen', 'os.system'):
        VIOLATIONS.append(event)
        raise AssertionError('no DNS or processes in M2 fixture suite')
    if event in ('socket.bind', 'socket.connect', 'socket.sendto'):
        address = args[-1] if event == 'socket.sendto' else args[1]
        if not isinstance(address, tuple) or address[0] != '127.0.0.1':
            VIOLATIONS.append(event)
            raise AssertionError('only numeric loopback fixtures')
sys.addaudithook(boundary)


LIMITS = ResourceLimits(10, 1, 1024 * 1024, 128 * 1024 * 1024, 16, 64, 10, 1024 * 1024)


class Driver:
    def __init__(self, *, status=200, fail=None, image=None, clean=True, hook=None):
        self.status, self.fail, self.image, self.clean, self.hook = status, fail, image, clean, hook
        self.calls = []
    def stage(self, name):
        self.calls.append(name)
        if self.hook:
            self.hook(name)
        if self.fail == name:
            raise RuntimeError('sensitive exception must not escape')
        if self.fail == name + '-timeout':
            raise TimeoutError()
    def start(self, p): self.stage('start')
    def http(self, u, t): self.stage('http'); return self.status
    def load(self, t): self.stage('load')
    def capture(self, p, t):
        self.stage('capture')
        return self.image if self.image is not None else preview.fixture('original')
    def close(self): self.calls.append('close'); return self.clean


class M2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='siteproof-m2-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / 'state.sqlite'
        self.workspace = OfflineWorkspace.create(self.db, self.root)
        self.workspace.save_site({'label':'Fixture', 'origin':'https://fixture.invalid', 'expected_revision':0})
        self.workspace.save_page({'page_id':'page-1', 'label':'One', 'path':'/', 'expected_revision':0})
        initialize(self.db, self.root)
        self.fp = Failpoints()
        self.repo = Repository(self.db, failpoints=self.fp)
        self.finalizer = EvidenceFinalizer(self.repo, ArtifactStore(self.root, failpoints=self.fp), failpoints=self.fp)
        self.worker = TrustedWorker(EvidenceBridge(self.finalizer), cleanup_seconds=.2)
        self.service = RuntimeService(self.workspace, self.worker)
        self.proxies = []
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for p in self.proxies:
            self.assertTrue(p.stop())
            self.assertEqual(p._listener.fileno(), -1)
        self.assertEqual(VIOLATIONS, [])
        self.assertFalse(any(t.is_alive() and t.name.startswith('siteproof-evidence-')
                             for t in threading.enumerate()))

    def lease(self, *, connections=20, duration=30):
        b = BudgetLimits(1024*1024, connections, 2, 20, duration)
        session = QuotaSession('m2-batch', NetworkBudget(b, b), IoLimits(256, 1024),
                               termination_limits=TerminationLimits(.3, 1))
        resolver = Mock(side_effect=AssertionError('fixture driver must not resolve'))
        proxy = ConnectTransport(session, DestinationPolicy((AllowedDestination('fixture.invalid',443),)),
            resolver, DnsLimits(8,512), TransportLimits(1024,.3,.005,4,1))
        proxy.start()
        self.proxies.append(proxy)
        return ProxyLease(proxy)

    def factory(self, lease, driver=None, mutate=None):
        def produce(req, remaining):
            output = capture(req, driver or Driver(), lease, replace(LIMITS, seconds=min(remaining,10)))
            wire = mutate(output.wire) if mutate else output.wire
            return MemoryChannel(wire), output.reason, output.cleanup_confirmed
        return produce

    def run_batch(self, *, driver=None, mutate=None):
        batch, lease = self.service.submit(), self.lease()
        return self.service.run(batch, self.factory(lease, driver, mutate), lease, LIMITS)

    def test_success_http_load_capture_s1_manifest_and_reopen(self):
        state = self.run_batch()
        self.assertEqual(len(state['jobs']), 2)
        for j in state['jobs']:
            self.assertEqual(j['execution'], 'COMPLETED')
            self.assertIsNotNone(j['evidence'])
            self.assertEqual(j['quality'], 'UNKNOWN')
            self.assertEqual(j['profile_reason'], 'PROFILE_UNATTESTED')
            reports = {r.check_type.value:r.outcome.value for r in self.repo.list_check_results(j['job_id'])}
            self.assertEqual(reports, {'HTTP':'PASS', 'LOAD':'PASS', 'CAPTURE':'UNKNOWN'})
            self.assertTrue((self.root/j['evidence']['manifest_ref']).is_file())
        reopened = RuntimeService(OfflineWorkspace(self.db,self.root), self.worker)
        self.assertEqual(reopened.state(), state)
        self.assertEqual(self.workspace.state()['captures'], [])

    def test_five_pages_ten_jobs_independent_profiles_and_pinned_revision(self):
        for n in range(2,6):
            self.workspace.save_page({'page_id':f'p{n}', 'label':str(n),'path':f'/{n}','expected_revision':0})
        batch, lease = self.service.submit(), self.lease()
        self.workspace.save_profile({'page_id':'page-1','kind':'Desktop','width':1024,'height':768,'expected_revision':1})
        state = self.service.run(batch,self.factory(lease),lease,LIMITS)
        self.assertEqual(len(state['jobs']),10)
        old = next(j for j in state['jobs'] if j['page_id']=='page-1' and j['kind']=='Desktop')
        self.assertEqual(old['profile']['attributes']['viewport_width'],1440)
        self.assertTrue(all(j['execution']=='COMPLETED' for j in state['jobs']))

    def test_http_fail_skips_downstream_but_execution_completed(self):
        driver = Driver(status=404)
        state = self.run_batch(driver=driver)
        self.assertNotIn('capture',driver.calls)
        for j in state['jobs']:
            self.assertEqual(j['execution'],'COMPLETED')
            self.assertEqual(j['quality'],'UNKNOWN')
            self.assertIsNone(j['evidence'])
            self.assertEqual({r.check_type.value:r.outcome.value for r in self.repo.list_check_results(j['job_id'])},
                             {'HTTP':'FAIL','LOAD':'SKIPPED','CAPTURE':'SKIPPED'})

    def test_timeout_is_not_quality_pass(self):
        state = self.run_batch(driver=Driver(fail='load-timeout'))
        self.assertTrue(all(j['execution']=='TIMED_OUT' for j in state['jobs']))

    def test_driver_crash_retains_partial_output_without_end(self):
        lease = self.lease()
        output = capture(CaptureRequest('p',profile('Desktop'),'https://fixture.invalid/'),Driver(fail='load'),lease,LIMITS)
        self.assertEqual(output.reason,'LOAD_FAILED')
        self.assertIn(b'HTTP_RECORD',output.wire)
        self.assertNotIn(b'"kind":"END"',output.wire)
        self.assertNotIn(b'sensitive',output.wire)

    def test_pre_cancel_does_not_start_driver(self):
        batch, lease, cancel = self.service.submit(), self.lease(), threading.Event()
        cancel.set()
        driver = Driver()
        state = self.service.run(batch,self.factory(lease,driver),lease,LIMITS,cancel=cancel)
        self.assertEqual(driver.calls,[])
        self.assertTrue(all(j['execution']=='CANCELLED' for j in state['jobs']))

    def test_cancel_during_capture_is_not_adopted(self):
        cancel, lease = threading.Event(), self.lease()
        driver = Driver(hook=lambda stage: cancel.set() if stage=='capture' else None)
        def factory(req, remaining):
            out=capture(req,driver,lease,LIMITS,cancel=cancel)
            return MemoryChannel(out.wire),out.reason,out.cleanup_confirmed
        state=self.service.run(self.service.submit(),factory,lease,LIMITS,cancel=cancel)
        self.assertTrue(all(j['execution']=='CANCELLED' for j in state['jobs']))

    def test_bad_png_is_rejected_by_trusted_s1(self):
        state = self.run_batch(driver=Driver(image=b'not png'))
        self.assertTrue(all(j['execution']=='FAILED_EVIDENCE' for j in state['jobs']))

    def test_truncated_frame_and_size_lie_are_rejected(self):
        for mutate in (lambda b:b[:-8], lambda b:b.replace(b'"declared_length":',b'"declared_length":9',1)):
            state = self.run_batch(mutate=mutate)
            self.assertTrue(all(j['execution']=='FAILED_EVIDENCE' for j in state['jobs']))

    def test_output_limit_and_header_limit(self):
        lease, req = self.lease(), CaptureRequest('p',profile('Desktop'),'https://fixture.invalid/')
        out = capture(req,Driver(),lease,replace(LIMITS,output_bytes=20))
        self.assertNotEqual(out.reason,'CAPTURE_COMPLETE')
        self.assertLessEqual(len(out.wire),20)
        with self.assertRaises(ValueError):
            FrameWriter(req,replace(FrameLimits(),max_header_bytes=10)).emit('END')

    def test_browser_cleanup_unconfirmed_prevents_commit(self):
        state = self.run_batch(driver=Driver(clean=False))
        self.assertTrue(all(j['execution']=='FAILED_EXECUTION' and j['evidence'] is None for j in state['jobs']))

    def test_missing_stopped_proxy_and_forbidden_destinations(self):
        with self.assertRaises(RuntimeRefused): ProxyLease(None)
        lease = self.lease()
        for url in ('https://127.0.0.1/','https://169.254.169.254/','https://other.invalid/',
                    'http://fixture.invalid/','https://fixture.invalid:444/','https://x@fixture.invalid/'):
            with self.assertRaises(RuntimeRefused): lease.check(url)
        lease.stop()
        with self.assertRaises(RuntimeRefused): lease.check('https://fixture.invalid/')

    def test_proxy_dies_between_stages_fails_closed(self):
        lease = self.lease()
        driver=Driver(hook=lambda stage:lease.stop() if stage=='http' else None)
        out=capture(CaptureRequest('p',profile('Desktop'),'https://fixture.invalid/'),driver,lease,LIMITS)
        self.assertEqual(out.reason,'HTTP_FAILED')
        self.assertNotIn('load',driver.calls)

    def test_job_budget_stop_is_shared_across_all_children(self):
        lease=self.lease()
        def factory(req,remaining):
            lease.transport.session.stop('TOTAL_BYTES_EXCEEDED')
            return MemoryChannel(b''),'CAPTURE_FAILED',True
        state=self.service.run(self.service.submit(),factory,lease,LIMITS)
        self.assertTrue(all(j['execution']=='FAILED_EXECUTION' for j in state['jobs']))
        self.assertTrue(all(j['evidence'] is None for j in state['jobs']))

    def test_default_real_browser_runtime_is_denied(self):
        driver=PlaywrightDriver(UnconfiguredIsolation(),self.lease(),LIMITS)
        with self.assertRaisesRegex(RuntimeRefused,'ISOLATION_NOT_VERIFIED'):
            driver.start(profile('Desktop'))

    def test_playwright_adapter_options_and_stage_mapping_no_real_launch(self):
        lease=self.lease()
        launcher=Mock()
        launcher.close.return_value=True
        browser=launcher.open_browser.return_value
        page=browser.new_context.return_value.new_page.return_value
        page.goto.return_value.status=200
        page.screenshot.return_value=preview.fixture('original')
        driver=PlaywrightDriver(launcher,lease,LIMITS)
        out=capture(CaptureRequest('p',profile('Mobile'),'https://fixture.invalid/'),driver,lease,LIMITS)
        self.assertEqual(out.reason,'CAPTURE_COMPLETE')
        plan=launcher.open_browser.call_args.args[0]
        self.assertTrue(plan.playwright_options()['chromium_sandbox'])
        self.assertEqual(plan.playwright_options()['proxy']['bypass'],'<-loopback>')
        self.assertNotIn('--no-sandbox',plan.playwright_options()['args'])
        # Only the page context is routed to the audited proxy; the browser-wide default route goes nowhere.
        self.assertEqual(browser.new_context.call_args.kwargs['proxy']['server'],plan.proxy)
        self.assertEqual(plan.playwright_options()['proxy']['server'],UNREACHABLE_BROWSER_PROXY)
        self.assertNotEqual(plan.playwright_options()['proxy']['server'],plan.proxy)
        features=[a for a in plan.playwright_options()['args'] if a.startswith('--disable-features=')]
        self.assertEqual(len(features),1)  # Chromium keeps only the last such switch.
        self.assertIn('PreconnectToSearch',features[0]);self.assertIn('OptimizationHints',features[0])
        self.assertEqual(browser.new_context.call_args.kwargs['service_workers'],'block')
        self.assertFalse(browser.new_context.call_args.kwargs['ignore_https_errors'])
        self.assertEqual(page.goto.call_args.kwargs['wait_until'],'commit')

    def test_invalid_launch_resources_and_proxy_are_refused(self):
        for value in ('http://0.0.0.0:123','http://localhost:123','http://127.0.0.1:123/path'):
            with self.assertRaises(RuntimeRefused): LaunchPlan(value,LIMITS)
        for key,value in (('seconds',float('nan')),('processes',True),('output_bytes',0)):
            with self.assertRaises(ValueError): replace(LIMITS,**{key:value})

    def test_save_failure_preserves_orphans_and_no_false_completion(self):
        self.fp.fail('after_publish')
        state=self.run_batch()
        self.assertTrue(all(j['execution']=='FAILED_EVIDENCE' for j in state['jobs']))
        files=list(self.root.rglob('*'))
        self.assertTrue(any(p.is_file() for p in files))
        report=plan_recovery(self.db,self.root)
        self.assertFalse(report.applied)
        self.assertTrue(report.findings)

    def test_missing_evidence_readback_is_not_success_and_does_not_repair(self):
        state=self.run_batch()
        ref=state['jobs'][0]['evidence']['artifact_ref']
        (self.root/ref).unlink()  # synthetic temp fixture corruption only
        item=next(j for j in self.service.state()['jobs'] if j['job_id']==state['jobs'][0]['job_id'])
        self.assertIsNone(item['evidence'])
        self.assertEqual(item['reason'],'EVIDENCE_UNAVAILABLE')
        self.assertEqual(item['quality'],'UNKNOWN')

    def test_read_view_does_not_mutate_db_or_initialize_schema(self):
        self.run_batch()
        before=self.db.read_bytes()
        self.service.state()
        self.assertEqual(self.db.read_bytes(),before)
        with self.assertRaises(Exception): initialize(self.db,self.root)
        with self.workspace.repo.write() as c:
            with self.assertRaises(Exception): c.execute('DELETE FROM runtime_jobs')

    def test_deadline_bounds_wait_but_reports_unstopped_reader(self):
        release=threading.Event()
        class Blocking:
            def read(self,n): release.wait(); return b''
            def close(self): pass
        source=DeadlineSource(Blocking(),.03)
        try:
            with self.assertRaises(TimeoutError): source.read(1)
            self.assertFalse(source.close(.03))
        finally:
            release.set(); source.thread.join(1)
        self.assertFalse(source.thread.is_alive())

    def test_oversized_channel_read_is_rejected(self):
        class Bad(io.BytesIO):
            def read(self,n): return b'x'*(n+1)
        source=DeadlineSource(Bad(),1)
        try:
            with self.assertRaises(OSError): source.read(1)
        finally:
            self.assertTrue(source.close(.2))

    def test_actual_shared_budget_exhaustion_spans_profile_children(self):
        lease=self.lease()
        budget=lease.transport.session.budget
        count=[]
        def factory(req,remaining):
            tunnel='profile-'+str(len(count))
            count.append(tunnel)
            budget.open_tunnel(tunnel)
            connection=budget.begin_connection(tunnel).connection_id
            budget.connected(connection)
            try:
                decision=budget.transfer(connection,sent=1024*1024 if len(count)==1 else 1)
            finally:
                budget.close_connection(connection)
            if not decision.allowed:
                return MemoryChannel(b''),'CAPTURE_FAILED',True
            return self.factory(lease)(req,remaining)
        state=self.service.run(self.service.submit(),factory,lease,LIMITS)
        self.assertEqual(sorted(j['execution'] for j in state['jobs']),['COMPLETED','FAILED_EXECUTION'])
        self.assertEqual(budget.snapshot().total_bytes,1024*1024)
        self.assertEqual(budget.snapshot().concurrent_connections,0)

    def test_batch_ipc_byte_limit_does_not_reset_per_profile(self):
        lease=self.lease()
        req=CaptureRequest('page-1',profile('Desktop'),'https://fixture.invalid/')
        size=len(capture(req,Driver(),lease,LIMITS).wire)
        state=self.service.run(self.service.submit(),self.factory(lease),lease,
                               replace(LIMITS,output_bytes=size+50))
        self.assertEqual(sum(j['execution']=='COMPLETED' for j in state['jobs']),1)
        self.assertEqual(sum(j['execution']=='FAILED_EVIDENCE' for j in state['jobs']),1)

    def test_cross_profile_frame_is_not_rebound_by_trusted_worker(self):
        state=self.run_batch(mutate=lambda b:b.replace(b'"profile_id":"Desktop"',b'"profile_id":"Other"'))
        desktop=next(j for j in state['jobs'] if j['kind']=='Desktop')
        self.assertEqual(desktop['execution'],'FAILED_EVIDENCE')
        self.assertIsNone(desktop['evidence'])

    def test_pipe_timeout_releases_fixture_and_is_not_completed(self):
        lease=self.lease()
        self.worker.frame_limits=replace(FrameLimits(),timeout_seconds=.03)
        class Stalled:
            def __init__(self): self.release=threading.Event()
            def read(self,n): self.release.wait(); return b''
            def close(self): self.release.set()
        state=self.service.run(self.service.submit(),lambda r,t:(Stalled(),'CAPTURE_COMPLETE',True),lease,LIMITS)
        self.assertTrue(all(j['execution']=='TIMED_OUT' for j in state['jobs']))

    def test_cancel_during_pipe_read_fences_s1_commit(self):
        lease,cancel=self.lease(),threading.Event()
        class CancelSource(io.BytesIO):
            def read(self,n): cancel.set(); return super().read(n)
        def factory(req,remaining):
            out=capture(req,Driver(),lease,LIMITS)
            return CancelSource(out.wire),out.reason,True
        state=self.service.run(self.service.submit(),factory,lease,LIMITS,cancel=cancel)
        self.assertTrue(all(j['execution']=='CANCELLED' for j in state['jobs']))
        self.assertTrue(all(j['evidence'] is None for j in state['jobs']))

    def test_same_batch_cannot_run_again_with_a_new_budget(self):
        state=self.run_batch()
        lease=self.lease()
        with self.assertRaisesRegex(Exception,'RUNTIME_ALREADY_STARTED'):
            self.service.run(state['jobs'][0]['batch_id'],self.factory(lease),lease,LIMITS)

    def test_all_read_view_sqlite_connections_are_mode_ro(self):
        self.run_batch()
        original=sqlite3.connect
        def readonly(path,**kwargs):
            self.assertTrue(kwargs.get('uri'))
            self.assertIn('mode=ro',str(path))
            return original(path,**kwargs)
        with patch('sqlite3.connect',side_effect=readonly):
            self.assertEqual(len(self.service.state()['jobs']),2)


if __name__ == '__main__': unittest.main()
