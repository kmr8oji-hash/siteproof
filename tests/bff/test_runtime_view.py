"""Authenticated local HOME reads S1 references; no HTTP browser-start endpoint."""
import json
import unittest

from src.core.offline import OfflineWorkspace
from src.storage.m1 import initialize as initialize_m1
from src.storage.runtime import initialize
from src.storage.repository import Repository
from src.storage.artifacts import ArtifactStore
from src.storage.finalizer import EvidenceFinalizer
from src.bridge.adapter import EvidenceBridge
from src.worker.trusted import TrustedWorker
from src.runtime.service import RuntimeService
from tests.bff.test_local_ui import LocalUITests
from tests.integration.test_m2_runtime import M2Tests, LIMITS


class RuntimeViewTests(unittest.TestCase):
    setUp = LocalUITests.setUp
    _remove_temp = LocalUITests._remove_temp
    _stop_servers = LocalUITests._stop_servers
    socket = LocalUITests.socket
    request = LocalUITests.request
    pair = LocalUITests.pair
    server = LocalUITests.server
    lease = M2Tests.lease
    factory = M2Tests.factory

    def runtime(self):
        initialize_m1(self.db,self.root)
        workspace=OfflineWorkspace(self.db,self.root)
        workspace.save_site({'origin':'https://fixture.invalid','label':'Fixture','expected_revision':0})
        workspace.save_page({'page_id':'p','path':'/','label':'One','expected_revision':0})
        initialize(self.db,self.root)
        service=RuntimeService(workspace,TrustedWorker(EvidenceBridge(EvidenceFinalizer(
            Repository(self.db),ArtifactStore(self.root)))))
        return workspace,service

    def test_paired_home_runtime_read_reuses_s1_preserves_db_and_auth(self):
        workspace,service=self.runtime()
        self.proxies=[]
        lease=self.lease()
        try:
            state=service.run(service.submit(),self.factory(lease),lease,LIMITS)
        finally:
            self.assertTrue(lease.stop())
        server=self.server(offline=workspace,runtime=service)
        path='/api/baselines/_m1/runtime'
        self.assertEqual(self.request(server,path)[0],401)
        cookie,_=self.pair(server)
        before=self.db.read_bytes()
        status,_,raw=self.request(server,path,cookie=cookie)
        self.assertEqual(status,200)
        self.assertEqual(json.loads(raw),state)
        self.assertNotIn(str(self.root).encode(),raw)
        self.assertEqual(before,self.db.read_bytes())
        for headers in ({'Host':'localhost:123'}, {'Origin':'null'},
                        {'Origin':'https://evil.invalid'}, {'Sec-Fetch-Site':'cross-site'}):
            self.assertNotEqual(self.request(server,path,cookie=cookie,headers=headers)[0],200)
        for method in ('POST','DELETE','PUT'):
            self.assertNotEqual(self.request(server,path,method=method,cookie=cookie)[0],200)
        self.assertNotEqual(self.request(server,path+'?db=C:/secret',cookie=cookie)[0],200)
        server.destroy_session()
        self.assertEqual(self.request(server,path,cookie=cookie)[0],401)

    def test_runtime_unavailable_is_not_empty_success_and_assets_local_only(self):
        workspace,_=self.runtime()
        server=self.server(offline=workspace)
        cookie,_=self.pair(server)
        status,_,raw=self.request(server,'/api/baselines/_m1/runtime',cookie=cookie)
        self.assertEqual(status,503)
        self.assertEqual(json.loads(raw)['error']['code'],'RUNTIME_UNAVAILABLE')
        status,_,html=self.request(server,'/local/')
        self.assertEqual(status,200)
        self.assertIn(b'/local/workspace.js',html)  # one bundled script since b52bd38; runtime.js is one of its parts
        status,_,bundle=self.request(server,'/local/workspace.js')
        self.assertEqual(status,200)
        self.assertIn(b'runtime-results',bundle)
        status,_,script=self.request(server,'/local/runtime.js')
        self.assertEqual(status,200)
        self.assertNotIn(server._session.local_token().encode(),script)

    def test_runtime_schema_db_failure_is_not_empty_success(self):
        workspace,service=self.runtime()
        server=self.server(offline=workspace,runtime=service)
        cookie,_=self.pair(server)
        status,_,raw=self.request(server,'/api/baselines/_m1/runtime',cookie=cookie)
        self.assertEqual((status,json.loads(raw)['jobs']),(200,[]))
        self.db.rename(self.db.with_suffix('.unavailable'))
        self.assertEqual(self.request(server,'/api/baselines/_m1/runtime',cookie=cookie)[0],503)


if __name__=='__main__': unittest.main()
