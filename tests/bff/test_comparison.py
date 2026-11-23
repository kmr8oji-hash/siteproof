"""Authenticated M4 routes and existing explicit human approval, temporary DB."""
import json
from http.client import HTTPResponse
import socket
import random
import unittest

from src.bff.baseline import BFFLimits
from src.bff.local_ui import LocalBaselineHOME
from src.comparison import preview
from unittest.mock import patch
from tests.comparison.support import Fixture


class ComparisonGatewayTests(unittest.TestCase):
    def setUp(self):
        self.fixture=Fixture(); self.addCleanup(self.fixture.close)
        self.root,self.db=self.fixture.root,self.fixture.db
        self.servers=[]; self.addCleanup(self.stop_servers)

    def stop_servers(self):
        for server in self.servers: self.assertTrue(server.stop())

    def server(self, **kwargs):
        server=LocalBaselineHOME(self.db,self.root,**kwargs)
        server.start(); self.servers.append(server); return server

    def request(self,server,path,*,method='GET',cookie=None,headers=None,body=None):
        fields={'Host':server.authority}
        if cookie: fields['Cookie']=cookie
        if body is not None:
            fields.update({'Origin':server.origin,'Content-Type':'application/json',
                           'Sec-Fetch-Site':'same-origin','X-SiteProof-Pair':'1',
                           'Content-Length':str(len(body))})
        fields.update(headers or {})
        raw=(method+' '+path+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in fields.items())+'\r\n').encode()+(body or b'')
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as client:
            client.settimeout(8); client.connect(('127.0.0.1',server.address[1])); client.sendall(raw)
            with HTTPResponse(client) as response:
                response.begin(); data=response.read(); result_headers=dict(response.getheaders())
                self.assertEqual(result_headers['Cache-Control'],'no-store')
                self.assertEqual(result_headers['X-Content-Type-Options'],'nosniff')
                self.assertNotIn('Access-Control-Allow-Origin',result_headers)
                return response.status,result_headers,data

    def pair(self,server):
        raw=json.dumps({'pairing_code':server.pairing_for_local_user()}).encode()
        status,headers,_=self.request(server,'/local/pair',method='POST',body=raw)
        self.assertEqual(status,200)
        self.assertIn('HttpOnly',headers['Set-Cookie']); self.assertIn('SameSite=Strict',headers['Set-Cookie'])
        return headers['Set-Cookie'].split(';')[0],raw

    def start(self, **kwargs):
        f=self.fixture
        return self.server(offline=f.workspace,runtime=f.runtime,approval_actor='offline-local-operator',
                           limits=BFFLimits(request_timeout_seconds=5),**kwargs)

    def post(self,server,cookie,name,body,**kwargs):
        status,_,raw=self.request(server,'/api/baselines/_approval/session',cookie=cookie,
            headers={'X-SiteProof-UI':'1','Sec-Fetch-Site':'same-origin'})
        self.assertEqual(status,200)
        token=json.loads(raw)['csrf_token']
        return self.request(server,name,method='POST',cookie=cookie,body=json.dumps(body).encode(),
            headers={'X-SiteProof-CSRF':token,**kwargs})

    def test_first_pending_explicit_approval_images_diff_and_history(self):
        f=self.fixture; state=f.run(); server=self.start(); cookie,_=self.pair(server)
        for job in state['jobs']:
            cid=job['candidate']['candidate_id']
            status,_,raw=self.request(server,'/api/baselines/'+cid,cookie=cookie)
            item=json.loads(raw)['baseline']; self.assertEqual(item['approval_state'],'PENDING')
            body={'candidate_id':cid,'expected_revision':item['revision'],'reviewed_digest':item['candidate_digest'],
                  'expected_current_version':0,'confirmed':True}
            no_confirm={**body,'confirmed':False}
            self.assertEqual(self.post(server,cookie,'/api/baselines/_approval/approve',no_confirm)[0],400)
            self.assertEqual(self.post(server,cookie,'/api/baselines/_approval/approve',body)[0],200)
            self.assertEqual(self.post(server,cookie,'/api/baselines/_approval/approve',body)[0],409)
        current=f.run(changed=True)['results'][0]; rid=current['result_id']
        status,_,raw=self.request(server,'/api/baselines/_m4/state',cookie=cookie)
        self.assertEqual(status,200); self.assertEqual(json.loads(raw)['results'][0]['quality'],'CHANGED')
        before=f.db.read_bytes()
        for role in ('baseline','current','diff'):
            status,headers,raw=self.request(server,f'/api/baselines/_m4/result/{rid}/{role}',cookie=cookie)
            self.assertEqual(status,200); self.assertEqual(headers['Content-Type'],'image/png'); self.assertTrue(raw.startswith(b'\x89PNG'))
        self.assertEqual(f.db.read_bytes(),before)
        status,_,raw=self.request(server,'/api/baselines/_m4/history/0',cookie=cookie)
        self.assertEqual(status,200); self.assertEqual(len(json.loads(raw)['results']),4)

    def test_pairing_host_origin_csrf_session_and_no_start_or_arbitrary_path(self):
        f=self.fixture; state=f.run(); jid=state['jobs'][0]['job_id']; server=self.start()
        path='/api/baselines/_m4/state'
        self.assertEqual(self.request(server,path)[0],401)
        cookie,_=self.pair(server)
        for headers in ({'Host':'localhost:123'},{'Origin':'null'},{'Origin':'https://evil.invalid'},{'Sec-Fetch-Site':'cross-site'}):
            self.assertEqual(self.request(server,path,cookie=cookie,headers=headers)[0],403)
        for headers in ({},{'X-SiteProof-CSRF':'wrong'}):
            self.assertEqual(self.request(server,'/api/baselines/_m4/compare',method='POST',cookie=cookie,
                headers=headers,body=json.dumps({'job_id':jid}).encode())[0],403)
        for path in ('start','run','image/../state.sqlite','image/C:/secret','state?db=secret','result/'+'a'*32+'/../state.sqlite'):
            self.assertNotEqual(self.request(server,'/api/baselines/_m4/'+path,cookie=cookie)[0],200)
        status,_,_=self.post(server,cookie,'/api/baselines/_m4/compare',{'job_id':jid,'baseline_id':'injected'})
        self.assertEqual(status,400)
        status,_,raw=self.post(server,cookie,'/api/baselines/_m4/compare',{'job_id':jid})
        self.assertEqual(status,200); self.assertEqual(json.loads(raw)['quality'],'UNKNOWN')
        server.destroy_session(); self.assertEqual(self.request(server,'/api/baselines/_m4/image/'+jid,cookie=cookie)[0],401)

    def test_missing_evidence_refuses_approval_and_history_marks_historical_result(self):
        f=self.fixture; state=f.run(); job=state['jobs'][0]; cid=job['candidate']['candidate_id']
        binding=f.comparison.store.body('candidates',cid)
        (f.root/binding['evidence']['manifest']['artifact_ref']).unlink()
        server=self.start(); cookie,_=self.pair(server)
        status,_,raw=self.request(server,'/api/baselines/'+cid,cookie=cookie)
        item=json.loads(raw)['baseline']
        body={'candidate_id':cid,'expected_revision':item['revision'],'reviewed_digest':item['candidate_digest'],
              'expected_current_version':0,'confirmed':True}
        self.assertNotEqual(self.post(server,cookie,'/api/baselines/_approval/approve',body)[0],200)
        self.assertEqual(f.comparison.candidate_view(cid)['approval_state'],'PENDING')
        result=next(r for r in state['results'] if r['job_id']==job['job_id'])
        status,_,raw=self.request(server,'/api/baselines/_m4/result/'+result['result_id'],cookie=cookie)
        self.assertEqual(status,200); self.assertEqual(json.loads(raw)['source_availability'],'UNAVAILABLE')
        self.assertNotEqual(self.request(server,'/api/baselines/_m4/image/'+job['job_id'],cookie=cookie)[0],200)

    def test_unavailable_extension_is_explicit_and_never_initialized_by_get(self):
        f=self.fixture
        f.runtime.comparison=None
        server=self.start(); cookie,_=self.pair(server)
        before=f.db.read_bytes()
        status,_,raw=self.request(server,'/api/baselines/_m4/state',cookie=cookie)
        self.assertEqual(status,503); self.assertEqual(json.loads(raw)['error']['code'],'COMPARISON_UNAVAILABLE')
        self.assertEqual(before,f.db.read_bytes())

    def test_verified_png_larger_than_json_budget_is_bounded_local_binary(self):
        f=self.fixture
        for kind in ('Desktop','Mobile'):
            f.workspace.save_profile({'page_id':'p','kind':kind,'width':280,'height':280,'expected_revision':2})
        pixels=random.Random(0).randbytes(280*280*4)
        data=preview.png(280,280,pixels,max_pixels=4*1024*1024)
        self.assertGreater(len(data),256*1024)
        with patch('tests.comparison.support.Driver.capture',return_value=data):
            state=f.run()
        server=self.start(); cookie,_=self.pair(server)
        before=f.db.read_bytes()
        status,headers,raw=self.request(server,'/api/baselines/_m4/image/'+state['jobs'][0]['job_id'],cookie=cookie)
        self.assertEqual(status,200); self.assertEqual(raw,data)
        self.assertEqual(headers['Content-Type'],'image/png'); self.assertEqual(before,f.db.read_bytes())
