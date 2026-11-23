"""M1 acceptance: one disposable DB, valid synthetic PNGs, loopback-only HTTP.
Not formal T01-T21, browser UX, capture attestation or LOCAL-ISOLATION signoff.
"""
from contextlib import closing
import json
import io
import sqlite3
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from src.baseline.model import BaselineStatus
from src.core.offline import OfflineWorkspace
from src.comparison import preview
from src.storage.m1 import initialize, M1Error
from src.baseline.sqlite_store import SQLiteBaselineStore
from src.bff.baseline import BFFLimits
from src.bff.local_ui import LocalBaselineHOME
from tests.bff import test_baseline as fixtures
from tests.bff import test_local_ui as local
from tests.bff import test_approval as approval

PREFIX = '/api/baselines/_m1/'


class M1Tests(unittest.TestCase):
    _remove_temp = fixtures.BFFTests._remove_temp
    _stop_servers = local.LocalUITests._stop_servers
    socket = fixtures.BFFTests.socket
    request = local.LocalUITests.request
    pair = local.LocalUITests.pair
    authenticated = approval.ApprovalTests.authenticated
    payload = approval.ApprovalTests.payload
    approve = approval.ApprovalTests.approve

    def setUp(self):
        fixtures.BFFTests.setUp(self)
        initialize(self.db,self.root)
        self.workspace = OfflineWorkspace(self.db,self.root)
        self.auth = self.authenticated()

    def server(self, *, actor='fixture-local-operator', db=None):
        server = LocalBaselineHOME(db or self.db,self.root,approval_actor=actor,
            offline=self.workspace if db is None else None,limits=BFFLimits(request_timeout_seconds=3))
        server.start(); self.servers.append(server)
        return server

    def get(self,path='state'):
        status, _, raw = self.request(self.auth[0],PREFIX+path,cookie=self.auth[1])
        return status,json.loads(raw)

    def post(self,name,obj,expected=200,**headers):
        status, _, raw = self.request(self.auth[0],PREFIX+name,method='POST',cookie=self.auth[1],
            body=json.dumps(obj).encode(),headers={'X-SiteProof-CSRF':self.auth[2],**headers})
        self.assertEqual(status,expected,raw)
        return json.loads(raw)

    def site_page(self):
        self.post('site',{'label':'Fixture site','origin':'https://fixture.invalid','expected_revision':0})
        self.page('page-1')

    def page(self,key,expected=200,**changes):
        return self.post('page',{'page_id':key,'label':'ページ '+key,'path':'/'+key,
            'expected_revision':0,**changes},expected)

    def capture(self,name='original',kind='Desktop'):
        return self.post('fixture',{'page_id':'page-1','kind':kind,'fixture':name})

    def candidate(self,capture):
        return self.post('candidate',{'capture_id':capture['capture_id']})

    def baseline(self):
        capture = self.capture()
        candidate = self.candidate(capture)
        self.assertEqual(self.approve(self.auth,self.payload(candidate['candidate_id']))[0],200)
        return capture,candidate

    def compare(self,capture,candidate):
        return self.post('compare',{'capture_id':capture['capture_id'],'baseline_id':candidate['candidate_id']})

    def test_M01_five_pages_sixth_rejected_site_and_page_edit_cas(self):
        self.site_page()
        for n in range(2,6): self.page('page-'+str(n))
        self.page('page-6',409)
        self.assertEqual(len(self.get()[1]['pages']),5)
        self.page('page-1',expected_revision=1,label='編集済み',path='/edited')
        self.page('page-1',409,expected_revision=1)
        self.assertEqual(self.get()[1]['pages'][0]['label'],'編集済み')
        self.post('site',{'label':'second','origin':'https://other.invalid','expected_revision':1},409)
        with self.workspace.repo.write() as c:
            with self.assertRaises(sqlite3.IntegrityError):
                c.execute("INSERT INTO m1_pages VALUES('bypass','label','/',1)")

    def test_M02_desktop_mobile_profiles_independent_immutable_revisions(self):
        self.site_page()
        before = self.capture()
        profiles = self.get()[1]['profiles']
        desktop = next(p for p in profiles if p['kind']=='Desktop')
        mobile = next(p for p in profiles if p['kind']=='Mobile')
        self.assertNotEqual(desktop['fingerprint'],mobile['fingerprint'])
        self.post('profile',{'page_id':'page-1','kind':'Desktop','width':1200,'height':800,'expected_revision':1})
        self.post('profile',{'page_id':'page-1','kind':'Desktop','width':1100,'height':800,'expected_revision':1},409)
        current = self.get()[1]['profiles']
        self.assertEqual(next(p for p in current if p['kind']=='Mobile'),mobile)
        self.assertEqual(self.workspace.capture(before['capture_id'])['fingerprint'],desktop['fingerprint'])
        self.assertNotEqual(self.capture()['profile_fingerprint'],desktop['fingerprint'])

    def test_M03_candidate_confirmation_approval_and_old_history_preservation(self):
        self.site_page(); old_capture, old = self.baseline()
        old_record = self.store.get(old['candidate_id'])
        new = self.candidate(self.capture('changed'))
        bad = self.payload(new['candidate_id'],expected_current_version=1,reviewed_digest='f'*64)
        self.assertEqual(self.approve(self.auth,bad)[0],422)
        self.assertEqual(self.approve(self.auth,self.payload(new['candidate_id'],expected_revision=9,expected_current_version=1))[0],409)
        self.assertEqual(self.approve(self.auth,self.payload(new['candidate_id'],expected_current_version=1))[0],200)
        self.assertEqual(self.store.get(old['candidate_id']),old_record)
        self.assertEqual(len(self.store.history('page-1',old_capture['profile_fingerprint'])),2)
        # Explicit old version stays selected even after adoption of version 2.
        result = self.compare(self.capture('changed'),old)
        self.assertEqual(result['baseline_version'],1)

    def test_M04_real_png_diff_save_reopen_and_authenticated_images(self):
        self.site_page(); before, base = self.baseline(); current = self.capture('changed')
        result = self.compare(current,base)
        self.assertEqual(result['metrics']['changed_pixels'],1)
        self.assertEqual(result['metrics']['total_pixels'],64)
        self.assertEqual(result['assessment']['quality'],'UNKNOWN')
        self.assertTrue(result['preview_only'])
        reopened = OfflineWorkspace(self.db,self.root)
        self.assertEqual(reopened.result(result['result_id']),result)
        digest_before = self.db.read_bytes()
        self.assertEqual(self.get('result/'+result['result_id'])[1],result)
        for path in ('image/'+before['capture_id'],'image/'+current['capture_id'],'diff/'+result['result_id']):
            status, headers, image = self.request(self.auth[0],PREFIX+path,cookie=self.auth[1])
            self.assertEqual(status,200); self.assertEqual(headers['Content-Type'],'image/png')
            self.assertEqual(preview.decode(image)[:2],(8,8))
        self.assertEqual(self.db.read_bytes(),digest_before)
        self.assertEqual(len(self.get()[1]['results']),1)

    def test_M05_equal_pixels_are_preview_only_unknown(self):
        self.site_page(); before, base = self.baseline()
        result = self.compare(before,base)
        self.assertEqual(result['metrics']['changed_pixels'],0)
        self.assertEqual(result['assessment']['comparison'],'NOT_RUN')
        self.assertEqual(result['assessment']['quality'],'UNKNOWN')

    def test_M06_profile_mismatch_missing_and_pending_remain_unknown(self):
        self.site_page(); _, base = self.baseline()
        for capture in (self.capture(kind='Mobile'),self.capture('profile-mismatch')):
            result = self.compare(capture,base)
            self.assertIn('PROFILE_MISMATCH',result['reasons']); self.assertIsNone(result['metrics'])
        missing = self.capture('missing')
        result = self.compare(missing,base)
        self.assertIn('EVIDENCE_MISSING',result['reasons'])
        self.post('candidate',{'capture_id':missing['capture_id']},400)
        self.assertEqual(self.request(self.auth[0],PREFIX+'image/'+missing['capture_id'],cookie=self.auth[1])[0],404)
        pending = self.candidate(self.capture('changed'))
        result = self.compare(self.capture(),pending)
        self.assertIn('BASELINE_PENDING',result['reasons']); self.assertIsNone(result['metrics'])
        self.assertEqual(self.store.get(pending['candidate_id']).status,BaselineStatus.PENDING)

    def test_M07_all_mutations_require_session_csrf_and_exact_origin(self):
        before = self.db.read_bytes()
        server,cookie,csrf = self.auth
        for name in ('site','page','profile','fixture','candidate','compare'):
            for headers in ({'X-SiteProof-CSRF':''},{'X-SiteProof-CSRF':'wrong'},
                            {'Origin':'null'},{'Host':'evil.invalid'},{'Sec-Fetch-Site':'cross-site'},
                            {'Content-Type':'text/plain'}):
                status,_,_ = self.request(server,PREFIX+name,method='POST',cookie=cookie,body=b'{}',
                    headers={'X-SiteProof-CSRF':csrf,**headers})
                self.assertIn(status,(400,403))
            self.assertEqual(self.request(server,PREFIX+name,method='POST',body=b'{}')[0],401)
            self.assertEqual(self.request(server,PREFIX+name,cookie=cookie)[0],405)
        self.assertEqual(self.db.read_bytes(),before)
        server._session._expires = 0
        self.assertEqual(self.request(server,PREFIX+'state',cookie=cookie)[0],401)

    def test_M08_save_failure_rolls_back_result_no_false_success(self):
        self.site_page(); _, base = self.baseline(); current = self.capture('changed')
        original = SQLiteBaselineStore._connect
        def fail(store,readonly):
            conn = original(store,readonly)
            if not readonly:
                conn.set_authorizer(lambda action,table,*a: sqlite3.SQLITE_DENY
                    if action==sqlite3.SQLITE_INSERT and table=='m1_results' else sqlite3.SQLITE_OK)
            return conn
        before = self.db.read_bytes()
        with patch.object(SQLiteBaselineStore,'_connect',fail):
            self.post('compare',{'capture_id':current['capture_id'],'baseline_id':base['candidate_id']},503)
        self.assertEqual(self.db.read_bytes(),before)
        self.assertEqual(self.get()[1]['results'],[])

    def test_M09_get_does_not_initialize_m1_and_no_arbitrary_path_sql_or_write_routes(self):
        path = self.root/'without-m1.sqlite'
        SQLiteBaselineStore.create(path,self.root)
        server = self.server(db=path)
        cookie,_ = self.pair(server)
        before = path.read_bytes()
        self.assertEqual(self.request(server,PREFIX+'state',cookie=cookie)[0],503)
        self.assertEqual(path.read_bytes(),before)
        with self.assertRaises(M1Error): OfflineWorkspace(path,self.root)
        self.assertEqual(path.read_bytes(),before)
        for route in ('state?db=C:/secret','sql','image/../../secret','result/not-a-key'):
            self.assertEqual(self.get(route)[0],404)
        self.assertEqual(fixtures.BFFTests.request(self,server.backend,PREFIX+'state')[0],404)
        self.assertEqual(fixtures.BFFTests.request(self,server.backend,PREFIX+'site',method='POST')[0],405)

    def test_M10_immutable_images_results_and_existing_baseline_tables(self):
        self.site_page(); before,base = self.baseline(); result = self.compare(self.capture('changed'),base)
        for table,statement in (('m1_captures',"UPDATE m1_captures SET png=x'00'"),
                                ('m1_results','DELETE FROM m1_results'),('m1_profiles','DELETE FROM m1_profiles')):
            with self.workspace.repo.write() as c:
                with self.assertRaises(sqlite3.IntegrityError): c.execute(statement)
        self.assertEqual(self.workspace.result(result['result_id']),result)
        self.assertEqual(self.workspace.capture(before['capture_id'])['sha256'],before['sha256'])
        self.assertTrue(SQLiteBaselineStore.open(self.db,self.root).get(base['candidate_id']).is_valid_approval())

    def test_M11_page_and_site_input_rejections_do_not_fetch_urls(self):
        for url in ('http://fixture.invalid','https://user:secret@fixture.invalid','https://fixture.invalid/path','https://fixture.invalid?secret=1'):
            self.post('site',{'label':'bad','origin':url,'expected_revision':0},400)
        self.site_page()
        for path in ('//evil.invalid','https://evil.invalid','/page?secret=1','/page#fragment','/\\host'):
            self.page('invalid',400,path=path)
        self.assertEqual(len(self.get()[1]['pages']),1)

    def test_M12_preview_image_refusal_and_decompression_limits(self):
        original = preview.fixture('original')
        self.assertEqual(preview.decode(original)[:2],(8,8))
        for bad in (b'not png',original[:-1],original+b'extra',original[:30]+b'bad crc'+original[37:]):
            with self.assertRaises(preview.PreviewError): preview.decode(bad)
        with self.assertRaises(preview.PreviewError): preview.png(4096,4096,b'')
        for w,h in ((-1,-1),(True,1),(1,0)):
            with self.assertRaises(preview.PreviewError): preview.png(w,h,b'\0'*4)
        smaller = preview.png(1,1,bytes((0,0,0,255)))
        with self.assertRaises(preview.PreviewError): preview.compare(original,smaller)

    def test_M13_s1_finalizer_and_evidence_reader_share_database_without_promotion(self):
        from src.core.model import JobIntent, JobStatus
        from src.core.frames import CheckType
        from src.bridge import EvidenceBridge
        from src.bridge.s1_evidence import read_s1_capture
        from src.storage.repository import Repository
        from src.storage.artifacts import ArtifactStore
        from src.storage.finalizer import EvidenceFinalizer, CommitState
        from tests.integration.fixtures import complete, stream
        from tests.integration.s1_s2_fixtures import FoundationCase
        repo = Repository(self.db)
        repo.init()
        artifacts = ArtifactStore(self.root/'s1-evidence')
        finalizer = EvidenceFinalizer(repo,artifacts)
        job = repo.accept_job('m1-s1-compat',JobIntent('https://fixture.invalid/','page-1','profile-1',tuple(CheckType))).job
        attempt = repo.register_attempt(job.job_id,'attempt-1',1)
        for status in (JobStatus.WAITING_WORKER,JobStatus.RUNNING,JobStatus.SAVING):
            job = repo.transition(job.job_id,job.version,status)
        result = EvidenceBridge(finalizer).finalize(job.job_id,attempt.attempt_id,io.BytesIO(stream(complete())))
        self.assertEqual(result.outcome.commit_state,CommitState.COMMITTED)
        job = repo.get_job(job.job_id)
        declaration = FoundationCase.binding_for(SimpleNamespace(repo=repo,store=artifacts),job,attempt)
        read = read_s1_capture(self.db,artifacts.root,job.job_id,profile_declaration=declaration)
        self.assertTrue(read.accepted,read.rejection)
        self.assertEqual(read.evidence.unattested_profile.trust.value,'UNATTESTED')
        originals = {p:p.read_bytes() for p in artifacts.root.rglob('*') if p.is_file()}
        self.site_page(); self.baseline()
        self.assertEqual(repo.get_job(job.job_id),job)
        self.assertEqual({p:p.read_bytes() for p in originals},originals)
        self.assertEqual(len(self.get()[1]['captures']),1)


if __name__ == '__main__': unittest.main()
