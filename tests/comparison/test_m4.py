"""M4 acceptance contracts: synthetic pixels, temporary SQLite, no live jobs."""
import copy
import hashlib
import json
import sqlite3
import secrets
import unittest
from unittest.mock import patch

from src.baseline.approval import AlreadyDecided, RevisionConflict
from src.comparison import preview
from src.comparison.provenance import TrustedProfileAuthority, fingerprint
from src.comparison.service import ComparisonService, PixelPolicy
from src.core.offline import OfflineWorkspace
from src.core.offline import read_profile
from src.storage.comparison import initialize
from src.storage.m1 import M1Error
from tests.comparison.support import Fixture, KEY, observations


class ComparisonAcceptanceTests(unittest.TestCase):
    def fixture(self, **kwargs):
        f = Fixture(**kwargs); self.addCleanup(f.close); return f

    def approved(self, f):
        state = f.run()
        for job in state['jobs']: f.approve(job['candidate'])
        return state

    def test_initial_capture_pending_and_explicit_approval_versions(self):
        f = self.fixture(); state = f.run()
        self.assertEqual(len(state['jobs']), 2)
        for job in state['jobs']:
            self.assertEqual(job['candidate']['approval_state'], 'PENDING')
            self.assertIsNone(job['candidate']['version'])
        self.assertTrue(all(r['quality'] == 'UNKNOWN' and 'BASELINE_PENDING' in r['reasons'] for r in state['results']))
        self.approve_jobs(f, state)
        self.assertTrue(all(j['candidate']['approval_state'] == 'APPROVED' and j['candidate']['version'] == 1 for j in f.comparison.state()['jobs']))
        # Approval never changes the baseline pinned by these first jobs.
        self.assertTrue(all(r['baseline'] is None for r in f.comparison.state()['results']))

    @staticmethod
    def approve_jobs(f, state):
        for job in state['jobs']: f.approve(job['candidate'])

    def test_same_image_pass_and_change_observed_with_diff_and_checks_unchanged(self):
        f = self.fixture(); self.approved(f)
        state = f.run()
        newest = state['results'][:2]
        self.assertEqual({r['quality'] for r in newest}, {'PASS'})
        for result in newest:
            self.assertEqual(result['metrics']['changed_pixels'], 0)
            self.assertEqual(result['trust_domain'], 'OFFLINE_TEST')
            self.assertEqual(result['profile_trust'], 'TRUSTED_TEST')
            self.assertEqual(next(c['outcome'] for c in result['checks'] if c['type'] == 'CAPTURE'), 'UNKNOWN')
        result = f.run(changed=True)['results'][0]
        self.assertEqual(result['quality'], 'CHANGED')
        self.assertEqual(result['metrics']['changed_pixels'], 1)
        for role in ('baseline','current','diff'):
            data = f.comparison.result_image(result['result_id'], role)
            self.assertEqual(preview.decode(data)[:2], (8,8))
        self.assertEqual(preview.digest(f.comparison.result_image(result['result_id'],'diff')),result['diff_sha256'])

    def test_missing_or_untrusted_source_for_every_required_field_prohibits_pass(self):
        f = self.fixture(); self.approved(f); state = f.run()
        jid = state['jobs'][0]['job_id']
        envelope, plan, evidence, _ = f.comparison.observe(jid)
        receipt = f.comparison.store.body('receipts',jid)['body']
        names = list(observations(read_profile(plan['profile']),'prepare',None))
        original = f.comparison.store.get
        for name in names:
            with self.subTest(field=name):
                broken_plan, broken_receipt = copy.deepcopy(plan), copy.deepcopy(receipt)
                if name == 'stability_result':
                    broken_receipt['stability'] = None
                else:
                    broken_plan['settings'].pop(name); broken_receipt['post'].pop(name)
                signed_plan = f.authority.sign(broken_plan)
                broken_receipt['plan_sha256'] = fingerprint(signed_plan)
                signed_receipt = {'body':json.dumps(f.authority.sign(broken_receipt))}
                def missing(table,key):
                    return signed_receipt if table == 'receipts' and key == jid else original(table,key)
                with patch.object(f.comparison.store,'get',side_effect=missing):
                    trust, reason = f.comparison.trust(signed_plan,broken_plan,evidence)
                self.assertEqual(trust,'UNATTESTED')
                self.assertIn(reason, ('PROFILE_UNATTESTED','CAPTURE_UNSTABLE'))

    def test_browser_self_report_is_not_a_trusted_observation(self):
        def browser(profile, phase, jid):
            data = observations(profile, phase, jid)
            data['browser_version']['source'] = 'browser:self-report'
            return data
        f = self.fixture(observer=browser); self.approved(f)
        self.assertEqual(f.run()['results'][0]['quality'],'UNKNOWN')

    def test_unattested_capture_can_be_human_reviewed_but_never_quality_pass(self):
        f = self.fixture(trusted=False); self.approved(f)
        result = f.run()['results'][0]
        self.assertEqual(result['quality'],'UNKNOWN')
        self.assertIn('PROFILE_UNATTESTED',result['reasons'])
        self.assertIsNone(result['diff_sha256'])

    def test_missing_threshold_stays_unknown_with_no_default(self):
        f = self.fixture(threshold=False); self.approved(f)
        result = f.run()['results'][0]
        self.assertEqual(result['quality'],'UNKNOWN')
        self.assertIn('THRESHOLD_UNDEFINED',result['reasons'])
        self.assertIsNone(result['policy'])

    def test_profile_mismatch_in_extended_runtime_field(self):
        f = self.fixture(); self.approved(f)
        def changed(profile, phase, jid):
            result = observations(profile, phase, jid)
            result['fonts_digest']['value'] = 'c'*64
            return result
        f.authority._observer = changed
        result = f.run()['results'][0]
        self.assertEqual(result['quality'],'UNKNOWN')
        self.assertIn('PROFILE_MISMATCH',result['reasons'])

    def test_capture_time_change_from_prepared_plan_is_not_authenticated(self):
        def changing(profile, phase, jid):
            data = observations(profile,phase,jid)
            if phase == 'captured': data['browser_version']['value'] = 'different'
            return data
        f = self.fixture(observer=changing); self.approved(f)
        result = f.run()['results'][0]
        self.assertEqual(result['quality'],'UNKNOWN')
        self.assertIn('PROFILE_ATTESTATION_MISMATCH',result['reasons'])

    def test_wrong_key_and_replayed_other_job_receipt_are_unattested(self):
        f = self.fixture(); self.approved(f); state = f.run()
        wrong = ComparisonService(f.workspace, authority=TrustedProfileAuthority(secrets.token_bytes(32),observations,domain='OFFLINE_TEST'),policy=f.policy)
        self.assertEqual(wrong.compare(state['jobs'][0]['job_id'])['quality'],'UNKNOWN')
        # Even a valid MAC on an unrelated receipt cannot bind another manifest.
        original = f.comparison.store.get
        first, second = state['jobs'][:2]
        def replay(table, key):
            return original(table, second['job_id'] if table == 'receipts' and key == first['job_id'] else key)
        with patch.object(f.comparison.store,'get',side_effect=replay):
            result = f.comparison.compare(first['job_id'])
        self.assertEqual(result['quality'],'UNKNOWN')
        self.assertIn('PROFILE_ATTESTATION_MISMATCH',result['reasons'])

    def test_immutable_head_pin_survives_later_approval_and_old_history(self):
        f = self.fixture(); old = self.approved(f)
        batch = f.runtime.submit()
        newer = f.run(changed=True)
        self.approve_jobs(f,{'jobs':newer['jobs'][:2]})
        state = f.run(batch=batch)
        result = next(r for r in state['results'] if r['job_id'] in
                      [jid for jid,_,_ in f.runtime.store.bindings(batch)])
        self.assertEqual(result['baseline']['version'],1)
        self.assertEqual(result['quality'],'PASS')
        for job in old['jobs']:
            record = f.workspace.repo.baselines.get(job['candidate']['candidate_id'])
            versions = f.workspace.repo.baselines.history(record.candidate.page_id,record.candidate.profile_fingerprint)
            self.assertEqual([v.version for v in versions],[1,2])
            self.assertEqual(versions[0].record.candidate.candidate_id,record.candidate.candidate_id)

    def test_approval_cas_conflict_and_repeated_decision_do_not_add_version(self):
        f = self.fixture(); state = f.run()
        candidate = state['jobs'][0]['candidate']; f.approve(candidate)
        with self.assertRaises(AlreadyDecided): f.approve(candidate)
        newer = f.run()['jobs'][0]['candidate']
        with self.assertRaises(RevisionConflict): f.approve(newer,current=0)
        self.assertEqual(f.comparison.candidate_view(newer['candidate_id'])['approval_state'],'PENDING')

    def test_corrupt_or_missing_png_and_manifest_cannot_pass_or_be_approved(self):
        for target in ('screenshot','manifest'):
            for mutation in ('corrupt','missing'):
                with self.subTest(target=target,mutation=mutation):
                    f = self.fixture(); state = self.approved(f)
                    candidate = state['jobs'][0]['candidate']
                    binding = f.comparison.store.body('candidates',candidate['candidate_id'])
                    path = f.root/binding['evidence'][target]['artifact_ref']
                    if mutation == 'corrupt': path.write_bytes(b'invalid synthetic corruption')
                    else: path.unlink()
                    with self.assertRaises(M1Error): f.comparison.validate_candidate(candidate['candidate_id'])
                    next_state = f.run()
                    result = next(r for r in next_state['results'] if r['kind'] == state['jobs'][0]['kind'])
                    self.assertEqual(result['quality'],'UNKNOWN')
                    self.assertFalse(path.exists() if mutation == 'missing' else path.read_bytes() != b'invalid synthetic corruption')

    def test_failed_http_bad_png_cleanup_and_timeout_never_create_approved_candidates(self):
        for kwargs in ({'status':404},{'bad':True},{'clean':False}):
            with self.subTest(kwargs=kwargs):
                f = self.fixture(); state = f.run(**kwargs)
                self.assertTrue(all(j['candidate'] is None for j in state['jobs']))
                self.assertTrue(all(r['quality'] in ('UNKNOWN','FAIL') for r in state['results']))
                self.assertEqual(f.workspace.repo.baselines.read_page(limit=100).items,())
                if 'status' in kwargs:
                    self.assertEqual(state['results'][0]['quality'],'FAIL')
                    self.assertIn('SKIPPED',[c['outcome'] for c in state['results'][0]['checks']])

    def test_proxy_cleanup_unconfirmed_and_unstable_capture_never_pass(self):
        f = self.fixture(); self.approved(f)
        self.assertEqual(f.run(proxy_clean=False)['results'][0]['quality'],'UNKNOWN')
        def unstable(profile, phase, jid):
            data=observations(profile,phase,jid)
            data['stability_result']['value']='UNSTABLE'
            return data
        g=self.fixture(observer=unstable); self.approved(g)
        self.assertEqual(g.run()['results'][0]['quality'],'UNKNOWN')

    def test_five_pages_desktop_mobile_limit_and_profile_revision_pin(self):
        f=self.fixture()
        for n in range(2,6):
            f.workspace.save_page({'page_id':f'p{n}','label':str(n),'path':f'/{n}','expected_revision':0})
            for kind in ('Desktop','Mobile'):
                f.workspace.save_profile({'page_id':f'p{n}','kind':kind,'width':8,'height':8,'expected_revision':1})
        with self.assertRaisesRegex(M1Error,'PAGE_LIMIT'):
            f.workspace.save_page({'page_id':'p6','label':'6','path':'/6','expected_revision':0})
        batch=f.runtime.submit()
        f.workspace.save_profile({'page_id':'p','kind':'Desktop','width':9,'height':8,'expected_revision':2})
        state=f.run(batch=batch)
        self.assertEqual(len(state['jobs']),10)
        self.assertEqual({j['kind'] for j in state['jobs']},{'Desktop','Mobile'})
        self.assertTrue(all(j['profile']['attributes']['viewport_width']==8 for j in state['jobs']))

    def test_sqlite_reopen_readonly_and_evidence_write_once(self):
        f=self.fixture(); self.approved(f); state=f.run(changed=True)
        before={str(p.relative_to(f.root)):hashlib.sha256(p.read_bytes()).hexdigest()
                for p in f.root.rglob('*') if p.is_file()}
        reopened=ComparisonService(OfflineWorkspace(f.db,f.root),authority=TrustedProfileAuthority(KEY,observations,domain='OFFLINE_TEST'),policy=f.policy)
        original=sqlite3.connect
        def read_only(path,**kwargs):
            self.assertIn('mode=ro',str(path)); self.assertTrue(kwargs.get('uri')); return original(path,**kwargs)
        with patch('sqlite3.connect',side_effect=read_only): self.assertEqual(reopened.state(),state)
        self.assertEqual(before,{str(p.relative_to(f.root)):hashlib.sha256(p.read_bytes()).hexdigest()
                for p in f.root.rglob('*') if p.is_file()})
        with self.assertRaises(M1Error): initialize(f.db,f.root)
        for table in ('m4_jobs','m4_receipts','m4_candidates','m4_results'):
            with self.assertRaises(M1Error):
                with f.workspace.repo.write() as c: c.execute(f'DELETE FROM {table}')
        source_before={k:v for k,v in before.items() if k.endswith('.png') or k.endswith('manifest.json')}
        f.comparison.compare(state['jobs'][0]['job_id'])
        self.assertEqual(source_before,{str(p.relative_to(f.root)):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in f.root.rglob('*') if p.is_file() and (p.name.endswith('.png') or p.name=='manifest.json')})

    def test_no_retroactive_m3_plan_or_receipt(self):
        f=self.fixture(); f.runtime.comparison=None
        raw=f.runtime.submit(source='REAL_CHROMIUM_FIXTURE_UNATTESTED'); f.run(batch=raw)
        self.assertEqual(f.comparison.state()['jobs'],[])
        for jid,_,body in f.runtime.store.bindings(raw):
            with self.assertRaisesRegex(M1Error,'CAPTURE_PLAN_TOO_LATE'):
                f.comparison.bind(f.repo.get_job(jid),f.comparison.prepare(
                    read_profile(body['profile']),
                    'p',body['kind'],body['source']))
            with self.assertRaises(M1Error): f.comparison.attest(jid)

    def test_explicit_threshold_validation(self):
        for value in (-1,True,float('nan'),None):
            with self.assertRaises(ValueError): PixelPolicy(value,'explicit')
        with self.assertRaises(ValueError): PixelPolicy(0,'')

    def test_capture_dimensions_cannot_be_relabelled_as_the_declared_viewport(self):
        f=self.fixture(); self.approved(f)
        wrong=preview.png(7,8,b'\0\0\0\xff'*(7*8))
        with patch('tests.comparison.support.Driver.capture',return_value=wrong):
            state=f.run()
        self.assertTrue(all(j['candidate'] is None for j in state['jobs'][:2]))
        self.assertTrue(all(r['quality']=='UNKNOWN' and 'CAPTURE_DIMENSIONS_MISMATCH' in r['reasons']
                            for r in state['results'][:2]))

    def test_offline_receipt_cannot_authenticate_a_real_source_and_cannot_be_resealed(self):
        f=self.fixture(); batch=f.runtime.submit(source='REAL_CHROMIUM_FIXTURE_UNATTESTED')
        state=f.run(batch=batch)
        for job in state['jobs']:
            self.assertEqual(job['profile_trust'],'UNATTESTED')
            with self.assertRaisesRegex(M1Error,'CAPTURE_RECEIPT_TOO_LATE'):
                f.comparison.attest(job['job_id'])

    def test_png_bounds_real_viewport_and_size_format_refusal(self):
        data=preview.png(1440,900,b'\0\0\0\xff'*(1440*900),max_pixels=4*1024*1024)
        self.assertEqual(preview.decode(data,max_pixels=4*1024*1024,max_bytes=32*1024*1024)[:2],(1440,900))
        with self.assertRaises(preview.PreviewError): preview.decode(data)
        with self.assertRaisesRegex(preview.PreviewError,'IMAGE_SIZE_MISMATCH'):
            preview.compare(preview.png(8,8,b'\0'*256),preview.png(7,8,b'\0'*224))


if __name__=='__main__': unittest.main()
