"""Real local JS -> HTTP -> temporary SQLite, MOCK DOM; no browser UX claim."""
import json
import subprocess
import unittest

from src.bff.baseline import BFFLimits
from src.bff.local_ui import LocalBaselineHOME
from tests.comparison.support import Fixture
from tests.ui import test_local_baseline as ui


IDS=['m4-message','m4-jobs','m4-history','m4-result','m4-baseline','m4-current','m4-diff','m4-refresh','m4-next']


class ComparisonUITests(unittest.TestCase):
    def setUp(self):
        self.fixture=Fixture(); self.addCleanup(self.fixture.close)
        self.server=None; self.addCleanup(self.stop)

    def stop(self):
        if self.server: self.assertTrue(self.server.stop())

    def run_js(self,code,**extra):
        if ui.NODE is None: self.skipTest('existing Node unavailable; no installation')
        f=self.fixture
        self.server=LocalBaselineHOME(f.db,f.root,offline=f.workspace,runtime=f.runtime,
            approval_actor='offline-ui-operator',limits=BFFLimits(request_timeout_seconds=5))
        self.server.start()
        declarations={'APP_PATH':str(ui.ROOT/'src/bff/ui/baseline.js'), 'IDS':ui.IDS+IDS,
            'PAIR_CODE':self.server.pairing_for_local_user(),'AUTHORITY':self.server.authority,
            'ORIGIN':self.server.origin,'PORT':self.server.address[1],
            'M4_PATH':str(ui.ROOT/'src/bff/ui/comparison.js'),**extra}
        harness=ui.HARNESS.replace("['tr', 'td', 'button', 'dt', 'dd', 'li']",
            "['tr','td','button','dt','dd','li','div','p','details','summary','pre']")
        harness=harness.replace('const requests = [];','const requests = []; let dropM4Reply = false;')
        harness=harness.replace('resolve({status: res.statusCode, json: async () => JSON.parse(raw)});',
            "if (dropM4Reply && path.includes('/_m4/') && options.method === 'POST') { dropM4Reply = false; reject(Error('lost reply')); return; } resolve({status: res.statusCode, json: async () => JSON.parse(raw)});")
        setup="""
Element.prototype.removeAttribute=function(name){ delete this[name]; };
const view=require(M4_PATH).create({document,fetch:fetchLocal,baseline:controller});
"""
        script='\n'.join('const '+k+' = '+json.dumps(v)+';' for k,v in declarations.items())
        script+=harness+setup+'\n(async()=>{\n'+code+"\n})().catch(e=>{process.stderr.write(e.stack);process.exitCode=1;});"
        result=subprocess.run([ui.NODE,'-'],input=script,text=True,capture_output=True,cwd=ui.ROOT,timeout=45)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,''); self.assertEqual(result.stderr,'')

    def prepared(self):
        f=self.fixture
        for job in f.run()['jobs']: f.approve(job['candidate'])
        return f.run(changed=True)

    def test_home_job_pending_review_explicit_approval_compare_images_history(self):
        state=self.prepared(); current=state['jobs'][0]
        self.run_js(r'''
await controller.start(); await view.start();
assert.equal($('m4-message').textContent,'認証が必要です');
$('pair-code').value=PAIR_CODE; await controller.pair(); await view.refresh();
assert.equal($('m4-jobs').children.length,4);
assert.ok($('m4-jobs').textContent.includes('BASELINE_PENDING'));
assert.ok($('m4-jobs').textContent.includes('Desktop')); assert.ok($('m4-jobs').textContent.includes('Mobile'));
const row=$('m4-jobs').children[0];
await row.children.find(b=>b.textContent==='Baseline詳細・明示承認').events.click();
assert.ok($('baseline-detail').textContent.includes(CANDIDATE));
assert.equal($('approval-confirm').checked,false);
$('approval-confirm').checked=true; await controller.approve(); await view.refresh();
assert.equal($('approval-message').textContent,'Baseline承認済み');
const result=await view.action('compare',JOB);
assert.equal(result.quality,'CHANGED');
assert.ok($('m4-result').textContent.includes('品質 CHANGED'));
assert.ok($('m4-result').textContent.includes('差分 1 / 64 pixels'));
assert.ok($('m4-result').textContent.includes('基準version 1'));
assert.ok($('m4-result').textContent.includes('オフライン合成検証'));
for (const name of ['m4-baseline','m4-current','m4-diff']) {
  assert.equal($(name).hidden,false); assert.ok($(name).src.startsWith('/api/baselines/_m4/result/'));
}
assert.equal($('m4-history').children.length,5);
await view.show(result.result_id); assert.ok($('m4-result').textContent.includes('元の証拠を再確認済み'));
assert.ok(requests.every(r=>r.path.startsWith('/api/baselines') || r.path==='/local/pair'));
$('m4-diff').events.error(); assert.equal($('m4-diff').hidden,true);
assert.ok($('m4-message').textContent.includes('画像を表示できません'));
''',JOB=current['job_id'],CANDIDATE=current['candidate']['candidate_id'])
        versions=self.fixture.workspace.repo.baselines.history('p',
            self.fixture.workspace.repo.baselines.get(current['candidate']['candidate_id']).candidate.profile_fingerprint)
        self.assertEqual([v.version for v in versions],[1,2])

    def test_error_session_loss_and_lost_write_reply_no_automatic_retry(self):
        state=self.prepared()
        self.run_js(r'''
await controller.start(); $('pair-code').value=PAIR_CODE; await controller.pair(); await view.start();
dropM4Reply=true; const count=$('m4-history').children.length;
const saved=await view.action('compare',JOB); assert.equal(saved,null);
assert.ok($('m4-message').textContent.includes('保存結果は未確認'));
assert.equal($('m4-history').children.length,count+1);
assert.equal(requests.filter(r=>r.path.endsWith('/_m4/compare') && r.method==='POST').length,1);
interceptedStatus=503; assert.equal(await view.refresh(),false);
assert.ok($('m4-message').textContent.includes('取得できません'));
assert.equal($('m4-jobs').children.length,0); assert.equal($('m4-diff').hidden,true);
jar=jar.split('=')[0]+'=wrong'; await view.refresh();
assert.equal($('m4-message').textContent,'認証が必要です'); assert.equal($('m4-history').children.length,0);
''',JOB=state['jobs'][0]['job_id'])

    def test_unknown_missing_and_injected_text_are_explicit(self):
        f=self.fixture
        f.workspace.save_page({'page_id':'p','label':'<img src=x onerror=evil>','path':'/','expected_revision':1})
        state=f.run(); jid=state['jobs'][0]['job_id']; rid=next(r['result_id'] for r in state['results'] if r['job_id']==jid)
        binding=f.comparison.store.body('candidates',state['jobs'][0]['candidate']['candidate_id'])
        (f.root/binding['evidence']['screenshot']['artifact_ref']).unlink()
        self.run_js(r'''
await controller.start(); $('pair-code').value=PAIR_CODE; await controller.pair(); await view.start();
assert.ok($('m4-jobs').textContent.includes('証拠'));
const result=await view.show(RESULT); assert.equal(result.quality,'UNKNOWN');
assert.ok($('m4-result').textContent.includes('元の証拠を確認できません'));
assert.equal($('m4-current').hidden,true); assert.equal($('m4-diff').hidden,true);
''',RESULT=rid)

    def test_historical_paging_is_bounded_and_available(self):
        state=self.prepared(); f=self.fixture; sample=state['results'][0]
        row=f.comparison.store.get('results',sample['result_id'])
        for n in range(26):
            rid=f'{n:032x}'
            f.comparison.store.put('results',rid,{**sample,'result_id':rid},job_id=sample['job_id'],diff=row['diff'])
        self.run_js(r'''
await controller.start(); $('pair-code').value=PAIR_CODE; await controller.pair(); await view.start();
assert.equal($('m4-history').children.length,25); assert.equal($('m4-next').disabled,false);
assert.equal(await view.moreHistory(),true); assert.equal($('m4-history').children.length,30);
assert.equal($('m4-next').disabled,true);
assert.ok(requests.some(r=>r.path.endsWith('/_m4/history/25')));
''')
