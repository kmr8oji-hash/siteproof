"""Actual local JS + mock DOM + temporary SQLite gateway; NO browser or external I/O."""
import hashlib
import json
from pathlib import Path
import subprocess
import unittest

from src.core.offline import OfflineWorkspace
from src.comparison import preview
from src.bff.local_ui import LocalBaselineHOME
from src.bff.baseline import BFFLimits
from tests.ui import test_local_baseline as ui

IDS = ['m1-message','m1-site-label','m1-site-origin','m1-site-save','m1-page-id',
       'm1-page-label','m1-page-path','m1-page-save','m1-pages','m1-profile-page','m1-profile-kind',
       'm1-profile-width','m1-profile-height','m1-profile-save','m1-fixture-name','m1-fixture-save',
       'm1-captures','m1-capture','m1-baseline','m1-compare','m1-result','m1-history','m1-reload',
       'm1-before','m1-after','m1-diff']


class M1UITests(unittest.TestCase):
    setUp = ui.LocalBaselineUITests.setUp
    stop_server = ui.LocalBaselineUITests.stop_server

    def run_js(self, code, *, writes=False):
        if ui.NODE is None: self.skipTest('installed Node unavailable; no installation')
        # setUp created a fresh S1+Baseline file. Explicitly add only M1 tables.
        from src.storage.m1 import initialize
        initialize(self.db,self.root)
        self.workspace = OfflineWorkspace(self.db,self.root)
        self.server = LocalBaselineHOME(self.db,self.root,approval_actor='fixture-local-operator',
            offline=self.workspace,limits=BFFLimits(request_timeout_seconds=3))
        self.server.start()
        declarations = {'APP_PATH':str(ui.ROOT/'src/bff/ui/baseline.js'),'IDS':ui.IDS+IDS,
            'PAIR_CODE':self.server.pairing_for_local_user(),'AUTHORITY':self.server.authority,
            'ORIGIN':self.server.origin,'PORT':self.server.address[1],
            'M1_PATH':str(ui.ROOT/'src/bff/ui/m1.js'),'COMPARE_PATH':str(ui.ROOT/'web/compare/app.js')}
        harness = ui.HARNESS.replace("['tr', 'td', 'button', 'dt', 'dd', 'li']","['tr', 'td', 'button', 'dt', 'dd', 'li', 'option']")
        harness = harness.replace("const controller = app.createController({document, fetch: fetchLocal});",
            "let changes = 0; const controller = app.createController({document, fetch: fetchLocal, onBaselineChange: () => { changes++; }});")
        harness = harness.replace("const requests = [];","const requests = []; let dropM1Reply = false;")
        harness = harness.replace("resolve({status: res.statusCode, json: async () => JSON.parse(raw)});",
            "if (dropM1Reply && options.method === 'POST' && path.includes('/_m1/')) { dropM1Reply = false; reject(Error('reply lost')); return; } resolve({status: res.statusCode, json: async () => JSON.parse(raw)});")
        setup = """
Element.prototype.removeAttribute = function (name) { delete this[name]; };
$('m1-profile-kind').value = 'Desktop'; $('m1-fixture-name').value = 'original';
const compareCore = require(COMPARE_PATH);
const m1 = require(M1_PATH).createController({document,fetch:fetchLocal,baseline:controller,compareCore});
"""
        script = '\n'.join('const '+k+' = '+json.dumps(v)+';' for k,v in declarations.items())
        script += harness + setup + '\n(async()=>{\n'+code+"\n})().catch(e=>{process.stderr.write('M1 fixture failed: '+e.message);process.exitCode=1;});"
        before = self.db.read_bytes()
        result = subprocess.run([ui.NODE,'-'],input=script,text=True,capture_output=True,timeout=25,cwd=ui.ROOT)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,''); self.assertEqual(result.stderr,'')
        if writes: self.assertNotEqual(self.db.read_bytes(),before)
        else: self.assertEqual(self.db.read_bytes(),before)

    def test_UI01_home_baseline_compare_history_end_to_end(self):
        self.run_js(r'''
await controller.start(); await m1.start();
assert.equal($('m1-message').textContent,'認証が必要です');
assert.equal($('m1-captures').children.length,0);
$('pair-code').value = PAIR_CODE; await controller.pair(); assert.equal(changes,1);
await m1.refresh();
$('m1-site-label').value='Fixture site'; $('m1-site-origin').value='https://fixture.invalid'; await m1.saveSite();
for (let n=1;n<=5;n++) {
  $('m1-page-id').value='page-'+n; $('m1-page-label').value='ページ'+n; $('m1-page-path').value='/'+n;
  await m1.savePage();
}
assert.equal($('m1-pages').children.length,5);
$('m1-page-id').value='page-6'; $('m1-page-label').value='6'; $('m1-page-path').value='/6'; await m1.savePage();
assert.ok($('m1-message').textContent.includes('最大5ページ'));
assert.equal($('m1-pages').children.length,5);
$('m1-profile-page').value='page-1'; $('m1-profile-width').value='1200'; $('m1-profile-height').value='800';
await m1.saveProfile();
const original = await m1.saveFixture();
assert.equal(original.job_execution,'NOT_RUN'); assert.equal(original.quality,'UNKNOWN');
const candidate = await m1.registerCandidate(original.capture_id);
assert.ok($('baseline-detail').textContent.includes(candidate.digest));
assert.ok($('baseline-detail').textContent.includes('BASELINE_PENDING'));
assert.equal($('approval-confirm').checked,false);
$('approval-confirm').checked=true; await controller.approve();
assert.equal($('approval-message').textContent,'Baseline承認済み'); assert.equal(changes,2);
await m1.refresh();
$('m1-fixture-name').value='changed'; const current = await m1.saveFixture();
$('m1-capture').value=current.capture_id; $('m1-baseline').value=candidate.candidate_id;
const result = await m1.compare();
assert.ok($('m1-result').textContent.includes('差分 1 / 64 pixels (1.5625%)'));
assert.ok($('m1-result').textContent.includes('PREVIEW_ONLY'));
assert.ok($('m1-result').textContent.includes('品質UNKNOWN'));
assert.ok($('m1-result').textContent.includes('正式比較NOT_RUN'));
assert.equal($('m1-history').children.length,1);
assert.ok($('m1-diff').src.endsWith(result.result_id));
$('m1-result').textContent=''; await m1.showResult(result.result_id);
assert.ok($('m1-result').textContent.includes('差分 1 / 64'));
assert.ok($('m1-captures').textContent.includes('実Job: NOT_RUN'));
assert.ok(requests.every(r => r.path.startsWith('/api/baselines') || r.path === '/local/pair'));
''',writes=True)
        reopened = OfflineWorkspace(self.db,self.root)
        state = reopened.state()
        self.assertEqual(len(state['pages']),5)
        self.assertEqual(len(state['results']),1)
        self.assertEqual(state['results'][0]['assessment']['quality'],'UNKNOWN')
        profiles = {p['kind']:p for p in state['profiles'] if p['page_id']=='page-1'}
        self.assertEqual(profiles['Desktop']['profile']['attributes']['viewport_width'],1200)
        self.assertEqual(profiles['Mobile']['revision'],1)

    def test_UI02_lost_save_reply_reconciles_without_fabricating_success_or_retry(self):
        self.run_js(r'''
await controller.start(); $('pair-code').value=PAIR_CODE; await controller.pair(); await m1.start();
$('m1-site-label').value='fixture'; $('m1-site-origin').value='https://fixture.invalid'; await m1.saveSite();
$('m1-page-id').value='p1'; $('m1-page-label').value='fixture'; $('m1-page-path').value='/'; await m1.savePage();
dropM1Reply=true; const result=await m1.saveFixture();
assert.equal(result,null);
assert.ok($('m1-message').textContent.includes('保存結果は未確認'));
assert.equal($('m1-captures').children.length,1);
assert.equal(requests.filter(r=>r.path.endsWith('/_m1/fixture') && r.method==='POST').length,1);
''',writes=True)
        self.assertEqual(len(self.workspace.state()['captures']),1)

    def test_UI03_db_http_and_session_failures_clear_data_never_show_empty_success(self):
        self.run_js(r'''
await controller.start(); $('pair-code').value=PAIR_CODE; await controller.pair(); await m1.start();
interceptedStatus=503; await m1.refresh();
assert.ok($('m1-message').textContent.includes('取得できません'));
assert.ok(!$('m1-message').textContent.includes('登録されていません'));
assert.equal(await m1.saveSite(),null);
await m1.refresh(); jar=jar.split('=')[0]+'=wrong'; await m1.refresh();
assert.equal($('m1-message').textContent,'認証が必要です');
assert.equal($('m1-pages').children.length,0); assert.equal($('m1-history').children.length,0);
''')

    def test_UI04_html_injection_is_text_and_profile_missing_reasons_visible(self):
        self.run_js(r'''
await controller.start(); $('pair-code').value=PAIR_CODE; await controller.pair(); await m1.start();
$('m1-site-label').value='<img src=x onerror=alert(1)>'; $('m1-site-origin').value='https://fixture.invalid'; await m1.saveSite();
$('m1-page-id').value='p'; $('m1-page-label').value='<svg onload=alert(1)>'; $('m1-page-path').value='/'; await m1.savePage();
assert.ok($('m1-pages').textContent.includes('<svg onload=alert(1)>'));
const original=await m1.saveFixture(); const candidate=await m1.registerCandidate(original.capture_id);
$('approval-confirm').checked=true; await controller.approve(); await m1.refresh();
$('m1-fixture-name').value='missing'; const current=await m1.saveFixture();
$('m1-capture').value=current.capture_id; $('m1-baseline').value=candidate.candidate_id; await m1.compare();
assert.ok($('m1-result').textContent.includes('EVIDENCE_MISSING'));
assert.ok($('m1-result').textContent.includes('品質UNKNOWN'));
assert.equal($('m1-diff').hidden,true);
''',writes=True)

    def test_UI05_existing_compare_diff_rule_matches_saved_preview(self):
        before = preview.fixture('original'); after = preview.fixture('changed')
        metrics,diff = preview.compare(before,after)
        a,b,out = preview.decode(before)[2],preview.decode(after)[2],preview.decode(diff)[2]
        code = "const a="+json.dumps(list(a))+",b="+json.dumps(list(b))+",expected="+json.dumps(list(out))+";"
        code += "const out=new Uint8Array(a.length); assert.equal(compareCore.diffBand(a,b,out),1); assert.deepEqual(Array.from(out),expected);"
        self.run_js(code)
        self.assertEqual(metrics['changed_pixels'],1)

    def test_UI06_page_edit_retains_reviewed_revision_across_background_refresh(self):
        self.run_js(r'''
await controller.start(); $('pair-code').value=PAIR_CODE; await controller.pair(); await m1.start();
$('m1-site-label').value='fixture'; $('m1-site-origin').value='https://fixture.invalid'; await m1.saveSite();
$('m1-page-id').value='p1'; $('m1-page-label').value='original'; $('m1-page-path').value='/'; await m1.savePage();
$('m1-pages').children[0].children[4].children[0].events.click();
const session=await (await fetchLocal('/api/baselines/_approval/session',{method:'GET',headers:{'X-SiteProof-UI':'1'},credentials:'same-origin',mode:'same-origin',cache:'no-store',redirect:'error'})).json();
await fetchLocal('/api/baselines/_m1/page',{method:'POST',headers:{'Content-Type':'application/json','X-SiteProof-CSRF':session.csrf_token},
  body:JSON.stringify({page_id:'p1',label:'other edit',path:'/other',expected_revision:1}),credentials:'same-origin',mode:'same-origin',cache:'no-store',redirect:'error'});
await m1.refresh();
$('m1-page-label').value='stale edit'; await m1.savePage();
assert.ok($('m1-message').textContent.includes('競合'));
assert.ok($('m1-pages').textContent.includes('other edit'));
assert.ok(!$('m1-pages').textContent.includes('stale edit'));
''',writes=True)
        self.assertEqual(self.workspace.state()['pages'][0]['label'],'other edit')

    def test_UI07_existing_compare_browser_export_does_not_mount_on_local_home(self):
        self.run_js(r'''
const vm=require('node:vm'),fs=require('node:fs');
const local={document:{readyState:'complete',getElementById:()=>null}};
vm.runInNewContext(fs.readFileSync(COMPARE_PATH,'utf8'),local);
assert.equal(typeof local.SiteProofCompare.diffBand,'function');
assert.equal(local.SiteProofCompare.formatRatio(1,64),'1.5625%');
''')


if __name__ == '__main__': unittest.main()
