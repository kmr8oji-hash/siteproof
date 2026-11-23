"""M5 untrusted capture/UI client. No signing key, Worker DB, Docker or volume."""
import base64
import hashlib
import json
import os
import sys
import time
from urllib.parse import urlsplit

from tests.runtime.browser_process import IsolatedPlaywright, FixtureProxyBinding, install_fixture_ca
from src.comparison.profile import CaptureProfile
from src.runtime.browser import PlaywrightDriver, ResourceLimits
from src.runtime.stability import stable_capture
from src.worker.capture import capture, CaptureRequest, FrameWriter
from src.isolation.frames import FrameLimits


class Driver(PlaywrightDriver):
    stability_policy=None  # The trusted Worker's policy for this page (src/runtime/stability.py); None = the default policy.

    def capture(self, profile, seconds):
        # Load and fonts first, then time-spaced screenshots until the last ones repeat (bounded). `repeat` = the previous identical shot.
        start=time.monotonic()
        self.page.wait_for_function('document.readyState==="complete"',timeout=max(seconds,0.5)*1000)
        self.page.evaluate('document.fonts.ready')
        budget=max(0.0,seconds-(time.monotonic()-start))
        first,self.repeat,self.stability=stable_capture(lambda timeout:super(Driver,self).capture(profile,timeout),self.stability_policy,budget)
        self.report=self.page.evaluate('''()=>({viewport:{width:innerWidth,height:innerHeight},dpr:devicePixelRatio,
          locale:navigator.language,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,
          dark:matchMedia('(prefers-color-scheme: dark)').matches,
          reducedMotion:matchMedia('(prefers-reduced-motion: reduce)').matches,
          userAgent:navigator.userAgent,fontsStatus:document.fonts.status,
          readyState:document.readyState,scrollHeight:document.documentElement.scrollHeight,bodyTextLength:(document.body?document.body.innerText.length:0),
          images:document.images.length,brokenImages:Array.from(document.images).filter(i=>i.complete&&i.naturalWidth===0).length})''')
        return first


def emit(value,wire=b'',repeat=b''):
    sys.stdout.buffer.write(json.dumps(value,separators=(',',':')).encode()+b'\n'+wire+repeat);sys.stdout.buffer.flush()


def ui(config):
    launcher=IsolatedPlaywright(ui=True);checks={};shots={}
    try:
        browser=launcher.open_browser();context=browser.new_context(viewport={'width':1440,'height':900})
        page=context.new_page();origin='http://127.0.0.1:'+str(config['ui_port'])
        events = [0]
        def trace(stage, **fields):
            if events[0] >= 400: return
            events[0] += 1
            sys.stderr.write(json.dumps({'t':time.monotonic(),'stage':stage,**fields})+'\n');sys.stderr.flush()
        # Fixed local paths and status only. Never bodies, query, headers, cookies,
        # pairing input, browser exceptions or request failure text.
        def route(request):
            path=urlsplit(request.url).path
            return path if path.startswith(('/api/baselines','/local/')) else 'other-local-path'
        page.on('request',lambda r:trace('http_request',method=r.method,path=route(r)))
        page.on('response',lambda r:trace('http_response',status=r.status,path=route(r.request)))
        page.on('requestfailed',lambda r:trace('http_request_failed',path=route(r)))
        page.goto(origin+'/local/',wait_until='load',timeout=10000)
        checks['all_home_controllers_loaded']=page.evaluate('''()=>!!(window.SiteProofCompare&&window.SiteProofBaseline&&window.SiteProofM1&&window.SiteProofRuntime)''')
        if not checks['all_home_controllers_loaded']:raise RuntimeError('HOME_CONTROLLER_UNAVAILABLE')
        page.locator('#m4-message',has_text='認証').wait_for(timeout=10000)
        checks['unauthenticated_results_hidden']=page.locator('#m4-jobs > div').count()==0
        page.locator('#pair-code').fill(config['pairing_code']);page.locator('#pair-code').press('Tab')
        checks['keyboard_pairing_focus']=page.locator('#pair-button').evaluate('(el)=>el===document.activeElement')
        page.keyboard.press('Enter')
        page.locator('#connection-status',has_text='接続中（ローカルBaseline）').wait_for(timeout=10000)
        checks['cookie_boundary']=any(c['httpOnly'] and c['sameSite']=='Strict' and c['path']=='/api/baselines' for c in context.cookies())
        emit({'type':'ui_ready','checks':checks})
        while True:
            raw=sys.stdin.buffer.readline(4097)
            if len(raw)>4096:raise ValueError('UI control cap')
            command=json.loads(raw);mode=command['type']
            if mode=='module_failure_probe':
                # Reproduce the observed 503 -> missing controller -> no approval
                # dispatch mechanism using an intercepted old parallel-script HOME.
                # This does not assert which resource failed in historical run03.
                probe=context.new_page();posts=[]
                probe.add_init_script("window.__m5ModuleError=false;addEventListener('error',()=>{window.__m5ModuleError=true;});")
                def old_home(route):
                    response=route.fetch()
                    tags=''.join('<script defer src="/local/'+n+'.js"></script>' for n in
                        ('compare-core','baseline','m1','runtime','comparison'))
                    html=response.text().replace('<script src="/local/workspace.js" defer></script>',tags)
                    route.fulfill(response=response,body=html)
                probe.route('**/local/',old_home)
                probe.route('**/local/baseline.js',lambda r:r.fulfill(status=503,content_type='text/javascript',body=''))
                probe.on('request',lambda r:posts.append(True) if r.method=='POST' and urlsplit(r.url).path=='/api/baselines/_approval/approve' else None)
                probe.goto(origin+'/local/',wait_until='load',timeout=10000)
                row=probe.locator('#m4-jobs > div').filter(has_text=command['candidate_id'])
                row.get_by_role('button',name='Baseline詳細・明示承認').click()
                probe.wait_for_function('window.__m5ModuleError===true',timeout=10000)
                checks['missing_controller_prevents_approval_dispatch']=probe.evaluate('typeof window.SiteProofBaseline==="undefined"') and probe.locator('#approval-panel').is_hidden() and not posts
                probe.close();emit({'type':'module_failure_confirmed','checks':checks})
            elif mode=='approve':
                trace('approve_refresh')
                page.locator('#m4-refresh').click();page.locator('#m4-jobs > div').first.wait_for(timeout=10000)
                for item in command['jobs']:
                    trace('approve_select',candidate=item['candidate_id'])
                    row=page.locator('#m4-jobs > div').filter(has_text=item['candidate_id'])
                    row.get_by_role('button',name='Baseline詳細・明示承認').click()
                    trace('approve_wait_panel')
                    page.locator('#approval-panel').wait_for(state='visible',timeout=10000)
                    trace('approve_panel_ready')
                    checks['approval_starts_unchecked']=not page.locator('#approval-confirm').is_checked()
                    page.locator('#approval-confirm').check();trace('approve_checked')
                    page.locator('#approve-button').click();trace('approve_clicked')
                    page.locator('#approval-message',has_text='Baseline承認済み').wait_for(timeout=10000)
                    trace('approve_confirmed')
                    page.locator('#m4-refresh').click()
                    page.locator('#m4-jobs > div').filter(has_text=item['candidate_id']).filter(has_text='APPROVED').wait_for(timeout=10000)
                checks['explicit_approval']=True
                checks['approval_history']=page.locator('#baseline-history li').count()>0
                emit({'type':'approved','checks':checks})
            elif mode=='inspect_result':
                rid=command['result_id'];page.locator('#m4-refresh').click()
                row=page.locator('#m4-history > p').filter(has_text=rid)
                row.get_by_role('button',name='画像と保存結果を表示').click()
                page.locator('#m4-result',has_text='品質 UNKNOWN').wait_for(timeout=10000)
                text=page.locator('#m4-result').inner_text()
                checks['japanese_unknown_reason']='撮影条件は未認証' in text and 'PROFILE_UNATTESTED' in text
                checks['preview_not_quality_pass']='未認証プレビューのみ' in text
                checks['expected_change_observation']=('変更あり' if command['changed'] else '変更なし') in text
                for name in ('m4-baseline','m4-current','m4-diff'):
                    page.locator('#'+name).wait_for(state='visible',timeout=10000)
                    page.wait_for_function('(id)=>{const e=document.getElementById(id);return e.complete&&e.naturalWidth>0}',arg=name,timeout=10000)
                checks['three_pngs_loaded']=True
                # Compare uses the real authenticated UI action and saves another
                # result. Cached pixel work is reused only after fresh readback.
                if command.get('compare_action',True):
                    job=page.locator('#m4-jobs > div').filter(has_text=command['candidate_id'])
                    previous=page.locator('#m4-history > p').count()
                    job.get_by_role('button',name='固定基準版と比較・履歴保存').click()
                    page.wait_for_function('(n)=>document.querySelectorAll("#m4-history > p").length>n',arg=previous,timeout=15000)
                    checks['comparison_button_saved_history']=True
                tokenless=page.evaluate('''async()=>{const r=await fetch('/api/baselines/_m4/compare',{method:'POST',headers:{'Content-Type':'application/json','X-SiteProof-CSRF':'invalid'},body:JSON.stringify({job_id:'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'})});return r.status;}''')
                checks['csrf_rejected']=tokenless==403
                page.set_viewport_size({'width':1440,'height':900})
                page.locator('#m4-result').scroll_into_view_if_needed()
                shots['desktop']=page.screenshot(type='png',full_page=False)
                page.set_viewport_size({'width':390,'height':844})
                checks['mobile_no_document_overflow']=page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                if not checks['mobile_no_document_overflow']:
                    trace('mobile_overflow',geometry=page.evaluate('''()=>Array.from(document.querySelectorAll('main,section,select,input,table')).map(e=>({tag:e.tagName,id:e.id,width:e.getBoundingClientRect().width,right:e.getBoundingClientRect().right})).filter(e=>e.right>innerWidth).slice(0,16)'''))
                page.locator('#m4-refresh').focus();page.keyboard.press('Tab')
                checks['keyboard_focus_visible']=page.evaluate('document.activeElement!==document.body')
                page.locator('#m4-result').scroll_into_view_if_needed()
                page.evaluate("window.scrollTo(0,document.getElementById('m4-result').getBoundingClientRect().top+scrollY)")
                shots['mobile']=page.screenshot(type='png',full_page=False)
                page.set_viewport_size({'width':1440,'height':900})
                for label,data in shots.items():
                    if len(data)>2*1024*1024:raise ValueError('UI screenshot limit')
                    for start in range(0,len(data),32768):
                        emit({'type':'screenshot_chunk','label':label,'offset':start,
                              'data':base64.b64encode(data[start:start+32768]).decode()})
                emit({'type':'result_inspected','checks':checks,'screenshots':{
                    label:{'length':len(data),'sha256':hashlib.sha256(data).hexdigest()} for label,data in shots.items()}})
            elif mode=='missing':
                page.locator('#m4-refresh').click()
                page.locator('#m4-history > p').filter(has_text=command['result_id']).wait_for(timeout=10000)
                # No primary evidence is changed: a browser intercept simulates
                # the authenticated image read failing and exercises real onerror.
                page.route('**/api/baselines/_m4/result/*/diff',lambda r:r.fulfill(status=422,content_type='application/json',body='{"error":{"code":"EVIDENCE_UNAVAILABLE"}}'))
                page.locator('#m4-history > p').filter(has_text=command['result_id']).get_by_role('button').click()
                page.locator('#m4-message',has_text='画像を表示できません').wait_for(timeout=10000)
                checks['missing_image_error']=page.locator('#m4-diff').is_hidden()
                page.unroute('**/api/baselines/_m4/result/*/diff')
                page.route('**/api/baselines/_m4/state',lambda r:r.fulfill(status=503,content_type='application/json',body='{"error":{"code":"DATA_UNAVAILABLE"}}'))
                page.locator('#m4-refresh').click();page.locator('#m4-message',has_text='取得できません').wait_for(timeout=10000)
                checks['error_clears_rows']=page.locator('#m4-jobs > div').count()==0
                page.unroute('**/api/baselines/_m4/state')
                emit({'type':'missing_checked','checks':checks})
            elif mode=='expired':
                page.locator('#m4-refresh').click();page.locator('#m4-message',has_text='認証が必要').wait_for(timeout=10000)
                checks['expired_session_clears_results']=page.locator('#m4-jobs > div').count()==0
                emit({'type':'expired_checked','checks':checks})
            elif mode=='quit':
                emit({'type':'ui_closed','checks':checks,'all_checks':all(checks.values()),'sandbox':launcher.sandbox});return
            else:raise ValueError('unknown UI command')
    finally:launcher.close()


def main():
    raw=sys.stdin.buffer.readline(16385)
    if len(raw)>16384:raise ValueError('input cap')
    config=json.loads(raw);install_fixture_ca()
    if config['mode']=='ui':ui(config);return
    req=config['request'];profile=CaptureProfile(req['profile']['profile_id'],req['profile']['attributes'])
    request=CaptureRequest(req['page_id'],profile,req['url'],req['baseline_id'])
    launcher=IsolatedPlaywright()
    driver=Driver(launcher,FixtureProxyBinding(config['proxy_port']),ResourceLimits(**config['resources']),is_mobile=profile.profile_id=='Mobile')
    driver.stability_policy=req.get('stability')
    if config['mode']=='crash':
        driver.start(profile);driver.http(req['url'],5)
        writer=FrameWriter(request,FrameLimits())
        writer.record('HTTP',state='OBSERVED',status_code=200,reason_code='HTTP_OBSERVED')
        emit({'length':len(writer.data),'repeat_length':0,'reason':'CAPTURE_FAILED','cleanup':False,'browser_report':{}},bytes(writer.data))
        os._exit(7)  # Deliberate abnormal producer death; host must stop its cgroup.
    output=capture(request,driver,driver.lease,driver.limits)
    repeat=getattr(driver,'repeat',b'')
    emit({'length':len(output.wire),'repeat_length':len(repeat),'reason':output.reason,
          'cleanup':output.cleanup_confirmed,'sandbox':launcher.sandbox,
          'browser_report':{'classification':'BROWSER_SELF_REPORT','runtime':getattr(driver,'report',{}),
              'stability':getattr(driver,'stability',None),'is_mobile_instruction':driver.is_mobile}},output.wire,repeat)


if __name__=='__main__':
    try:main()
    except Exception as exc:
        # Never emit raw Playwright form errors, cookies, pairing values or argv.
        sys.stderr.write(json.dumps({'failure':'M5_BROWSER_HELPER_FAILED','type':type(exc).__name__})+'\n');raise SystemExit(1)
