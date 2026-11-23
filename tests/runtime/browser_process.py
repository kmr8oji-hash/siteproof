"""Real Chromium, dedicated UID/container only, after host-measured preflight.

Input is a trusted bounded stdin request. Output is fixed metadata + capped framed
bytes. No evidence-directory mount, arbitrary URL, token URL, external DNS or site.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys

from playwright.sync_api import sync_playwright
from src.comparison.profile import CaptureProfile
from src.isolation.destination import DestinationPolicy, AllowedDestination, check_authority
from src.runtime.browser import PlaywrightDriver, ResourceLimits, RuntimeRefused
from src.worker.capture import capture, CaptureRequest


def status():
    return [s for s in Path('/proc/self/status').read_text().splitlines()
            if s.startswith(('Uid:','Cap','NoNewPrivs','Seccomp'))]


class FixtureProxyBinding:
    """Pinned fixture endpoint inside the measured shared namespace, no fallback.
    Does not claim to own a remote Python transport object or attest isolation.
    """
    def __init__(self,port):
        if type(port) is not int or port!=18080:raise ValueError('fixture proxy binding')
        self.port=port
        self.policy=DestinationPolicy((AllowedDestination('fixture.invalid',443),))
    def check(self,url=None):
        if url is not None:
            from urllib.parse import urlsplit
            u=urlsplit(url)
            fixture_http=(u.scheme=='http' and u.hostname=='fixture.invalid' and u.port in (None,80))
            if (u.username or u.password or u.fragment or not (fixture_http or
                    (u.scheme=='https' and check_authority(self.policy,u.hostname,u.port or 443).allowed))):
                raise RuntimeRefused('DESTINATION_REFUSED')
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.settimeout(1);s.connect(('127.0.0.1',self.port))
        return 'http://127.0.0.1:'+str(self.port)


class IsolatedPlaywright:
    def __init__(self,ui=False):self.browser=None;self.pw=None;self.sandbox=None;self.ui=ui
    def open_browser(self,plan=None):
        if os.getuid() not in (1000,1003):raise RuntimeError('nonroot dedicated Browser UID')
        current=status()
        if not any(x.startswith('CapBnd:') and x.split()[-1]=='0000000000000000' for x in current):
            raise RuntimeError('Browser capability boundary')
        self.pw=sync_playwright().start()
        options=plan.playwright_options() if plan else {'headless':True,'chromium_sandbox':True,
            'args':['--disable-quic','--disable-background-networking']}
        options['args']+=['--disable-dev-shm-usage','--dns-prefetch-disable']
        # Full Chromium supports chrome://sandbox; headless-shell does not.
        options['channel']='chromium'
        self.browser=self.pw.chromium.launch(**options)
        context=self.browser.new_context(service_workers='block',accept_downloads=False)
        page=context.new_page();page.goto('chrome://sandbox')
        text=page.locator('body').inner_text()
        context.close()
        # Require Chromium's own status; launch flags alone are not evidence.
        namespace=(re.search(r'Namespace sandbox\s+Yes',text,re.I)
                   or re.search(r'Layer 1 Sandbox\s+Namespace',text,re.I))
        if not (namespace and re.search(r'PID namespaces\s+Yes',text,re.I)
                and re.search(r'Network namespaces\s+Yes',text,re.I)
                and re.search(r'Seccomp-BPF sandbox\s+Yes',text,re.I)):
            self.close();raise RuntimeError('Chromium sandbox not verified: '+text[:2000])
        self.sandbox={'body':text,'browser_version':self.browser.version,'status':current,
            'netns':os.readlink('/proc/self/ns/net'),
            'cgroup':{n:Path('/sys/fs/cgroup/'+n).read_text().strip() for n in ('memory.max','pids.max','cpu.max')}}
        return self.browser
    def close(self):
        if self.browser is not None:self.browser.close();self.browser=None
        if self.pw is not None:self.pw.stop();self.pw=None
        return True


def install_fixture_ca():
    home=Path(os.environ['HOME']);nss=home/'.pki/nssdb';nss.mkdir(parents=True,exist_ok=True)
    subprocess.run(['certutil','-N','--empty-password','-d','sql:'+str(nss)],check=True,
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['certutil','-A','-d','sql:'+str(nss),'-n','SiteProof controlled fixture',
        '-t','C,,','-i','/fixture-ca.crt'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def ui_test(c):
    launcher=IsolatedPlaywright(ui=True);results={}
    try:
        browser=launcher.open_browser()
        context=browser.new_context();page=context.new_page()
        origin='http://127.0.0.1:'+str(c['ui_port'])
        page.goto(origin+'/local/',wait_until='load',timeout=5000)
        page.locator('#reload-list').click()
        page.locator('#list-message',has_text='認証').wait_for(timeout=5000)
        results['before_pairing']=page.locator('#baseline-list tr').count()==0
        page.locator('#pair-code').fill(c['pairing_code'])
        page.locator('#pair-code').press('Tab')
        results['keyboard_focus']=page.locator('#pair-button').evaluate('(el)=>el === document.activeElement')
        page.keyboard.press('Enter')
        page.wait_for_selector('#baseline-list tr',timeout=5000)
        results['list']=page.locator('#baseline-list tr').count()>=2
        # Select approved fixture to exercise real persisted approval history.
        for row in page.locator('#baseline-list tr').all():
            if 'APPROVED' in row.inner_text():row.locator('button').click();break
        page.wait_for_selector('#baseline-detail dd',timeout=5000)
        page.wait_for_selector('#baseline-history li',timeout=5000)
        results['detail']=page.locator('#baseline-detail').inner_text()!=''
        results['history']=page.locator('#baseline-history li').count()>0
        cookies=context.cookies()
        results['cookie']=any(x['httpOnly'] and x['sameSite']=='Strict' for x in cookies)
        page.reload();page.wait_for_selector('#baseline-list tr',timeout=5000)
        results['cookie_persisted']=page.locator('#baseline-list tr').count()>=2
        print(json.dumps({'type':'ui_ready','checks':results,'sandbox':launcher.sandbox}),flush=True)
        if json.loads(sys.stdin.buffer.readline(1025)).get('type')!='runtime_ready':raise ValueError('control')
        page.locator('#runtime-refresh').click()
        page.locator('#runtime-results',has_text='保存参照').wait_for(timeout=5000)
        text=page.locator('#runtime-results').inner_text()
        results['s1_runtime_view']='COMPLETED' in text and 'UNKNOWN' in text and 'PROFILE_UNATTESTED' in text
        # Deterministic HTTP read error, no DB mutation or route fallback.
        page.route('**/api/baselines?*',lambda route:route.fulfill(status=503,content_type='application/json',body='{"error":{"code":"DATA_UNAVAILABLE"}}'))
        page.locator('#reload-list').click()
        page.locator('#list-message',has_text='取得できません').wait_for(timeout=5000)
        results['error_not_empty']=page.locator('#baseline-list tr').count()==0
        page.unroute('**/api/baselines?*')
        print(json.dumps({'type':'ui_expire_session'}),flush=True)
        if json.loads(sys.stdin.buffer.readline(1025)).get('type')!='session_destroyed':raise ValueError('control')
        page.locator('#reload-list').click()
        page.locator('#list-message',has_text='認証').wait_for(timeout=5000)
        results['invalid_session']=page.locator('#baseline-list tr').count()==0
        if not all(results.values()):raise RuntimeError('UI check failed')
        return {'reason':'UI_PASS','checks':results,'sandbox':launcher.sandbox,'cleanup':True}
    finally:launcher.close()


def network_test(c):
    launcher=IsolatedPlaywright();checks={}
    try:
        browser=launcher.open_browser()
        # Deliberately direct contexts: the unchanged OS boundary must still deny.
        # This browser was launched without proxy options: omission is direct.
        # An invented direct:// proxy URI would fail before attempting the target.
        context=browser.new_context(service_workers='block')
        for key,url in {'tcp':'http://127.0.0.2:18555/','metadata':'http://169.254.169.254/',
            'lan':'http://10.231.77.5:18555/','host_model':'http://127.0.0.4:18555/',
            'ipv6':'http://[::1]:18555/','dns':'http://dns-probe.fixture.invalid/'}.items():
            page=context.new_page()
            try:page.goto(url,timeout=1000,wait_until='commit');checks[key]=False
            except Exception as exc:checks[key]='net::ERR_' in str(exc) or 'Timeout' in str(exc)
            finally:page.close()
        # STUN explicitly targets the controlled UDP canary. No external STUN/DNS.
        page=context.new_page()
        checks['udp_attempt']=page.evaluate('''async()=>{const p=new RTCPeerConnection({iceServers:[{urls:'stun:127.0.0.3:5353'}]});p.createDataChannel('fixture');await p.setLocalDescription(await p.createOffer());await new Promise(r=>setTimeout(r,1200));p.close();return true;}''')
        context.close()
        # Keep a real browser open while the host stops the owned Proxy.
        context=browser.new_context(proxy={'server':'http://127.0.0.1:'+str(c['proxy_port']),'bypass':'<-loopback>'})
        page=context.new_page();page.goto('https://fixture.invalid/',timeout=5000)
        print(json.dumps({'type':'need_proxy_stop'}),flush=True)
        if json.loads(sys.stdin.buffer.readline(1025)).get('type')!='proxy_stopped':raise ValueError('control')
        try:page.goto('https://fixture.invalid/after-stop',timeout=2000);checks['proxy_stopped']=False
        except Exception:checks['proxy_stopped']=True
        if not all(checks.values()):raise RuntimeError('Browser bypass failure')
        return {'type':'network_result','checks':checks,'sandbox':launcher.sandbox,'cleanup':True}
    finally:launcher.close()


def main():
    raw=sys.stdin.buffer.readline(16385)
    if len(raw)>16384:raise ValueError('input cap')
    c=json.loads(raw);mode=c['mode']
    install_fixture_ca()
    if mode=='network':
        print(json.dumps(network_test(c)),flush=True);return
    if mode=='cancel':
        launcher=IsolatedPlaywright()
        try:
            browser=launcher.open_browser()
            context=browser.new_context(proxy={'server':'http://127.0.0.1:'+str(c['proxy_port']),'bypass':'<-loopback>'})
            page=context.new_page()
            print(json.dumps({'type':'cancel_ready','sandbox':launcher.sandbox}),flush=True)
            page.goto('https://fixture.invalid/slow',timeout=20000)
        finally:launcher.close()
        raise RuntimeError('cancel was not delivered')
    if mode=='ui':
        result=ui_test(c);wire=b''
    else:
        req=c['request'];profile=CaptureProfile(req['profile']['profile_id'],req['profile']['attributes'])
        request=CaptureRequest(req['page_id'],profile,req['url'],req['baseline_id'])
        launcher=IsolatedPlaywright()
        driver=PlaywrightDriver(launcher,FixtureProxyBinding(c['proxy_port']),ResourceLimits(**c['resources']))
        output=capture(request,driver,driver.lease,driver.limits)
        result={'reason':output.reason,'cleanup':output.cleanup_confirmed,'sandbox':launcher.sandbox}
        wire=output.wire
    result['length']=len(wire)
    sys.stdout.buffer.write(json.dumps(result,separators=(',',':')).encode()+b'\n'+wire)
    sys.stdout.buffer.flush()


if __name__=='__main__':
    try:main()
    except Exception as exc:
        # Playwright call logs can include form values. Never persist pairing
        # input, cookies or raw UI exceptions into Docker/host stderr logs.
        sys.stderr.write(json.dumps({'failure':'BROWSER_HELPER_FAILED','type':type(exc).__name__})+'\n')
        raise SystemExit(1)
