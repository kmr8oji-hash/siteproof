"""M5 trusted Worker. Signing keys stay only in this UID1001 process's memory."""
import copy
import io
import json
from pathlib import Path
import shutil
import sqlite3
import time

from playwright.sync_api import sync_playwright
from tests.runtime import linux_worker as base
from src.bff.baseline import BFFLimits
from src.bff.local_ui import LocalBaselineHOME
from src.bridge.adapter import EvidenceBridge
from src.comparison.service import ComparisonService, PixelPolicy
from src.core.offline import OfflineWorkspace, profile_body
from src.isolation.frames import FrameReader, TrustedContext
from src.runtime.profile_observer import WorkerProfileObserver, EphemeralFixtureSigner
from src.runtime.service import RuntimeService
from src.storage.artifacts import ArtifactStore
from src.storage.comparison import initialize as initialize_comparison
from src.storage.finalizer import EvidenceFinalizer
from src.storage.repository import Repository
from src.storage.runtime import initialize
from src.worker.trusted import TrustedWorker


VARIANT='original'


class Handler(base.Handler):
    def do_GET(self):
        base.count('https' if getattr(self.server,'is_tls',False) else 'http')
        if self.path.startswith('/slow'):time.sleep(12)
        color='#213876' if VARIANT=='original' else '#d52c35'
        raw=('<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
             '<title>M5 fixture</title><style>body{margin:0;background:#eef2ff;font:24px sans-serif;padding:24px;box-sizing:border-box}'
             'h1{color:'+color+'}*{animation:none!important;transition:none!important}</style>'
             '<h1>SiteProof M5 fixture</h1><p>Controlled local HTTPS</p></html>').encode()
        try:
            self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(raw)
        except (OSError,base.ssl.SSLError):pass


def main():
    global VARIANT
    if base.os.getuid()!=1001:raise RuntimeError('trusted Worker UID required')
    base.Handler=Handler
    http,thread,plain,plain_thread,cert=base.start_fixtures()
    root=base.ROOT;db=root/'siteproof.sqlite';workspace=OfflineWorkspace.create(db,root)
    workspace.save_site({'label':'M5 controlled fixture','origin':'https://fixture.invalid','expected_revision':0})
    workspace.save_page({'page_id':'fixture-page','label':'M5 local fixture','path':'/','expected_revision':0})
    initialize(db,root)
    worker=TrustedWorker(EvidenceBridge(EvidenceFinalizer(Repository(db),ArtifactStore(root))))
    service=RuntimeService(workspace,worker)
    # The UI listener is needed by preflight; M4 activates only after preflight.
    home=LocalBaselineHOME(db,root,offline=workspace,runtime=service,approval_actor='m5-fixture-local-operator',
                           limits=BFFLimits(request_timeout_seconds=5,session_seconds=1800))
    home.start();lease=base.proxy();signer=observer=comparison=None
    resources=base.RESOURCES
    base.output({'type':'ready','proxy_port':base.PROXY_PORT,'ui_port':home.address[1],
                 'ca_pem':cert.read_text(),'pairing_code':home.pairing_for_local_user(),
                 'namespace':base.os.readlink('/proc/self/ns/net'),'uid':base.os.getuid(),
                 'resources':vars(resources)})

    def remote(req,remaining):
        running=[j for j,_,_ in service.store.bindings() if service.repo.get_job(j).status.value=='RUNNING']
        if len(running)!=1:raise RuntimeError('single active child required')
        jid=running[0]
        base.output({'type':'capture','job_id':jid,'request':{'page_id':req.page_id,'profile':profile_body(req.profile),
                     'url':req.url,'baseline_id':req.baseline_id},'remaining':remaining,'resources':vars(resources)})
        reply=base.command();length=reply.get('length');repeat_length=reply.get('repeat_length',0)
        if (reply.get('type')!='capture_result' or type(length) is not int or type(repeat_length) is not int
                or min(length,repeat_length)<0 or length+repeat_length>resources.output_bytes):
            raise ValueError('bounded producer payload required')
        wire=base.sys.stdin.buffer.read(length);repeat=base.sys.stdin.buffer.read(repeat_length)
        if len(wire)!=length or len(repeat)!=repeat_length:raise EOFError()
        observer.record_browser_report(jid,reply.get('browser_report',{}))
        if repeat and reply.get('reason')=='CAPTURE_COMPLETE':
            stream=FrameReader(io.BytesIO(wire),TrustedContext(jid,'capture-1',1)).read()
            png=next(f.payload for f in stream.frames if f.kind=='SCREENSHOT_PNG')
            observer.record_repetition(jid,png,repeat,(reply.get('browser_report') or {}).get('stability'))
        return io.BytesIO(wire),reply['reason'],reply.get('cleanup') is True

    try:
        while True:
            command=base.command();kind=command.get('type')
            if kind=='counts':
                with base.LOCK:base.output({'type':'counts','counts':dict(base.COUNTS)})
            elif kind=='stop_proxy':base.output({'type':'proxy_stopped','confirmed':lease.stop()})
            elif kind=='restart_proxy':
                if not lease.stop():raise RuntimeError('proxy cleanup unconfirmed')
                lease=base.proxy();base.output({'type':'proxy_ready','port':base.PROXY_PORT})
            elif kind=='enable_m5':
                if comparison is not None:raise RuntimeError('one initialization only')
                # Path lookup does not launch a browser. --version measurement
                # below occurs only after host preflight over this private pipe.
                with sync_playwright() as pw:executable=pw.chromium.executable_path
                observer=WorkerProfileObserver(command['image'],executable=executable)
                signer=EphemeralFixtureSigner(observer)
                initialize_comparison(db,root)
                comparison=ComparisonService(workspace,authority=signer.authority,
                    policy=PixelPolicy(0,'M5 controlled static fixture: exact RGBA equality; no production tolerance adoption'),
                    allow_unattested_preview=True)
                service.comparison=comparison
                home._comparison=comparison;home._approval._candidate_validator=comparison.validate_candidate
                base.output({'type':'enabled','observer':observer.report(),'key_events':signer.events})
            elif kind=='run':
                if comparison is None:raise RuntimeError('preflight/observer not enabled')
                VARIANT=command.get('variant','original')
                mode=command.get('case','normal')
                if mode=='mismatch':
                    for p in workspace.state()['profiles']:
                        a=p['profile']['attributes'];workspace.save_profile({'page_id':p['page_id'],'kind':p['kind'],
                            'width':a['viewport_width']+8,'height':a['viewport_height'],'expected_revision':p['revision']})
                batch=service.submit(source='REAL_CHROMIUM_FIXTURE_UNATTESTED')
                # Optional delayed execution allows approvals to advance after
                # submission, while the signed baseline pin remains unchanged.
                if command.get('defer') is True:
                    base.output({'type':'deferred','batch_id':batch});continue
                if mode=='unattested':comparison.authority=None
                try:
                    state=service.run(batch,remote,lease,resources)
                finally:comparison.authority=signer.authority
                base.output({'type':'result','batch_id':batch,'runtime':state,'comparison':comparison.state()})
            elif kind=='run_deferred':
                state=service.run(command['batch_id'],remote,lease,resources)
                base.output({'type':'result','batch_id':command['batch_id'],'runtime':state,'comparison':comparison.state()})
            elif kind=='restore_profiles':
                for p in workspace.state()['profiles']:
                    width=1440 if p['kind']=='Desktop' else 390;height=900 if p['kind']=='Desktop' else 844
                    workspace.save_profile({'page_id':p['page_id'],'kind':p['kind'],'width':width,'height':height,'expected_revision':p['revision']})
                base.output({'type':'profiles_restored'})
            elif kind=='state':base.output({'type':'state','runtime':service.state(),'comparison':comparison.state()})
            elif kind=='pairing':base.output({'type':'pairing','pairing_code':home.renew_pairing_for_local_user()})
            elif kind=='negative_evidence':
                sample=next(j for j in comparison.state()['jobs'] if j['evidence_available'] and j['baseline'])
                results={}
                for target in ('manifest','screenshot'):
                    clone=root/'negative-evidence'/target;clone.mkdir(parents=True,exist_ok=False)
                    # SQLite backup: no write or copy-over of the primary DB.
                    source=sqlite3.connect(f'file:{db}?mode=ro',uri=True)
                    destination=sqlite3.connect(clone/'siteproof.sqlite')
                    source.backup(destination);destination.close();source.close()
                    for jid,_,_ in service.store.bindings():
                        if (root/jid).is_dir():shutil.copytree(root/jid,clone/jid)
                    check=ComparisonService(OfflineWorkspace(clone/'siteproof.sqlite',clone),authority=signer.authority)
                    binding=check.store.body('candidates','capture-'+sample['job_id'])
                    path=clone/binding['evidence'][target]['artifact_ref'];path.write_bytes(b'M5 deliberate isolated fixture corruption')
                    result=check.compare(sample['job_id'])
                    results[target]={'quality':result['quality'],'reasons':result['reasons'],'diff_sha256':result['diff_sha256']}
                base.output({'type':'negative_evidence','results':results})
            elif kind=='tamper_checks':
                jobs=comparison.state()['jobs'];first,second=jobs[:2]
                env=comparison.store.body('jobs',first['job_id']);mutated=copy.deepcopy(env)
                mutated['body']['source']='tampered'
                tamper=not signer.authority.verifies(mutated)
                _,second_plan,second_evidence,_=comparison.observe(second['job_id'])
                replay=comparison.trust(env,second_plan,second_evidence)[0]=='UNATTESTED'
                signer.verification('tampered-plan',not tamper);signer.verification('cross-job-replay',not replay)
                base.output({'type':'tamper_checks','tamper_rejected':tamper,'replay_rejected':replay,'key_events':signer.events})
            elif kind=='expire_session':home.destroy_session();base.output({'type':'session_destroyed'})
            elif kind=='quit':break
            else:raise ValueError('unknown trusted fixture command')
    finally:
        if signer:
            signer.destroy()
            (root/'m5-key-events.json').write_text(json.dumps(signer.events,indent=2))
        if observer:(root/'m5-observer.json').write_text(json.dumps(observer.report(),indent=2))
        proxy_clean=lease.stop();ui_clean=home.stop()
        http.shutdown();http.server_close();thread.join(3)
        plain.shutdown();plain.server_close();plain_thread.join(3)
        for sock,t,stop in base.SERVERS:stop.set();sock.close();t.join(1)
        base.output({'type':'closed','proxy':proxy_clean,'ui':ui_clean,'key_revoked':signer.authority._key is None if signer else True,
                     'fixtures':all(not t.is_alive() for _,t,_ in base.SERVERS) and not thread.is_alive() and not plain_thread.is_alive()})


if __name__=='__main__':main()
