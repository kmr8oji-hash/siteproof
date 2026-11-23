"""Host orchestration: dedicated resources, measured preflight BEFORE Chromium.

Stopped containers are archived and removed at the final run boundary. All Docker
control remains on trusted Windows. Networks and volumes are retained. Images are
built separately from official pinned distributions; runtime containers have no
external network permit. Only public fixture CA/resolver files reach Browser.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import re
import io

from src.isolation.frames import FrameReader,TrustedContext

from src.runtime.docker_launcher import DockerLauncher,read_control,send_control


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--evidence',required=True)
    parser.add_argument('--image',default='siteproof-m2-runtime:20261105')
    args=parser.parse_args();root=Path.cwd()
    launch=DockerLauncher(args.evidence,args.image,root/'runtime/docker/seccomp-siteproof.json')
    token=time.strftime('%H%M%S');prefix='siteproof-m2-'+token
    worker_process=ui_process=None;anchor=None;worker_stderr=None
    report={'task':'SITEPROOF-M2-RUNTIME-VALIDATION-01','passed':False,'chromium_started':False}
    case=0
    def name(label):
        nonlocal case
        case+=1;return prefix+'-'+label+'-'+str(case)
    def container(label,uid,command,config,*,admin=False):
        opts=launch.options(anchor,uid)
        if admin:opts+=['--cap-add','NET_ADMIN']
        n=launch.create(name(label),opts,command)
        out,err=launch.bounded(n,json.dumps(config).encode()+b'\n',seconds=30)
        if err:launch.save(n+'-stderr.json',{'stderr':err.decode(errors='replace')})
        return json.loads(out)
    def control(obj):send_control(worker_process,obj);return read_control(worker_process)
    def snapshot(label):
        result=container('snapshot',0,['python','-m','tests.runtime.netpolicy'],
            {'type':'snapshot','netns':namespace},admin=True)
        launch.save(label+'.json',result);return result
    def drops(snapshot):
        out={}
        for line in (snapshot['ipv4']+snapshot['ipv6']).splitlines():
            match=re.match(r'\[(\d+):\d+\].*--comment (SP_BROWSER_\w+_DROP)',line)
            if match:out[match[2]]=int(match[1])
        return out
    def counts():return control({'type':'counts'})['counts']
    def probe(uid,label,mode=None):
        config={k:ready[k] for k in ('proxy_port','ui_port','ca_pem')}
        if mode:config['mode']=mode
        result=container('probe',uid,['python','-m','tests.runtime.netprobe'],config)
        launch.save(label+'.json',result)
        assert result['netns']==namespace
        assert result['uid']==uid
        assert any(x.split()==['CapBnd:','0000000000000000'] for x in result['status'])
        assert result['cgroup']['memory.max']=='805306368'
        assert result['cgroup']['pids.max']=='256'
        return result['results']
    def negative(label):
        before=counts();r=probe(1000,label)
        assert r.pop('proxy') is True
        assert not any(r.values()),r
        after=counts()
        assert all(after.get(k,0)==before.get(k,0) for k in forbidden_keys),(before,after)
        return before,after
    def browser_options(uid):
        return launch.options(anchor,uid,mounts=mounts)
    def browser_start(label,uid,config):
        if launch.boundary is None:raise RuntimeError('Browser blocked before preflight')
        assert launch.call('exec',anchor,'readlink','/proc/self/ns/net').strip()==namespace
        n=launch.create(name(label),browser_options(uid),['python','-m','tests.runtime.browser_process'])
        log=(launch.evidence/(n+'-stderr.log')).open('wb')
        p=subprocess.Popen(launch.cli+['start','-a','-i',n],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log)
        send_control(p,config)
        return n,p,log
    def browser_done(n,p,log):
        p.stdin.close();p.wait(timeout=15);log.close()
        if p.returncode:raise RuntimeError('Browser helper failed; see '+n+'-stderr.log')
        obj=launch.inspect(n)
        assert not obj['State']['Running'] and obj['State']['Pid']==0
        launch.save(n+'-inspection.json',{'state':obj['State'],'host_config':{
            k:obj['HostConfig'][k] for k in ('NetworkMode','CapAdd','CapDrop','SecurityOpt','ReadonlyRootfs','Memory','PidsLimit','NanoCpus','Binds','Mounts') if k in obj['HostConfig']}})
    try:
        image=json.loads(launch.call('image','inspect',args.image))[0]
        launch.image=image['Id']
        launch.save('runtime-image.json',{'id':image['Id'],'repo_digests':image['RepoDigests'],
            'base':'mcr.microsoft.com/playwright/python@sha256:330d401ae23c905896a0c26c66c36fc971b621519e7b11b435a8328d7bf6e031'})
        network=launch.create_network(prefix+'-network')
        volume=launch.create_volume(prefix+'-evidence')
        init=launch.create(name('volume-init'),['--network','none','--user','0:0','--cap-drop','ALL','--cap-add','CHOWN',
            '--security-opt','no-new-privileges=true','--read-only','--mount',f'type=volume,src={volume},dst=/evidence'],
            ['python','-c',"import os;os.chmod('/evidence',0o700);os.chown('/evidence',1001,1001)"])
        launch.bounded(init)
        anchor=launch.create(name('worker'),['--network',network,'--user','1001:1001','--cap-drop','ALL',
            '--security-opt','no-new-privileges=true','--read-only','--pids-limit','128','--memory','512m',
            '--memory-swap','512m','--cpus','1','--sysctl','net.ipv6.conf.all.disable_ipv6=0',
            '--sysctl','net.ipv4.ip_unprivileged_port_start=0',
            '--tmpfs','/tmp:rw,nosuid,nodev,size=128m,uid=1001,gid=1001','--mount',f'type=volume,src={volume},dst=/evidence'],
            ['python','-c','import time;time.sleep(86400)'])
        launch.call('start',anchor)
        namespace=launch.call('exec',anchor,'readlink','/proc/self/ns/net').strip()
        policy=container('policy-prepare',0,['python','-m','tests.runtime.netpolicy'],
            {'type':'prepare','netns':namespace,'ui_port':18081,'proxy_port':18080},admin=True)
        launch.save('policy-prepare.json',policy)
        worker_stderr=(launch.evidence/'worker-stderr.log').open('wb')
        worker_process=subprocess.Popen(launch.cli+['exec','-i','--user','1001:1001',anchor,'python','-m','tests.runtime.linux_worker'],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=worker_stderr)
        ready=read_control(worker_process,30);assert ready['type']=='ready'
        assert ready['namespace']==namespace and ready['uid']==1001
        launch.save('worker-ready.json',{k:v for k,v in ready.items() if k!='pairing_code'})
        ca=launch.evidence/'fixture-ca.crt';ca.write_text(ready['ca_pem'],encoding='ascii')
        resolver=launch.evidence/'resolv.conf';resolver.write_text('nameserver 127.0.0.3\noptions timeout:1 attempts:1\n',encoding='ascii')
        mounts=['--mount',f'type=bind,src={ca.resolve()},dst=/fixture-ca.crt,readonly',
                '--mount',f'type=bind,src={resolver.resolve()},dst=/etc/resolv.conf,readonly']
        policy=container('policy-install',0,['python','-m','tests.runtime.netpolicy'],
            {'type':'install','netns':namespace,'ui_port':ready['ui_port'],'proxy_port':ready['proxy_port']},admin=True)
        launch.save('policy-installed.json',policy)
        forbidden_keys=('tcp','dns','udp','metadata','lan','host_model','ipv6')
        positive=probe(1001,'preflight-positive')
        assert all(positive.values()),positive
        positive_counts=counts()
        assert all(positive_counts.get(k,0)>0 for k in forbidden_keys),positive_counts
        before,after=negative('preflight-capture')
        ui=probe(1003,'preflight-ui');assert ui.pop('ui') is True and not any(ui.values()),ui
        assert control({'type':'stop_proxy'})['confirmed'] is True
        stopped=probe(1000,'preflight-proxy-stopped','stopped');assert not any(stopped.values())
        assert control({'type':'restart_proxy'})['type']=='proxy_ready'
        negative('preflight-after-proxy-restart')
        snap=snapshot('preflight-rules')
        preflight={'passed':True,'netns':namespace,'canary_positive':positive_counts,
            'canary_zero':{k:after.get(k,0)-before.get(k,0) for k in forbidden_keys},
            'rule_sha256':hashlib.sha256((snap['ipv4']+snap['ipv6']).encode()).hexdigest()}
        launch.save('preflight.json',preflight);launch.seal(preflight,namespace)
        report['preflight']=preflight;report['chromium_started']=True
        # Keep the paired UI alive until real S1 results have been persisted.
        ui_name,ui_process,ui_log=browser_start('ui',1003,{'mode':'ui','ui_port':ready['ui_port'],'pairing_code':ready['pairing_code']})
        ui_ready=read_control(ui_process,30);assert ui_ready['type']=='ui_ready';launch.save('ui-initial.json',ui_ready)
        network_before=counts()
        rules_before=snapshot('browser-network-before')
        n,p,log=browser_start('browser-network',1000,{'mode':'network','proxy_port':ready['proxy_port']})
        msg=read_control(p,35);assert msg['type']=='need_proxy_stop'
        assert control({'type':'stop_proxy'})['confirmed'] is True
        send_control(p,{'type':'proxy_stopped'})
        result=read_control(p,15);browser_done(n,p,log)
        assert result['type']=='network_result' and all(result['checks'].values())
        network_after=counts();assert all(network_after.get(k,0)==network_before.get(k,0) for k in forbidden_keys)
        rules_after=snapshot('browser-network-after')
        old,new=drops(rules_before),drops(rules_after)
        drop_delta={key:new[key]-old[key] for key in new}
        assert len(drop_delta)==4 and all(v>0 for v in drop_delta.values()),drop_delta
        launch.save('browser-network.json',{'result':result,'before':network_before,'after':network_after,'protocol_drop_delta':drop_delta})
        control({'type':'restart_proxy'});negative('preflight-after-browser-stop-test')
        snapshot('browser-rules')
        # Real slow fixture: Playwright timeout classification and process cleanup.
        request={'page_id':'timeout-fixture','profile':{'profile_id':'Desktop','attributes':{
            'viewport_width':320,'viewport_height':240,'device_scale_factor':1,'color_scheme':'light',
            'locale':'ja-JP','timezone':'Asia/Tokyo','user_agent':'SiteProof controlled fixture',
            'reduced_motion':True,'full_page':False}},'url':'https://fixture.invalid/slow','baseline_id':None}
        http_request=dict(request);http_request['page_id']='http-fixture';http_request['url']='http://fixture.invalid/'
        out,_=launch.browser(name('http-fixture'),anchor,1000,['python','-m','tests.runtime.browser_process'],
            json.dumps({'mode':'capture','request':http_request,'proxy_port':18080,'resources':ready['resources']}).encode()+b'\n',mounts=mounts,seconds=20)
        line,wire=out.split(b'\n',1);http_meta=json.loads(line)
        assert http_meta['reason']=='CAPTURE_COMPLETE' and http_meta['cleanup']
        stream=FrameReader(io.BytesIO(wire),TrustedContext('http-fixture','capture-1',1)).read()
        assert stream.summary.termination=='CLEAN'
        png=next(f.payload for f in stream.frames if f.kind=='SCREENSHOT_PNG')
        (launch.evidence/'http-fixture.png').write_bytes(png)
        launch.save('http-fixture.json',{'metadata':http_meta,'png_sha256':hashlib.sha256(png).hexdigest(),
            'scope':'Exact test-only plain HTTP adapter; production CONNECT policy unchanged'})
        timeout_resources=dict(ready['resources']);timeout_resources['stage_seconds']=.5
        out,_=launch.browser(name('timeout'),anchor,1000,['python','-m','tests.runtime.browser_process'],
            json.dumps({'mode':'capture','request':request,'proxy_port':18080,'resources':timeout_resources}).encode()+b'\n',mounts=mounts,seconds=20)
        timeout_meta=json.loads(out.split(b'\n',1)[0]);assert timeout_meta['reason']=='HTTP_TIMEOUT' and timeout_meta['cleanup']
        launch.save('browser-timeout.json',timeout_meta)
        n,p,log=browser_start('cancel',1000,{'mode':'cancel','proxy_port':18080})
        msg=read_control(p,20);assert msg['type']=='cancel_ready'
        assert launch.stop(n);p.stdin.close();p.wait(timeout=10);log.close()
        assert not launch.inspect(n)['State']['Running'] and launch.inspect(n)['State']['Pid']==0
        launch.save('browser-cancel.json',{'process_group_stopped':True,'sandbox':msg['sandbox'],'exit_code':p.returncode})
        # Worker retains the actual transport/session and finalizes returned bytes.
        send_control(worker_process,{'type':'run'})
        captures=[]
        while True:
            msg=read_control(worker_process,35)
            if msg['type']=='result':state=msg['state'];break
            assert msg['type']=='capture'
            payload={'mode':'capture','request':msg['request'],'proxy_port':18080,'resources':ready['resources']}
            out,err=launch.browser(name('capture'),anchor,1000,['python','-m','tests.runtime.browser_process'],
                json.dumps(payload).encode()+b'\n',mounts=mounts,seconds=min(30,msg['remaining']))
            line,wire=out.split(b'\n',1);meta=json.loads(line)
            assert len(wire)==meta['length'] and meta['reason']=='CAPTURE_COMPLETE' and meta['cleanup']
            captures.append({'profile':msg['request']['profile']['profile_id'],'wire_sha256':hashlib.sha256(wire).hexdigest(),'metadata':meta})
            send_control(worker_process,{'type':'capture_result','length':len(wire),'reason':meta['reason'],'cleanup':True},wire)
        assert len(state['jobs'])==2
        assert all(j['execution']=='COMPLETED' and j['evidence'] and j['quality']=='UNKNOWN'
                   and j['profile_reason']=='PROFILE_UNATTESTED' for j in state['jobs'])
        launch.save('captures.json',captures);launch.save('runtime-state.json',state)
        send_control(ui_process,{'type':'runtime_ready'})
        assert read_control(ui_process,20)['type']=='ui_expire_session'
        assert control({'type':'expire_session'})['type']=='session_destroyed'
        send_control(ui_process,{'type':'session_destroyed'})
        ui_result=read_control(ui_process,20);browser_done(ui_name,ui_process,ui_log);ui_process=None
        assert ui_result['reason']=='UI_PASS' and all(ui_result['checks'].values())
        launch.save('ui-final.json',ui_result)
        final=control({'type':'state'})['state'];assert final==state
        assert control({'type':'quit'})=={'type':'closed','proxy':True,'ui':True,'fixtures':True}
        worker_process.stdin.close();worker_process.wait(timeout=10);worker_process=None
        export=launch.evidence/'s1';export.mkdir(exist_ok=True)
        launch.call('cp',anchor+':/evidence/siteproof.sqlite',str(export/'siteproof.sqlite'))
        for j in state['jobs']:
            launch.call('cp',anchor+':/evidence/'+j['job_id'],str(export/j['job_id']))
        report.update(passed=True,checks=['preflight','sandbox','browser_negative','proxy_stop',
            'timeout','cancel_process_group','plain_http_fixture','desktop_mobile','s1_manifest_readback','ui_pair_cookie_history_keyboard_error_session','cleanup'],
            formal_T01_T21='UNKNOWN',profile_trust='UNATTESTED',quality='UNKNOWN',plain_http='EXACT_TEST_FIXTURE_PASS')
    except Exception as exc:
        report['error']=str(exc)
        raise
    finally:
        # Close producers/control pipes before archival and non-forced removal.
        if worker_process is not None:
            try:
                send_control(worker_process,{'type':'quit'})
                read_control(worker_process,5)
            except Exception:pass
        report['all_owned_containers_stopped']=launch.stop_all()
        for process in (worker_process,ui_process):
            if process is not None:
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=5)
        if worker_stderr:worker_stderr.close()
        report['all_owned_containers_removed']=launch.cleanup()
        if not report['all_owned_containers_removed']:
            report['passed']=False
            report['cleanup_error']='CONTAINER_ARCHIVAL_OR_REMOVAL_FAILED'
        launch.save('validation-result.json',report)
        print(json.dumps(report,ensure_ascii=False,indent=2))
        if not report['all_owned_containers_removed']:
            raise RuntimeError('Container cleanup incomplete; inspect cleanup.json')


if __name__=='__main__':main()
