"""M5 real controlled fixture orchestration. No registry, real sites or AWS.

Reuse the existing bounded launcher/preflight. At most one capture and one UI
Browser are active. Helpers are reused and retired; volumes/images are retained.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import uuid

from src.runtime.docker_launcher import DockerLauncher, read_control, send_control


FORBIDDEN=('tcp','dns','udp','metadata','lan','host_model','ipv6')


class IsolationLeak(RuntimeError):pass


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--evidence',required=True);parser.add_argument('--image',default='sha256:9c88112b42070369876fdb24476af283b3908a3fdc630b66fedacf4f20c4d2c8');parser.add_argument('--resume-ui',action='store_true');parser.add_argument('--resume-history',action='store_true');args=parser.parse_args()
    if args.resume_history:args.resume_ui=True
    evidence=Path(args.evidence).resolve();evidence.mkdir(parents=True,exist_ok=False)
    launch=DockerLauncher(evidence,args.image,Path.cwd()/'runtime/docker/seccomp-siteproof.json')
    prefix='siteproof-m2-m5-'+time.strftime('%H%M%S')+'-'+uuid.uuid4().hex[:6]
    report={'task':'SITEPROOF-M5-LOCAL-UX-AND-PROFILE-01','passed':False,'chromium_started':False,
            'formal_T01_T21':'UNKNOWN','user_personal_UX':'NOT_RUN','profile_trust':'UNATTESTED'}
    worker_process=ui_process=None;worker_log=ui_log=None;anchor=policy=capture_container=ui_name=None
    prior=[];job_ids=set();counter=0;capture_count=0;states={}

    def name(label):
        nonlocal counter
        counter+=1;return prefix+'-'+label+'-'+str(counter)
    def other_containers():
        return sorted(launch.call('ps','-a','--no-trunc','--format','{{.ID}}|{{.Names}}|{{.State}}').splitlines())
    original_containers=other_containers();launch.save('other-containers-before.json',original_containers)
    def control(command,seconds=30):
        send_control(worker_process,command);return read_control(worker_process,seconds)
    def helper(label,uid,module,*,admin=False,mounts=()):
        opts=launch.options(anchor,uid,mounts=mounts)
        if admin:opts+=['--cap-add','NET_ADMIN']
        return launch.create(name(label),opts,['python','-m',module])
    def policy_call(kind,**kwargs):
        out,_=launch.bounded(policy,json.dumps({'type':kind,'netns':namespace,**kwargs}).encode()+b'\n')
        result=json.loads(out);launch.save('policy-'+kind+'-'+str(time.monotonic_ns())+'.json',result);return result
    def drops(snap):
        result={}
        for line in (snap['ipv4']+snap['ipv6']).splitlines():
            match=re.match(r'\[(\d+):\d+\].*--comment (SP_BROWSER_\w+_DROP)',line)
            if match:result[match[2]]=int(match[1])
        return result
    def counts():return control({'type':'counts'})['counts']
    def no_canary_delta(before,after,label):
        delta={k:after.get(k,0)-before.get(k,0) for k in FORBIDDEN}
        launch.save(label+'-canaries.json',delta)
        if any(delta.values()):
            launch.stop_all();raise IsolationLeak('forbidden canary received: '+label)
        return delta
    def probe(n,uid,label,mode=None):
        config={k:ready[k] for k in ('proxy_port','ui_port','ca_pem')}
        if mode:config['mode']=mode
        out,_=launch.bounded(n,json.dumps(config).encode()+b'\n')
        result=json.loads(out);launch.save(label+'.json',result)
        assert result['netns']==namespace and result['uid']==uid
        assert result['cgroup']['memory.max']=='805306368' and result['cgroup']['pids.max']=='256'
        assert result['cgroup']['cpu.max']=='100000 100000'
        for key,value in (('CapEff:','0000000000000000'),('CapBnd:','0000000000000000'),('NoNewPrivs:','1'),('Seccomp:','2')):
            assert any(line.split()==[key,value] for line in result['status']),(key,result['status'])
        return result['results']
    def start_ui(code):
        nonlocal ui_process,ui_log,ui_name
        assert launch.boundary and launch.call('exec',anchor,'readlink','/proc/self/ns/net').strip()==namespace
        ui_name=launch.create(name('ui'),launch.options(anchor,1003,mounts=mounts),['python','-m','tests.runtime.m5_browser'])
        ui_log=(evidence/'ui-stderr.log').open('ab')
        ui_process=subprocess.Popen(launch.cli+['start','-a','-i',ui_name],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=ui_log)
        send_control(ui_process,{'mode':'ui','ui_port':ready['ui_port'],'pairing_code':code})
        result=read_control(ui_process,30);assert result['type']=='ui_ready';launch.save('ui-ready.json',result)
    def ui(command,expected,seconds=45):
        send_control(ui_process,command);result=read_control(ui_process,seconds);chunks={}
        while result['type']=='screenshot_chunk':
            label=result['label'];assert label in ('desktop','mobile')
            data=chunks.setdefault(label,bytearray());assert result['offset']==len(data)
            data.extend(base64.b64decode(result['data'],validate=True));assert len(data)<=2*1024*1024
            result=read_control(ui_process,seconds)
        assert result['type']==expected,result.get('type')
        screenshots=result.pop('screenshots',{})
        for label,metadata in screenshots.items():
            data=bytes(chunks[label]);assert len(data)==metadata['length'] and hashlib.sha256(data).hexdigest()==metadata['sha256']
            (evidence/('ui-'+label+'.png')).write_bytes(data)
        launch.save('ui-'+expected+'-'+str(time.monotonic_ns())+'.json',result)
        return result
    def run_case(label,*,variant='original',mode='normal',batch=None):
        nonlocal capture_container,capture_count
        assert control({'type':'restart_proxy'})['type']=='proxy_ready'
        send_control(worker_process,{'type':'run_deferred','batch_id':batch} if batch else
                     {'type':'run','variant':variant,'case':mode})
        captures=[]
        while True:
            msg=read_control(worker_process,90)
            if msg['type']=='result':result=msg;break
            assert msg['type']=='capture'
            job_ids.add(msg['job_id']);capture_count+=1
            if capture_container is None:capture_container=helper('capture',1000,'tests.runtime.m5_browser',mounts=mounts)
            config={'mode':'crash' if mode=='crash' else 'capture','request':msg['request'],
                    'proxy_port':ready['proxy_port'],'resources':msg['resources']}
            if mode=='timeout':
                config['request']['url']='https://fixture.invalid/slow';config['resources']['stage_seconds']=.5
            label_path=evidence/('capture-'+str(capture_count))
            def sink(out,err,execution):
                label_path.with_suffix('.stdout.bin').write_bytes(out)
                label_path.with_suffix('.stderr.log').write_bytes(launch._redact_log(err))
                launch.save(label_path.name+'-execution.json',execution)
            try:
                out,_=launch.bounded(capture_container,json.dumps(config).encode()+b'\n',seconds=min(45,msg['remaining']),evidence_sink=sink)
                line,payload=out.split(b'\n',1);meta=json.loads(line)
                assert len(payload)==meta['length']+meta['repeat_length']
                clean=meta['cleanup'] is True
                reply={'type':'capture_result','length':meta['length'],'repeat_length':meta['repeat_length'],
                       'reason':meta['reason'],'cleanup':clean,'browser_report':meta['browser_report']}
                captures.append({'job_id':msg['job_id'],'kind':msg['request']['profile']['profile_id'],
                                 'reason':meta['reason'],'cleanup':clean,'sandbox':meta.get('sandbox')})
            except RuntimeError:
                if mode!='crash' or launch.last_execution['cleanup_confirmed'] is not True:raise
                payload=b'';reply={'type':'capture_result','length':0,'repeat_length':0,'reason':'CAPTURE_FAILED','cleanup':True}
                captures.append({'job_id':msg['job_id'],'reason':'ABNORMAL_EXIT_7','cleanup':True})
            send_control(worker_process,reply,payload)
        launch.save(label+'-captures.json',captures);launch.save(label+'-result.json',result)
        states[label]=result
        no_canary_delta(baseline_canaries,counts(),label)
        return result

    def export_evidence():
        if not anchor:return True
        exported=evidence/'s1';exported.mkdir(exist_ok=True)
        # Never export /evidence/private (temporary TLS key); profile key is not a file.
        if args.resume_ui:
            for run in ('02','03'):
                launch.call('cp',anchor+':/evidence/resume-'+run,str(exported/('resume-'+run)))
            return True
        launch.call('cp',anchor+':/evidence/siteproof.sqlite',str(exported/'siteproof.sqlite'))
        for jid in sorted(job_ids):
            # Failed attempts may have no published S1 directory.
            try:launch.call('cp',anchor+':/evidence/'+jid,str(exported/jid))
            except RuntimeError:pass
        for filename in ('m5-key-events.json','m5-observer.json'):
            try:launch.call('cp',anchor+':/evidence/'+filename,str(exported/filename))
            except RuntimeError:pass
        if 'negative_evidence' in report:
            launch.call('cp',anchor+':/evidence/negative-evidence',str(evidence/'negative-evidence'))
        manifest={str(p.relative_to(evidence)):hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in evidence.rglob('*') if p.is_file() and p.name!='export-sha256.json'}
        launch.save('export-sha256.json',manifest)
        return True

    try:
        image=json.loads(launch.call('image','inspect',launch.image))[0];launch.image=image['Id']
        launch.save('runtime-image.json',{'id':image['Id'],'os':image['Os'],'architecture':image['Architecture']})
        # Reuse historical evidence READ ONLY, never run or reauthenticate its jobs.
        prior_volumes=() if args.resume_ui else ('siteproof-m2-170608-evidence','siteproof-m2-m3b-220048-evidence')
        for volume in prior_volumes:
            read_code="import hashlib,json,pathlib,sqlite3; r=pathlib.Path('/prior'); p=r/'siteproof.sqlite'; c=sqlite3.connect('file:/prior/siteproof.sqlite?mode=ro',uri=True) if p.exists() else None; print(json.dumps({'volume_present':r.is_dir(),'db_sha256':hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None,'jobs':c.execute('select status,count(*) from jobs group by status').fetchall() if c else [],'png_count':len(list(r.glob('*/*/*.png')))})); c.close() if c else None"
            opts=['--network','none','--user','1001:1001','--cap-drop','ALL','--security-opt','no-new-privileges=true','--read-only',
                  '--memory','128m','--pids-limit','16','--mount',f'type=volume,src={volume},dst=/prior,readonly']
            n=launch.create(name('prior-readonly'),opts,['python','-c',read_code])
            out,_=launch.bounded(n);result=json.loads(out);prior.append({'volume':volume,**result});launch.retire(n)
        launch.save('prior-readonly.json',prior)
        network=launch.create_network(prefix+'-network');volume=launch.create_volume(prefix+'-evidence')
        init=launch.create(name('volume-init'),['--network','none','--user','0:0','--cap-drop','ALL','--cap-add','CHOWN',
            '--security-opt','no-new-privileges=true','--read-only','--mount',f'type=volume,src={volume},dst=/evidence'],
            ['python','-c',"import os;os.chmod('/evidence',0o700);os.chown('/evidence',1001,1001)"])
        launch.bounded(init);launch.retire(init)
        resume_mounts=[]
        if args.resume_ui:
            for run in ('02','03'):
                source=Path('.local/m5-run-'+run+'/s1').resolve()
                assert source.is_dir()
                resume_mounts+=['--mount',f'type=bind,src={source},dst=/resume-run{run},readonly']
            for rel in ('src/bff/local_ui.py','src/bff/ui/index.html','src/bff/ui/baseline.css'):
                overlay=Path(rel).resolve()
                resume_mounts+=['--mount',f'type=bind,src={overlay},dst=/opt/siteproof/{rel},readonly']
            source=Path('tests/runtime/m5_ui_worker.py').resolve()
            resume_mounts+=['--mount',f'type=bind,src={source},dst=/opt/siteproof/tests/runtime/m5_ui_worker.py,readonly']
        anchor=launch.create(name('worker'),[*resume_mounts,'--network',network,'--user','1001:1001','--cap-drop','ALL',
            '--security-opt','no-new-privileges=true','--read-only','--pids-limit','128','--memory','512m','--memory-swap','512m','--cpus','1',
            '--sysctl','net.ipv6.conf.all.disable_ipv6=0','--sysctl','net.ipv4.ip_unprivileged_port_start=0',
            '--tmpfs','/tmp:rw,nosuid,nodev,size=128m,uid=1001,gid=1001','--mount',f'type=volume,src={volume},dst=/evidence'],
            ['python','-c','import time;time.sleep(86400)'])
        launch.call('start',anchor);namespace=launch.call('exec',anchor,'readlink','/proc/self/ns/net').strip()
        policy=helper('policy',0,'tests.runtime.netpolicy',admin=True)
        policy_call('prepare',ui_port=18081,proxy_port=18080)
        worker_log=(evidence/'worker-stderr.log').open('wb')
        worker_process=subprocess.Popen(launch.cli+['exec','-i','--user','1001:1001',anchor,'python','-m',*(['tests.runtime.m5_ui_worker','02' if args.resume_history else '03'] if args.resume_ui else ['tests.runtime.m5_worker'])],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=worker_log)
        ready=read_control(worker_process,30);assert ready['type']=='ready' and ready['namespace']==namespace
        launch.save('worker-ready.json',{k:v for k,v in ready.items() if k!='pairing_code'})
        ca=evidence/'fixture-ca.crt';ca.write_text(ready['ca_pem'],encoding='ascii')
        resolver=evidence/'resolv.conf';resolver.write_text('nameserver 127.0.0.3\noptions timeout:1 attempts:1\n',encoding='ascii')
        mounts=['--mount',f'type=bind,src={ca},dst=/fixture-ca.crt,readonly','--mount',f'type=bind,src={resolver},dst=/etc/resolv.conf,readonly']
        if args.resume_ui:
            source=Path('tests/runtime/m5_browser.py').resolve()
            mounts+=['--mount',f'type=bind,src={source},dst=/opt/siteproof/tests/runtime/m5_browser.py,readonly']
        policy_call('install',ui_port=ready['ui_port'],proxy_port=ready['proxy_port'])
        positive_n=helper('positive-probe',1001,'tests.runtime.netprobe')
        positive=probe(positive_n,1001,'preflight-positive');assert all(positive.values());launch.retire(positive_n)
        positive_counts=counts();assert all(positive_counts.get(k,0)>0 for k in FORBIDDEN)
        browser_probe=helper('browser-probe',1000,'tests.runtime.netprobe')
        before=counts();negative=probe(browser_probe,1000,'preflight-negative');assert negative.pop('proxy') is True
        assert not any(negative.values());after=counts();zero=no_canary_delta(before,after,'preflight')
        ui_probe=helper('ui-probe',1003,'tests.runtime.netprobe')
        result=probe(ui_probe,1003,'preflight-ui');assert result.pop('ui') is True and not any(result.values());launch.retire(ui_probe)
        assert control({'type':'stop_proxy'})['confirmed'] is True
        stopped=probe(browser_probe,1000,'preflight-proxy-stop','stopped');assert not any(stopped.values())
        assert control({'type':'restart_proxy'})['type']=='proxy_ready'
        restarted=probe(browser_probe,1000,'preflight-proxy-restart');assert restarted.pop('proxy') is True and not any(restarted.values())
        launch.retire(browser_probe)
        rules=policy_call('snapshot')
        preflight={'passed':True,'netns':namespace,'canary_positive':positive_counts,'canary_zero':zero,
                   'rule_sha256':hashlib.sha256((rules['ipv4']+rules['ipv6']).encode()).hexdigest()}
        launch.seal(preflight,namespace);launch.save('preflight.json',preflight);report['preflight']=preflight
        if not args.resume_ui:
            observations=launch.capture_profile_observations(anchor)
            image_conditions={'image_digest':observations['image_digest']['value'],'os':observations['os']['value'],
                              'architecture':observations['architecture']['value'],'source':observations['image_digest']['source']}
            enabled=control({'type':'enable_m5','image':image_conditions});assert enabled['type']=='enabled'
            launch.save('observer-enabled.json',enabled)
        # Actual Chromium negative controls reuse M2's reviewed browser probe.
        network_before=counts();rules_before=policy_call('snapshot')
        n=helper('chromium-negative',1000,'tests.runtime.browser_process',mounts=mounts)
        stderr=(evidence/'network-browser-stderr.log').open('wb')
        p=subprocess.Popen(launch.cli+['start','-a','-i',n],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=stderr)
        report['chromium_started']=True
        send_control(p,{'mode':'network','proxy_port':ready['proxy_port']})
        assert read_control(p,35)['type']=='need_proxy_stop'
        assert control({'type':'stop_proxy'})['confirmed'] is True;send_control(p,{'type':'proxy_stopped'})
        result=read_control(p,20);p.stdin.close();p.wait(timeout=10);stderr.close();assert p.returncode==0
        no_canary_delta(network_before,counts(),'chromium-negative')
        if not all(result['checks'].values()):raise IsolationLeak('Chromium bypass check failed')
        rules_after=policy_call('snapshot');old,new=drops(rules_before),drops(rules_after)
        assert len(new)==4 and all(new[k]>old[k] for k in new)
        launch.save('chromium-network.json',{'result':result,'protocol_drop_delta':{k:new[k]-old[k] for k in new}})
        launch.retire(n);control({'type':'restart_proxy'})
        baseline_canaries=counts()
        code=control({'type':'pairing'})['pairing_code'];start_ui(code);code=None
        if args.resume_ui:
            state=control({'type':'state'})['comparison']
            if not args.resume_history:
                ui({'type':'module_failure_probe','candidate_id':state['jobs'][0]['candidate']['candidate_id']},'module_failure_confirmed')
                ui({'type':'approve','jobs':[{'candidate_id':j['candidate']['candidate_id']} for j in state['jobs']]},'approved')
            if args.resume_history:
                # Previously observed real captures and stored PNG diffs, no recapture.
                candidates=[r for r in state['results'] if r['metrics'] and r.get('preview_only')]
                for changed in (False,True):
                    r=next(r for r in candidates if (r['metrics']['changed_pixels']>0)==changed)
                    ui({'type':'inspect_result','result_id':r['result_id'],'candidate_id':'capture-'+r['job_id'],'changed':changed,'compare_action':False},'result_inspected')
                ui({'type':'missing','result_id':r['result_id']},'missing_checked')
                control({'type':'expire_session'});ui({'type':'expired'},'expired_checked')
            final_ui=ui({'type':'quit'},'ui_closed');assert final_ui['all_checks']
            ui_process.stdin.close();ui_process.wait(timeout=10);assert ui_process.returncode==0;ui_process=None;ui_log.close()
            report['ui']=final_ui
            closed=control({'type':'quit'});assert all(closed[k] for k in ('ui','proxy','fixtures'))
            worker_process.stdin.close();worker_process.wait(timeout=15);assert worker_process.returncode==0;worker_process=None
            report.update(passed=True,scope='RESUME_HISTORY_ONLY' if args.resume_history else 'RESUME_APPROVAL_ONLY',worker_closed=closed,reused_capture_evidence='m5-run-02',quality='UNKNOWN')
        else:
            initial=run_case('initial')
            jobs=initial['comparison']['jobs'][:2]
            assert all(j['candidate']['baseline_state']=='BASELINE_PENDING' for j in jobs)
            assert all(r['quality']=='UNKNOWN' and r['baseline'] is None for r in initial['comparison']['results'][:2])
            ui({'type':'approve','jobs':[{'candidate_id':j['candidate']['candidate_id']} for j in jobs]},'approved')
            same=run_case('same')
            assert all(r['quality']=='UNKNOWN' and r['preview_only'] and r['metrics']['changed_pixels']==0 for r in same['comparison']['results'][:2])
            r=same['comparison']['results'][0]
            ui({'type':'inspect_result','result_id':r['result_id'],'candidate_id':'capture-'+r['job_id'],'changed':False},'result_inspected')
            changed=run_case('changed',variant='changed')
            assert all(r['quality']=='UNKNOWN' and r['preview_only'] and r['metrics']['changed_pixels']>0 for r in changed['comparison']['results'][:2])
            r=changed['comparison']['results'][0]
            ui({'type':'inspect_result','result_id':r['result_id'],'candidate_id':'capture-'+r['job_id'],'changed':True},'result_inspected')
            deferred=control({'type':'run','variant':'changed','defer':True});assert deferred['type']=='deferred'
            ui({'type':'approve','jobs':[{'candidate_id':j['candidate']['candidate_id']} for j in changed['comparison']['jobs'][:2]]},'approved')
            pinned=run_case('pinned-version',batch=deferred['batch_id'])
            assert all(r['baseline']['version']==1 for r in pinned['comparison']['results'][:2])
            mismatch=run_case('profile-mismatch',mode='mismatch')
            assert all(r['quality']=='UNKNOWN' and 'PROFILE_MISMATCH' in r['reasons'] and r['metrics'] is None for r in mismatch['comparison']['results'][:2])
            control({'type':'restore_profiles'})
            unattested=run_case('unattested',mode='unattested',variant='changed')
            assert all(r['quality']=='UNKNOWN' and 'PROFILE_UNATTESTED' in r['reasons'] for r in unattested['comparison']['results'][:2])
            # Use a new valid capture for clone-only evidence corruption checks.
            valid=run_case('valid-for-integrity',variant='changed')
            report['negative_evidence']=control({'type':'negative_evidence'},60)
            assert all(r['quality']=='UNKNOWN' and r['diff_sha256'] is None for r in report['negative_evidence']['results'].values())
            report['signature_checks']=control({'type':'tamper_checks'})
            assert report['signature_checks']['tamper_rejected'] and report['signature_checks']['replay_rejected']
            timeout=run_case('timeout',mode='timeout')
            assert all(j['execution']=='TIMED_OUT' and not j['evidence'] for j in timeout['runtime']['jobs'][:2])
            crash=run_case('abnormal-exit',mode='crash')
            assert all(j['execution']=='FAILED_EXECUTION' and not j['evidence'] for j in crash['runtime']['jobs'][:2])
            latest=valid['comparison']['results'][0]
            ui({'type':'missing','result_id':latest['result_id']},'missing_checked')
            control({'type':'expire_session'});ui({'type':'expired'},'expired_checked')
            final_ui=ui({'type':'quit'},'ui_closed');assert final_ui['all_checks']
            ui_process.stdin.close();ui_process.wait(timeout=10);ui_log.close();assert ui_process.returncode==0;ui_process=None
            report['ui']=final_ui
            closed=control({'type':'quit'});assert closed=={'type':'closed','proxy':True,'ui':True,'key_revoked':True,'fixtures':True}
            worker_process.stdin.close();worker_process.wait(timeout=15);assert worker_process.returncode==0;worker_process=None
            report['worker_closed']=closed
            report.update(passed=True,capture_processes=capture_count,quality='UNKNOWN',
                          fixture_comparison='BYTE_IDENTICAL_AND_CHANGED_PREVIEW_VERIFIED',
                          production_profile_authenticity='UNKNOWN',production_threshold='NOT_ADOPTED')
    except Exception as exc:
        report['error_type']=type(exc).__name__
        report['error']=str(exc)[:400] if isinstance(exc,(AssertionError,IsolationLeak)) else 'Inspect bounded fixture logs'
        report['isolation_leak']=isinstance(exc,IsolationLeak)
        raise
    finally:
        if ui_process is not None:
            try:send_control(ui_process,{'type':'quit'});read_control(ui_process,5)
            except Exception:pass
        if worker_process is not None:
            try:send_control(worker_process,{'type':'quit'});read_control(worker_process,5)
            except Exception:pass
        export_ok=False
        try:export_ok=export_evidence()
        except Exception:report['export_error']='EVIDENCE_EXPORT_UNCONFIRMED';report['passed']=False
        report['all_owned_stopped']=launch.stop_all()
        for process in (worker_process,ui_process):
            if process is not None:
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=5)
                for pipe in (process.stdin,process.stdout):
                    try:
                        if pipe is not None and not pipe.closed:pipe.close()
                    except OSError:pass
        for handle in (worker_log,ui_log):
            if handle is not None and not handle.closed:handle.close()
        report['all_owned_removed']=launch.cleanup() if export_ok else False
        if not report['all_owned_removed']:report['passed']=False
        after=other_containers();report['other_containers_unchanged']=after==original_containers
        launch.save('other-containers-after.json',after)
        if not report['other_containers_unchanged']:report['passed']=False
        launch.save('validation-result.json',report)
        print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
