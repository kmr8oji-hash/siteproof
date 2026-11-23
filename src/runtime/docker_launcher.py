"""Dedicated Docker Desktop launcher; no global config changes or volume deletion.

Only recorded container IDs with the exact task label can be stopped. Browser
startup additionally requires the validator's measured namespace-bound preflight.
Docker API/control pipes belong to the trusted host, never to Browser containers.
Harnesses must call cleanup() after evidence export and process/pipe shutdown;
stop_all() alone intentionally only stops containers for compatibility/reuse.
"""
import json
import hashlib
from pathlib import Path
import queue
import re
import subprocess
import threading
import time


TASK='M2-RUNTIME-VALIDATION-01'
LABEL='siteproof.task='+TASK


class BoundedExecutionError(TimeoutError):
    """Failed execution, with a separate acknowledgement of resource cleanup."""
    def __init__(self,reason,report):
        super().__init__(reason)
        self.reason=reason
        self.cleanup_confirmed=report['cleanup_confirmed']
        self.report=report


class DockerLauncher:
    def __init__(self,evidence,image,seccomp):
        self.evidence=Path(evidence);self.evidence.mkdir(parents=True,exist_ok=True)
        self.cli=['C:/Program Files/Docker/Docker/resources/bin/docker.exe','--context','desktop-linux']
        endpoint=self.call('context','inspect','desktop-linux','--format','{{.Endpoints.docker.Host}}').strip()
        if endpoint!='npipe:////./pipe/dockerDesktopLinuxEngine':raise RuntimeError('local engine required')
        self.image=image;self.seccomp=str(Path(seccomp).resolve())
        profile=json.loads(Path(seccomp).read_text())
        if profile.get('defaultAction')!='SCMP_ACT_ERRNO':raise ValueError('bounded seccomp required')
        self.resources={};self.boundary=None;self.counter=0
        self.retired={}

    def call(self,*args,input=None,timeout=30):
        r=subprocess.run(self.cli+list(args),input=input,capture_output=True,text=True,timeout=timeout)
        if r.returncode:raise RuntimeError('Docker command failed: '+r.stderr[-2000:])
        return r.stdout

    def save(self,name,obj):
        (self.evidence/name).write_text(json.dumps(obj,indent=2,ensure_ascii=False),encoding='utf8')

    def record(self,kind,name,identifier):
        self.resources[name]={'kind':kind,'id':identifier}
        self.save('resources.json',self.resources)

    def create_network(self,name):
        if name in self.call('network','ls','--format','{{.Name}}').splitlines():
            raise RuntimeError('network collision')
        ident=self.call('network','create','--internal','--label',LABEL,name).strip()
        self.record('network',name,ident);return name

    def create_volume(self,name):
        # Never reuse a pre-existing volume, including another project's volume.
        existing=self.call('volume','ls','--format','{{.Name}}').splitlines()
        if name in existing:raise RuntimeError('volume collision')
        ident=self.call('volume','create','--label',LABEL,name).strip()
        self.record('volume',name,ident);return name

    def create(self,name,options,command):
        if not name.startswith('siteproof-m2-'):raise ValueError('dedicated name required')
        ident=self.call('create','--interactive','--name',name,'--label',LABEL,*options,self.image,*command).strip()
        self.record('container',name,ident);return name

    def inspect(self,name):
        obj=json.loads(self.call('inspect',name))[0]
        expected=self.resources[name]
        if (expected['kind']!='container' or obj['Id']!=expected['id']
                or obj['Config']['Labels'].get('siteproof.task')!=TASK):
            raise RuntimeError('resource ownership mismatch')
        return obj

    def stop(self,name):
        obj=self.inspect(name)
        if obj['State']['Running']:self.call('stop','--time','3',name,timeout=15)
        return not self.inspect(name)['State']['Running']

    def capture_profile_observations(self,name):
        """Partial trusted image observations; never certify browser conditions.

        Uses only recorded owned container/image IDs, with an identity recheck.
        Image metadata cannot verify Browser/Playwright versions, fonts, context
        options or stability. Those fields deliberately remain absent. No exec,
        launch, pull, network request or inference from Browser output occurs.
        """
        obj=self.inspect(name)
        info=json.loads(self.call('image','inspect',obj['Image']))[0]
        current=self.inspect(name)
        identifier=info.get('Id','')
        if (current['Image']!=obj['Image'] or identifier!=obj['Image']
                or not re.fullmatch(r'sha256:[0-9a-f]{64}',identifier)
                or not all(type(info.get(k)) is str and info[k] for k in ('Os','Architecture'))):
            raise RuntimeError('image observation unconfirmed')
        source='launcher:docker-image-inspect:'+identifier
        return {key:{'value':value,'source':source} for key,value in
                (('os',info['Os']),('architecture',info['Architecture']),('image_digest',identifier[7:]))}

    def stop_all(self):
        result={}
        for name,record in self.resources.items():
            if record['kind']=='container':
                if name in getattr(self,'retired',{}):
                    result[name]=True;continue
                try:result[name]=self.stop(name)
                except Exception:result[name]=False
        self.save('stopped.json',result)
        return all(result.values())

    def _container_logs(self,identifier,*,limit=2*1024*1024,seconds=10):
        """Archive the last 64 log entries; incomplete collection prevents deletion.

        Only the local Docker CLI is killed on a collection failure. No container
        is restarted, and no unredacted logs are written to the filesystem. Full
        application outputs/frames must already be exported by the harness; a
        container log is a bounded diagnostic tail, not an evidence store.
        """
        p=subprocess.Popen(self.cli+['logs','--timestamps','--tail','64',identifier],
                           stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        data=bytearray();overflow=threading.Event();failed=threading.Event()
        def collect():
            try:
                while True:
                    chunk=p.stdout.read(16384)
                    if not chunk:break
                    remaining=max(0,limit-len(data));data.extend(chunk[:remaining])
                    if len(chunk)>remaining:overflow.set()
            except OSError:failed.set()
        thread=threading.Thread(target=collect,daemon=True);thread.start()
        deadline=time.monotonic()+seconds;timed_out=False
        try:
            while p.poll() is None:
                if overflow.is_set() or time.monotonic()>=deadline:
                    timed_out=True;p.kill();break
                time.sleep(.02)
            p.wait(timeout=3)
        finally:
            if p.poll() is None:p.kill();p.wait(timeout=3)
            thread.join(3)
            if not thread.is_alive():p.stdout.close()
        if (timed_out or overflow.is_set() or failed.is_set()
                or thread.is_alive() or p.returncode):
            raise RuntimeError('container logs not completely archived')
        return bytes(data)

    @staticmethod
    def _redact_log(raw):
        text=raw.decode('utf8',errors='replace')
        text=re.sub(r'(?im)(authorization|(?:set-)?cookie|pairing[_ -]?code|'
                    r'csrf[_ -]?token|password|secret|bearer)[^\r\n]*',
                    lambda m:m[1]+': [REDACTED]',text)
        # Pairing/session values and binary/base64 output are not useful in logs.
        # Exact container/image IDs and evidence hashes are retained in metadata.
        return re.sub(r'[A-Za-z0-9_+/=-]{24,}','[REDACTED_LONG_VALUE]',text).encode('utf8')

    def retire(self,name):
        """Archive then remove one stopped owned container, never its volumes.

        Reusable helpers remain available throughout a run. Call cleanup() only
        after exporting application evidence and closing all control processes.
        A writable container root or unowned writable mount requires manual review.
        """
        if name in self.retired:return self.retired[name]
        obj=self.inspect(name);hc=obj['HostConfig'];identifier=obj['Id']
        if obj['State']['Running'] or obj['State']['Pid']!=0:
            raise RuntimeError('running container cannot be retired')
        if not hc['ReadonlyRootfs']:
            raise RuntimeError('writable container data requires explicit export')
        for mount in obj['Mounts']:
            if not mount['RW']:continue
            if mount['Type']!='volume':raise RuntimeError('writable bind mount requires review')
            volume=json.loads(self.call('volume','inspect',mount['Name']))[0]
            if (volume.get('Labels') or {}).get('siteproof.task')!=TASK:
                raise RuntimeError('shared writable volume requires review')
        raw=self._container_logs(identifier)
        directory=self.evidence/'containers'/identifier;directory.mkdir(parents=True,exist_ok=False)
        config=obj['Config']
        metadata={'id':identifier,'name':name,'labels':config['Labels'],
            'image_id':obj['Image'],'image_ref':config['Image'],'created':obj['Created'],
            'state':obj['State'],'mounts':obj['Mounts'],'networks':obj['NetworkSettings']['Networks'],
            'host_config':{k:hc[k] for k in ('NetworkMode','CapAdd','CapDrop','SecurityOpt',
                'ReadonlyRootfs','Memory','MemorySwap','PidsLimit','NanoCpus','Ulimits','PortBindings')},
            'user':config['User'],
            'command_sha256':hashlib.sha256(json.dumps(config['Cmd']).encode()).hexdigest(),
            'environment_names':[v.split('=',1)[0] for v in config.get('Env',[])],
            'raw_log_sha256':hashlib.sha256(raw).hexdigest(),'raw_log_bytes':len(raw),
            'log_scope':'last 64 Docker log entries, maximum 2 MiB; not full application output',
            'log_policy':'redacted text only; stdin, argv and environment values not archived',
            'data_policy':'readonly root; named owned volumes retained; no rm -v'}
        files={'metadata.json':json.dumps(metadata,indent=2).encode('utf8'),
               'docker.log':self._redact_log(raw)}
        hashes={}
        for filename,data in files.items():
            path=directory/filename;path.write_bytes(data)
            digest=hashlib.sha256(data).hexdigest()
            if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
                raise RuntimeError('archive verification failed')
            hashes[filename]=digest
        (directory/'sha256.json').write_text(json.dumps(hashes,indent=2),encoding='utf8')
        # Recheck immutable ID, label and state immediately before non-forced rm.
        current=self.inspect(name)
        if (current['State']['Running'] or current['State']['Pid']!=0
                or current['State']!=obj['State']):
            raise RuntimeError('container became active during archival')
        self.call('rm',identifier)
        if self.call('ps','-aq','--no-trunc','--filter','id='+identifier).strip():
            raise RuntimeError('container removal unconfirmed')
        self.retired[name]={'id':identifier,'archive':str(directory),'removed':True}
        self.save('retired.json',self.retired)
        return self.retired[name]

    def cleanup(self):
        """Final run boundary: stop, archive, remove; failures remain visible.

        Images, networks and volumes are deliberately retained. This does not
        change the historical stop_all() stop-only contract.
        """
        result={}
        if not self.stop_all():
            self.save('cleanup.json',{'passed':False,'reason':'STOP_UNCONFIRMED'})
            return False
        for name,record in reversed(list(self.resources.items())):
            if record['kind']!='container':continue
            try:
                self.retire(name);result[name]={'removed':True}
            except Exception as exc:
                # No raw exception text: it can include Docker/OS private details.
                result[name]={'removed':False,'error_type':type(exc).__name__}
        passed=all(r['removed'] for r in result.values())
        self.save('cleanup.json',{'passed':passed,'containers':result})
        return passed

    def options(self,anchor,uid,*,memory='768m',pids=256,mounts=()):
        return ['--network','container:'+anchor,'--user',f'{uid}:{uid}','--cap-drop','ALL',
            '--security-opt','no-new-privileges=true','--security-opt','seccomp='+self.seccomp,
            '--read-only','--pids-limit',str(pids),'--memory',memory,'--memory-swap',memory,
            '--cpus','1','--ulimit','nofile=256:256','--shm-size','128m',
            '--tmpfs',f'/tmp:rw,nosuid,nodev,size=256m,uid={uid},gid={uid}',
            '--env','HOME=/tmp/browser-home',*mounts]

    def bounded(self,name,payload=b'',*,seconds=30,limit=5*1024*1024,evidence_sink=None):
        self.inspect(name)
        p=subprocess.Popen(self.cli+['start','-a','-i',name],stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        out,err=bytearray(),bytearray()
        exceeded,read_failed=threading.Event(),threading.Event()
        received=[0,0]
        def collect(source,target,cap,index):
            try:
                while True:
                    chunk=source.read(16384)
                    if not chunk:break
                    received[index]+=len(chunk)
                    remaining=max(0,cap-len(target))
                    target.extend(chunk[:remaining])
                    if len(chunk)>remaining:exceeded.set()
                    # Keep draining after overflow. Breaking here can block Docker's
                    # attach/stop acknowledgement even after the container is killed.
            except OSError:read_failed.set()
        threads=[threading.Thread(target=collect,args=(p.stdout,out,limit,0),daemon=True),
                 threading.Thread(target=collect,args=(p.stderr,err,65536,1),daemon=True)]
        for t in threads:t.start()
        reason=None;error=None;cleanup_errors=[];stopped=False;reaped=False
        try:
            p.stdin.write(payload);p.stdin.close()
            deadline=time.monotonic()+seconds
            while p.poll() is None:
                if exceeded.is_set():reason='OUTPUT_LIMIT';break
                if read_failed.is_set():reason='OUTPUT_READ_FAILED';break
                if time.monotonic()>=deadline:reason='TIMEOUT';break
                time.sleep(.02)
        except BaseException as exc:
            error=exc
        finally:
            # Stop the recorded container/cgroup before reaping its Docker CLI.
            # A Docker API failure must not skip CLI/pipe cleanup or become PASS.
            try:stopped=self.stop(name)
            except Exception as exc:cleanup_errors.append('stop:'+type(exc).__name__)
            try:
                p.wait(timeout=10);reaped=True
            except Exception as exc:
                cleanup_errors.append('wait:'+type(exc).__name__)
                try:
                    p.terminate()  # Local attach CLI only; not a container-stop fallback.
                    try:p.wait(timeout=3)
                    except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)
                    reaped=True
                except Exception as exc:cleanup_errors.append('cli:'+type(exc).__name__)
            for t in threads:t.join(3)
            # Closing a pipe under a blocked reader can itself wait indefinitely.
            # Unfinished readers are explicitly unconfirmed, never silent success.
            for source,thread in ((p.stdout,threads[0]),(p.stderr,threads[1])):
                if thread.is_alive():cleanup_errors.append('reader:UNCONFIRMED');continue
                try:source.close()
                except Exception as exc:cleanup_errors.append('pipe:'+type(exc).__name__)
            try:
                if not p.stdin.closed:p.stdin.close()
            except Exception as exc:cleanup_errors.append('stdin:'+type(exc).__name__)
        if exceeded.is_set():reason='OUTPUT_LIMIT'
        elif read_failed.is_set():reason='OUTPUT_READ_FAILED'
        cleanup=(stopped is True and reaped and not cleanup_errors
                 and all(not t.is_alive() for t in threads)
                 and all(s.closed for s in (p.stdin,p.stdout,p.stderr)))
        outcome=reason or ('CONTROL_ERROR' if error is not None else
                          'CONTAINER_FAILED' if p.returncode else 'COMPLETE')
        report={'reason':outcome,'cleanup_confirmed':cleanup,'container_stopped':stopped,
            'cli_reaped':reaped,'readers_joined':all(not t.is_alive() for t in threads),
            'pipes_closed':all(s.closed for s in (p.stdin,p.stdout,p.stderr)),
            'stdout_retained':len(out),'stderr_retained':len(err),'received':received,
            'stdout_limit':limit,'stderr_limit':65536,'exit_code':p.returncode,
            'cleanup_errors':cleanup_errors}
        self.last_execution=report
        # Optional trusted harness sink receives capped bytes ONLY after stop/
        # pipe supervision. It must exclude credentials and must never adopt a
        # partial capture as S1 evidence. Default behavior is unchanged.
        if evidence_sink is not None:evidence_sink(bytes(out),bytes(err),report)
        if not cleanup:raise BoundedExecutionError('CLEANUP_UNCONFIRMED',report) from None
        if error is not None:raise error
        if reason is not None:raise BoundedExecutionError(reason,report)
        if p.returncode:raise RuntimeError('container failed')
        return bytes(out),bytes(err)

    def seal(self,report,namespace):
        # Called only after the real positive/negative probes and counter comparison.
        required={'tcp','dns','udp','metadata','lan','host_model','ipv6'}
        positive=report.get('canary_positive',{});zero=report.get('canary_zero',{})
        if (report.get('passed') is not True or report.get('netns')!=namespace
                or not required.issubset(positive) or set(zero)!=required
                or any(type(positive[k]) is not int or positive[k]<=0 for k in required)
                or any(type(v) is not int or v!=0 for v in zero.values())):
            raise RuntimeError('measured preflight required')
        self.boundary={'netns':namespace,'report':report}

    def browser(self,name,anchor,uid,command,payload,*,mounts=(),seconds=30,evidence_sink=None):
        if self.boundary is None:raise RuntimeError('Chromium blocked before preflight')
        current=self.call('exec',anchor,'readlink','/proc/self/ns/net').strip()
        if current!=self.boundary['netns']:raise RuntimeError('measured namespace changed')
        self.create(name,self.options(anchor,uid,mounts=mounts),command)
        return self.bounded(name,payload,seconds=seconds,evidence_sink=evidence_sink)


def read_control(process,seconds=30):
    q=queue.Queue(1)
    def read():
        try:q.put(process.stdout.readline(512*1024+1))
        except Exception:q.put(b'')
    thread=threading.Thread(target=read,daemon=True);thread.start()
    try:raw=q.get(timeout=seconds)
    except queue.Empty:raise TimeoutError('Worker control deadline') from None
    thread.join(1)
    if not raw.endswith(b'\n') or len(raw)>512*1024:raise RuntimeError('invalid Worker control frame')
    return json.loads(raw)


def send_control(process,obj,payload=b''):
    raw=json.dumps(obj,separators=(',',':')).encode()+b'\n'
    if len(raw)>4096:raise ValueError('Worker command cap')
    process.stdin.write(raw+payload);process.stdin.flush()
