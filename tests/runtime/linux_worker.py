"""Trusted fixture Worker. Private Docker stdin/stdout, no published control port.

Only this container mounts its dedicated test volume. The Browser container sees
neither this volume nor any Docker socket. All network servers are local fixtures.
"""
import base64
from collections import Counter
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

from src.bff.local_ui import LocalBaselineHOME
from src.bridge.adapter import EvidenceBridge
from src.core.offline import OfflineWorkspace, profile_body
from src.baseline.model import BaselineStatus
from src.isolation.budget import NetworkBudget, BudgetLimits
from src.isolation.connect_dns import DnsLimits
from src.isolation.destination import DestinationPolicy, AllowedDestination
from src.isolation.quota_session import QuotaSession, IoLimits
from src.isolation.termination import TerminationLimits
from src.isolation.transport import TransportLimits
from src.runtime.browser import ResourceLimits, ProxyLease
from src.runtime.service import RuntimeService
from src.storage.artifacts import ArtifactStore
from src.storage.finalizer import EvidenceFinalizer
from src.storage.repository import Repository
from src.storage.runtime import initialize
from src.worker.trusted import TrustedWorker
from tests.runtime.http_fixture import HTTPFixtureMixin

spec=importlib.util.spec_from_file_location('fixture_transport','/opt/siteproof/tests/isolation/transport_fixtures.py')
fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
ROOT=Path('/evidence')
COUNTS=Counter()
LOCK=threading.Lock()
SERVERS=[]
PROXY_PORT=18080
TLS_PORT=18443
CANARY_PORT=18555
RESOURCES=ResourceLimits(90,20,64*1024*1024,768*1024*1024,256,256,60,256*1024*1024)  # output: two full-page PNGs of a tall page


def count(key):
    with LOCK: COUNTS[key]+=1


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        count('https' if getattr(self.server,'is_tls',False) else 'http')
        if self.path.startswith('/slow'): time.sleep(12)
        raw=b'<!doctype html><html lang="ja"><meta charset="utf-8"><title>SiteProof fixture</title><style>body{background:#eef2ff;font:24px sans-serif;padding:30px}h1{color:#233876}</style><h1>SiteProof fixture</h1><p>Controlled HTTPS capture</p></html>'
        try:
            self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store')
            self.end_headers();self.wfile.write(raw)
        except (OSError,ssl.SSLError): pass


def canary(address,family=socket.AF_INET,kind=socket.SOCK_STREAM,key='tcp'):
    s=socket.socket(family,kind);s.bind(address)
    if kind==socket.SOCK_STREAM:s.listen(16)
    s.settimeout(.2);stop=threading.Event()
    def run():
        while not stop.is_set():
            try:
                if kind==socket.SOCK_STREAM:
                    c,_=s.accept();count(key);c.close()
                else:
                    data,peer=s.recvfrom(2048);count(key)
                    s.sendto(data[:32],peer)
            except socket.timeout:continue
            except OSError:break
    t=threading.Thread(target=run,daemon=True);t.start();SERVERS.append((s,t,stop))


def start_fixtures():
    private=ROOT/'private';private.mkdir(mode=0o700,exist_ok=True)
    cert,key=private/'fixture.crt',private/'fixture.key'
    if not cert.exists():
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-keyout',str(key),'-out',str(cert),'-subj','/CN=fixture.invalid',
            '-addext','subjectAltName=DNS:fixture.invalid'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        key.chmod(0o600)
    http=ThreadingHTTPServer(('127.0.0.1',TLS_PORT),Handler)
    http.is_tls=True
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
    http.socket=context.wrap_socket(http.socket,server_side=True)
    thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
    plain=ThreadingHTTPServer(('127.0.0.1',18444),Handler)
    plain_thread=threading.Thread(target=plain.serve_forever,daemon=True);plain_thread.start()
    canary(('127.0.0.2',CANARY_PORT),key='tcp')
    canary(('127.0.0.3',53),kind=socket.SOCK_DGRAM,key='dns')
    canary(('127.0.0.3',5353),kind=socket.SOCK_DGRAM,key='udp')
    canary(('169.254.169.254',80),key='metadata')
    canary(('10.231.77.5',CANARY_PORT),key='lan')
    canary(('127.0.0.4',CANARY_PORT),key='host_model')
    canary(('::1',CANARY_PORT),family=socket.AF_INET6,key='ipv6')
    return http,thread,plain,plain_thread,cert


def proxy():
    # Same exact fixture capability as existing transport tests, normal authority443.
    limits=BudgetLimits(32*1024*1024,64,8,128,300)
    session=QuotaSession('fixture-runtime',NetworkBudget(limits,limits),IoLimits(16384,65536),
                         termination_limits=TerminationLimits(3,20))
    class ExactFixture(HTTPFixtureMixin,fixtures.FixtureTransport):
        def __init__(self):
            super().__init__(session,DestinationPolicy((AllowedDestination('fixture.invalid',443),)),
                fixtures.ControlledResolver(),DnsLimits(8,512),TransportLimits(4096,2,.01,16,3),
                endpoint=('127.0.0.1',TLS_PORT),listen_port=PROXY_PORT)
            self.authority=b'fixture.invalid:443'
    p=ExactFixture();p.start();return ProxyLease(p)


def output(obj):
    raw=json.dumps(obj,separators=(',',':')).encode()+b'\n'
    if len(raw)>512*1024: raise ValueError('control output limit')
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()


def command():
    raw=sys.stdin.buffer.readline(4097)
    if not raw: raise EOFError()
    if not raw.endswith(b'\n') or len(raw)>4096: raise ValueError('control input limit')
    return json.loads(raw)


def main():
    if os.getuid()!=1001: raise RuntimeError('trusted Worker UID required')
    http,thread,plain,plain_thread,cert=start_fixtures()
    db=ROOT/'siteproof.sqlite'
    workspace=OfflineWorkspace.create(db,ROOT)
    workspace.save_site({'origin':'https://fixture.invalid','label':'Controlled fixture','expected_revision':0})
    workspace.save_page({'page_id':'fixture-page','label':'Fixture','path':'/','expected_revision':0})
    # Existing M1 fixtures for baseline list/detail/history UX, explicitly synthetic.
    for kind in ('Desktop','Mobile'):
        saved=workspace.save_fixture({'page_id':'fixture-page','kind':kind,'fixture':'original'})
        candidate=workspace.register_candidate({'capture_id':saved['capture_id']})
        if kind=='Desktop':
            workspace.repo.baselines.decide(candidate['candidate_id'],decision=BaselineStatus.APPROVED,
                actor='synthetic-fixture-setup',expected_revision=0,reviewed_digest=candidate['digest'],
                expected_current_version=0)
    initialize(db,ROOT)
    worker=TrustedWorker(EvidenceBridge(EvidenceFinalizer(Repository(db),ArtifactStore(ROOT))))
    service=RuntimeService(workspace,worker)
    home=LocalBaselineHOME(db,ROOT,offline=workspace,runtime=service,approval_actor='fixture-local-operator')
    home.start();lease=proxy()
    output({'type':'ready','proxy_port':PROXY_PORT,'tls_port':TLS_PORT,'canary_port':CANARY_PORT,
        'ui_port':home.address[1],'ca_pem':cert.read_text(),'pairing_code':home.pairing_for_local_user(),
        'namespace':os.readlink('/proc/self/ns/net'),'uid':os.getuid(),'resources':vars(RESOURCES)})
    def remote(req,remaining):
        output({'type':'capture','request':{'page_id':req.page_id,'profile':profile_body(req.profile),
            'url':req.url,'baseline_id':req.baseline_id},'remaining':remaining})
        reply=command()
        if reply.get('type')!='capture_result' or type(reply.get('length')) is not int or not 0<=reply['length']<=RESOURCES.output_bytes:
            raise ValueError('invalid browser result')
        wire=sys.stdin.buffer.read(reply['length'])
        if len(wire)!=reply['length']: raise EOFError()
        return io.BytesIO(wire),reply['reason'],reply['cleanup'] is True
    try:
        while True:
            c=command();name=c.get('type')
            if name=='counts':
                with LOCK: output({'type':'counts','counts':dict(COUNTS)})
            elif name=='stop_proxy': output({'type':'proxy_stopped','confirmed':lease.stop()})
            elif name=='restart_proxy':
                if not lease.stop():raise RuntimeError('proxy cleanup unconfirmed')
                lease=proxy();output({'type':'proxy_ready','port':PROXY_PORT})
            elif name=='run':
                batch=service.submit(source='REAL_CHROMIUM_FIXTURE_UNATTESTED')
                state=service.run(batch,remote,lease,RESOURCES)
                (ROOT/'runtime-result.json').write_text(json.dumps(state,indent=2))
                output({'type':'result','state':state})
            elif name=='state':output({'type':'state','state':service.state()})
            elif name=='expire_session':home.destroy_session();output({'type':'session_destroyed'})
            elif name=='quit':break
            else:raise ValueError('unknown control command')
    finally:
        proxy_clean=lease.stop();ui_clean=home.stop()
        http.shutdown();http.server_close();thread.join(3)
        plain.shutdown();plain.server_close();plain_thread.join(3)
        for s,t,stop in SERVERS:stop.set();s.close();t.join(1)
        output({'type':'closed','proxy':proxy_clean,'ui':ui_clean,
                'fixtures':all(not t.is_alive() for _,t,_ in SERVERS) and not thread.is_alive() and not plain_thread.is_alive()})


if __name__=='__main__':main()
