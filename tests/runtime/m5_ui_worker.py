"""Narrow resume of paired UI against copies of previously exported M5 evidence.

No capture, key recovery, profile upgrade, dependency resolution or original write.
"""
import json
import re
import shutil
import sqlite3
import sys
import time
from pathlib import Path

from tests.runtime import linux_worker as base
from src.bff.baseline import BFFLimits
from src.bff.local_ui import LocalBaselineHOME
from src.bridge.adapter import EvidenceBridge
from src.comparison.service import ComparisonService, PixelPolicy
from src.core.offline import OfflineWorkspace
from src.runtime.service import RuntimeService
from src.storage.artifacts import ArtifactStore
from src.storage.finalizer import EvidenceFinalizer
from src.storage.repository import Repository
from src.worker.trusted import TrustedWorker


def main():
    assert base.os.getuid()==1001
    http,thread,plain,plain_thread,cert=base.start_fixtures()
    lease=base.proxy();home=None;homes=[]
    roots={}
    for run in ('02','03'):
        source=Path('/resume-run'+run);root=base.ROOT/('resume-'+run);root.mkdir()
        original=sqlite3.connect('file:'+str(source/'siteproof.sqlite')+'?mode=ro',uri=True)
        clone=sqlite3.connect(root/'siteproof.sqlite');original.backup(clone);clone.close();original.close()
        for child in source.iterdir():
            if child.is_dir() and re.fullmatch('[a-f0-9]{32}',child.name):shutil.copytree(child,root/child.name)
        roots[run]=root

    def trace(stage,**fields):
        sys.stderr.write(json.dumps({'t':time.monotonic(),'stage':stage,**fields})+'\n');sys.stderr.flush()

    def open_home(run):
        root=roots[run];db=root/'siteproof.sqlite';workspace=OfflineWorkspace(db,root)
        worker=TrustedWorker(EvidenceBridge(EvidenceFinalizer(Repository(db),ArtifactStore(root))))
        service=RuntimeService(workspace,worker)
        service.comparison=ComparisonService(workspace,policy=PixelPolicy(0,
            'M5 controlled static fixture: exact RGBA equality; no production tolerance adoption'),allow_unattested_preview=True)
        home=LocalBaselineHOME(db,root,offline=workspace,runtime=service,approval_actor='m5-fixture-local-operator',
            limits=BFFLimits(request_timeout_seconds=5,session_seconds=1800))
        original=home._approval.approve
        def approve(*args,**kwargs):
            trace('approval_dispatch_authenticated_csrf')
            try:
                result=original(*args,**kwargs);trace('approval_transaction_return',approved=result.get('approved'));return result
            except Exception as exc:trace('approval_rejected',type=type(exc).__name__);raise
        home._approval.approve=approve
        home.start();homes.append(home)
        return home,service.comparison

    try:
        home,comparison=open_home(sys.argv[1])
        base.output({'type':'ready','proxy_port':base.PROXY_PORT,'ui_port':home.address[1],
            'ca_pem':cert.read_text(),'namespace':base.os.readlink('/proc/self/ns/net'),'uid':1001,
            'resources':vars(base.RESOURCES)})
        while True:
            command=base.command();kind=command['type']
            if kind=='counts':
                with base.LOCK:base.output({'type':'counts','counts':dict(base.COUNTS)})
            elif kind=='stop_proxy':base.output({'type':'proxy_stopped','confirmed':lease.stop()})
            elif kind=='restart_proxy':
                assert lease.stop();lease=base.proxy();base.output({'type':'proxy_ready','port':base.PROXY_PORT})
            elif kind=='pairing':base.output({'type':'pairing','pairing_code':home.renew_pairing_for_local_user()})
            elif kind=='state':base.output({'type':'state','comparison':comparison.state()})
            elif kind=='expire_session':home.destroy_session();base.output({'type':'session_destroyed'})
            elif kind=='quit':break
            else:raise ValueError('unsupported resume control')
    finally:
        ui_clean=all(h.stop() for h in homes);proxy_clean=lease.stop()
        http.shutdown();http.server_close();thread.join(3)
        plain.shutdown();plain.server_close();plain_thread.join(3)
        for sock,t,stop in base.SERVERS:stop.set();sock.close();t.join(1)
        base.output({'type':'closed','ui':ui_clean,'proxy':proxy_clean,
            'fixtures':all(not t.is_alive() for _,t,_ in base.SERVERS) and not thread.is_alive() and not plain_thread.is_alive()})


if __name__=='__main__':main()
