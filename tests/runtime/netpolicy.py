"""Runs ONLY in a new SiteProof network namespace via a short-lived helper.

Never run this on Windows/WSL host or an existing container. Host launcher verifies
the namespace belongs to its newly created labelled anchor before invoking it.
"""
import json
import os
from pathlib import Path
import subprocess
import sys


def call(*args):
    return subprocess.run(args,check=True,capture_output=True,text=True).stdout


def snapshot():
    return {'netns':os.readlink('/proc/self/ns/net'),
        'ipv4':call('iptables-save','-c'),'ipv6':call('ip6tables-save','-c'),
        'routes':json.loads(call('ip','-j','route','show','table','all')),
        'addresses':json.loads(call('ip','-j','address')),
        'status':[x for x in Path('/proc/self/status').read_text().splitlines()
                  if x.startswith(('Uid:','Cap','NoNewPrivs','Seccomp'))]}


def main():
    obj=json.loads(sys.stdin.buffer.readline(4097))
    if obj['netns']!=os.readlink('/proc/self/ns/net'):raise ValueError('namespace mismatch')
    if obj['type']=='snapshot':print(json.dumps(snapshot()));return
    if obj['type'] not in ('prepare','install') or os.getuid()!=0:raise ValueError('trusted setup only')
    ui=obj['ui_port'];proxy=obj['proxy_port']
    if any(type(p) is not int or not 1024<=p<=65535 for p in (ui,proxy)):raise ValueError('ports')
    if obj['type']=='prepare':
        for addr in ('169.254.169.254/32','10.231.77.5/32'):
            call('ip','address','add',addr,'dev','lo')
        for binary in ('iptables','ip6tables'):
            for chain in ('INPUT','OUTPUT','FORWARD'):call(binary,'-w','-P',chain,'DROP')
            call(binary,'-w','-A','INPUT','-i','lo','-j','ACCEPT')
            call(binary,'-w','-A','OUTPUT','-o','lo','-m','owner','--uid-owner','1001','-j','ACCEPT')
    else:
        for uid,port in ((1000,proxy),(1003,ui)):
            call('iptables','-w','-A','OUTPUT','-o','lo','-d','127.0.0.1','-p','tcp',
                 '--dport',str(port),'-m','owner','--uid-owner',str(uid),'-j','ACCEPT')
        for proto,extra,label in (('udp',['--dport','53'],'SP_BROWSER_DNS_DROP'),
                                  ('udp',[],'SP_BROWSER_UDP_DROP'),('tcp',[],'SP_BROWSER_TCP_DROP')):
            call('iptables','-w','-A','OUTPUT','-p',proto,*extra,'-m','owner','--uid-owner','1000',
                 '-m','comment','--comment',label,'-j','DROP')
        call('ip6tables','-w','-A','OUTPUT','-m','owner','--uid-owner','1000',
             '-m','comment','--comment','SP_BROWSER_IPV6_DROP','-j','DROP')
    print(json.dumps(snapshot()))


if __name__=='__main__':main()
