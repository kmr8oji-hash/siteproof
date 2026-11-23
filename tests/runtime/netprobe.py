"""No Chromium: same UID/caps/seccomp/network as each later Browser container."""
import json
import os
from pathlib import Path
import socket
import ssl
import sys


def tcp(host,port,family=socket.AF_INET):
    with socket.socket(family,socket.SOCK_STREAM) as s:
        s.settimeout(.35)
        try:s.connect((host,port));return True
        except OSError:return False


def udp(port):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.settimeout(.35)
        try:
            s.sendto(b'SITEPROOF-CONTROLLED-PROBE',('127.0.0.3',port))
            return bool(s.recvfrom(512)[0])
        except OSError:return False


def proxy(config):
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.settimeout(2);s.connect(('127.0.0.1',config['proxy_port']))
        s.sendall(b'CONNECT fixture.invalid:443 HTTP/1.1\r\nHost: fixture.invalid:443\r\n\r\n')
        response=b''
        while not response.endswith(b'\r\n\r\n') and len(response)<4096:
            part=s.recv(1024)
            if not part:break
            response+=part
        if not response.startswith(b'HTTP/1.1 200'):return False
        ctx=ssl.create_default_context(cadata=config['ca_pem'])
        with ctx.wrap_socket(s,server_hostname='fixture.invalid') as tls:
            tls.sendall(b'GET /preflight HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n')
            return b'200' in tls.recv(4096).split(b'\r\n')[0]


def main():
    c=json.loads(sys.stdin.buffer.readline(16385));uid=os.getuid()
    targets={'tcp':('127.0.0.2',18555),'fixture_direct':('127.0.0.1',18443),'http_direct':('127.0.0.1',18444),
        'host_model':('127.0.0.4',18555),'metadata':('169.254.169.254',80),
        'lan':('10.231.77.5',18555)}
    result={key:tcp(*value) for key,value in targets.items()}
    result.update(dns=udp(53),udp=udp(5353),ipv6=tcp('::1',18555,socket.AF_INET6))
    if c.get('mode')=='stopped':result['proxy']=tcp('127.0.0.1',c['proxy_port'])
    elif uid in (1000,1001):result['proxy']=proxy(c)
    if uid==1003:
        with socket.socket() as s:
            s.settimeout(2);s.connect(('127.0.0.1',c['ui_port']))
            s.sendall(('GET /local/ HTTP/1.1\r\nHost: 127.0.0.1:'+str(c['ui_port'])+'\r\nConnection: close\r\n\r\n').encode())
            result['ui']=b'200' in s.recv(4096).split(b'\r\n')[0]
        result['proxy']=tcp('127.0.0.1',c['proxy_port'])
    print(json.dumps({'uid':uid,'netns':os.readlink('/proc/self/ns/net'),'results':result,
        'cgroup':{n:Path('/sys/fs/cgroup/'+n).read_text().strip() for n in ('memory.max','pids.max','cpu.max')},
        'status':[x for x in Path('/proc/self/status').read_text().splitlines()
                  if x.startswith(('Cap','NoNewPrivs','Seccomp'))]}))


if __name__=='__main__':main()
