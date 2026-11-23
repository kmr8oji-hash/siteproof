"""Test-only plain HTTP capability on the same owned fixture proxy.

Exactly GET http://fixture.invalid:80 -> fixed loopback fixture, no arbitrary
forwarding. Production ConnectTransport remains CONNECT/HTTPS-only. Uses the same
QuotaSession and existing DNS/peer checks; never a production-policy exception.
"""
import select
import socket
import time
from urllib.parse import urlsplit

from src.isolation.connect_dns import DnsResolution, _resolution_reason
from src.isolation.connector import ConnectorResult, _peer_reason


class HTTPFixtureMixin:
    http_endpoint=('127.0.0.1',18444)

    def _serve(self,client):
        deadline=time.monotonic()+self.limits.header_timeout_seconds
        while time.monotonic()<deadline and not self._halted():
            if not select.select([client],[],[],.01)[0]:continue
            peek=client.recv(8,socket.MSG_PEEK)
            if not peek:return super()._serve(client)
            if len(peek)<4:continue
            if peek.startswith(b'GET '):return self._serve_http(client)
            return super()._serve(client)
        return super()._serve(client)

    def _serve_http(self,client):
        cid=None
        try:
            deadline=time.monotonic()+self.limits.header_timeout_seconds
            raw=b''
            while b'\r\n\r\n' not in raw:
                if self._halted() or time.monotonic()>=deadline or len(raw)>=4096:raise ValueError('HTTP fixture cap')
                if select.select([client],[],[],.01)[0]:
                    chunk=client.recv(4096-len(raw))
                    if not chunk:raise ValueError('HTTP fixture EOF')
                    raw+=chunk
            if not raw.endswith(b'\r\n\r\n'):raise ValueError('HTTP fixture body forbidden')
            lines=raw.decode('ascii').split('\r\n')
            method,target,version=lines.pop(0).split(' ')
            u=urlsplit(target)
            if (method!='GET' or version!='HTTP/1.1' or u.scheme!='http' or u.hostname!='fixture.invalid'
                    or u.port not in (None,80) or u.username or u.password or u.fragment):raise ValueError('HTTP fixture authority')
            headers={}
            for line in lines:
                if not line:continue
                k,sep,v=line.partition(':');k=k.lower();v=v.strip()
                if not sep or k in headers or any(ord(x)<32 for x in v):raise ValueError('HTTP fixture header')
                headers[k]=v
            if (headers.get('host') not in ('fixture.invalid','fixture.invalid:80')
                    or 'transfer-encoding' in headers or headers.get('content-length','0')!='0'):
                raise ValueError('HTTP fixture header')
            with self._lock:self._next_tunnel+=1;tunnel='http-fixture-'+str(self._next_tunnel)
            if not self.session.open_tunnel(tunnel).allowed:return
            def connect(dial):
                resolution=DnsResolution('fixture.invalid','COMPLETE',True,True,('127.0.0.1',))
                reason=_resolution_reason(resolution,'fixture.invalid',self.dns_limits)
                if reason!='ALLOW':return ConnectorResult(False,reason)
                handle=dial(*self.http_endpoint)
                reason=_peer_reason(handle.getpeername(),*self.http_endpoint)
                if reason!='ALLOW':handle.close();return ConnectorResult(False,reason)
                return ConnectorResult(True,'ALLOW',selected_ip='127.0.0.1',handle=handle)
            result=self.session._connect(tunnel,lambda ip,port:self._dial(ip,port,deadline),connect)
            cid=result.connection_id
            if not result.allowed:return
            path=(u.path or '/')+('?' + u.query if u.query else '')
            request=('GET '+path+' HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n').encode('ascii')
            while request:
                if self._halted() or time.monotonic()>=deadline:return
                sent=self.session.write(cid,request)
                if sent.reason not in ('ALLOW','WOULD_BLOCK'):return
                request=request[sent.count:]
            self._relay(client,cid)
        except (OSError,ValueError):pass
        finally:
            client.close()
            if cid is not None:self.session.finish_connection(cid)
            with self._lock:self._clients.discard(client)
