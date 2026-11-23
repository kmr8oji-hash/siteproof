"""Exact HTTP fixture capability, mocked I/O only. No production policy changes."""
from types import SimpleNamespace
import threading
import unittest
from unittest.mock import Mock,patch

from src.isolation.connect_dns import DnsLimits
from tests.runtime.http_fixture import HTTPFixtureMixin


class Harness(HTTPFixtureMixin):
    def __init__(self,peer=('127.0.0.1',18444)):
        self.session=Mock();self._lock=threading.Lock();self._clients=set();self._next_tunnel=0
        self.limits=SimpleNamespace(header_timeout_seconds=1);self.dns_limits=DnsLimits(8,512)
        self._halted=lambda:False;self._relay=Mock()
        self.handle=Mock();self.handle.getpeername.return_value=peer
        self._dial=Mock(return_value=self.handle)
        self.session.open_tunnel.return_value.allowed=True
        def connect(tunnel,dial,validate):
            decision=validate(lambda ip,port:dial(ip,port))
            return SimpleNamespace(allowed=decision.allowed,connection_id=1 if decision.allowed else None)
        self.session._connect.side_effect=connect
        self.session.write.side_effect=lambda cid,data:SimpleNamespace(reason='ALLOW',count=len(data))

    def run(self,raw):
        client=Mock();client.recv.side_effect=[raw];self._clients.add(client)
        with patch('tests.runtime.http_fixture.select.select',return_value=([client],[],[])):
            self._serve_http(client)
        return client


class HTTPFixtureTests(unittest.TestCase):
    def test_exact_fixture_get_uses_shared_session_and_peer(self):
        h=Harness();client=h.run(b'GET http://fixture.invalid/ HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n')
        h._relay.assert_called_once_with(client,1)
        h.session.finish_connection.assert_called_once_with(1)
        self.assertFalse(h._clients)

    def test_unrelated_host_refused_before_dial(self):
        h=Harness();h.run(b'GET http://other.invalid/ HTTP/1.1\r\nHost: other.invalid\r\n\r\n')
        h._dial.assert_not_called();h.session.open_tunnel.assert_not_called()

    def test_nonfixture_port_refused(self):
        h=Harness();h.run(b'GET http://fixture.invalid:9999/ HTTP/1.1\r\nHost: fixture.invalid:9999\r\n\r\n')
        h._dial.assert_not_called()

    def test_body_and_duplicate_headers_refused(self):
        for headers in (b'Content-Length: 1\r\n',b'Host: fixture.invalid\r\n',b'Transfer-Encoding: chunked\r\n'):
            h=Harness();h.run(b'GET http://fixture.invalid/ HTTP/1.1\r\nHost: fixture.invalid\r\n'+headers+b'\r\n')
            h._dial.assert_not_called()

    def test_peer_mismatch_cannot_become_success(self):
        h=Harness(peer=('127.0.0.2',18444))
        h.run(b'GET http://fixture.invalid/ HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n')
        h.handle.close.assert_called_once();h._relay.assert_not_called()

    def test_credentials_refused(self):
        h=Harness();h.run(b'GET http://secret@fixture.invalid/ HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n')
        h._dial.assert_not_called()


if __name__=='__main__':unittest.main()
