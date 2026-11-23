"""S1-B: the real loopback CONNECT proxy records every attempt. No DNS, no external traffic."""
import json
import unittest

from src.isolation.ledger import ConnectLedger, unavailable
from test_transport import TransportTests as Base, wait_for


class ProxyLedgerTests(unittest.TestCase):
    setUp = Base.setUp
    _clean_fixture = Base._clean_fixture
    _clean_proxies = Base._clean_proxies
    proxy = Base.proxy
    client = Base.client
    request = Base.request
    tunnel = Base.tunnel

    def audit(self, proxy, mark):
        self.assertTrue(wait_for(lambda: proxy.ledger.window(mark)['in_flight'] == 0))
        return proxy.ledger.window(mark)

    def entries(self, audit):
        return {(e['host'], e['port'], e['decision'], e['reason']): e['count'] for e in audit['entries']}

    def test_policy_blocks_are_recorded_with_host_and_reason_only(self):
        proxy = self.proxy(production=True); mark = proxy.ledger.mark()
        for authority in (b'cdn.example:443', b'fixture.invalid:8443', b'user:pw@evil.example:443',
                          b'192.0.2.1:443', b'evil.example:443'):
            _, response = self.request(proxy, authority=authority)
            self.assertTrue(response.startswith(b'HTTP/1.1 502'), (authority, response))
        audit = self.audit(proxy, mark)
        self.assertTrue(audit['complete'])
        self.assertEqual((audit['allowed'], audit['blocked'], audit['failed']), (0, 5, 0))
        seen = self.entries(audit)
        self.assertEqual(seen[('cdn.example', 443, 'BLOCK', 'NOT_ALLOWLISTED')], 1)
        self.assertEqual(seen[('evil.example', 443, 'BLOCK', 'NOT_ALLOWLISTED')], 1)
        self.assertEqual(seen[(None, None, 'BLOCK', 'PORT_NOT_ALLOWED')], 1)
        text = json.dumps(audit)
        for leak in ('pw', '@', '192.0.2.1'):
            self.assertNotIn(leak, text)

    def test_allowed_tunnel_malformed_request_and_dns_failure_are_distinguished(self):
        proxy = self.proxy(); mark = proxy.ledger.mark()
        self.tunnel(proxy)
        self.request(proxy, raw=b'GET / HTTP/1.1\r\nHost: x\r\n\r\n')
        audit = self.audit(proxy, mark)
        seen = self.entries(audit)
        self.assertEqual(sum(n for k, n in seen.items() if k[2] == 'ALLOW'), 1)
        self.assertEqual(seen[(None, None, 'FAILED', 'MALFORMED_CONNECT')], 1)
        self.assertTrue(audit['complete'])
        self.assertEqual(audit['resource_types'], 'NOT_OBSERVABLE')

    def test_tunnel_still_open_does_not_make_the_window_incomplete(self):
        proxy = self.proxy(); mark = proxy.ledger.mark()
        self.tunnel(proxy)  # Left open: the outcome was recorded when it was established.
        self.assertTrue(proxy.ledger.window(mark)['complete'])

    def test_unfinished_connect_is_incomplete_not_absent(self):
        proxy = self.proxy(header=2); mark = proxy.ledger.mark()
        stalled = self.client(proxy)
        stalled.sendall(b'CONNECT fixture.invalid:44')  # Header never completes yet.
        self.assertTrue(wait_for(lambda: proxy.ledger.window(mark)['in_flight'] == 1))
        self.assertFalse(proxy.ledger.window(mark)['complete'])

    def test_ledger_bounds_and_failures_make_the_window_incomplete(self):
        ledger = ConnectLedger(max_records=2); mark = ledger.mark()
        for n in range(4):
            ledger.begin(); ledger.record(f'h{n}.example', 443, 'ALLOW', 'ALLOW')
        audit = ledger.window(mark)
        self.assertFalse(audit['complete'])
        self.assertEqual(audit['dropped'], 2)
        ledger2 = ConnectLedger(); mark2 = ledger2.mark()
        ledger2.begin(); ledger2.record('a.example', 443, 'EXPLODE', 'X')  # invalid decision is lost, not hidden
        self.assertFalse(ledger2.window(mark2)['complete'])
        self.assertEqual(unavailable('X')['source'], 'UNAVAILABLE')
        self.assertFalse(unavailable('X')['complete'])

    def test_empty_connection_is_distinguished_from_malformed_and_never_hidden(self):
        proxy = self.proxy(production=True); mark = proxy.ledger.mark()
        self.client(proxy).close()  # Connects, sends nothing, closes: no request existed.
        partial = self.client(proxy); partial.sendall(b'CONNECT fixt'); partial.close()  # Partial data: malformed.
        self.assertTrue(wait_for(lambda: proxy.ledger.window(mark)['idle'] == 1 and proxy.ledger.window(mark)['failed'] == 1))
        audit = self.audit(proxy, mark)
        seen = self.entries(audit)
        self.assertEqual(seen[(None, None, 'IDLE', 'EMPTY_CONNECTION')], 1)
        self.assertEqual(seen[(None, None, 'FAILED', 'MALFORMED_CONNECT')], 1)
        self.assertEqual((audit['idle'], audit['failed'], audit['allowed'], audit['blocked']), (1, 1, 0, 0))
        self.assertTrue(audit['complete'])

    def test_prelude_is_split_only_by_the_jobs_own_first_allowed_connection(self):
        ledger = ConnectLedger(); mark = ledger.mark()
        def rec(host, decision, reason):
            ledger.begin(); ledger.record(host, 443, decision, reason)
        rec('www.google.com', 'BLOCK', 'NOT_ALLOWLISTED'); rec('page.example', 'BLOCK', 'NOT_ALLOWLISTED')
        rec('page.example', 'ALLOW', 'ALLOW')
        rec('cdn.example', 'BLOCK', 'NOT_ALLOWLISTED'); rec('www.google.com', 'BLOCK', 'NOT_ALLOWLISTED')
        audit = ledger.window(mark, ('page.example', 443))
        self.assertTrue(audit['anchor']['seen'])
        # Before the document: both refusals (host names play no part). From the document on: all of it.
        self.assertEqual((audit['prelude']['blocked'], audit['prelude']['allowed']), (2, 0))
        self.assertEqual((audit['allowed'], audit['blocked']), (1, 2))
        self.assertEqual([r[4] for r in audit['timeline']], ['BLOCK', 'BLOCK', 'ALLOW', 'BLOCK', 'BLOCK'])
        self.assertEqual(len({r[0] for r in audit['timeline']}), 5)
        # No connection to the anchor: nothing is split off, everything counts against the job.
        other = ledger.window(mark, ('elsewhere.example', 443))
        self.assertFalse(other['anchor']['seen']); self.assertEqual(other['prelude']['blocked'], 0)
        self.assertEqual(other['blocked'], 4)
        # Windows never overlap.
        mark2 = ledger.mark(); rec('page.example', 'ALLOW', 'ALLOW')
        again = ledger.window(mark2, ('page.example', 443))
        self.assertEqual((again['allowed'], again['blocked'], again['prelude']['blocked']), (1, 0, 0))

    def test_decision_classes_separate_refusals_from_failures(self):
        from src.isolation.transport import _classify
        for reason in ('NOT_ALLOWLISTED', 'INVALID_HOSTNAME', 'INVALID_AUTHORITY', 'PORT_NOT_ALLOWED', 'PRIVATE_ADDRESS',
                       'LOOPBACK_ADDRESS', 'LINK_LOCAL_ADDRESS', 'IPV4_MAPPED_IPV6', 'IPV6_TRANSLATION_ADDRESS',
                       'IPV6_TRANSITION_ADDRESS', 'DNS_ANSWERS_INVALID', 'NON_GLOBAL_ADDRESS'):
            self.assertEqual(_classify(False, reason), ('BLOCK', reason), reason)
        # Failing to resolve is not a verdict on the destination, even when the code ends in _ADDRESS.
        for reason in ('DNS_NO_ADDRESS', 'DNS_ERROR', 'DNS_TIMEOUT', 'DNS_INCOMPLETE', 'PEER_MISMATCH', 'DIAL_ERROR',
                       'SESSION_STOPPED', 'CONNECTION_TIMEOUT'):
            self.assertEqual(_classify(False, reason), ('FAILED', reason), reason)
        self.assertEqual(_classify(True, 'ALLOW'), ('ALLOW', 'ALLOW'))

    def test_recording_never_widens_the_allowlist(self):
        proxy = self.proxy(production=True)
        policy = proxy.policy
        for _ in range(3):
            self.request(proxy, authority=b'cdn.example:443')
        self.assertIs(proxy.policy, policy)
        self.assertEqual([(a.hostname, a.port) for a in policy.allowlist], [('fixture.invalid', 443)])


if __name__ == '__main__':
    unittest.main()
