"""S2-B-HARDEN: per-connection OS egress grants. Offline; fake firewall, fake clock, table resolver."""
import json
import threading
import unittest

from src.isolation.connect_dns import DnsLimits, DnsResolution
from src.isolation.egress_grant import BrokeredResolver, GrantBroker, handle_worker_line
from src.isolation.site_policy import SiteEntry, SiteNetworkPlan, fixture_policy

A, B, C = '11.22.33.44', '11.22.33.45', '11.22.33.46'
HOSTS = ('a.invalid', 'b.invalid', 'c.invalid', 'rebind.invalid', 'multi.invalid', 'v6first.invalid', 'private.invalid',
         'metadata.invalid', 'loopback.invalid', 'mixed.invalid', 'v4mapped.invalid', 'nat64.invalid', 'dnserr.invalid',
         'dnsincomplete.invalid', 'dnsempty.invalid')
ANSWERS = {'a.invalid': [[A]], 'b.invalid': [[B]], 'c.invalid': [[C]], 'rebind.invalid': [[A], [B], ['10.0.0.5']],
           'multi.invalid': [[A, B, C]], 'v6first.invalid': [['2a05:d018:1::1', A]], 'private.invalid': [['10.0.0.5']],
           'metadata.invalid': [['169.254.169.254']], 'loopback.invalid': [['127.0.0.1']], 'mixed.invalid': [[A, '10.0.0.5']],
           'v4mapped.invalid': [['::ffff:10.0.0.5']], 'nat64.invalid': [['64:ff9b::a00:5']]}


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Table:
    def __init__(self):
        self.calls, self.lock = [], threading.Lock()

    def resolve_complete(self, host):
        with self.lock:
            index = sum(1 for h in self.calls if h == host)
            self.calls.append(host)
        if host == 'dnserr.invalid':
            raise TimeoutError()
        if host == 'dnsincomplete.invalid':
            return DnsResolution(host, 'COMPLETE', True, False, (A,))
        if host == 'dnsempty.invalid':
            return DnsResolution(host, 'COMPLETE', True, True, ())
        seq = ANSWERS[host]
        return DnsResolution(host, 'COMPLETE', True, True, tuple(seq[min(index, len(seq) - 1)]))


class Firewall:
    def __init__(self):
        self.active, self.ops, self.fail_allow, self.fail_revoke = set(), [], 0, 0
        self.lock = threading.Lock()

    def allow(self, ip):
        with self.lock:
            self.ops.append(('allow', ip))
            if self.fail_allow:
                self.fail_allow -= 1
                self.active.add(ip)  # Worst case: the rule landed but the verification failed.
                raise OSError('iptables failed')
            self.active.add(ip)

    def revoke(self, ip):
        with self.lock:
            self.ops.append(('revoke', ip))
            if self.fail_revoke:
                self.fail_revoke -= 1
                raise OSError('iptables failed')
            self.active.discard(ip)


def make(max_grants=8, ttl=10):
    clock, table, firewall = Clock(), Table(), Firewall()
    policy = fixture_policy(SiteNetworkPlan('FIXTURE', (SiteEntry('s2h', HOSTS),)))
    broker = GrantBroker(policy, table, firewall, DnsLimits(8, 512), ttl_seconds=ttl, max_grants=max_grants, clock=clock)
    broker.enable()
    return broker, clock, table, firewall


class GrantBrokerTests(unittest.TestCase):
    def test_disabled_unknown_lease_and_off_policy_names_never_resolve_or_touch_the_firewall(self):
        broker, _, table, firewall = make()
        broker.disable_and_close()
        self.assertEqual(broker.resolve('l1', 'a.invalid')['reason'], 'EGRESS_DISABLED')
        broker.enable()
        self.assertEqual(broker.resolve('l1', 'a.invalid')['reason'], 'LEASE_UNKNOWN')
        broker.open_lease('l1', ['a.invalid'])
        for host, reason in (('b.invalid', 'HOST_NOT_IN_LEASE'), ('www.a.invalid', 'NOT_ALLOWLISTED'), ('10.0.0.5', 'INVALID_HOSTNAME'),
                             ('a.invalid.', 'INVALID_HOSTNAME'), ('*.invalid', 'INVALID_HOSTNAME'), ('example.com', 'NOT_ALLOWLISTED')):
            self.assertEqual(broker.resolve('l1', host)['reason'], reason, host)
        self.assertEqual((table.calls, firewall.ops), ([], []))

    def test_lease_can_only_narrow_the_policy(self):
        broker, *_ = make()
        self.assertEqual(broker.open_lease('l1', ['zzz.invalid'])['reason'], 'LEASE_HOST_NOT_ALLOWLISTED')
        self.assertEqual(broker.open_lease('Bad Lease', ['a.invalid'])['reason'], 'LEASE_INVALID')
        self.assertTrue(broker.open_lease('l1', ['a.invalid'])['ok'])
        self.assertEqual(broker.open_lease('l1', ['a.invalid'])['reason'], 'LEASE_EXISTS')

    def test_only_the_first_validated_ipv4_answer_is_granted_and_all_answers_are_returned(self):
        broker, _, _, firewall = make()
        broker.open_lease('l1', ['multi.invalid'])
        reply = broker.resolve('l1', 'multi.invalid')
        self.assertEqual((reply['ok'], reply['granted'], reply['addresses']), (True, A, [A, B, C]))
        self.assertEqual(firewall.active, {A})

    def test_every_forbidden_answer_set_is_refused_without_a_rule(self):
        broker, _, _, firewall = make()
        hosts = ['private.invalid', 'metadata.invalid', 'loopback.invalid', 'mixed.invalid', 'v4mapped.invalid', 'nat64.invalid',
                 'dnserr.invalid', 'dnsincomplete.invalid', 'dnsempty.invalid', 'v6first.invalid']
        broker.open_lease('l1', hosts)
        expected = {'private.invalid': 'PRIVATE_ADDRESS', 'metadata.invalid': 'LINK_LOCAL_ADDRESS', 'loopback.invalid': 'LOOPBACK_ADDRESS',
                    'mixed.invalid': 'PRIVATE_ADDRESS', 'v4mapped.invalid': 'IPV4_MAPPED_IPV6', 'nat64.invalid': 'IPV6_TRANSLATION_ADDRESS',
                    'dnserr.invalid': 'DNS_ERROR', 'dnsincomplete.invalid': 'DNS_INCOMPLETE', 'dnsempty.invalid': 'DNS_NO_ADDRESS',
                    'v6first.invalid': 'FIRST_ADDRESS_NOT_IPV4'}
        for host in hosts:
            self.assertEqual(broker.resolve('l1', host), {'ok': False, 'reason': expected[host]}, host)
        self.assertEqual((firewall.ops, firewall.active), ([], set()))

    def test_re_resolution_is_revalidated_and_a_private_rebind_gets_no_grant(self):
        broker, clock, _, firewall = make(ttl=10)
        broker.open_lease('l1', ['rebind.invalid'])
        self.assertEqual(broker.resolve('l1', 'rebind.invalid')['granted'], A)
        self.assertEqual(broker.resolve('l1', 'rebind.invalid')['granted'], B)  # New answer: validated and granted anew.
        self.assertEqual(firewall.active, {A, B})
        self.assertEqual(broker.resolve('l1', 'rebind.invalid'), {'ok': False, 'reason': 'PRIVATE_ADDRESS'})
        self.assertEqual(firewall.active, {A, B})  # Nothing was added for the private answer.
        clock.now += 11  # TTL passes: both earlier grants disappear, and no new one exists.
        self.assertEqual(broker.state()['active_addresses'], [])
        self.assertEqual(firewall.active, set())

    def test_ttl_expiry_and_refresh(self):
        broker, clock, _, firewall = make(ttl=10)
        broker.open_lease('l1', ['a.invalid'])
        broker.resolve('l1', 'a.invalid')
        clock.now += 8
        broker.resolve('l1', 'a.invalid')  # Refresh extends, no second rule.
        self.assertEqual(firewall.ops, [('allow', A)])
        clock.now += 8
        self.assertEqual(broker.state()['active_addresses'], [A])
        clock.now += 3
        self.assertEqual(broker.state()['active_addresses'], [])
        self.assertEqual((firewall.active, firewall.ops[-1]), (set(), ('revoke', A)))

    def test_firewall_update_failure_returns_no_answer_and_leaves_nothing_behind(self):
        broker, _, _, firewall = make()
        broker.open_lease('l1', ['a.invalid'])
        firewall.fail_allow = 1
        self.assertEqual(broker.resolve('l1', 'a.invalid'), {'ok': False, 'reason': 'FIREWALL_UPDATE_FAILED'})
        self.assertEqual((firewall.active, broker.state()['active_addresses']), (set(), []))
        self.assertEqual(broker.resolve('l1', 'a.invalid')['granted'], A)  # Recovers on the next, independent attempt.

    def test_revoke_failure_is_pending_blocks_new_grants_and_is_retried(self):
        broker, clock, _, firewall = make(ttl=10)
        broker.open_lease('l1', ['a.invalid', 'b.invalid'])
        broker.resolve('l1', 'a.invalid')
        firewall.fail_revoke = 1
        clock.now += 11
        state = broker.state()
        self.assertEqual((state['pending_revocations'], firewall.active), ([A], {A}))
        firewall.fail_revoke = 1  # The retry inside this resolve fails again: still refused, no DNS-driven grant.
        self.assertEqual(broker.resolve('l1', 'b.invalid')['reason'], 'REVOCATION_PENDING')
        self.assertEqual(firewall.active, {A})
        self.assertEqual(broker.resolve('l1', 'b.invalid')['granted'], B)  # Retry succeeded, nothing pending, grant allowed.
        self.assertEqual(firewall.active, {B})

    def test_leases_are_separate_shared_addresses_are_reference_counted(self):
        broker, _, _, firewall = make()
        broker.open_lease('j1', ['a.invalid', 'b.invalid'])
        broker.open_lease('j2', ['a.invalid', 'c.invalid'])
        self.assertEqual(broker.resolve('j2', 'b.invalid')['reason'], 'HOST_NOT_IN_LEASE')  # j1's host never leaks into j2.
        broker.resolve('j1', 'a.invalid')
        broker.resolve('j2', 'a.invalid')
        broker.resolve('j2', 'c.invalid')
        self.assertEqual(firewall.ops.count(('allow', A)), 1)
        self.assertTrue(broker.release('j1'))
        self.assertEqual(firewall.active, {A, C})  # A still needed by j2.
        self.assertTrue(broker.release('j2'))
        self.assertEqual((firewall.active, broker.state()['leases']), (set(), {}))

    def test_grant_limit_is_enforced_across_leases(self):
        broker, *_ = make(max_grants=2)
        broker.open_lease('l1', ['a.invalid', 'b.invalid', 'c.invalid'])
        self.assertTrue(broker.resolve('l1', 'a.invalid')['ok'] and broker.resolve('l1', 'b.invalid')['ok'])
        self.assertEqual(broker.resolve('l1', 'c.invalid')['reason'], 'GRANT_LIMIT')

    def test_concurrent_jobs_never_share_or_leak_grants(self):
        broker, _, _, firewall = make(max_grants=8)
        jobs = {'j1': 'a.invalid', 'j2': 'b.invalid', 'j3': 'c.invalid'}
        for lease, host in jobs.items():
            broker.open_lease(lease, [host])
        results, errors = [], []

        def work(lease, host):
            try:
                for _ in range(20):
                    results.append((lease, host, broker.resolve(lease, host), broker.resolve(lease, 'a.invalid' if host != 'a.invalid' else 'b.invalid')))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
        threads = [threading.Thread(target=work, args=item) for item in jobs.items()]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(errors, [])
        ips = {'a.invalid': A, 'b.invalid': B, 'c.invalid': C}
        for lease, host, own, other in results:
            self.assertEqual(own['granted'], ips[host])
            self.assertEqual(other, {'ok': False, 'reason': 'HOST_NOT_IN_LEASE'})
        self.assertEqual(firewall.active, {A, B, C})
        broker.release('j2')
        self.assertEqual(firewall.active, {A, C})
        self.assertTrue(broker.disable_and_close())
        self.assertEqual((firewall.active, broker.state()['active_addresses']), (set(), []))

    def test_disable_and_close_reports_an_unclean_firewall(self):
        broker, _, _, firewall = make()
        broker.open_lease('l1', ['a.invalid'])
        broker.resolve('l1', 'a.invalid')
        firewall.fail_revoke = 1
        self.assertFalse(broker.disable_and_close())  # Reported, never hidden.
        self.assertEqual(firewall.active, {A})
        self.assertEqual(broker.resolve('l1', 'a.invalid')['reason'], 'EGRESS_DISABLED')
        self.assertEqual(broker.state()['pending_revocations'], [])  # state() retried the revoke, which now succeeded.
        self.assertEqual(firewall.active, set())

    def test_construction_and_wire_surface(self):
        policy = fixture_policy(SiteNetworkPlan('FIXTURE', (SiteEntry('s2h', HOSTS),)))
        for kwargs in ({'ttl_seconds': 0, 'max_grants': 1}, {'ttl_seconds': 301, 'max_grants': 1}, {'ttl_seconds': 5, 'max_grants': 0}):
            with self.assertRaises(ValueError):
                GrantBroker(policy, Table(), Firewall(), DnsLimits(8, 512), **kwargs)
        broker, *_ = make()
        broker.open_lease('l1', ['a.invalid'])
        ok = json.loads(handle_worker_line(broker, b'{"op":"resolve","lease":"l1","host":"a.invalid"}'))
        self.assertEqual((ok['ok'], ok['granted']), (True, A))
        for raw in (b'not json', b'{"op":"open_lease","lease":"x","hosts":["a.invalid"]}', b'{"op":"enable"}', b'{"op":"resolve","lease":"l1"}',
                    b'x' * 5000):
            self.assertFalse(json.loads(handle_worker_line(broker, raw))['ok'], raw[:30])
        self.assertEqual(BrokeredResolver('l1').lease, 'l1')


if __name__ == '__main__':
    unittest.main()
