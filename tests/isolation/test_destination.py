"""All IP strings here are synthetic fixtures; no DNS or connections."""

import unittest

from src.isolation.destination import (
    AllowedDestination, DestinationPolicy, check_destination,
)


class DestinationTests(unittest.TestCase):
    def setUp(self):
        self.policy = DestinationPolicy((AllowedDestination("example.com", 443),))

    def check(self, answers=("8.8.8.8",), hostname="example.com", port=443):
        return check_destination(self.policy, hostname, port, answers)

    def test_public_ipv4_candidates(self):
        for address in ("8.8.8.8", "1.1.1.1", "9.9.9.9", "93.184.216.34"):
            with self.subTest(address=address):
                result = self.check((address,))
                self.assertTrue(result.allowed)
                self.assertEqual(result.addresses, (address,))
                self.assertEqual(result.reason, "ALLOW")

    def test_public_ipv6_candidates(self):
        for address in ("2606:4700:4700::1111", "2001:4860:4860::8888"):
            with self.subTest(address=address):
                self.assertTrue(self.check((address,)).allowed)

    def test_forbidden_address_classes(self):
        fixtures = {
            "LOOPBACK_ADDRESS": ("127.0.0.1", "127.9.8.7", "::1"),
            "PRIVATE_ADDRESS": ("10.0.0.1", "172.16.0.1", "192.168.0.1", "fc00::1"),
            "LINK_LOCAL_ADDRESS": ("169.254.169.254", "fe80::1"),
            "MULTICAST_ADDRESS": ("224.0.0.1", "239.255.255.255", "ff02::1"),
            "UNSPECIFIED_ADDRESS": ("0.0.0.0", "::"),
            "RESERVED_ADDRESS": ("240.0.0.1", "255.255.255.255"),
            "NON_GLOBAL_ADDRESS": ("100.64.0.1",),
            "SITE_LOCAL_ADDRESS": ("fec0::1",),
        }
        for reason, addresses in fixtures.items():
            for address in addresses:
                with self.subTest(address=address):
                    result = self.check((address,))
                    self.assertFalse(result.allowed)
                    self.assertEqual(result.reason, reason)

    def test_documentation_and_special_ranges_denied(self):
        for address in ("192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1",
                        "198.18.0.1", "0.1.2.3", "100::1"):
            with self.subTest(address=address):
                self.assertFalse(self.check((address,)).allowed)

    def test_mixed_dns_answers_fail_closed_in_any_order(self):
        for answers in (("8.8.8.8", "10.0.0.1"), ("::1", "1.1.1.1"),
                        ("8.8.8.8", "garbage"), ("8.8.8.8", "::ffff:8.8.8.8")):
            with self.subTest(answers=answers):
                result = self.check(answers)
                self.assertFalse(result.allowed)
                self.assertEqual(result.addresses, ())

    def test_ipv4_mapped_and_transition_bypasses(self):
        for address in ("::ffff:127.0.0.1", "::ffff:8.8.8.8", "::ffff:0808:0808",
                        "2002:0808:0808::1", "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
                        "64:ff9b::808:808", "64:ff9b:1::a00:1"):
            with self.subTest(address=address):
                self.assertFalse(self.check((address,)).allowed)

    def test_ambiguous_dns_ip_strings_denied(self):
        for address in ("127.1", "2130706433", "0177.0.0.1", "0x7f000001",
                        "0x7f.0.0.1", "127.000.000.001", "+8.8.8.8", " 8.8.8.8",
                        "8.8.8.8 ", "8.8.8.8/32", "[::1]", "fe80::1%eth0",
                        "2606:4700::1%1", b"8.8.8.8", 123, None, ""):
            with self.subTest(address=address):
                self.assertEqual(self.check((address,)).reason, "INVALID_DNS_ADDRESS")

    def test_dns_answers_required_and_typed(self):
        for answers in ((), [], None, "8.8.8.8", {"8.8.8.8"}, (None,)):
            with self.subTest(answers=answers):
                self.assertFalse(self.check(answers).allowed)

    def test_hostname_is_exact_and_case_insensitive(self):
        result = self.check(hostname="EXAMPLE.COM")
        self.assertTrue(result.allowed)
        self.assertEqual(result.hostname, "example.com")
        for hostname in ("sub.example.com", "example.com.evil.test", "evil.test"):
            with self.subTest(hostname=hostname):
                self.assertEqual(self.check(hostname=hostname).reason, "NOT_ALLOWLISTED")

    def test_literal_or_ambiguous_destination_host_denied(self):
        for hostname in ("8.8.8.8", "127.1", "2130706433", "0177.0.0.1",
                         "0x7f000001", "0x7f.0.0.1", "::1", "[2606:4700::1]",
                         "example.com.", " example.com", "example.com:443",
                         "https://example.com", "user@example.com", "example%2ecom",
                         "exämple.com", "１２７.０.０.１", "a..com", "-bad.com",
                         "a" * 64 + ".com", "*.example.com", "localhost", "", None):
            with self.subTest(hostname=hostname):
                self.assertEqual(self.check(hostname=hostname).reason, "INVALID_HOSTNAME")

    def test_port_must_match_and_have_strict_type(self):
        self.assertEqual(self.check(port=80).reason, "NOT_ALLOWLISTED")
        for port in (0, -1, 65536, True, 443.0, "443", None):
            with self.subTest(port=port):
                self.assertEqual(self.check(port=port).reason, "INVALID_PORT")

    def test_policy_missing(self):
        self.assertEqual(check_destination(None, "example.com", 443, ("8.8.8.8",)).reason,
                         "POLICY_MISSING")

    def test_entire_policy_validated(self):
        for policy in ({}, DestinationPolicy(()), DestinationPolicy([]),
                       DestinationPolicy(("example.com",)),
                       DestinationPolicy((AllowedDestination("8.8.8.8", 443),)),
                       DestinationPolicy((AllowedDestination("example.com", True),)),
                       DestinationPolicy((AllowedDestination("example.com", 443),
                                          AllowedDestination("bad..test", 80)))):
            with self.subTest(policy=policy):
                result = check_destination(policy, "example.com", 443, ("8.8.8.8",))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, "POLICY_INVALID")

    def test_address_set_is_canonicalized_and_deduplicated(self):
        result = self.check(("8.8.8.8", "8.8.8.8", "2606:4700:4700:0:0:0:0:1111"))
        self.assertEqual(result.addresses, ("8.8.8.8", "2606:4700:4700::1111"))

    def test_port_boundaries_are_configurable(self):
        for port in (1, 65535):
            with self.subTest(port=port):
                policy = DestinationPolicy((AllowedDestination("example.com", port),))
                self.assertTrue(check_destination(policy, "example.com", port,
                                                  ("8.8.8.8",)).allowed)
