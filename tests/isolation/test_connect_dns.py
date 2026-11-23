"""In-memory authority/resolver/connector tests; no real DNS or connections."""

from dataclasses import FrozenInstanceError, replace
import unittest
from unittest.mock import patch

from src.isolation import connect_dns
from src.isolation.connect_dns import (
    DnsLimits, DnsResolution, check_connect_authority, open_connect_target,
)
from src.isolation.connector import connect_pinned
from src.isolation.destination import (
    AllowedDestination, AuthorityDecision, DestinationDecision, DestinationPolicy,
    check_authority, check_destination,
)


class FakeHandle:
    def __init__(self, events):
        self.events = events
        self.peer = ("8.8.8.8", 443)
        self.peer_error = None
        self.close_error = None
        self.close_calls = 0

    def getpeername(self):
        self.events.append(("peer",))
        if self.peer_error is not None:
            raise self.peer_error
        return self.peer

    def close(self):
        self.events.append(("close",))
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class FakeResolver:
    def __init__(self, events):
        self.events = events
        self.result = DnsResolution("example.com", "COMPLETE", True, True, ("8.8.8.8",))
        self.error = None

    def resolve_complete(self, hostname):
        self.events.append(("resolve", hostname))
        if self.error is not None:
            raise self.error
        return self.result


class ConnectDnsTests(unittest.TestCase):
    def setUp(self):
        self.policy = DestinationPolicy((AllowedDestination("example.com", 443),))
        self.events = []
        self.resolver = FakeResolver(self.events)
        self.handle = FakeHandle(self.events)
        self.dial_error = None
        self.on_dial = None
        self.limits = DnsLimits(max_answers=8, max_answer_chars=512)

    def dial(self, ip, port):
        self.events.append(("dial", ip, port))
        if self.on_dial is not None:
            self.on_dial()
        if self.dial_error is not None:
            raise self.dial_error
        return self.handle

    def open(self, authority=b"example.com:443"):
        return open_connect_target(self.policy, authority, resolver=self.resolver,
                                   dialer=self.dial, limits=self.limits)

    def dns(self, **changes):
        self.resolver.result = replace(self.resolver.result, **changes)

    def assert_before_dns(self, out, reason=None):
        self.assertFalse(out.allowed)
        self.assertIsNone(out.connector)
        self.assertEqual(self.events, [])
        if reason is not None:
            self.assertEqual(out.reason, reason)

    def assert_before_dial(self, out, reason=None):
        self.assertFalse(out.allowed)
        self.assertIsNone(out.connector)
        self.assertEqual(self.events, [("resolve", "example.com")])
        if reason is not None:
            self.assertEqual(out.reason, reason)

    def test_shared_authority_canonicalizes_without_an_ip_grant(self):
        authority = check_authority(self.policy, "EXAMPLE.COM", 443)
        self.assertEqual(authority, AuthorityDecision(True, "ALLOW", "example.com", 443))
        self.assertFalse(hasattr(authority, "addresses"))
        self.assertEqual(check_destination(self.policy, "EXAMPLE.COM", 443, ()),
                         DestinationDecision(False, "DNS_ANSWERS_INVALID", "example.com", 443))

    def test_shared_rejections_preserve_existing_diagnostics_and_priority(self):
        cases = (
            (None, None, True, "POLICY_MISSING", None, None),
            ({}, "bad", 0, "POLICY_INVALID", None, None),
            (DestinationPolicy(()), "example.com", 443, "POLICY_INVALID", None, None),
            (self.policy, "example.com.", 443, "INVALID_HOSTNAME", None, None),
            (self.policy, "example.com", True, "INVALID_PORT", None, None),
            (self.policy, "EVIL.TEST", 443, "NOT_ALLOWLISTED", "evil.test", 443),
        )
        for policy, host, port, reason, name, checked_port in cases:
            with self.subTest(reason=reason):
                self.assertEqual(check_authority(policy, host, port),
                                 AuthorityDecision(False, reason, name, checked_port))
                self.assertEqual(check_destination(policy, host, port, ("8.8.8.8",)),
                                 DestinationDecision(False, reason, name, checked_port))

    def test_generic_destination_ports_remain_configurable(self):
        policy = DestinationPolicy((AllowedDestination("example.com", 80),))
        self.assertTrue(check_authority(policy, "example.com", 80).allowed)
        self.assertTrue(check_destination(policy, "example.com", 80, ("8.8.8.8",)).allowed)
        self.policy = policy
        self.assert_before_dns(self.open(b"example.com:80"), "PORT_NOT_ALLOWED")

    def test_invalid_authority_types_do_not_resolve(self):
        class BytesSubclass(bytes):
            pass
        for authority in (None, "example.com:443", bytearray(b"example.com:443"),
                          memoryview(b"example.com:443"), BytesSubclass(b"example.com:443"), b""):
            with self.subTest(authority=authority):
                self.assert_before_dns(self.open(authority), "INVALID_AUTHORITY")

    def test_authority_requires_one_separator_and_explicit_port(self):
        for authority in (b"example.com", b"example.com::443", b"[::1]:443", b"::1:443"):
            with self.subTest(authority=authority):
                self.assert_before_dns(self.open(authority), "INVALID_AUTHORITY")

    def test_port_text_is_not_normalized(self):
        for port in (b"", b"80", b"8443", b"0443", b"+443", b"443.0", b" 443",
                     b"443 ", b"443\r\n", b"443/path", b"443?x", b"443#x", b"%3443"):
            with self.subTest(port=port):
                self.assert_before_dns(self.open(b"example.com:" + port), "PORT_NOT_ALLOWED")

    def test_unsupported_host_representations_are_not_repaired(self):
        for host in (b"", b"example.com.", b" example.com", b"example.com ", b"localhost",
                     b"8.8.8.8", b"127.1", b"2130706433", b"0x7f000001", b"*.example.com",
                     b"example%2ecom", b"user@example.com", b"a..com", b"a_b.com",
                     b"example.com/path", b"example.com?x", b"example.com#x", b"example\x00.com"):
            with self.subTest(host=host):
                self.assert_before_dns(self.open(host + b":443"), "INVALID_HOSTNAME")

    def test_non_ascii_authority_is_rejected_before_resolution(self):
        for authority in ("exämple.com:443".encode(), "example.com:４４３".encode(), b"\xff:443"):
            with self.subTest(authority=authority):
                self.assert_before_dns(self.open(authority), "INVALID_AUTHORITY")

    def test_request_lines_headers_and_control_bytes_are_not_accepted(self):
        for authority in (b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
                          b"https://example.com:443", b"example.com:443\r\nHost: evil.test",
                          b"example\r\n.com:443", b"example\t.com:443"):
            with self.subTest(authority=authority):
                self.assert_before_dns(self.open(authority))

    def test_253_character_hostname_at_257_byte_boundary_succeeds(self):
        host = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
        self.assertEqual(len(host), 253)
        self.policy = DestinationPolicy((AllowedDestination(host, 443),))
        self.dns(query_hostname=host)
        self.assertTrue(self.open((host + ":443").encode()).allowed)
        self.assertEqual(self.events[0], ("resolve", host))

    def test_authority_over_257_bytes_is_rejected_before_policy_or_dns(self):
        authority = b"a" * 254 + b":443"
        with patch.object(connect_dns, "check_authority", side_effect=AssertionError("too late")):
            self.assert_before_dns(self.open(authority), "AUTHORITY_TOO_LONG")

    def test_label_length_is_checked_by_shared_hostname_rules(self):
        host = "a" * 63 + ".com"
        policy = DestinationPolicy((AllowedDestination(host, 443),))
        self.assertTrue(check_connect_authority(policy, (host + ":443").encode()).allowed)
        self.assertFalse(check_connect_authority(policy, ("a" * 64 + ".com:443").encode()).allowed)

    def test_non_allowlisted_hosts_never_resolve(self):
        for host in (b"evil.test", b"sub.example.com", b"example.com.evil.test"):
            with self.subTest(host=host):
                self.assert_before_dns(self.open(host + b":443"), "NOT_ALLOWLISTED")

    def test_missing_or_invalid_policy_never_resolves(self):
        policies = (None, {}, DestinationPolicy(()), DestinationPolicy([]),
                    DestinationPolicy((AllowedDestination("example.com", 443),
                                       AllowedDestination("bad..test", 80))))
        for policy in policies:
            with self.subTest(policy=policy):
                self.policy = policy
                self.assert_before_dns(self.open())

    def test_canonical_hostname_and_exact_stage_order(self):
        def authorize(*args):
            self.events.append(("authorize",))
            return check_authority(*args)
        with patch.object(connect_dns, "check_authority", side_effect=authorize):
            out = self.open(b"EXAMPLE.COM:443")
        self.assertTrue(out.allowed)
        self.assertEqual(out.authority.hostname, "example.com")
        self.assertEqual(self.events, [("authorize",), ("resolve", "example.com"),
                                     ("dial", "8.8.8.8", 443), ("peer",)])

    def test_complete_ipv4_and_terminal_aaaa_nodata_can_connect(self):
        out = self.open()
        self.assertTrue(out.allowed)
        self.assertEqual(out.connector.destination.addresses, ("8.8.8.8",))
        self.assertEqual(self.events, [("resolve", "example.com"),
                                     ("dial", "8.8.8.8", 443), ("peer",)])

    def test_complete_ipv6_and_terminal_a_nodata_can_connect(self):
        self.dns(addresses=("2606:4700:4700:0:0:0:0:1111",))
        self.handle.peer = ("2606:4700:4700::1111", 443)
        out = self.open()
        self.assertTrue(out.allowed)
        self.assertEqual(out.connector.selected_ip, "2606:4700:4700::1111")
        self.assertEqual(self.events[1], ("dial", "2606:4700:4700::1111", 443))

    def test_full_ordered_answer_tuple_reaches_real_connector_once(self):
        answers = ("9.9.9.9", "9.9.9.9", "2606:4700:4700::1111", "1.1.1.1")
        self.dns(addresses=answers)
        self.handle.peer = ("9.9.9.9", 443)
        with patch.object(connect_dns, "connect_pinned", wraps=connect_pinned) as delegate:
            out = self.open()
        delegate.assert_called_once_with(self.policy, "example.com", 443, answers, dialer=self.dial)
        self.assertTrue(out.allowed)
        self.assertEqual(out.connector.destination.addresses,
                         ("9.9.9.9", "2606:4700:4700::1111", "1.1.1.1"))
        self.assertEqual(out.connector.selected_ip, "9.9.9.9")

    def test_any_incomplete_family_prevents_connection(self):
        for a, aaaa in ((False, True), (True, False), (False, False)):
            with self.subTest(a=a, aaaa=aaaa):
                self.events.clear()
                self.dns(a_complete=a, aaaa_complete=aaaa)
                self.assert_before_dial(self.open(), "DNS_INCOMPLETE")

    def test_failure_statuses_never_adopt_partial_answers(self):
        for status in ("TIMEOUT", "ERROR", "INCOMPLETE"):
            with self.subTest(status=status):
                self.events.clear()
                self.dns(status=status, a_complete=True, aaaa_complete=False)
                with patch.object(connect_dns, "connect_pinned", side_effect=AssertionError("dial")):
                    self.assert_before_dial(self.open(), "DNS_" + status)

    def test_complete_but_empty_answer_set_is_rejected(self):
        self.dns(addresses=())
        self.assert_before_dial(self.open(), "DNS_NO_ADDRESS")

    def test_result_for_another_query_or_alias_cannot_authorize_a_connection(self):
        for hostname in ("evil.test", "cdn.example.net", "EXAMPLE.COM", "example.com.", None):
            with self.subTest(hostname=hostname):
                self.events.clear()
                self.dns(query_hostname=hostname)
                self.assert_before_dial(self.open(), "DNS_QUERY_MISMATCH")

    def test_only_exact_resolution_records_are_accepted(self):
        class ResolutionSubclass(DnsResolution):
            pass
        for result in (None, {}, ("8.8.8.8",), ResolutionSubclass(
                "example.com", "COMPLETE", True, True, ("8.8.8.8",))):
            with self.subTest(result=result):
                self.events.clear()
                self.resolver.result = result
                self.assert_before_dial(self.open(), "DNS_RESULT_INVALID")

    def test_completion_flags_must_be_actual_booleans(self):
        for field in ("a_complete", "aaaa_complete"):
            for value in (1, 0, None, "True", []):
                with self.subTest(field=field, value=value):
                    self.setUp()
                    self.dns(**{field: value})
                    self.assert_before_dial(self.open(), "DNS_RESULT_INVALID")

    def test_unknown_or_malformed_status_is_rejected(self):
        for status in ("complete", "NODATA", "", None, True, []):
            with self.subTest(status=status):
                self.setUp()
                self.dns(status=status)
                self.assert_before_dial(self.open(), "DNS_RESULT_INVALID")

    def test_answer_container_cannot_be_mutable_or_lazily_consumed(self):
        class TupleSubclass(tuple):
            pass
        for answers in (["8.8.8.8"], iter(("8.8.8.8",)), "8.8.8.8", None,
                        TupleSubclass(("8.8.8.8",))):
            with self.subTest(answers=answers):
                self.setUp()
                self.dns(addresses=answers)
                self.assert_before_dial(self.open(), "DNS_RESULT_INVALID")

    def test_answer_members_must_be_plain_strings(self):
        class StrSubclass(str):
            pass
        for address in (None, 123, b"8.8.8.8", StrSubclass("8.8.8.8")):
            with self.subTest(address=address):
                self.setUp()
                self.dns(addresses=("8.8.8.8", address))
                self.assert_before_dial(self.open(), "DNS_RESULT_INVALID")

    def test_count_limit_exact_then_one_over_does_not_truncate_or_deduplicate(self):
        self.limits = DnsLimits(2, 512)
        self.dns(addresses=("8.8.8.8", "8.8.8.8"))
        self.assertTrue(self.open().allowed)
        self.events.clear()
        self.dns(addresses=("8.8.8.8", "8.8.8.8", "8.8.8.8"))
        self.assert_before_dial(self.open(), "DNS_ANSWER_COUNT_LIMIT")

    def test_total_character_limit_exact_then_one_over(self):
        self.dns(addresses=("8.8.8.8", "1.1.1.1"))
        self.limits = DnsLimits(2, 14)
        self.assertTrue(self.open().allowed)
        self.events.clear()
        self.limits = DnsLimits(2, 13)
        self.assert_before_dial(self.open(), "DNS_ANSWER_CHARS_LIMIT")

    def test_oversized_first_answer_is_not_parsed_or_dialed(self):
        self.dns(addresses=("x" * 513,))
        with patch.object(connect_dns, "connect_pinned", side_effect=AssertionError("IP parsing")):
            self.assert_before_dial(self.open(), "DNS_ANSWER_CHARS_LIMIT")

    def test_limits_require_explicit_positive_integer_configuration(self):
        for value in (0, -1, True, 1.0, "2", None):
            for args in ((value, 100), (2, value)):
                with self.subTest(args=args), self.assertRaises(ValueError):
                    DnsLimits(*args)
        with self.assertRaises(TypeError):
            DnsLimits()

    def test_invalid_limits_fail_before_resolver(self):
        for limits in (None, {}, (8, 512)):
            with self.subTest(limits=limits):
                self.limits = limits
                self.assert_before_dns(self.open(), "DNS_LIMITS_INVALID")

    def test_resolver_exceptions_fail_closed_without_copying_exception_messages(self):
        for error, reason in ((TimeoutError("sensitive query"), "DNS_TIMEOUT"),
                              (OSError("sensitive DNS data"), "DNS_ERROR"),
                              (ValueError("adapter failure"), "DNS_ERROR")):
            with self.subTest(error=type(error).__name__):
                self.events.clear()
                self.resolver.error = error
                out = self.open()
                self.assert_before_dial(out, reason)
                self.assertEqual(out.error, type(error).__name__)
                self.assertNotIn(str(error), repr(out))

    def test_resolver_interruptions_propagate_without_dialing(self):
        interrupt = KeyboardInterrupt()
        self.resolver.error = interrupt
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.open()
        self.assertIs(caught.exception, interrupt)
        self.assertEqual(self.events, [("resolve", "example.com")])

    def test_mixed_forbidden_or_invalid_ips_are_rejected_by_existing_destination(self):
        for bad in ("127.0.0.1", "169.254.169.254", "10.0.0.1", "::1", "fc00::1",
                    "::ffff:8.8.8.8", "64:ff9b::808:808", "garbage", "8.8.8.8 "):
            for answers in (("8.8.8.8", bad), (bad, "8.8.8.8")):
                with self.subTest(answers=answers):
                    self.events.clear()
                    self.dns(addresses=answers)
                    expected = check_destination(self.policy, "example.com", 443, answers)
                    out = self.open()
                    self.assertFalse(out.allowed)
                    self.assertEqual(out.reason, expected.reason)
                    self.assertEqual(out.connector.destination, expected)
                    self.assertIsNone(out.connector.handle)
                    self.assertEqual(self.events, [("resolve", "example.com")])

    def test_resolver_reports_and_results_are_immutable(self):
        out = self.open()
        for obj, name, value in ((self.resolver.result, "a_complete", False),
                                  (self.limits, "max_answers", 999),
                                  (out, "reason", "forged"),
                                  (out.authority, "hostname", "evil.test")):
            with self.subTest(name=name), self.assertRaises(FrozenInstanceError):
                setattr(obj, name, value)
        with self.assertRaises(TypeError):
            self.resolver.result.addresses[0] = "127.0.0.1"

    def test_later_input_mutation_cannot_replace_the_selected_pin(self):
        original = ["8.8.8.8", "1.1.1.1"]
        self.dns(addresses=tuple(original))
        self.on_dial = lambda: original.__setitem__(slice(None), ["127.0.0.1"])
        out = self.open()
        self.assertTrue(out.allowed)
        self.assertEqual(original, ["127.0.0.1"])
        self.assertEqual(out.connector.destination.addresses, ("8.8.8.8", "1.1.1.1"))
        self.assertEqual(out.connector.selected_ip, "8.8.8.8")

    def test_fresh_request_reauthorizes_and_resolves_instead_of_reusing_success(self):
        first = self.open()
        self.assertTrue(first.allowed)
        self.events.clear()
        self.dns(addresses=("127.0.0.1",))
        second = self.open()
        self.assertFalse(second.allowed)
        self.assertEqual(second.reason, "LOOPBACK_ADDRESS")
        self.assertEqual(self.events, [("resolve", "example.com")])
        self.assertEqual(self.handle.close_calls, 0)
        self.policy = None
        self.events.clear()
        self.assert_before_dns(self.open(), "POLICY_MISSING")

    def test_new_complete_public_answer_set_is_allowed_without_cross_request_pins(self):
        self.assertTrue(self.open().allowed)
        self.events.clear()
        self.dns(addresses=("1.1.1.1",))
        self.handle.peer = ("1.1.1.1", 443)
        out = self.open()
        self.assertTrue(out.allowed)
        self.assertEqual(out.connector.selected_ip, "1.1.1.1")
        self.assertEqual(self.events, [("resolve", "example.com"),
                                     ("dial", "1.1.1.1", 443), ("peer",)])

    def test_peer_change_to_another_approved_ip_is_not_dns_or_connection_success(self):
        self.dns(addresses=("8.8.8.8", "1.1.1.1"))
        self.handle.peer = ("1.1.1.1", 443)
        out = self.open()
        self.assertTrue(out.authority.allowed)
        self.assertTrue(out.connector.destination.allowed)
        self.assertFalse(out.allowed)
        self.assertEqual(out.reason, "PEER_MISMATCH")
        self.assertIsNone(out.connector.handle)
        self.assertEqual(self.handle.close_calls, 1)
        self.assertEqual(self.events, [("resolve", "example.com"),
                                     ("dial", "8.8.8.8", 443), ("peer",), ("close",)])

    def test_original_connector_result_and_cleanup_diagnostics_are_preserved(self):
        self.handle.peer_error = TimeoutError("peer timeout")
        self.handle.close_error = OSError("cleanup failed")
        captured = []
        def delegate(*args, **kwargs):
            result = connect_pinned(*args, **kwargs)
            captured.append(result)
            return result
        with patch.object(connect_dns, "connect_pinned", side_effect=delegate):
            out = self.open()
        self.assertIs(out.connector, captured[0])
        self.assertFalse(out.allowed)
        self.assertEqual(out.reason, "PEER_ERROR")
        self.assertEqual(out.connector.error, "TimeoutError")
        self.assertEqual(out.connector.close_error, "OSError")
        self.assertEqual(self.handle.close_calls, 1)

    def test_dial_error_is_not_retried_reresolved_or_given_a_fallback(self):
        self.dial_error = TimeoutError("dial timeout")
        self.dns(addresses=("8.8.8.8", "1.1.1.1"))
        out = self.open()
        self.assertFalse(out.allowed)
        self.assertEqual(out.reason, "DIAL_ERROR")
        self.assertEqual(out.connector.error, "TimeoutError")
        self.assertEqual(self.events, [("resolve", "example.com"), ("dial", "8.8.8.8", 443)])
        self.assertEqual(self.handle.close_calls, 0)

    def test_success_transfers_handle_only_to_the_caller(self):
        out = self.open()
        self.assertTrue(out.allowed)
        self.assertIs(out.connector.handle, self.handle)
        self.assertEqual(self.handle.close_calls, 0)
        out.connector.handle.close()
        self.assertEqual(self.handle.close_calls, 1)

    def test_connector_interrupt_cleanup_and_original_exception_are_not_hidden(self):
        interrupt = SystemExit("cancel")
        self.handle.peer_error = interrupt
        self.handle.close_error = OSError("cleanup")
        with self.assertRaises(SystemExit) as caught:
            self.open()
        self.assertIs(caught.exception, interrupt)
        self.assertEqual(interrupt.__notes__, ["connector close failed: OSError"])
        self.assertEqual(self.handle.close_calls, 1)


if __name__ == "__main__":
    unittest.main()
