"""In-memory handles/dialers only; IP strings are synthetic fixtures."""

from dataclasses import FrozenInstanceError
import unittest
from unittest.mock import patch

from src.isolation import connector
from src.isolation.destination import (
    AllowedDestination, DestinationPolicy, check_destination,
)


class FakeHandle:
    def __init__(self, events, peer=("8.8.8.8", 443), *, peer_error=None,
                 close_error=None, on_peer=None):
        self.events = events
        self.peer = peer
        self.peer_error = peer_error
        self.close_error = close_error
        self.on_peer = on_peer
        self.close_calls = 0

    def getpeername(self):
        self.events.append(("peer",))
        if self.on_peer is not None:
            self.on_peer()
        if self.peer_error is not None:
            raise self.peer_error
        return self.peer

    def close(self):
        self.events.append(("close",))
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class FakeDialer:
    def __init__(self, events, handle, *, error=None, on_dial=None):
        self.events = events
        self.handle = handle
        self.error = error
        self.on_dial = on_dial

    def __call__(self, numeric_ip, port):
        self.events.append(("dial", numeric_ip, port))
        if self.on_dial is not None:
            self.on_dial()
        if self.error is not None:
            raise self.error
        return self.handle


class ConnectorTests(unittest.TestCase):
    def setUp(self):
        self.policy = DestinationPolicy((AllowedDestination("example.com", 443),))
        self.events = []
        self.handle = FakeHandle(self.events)
        self.dialer = FakeDialer(self.events, self.handle)

    def connect(self, answers=("8.8.8.8",), *, hostname="example.com", port=443):
        return connector.connect_pinned(self.policy, hostname, port, answers,
                                        dialer=self.dialer)

    def assert_denied_before_dial(self, result, reason=None):
        self.assertFalse(result.allowed)
        self.assertIsNone(result.handle)
        self.assertIsNone(result.selected_ip)
        self.assertIsNone(result.error)
        self.assertIsNone(result.close_error)
        self.assertEqual(self.events, [])
        if reason is not None:
            self.assertEqual(result.reason, reason)

    def assert_closed_failure(self, result, reason):
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, reason)
        self.assertIsNone(result.handle)
        self.assertEqual(self.events, [("dial", "8.8.8.8", 443), ("peer",), ("close",)])
        self.assertEqual(self.handle.close_calls, 1)

    def test_ipv4_success_passes_only_numeric_ip_and_port_to_dialer(self):
        result = self.connect(hostname="EXAMPLE.COM")
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "ALLOW")
        self.assertEqual(result.destination.hostname, "example.com")
        self.assertEqual(result.destination.port, 443)
        self.assertEqual(result.destination.addresses, ("8.8.8.8",))
        self.assertEqual(result.selected_ip, "8.8.8.8")
        self.assertIs(result.handle, self.handle)
        self.assertIsNone(result.error)
        self.assertIsNone(result.close_error)
        self.assertEqual(self.events, [("dial", "8.8.8.8", 443), ("peer",)])

    def test_ipv6_is_canonicalized_before_dial_and_peer_comparison(self):
        self.handle.peer = ("2606:4700:4700:0:0:0:0:1111", 443)
        result = self.connect(("2606:4700:4700:0000:0000:0000:0000:1111",))
        self.assertTrue(result.allowed)
        self.assertEqual(result.selected_ip, "2606:4700:4700::1111")
        self.assertEqual(self.events, [("dial", "2606:4700:4700::1111", 443), ("peer",)])

    def test_first_canonical_unique_answer_selected_without_sorting(self):
        answers = ("9.9.9.9", "9.9.9.9", "1.1.1.1", "2606:4700:4700::1111")
        self.handle.peer = ("9.9.9.9", 443)
        result = self.connect(answers)
        self.assertTrue(result.allowed)
        self.assertEqual(result.destination.addresses,
                         ("9.9.9.9", "1.1.1.1", "2606:4700:4700::1111"))
        self.assertEqual(self.events, [("dial", "9.9.9.9", 443), ("peer",)])

    def test_only_strict_integer_443_allowed_even_when_policy_allows_other_ports(self):
        self.policy = DestinationPolicy(tuple(AllowedDestination("example.com", port)
                                              for port in (1, 80, 443, 8443, 65535)))
        for port in (1, 80, 8443, 65535, 0, -1, 65536, True, False, 443.0, "443", None):
            with self.subTest(port=port):
                with patch.object(connector, "check_destination", wraps=check_destination) as check:
                    self.assert_denied_before_dial(self.connect(port=port), "PORT_NOT_ALLOWED")
                    check.assert_not_called()

    def test_missing_and_invalid_policy_do_not_dial(self):
        for policy, reason in ((None, "POLICY_MISSING"), ({}, "POLICY_INVALID"),
                               (DestinationPolicy(()), "POLICY_INVALID"),
                               (DestinationPolicy([]), "POLICY_INVALID")):
            with self.subTest(policy=policy):
                self.policy = policy
                self.assert_denied_before_dial(self.connect(), reason)

    def test_invalid_unused_allowlist_entry_rejects_entire_policy(self):
        self.policy = DestinationPolicy((AllowedDestination("example.com", 443),
                                         AllowedDestination("bad..test", 80)))
        self.assert_denied_before_dial(self.connect(), "POLICY_INVALID")

    def test_hostname_and_exact_allowlist_rules_are_reused(self):
        for hostname in ("evil.test", "sub.example.com", "example.com.evil.test",
                         "example.com.", "https://example.com", "8.8.8.8",
                         "example.com:443", "exämple.com", " example.com", None):
            with self.subTest(hostname=hostname):
                expected = check_destination(self.policy, hostname, 443, ("8.8.8.8",))
                result = self.connect(hostname=hostname)
                self.assert_denied_before_dial(result, expected.reason)
                self.assertEqual(result.destination, expected)

    def test_invalid_answer_containers_are_not_coerced_into_allowed_sets(self):
        class AnswerList(list):
            pass

        for answers in ((), [], None, "8.8.8.8", {"8.8.8.8"},
                        iter(("8.8.8.8",)), AnswerList(["8.8.8.8"])):
            with self.subTest(answers=answers):
                self.assert_denied_before_dial(self.connect(answers), "DNS_ANSWERS_INVALID")

    def test_every_answer_checked_before_dial_in_any_order(self):
        forbidden = ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1",
                     "fc00::1", "fe80::1", "224.0.0.1", "0.0.0.0",
                     "240.0.0.1", "100.64.0.1", "fec0::1", "192.0.2.1",
                     "::ffff:8.8.8.8", "2002:0808:0808::1", "64:ff9b::808:808",
                     "2606:4700:4700::1111%1", "garbage", "127.1", b"8.8.8.8", None)
        for address in forbidden:
            for answers in (("8.8.8.8", address), (address, "8.8.8.8")):
                with self.subTest(answers=answers):
                    result = self.connect(answers)
                    self.assert_denied_before_dial(result)
                    self.assertEqual(result.destination.addresses, ())

    def test_destination_validation_precedes_dial_and_peer_read(self):
        def check(*args):
            self.events.append(("validate",))
            return check_destination(*args)

        with patch.object(connector, "check_destination", side_effect=check) as validate:
            result = self.connect(["8.8.8.8", "1.1.1.1"])
        self.assertTrue(result.allowed)
        validate.assert_called_once_with(self.policy, "example.com", 443,
                                         ("8.8.8.8", "1.1.1.1"))
        self.assertEqual(self.events, [("validate",), ("dial", "8.8.8.8", 443), ("peer",)])

    def test_mutating_original_answers_during_dial_cannot_change_pin(self):
        answers = ["8.8.8.8", "1.1.1.1"]
        self.dialer.on_dial = lambda: answers.__setitem__(slice(None), ["127.0.0.1"])
        result = self.connect(answers)
        self.assertTrue(result.allowed)
        self.assertEqual(answers, ["127.0.0.1"])
        self.assertEqual(result.destination.addresses, ("8.8.8.8", "1.1.1.1"))
        self.assertEqual(result.selected_ip, "8.8.8.8")

    def test_rebinding_original_answers_to_peer_does_not_authorize_it(self):
        answers = ["8.8.8.8"]
        self.dialer.on_dial = lambda: answers.__setitem__(0, "1.1.1.1")
        self.handle.peer = ("1.1.1.1", 443)
        result = self.connect(answers)
        self.assert_closed_failure(result, "PEER_MISMATCH")
        self.assertEqual(result.destination.addresses, ("8.8.8.8",))

    def test_result_and_validated_addresses_are_immutable(self):
        result = self.connect()
        with self.assertRaises(FrozenInstanceError):
            result.selected_ip = "1.1.1.1"
        with self.assertRaises(FrozenInstanceError):
            result.destination.addresses = ("1.1.1.1",)
        with self.assertRaises(TypeError):
            result.destination.addresses[0] = "1.1.1.1"

    def test_another_validated_ip_is_still_a_peer_mismatch(self):
        self.handle.peer = ("1.1.1.1", 443)
        result = self.connect(("8.8.8.8", "1.1.1.1"))
        self.assert_closed_failure(result, "PEER_MISMATCH")
        self.assertEqual(result.selected_ip, "8.8.8.8")

    def test_unselected_public_ip_is_rejected_and_closed(self):
        self.handle.peer = ("9.9.9.9", 443)
        self.assert_closed_failure(self.connect(), "PEER_MISMATCH")

    def test_forbidden_and_cross_family_peer_ips_are_rejected(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1",
                        "::ffff:8.8.8.8", "2606:4700:4700::1111"):
            with self.subTest(address=address):
                self.setUp()
                self.handle.peer = (address, 443)
                self.assert_closed_failure(self.connect(), "PEER_MISMATCH")

    def test_peer_port_must_match_selected_443(self):
        for port in (1, 80, 8443, 65535):
            with self.subTest(port=port):
                self.setUp()
                self.handle.peer = ("8.8.8.8", port)
                self.assert_closed_failure(self.connect(), "PEER_MISMATCH")

    def test_malformed_peer_pairs_are_rejected_and_closed(self):
        peers = (None, "8.8.8.8", ["8.8.8.8", 443], (), ("8.8.8.8",),
                 ("8.8.8.8", 443, 0, 0), ("8.8.8.8", True), ("8.8.8.8", 443.0),
                 ("8.8.8.8", "443"), ("8.8.8.8", 0), ("8.8.8.8", 65536),
                 (b"8.8.8.8", 443), (None, 443), (134744072, 443),
                 ("example.com", 443), ("8.8.8.8 ", 443), ("010.0.0.1", 443),
                 ("2606:4700:4700::1111%1", 443))
        for peer in peers:
            with self.subTest(peer=peer):
                self.setUp()
                self.handle.peer = peer
                self.assert_closed_failure(self.connect(), "INVALID_PEER")

    def test_peer_read_exceptions_close_without_returning_handle(self):
        for error in (OSError("peer failed"), RuntimeError("adapter failed"),
                      TimeoutError("peer timeout"), ValueError("bad peer")):
            with self.subTest(error=type(error).__name__):
                self.setUp()
                self.handle.peer_error = error
                result = self.connect()
                self.assert_closed_failure(result, "PEER_ERROR")
                self.assertEqual(result.error, type(error).__name__)
                self.assertIsNone(result.close_error)

    def test_missing_peer_method_still_attempts_close(self):
        class CloseOnly:
            def close(inner):
                self.events.append(("close",))

        self.dialer.handle = CloseOnly()
        result = self.connect()
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "PEER_ERROR")
        self.assertEqual(result.error, "AttributeError")
        self.assertIsNone(result.handle)
        self.assertEqual(self.events, [("dial", "8.8.8.8", 443), ("close",)])

    def test_dial_exceptions_do_not_retry_or_read_an_unreturned_handle(self):
        for error in (ConnectionError("refused"), TimeoutError("timeout"),
                      RuntimeError("adapter error"), ValueError("bad dial")):
            with self.subTest(error=type(error).__name__):
                self.setUp()
                self.dialer.error = error
                result = self.connect(("8.8.8.8", "1.1.1.1"))
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, "DIAL_ERROR")
                self.assertEqual(result.error, type(error).__name__)
                self.assertIsNone(result.handle)
                self.assertIsNone(result.close_error)
                self.assertEqual(self.events, [("dial", "8.8.8.8", 443)])

    def test_dialer_owns_and_closes_partial_resource_before_raising(self):
        def failed_dial(ip, port):
            self.events.append(("dial", ip, port))
            self.handle.close()
            raise OSError("failed before returning handle")

        self.dialer = failed_dial
        result = self.connect()
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "DIAL_ERROR")
        self.assertEqual(self.handle.close_calls, 1)
        self.assertEqual(self.events, [("dial", "8.8.8.8", 443), ("close",)])

    def test_dialer_returning_none_fails_without_transferring_ownership(self):
        self.dialer.handle = None
        result = self.connect()
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "DIAL_INVALID_HANDLE")
        self.assertIsNone(result.handle)
        self.assertEqual(self.events, [("dial", "8.8.8.8", 443)])

    def test_matching_peer_without_callable_close_cannot_succeed(self):
        class MissingClose:
            def getpeername(inner):
                self.events.append(("peer",))
                return ("8.8.8.8", 443)

        class NoncallableClose(MissingClose):
            close = None

        for handle_type, close_error in ((MissingClose, "AttributeError"),
                                          (NoncallableClose, "TypeError")):
            with self.subTest(handle_type=handle_type.__name__):
                self.events.clear()
                self.dialer.handle = handle_type()
                result = self.connect()
                self.assertFalse(result.allowed)
                self.assertEqual(result.reason, "DIAL_INVALID_HANDLE")
                self.assertIsNone(result.handle)
                self.assertEqual(result.close_error, close_error)
                self.assertEqual(self.events, [("dial", "8.8.8.8", 443), ("peer",)])

    def test_close_failure_preserves_peer_mismatch_and_records_cleanup_error(self):
        self.handle.peer = ("1.1.1.1", 443)
        self.handle.close_error = OSError("close failed")
        result = self.connect()
        self.assert_closed_failure(result, "PEER_MISMATCH")
        self.assertIsNone(result.error)
        self.assertEqual(result.close_error, "OSError")

    def test_peer_and_close_exceptions_are_both_recorded(self):
        self.handle.peer_error = TimeoutError("peer timed out")
        self.handle.close_error = RuntimeError("close failed")
        result = self.connect()
        self.assert_closed_failure(result, "PEER_ERROR")
        self.assertEqual(result.error, "TimeoutError")
        self.assertEqual(result.close_error, "RuntimeError")

    def test_missing_close_method_is_recorded_as_cleanup_failure(self):
        class PeerOnly:
            def getpeername(inner):
                self.events.append(("peer",))
                return ("1.1.1.1", 443)

        self.dialer.handle = PeerOnly()
        result = self.connect()
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "PEER_MISMATCH")
        self.assertIsNone(result.handle)
        self.assertEqual(result.close_error, "AttributeError")
        self.assertEqual(self.events, [("dial", "8.8.8.8", 443), ("peer",)])

    def test_success_transfers_handle_and_only_caller_closes_it(self):
        result = self.connect()
        self.assertTrue(result.allowed)
        self.assertIs(result.handle, self.handle)
        self.assertEqual(self.handle.close_calls, 0)
        result.handle.close()
        self.assertEqual(self.handle.close_calls, 1)
        self.assertEqual(self.events, [("dial", "8.8.8.8", 443), ("peer",), ("close",)])

    def test_peer_read_occurs_before_ownership_transfer(self):
        def during_peer():
            self.assertEqual(self.events, [("dial", "8.8.8.8", 443), ("peer",)])
            self.assertEqual(self.handle.close_calls, 0)
            raise OSError("verification did not complete")

        self.handle.on_peer = during_peer
        self.assert_closed_failure(self.connect(), "PEER_ERROR")

    def test_peer_failure_does_not_revalidate_redial_or_try_next_ip(self):
        self.handle.peer = ("1.1.1.1", 443)
        with patch.object(connector, "check_destination", wraps=check_destination) as check:
            result = self.connect(("8.8.8.8", "1.1.1.1", "9.9.9.9"))
            check.assert_called_once()
        self.assert_closed_failure(result, "PEER_MISMATCH")

    def test_interrupt_during_peer_check_closes_then_propagates(self):
        interrupt = KeyboardInterrupt()
        self.handle.peer_error = interrupt
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.connect()
        self.assertIs(caught.exception, interrupt)
        self.assertEqual(self.handle.close_calls, 1)
        self.assertEqual(self.events, [("dial", "8.8.8.8", 443), ("peer",), ("close",)])

    def test_interrupt_cleanup_failure_is_recorded_on_original_exception(self):
        interrupt = SystemExit("cancelled")
        self.handle.peer_error = interrupt
        self.handle.close_error = OSError("close failed")
        with self.assertRaises(SystemExit) as caught:
            self.connect()
        self.assertIs(caught.exception, interrupt)
        self.assertEqual(interrupt.__notes__, ["connector close failed: OSError"])
        self.assertEqual(self.handle.close_calls, 1)

    def test_interrupted_close_does_not_hide_original_peer_failure(self):
        self.handle.peer = ("1.1.1.1", 443)
        self.handle.close_error = KeyboardInterrupt()
        result = self.connect()
        self.assert_closed_failure(result, "PEER_MISMATCH")
        self.assertEqual(result.close_error, "KeyboardInterrupt")


if __name__ == "__main__":
    unittest.main()
