"""AWS-B probe: destination allowlist, pinned connection, redirect refusal, bounded reads.

No real DNS, TLS or socket to any host. `socket.socketpair()` is used for the HTTP framing
test; the real TLS adapter (`TlsTransport`) is NOT exercised offline.
"""
import socket
import ssl
import unittest

from src.aws_b.model import MonitorConfig
from src.aws_b.probe import (MAX_RESPONSE_HEAD_BYTES, IncompleteStatusLine, build_request, parse_status_line,
                             read_status_line, run_probe)
from src.core.model import CheckOutcome
from tests.aws_b.support import ENV

PUBLIC = "93.184.216.34"


class FakeHandle:
    def __init__(self, ip, port=443):
        self.peer, self.closed = (ip, port), 0

    def getpeername(self):
        return self.peer

    def close(self):
        self.closed += 1


class FakeTransport:
    def __init__(self, line=b"HTTP/1.1 200 OK", error=None, not_after="Jan  1 00:00:00 2027 GMT"):
        self.line, self.error, self.not_after, self.calls = line, error, not_after, []

    def exchange(self, handle, hostname, path, deadline):
        self.calls.append((hostname, path))
        if self.error:
            raise self.error
        return self.line, self.not_after


def probe(answers=(PUBLIC,), transport=None, dialer=None, resolver=None, now=0.0, deadline=5.0):
    config = MonitorConfig.from_env(ENV)
    dialled = []

    def default_dialer(ip, port):
        handle = FakeHandle(ip, port)
        dialled.append(handle)
        return handle
    transport = transport or FakeTransport()
    result = run_probe(config, resolver=resolver or (lambda host: answers),
                       dialer=dialer or default_dialer, transport=transport,
                       deadline=deadline, clock=lambda: now)
    return result, dialled, transport


class Outcomes(unittest.TestCase):
    def test_200_is_pass_and_handle_is_closed(self):
        result, dialled, transport = probe()
        self.assertEqual((result.outcome, result.reason, result.http_status),
                         (CheckOutcome.PASS, "HTTP_200", 200))
        self.assertEqual(result.selected_ip, PUBLIC)
        self.assertEqual(dialled[0].closed, 1)
        self.assertEqual(transport.calls, [("d111111abcdef8.cloudfront.net", "/home/index.html")])

    def test_4xx_5xx_fail(self):
        for status in (403, 404, 500, 503):
            result, _, _ = probe(transport=FakeTransport(b"HTTP/1.1 %d X" % status))
            self.assertEqual((result.outcome, result.http_status), (CheckOutcome.FAIL, status))

    def test_redirect_is_unknown_and_never_followed(self):
        for status in (301, 302, 307, 308):
            result, dialled, transport = probe(transport=FakeTransport(b"HTTP/1.1 %d Moved" % status))
            self.assertEqual(result.outcome, CheckOutcome.UNKNOWN)
            self.assertEqual(result.reason, "HTTP_%d_UNRESOLVED" % status)
            self.assertEqual((len(dialled), len(transport.calls)), (1, 1))

    def test_malformed_status_line_is_unknown(self):
        for line in (b"", b"HTTP/2 200", b"HTTP/1.1 20", b"HTTP/1.1 abc OK", b"garbage", None):
            result, _, _ = probe(transport=FakeTransport(line))
            self.assertEqual((result.outcome, result.reason),
                             (CheckOutcome.UNKNOWN, "HTTP_MALFORMED"))

    def test_transport_failures_are_classified_and_handle_closed(self):
        for error, reason, outcome in (
                (ssl.SSLCertVerificationError("expired"), "TLS_FAILED", CheckOutcome.FAIL),
                (TimeoutError(), "HTTP_TIMEOUT", CheckOutcome.FAIL),
                (ConnectionResetError(), "HTTP_IO_ERROR", CheckOutcome.FAIL),
                (RuntimeError("bug"), "HTTP_EXCHANGE_ERROR", CheckOutcome.UNKNOWN)):
            result, dialled, _ = probe(transport=FakeTransport(error=error))
            self.assertEqual((result.outcome, result.reason), (outcome, reason))
            self.assertEqual(dialled[0].closed, 1)


class DestinationBoundary(unittest.TestCase):
    def test_forbidden_answers_are_never_dialled(self):
        cases = {"127.0.0.1": "LOOPBACK_ADDRESS", "10.0.0.5": "PRIVATE_ADDRESS",
                 "192.168.1.1": "PRIVATE_ADDRESS", "169.254.169.254": "LINK_LOCAL_ADDRESS",
                 "::1": "LOOPBACK_ADDRESS", "fe80::1": "LINK_LOCAL_ADDRESS",
                 "fd00::1": "PRIVATE_ADDRESS", "::ffff:10.0.0.1": "IPV4_MAPPED_IPV6",
                 "0.0.0.0": "UNSPECIFIED_ADDRESS", "not-an-ip": "INVALID_DNS_ADDRESS"}
        for answer, reason in cases.items():
            with self.subTest(answer=answer):
                result, dialled, transport = probe(answers=(answer,))
                self.assertEqual((result.outcome, result.reason),
                                 (CheckOutcome.UNKNOWN, "DESTINATION_" + reason))
                self.assertEqual((dialled, transport.calls), ([], []))

    def test_one_forbidden_answer_poisons_the_whole_set(self):
        result, dialled, _ = probe(answers=(PUBLIC, "169.254.169.254"))
        self.assertEqual(result.reason, "DESTINATION_LINK_LOCAL_ADDRESS")
        self.assertEqual(dialled, [])

    def test_empty_or_invalid_answer_set(self):
        self.assertEqual(probe(answers=())[0].reason, "DESTINATION_DNS_ANSWERS_INVALID")
        self.assertEqual(probe(answers="93.184.216.34")[0].reason, "DNS_RESULT_INVALID")

    def test_resolver_errors_are_unknown_not_fail(self):
        def boom(host):
            raise OSError("nxdomain")

        def slow(host):
            raise TimeoutError()
        self.assertEqual(probe(resolver=boom)[0].reason, "DNS_ERROR")
        self.assertEqual(probe(resolver=slow)[0].reason, "DNS_TIMEOUT")
        self.assertEqual(probe(resolver=boom)[0].outcome, CheckOutcome.UNKNOWN)

    def test_resolver_is_asked_only_for_the_configured_hostname(self):
        asked = []
        probe(resolver=lambda host: asked.append(host) or (PUBLIC,))
        self.assertEqual(asked, ["d111111abcdef8.cloudfront.net"])

    def test_peer_mismatch_closes_and_reports_unknown(self):
        handles = []

        def lying_dialer(ip, port):
            handles.append(FakeHandle("198.51.100.7", port))
            return handles[-1]
        result, _, transport = probe(dialer=lying_dialer)
        self.assertEqual(result.reason, "DESTINATION_PEER_MISMATCH")
        self.assertEqual((handles[0].closed, transport.calls), (1, []))

    def test_dial_error_is_an_observed_failure(self):
        def refused(ip, port):
            raise ConnectionRefusedError()
        result, _, transport = probe(dialer=refused)
        self.assertEqual((result.outcome, result.reason), (CheckOutcome.FAIL, "CONNECT_FAILED"))
        self.assertEqual(transport.calls, [])

    def test_only_port_443_is_dialled(self):
        ports = []

        def dialer(ip, port):
            ports.append(port)
            return FakeHandle(ip, port)
        probe(dialer=dialer)
        self.assertEqual(ports, [443])

    def test_deadline_already_passed_does_nothing(self):
        result, dialled, _ = probe(now=9.0, deadline=5.0)
        self.assertEqual(result.reason, "PROBE_DEADLINE_BEFORE_START")
        self.assertEqual(dialled, [])


class HttpFraming(unittest.TestCase):
    def test_request_is_minimal_and_has_no_credentials(self):
        raw = build_request("example.org", "/a").decode("ascii")
        self.assertTrue(raw.startswith("GET /a HTTP/1.1\r\nHost: example.org\r\n"))
        self.assertTrue(raw.endswith("Connection: close\r\n\r\n"))
        for forbidden in ("Authorization", "Cookie", "Referer"):
            self.assertNotIn(forbidden, raw)

    def test_status_line_parsing(self):
        self.assertEqual(parse_status_line(b"HTTP/1.1 204 No Content"), 204)
        self.assertEqual(parse_status_line(b"HTTP/1.0 200"), 200)
        for bad in (b"HTTP/1.1", b"HTTP/1.1 2000 X", b"http/1.1 200 OK", b" HTTP/1.1 200"):
            self.assertIsNone(parse_status_line(bad))

    def test_reads_only_until_first_crlf_over_a_local_socketpair(self):
        left, right = socket.socketpair()
        try:
            right.sendall(b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n<html>body never parsed")
            self.assertEqual(read_status_line(left.recv, deadline=10.0, clock=lambda: 0.0),
                             b"HTTP/1.1 200 OK")
        finally:
            left.close()
            right.close()

    def test_unbounded_status_line_is_refused(self):
        chunks = iter([b"A" * 4096] * 10)
        with self.assertRaises(ValueError):
            read_status_line(lambda size: next(chunks), deadline=10.0, clock=lambda: 0.0)
        self.assertEqual(MAX_RESPONSE_HEAD_BYTES, 16384)

    def test_read_respects_deadline_and_eof(self):
        with self.assertRaises(TimeoutError):
            read_status_line(lambda size: b"H", deadline=1.0, clock=lambda: 2.0)
        self.assertEqual(read_status_line(lambda size: b"", deadline=1.0, clock=lambda: 0.0), b"")

    def test_an_unterminated_status_line_is_never_a_status(self):
        """EOF inside a line without CRLF: the bytes read so far must not become a verdict (a cut-off "HTTP/1.1 200" is not a 200)."""
        for partial in (b"HTTP/1.1 200 OK", b"HTTP/1.1 200", b"HTTP/1.1 20", b"H", b"HTTP/1.1 200 OKHTTP/1.1 200 OK"):
            with self.subTest(partial):
                chunks = iter([partial, b""])
                with self.assertRaises(IncompleteStatusLine):
                    read_status_line(lambda size: next(chunks), deadline=10.0, clock=lambda: 0.0)

    def test_incomplete_is_not_the_same_as_a_timeout_or_nothing_at_all(self):
        self.assertTrue(issubclass(IncompleteStatusLine, ValueError) and not issubclass(IncompleteStatusLine, TimeoutError))
        with self.assertRaises(TimeoutError):  # a deadline stays a TimeoutError
            read_status_line(lambda size: b"H", deadline=1.0, clock=lambda: 2.0)
        self.assertEqual(read_status_line(lambda size: b"", deadline=1.0, clock=lambda: 0.0), b"")  # nothing at all: still no line, never a status

    def test_complete_lines_still_read_whole_and_the_cap_still_holds(self):
        for line in (b"HTTP/1.1 200 OK", b"HTTP/1.1 503 Service Unavailable"):
            chunks = iter([line[:5], line[5:] + b"\r\nServer: x\r\n\r\nbody"])
            self.assertEqual(read_status_line(lambda size: next(chunks), deadline=10.0, clock=lambda: 0.0), line)
        endless = iter([b"A" * 4096] * 10)
        with self.assertRaises(ValueError) as refused:
            read_status_line(lambda size: next(endless), deadline=10.0, clock=lambda: 0.0)
        self.assertNotIsInstance(refused.exception, IncompleteStatusLine)  # over the 16 KiB cap is its own refusal
        self.assertEqual(MAX_RESPONSE_HEAD_BYTES, 16384)

    def test_an_incomplete_line_is_undecided_not_pass_and_not_a_site_failure(self):
        result, dialled, _ = probe(transport=FakeTransport(error=IncompleteStatusLine("cut")))
        self.assertEqual((result.outcome, result.reason, result.http_status), (CheckOutcome.UNKNOWN, "HTTP_INCOMPLETE", None))
        self.assertEqual(dialled[0].closed, 1)
        result, _, _ = probe(transport=FakeTransport(error=TimeoutError()))
        self.assertEqual((result.outcome, result.reason), (CheckOutcome.FAIL, "HTTP_TIMEOUT"))  # a timeout is still a different, observed failure


if __name__ == "__main__":
    unittest.main()
