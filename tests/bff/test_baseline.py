"""BFF01..BFF12: disposable SQLite DBs and numeric 127.0.0.1 sockets only."""

from contextlib import closing, redirect_stderr
from dataclasses import replace
from http.client import HTTPResponse, RemoteDisconnected
import io
import json
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

from src.baseline.model import BaselineCandidate, BaselineStatus
from src.baseline.sqlite_store import SQLiteBaselineStore
from src.bff.baseline import BaselineBFF, BFFLimits


VIOLATIONS = []
ROOTS = set()


def boundary(event, args):
    if event == "socket.getaddrinfo" or event.startswith("subprocess."):
        VIOLATIONS.append(event)
        raise AssertionError("external DNS/process forbidden")
    if event in ("socket.bind", "socket.connect", "socket.sendto"):
        address = args[1] if event != "socket.sendto" else args[-1]
        if type(address) is not tuple or address[0] != "127.0.0.1":
            VIOLATIONS.append(event)
            raise AssertionError("only numeric IPv4 loopback allowed")
    if event == "sqlite3.connect":
        value = str(args[0])
        value = unquote(urlsplit(value).path) if value.startswith("file:") else value
        if sys.platform == "win32" and len(value) > 2 and value[0] == "/" and value[2] == ":":
            value = value[1:]
        path = Path(value).absolute()
        if not any(path.is_relative_to(root) for root in ROOTS):
            VIOLATIONS.append("sqlite outside fixture")
            raise AssertionError("only this suite's temporary databases allowed")


sys.addaudithook(boundary)


def wait_for(check, seconds=1):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return True
        threading.Event().wait(.005)
    return bool(check())


class BFFTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="siteproof-baseline-bff-01-")
        self.root = Path(self.temp.name)
        ROOTS.add(self.root)
        self.addCleanup(self._remove_temp)
        self.db = self.root / "siteproof.sqlite"
        self.store = SQLiteBaselineStore.create(self.db, self.root)
        self.servers, self.clients = [], []
        self.addCleanup(self._stop_servers)

    def _remove_temp(self):
        self.temp.cleanup()
        self.assertFalse(self.root.exists())
        ROOTS.remove(self.root)

    def _stop_servers(self):
        for client in self.clients:
            client.close()
        for server in self.servers:
            self.assertTrue(server.stop(), "listener/request worker remains")
            self.assertEqual(server._server.socket.fileno(), -1)
            self.assertEqual(len(server._server.clients), 0)
        self.assertEqual(VIOLATIONS, [])

    def add(self, cid="c1", *, approve=False, current=0, artifact_ref="job/attempt/shot.png"):
        record = self.store.register(BaselineCandidate(cid, "page-1", "a" * 64,
                                                      artifact_ref, "b" * 64))
        if approve:
            return self.store.decide(cid, decision=BaselineStatus.APPROVED, actor="alice",
                expected_revision=0, reviewed_digest=record.registered_digest,
                expected_current_version=current)
        return record

    def server(self, *, db=None, **limits):
        server = BaselineBFF(db or self.db, self.root, limits=replace(BFFLimits(), **limits))
        server.start()
        self.assertEqual(server.address[0], "127.0.0.1")
        self.servers.append(server)
        return server

    def socket(self, server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(server.address)
        self.clients.append(sock)
        return sock

    def request(self, server, path="/api/baselines", *, method="GET", headers=None,
                authorized=True, host=True, raw=None):
        fields = {}
        if host:
            fields["Host"] = server.authority
        if authorized:
            fields["Authorization"] = "Bearer " + server.token_for_local_client()
        fields.update(headers or {})
        data = raw or ((method + " " + path + " HTTP/1.1\r\n" +
                        "".join(key + ": " + value + "\r\n" for key, value in fields.items()) +
                        "\r\n").encode("ascii"))
        sock = self.socket(server)
        try:
            sock.sendall(data)
            with closing(HTTPResponse(sock)) as response:
                response.begin()
                payload = response.read()
                result = json.loads(payload)
                self.assertEqual(response.getheader("Content-Type"), "application/json")
                self.assertEqual(response.getheader("Cache-Control"), "no-store")
                self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")
                self.assertIsNone(response.getheader("Access-Control-Allow-Origin"))
                self.assertNotIn(str(self.root), payload.decode())
                self.assertNotIn(str(self.db), payload.decode())
                self.assertNotIn("Traceback", payload.decode())
                return response.status, result
        finally:
            sock.close()

    def test_BFF01_paginated_candidate_list_includes_pending_and_approved(self):
        self.add("a", approve=True)
        self.add("b")
        self.add("c")
        server = self.server()
        status, first = self.request(server, "/api/baselines?limit=2")
        self.assertEqual(status, 200)
        self.assertEqual([r["candidate_id"] for r in first["items"]], ["a", "b"])
        self.assertEqual(first["next_offset"], 2)
        self.assertEqual([r["approval_state"] for r in first["items"]], ["APPROVED", "PENDING"])
        status, last = self.request(server, "/api/baselines?limit=2&offset=2")
        self.assertEqual(status, 200)
        self.assertEqual([r["candidate_id"] for r in last["items"]], ["c"])
        self.assertIsNone(last["next_offset"])

    def test_BFF02_detail_contains_stored_digest_revision_and_current_reference(self):
        old = self.add("old", approve=True)
        self.add("new", approve=True, current=1)
        server = self.server()
        status, result = self.request(server, "/api/baselines/old")
        item = result["baseline"]
        self.assertEqual(status, 200)
        self.assertEqual(item["candidate_digest"], old.registered_digest)
        self.assertEqual(item["revision"], 1)
        self.assertEqual(item["candidate_version"], 1)
        self.assertEqual(item["current"], {"version": 2, "candidate_id": "new"})
        self.assertFalse(item["is_current"])
        self.assertEqual(item["approval"]["actor"], "alice")
        self.assertNotIn("approved_at", item["approval"])

    def test_BFF03_history_is_paged_and_current_identified_without_modification(self):
        self.add("old", approve=True)
        self.add("new", approve=True, current=1)
        self.add("pending")
        server = self.server()
        status, first = self.request(server, "/api/baselines/pending/history?limit=1")
        self.assertEqual(status, 200)
        self.assertEqual(first["versions"][0]["version"], 1)
        self.assertFalse(first["versions"][0]["is_current"])
        self.assertEqual(first["next_offset"], 1)
        _, second = self.request(server, "/api/baselines/pending/history?limit=1&offset=1")
        self.assertTrue(second["versions"][0]["is_current"])
        self.assertEqual(second["versions"][0]["baseline"]["approval"]["state"], "APPROVED")
        self.assertIsNone(second["next_offset"])

    def test_BFF04_empty_not_found_and_database_failure_are_distinct(self):
        server = self.server()
        status, empty = self.request(server)
        self.assertEqual((status, empty["items"]), (200, []))
        self.assertEqual(self.request(server, "/api/baselines/missing")[0], 404)
        missing = self.root / "never-created.sqlite"
        bad = self.server(db=missing)
        status, error = self.request(bad)
        self.assertEqual((status, error), (503, {"error": {"code": "DATA_UNAVAILABLE"}}))
        self.assertFalse(missing.exists())

    def test_BFF04_incompatible_database_is_not_initialized_or_migrated(self):
        bad = self.root / "unsupported.sqlite"
        with closing(sqlite3.connect(bad)) as conn, conn:
            conn.execute("CREATE TABLE unrelated(value TEXT)")
        before = bad.read_bytes()
        server = self.server(db=bad)
        self.assertEqual(self.request(server)[0], 503)
        self.assertEqual(bad.read_bytes(), before)

    def test_BFF05_no_token_invalid_token_and_token_distribution_refused(self):
        self.add()
        server = self.server()
        self.assertGreaterEqual(len(server.token_for_local_client()), 40)
        with patch.object(server, "_query", side_effect=AssertionError("must not read DB")):
            self.assertEqual(self.request(server, authorized=False)[0], 401)
            self.assertEqual(self.request(server, headers={"Authorization": "Bearer wrong"})[0], 401)
            self.assertEqual(self.request(server, headers={"Authorization": "Basic wrong"})[0], 401)
        self.assertEqual(self.request(server, "/api/token", authorized=False)[0], 401)
        self.assertEqual(self.request(server, "/api/token")[0], 404)

    def test_BFF06_expired_session_refused(self):
        server = self.server(session_seconds=.04)
        token = server.token_for_local_client()
        threading.Event().wait(.06)
        self.assertEqual(self.request(server, authorized=False,
                         headers={"Authorization": "Bearer " + token})[0], 401)

    def test_BFF06_destroyed_session_refused_even_with_original_token(self):
        server = self.server()
        token = server.token_for_local_client()
        server.destroy_session()
        self.assertEqual(self.request(server, authorized=False,
                         headers={"Authorization": "Bearer " + token})[0], 401)

    def test_BFF07_wrong_host_origin_and_fetch_metadata_refused(self):
        server = self.server()
        for headers in ({"Host": "localhost:" + str(server.address[1])},
                        {"Host": "evil.invalid"}, {"Host": "127.0.0.1:1"},
                        {"Origin": "null"}, {"Origin": "https://evil.invalid"},
                        {"Origin": server.origin + "/"}, {"Sec-Fetch-Site": "cross-site"},
                        {"Sec-Fetch-Site": "same-site"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request(server, headers=headers)[0], 403)
        self.assertEqual(self.request(server, host=False)[0], 403)
        self.assertEqual(self.request(server, headers={"Origin": server.origin,
                                                      "Sec-Fetch-Site": "same-origin"})[0], 200)

    def test_BFF07_absent_origin_never_bypasses_host_or_session(self):
        server = self.server()
        self.assertEqual(self.request(server)[0], 200)
        self.assertEqual(self.request(server, authorized=False)[0], 401)
        self.assertEqual(self.request(server, headers={"Host": "evil.invalid"})[0], 403)

    def test_BFF08_all_non_get_methods_and_unknown_routes_refused(self):
        server = self.server()
        for method in ("POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"):
            with self.subTest(method=method):
                self.assertEqual(self.request(server, method=method)[0], 405)
        for path in ("/", "/api/baselines/c1/approve", "/api/baselines/", "/api/unknown"):
            with self.subTest(path=path):
                self.assertEqual(self.request(server, path)[0], 404)

    def test_BFF09_arbitrary_db_sql_credentials_and_invalid_paging_rejected(self):
        server = self.server()
        token = server.token_for_local_client()
        for query in ("db=secret.sqlite", "sql=SELECT+1", "token=" + token, "limit=101", "limit=0",
                      "limit=-1", "offset=10001", "offset=x", "limit=2&limit=3", "a=1&b=2&c=3"):
            with self.subTest(query=query):
                status, body = self.request(server, "/api/baselines?" + query)
                self.assertEqual(status, 400)
                self.assertNotIn(token, json.dumps(body))
        self.assertEqual(self.request(server, "/api/baselines/%zz")[0], 400)

    def test_BFF09_oversized_malformed_and_duplicated_headers_are_json_errors(self):
        server = self.server(max_header_bytes=512)
        status, _ = self.request(server, headers={"X-Padding": "x" * 600})
        self.assertEqual(status, 431)
        duplicate = ("GET /api/baselines HTTP/1.1\r\nHost: " + server.authority +
                     "\r\nHost: evil.invalid\r\n\r\n").encode()
        self.assertEqual(self.request(server, raw=duplicate)[0], 400)
        self.assertEqual(self.request(server, headers={"Content-Length": "0"})[0], 400)

    def test_BFF09_connection_cap_and_slow_header_deadline(self):
        server = self.server(max_connections=1, request_timeout_seconds=.4)
        slow = self.socket(server)
        slow.sendall(b"G")
        self.assertTrue(wait_for(lambda: len(server._server.clients) == 1))
        # Over-capacity rejection occurs before HTTP parsing. Send no unread
        # client payload, which can make Windows reset the close after the reply.
        extra = self.socket(server)
        with closing(HTTPResponse(extra)) as response:
            response.begin()
            self.assertEqual(response.status, 503)
            self.assertEqual(json.loads(response.read()), {"error": {"code": "BUSY"}})
        self.assertTrue(wait_for(lambda: len(server._server.clients) == 0))
        # Depending on deadline rounding, a valid JSON 408 can fit before close;
        # otherwise the server closes without publishing any late data.
        with closing(HTTPResponse(slow)) as response:
            try:
                response.begin()
            except (RemoteDisconnected, ConnectionResetError, ConnectionAbortedError):
                pass
            else:
                self.assertEqual(response.status, 408)
                self.assertEqual(response.getheader("Content-Type"), "application/json")
                self.assertEqual(json.loads(response.read()), {"error": {"code": "REQUEST_TIMEOUT"}})

    def test_BFF09_bounded_response_fails_without_partial_data(self):
        self.add()
        server = self.server(max_response_bytes=64)
        status, body = self.request(server)
        self.assertEqual((status, body), (503, {"error": {"code": "RESPONSE_LIMIT"}}))

    def test_BFF10_all_api_reads_are_query_only_and_leave_database_bytes_unchanged(self):
        self.add(approve=True)
        server = self.server()
        before = self.db.read_bytes()
        original = SQLiteBaselineStore._connect
        connections = []
        def checked(store, readonly):
            self.assertTrue(readonly)
            conn = original(store, readonly)
            connections.append(conn)
            # Both URI read-only and query_only apply; normal reads still work.
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("CREATE TABLE forbidden(value TEXT)")
            return conn
        with patch.object(SQLiteBaselineStore, "_connect", checked):
            for path in ("/api/baselines", "/api/baselines/c1", "/api/baselines/c1/history"):
                self.assertEqual(self.request(server, path)[0], 200)
        self.assertEqual(len(connections), 3)
        self.assertEqual(self.db.read_bytes(), before)
        for conn in connections:
            with self.assertRaises(sqlite3.ProgrammingError):
                conn.execute("SELECT 1")

    def test_BFF11_approved_is_not_quality_pass_and_no_timestamp_is_invented(self):
        self.add(approve=True)
        server = self.server()
        _, body = self.request(server, "/api/baselines/c1")
        self.assertEqual(body["baseline"]["approval_state"], "APPROVED")
        self.assertEqual(body["assessment"], {"profile_trust": "UNATTESTED",
            "profile_reason": "PROFILE_UNATTESTED", "quality": "UNKNOWN", "comparison": "NOT_RUN"})
        self.assertNotIn("PASS", json.dumps(body))
        self.assertNotIn("approved_at", json.dumps(body))

    def test_BFF11_absolute_artifact_reference_is_redacted_and_never_opened(self):
        self.add(artifact_ref=str(self.root / "private.png"))
        server = self.server()
        _, body = self.request(server, "/api/baselines/c1")
        self.assertIsNone(body["baseline"]["artifact_ref"])
        self.assertTrue(body["baseline"]["artifact_ref_redacted"])
        self.assertFalse((self.root / "private.png").exists())

    def test_BFF12_stop_releases_listener_and_invalidates_session(self):
        server = self.server()
        token = server.token_for_local_client()
        self.assertTrue(server.stop())
        self.assertFalse(server._session.accepts("Bearer " + token))
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as client:
            client.settimeout(.1)
            with self.assertRaises(OSError):
                client.connect(server.address)

    def test_BFF12_failed_thread_start_closes_listener_without_hanging_stop(self):
        server = BaselineBFF(self.db, self.root)
        with patch("threading.Thread.start", side_effect=RuntimeError("thread creation failed")):
            with self.assertRaises(RuntimeError):
                server.start()
        self.assertTrue(server.stop())
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as client:
            client.settimeout(.1)
            with self.assertRaises(OSError):
                client.connect(server.address)

    def test_limits_reject_polling_beyond_shutdown_and_too_small_errors(self):
        for limits in ({"poll_seconds": 3}, {"max_response_bytes": 1},
                       {"request_timeout_seconds": False}, {"max_connections": 0}):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                BFFLimits(**limits)

    def test_no_logs_leak_path_session_or_request_target(self):
        server = self.server()
        errors = io.StringIO()
        with redirect_stderr(errors), patch.object(server, "_query", side_effect=RuntimeError(str(self.db))):
            status, body = self.request(server)
        self.assertEqual(status, 503)
        self.assertEqual(body, {"error": {"code": "DATA_UNAVAILABLE"}})
        self.assertEqual(errors.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
