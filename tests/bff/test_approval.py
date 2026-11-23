"""Approval HTTP boundary: disposable SQLite and numeric loopback fixtures only."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr
import io
import json
import sqlite3
import threading
import time
import unittest
from unittest.mock import patch

from src.baseline.model import BaselineStatus
from src.baseline.sqlite_store import AmbiguousBaselineCommit, SQLiteBaselineStore
from src.bff.baseline import BFFLimits
from src.bff.local_ui import LocalBaselineHOME
from tests.bff import test_baseline as fixtures
from tests.bff import test_local_ui as ui_fixtures


SESSION = "/api/baselines/_approval/session"
APPROVE = "/api/baselines/_approval/approve"


class ApprovalTests(unittest.TestCase):
    setUp = fixtures.BFFTests.setUp
    _remove_temp = fixtures.BFFTests._remove_temp
    _stop_servers = ui_fixtures.LocalUITests._stop_servers
    add = fixtures.BFFTests.add
    socket = fixtures.BFFTests.socket
    request = ui_fixtures.LocalUITests.request
    pair = ui_fixtures.LocalUITests.pair

    def server(self, *, actor="fixture-local-operator", db=None):
        server = LocalBaselineHOME(db or self.db, self.root, approval_actor=actor,
                                   limits=BFFLimits(request_timeout_seconds=2))
        server.start()
        self.servers.append(server)
        return server

    def authenticated(self, **kwargs):
        server = self.server(**kwargs)
        cookie, _ = self.pair(server)
        status, _, raw = self.request(server, SESSION, cookie=cookie,
            headers={"X-SiteProof-UI": "1", "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 200)
        return server, cookie, json.loads(raw).get("csrf_token")

    def payload(self, cid="c1", **changes):
        result = {"candidate_id": cid, "expected_revision": 0,
                  "reviewed_digest": self.store.get(cid).registered_digest,
                  "expected_current_version": 0, "confirmed": True}
        result.update(changes)
        return result

    def approve(self, auth, obj=None, **kwargs):
        server, cookie, csrf = auth
        headers = {"X-SiteProof-CSRF": csrf or ""}
        headers.update(kwargs.pop("headers", {}))
        return self.request(server, APPROVE, method="POST", cookie=cookie,
            headers=headers, body=json.dumps(obj or self.payload()).encode(), **kwargs)

    def test_A01_explicit_approval_server_actor_and_history(self):
        self.add()
        auth = self.authenticated()
        before = self.db.read_bytes()
        self.assertEqual(self.store.get("c1").status, BaselineStatus.PENDING)
        self.assertEqual(self.approve(auth)[0], 200)
        self.assertNotEqual(self.db.read_bytes(), before)
        record = self.store.get("c1")
        self.assertEqual(record.decision.actor, "fixture-local-operator")
        self.assertEqual(record.revision, 1)
        for path in ("/api/baselines", "/api/baselines/c1", "/api/baselines/c1/history"):
            status, _, raw = self.request(auth[0], path, cookie=auth[1])
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(raw)["assessment"]["quality"], "UNKNOWN")
        self.assertEqual(len(self.store.history("page-1", "a" * 64)), 1)

    def test_A02_confirmation_required_and_get_never_approves(self):
        self.add()
        auth = self.authenticated()
        before = self.db.read_bytes()
        self.assertEqual(self.approve(auth, self.payload(confirmed=False))[0], 400)
        self.assertEqual(self.request(auth[0], APPROVE, cookie=auth[1])[0], 405)
        self.assertEqual(self.db.read_bytes(), before)

    def test_A03_revision_and_reviewed_current_version_must_match(self):
        self.add()
        auth = self.authenticated()
        before = self.db.read_bytes()
        for changes in ({"expected_revision": 1}, {"expected_current_version": 1}):
            self.assertEqual(self.approve(auth, self.payload(**changes))[0], 409)
        self.assertEqual(self.db.read_bytes(), before)

    def test_A04_digest_mismatch_refused(self):
        self.add()
        auth = self.authenticated()
        before = self.db.read_bytes()
        status, _, raw = self.approve(auth, self.payload(reviewed_digest="f" * 64))
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(raw)["error"]["code"], "DIGEST_MISMATCH")
        self.assertEqual(self.db.read_bytes(), before)

    def test_A05_duplicate_approval_and_two_gateways_current_cas(self):
        self.add("one")
        self.add("two")
        first, second = self.authenticated(), self.authenticated()
        barrier = threading.Barrier(2)
        original = SQLiteBaselineStore.decide
        def simultaneous(store, *args, **kwargs):
            barrier.wait(timeout=1)
            return original(store, *args, **kwargs)
        with patch.object(SQLiteBaselineStore, "decide", simultaneous):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda pair: self.approve(*pair)[0],
                    [(first, self.payload("one")), (second, self.payload("two"))]))
        self.assertEqual(sorted(results), [200, 409])
        history = self.store.history("page-1", "a" * 64)
        self.assertEqual(len(history), 1)
        self.assertEqual(self.approve(first, self.payload(history[0].record.candidate.candidate_id))[0], 409)
        self.assertEqual(self.store.history("page-1", "a" * 64), history)

    def test_A06_missing_expired_destroyed_session(self):
        self.add()
        auth = self.authenticated()
        server, cookie, csrf = auth
        raw = json.dumps(self.payload()).encode()
        self.assertEqual(self.request(server, APPROVE, method="POST", body=raw,
                                      headers={"X-SiteProof-CSRF": csrf})[0], 401)
        self.assertEqual(self.request(server, SESSION, headers={"X-SiteProof-UI": "1",
                                      "Sec-Fetch-Site": "same-origin"})[0], 401)
        server._session._expires = time.monotonic() - 1
        self.assertEqual(self.approve(auth)[0], 401)
        server.destroy_session()
        self.assertEqual(self.approve(auth)[0], 401)
        self.assertEqual(self.store.get("c1").status, BaselineStatus.PENDING)

    def test_A07_csrf_missing_wrong_and_bound_to_session(self):
        self.add()
        first = self.authenticated()
        other = self.authenticated()
        before = self.db.read_bytes()
        for value in ("", "wrong", other[2]):
            self.assertEqual(self.approve(first, headers={"X-SiteProof-CSRF": value})[0], 403)
        self.assertEqual(self.request(first[0], SESSION, cookie=first[1])[0], 403)
        self.assertEqual(self.request(first[0], SESSION, cookie=first[1],
                                      headers={"X-SiteProof-UI": "1", "Sec-Fetch-Site": "none"})[0], 403)
        self.assertEqual(self.db.read_bytes(), before)

    def test_A08_host_origin_cross_site_and_absent_origin_refused(self):
        self.add()
        auth = self.authenticated()
        for headers in ({"Host": "evil.invalid"}, {"Origin": "null"}, {"Origin": ""},
                        {"Origin": "http://127.0.0.1:1"}, {"Sec-Fetch-Site": "cross-site"},
                        {"Sec-Fetch-Site": "same-site"}):
            self.assertEqual(self.approve(auth, headers=headers)[0], 403)
        server, cookie, csrf = auth
        body = json.dumps(self.payload()).encode()
        # Omit Origin altogether (not merely an empty header).
        raw = (f"POST {APPROVE} HTTP/1.1\r\nHost: {server.authority}\r\nCookie: {cookie}\r\n"
               f"X-SiteProof-CSRF: {csrf}\r\nContent-Type: application/json\r\n"
               f"Content-Length: {len(body)}\r\n\r\n").encode() + body
        self.assertEqual(self.request(server, raw=raw)[0], 403)

    def test_A09_methods_type_size_duplicate_fields_and_actor_injection(self):
        self.add()
        auth = self.authenticated()
        server, cookie, _ = auth
        for method in ("PUT", "PATCH", "DELETE", "OPTIONS"):
            self.assertEqual(self.request(server, APPROVE, cookie=cookie, method=method)[0], 405)
        self.assertEqual(self.approve(auth, headers={"Content-Type": "text/plain"})[0], 400)
        self.assertEqual(self.approve(auth, self.payload(actor="impersonated"))[0], 400)
        for changes in ({"expected_revision": True}, {"expected_current_version": -1},
                        {"reviewed_digest": "x"}, {"candidate_id": ""}):
            self.assertEqual(self.approve(auth, self.payload(**changes))[0], 400)
        header = (f"POST {APPROVE} HTTP/1.1\r\nHost: {server.authority}\r\n"
                  "Content-Length: 8193\r\n\r\n").encode()
        self.assertEqual(self.request(server, raw=header)[0], 400)
        duplicate = b'{"confirmed":true,"confirmed":true}'
        self.assertEqual(self.request(server, APPROVE, method="POST", cookie=cookie,
            headers={"X-SiteProof-CSRF": auth[2]}, body=duplicate)[0], 400)

    def test_A10_transaction_failure_rolls_back_decision_and_version(self):
        self.add()
        auth = self.authenticated()
        original = SQLiteBaselineStore._connect
        def failed_connect(store, readonly):
            conn = original(store, readonly)
            if not readonly:
                conn.set_authorizer(lambda action, table, *args: sqlite3.SQLITE_DENY
                    if action == sqlite3.SQLITE_INSERT and table == "baseline_versions" else sqlite3.SQLITE_OK)
            return conn
        before = self.db.read_bytes()
        with patch.object(SQLiteBaselineStore, "_connect", failed_connect):
            self.assertEqual(self.approve(auth)[0], 503)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(self.store.get("c1").status, BaselineStatus.PENDING)
        self.assertEqual(self.store.history("page-1", "a" * 64), ())

    def test_A11_old_approved_versions_and_decisions_preserved(self):
        old = self.add("old", approve=True)
        self.add("new")
        auth = self.authenticated()
        previous = self.store.history("page-1", "a" * 64)
        self.assertEqual(self.approve(auth, self.payload("new", expected_current_version=1))[0], 200)
        reopened = SQLiteBaselineStore.open(self.db, self.root)
        self.assertEqual(reopened.get("old"), old)
        self.assertEqual(reopened.history("page-1", "a" * 64)[:1], previous)
        self.assertEqual(reopened.current("page-1", "a" * 64).version, 2)

    def test_A12_unattested_unknown_and_get_db_bytes_unchanged(self):
        self.add()
        auth = self.authenticated()
        self.assertEqual(self.approve(auth)[0], 200)
        before = self.db.read_bytes()
        for path in ("/api/baselines", "/api/baselines/c1", "/api/baselines/c1/history"):
            status, _, raw = self.request(auth[0], path, cookie=auth[1])
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(raw)["assessment"], {"profile_trust": "UNATTESTED",
                "profile_reason": "PROFILE_UNATTESTED", "quality": "UNKNOWN", "comparison": "NOT_RUN"})
        self.assertEqual(self.db.read_bytes(), before)

    def test_A13_committed_but_readback_lost_never_success_or_duplicate(self):
        self.add()
        auth = self.authenticated()
        with patch.object(SQLiteBaselineStore, "_readback", side_effect=AmbiguousBaselineCommit("secret")):
            status, _, raw = self.approve(auth)
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(raw), {"error": {"code": "RESULT_UNKNOWN"}})
        self.assertEqual(self.store.get("c1").status, BaselineStatus.APPROVED)
        self.assertEqual(self.approve(auth)[0], 409)
        self.assertEqual(len(self.store.history("page-1", "a" * 64)), 1)

    def test_A14_no_secret_logs_urls_or_untrusted_actor(self):
        malicious = '<img src=x onerror="throw 1">'
        self.add(malicious)
        auth = self.authenticated()
        log = io.StringIO()
        with redirect_stderr(log):
            status, _, raw = self.approve(auth, self.payload(malicious))
        self.assertEqual(status, 200)
        self.assertNotIn(auth[2].encode(), raw)
        self.assertNotIn(auth[2], auth[0].home_url)
        self.assertEqual(log.getvalue(), "")
        for actor in ("system", "", "bot"):
            with self.assertRaises(ValueError):
                LocalBaselineHOME(self.db, self.root, approval_actor=actor)

    def test_A15_original_bff_remains_get_only_and_missing_actor_fails_closed(self):
        self.add()
        auth = self.authenticated(actor=None)
        self.assertIsNone(auth[2])
        before = self.db.read_bytes()
        server = auth[0]
        for path in (APPROVE, SESSION):
            self.assertEqual(fixtures.BFFTests.request(self, server.backend, path)[0], 404)
        self.assertEqual(fixtures.BFFTests.request(self, server.backend, APPROVE, method="POST")[0], 405)
        self.assertEqual(self.approve((server, auth[1], server._csrf))[0], 503)
        self.assertEqual(self.db.read_bytes(), before)

    def test_A10_missing_database_never_created_or_approved(self):
        self.add()
        auth = self.authenticated(db=self.root / "missing.sqlite")
        self.assertEqual(self.approve(auth)[0], 503)
        self.assertFalse((self.root / "missing.sqlite").exists())


if __name__ == "__main__":
    unittest.main()
