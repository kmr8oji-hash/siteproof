"""Pairing/cookie gateway checks; reuse the existing loopback/temporary-DB guard."""

from contextlib import closing, redirect_stderr
from http.client import HTTPResponse
import io
import json
import socket
import time
import unittest

from src.bff.local_ui import LocalBaselineHOME
from tests.bff import test_baseline as fixtures


class LocalUITests(unittest.TestCase):
    setUp = fixtures.BFFTests.setUp
    _remove_temp = fixtures.BFFTests._remove_temp
    add = fixtures.BFFTests.add
    socket = fixtures.BFFTests.socket

    def _stop_servers(self):
        fixtures.BFFTests._stop_servers(self)
        for server in self.servers:
            self.assertEqual(server.backend._server.socket.fileno(), -1)
            self.assertFalse(any(t.is_alive() for t in server.backend._server.workers))

    def server(self, *, db=None, **kwargs):
        server = LocalBaselineHOME(db or self.db, self.root, **kwargs)
        server.start()
        self.servers.append(server)
        return server

    def request(self, server, path="/api/baselines", *, method="GET", cookie=None,
                headers=None, body=None, raw=None):
        fields = {"Host": server.authority}
        if cookie:
            fields["Cookie"] = cookie
        if body is not None:
            fields.update({"Origin": server.origin, "Content-Type": "application/json",
                           "Sec-Fetch-Site": "same-origin", "X-SiteProof-Pair": "1",
                           "Content-Length": str(len(body))})
        fields.update(headers or {})
        packet = raw or ((method + " " + path + " HTTP/1.1\r\n" +
                          "".join(k + ": " + v + "\r\n" for k, v in fields.items()) +
                          "\r\n").encode() + (body or b""))
        client = self.socket(server)
        try:
            client.sendall(packet)
            with closing(HTTPResponse(client)) as response:
                response.begin()
                data = response.read()
                fields = dict(response.getheaders())
                self.assertEqual(fields["Cache-Control"], "no-store")
                self.assertEqual(fields["X-Content-Type-Options"], "nosniff")
                self.assertEqual(fields["X-Frame-Options"], "DENY")
                self.assertIn("frame-ancestors 'none'", fields["Content-Security-Policy"])
                self.assertNotIn("Access-Control-Allow-Origin", fields)
                self.assertNotIn(server.backend.token_for_local_client().encode(), data)
                self.assertNotIn(server.backend.token_for_local_client(), str(fields))
                return response.status, fields, data
        finally:
            client.close()

    def pair(self, server):
        code = server.pairing_for_local_user()
        raw = json.dumps({"pairing_code": code}).encode()
        status, headers, data = self.request(server, "/local/pair", method="POST", body=raw)
        self.assertEqual((status, json.loads(data)), (200, {"paired": True}))
        cookie = headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn("Path=/api/baselines", cookie)
        self.assertIn("Max-Age=", cookie)
        self.assertNotIn("Domain=", cookie)
        self.assertNotIn(code, str(headers) + data.decode())
        self.assertNotIn(code, server.home_url)
        return cookie.split(";", 1)[0], raw

    def test_manual_pair_then_real_store_list_detail_and_history_without_db_write(self):
        self.add("old", approve=True)
        self.add("new", approve=True, current=1)
        before = self.db.read_bytes()
        server = self.server()
        self.assertEqual(self.request(server)[0], 401)
        cookie, _ = self.pair(server)
        for path in ("/api/baselines", "/api/baselines/old", "/api/baselines/old/history"):
            status, _, raw = self.request(server, path, cookie=cookie)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(raw)["assessment"]["quality"], "UNKNOWN")
        _, _, raw = self.request(server, "/api/baselines/old/history", cookie=cookie)
        self.assertEqual([v["is_current"] for v in json.loads(raw)["versions"]], [False, True])
        self.assertEqual(self.db.read_bytes(), before)

    def test_pairing_is_single_use_and_not_available_via_get_or_url(self):
        server = self.server()
        cookie, raw = self.pair(server)
        self.assertEqual(self.request(server, "/local/pair", method="POST", body=raw)[0], 401)
        self.assertEqual(self.request(server, "/local/pair")[0], 405)
        self.assertEqual(self.request(server, "/local/pair?pairing_code=secret")[0], 401)
        with self.assertRaises(ValueError):
            server.pairing_for_local_user()
        self.assertEqual(self.request(server, cookie=cookie)[0], 200)

    def test_expired_pairing_wrong_code_and_failed_attempt_limit(self):
        server = self.server()
        wrong = json.dumps({"pairing_code": "x" * 32}).encode()
        for _ in range(5):
            self.assertEqual(self.request(server, "/local/pair", method="POST", body=wrong)[0], 401)
        correct = json.dumps({"pairing_code": server.pairing_for_local_user()}).encode()
        self.assertEqual(self.request(server, "/local/pair", method="POST", body=correct)[0], 401)
        other = self.server()
        correct = json.dumps({"pairing_code": other.pairing_for_local_user()}).encode()
        other._pair_deadline = time.monotonic() - 1
        self.assertEqual(self.request(other, "/local/pair", method="POST", body=correct)[0], 401)

    def test_pairing_requires_exact_origin_json_and_custom_header(self):
        server = self.server()
        raw = json.dumps({"pairing_code": server.pairing_for_local_user()}).encode()
        for headers in ({"Origin": "null"}, {"Origin": "http://evil.invalid"},
                        {"Origin": ""}, {"Content-Type": "application/x-www-form-urlencoded"},
                        {"X-SiteProof-Pair": ""}, {"Sec-Fetch-Site": "cross-site"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request(server, "/local/pair", method="POST", headers=headers, body=raw)[0], 403)
        self.pair(server)

    def test_invalid_expired_destroyed_cookie_and_backend_bearer_refused(self):
        server = self.server()
        cookie, _ = self.pair(server)
        self.assertEqual(self.request(server, cookie=server.cookie_name + "=wrong")[0], 401)
        self.assertEqual(self.request(server, cookie=cookie + "; " + cookie)[0], 401)
        self.assertEqual(self.request(server, headers={"Authorization": "Bearer " + server.backend.token_for_local_client()})[0], 401)
        self.assertEqual(fixtures.BFFTests.request(self, server.backend, authorized=False,
                                                headers={"Cookie": cookie})[0], 401)
        server._session._expires = time.monotonic() - 1
        self.assertEqual(self.request(server, cookie=cookie)[0], 401)
        server.destroy_session()
        self.assertEqual(self.request(server, cookie=cookie)[0], 401)

    def test_cookie_does_not_bypass_host_origin_or_cross_site(self):
        server = self.server()
        cookie, _ = self.pair(server)
        for headers in ({"Host": "localhost:" + str(server.address[1])},
                        {"Host": "evil.invalid"}, {"Origin": "null"},
                        {"Origin": "http://127.0.0.1:1"}, {"Sec-Fetch-Site": "cross-site"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request(server, cookie=cookie, headers=headers)[0], 403)
        self.assertEqual(self.request(server, cookie=cookie)[0], 200)

    def test_fixed_static_assets_no_secret_and_no_arbitrary_files_or_writes(self):
        server = self.server()
        for path in ("/local/", "/local/baseline.js", "/local/baseline.css", "/local/home.css"):
            status, _, raw = self.request(server, path)
            self.assertEqual(status, 200)
            self.assertNotIn(server.pairing_for_local_user().encode(), raw)
        cookie, _ = self.pair(server)
        for path, expected in (("/local/../../README.md", 404), ("/local/?token=x", 400),
                               ("/local/unknown.js", 404)):
            self.assertEqual(self.request(server, path, cookie=cookie)[0], expected)
        for method in ("POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            self.assertEqual(self.request(server, cookie=cookie, method=method)[0], 405)

    def test_home_uses_one_ordered_bounded_workspace_script(self):
        from src.bff.local_ui import _WORKSPACE_PARTS
        server = self.server()
        status, _, html = self.request(server, '/local/')
        self.assertEqual(status, 200)
        self.assertEqual(html.count(b'<script '), 1)
        self.assertIn(b'src="/local/workspace.js" defer', html)
        status, headers, script = self.request(server, '/local/workspace.js')
        self.assertEqual(status, 200)
        self.assertEqual(headers['Content-Type'], 'text/javascript; charset=utf-8')
        self.assertEqual(script, b'\n;\n'.join(server._assets[p].content for p in _WORKSPACE_PARTS))
        self.assertLessEqual(len(script), server.limits.max_response_bytes)
        self.assertEqual(server.limits.max_connections, 4)

    def test_body_limits_duplicate_json_and_smuggling_refused(self):
        server = self.server()
        code = server.pairing_for_local_user()
        duplicate = ('{"pairing_code":"' + code + '","pairing_code":"' + code + '"}').encode()
        self.assertEqual(self.request(server, "/local/pair", method="POST", body=duplicate)[0], 400)
        self.assertEqual(self.request(server, "/local/pair", method="POST", body=b"x" * 257)[0], 400)
        self.assertEqual(self.request(server, "/local/pair", method="POST", body=b"{}",
                                     headers={"Transfer-Encoding": "chunked"})[0], 400)
        self.pair(server)

    def test_missing_database_is_not_empty_and_bearer_never_logged(self):
        missing = self.root / "missing.sqlite"
        server = self.server(db=missing)
        errors = io.StringIO()
        with redirect_stderr(errors):
            cookie, _ = self.pair(server)
            status, _, raw = self.request(server, cookie=cookie)
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(raw), {"error": {"code": "DATA_UNAVAILABLE"}})
        self.assertFalse(missing.exists())
        self.assertEqual(errors.getvalue(), "")

    def test_both_listeners_released_on_stop(self):
        server = self.server()
        self.pair(server)
        addresses = server.address, server.backend.address
        self.assertTrue(server.stop())
        for address in addresses:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(.1)
                with self.assertRaises(OSError):
                    sock.connect(address)


if __name__ == "__main__":
    unittest.main()
