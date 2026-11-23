"""Opt-in local HOME gateway. Original Bearer-only BFF remains a separate server.

Trusted caller starts LocalBaselineHOME(fixed_db, storage_root), obtains the plain
local URL and pairing_for_local_user() separately, and shows the latter locally.
The person types the 60-second, single-use code into the pairing form. No CLI,
automatic browser opening, token-in-URL, public token endpoint or stored secret.

The trusted starter may opt in to explicit approval with approval_actor=...;
omitting it preserves view-only access. The gateway alone serves authenticated
GET /api/baselines/_approval/session (same-origin Fetch Metadata + custom header)
and POST /api/baselines/_approval/approve (exact Origin + session-bound CSRF).
The separate Bearer BFF keeps its original three read-only GET APIs. Approval
bodies are bounded by min(max_header_bytes, 16384), pairing bodies by 256 bytes.
An explicitly initialized OfflineWorkspace may be supplied as offline=... on the
same fixed DB/root. Only its fixed M1 routes are enabled; its writes share the
session/Origin/CSRF guard. HTTP requests never initialize or migrate its schema.

Browser gets an independent host-only HttpOnly/SameSite=Strict cookie, limited to
/api/baselines, with random per-launch name and finite Max-Age. Secure is absent
on this numeric HTTP loopback service: this is not TLS or port-isolated cookies.
Exact Host/Origin checks and CSP protect the web boundary; a malicious same-user
process or compromised host is outside the guarantee. Native browser behavior and
cookie compatibility need a separate real-browser check, not an HTTP-test PASS.
"""

from dataclasses import dataclass
from http.client import HTTPResponse
import json
import hmac
from pathlib import Path
import re
import secrets
import socket
import threading
import time

from .baseline import (BaselineBFF, _Handler, _RequestFailure, _Server, _STATUS,
                       _error, _route)
from .approval import LocalApproval
from src.core.offline import OfflineWorkspace
from src.storage.m1 import M1Error


_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
_ASSETS = {"/local/": ("src/bff/ui/index.html", "text/html; charset=utf-8"),
           "/local/baseline.js": ("src/bff/ui/baseline.js", "text/javascript; charset=utf-8"),
           "/local/baseline.css": ("src/bff/ui/baseline.css", "text/css; charset=utf-8"),
           "/local/home.css": ("web/home/styles.css", "text/css; charset=utf-8"),
           "/local/m1.js": ("src/bff/ui/m1.js", "text/javascript; charset=utf-8"),
           "/local/runtime.js": ("src/bff/ui/runtime.js", "text/javascript; charset=utf-8"),
           "/local/comparison.js": ("src/bff/ui/comparison.js", "text/javascript; charset=utf-8"),
           "/local/compare-core.js": ("web/compare/app.js", "text/javascript; charset=utf-8")}
_WORKSPACE_SCRIPT = '/local/workspace.js'
_WORKSPACE_PARTS = ('/local/compare-core.js', '/local/baseline.js', '/local/m1.js',
                    '/local/runtime.js', '/local/comparison.js')
_APPROVAL_SESSION = "/api/baselines/_approval/session"
_APPROVE = "/api/baselines/_approval/approve"
_M1 = "/api/baselines/_m1/"
_M1_ACTIONS = ('site','page','profile','fixture','candidate','compare')
_M4 = '/api/baselines/_m4/'
_M4_ACTIONS = ('candidate', 'compare')
_UI_STATUS = {**_STATUS, 409: "Conflict", 422: "Unprocessable Content"}


@dataclass(frozen=True)
class _Reply:
    content: bytes
    content_type: str
    cookie: str | None = None


@dataclass(frozen=True)
class _EvidencePNG(_Reply):
    """Only M4's confined, verified PNGs; bounded separately from JSON/assets."""


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs)


class _UIHandler(_Handler):
    def _request_with_pairing(self, deadline):
        # Separate parser: the original BFF continues rejecting all request bodies.
        cap, data = self.server.owner.limits.max_header_bytes, bytearray()
        while b"\r\n\r\n" not in data:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _RequestFailure(408, "REQUEST_TIMEOUT")
            self.request.settimeout(remaining)
            chunk = self.request.recv(min(1024, cap + 1 - len(data)))
            if not chunk:
                raise _RequestFailure(400, "INVALID_REQUEST")
            data.extend(chunk)
            if b"\r\n\r\n" not in data and len(data) >= cap:
                raise _RequestFailure(431, "HEADERS_TOO_LARGE")
        end = data.index(b"\r\n\r\n") + 4
        if end > cap:
            raise _RequestFailure(431, "HEADERS_TOO_LARGE")
        try:
            lines = bytes(data[:end - 4]).decode("ascii", "strict").split("\r\n")
            first = lines.pop(0).split(" ")
            if (len(first) != 3 or first[2] != "HTTP/1.1" or not re.fullmatch(r"[A-Z]+", first[0])
                    or not first[1] or any(ord(c) < 33 or ord(c) > 126 for c in first[1]) or len(lines) > 32):
                raise ValueError()
            method, target, _ = first
            headers = {}
            for line in lines:
                key, sep, value = line.partition(":")
                if (not sep or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)
                        or key.lower() in headers or any(ord(c) < 32 or ord(c) > 126 for c in value)):
                    raise ValueError()
                headers[key.lower()] = value.strip(" ")
            if "transfer-encoding" in headers:
                raise ValueError()
            body = bytes(data[end:])
            if method == "POST" and (target in ("/local/pair", _APPROVE) or
                                      target in tuple(_M1 + a for a in _M1_ACTIONS) or
                                      target in tuple(_M4 + a for a in _M4_ACTIONS)):
                value = headers.get("content-length", "")
                body_cap = 256 if target == "/local/pair" else min(cap, 16384)
                if not re.fullmatch(r"[1-9][0-9]{0,4}", value) or int(value) > body_cap:
                    raise ValueError()
                size = int(value)
                if len(body) > size:
                    raise ValueError()
                while len(body) < size:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise _RequestFailure(408, "REQUEST_TIMEOUT")
                    self.request.settimeout(remaining)
                    chunk = self.request.recv(size - len(body))
                    if not chunk:
                        raise ValueError()
                    body += chunk
            elif body or "content-length" in headers:
                raise ValueError()
            return method, target, headers, body
        except (ValueError, UnicodeError):
            raise _RequestFailure(400, "INVALID_REQUEST") from None

    def handle(self):
        owner = self.server.owner
        deadline = self.server.deadlines[self.request]
        try:
            method, target, headers, raw = self._request_with_pairing(deadline)
            if (headers.get("host") != owner.authority or "origin" in headers
                    and headers["origin"] != owner.origin or
                    headers.get("sec-fetch-site") not in (None, "same-origin", "none")):
                raise _RequestFailure(403, "REQUEST_FORBIDDEN")
            if target == "/local/pair":
                if method != "POST":
                    raise _RequestFailure(405, "METHOD_NOT_ALLOWED")
                if (headers.get("origin") != owner.origin or headers.get("content-type") != "application/json"
                        or headers.get("x-siteproof-pair") != "1"):
                    raise _RequestFailure(403, "REQUEST_FORBIDDEN")
                try:
                    obj = _json(raw)
                except (ValueError, UnicodeError):
                    raise _RequestFailure(400, "INVALID_REQUEST") from None
                cookie = owner._pair(obj)
                reply = _Reply(b'{"paired":true}', "application/json", cookie)
            elif (target in _ASSETS or target == _WORKSPACE_SCRIPT) and method == "GET":
                reply = owner._assets[target]
            elif target.startswith(_M1):
                reply = self._m1(method, target, headers, raw)
            elif target.startswith(_M4):
                reply = self._m4(method, target, headers, raw)
            elif target in (_APPROVAL_SESSION, _APPROVE):
                required = "GET" if target == _APPROVAL_SESSION else "POST"
                if method != required:
                    raise _RequestFailure(405, "METHOD_NOT_ALLOWED")
                credential = owner._cookie_credential(headers.get("cookie", ""))
                if not owner._session.accepts(credential):
                    raise _RequestFailure(401, "SESSION_REQUIRED")
                if target == _APPROVAL_SESSION:
                    if (headers.get("x-siteproof-ui") != "1"
                            or headers.get("sec-fetch-site") != "same-origin"):
                        raise _RequestFailure(403, "REQUEST_FORBIDDEN")
                    result = {"approval_enabled": owner._approval.enabled,
                              "workspace_enabled": owner._offline is not None}
                    if owner._approval.enabled or owner._offline is not None:
                        result["csrf_token"] = owner._csrf
                else:
                    self._write_guard(headers)
                    try:
                        obj = _json(raw)
                    except (ValueError, UnicodeError):
                        raise _RequestFailure(400, "INVALID_REQUEST") from None
                    result = owner._approval.approve(obj, owner._session, credential,
                        deadline, owner.limits.max_db_bytes)
                if not owner._session.accepts(credential):
                    raise _RequestFailure(401, "SESSION_REQUIRED")
                self.server.respond(self.request, 200, result, deadline)
                return
            else:
                if method != "GET":
                    raise _RequestFailure(405, "METHOD_NOT_ALLOWED")
                credential = owner._cookie_credential(headers.get("cookie", ""))
                if not owner._session.accepts(credential):
                    raise _RequestFailure(401, "SESSION_REQUIRED")
                try:
                    _route(target)  # Same fixed three GET routes/query limits as BFF.
                except LookupError:
                    raise _RequestFailure(404, "NOT_FOUND") from None
                except (ValueError, UnicodeError):
                    raise _RequestFailure(400, "INVALID_REQUEST") from None
                status, result = owner._forward(target, deadline)
                if not owner._session.accepts(credential):
                    raise _RequestFailure(401, "SESSION_REQUIRED")
                self.server.respond(self.request, status, result, deadline)
                return
            self.server.respond(self.request, 200, reply, deadline)
        except _RequestFailure as exc:
            self.server.respond(self.request, exc.status, _error(exc.code), deadline)
        except (OSError, ValueError, RuntimeError):
            self.server.respond(self.request, 503, _error("DATA_UNAVAILABLE"), deadline)

    def _write_guard(self, headers):
        owner = self.server.owner
        if not owner._session.accepts(owner._cookie_credential(headers.get('cookie',''))):
            raise _RequestFailure(401, 'SESSION_REQUIRED')
        if headers.get('origin') != owner.origin:
            raise _RequestFailure(403, 'REQUEST_FORBIDDEN')
        if headers.get('content-type') != 'application/json':
            raise _RequestFailure(400, 'INVALID_REQUEST')
        csrf = headers.get('x-siteproof-csrf','')
        if (owner._csrf is None or not csrf.isascii() or len(csrf) != len(owner._csrf)
                or not hmac.compare_digest(csrf,owner._csrf)):
            raise _RequestFailure(403,'CSRF_REQUIRED')

    def _m1(self, method, target, headers, raw):
        owner = self.server.owner
        credential = owner._cookie_credential(headers.get('cookie',''))
        if not owner._session.accepts(credential):
            raise _RequestFailure(401,'SESSION_REQUIRED')
        if owner._offline is None:
            raise _RequestFailure(503,'M1_UNAVAILABLE')
        name = target[len(_M1):]
        try:
            if owner._offline.db_path.stat().st_size > owner.limits.max_db_bytes:
                raise M1Error('M1_DATA_UNAVAILABLE',503)
            if method == 'POST' and name in _M1_ACTIONS:
                self._write_guard(headers)
                try:
                    obj = _json(raw)
                except (ValueError,UnicodeError):
                    raise _RequestFailure(400,'INVALID_REQUEST') from None
                reply = owner._offline.action(name,obj)
            elif method == 'GET' and name == 'state':
                reply = owner._offline.state()
            elif method == 'GET' and name == 'runtime':
                if owner._runtime is None:
                    raise _RequestFailure(503, 'RUNTIME_UNAVAILABLE')
                reply = owner._runtime.state()
            elif method == 'GET' and re.fullmatch(r'(result|image|diff)/[a-f0-9]{32}',name):
                kind, key = name.split('/')
                if kind == 'result':
                    reply = owner._offline.result(key)
                else:
                    data = owner._offline.image(key) if kind == 'image' else owner._offline.diff_image(key)
                    reply = _Reply(data,'image/png')
            else:
                raise _RequestFailure(405 if method != 'GET' or name in _M1_ACTIONS else 404,
                                      'METHOD_NOT_ALLOWED' if method != 'GET' or name in _M1_ACTIONS else 'NOT_FOUND')
            if not owner._session.accepts(credential):
                raise _RequestFailure(401,'SESSION_REQUIRED')
            return reply
        except M1Error as exc:
            raise _RequestFailure(exc.status,exc.code) from None

    def _m4(self, method, target, headers, raw):
        owner = self.server.owner
        credential = owner._cookie_credential(headers.get('cookie', ''))
        if not owner._session.accepts(credential):
            raise _RequestFailure(401, 'SESSION_REQUIRED')
        if owner._comparison is None:
            raise _RequestFailure(503, 'COMPARISON_UNAVAILABLE')
        if owner._db_path.stat().st_size > owner.limits.max_db_bytes:
            raise _RequestFailure(503, 'DATA_UNAVAILABLE')
        name = target[len(_M4):]
        try:
            if method == 'POST' and name in _M4_ACTIONS:
                self._write_guard(headers)
                reply = owner._comparison.action(name, _json(raw))
            elif method == 'GET' and name == 'state':
                reply = owner._comparison.state()
            elif method == 'GET' and re.fullmatch(r'history/(0|[1-9][0-9]{0,4})', name):
                reply = owner._comparison.history(int(name.split('/')[1]))
            elif method == 'GET' and re.fullmatch(r'image/[a-f0-9]{32}', name):
                reply = _EvidencePNG(owner._comparison.image(name.split('/')[1]), 'image/png')
            elif method == 'GET' and re.fullmatch(r'result/[a-f0-9]{32}(/(baseline|current|diff))?', name):
                parts = name.split('/')
                reply = (owner._comparison.result(parts[1]) if len(parts) == 2 else
                         _EvidencePNG(owner._comparison.result_image(parts[1], parts[2]), 'image/png'))
            else:
                raise _RequestFailure(405 if method != 'GET' else 404,
                                      'METHOD_NOT_ALLOWED' if method != 'GET' else 'NOT_FOUND')
            if not owner._session.accepts(credential):
                raise _RequestFailure(401, 'SESSION_REQUIRED')
            return reply
        except M1Error as exc:
            raise _RequestFailure(exc.status, exc.code) from None
        except (ValueError, TypeError, KeyError):
            raise _RequestFailure(400, 'INVALID_REQUEST') from None


class _UIServer(_Server):
    def finish_request(self, request, client_address):
        _UIHandler(request, client_address, self)

    def respond(self, client, status, body, deadline):
        reply = body if isinstance(body, _Reply) else _Reply(
            json.dumps(body, ensure_ascii=True, separators=(",", ":")).encode(), "application/json")
        # New evidence-image route uses the same 32 MiB bound as the S1 confined
        # PNG reader. Existing JSON/static/M1 response bounds stay unchanged.
        response_limit = 32 * 1024 * 1024 if type(reply) is _EvidencePNG else self.owner.limits.max_response_bytes
        if len(reply.content) > response_limit:
            status, reply = 503, _Reply(b'{"error":{"code":"RESPONSE_LIMIT"}}', "application/json")
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            client.settimeout(remaining)
            header = (f"HTTP/1.1 {status} {_UI_STATUS[status]}\r\nContent-Type: {reply.content_type}\r\n"
                      "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
                      "X-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\n"
                      f"Content-Security-Policy: {_CSP}\r\nConnection: close\r\n"
                      f"Content-Length: {len(reply.content)}\r\n")
            if reply.cookie is not None:
                header += "Set-Cookie: " + reply.cookie + "\r\n"
            client.sendall((header + "\r\n").encode("ascii"))
            data = memoryview(reply.content)
            for start in range(0, len(data), 65536):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                client.settimeout(remaining)
                client.sendall(data[start:start + 65536])
        except (OSError, ValueError):
            pass


class LocalBaselineHOME(BaselineBFF):
    """Explicit opt-in gateway; public web/home files are never edited or served with secrets."""

    def __init__(self, db_path, storage_root, *, limits=None, pairing_seconds=60,
                 approval_actor=None, offline=None, runtime=None):
        super().__init__(db_path, storage_root, limits=limits)
        if type(pairing_seconds) not in (int, float) or not 0 < pairing_seconds <= 60:
            raise ValueError("pairing lifetime must be positive and at most 60 seconds")
        self.backend = BaselineBFF(db_path, storage_root, limits=self.limits)
        # Identity comes ONLY from the trusted starter, never HTTP or the cookie.
        # No configured operator means the previous read-only behavior is retained.
        self._approval = LocalApproval(self._db_path, self._root, approval_actor)
        if offline is not None and (type(offline) is not OfflineWorkspace
                or offline.db_path != self._db_path or offline.storage_root != self._root):
            raise ValueError('M1 workspace must use the fixed local database')
        self._offline = offline
        if runtime is not None:
            from src.runtime.service import RuntimeService
            if type(runtime) is not RuntimeService or runtime.workspace is not offline:
                raise ValueError('runtime must use the explicitly supplied M1 workspace')
        self._runtime = runtime
        self._comparison = runtime.comparison if runtime else None
        if self._comparison:
            self._approval._candidate_validator = self._comparison.validate_candidate
        self._csrf = secrets.token_urlsafe(32)
        self._pair_lock = threading.Lock()
        self._pair_code = secrets.token_urlsafe(24)
        self._pair_deadline = time.monotonic() + pairing_seconds
        self._pair_attempts = 0
        self.cookie_name = "spui_" + secrets.token_hex(12)
        root = Path(__file__).resolve().parents[2]
        self._assets = {}
        for route, (name, mime) in _ASSETS.items():
            with (root / name).open("rb") as handle:
                raw = handle.read(self.limits.max_response_bytes + 1)
            if len(raw) > self.limits.max_response_bytes:
                raise ValueError("local asset size limit")
            self._assets[route] = _Reply(raw, mime)
        # One ordered static response avoids five parallel script fetches
        # exhausting the unchanged four-connection BFF bound during HOME load.
        script = b'\n;\n'.join(self._assets[path].content for path in _WORKSPACE_PARTS)
        if len(script) > self.limits.max_response_bytes:
            raise ValueError('local workspace script size limit')
        self._assets[_WORKSPACE_SCRIPT] = _Reply(script, 'text/javascript; charset=utf-8')

    def _make_server(self):
        return _UIServer(self)

    def start(self):
        self.backend.start()
        try:
            address = super().start()
            self.home_url = self.origin + "/local/"
            return address
        except BaseException:
            self.backend.stop()
            raise

    def pairing_for_local_user(self):
        with self._pair_lock:
            if self._pair_code is None or time.monotonic() >= self._pair_deadline:
                raise ValueError("pairing unavailable")
            return self._pair_code

    def renew_pairing_for_local_user(self):
        """Trusted starter only; revoke an UNUSED code, issue a new 60s code.

        No HTTP route. A consumed pairing cannot be renewed, and session expiry
        is never extended. Useful when isolated preflight consumed startup time.
        """
        with self._pair_lock:
            if self._pair_code is None or not self._session.accepts('Bearer '+self._session.local_token()):
                raise ValueError('unused active pairing required')
            self._pair_code=secrets.token_urlsafe(24)
            self._pair_deadline=time.monotonic()+60
            self._pair_attempts=0
            return self._pair_code

    def _pair(self, obj):
        import hmac
        with self._pair_lock:
            if (self._pair_code is None or time.monotonic() >= self._pair_deadline
                    or self._pair_attempts >= 5):
                raise _RequestFailure(401, "SESSION_REQUIRED")
            self._pair_attempts += 1
            if (type(obj) is not dict or set(obj) != {"pairing_code"}
                    or type(obj["pairing_code"]) is not str
                    or not re.fullmatch(r"[A-Za-z0-9_-]{32}", obj["pairing_code"])
                    or not hmac.compare_digest(obj["pairing_code"], self._pair_code)):
                raise _RequestFailure(401, "SESSION_REQUIRED")
            token = self._session.local_token()
            if not self._session.accepts("Bearer " + token):
                raise _RequestFailure(401, "SESSION_REQUIRED")
            self._pair_code = None  # Consumed under lock before any HTTP reply.
            seconds = max(0, int(self._session._expires - time.monotonic()))
            return (f"{self.cookie_name}={token}; HttpOnly; SameSite=Strict; "
                    f"Path=/api/baselines; Max-Age={seconds}")

    def _cookie_credential(self, raw):
        values = []
        for part in raw.split(";"):
            key, sep, value = part.strip().partition("=")
            if sep and key == self.cookie_name:
                values.append(value)
        return "Bearer " + values[0] if len(values) == 1 else None

    def _forward(self, target, deadline):
        # Numeric loopback socket; no getaddrinfo, proxy environment or redirects.
        token = self.backend.token_for_local_client()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            sock.settimeout(remaining)
            sock.connect(self.backend.address)
            request = (f"GET {target} HTTP/1.1\r\nHost: {self.backend.authority}\r\n"
                       f"Origin: {self.backend.origin}\r\nSec-Fetch-Site: same-origin\r\n"
                       f"Authorization: Bearer {token}\r\nConnection: close\r\n\r\n")
            sock.sendall(request.encode("ascii"))
            response = HTTPResponse(sock)
            try:
                response.begin()
                raw = response.read(self.limits.max_response_bytes + 1)
                if (len(raw) > self.limits.max_response_bytes or
                        response.getheader("Content-Type") != "application/json"):
                    raise ValueError("upstream response")
                result = _json(raw)
                if type(result) is not dict or response.status not in _STATUS:
                    raise ValueError("upstream response")
                return response.status, result
            finally:
                response.close()

    def destroy_session(self):
        with self._pair_lock:
            self._pair_code = None
            self._csrf = None
        super().destroy_session()

    def stop(self):
        frontend = super().stop()
        backend = self.backend.stop()
        return frontend and backend
