"""Baseline-only loopback JSON API. Explicit lifecycle; no CLI or static hosting.

Routes: GET /api/baselines, /{id}, /{id}/history. List/history accept only
limit (1..100) and offset (0..10000), with 25 items by default. A request sees
one read-only SQLite snapshot. No cross-request paging snapshot is promised.

Authorization: Bearer <token>, handed ONLY to a trusted same-process caller via
token_for_local_client(). There is no HTTP token distribution or UI bootstrap.
Tokens expire and may be explicitly destroyed. No access/error logging is done.

Limits default to 8 KiB headers, 1 s/request, 4 workers, 256 KiB response and
64 MiB fixed local DB. These bound this small local API, not host CPU/OS isolation.
SQLite progress/deadline checks cannot interrupt arbitrary OS/filesystem stalls;
stop() reports whether listener/workers actually ended instead of claiming success.
"""

from dataclasses import dataclass
import hmac
import json
import math
from pathlib import Path
import re
import secrets
import socket
import socketserver
import threading
import time
from urllib.parse import parse_qsl, unquote_to_bytes, urlsplit

from src.baseline.approval import UnknownCandidate
from src.baseline.sqlite_store import SQLiteBaselineStore


@dataclass(frozen=True)
class BFFLimits:
    max_header_bytes: int = 8192
    request_timeout_seconds: float = 1.0
    max_connections: int = 4
    max_response_bytes: int = 256 * 1024
    max_db_bytes: int = 64 * 1024 * 1024
    session_seconds: float = 300.0
    poll_seconds: float = .01
    shutdown_seconds: float = 2.0

    def __post_init__(self):
        for n in (self.max_header_bytes, self.max_connections, self.max_response_bytes, self.max_db_bytes):
            if type(n) is not int or n <= 0:
                raise ValueError("positive BFF size/count limits required")
        for n in (self.request_timeout_seconds, self.session_seconds, self.poll_seconds, self.shutdown_seconds):
            if type(n) not in (int, float) or not math.isfinite(n) or n <= 0:
                raise ValueError("positive finite BFF time limits required")
        if self.max_response_bytes < 64 or self.poll_seconds > min(
                self.request_timeout_seconds, self.shutdown_seconds):
            raise ValueError("response error space and bounded polling required")


class _Session:
    def __init__(self, seconds):
        self._lock = threading.Lock()
        self._token = secrets.token_urlsafe(32)
        self._expires = time.monotonic() + seconds

    def local_token(self):
        with self._lock:
            if self._token is None:
                raise ValueError("session destroyed")
            return self._token

    def accepts(self, authorization):
        with self._lock:
            if self._token is None or time.monotonic() >= self._expires:
                return False
            if type(authorization) is not str or not authorization.startswith("Bearer "):
                return False
            supplied = authorization[7:]
            if not supplied.isascii() or len(supplied) != len(self._token):
                return False
            return hmac.compare_digest(supplied, self._token)

    def destroy(self):
        with self._lock:
            self._token = None


_ASSESSMENT = {"profile_trust": "UNATTESTED", "profile_reason": "PROFILE_UNATTESTED",
               "quality": "UNKNOWN", "comparison": "NOT_RUN"}
_STATUS = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
           404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout",
           413: "Content Too Large", 431: "Request Header Fields Too Large",
           503: "Service Unavailable"}


def _error(code):
    return {"error": {"code": code}}


def _artifact_ref(value):
    # References are text, never links or files to open. Hide absolute paths,
    # URIs, Windows names and traversal; retain a safe relative artifact reference.
    if (not re.fullmatch(r"[A-Za-z0-9._/-]{1,2048}", value) or value.startswith("/")
            or any(p in ("", ".", "..") for p in value.split("/"))):
        return None
    return value


def _record(record, *, candidate_version, current_version, current_candidate_id):
    c, decision = record.candidate, record.decision
    ref = _artifact_ref(c.artifact_ref)
    return {
        "candidate_id": c.candidate_id, "page_id": c.page_id,
        "profile_fingerprint": c.profile_fingerprint,
        "artifact_ref": ref, "artifact_ref_redacted": ref is None,
        "artifact_sha256": c.artifact_sha256, "candidate_digest": record.registered_digest,
        "revision": record.revision, "approval_state": record.status.value,
        "approval": None if decision is None else {
            "actor": decision.actor, "reviewed_digest": decision.candidate_digest,
            "revision": decision.revision, "state": decision.status.value},
        "candidate_version": candidate_version,
        "current": None if current_version is None else {
            "version": current_version, "candidate_id": current_candidate_id},
        "is_current": c.candidate_id == current_candidate_id,
        "has_history": current_version is not None,
    }


def _route(target):
    if not target.startswith("/") or len(target) > 4096:
        raise ValueError("target")
    url = urlsplit(target)
    if url.scheme or url.netloc or url.fragment:
        raise ValueError("target")
    params = parse_qsl(url.query, keep_blank_values=True, strict_parsing=True,
                       max_num_fields=2)
    options = dict(params)
    if len(options) != len(params) or set(options) - {"limit", "offset"}:
        raise ValueError("query")
    for value in options.values():
        if not re.fullmatch(r"0|[1-9][0-9]{0,4}", value):
            raise ValueError("page")
    limit, offset = int(options.get("limit", "25")), int(options.get("offset", "0"))
    if not 1 <= limit <= 100 or not 0 <= offset <= 10000:
        raise ValueError("page")
    if url.path == "/api/baselines":
        return None, False, limit, offset
    parts = url.path.split("/")
    if (len(parts) not in (4, 5) or parts[:3] != ["", "api", "baselines"]
            or not parts[3] or len(parts) == 5 and parts[4] != "history"):
        raise LookupError("route")
    if re.search(r"%(?![0-9a-fA-F]{2})", parts[3]):
        raise ValueError("encoding")
    cid = unquote_to_bytes(parts[3]).decode("utf-8", "strict")
    if len(cid) > 2048 or not cid or cid != cid.strip() or any(ord(c) < 32 or ord(c) == 127 for c in cid):
        raise ValueError("id")
    history = len(parts) == 5
    if not history and params:
        raise ValueError("detail has no paging")
    return cid, history, limit, offset


class _RequestFailure(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


class _Handler(socketserver.BaseRequestHandler):
    def _request(self, deadline):
        data = bytearray()
        cap = self.server.owner.limits.max_header_bytes
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _RequestFailure(408, "REQUEST_TIMEOUT")
            self.request.settimeout(remaining)
            chunk = self.request.recv(min(1024, cap - len(data) + 1))
            if not chunk:
                raise _RequestFailure(400, "INVALID_REQUEST")
            data.extend(chunk)
            if len(data) > cap:
                raise _RequestFailure(431, "HEADERS_TOO_LARGE")
            end = data.find(b"\r\n\r\n")
            if end >= 0:
                if end + 4 != len(data):
                    raise _RequestFailure(400, "INVALID_REQUEST")
                break
        try:
            lines = bytes(data[:-4]).decode("ascii", "strict").split("\r\n")
            first = lines.pop(0).split(" ")
            if len(first) != 3 or first[2] != "HTTP/1.1":
                raise ValueError()
            method, target, _ = first
            if not re.fullmatch(r"[A-Z]+", method) or any(ord(c) < 33 or ord(c) > 126 for c in target):
                raise ValueError()
            headers = {}
            if len(lines) > 32:
                raise ValueError()
            for line in lines:
                key, colon, value = line.partition(":")
                if not colon or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
                    raise ValueError()
                key = key.lower()
                if key in headers or any(ord(c) < 32 or ord(c) > 126 for c in value):
                    raise ValueError()
                headers[key] = value.strip(" ")
            if "content-length" in headers or "transfer-encoding" in headers:
                raise ValueError()
            return method, target, headers
        except (ValueError, UnicodeError):
            raise _RequestFailure(400, "INVALID_REQUEST") from None

    def handle(self):
        owner = self.server.owner
        deadline = self.server.deadlines[self.request]
        authorization = None
        try:
            method, target, headers = self._request(deadline)
            if headers.get("host") != owner.authority:
                raise _RequestFailure(403, "REQUEST_FORBIDDEN")
            if "origin" in headers and headers["origin"] != owner.origin:
                raise _RequestFailure(403, "REQUEST_FORBIDDEN")
            if headers.get("sec-fetch-site") not in (None, "same-origin", "none"):
                raise _RequestFailure(403, "REQUEST_FORBIDDEN")
            authorization = headers.get("authorization")
            if not owner._session.accepts(authorization):
                raise _RequestFailure(401, "SESSION_REQUIRED")
            if method != "GET":
                raise _RequestFailure(405, "METHOD_NOT_ALLOWED")
            try:
                route = _route(target)
            except LookupError:
                raise _RequestFailure(404, "NOT_FOUND") from None
            except (ValueError, UnicodeError):
                raise _RequestFailure(400, "INVALID_REQUEST") from None
            status, body = 200, owner._query(route, deadline)
            if not owner._session.accepts(authorization):
                raise _RequestFailure(401, "SESSION_REQUIRED")
        except _RequestFailure as exc:
            status, body = exc.status, _error(exc.code)
        except UnknownCandidate:
            status, body = 404, _error("NOT_FOUND")
        except (TimeoutError, socket.timeout):
            status, body = 408, _error("REQUEST_TIMEOUT")
        except Exception:
            status, body = 503, _error("DATA_UNAVAILABLE")
        self.server.respond(self.request, status, body, deadline)


class _Server(socketserver.TCPServer):
    # TCPServer avoids HTTPServer's getfqdn/server-name resolution.
    address_family = socket.AF_INET
    allow_reuse_address = False

    def __init__(self, owner):
        self.owner = owner
        self.request_queue_size = owner.limits.max_connections
        self.lock = threading.Lock()
        self.workers, self.clients, self.deadlines = set(), set(), {}
        self.closing = threading.Event()
        self.slots = threading.BoundedSemaphore(owner.limits.max_connections)
        super().__init__(("127.0.0.1", 0), _Handler)

    def handle_error(self, request, client_address):
        pass  # Never print exceptions, request targets, paths or credentials.

    def respond(self, client, status, body, deadline):
        try:
            raw = json.dumps(body, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            if len(raw) > self.owner.limits.max_response_bytes:
                status, raw = 503, b'{"error":{"code":"RESPONSE_LIMIT"}}'
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return  # No late data, even if storage returned after the deadline.
            client.settimeout(remaining)
            header = (f"HTTP/1.1 {status} {_STATUS[status]}\r\n"
                      "Content-Type: application/json\r\nCache-Control: no-store\r\n"
                      "X-Content-Type-Options: nosniff\r\nConnection: close\r\n"
                      f"Content-Length: {len(raw)}\r\n\r\n").encode("ascii")
            client.sendall(header + raw)
        except (OSError, ValueError):
            pass

    def process_request(self, request, client_address):
        deadline = time.monotonic() + self.owner.limits.request_timeout_seconds
        if self.closing.is_set() or not self.slots.acquire(blocking=False):
            self.respond(request, 503, _error("BUSY"), min(deadline, time.monotonic() + .05))
            self.shutdown_request(request)
            return
        def run():
            try:
                self.finish_request(request, client_address)
            except Exception:
                self.respond(request, 503, _error("DATA_UNAVAILABLE"), deadline)
            finally:
                self.shutdown_request(request)
                with self.lock:
                    self.clients.discard(request)
                    self.deadlines.pop(request, None)
                self.slots.release()
        with self.lock:
            self.workers = {t for t in self.workers if t.is_alive()}
            worker = threading.Thread(target=run, name="siteproof-baseline-bff-request")
            self.workers.add(worker)
            self.clients.add(request)
            self.deadlines[request] = deadline
            try:
                worker.start()
            except BaseException:
                self.workers.discard(worker)
                self.clients.discard(request)
                self.deadlines.pop(request, None)
                self.slots.release()
                self.shutdown_request(request)
                raise


class BaselineBFF:
    """Caller supplies a fixed local DB; no request can replace it.

    Stored approval is a human decision, not quality PASS. Artifact references
    are never followed. Approval timestamps are absent because the model has none.
    The assessment fields are fixed trust-boundary labels, not new DB facts.
    """

    def __init__(self, db_path, storage_root, *, limits=None):
        self._db_path, self._root = Path(db_path), Path(storage_root)
        self.limits = BFFLimits() if limits is None else limits
        if type(self.limits) is not BFFLimits:
            raise ValueError("BFFLimits required")
        if (not self._db_path.is_absolute() or not self._root.is_absolute()
                or self._db_path.drive.startswith("\\\\") or self._root.drive.startswith("\\\\")
                or ".." in self._db_path.parts or ".." in self._root.parts):
            raise ValueError("fixed local absolute database paths required")
        self._session = _Session(self.limits.session_seconds)
        self._server = self._thread = None
        self._started = False

    def token_for_local_client(self):
        return self._session.local_token()

    def destroy_session(self):
        self._session.destroy()

    def _make_server(self):
        return _Server(self)

    def start(self):
        if self._started:
            raise ValueError("single-use BFF")
        self._started = True
        self._server = self._make_server()
        self.address = self._server.server_address
        self.authority = f"127.0.0.1:{self.address[1]}"
        self.origin = "http://" + self.authority
        self._thread = threading.Thread(target=self._server.serve_forever,
            kwargs={"poll_interval": self.limits.poll_seconds}, name="siteproof-baseline-bff")
        try:
            self._thread.start()
        except BaseException:
            self._server.server_close()
            self._server = self._thread = None
            raise
        return self.address

    def _query(self, route, deadline):
        cid, history, limit, offset = route
        # Constructor pins the existing file; read_page audits it through mode=ro.
        store = SQLiteBaselineStore(self._db_path, self._root)
        if store.path.stat().st_size > self.limits.max_db_bytes:
            raise ValueError("DB read limit")
        page = store.read_page(limit=limit, offset=offset, candidate_id=cid,
                               history=history, deadline=deadline)
        items = [_record(i.record, candidate_version=i.candidate_version,
                         current_version=i.current_version, current_candidate_id=i.current_candidate_id)
                 for i in page.items]
        envelope = {"assessment": dict(_ASSESSMENT)}
        if cid is None:
            return {**envelope, "items": items, "next_offset": offset + len(items) if page.has_more else None}
        if not history:
            return {**envelope, "baseline": items[0]}
        selected = page.items[0]
        versions = [{"version": v.version, "is_current": v.version == selected.current_version,
                     "baseline": _record(v.record, candidate_version=v.version,
                         current_version=selected.current_version, current_candidate_id=selected.current_candidate_id)}
                    for v in page.versions]
        return {**envelope, "baseline": items[0], "versions": versions,
                "next_offset": offset + len(versions) if page.has_more else None}

    def stop(self):
        self.destroy_session()
        if self._server is None:
            return True
        server = self._server
        deadline = time.monotonic() + self.limits.shutdown_seconds
        server.closing.set()
        server.shutdown()
        server.server_close()
        with server.lock:
            workers, clients = tuple(server.workers), tuple(server.clients)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self._thread.join(max(0, deadline - time.monotonic()))
        for worker in workers:
            worker.join(max(0, deadline - time.monotonic()))
        return not self._thread.is_alive() and not any(t.is_alive() for t in workers)
