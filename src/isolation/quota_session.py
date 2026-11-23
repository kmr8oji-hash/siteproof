"""Offline Job owner for admission, bounded synchronous fake I/O and cleanup.

Injected adapters are trusted. No transport, timer or automatic retry exists.
All state/accounting uses the budget lock; adapter calls never hold that lock.
"""

from dataclasses import dataclass

from .budget import BudgetDecision, NetworkBudget
from .connector import ConnectorResult, connect_pinned
from .connect_dns import ConnectDnsResult, open_connect_target
from .termination import TerminationLimits, TerminationSnapshot


@dataclass(frozen=True)
class IoLimits:
    max_chunk_bytes: int
    max_buffer_bytes: int

    def __post_init__(self):
        if any(type(n) is not int or n <= 0 for n in
               (self.max_chunk_bytes, self.max_buffer_bytes)):
            raise ValueError("explicit positive integer I/O limits required")


class IoWouldBlock(Exception):
    """Trusted adapter asserts this operation made exactly zero progress."""


class _AdmissionDenied(Exception):
    pass


class _CloseUnconfirmed(Exception):
    pass


class _ConnectorHandle:
    """Observe connector-owned close without changing the connector contract.

    This exact facade is returned by the admitted dialer to the connector. The
    connector transfers that same facade on success; the session owns its raw
    resource. Non-None close returns cannot certify resource release.
    """

    def __init__(self, owner, record):
        self._owner, self._record = owner, record

    def getpeername(self):
        return self._record.handle.getpeername()

    @property
    def close(self):
        # Mirror the raw descriptor/callability at the point where the existing
        # connector checks it. Missing/broken methods keep their own diagnostics.
        try:
            method = getattr(self._record.handle, "close")
        except BaseException as exc:
            with self._owner._lock:
                self._record.close_lookup_error = type(exc).__name__
            raise
        if not callable(method):
            with self._owner._lock:
                self._record.close_lookup_error = "TypeError"
            return method
        return lambda: self._close(method)

    def _close(self, method):
        owner, record = self._owner, self._record
        with owner._lock:
            record.cleanup = "IN_PROGRESS"
        try:
            result = method()
        except BaseException as exc:
            with owner._lock:
                record.cleanup = "FAILED"
                record.cleanup_error = type(exc).__name__
            raise
        with owner._lock:
            record.cleanup = "SUCCEEDED" if result is None else "UNCONFIRMED"
        if result is not None:
            raise _CloseUnconfirmed()


@dataclass(frozen=True)
class SessionConnectResult:
    allowed: bool
    reason: str
    connection_id: int | None = None
    result: ConnectorResult | ConnectDnsResult | None = None


@dataclass(frozen=True)
class IoResult:
    reason: str
    count: int = 0
    error: str | None = None


@dataclass(frozen=True)
class ConnectionState:
    phase: str
    cleanup: str
    cleanup_error: str | None
    in_flight: bool
    buffered_bytes: int


@dataclass
class _Connection:
    tunnel: str
    last_progress: float | None = None
    handle: object = None
    connector_owned: bool = False
    close_lookup_error: str | None = None
    connecting: bool = True
    in_flight: bool = False
    phase: str = "DIALING"
    cleanup: str = "NOT_ATTEMPTED"
    cleanup_error: str | None = None
    buffer: bytes = b""


class QuotaSession:
    """One owner per Job, sharing one NetworkBudget across named tunnels.

    A successful result is CONNECT-ready, not an HTTP CONNECT response. The
    session owns the returned handle, including closure. Callers must not use
    raw handles/transfer to bypass this owner. Adapters implement read(n),
    write(bytes)->int, getpeername(), close()->None. No defaults are supplied.
    """

    def __init__(self, job_id: str, budget: NetworkBudget, limits: IoLimits,
                 *, termination_limits: TerminationLimits | None = None):
        if type(budget) is not NetworkBudget or type(limits) is not IoLimits:
            raise ValueError("explicit budget and I/O limits required")
        if termination_limits is not None and type(termination_limits) is not TerminationLimits:
            raise ValueError("explicit termination limits required")
        self._lock = budget._lock
        with self._lock:
            budget.bind_job(job_id)
            if getattr(budget, "_session_owner", None) is not None:
                raise ValueError("budget already has a Job owner")
            budget._session_owner = self
        self.job_id = job_id
        self.budget = budget
        self.limits = limits
        self._reason = None
        self._connections = {}
        # Original results are retained verbatim, including late success. Late
        # success is never returned to the caller because it contains a handle.
        self._results = []
        self._buffer_reserved = 0
        self._operation = 0
        self.termination_limits = termination_limits
        # Includes authorization/DNS before a budget connection ID exists.
        self._pending_connects = {}

    @property
    def stop_reason(self):
        with self._lock:
            return self._reason

    def _stop_locked(self, reason):
        if self._reason is None and self.budget._attempt.termination is None:
            reason = next((c.termination for c in self.budget._tunnels.values()
                           if c.termination is not None), reason)
        decision = self.budget.stop(reason)
        if self._reason is None:
            self._reason = decision.reason

    def _check_locked(self, tunnel=None):
        if self._reason is not None:
            return False
        decision = self.budget.poll(tunnel)
        if not decision.allowed:
            self._stop_locked(decision.reason)
            return False
        # The legacy poll also expires idle tunnels while returning Job ALLOW.
        # This owner stops/cleans the whole Job when any owned scope expires.
        for counter in self.budget._tunnels.values():
            if counter.termination is not None:
                self._stop_locked(counter.termination)
                return False
        limits = self.termination_limits
        now = self.budget._last_time
        if limits is not None:
            if any(now - start >= limits.connection_timeout_seconds
                   for start in self._pending_connects.values()):
                self._stop_locked("CONNECTION_TIMEOUT")
                return False
            if any(r.last_progress is not None and r.cleanup == "NOT_ATTEMPTED" and
                   now - r.last_progress >= limits.idle_timeout_seconds
                   for r in self._connections.values()):
                self._stop_locked("IDLE_TIMEOUT")
                return False
        return True

    def request_cancel(self):
        """Record cancellation only: no clock read, close or adapter call."""
        with self._lock:
            self._stop_locked("CANCELLED")

    def check_termination(self):
        """Observe deadlines and record the first cause without cleanup."""
        with self._lock:
            self._check_locked()
            return self._reason

    def run_cleanup(self):
        """Attempt eligible owned closes once, outside the shared lock."""
        self._cleanup()

    def termination_snapshot(self):
        """Pure observation; neither clock reads nor cleanup are performed."""
        with self._lock:
            records = tuple(self._connections.values())
            budget = self.budget.snapshot()
            pending = len(self._pending_connects)
            io = sum(r.in_flight for r in records)
            closing = sum(r.cleanup == "IN_PROGRESS" for r in records)
            unknown = sum(r.cleanup in ("FAILED", "UNCONFIRMED") for r in records)
            buffered = sum(len(r.buffer) for r in records)
            if self._reason is None:
                state = "RUNNING"
            elif (pending or io or closing or budget.reserved_bytes or
                  self._buffer_reserved or any(r.connecting for r in records)):
                state = "STOPPING"
            elif unknown:
                state = "CLOSE_UNCONFIRMED"
            elif (budget.concurrent_connections or buffered or
                  any(r.handle is not None and r.cleanup != "SUCCEEDED" for r in records)):
                state = "STOPPING"
            else:
                state = "CLOSED"
            return TerminationSnapshot(state, self._reason, pending, io,
                                       budget.reserved_bytes, budget.concurrent_connections,
                                       buffered, unknown, closing)

    def stop(self, reason):
        if type(reason) is not str or not reason:
            raise ValueError("nonempty stop reason required")
        with self._lock:
            self._stop_locked(reason)
        self._cleanup()

    def poll(self):
        with self._lock:
            self._check_locked()
        self._cleanup()
        return self.stop_reason

    def open_tunnel(self, tunnel_id):
        with self._lock:
            if not self._check_locked():
                decision = BudgetDecision(False, self._reason, "attempt")
            else:
                decision = self.budget.open_tunnel(tunnel_id)
                if not decision.allowed:
                    self._stop_locked(decision.reason)
        self._cleanup()
        return decision

    def connect(self, tunnel_id, policy, hostname, addresses, *, dialer):
        return self._connect(tunnel_id, dialer, lambda wrapped: connect_pinned(
            policy, hostname, 443, addresses, dialer=wrapped))

    def connect_target(self, tunnel_id, policy, authority, *, resolver, dialer, limits):
        return self._connect(tunnel_id, dialer, lambda wrapped: open_connect_target(
            policy, authority, resolver=resolver, dialer=wrapped, limits=limits))

    def _connect(self, tunnel, dialer, invoke):
        attempt = object()
        with self._lock:
            proceed = self._check_locked(tunnel)
            if proceed:
                self._pending_connects[attempt] = self.budget._last_time
        if not proceed:
            self._cleanup()
            return SessionConnectResult(False, self.stop_reason)
        connection_id = None
        record = None

        def wrapped(ip, port):
            nonlocal connection_id, record
            with self._lock:
                if not self._check_locked(tunnel):
                    raise _AdmissionDenied()
                decision = self.budget.begin_connection(tunnel, retain_on_stop=True)
                if not decision.allowed:
                    self._stop_locked(decision.reason)
                    raise _AdmissionDenied()
                connection_id = decision.connection_id
                record = _Connection(tunnel)
                self._connections[connection_id] = record
            handle = dialer(ip, port)
            if handle is not None:
                with self._lock:
                    record.handle = handle
                    record.phase = "PEER_VERIFYING"
                    decision = self.budget.connected(connection_id)
                    if not decision.allowed:
                        self._stop_locked(decision.reason)
                    # Hand the facade to Connector; only an observed successful
                    # result transfers cleanup responsibility back to session.
                    record.connector_owned = True
                return _ConnectorHandle(self, record)
            return None

        try:
            result = invoke(wrapped)
        except BaseException:
            with self._lock:
                self._pending_connects.pop(attempt)
                self._stop_locked("CONNECT_INTERRUPTED")
                if record is not None:
                    record.connecting = False
                    record.phase = "STOPPED"
                    # The facade observes peer-interruption cleanup as well.
                    # A dial interruption has no confirmed resource release.
                    if record.handle is None:
                        record.cleanup = "UNCONFIRMED"
                    elif record.cleanup == "SUCCEEDED":
                        self.budget.close_connection(connection_id)
                    elif record.connector_owned and record.cleanup == "NOT_ATTEMPTED":
                        # Connector may have failed before _close could observe
                        # its call (descriptor lookup/non-callable close). Keep
                        # that unknown outcome; never retry Connector cleanup.
                        record.cleanup = "UNCONFIRMED"
                        record.cleanup_error = record.close_lookup_error
            self._cleanup()
            raise
        with self._lock:
            self._results.append(result)
            connector = getattr(result, "connector", result)
            if record is not None:
                record.connecting = False
                if not result.allowed:
                    record.phase = "REJECTED"
                    if record.handle is None:
                        record.cleanup = "SUCCEEDED"  # No acquired resource.
                    elif record.cleanup == "NOT_ATTEMPTED" and connector.close_error is not None:
                        record.cleanup = "FAILED"
                        record.cleanup_error = connector.close_error
                    if record.cleanup == "SUCCEEDED":
                        self.budget.close_connection(connection_id)
                else:
                    record.connector_owned = False
                    record.phase = "CONNECT_READY"
            if (record is not None and not result.allowed and
                    (record.handle is not None or result.reason == "DIAL_INVALID_HANDLE")):
                self._stop_locked(result.reason)
            self._check_locked(tunnel)
        self._cleanup()
        with self._lock:
            # Recheck at the actual publication point, still counting CONNECT
            # time through authorization, DNS, dial and peer verification.
            self._check_locked(tunnel)
            self._pending_connects.pop(attempt)
            allowed = result.allowed and self._reason is None
            if allowed:
                record.last_progress = self.budget._last_time
            # Publication is linearized here, after cleanup and a final check.
            # Preserve a late result internally without publishing its handle.
            public_result = None if result.allowed and not allowed else result
            published = SessionConnectResult(allowed, self._reason or result.reason,
                                             connection_id, public_result)
        self._cleanup()
        return published

    def connection_state(self, connection_id):
        with self._lock:
            r = self._connections[connection_id]
            return ConnectionState(r.phase, r.cleanup, r.cleanup_error,
                                   r.connecting or r.in_flight, len(r.buffer))

    def finish_connection(self, connection_id):
        """Retire one quiescent tunnel without cancelling the shared Job.

        A transport must stop using the connection before calling this method.
        In-flight operations retain ownership; False means retry after settlement.
        Confirmed close releases occupancy, never cumulative bytes/connections.
        """
        with self._lock:
            r = self._connections[connection_id]
            if r.connecting or r.in_flight:
                return False
            if r.cleanup == "NOT_ATTEMPTED":
                r.phase = "FINISHING"
        self._cleanup()
        with self._lock:
            return r.cleanup == "SUCCEEDED"

    def _cleanup(self):
        # Mark each candidate before calling out, so concurrent/reentrant stop
        # cannot close twice. A blocked close remains IN_PROGRESS and occupies.
        while True:
            with self._lock:
                candidate = next(((cid, r) for cid, r in self._connections.items()
                                  if (self._reason is not None or r.phase == "FINISHING") and
                                  not r.connector_owned and not r.connecting and not r.in_flight and
                                  not any(t.connection_id == cid for t in self.budget._tokens.values()) and
                                  r.cleanup == "NOT_ATTEMPTED" and r.handle is not None), None)
                if candidate is None:
                    return
                cid, r = candidate
                r.cleanup = "IN_PROGRESS"
                r.phase = "STOPPED"
                r.buffer = b""
            error = None
            try:
                closed = r.handle.close()
                status = "SUCCEEDED" if closed is None else "UNCONFIRMED"
            except BaseException as exc:
                status, error = "FAILED", type(exc).__name__
            with self._lock:
                r.cleanup, r.cleanup_error = status, error
                if status == "SUCCEEDED":
                    self.budget.close_connection(cid)

    def _start_io(self, cid, direction, requested):
        with self._lock:
            r = self._connections[cid]
            if not self._check_locked(r.tunnel):
                return None, IoResult(self._reason)
            if r.phase != "CONNECT_READY":
                return None, IoResult("NOT_READY")
            if r.in_flight:
                return None, IoResult("WOULD_BLOCK")
            decision = self.budget.poll_bytes(cid)
            if not decision.allowed:
                self._stop_locked(decision.reason)
                return None, IoResult(decision.reason)
            amount = min(requested, self.limits.max_chunk_bytes)
            if direction == "receive":
                available = self.limits.max_buffer_bytes - self._buffer_reserved - sum(
                    len(c.buffer) for c in self._connections.values())
                if available == 0:
                    return None, IoResult("WOULD_BLOCK")
                amount = min(amount, available)
            self._operation += 1
            grant = self.budget.reserve_bytes(cid, job_id=self.job_id, tunnel_id=r.tunnel,
                                              direction=direction, operation=str(self._operation),
                                              requested=amount)
            if not grant.allowed:
                if grant.reason != "WOULD_BLOCK":
                    self._stop_locked(grant.reason)
                return None, IoResult(grant.reason)
            r.in_flight = True
            if direction == "receive":
                self._buffer_reserved += grant.token.amount
            return (r, grant.token), None

    def write(self, connection_id, payload):
        if type(payload) is not bytes or not payload:
            raise ValueError("nonempty immutable bytes required")
        return self._io(connection_id, "send", len(payload), payload)

    def read(self, connection_id, requested):
        if type(requested) is not int or requested <= 0:
            raise ValueError("positive integer read size required")
        return self._io(connection_id, "receive", requested, None)

    def _io(self, cid, direction, requested, payload):
        started, denied = self._start_io(cid, direction, requested)
        if denied is not None:
            self._cleanup()
            return denied
        r, token = started
        actual, data, reason, error, interrupt = None, b"", "ALLOW", None, None
        try:
            if direction == "send":
                count = r.handle.write(payload[:token.amount])
                if type(count) is not int or not 0 <= count <= token.amount:
                    reason = "ADAPTER_VIOLATION"
                else:
                    actual = count
            else:
                value = r.handle.read(token.amount)
                if type(value) is not bytes or len(value) > token.amount:
                    reason = "ADAPTER_VIOLATION"
                else:
                    data, actual = value, len(value)
                    if not value:
                        reason = "EOF"
        except IoWouldBlock:
            actual, reason = 0, "WOULD_BLOCK"
        except BaseException as exc:
            reason, error = "IO_ERROR", type(exc).__name__
            if not isinstance(exc, Exception):
                interrupt = exc
        with self._lock:
            self.budget.settle_bytes(token, job_id=self.job_id, tunnel_id=r.tunnel,
                                     connection_id=cid, direction=direction,
                                     operation=token.operation, actual=actual)
            if direction == "receive":
                self._buffer_reserved -= token.amount
            r.in_flight = False
            if reason in ("ADAPTER_VIOLATION", "IO_ERROR"):
                self._stop_locked(reason)
            self._check_locked(r.tunnel)
            if self._reason is None:
                if actual:
                    r.last_progress = self.budget._last_time
                r.buffer += data
            outcome = IoResult(self._reason or reason, actual or 0, error)
        self._cleanup()
        if interrupt is not None:
            raise interrupt
        return outcome

    def deliver(self, connection_id, writer):
        """Deliver already charged upstream bytes; no second network charge."""
        with self._lock:
            r = self._connections[connection_id]
            denied = None
            if not self._check_locked(r.tunnel):
                denied = IoResult(self._reason)
            elif r.in_flight:
                denied = IoResult("WOULD_BLOCK")
            elif r.phase != "CONNECT_READY":
                denied = IoResult("NOT_READY")
            elif not r.buffer:
                denied = IoResult("EMPTY")
            else:
                data = r.buffer[:self.limits.max_chunk_bytes]
                r.in_flight = True
        if denied is not None:
            self._cleanup()
            return denied
        reason, error, count, interrupt = "ALLOW", None, 0, None
        try:
            count = writer.write(data)
            if type(count) is not int or not 0 <= count <= len(data):
                reason, count = "ADAPTER_VIOLATION", 0
        except IoWouldBlock:
            reason = "WOULD_BLOCK"
        except BaseException as exc:
            reason, error = "IO_ERROR", type(exc).__name__
            if not isinstance(exc, Exception):
                interrupt = exc
        with self._lock:
            r.in_flight = False
            if reason in ("ADAPTER_VIOLATION", "IO_ERROR"):
                self._stop_locked(reason)
            self._check_locked(r.tunnel)
            if self._reason is None and count:
                r.last_progress = self.budget._last_time
            r.buffer = r.buffer[count:] if self._reason is None else b""
            outcome = IoResult(self._reason or reason, count, error)
        self._cleanup()
        if interrupt is not None:
            raise interrupt
        return outcome
