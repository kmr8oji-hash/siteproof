"""Thread-safe accounting only: this module owns no actual connections.

Limits are explicit trusted configuration, not production defaults. Pending
connections consume concurrency and reserve cumulative connection capacity.
A successful establishment consumes that reserved cumulative capacity; failure
releases it. Every admitted attempt consumes the attempt
budget, even if it later fails. Rejected events are not added to counters.
A limit breach terminates its scope. Legacy accounting-only connections release
on stop; explicitly retained resources require confirmed close instead.
"""

from dataclasses import dataclass
import math
from threading import RLock
import time
from typing import Callable


@dataclass(frozen=True)
class BudgetLimits:
    total_bytes: int
    total_connections: int
    concurrent_connections: int
    connection_attempts: int
    duration_seconds: float

    def __post_init__(self):
        for value in (self.total_bytes, self.total_connections,
                      self.concurrent_connections, self.connection_attempts):
            if type(value) is not int or value < 0:
                raise ValueError("count/byte limits must be nonnegative integers")
        if not _valid_time(self.duration_seconds) or self.duration_seconds <= 0:
            raise ValueError("duration must be positive and finite")


def _valid_time(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


@dataclass(frozen=True)
class BudgetSnapshot:
    total_bytes: int
    total_connections: int
    concurrent_connections: int
    connection_attempts: int
    termination: str | None
    confirmed_bytes: int = 0
    uncertain_bytes: int = 0
    reserved_bytes: int = 0
    pending_connections: int = 0


@dataclass(frozen=True)
class ByteReservation:
    job_id: str
    tunnel_id: str
    connection_id: int
    direction: str
    operation: str
    amount: int


@dataclass(frozen=True)
class ByteGrant:
    allowed: bool
    reason: str
    token: ByteReservation | None = None
    scope: str | None = None


@dataclass(frozen=True)
class BudgetDecision:
    allowed: bool
    reason: str
    scope: str | None = None
    connection_id: int | None = None


@dataclass
class _Counter:
    started: float
    total_bytes: int = 0
    total_connections: int = 0
    concurrent_connections: int = 0
    connection_attempts: int = 0
    termination: str | None = None
    pending_connections: int = 0
    uncertain_bytes: int = 0
    reserved_bytes: int = 0

    def snapshot(self):
        return BudgetSnapshot(self.total_bytes, self.total_connections,
                              self.concurrent_connections,
                              self.connection_attempts, self.termination,
                              self.total_bytes - self.uncertain_bytes,
                              self.uncertain_bytes, self.reserved_bytes,
                              self.pending_connections)


class NetworkBudget:
    """One trusted attempt, multiple named tunnels, atomic shared accounting.

    begin_connection -> connected (optional) -> transfer* -> close_connection.
    close_connection also records a failed/cancelled pending attempt. poll must
    be scheduled by a future transport to enforce deadlines while idle. Methods
    check both deadlines; snapshots are observational and do not advance time.
    Tunnel IDs cannot be reused to reset counters within this attempt.
    """

    def __init__(self, attempt_limits: BudgetLimits, tunnel_limits: BudgetLimits,
                 *, clock: Callable[[], float] = time.monotonic):
        if type(attempt_limits) is not BudgetLimits or type(tunnel_limits) is not BudgetLimits:
            raise ValueError("both limit sets are required")
        now = clock()
        if not _valid_time(now):
            raise ValueError("invalid clock")
        self._attempt_limits = attempt_limits
        self._tunnel_limits = tunnel_limits
        self._clock = clock
        self._last_time = now
        self._attempt = _Counter(now)
        self._tunnels: dict[str, _Counter] = {}
        self._connections: dict[int, tuple[str, bool]] = {}
        self._next_id = 1
        self._lock = RLock()
        self._job_id = None
        self._retained = set()
        self._byte_modes = {}
        self._tokens = {}
        self._operations = set()

    def _stop(self, scope, reason):
        counter = self._attempt if scope == "attempt" else self._tunnels[scope]
        if counter.termination is None:
            counter.termination = reason
        for connection_id, (tunnel, established) in tuple(self._connections.items()):
            if scope == "attempt" or tunnel == scope:
                if connection_id in self._retained:
                    continue
                self._attempt.concurrent_connections -= 1
                self._tunnels[tunnel].concurrent_connections -= 1
                if not established:
                    self._attempt.pending_connections -= 1
                    self._tunnels[tunnel].pending_connections -= 1
                del self._connections[connection_id]
        if scope == "attempt":
            for tunnel in self._tunnels.values():
                if tunnel.termination is None:
                    tunnel.termination = reason
        return BudgetDecision(False, counter.termination, scope)

    def _now(self):
        try:
            now = self._clock()
        except (OSError, ValueError):
            return None
        if not _valid_time(now) or now < self._last_time:
            return None
        self._last_time = now
        return now

    def _check(self, tunnel_id=None):
        if self._attempt.termination is not None:
            return BudgetDecision(False, self._attempt.termination, "attempt")
        now = self._now()
        if now is None:
            return self._stop("attempt", "INVALID_CLOCK")
        if now - self._attempt.started >= self._attempt_limits.duration_seconds:
            return self._stop("attempt", "DEADLINE")
        # Expire idle tunnels as well, so their reservations cannot block peers.
        for name, counter in self._tunnels.items():
            if (counter.termination is None and
                    now - counter.started >= self._tunnel_limits.duration_seconds):
                self._stop(name, "DEADLINE")
        if tunnel_id is not None:
            counter = self._tunnels[tunnel_id]
            if counter.termination is not None:
                return BudgetDecision(False, counter.termination, tunnel_id)
        return BudgetDecision(True, "ALLOW")

    def open_tunnel(self, tunnel_id: str) -> BudgetDecision:
        with self._lock:
            if (type(tunnel_id) is not str or not tunnel_id or
                    tunnel_id == "attempt" or tunnel_id in self._tunnels):
                raise ValueError("tunnel ID must be new, nonempty, and not 'attempt'")
            decision = self._check()
            if not decision.allowed:
                return decision
            self._tunnels[tunnel_id] = _Counter(self._last_time)
            return decision

    def poll(self, tunnel_id: str | None = None) -> BudgetDecision:
        with self._lock:
            if tunnel_id is not None and tunnel_id not in self._tunnels:
                raise ValueError("unknown tunnel")
            return self._check(tunnel_id)

    def _reserve(self, tunnel_id, changes, *, reserve_connection=False):
        decision = self._check(tunnel_id)
        if not decision.allowed:
            return decision
        blocked_scope = None
        for scope, counter, limits in (
            ("attempt", self._attempt, self._attempt_limits),
            (tunnel_id, self._tunnels[tunnel_id], self._tunnel_limits),
        ):
            for field, amount in changes.items():
                occupied = counter.reserved_bytes if field == "total_bytes" else 0
                if getattr(counter, field) + occupied + amount > getattr(limits, field):
                    if (occupied and field == "total_bytes" and
                            counter.total_bytes + amount <= limits.total_bytes):
                        blocked_scope = scope
                    else:
                        return self._stop(scope, field.upper() + "_LIMIT")
            if (reserve_connection and counter.total_connections +
                    counter.pending_connections + 1 > limits.total_connections):
                return self._stop(scope, "TOTAL_CONNECTIONS_LIMIT")
        if blocked_scope is not None:
            return BudgetDecision(False, "WOULD_BLOCK", blocked_scope)
        for counter in (self._attempt, self._tunnels[tunnel_id]):
            for field, amount in changes.items():
                setattr(counter, field, getattr(counter, field) + amount)
            if reserve_connection:
                counter.pending_connections += 1
        return BudgetDecision(True, "ALLOW")

    def begin_connection(self, tunnel_id: str, *, retain_on_stop=False) -> BudgetDecision:
        with self._lock:
            if type(retain_on_stop) is not bool:
                raise ValueError("retain_on_stop must be bool")
            if tunnel_id not in self._tunnels:
                raise ValueError("unknown tunnel")
            decision = self._reserve(tunnel_id, {
                "connection_attempts": 1, "concurrent_connections": 1,
            }, reserve_connection=True)
            if not decision.allowed:
                return decision
            connection_id = self._next_id
            self._next_id += 1
            self._connections[connection_id] = (tunnel_id, False)
            if retain_on_stop:
                self._retained.add(connection_id)
            return BudgetDecision(True, "ALLOW", connection_id=connection_id)

    def _connection(self, connection_id):
        if type(connection_id) is not int or connection_id not in self._connections:
            raise ValueError("unknown or closed connection")
        return self._connections[connection_id]

    def connected(self, connection_id: int) -> BudgetDecision:
        with self._lock:
            tunnel, established = self._connection(connection_id)
            if established:
                raise ValueError("connection already established")
            if connection_id in self._retained:
                # A returned handle is a real establishment even after stop or
                # before peer rejection. Its pre-dial reservation guarantees room.
                for counter in (self._attempt, self._tunnels[tunnel]):
                    counter.pending_connections -= 1
                    counter.total_connections += 1
                self._connections[connection_id] = (tunnel, True)
                return self._check(tunnel)
            decision = self._reserve(tunnel, {"total_connections": 1})
            if decision.allowed:
                self._attempt.pending_connections -= 1
                self._tunnels[tunnel].pending_connections -= 1
                self._connections[connection_id] = (tunnel, True)
            return decision

    def transfer(self, connection_id: int, *, sent: int = 0,
                 received: int = 0) -> BudgetDecision:
        with self._lock:
            if any(type(n) is not int or n < 0 for n in (sent, received)):
                raise ValueError("byte counts must be nonnegative integers")
            tunnel, established = self._connection(connection_id)
            if not established:
                raise ValueError("connection is not established")
            if self._byte_modes.get(connection_id) == "reservation":
                raise ValueError("reservation connections cannot use transfer")
            decision = self._reserve(tunnel, {"total_bytes": sent + received})
            if decision.allowed:
                self._byte_modes[connection_id] = "legacy"
            return decision

    def close_connection(self, connection_id: int) -> BudgetDecision:
        with self._lock:
            if type(connection_id) is not int:
                raise ValueError("invalid connection ID")
            # Idempotent release also permits cleanup after automatic termination.
            if connection_id not in self._connections:
                return BudgetDecision(True, "ALREADY_CLOSED")
            if any(t.connection_id == connection_id for t in self._tokens.values()):
                return BudgetDecision(False, "IN_FLIGHT")
            tunnel, established = self._connections[connection_id]
            decision = self._check(tunnel)
            if connection_id in self._connections:
                del self._connections[connection_id]
                self._retained.discard(connection_id)
                self._byte_modes.pop(connection_id, None)
                self._attempt.concurrent_connections -= 1
                self._tunnels[tunnel].concurrent_connections -= 1
                if not established:
                    self._attempt.pending_connections -= 1
                    self._tunnels[tunnel].pending_connections -= 1
            return decision

    def bind_job(self, job_id: str):
        """Bind this shared budget once; a different Job cannot reuse it."""
        with self._lock:
            if type(job_id) is not str or not job_id:
                raise ValueError("nonempty Job ID required")
            if self._job_id is not None and self._job_id != job_id:
                raise ValueError("budget already belongs to another Job")
            self._job_id = job_id

    def stop(self, reason: str) -> BudgetDecision:
        with self._lock:
            if type(reason) is not str or not reason:
                raise ValueError("nonempty stop reason required")
            return self._stop("attempt", reason)

    def poll_bytes(self, connection_id: int) -> BudgetDecision:
        """Check committed byte exhaustion, independently of temporary buffers."""
        with self._lock:
            tunnel, established = self._connection(connection_id)
            if not established:
                raise ValueError("connection is not established")
            decision = self._check(tunnel)
            if not decision.allowed:
                return decision
            for scope, counter, limits in (
                ("attempt", self._attempt, self._attempt_limits),
                (tunnel, self._tunnels[tunnel], self._tunnel_limits),
            ):
                if counter.total_bytes >= limits.total_bytes:
                    return self._stop(scope, "TOTAL_BYTES_LIMIT")
            return decision

    def reserve_bytes(self, connection_id: int, *, job_id: str, tunnel_id: str,
                      direction: str, operation: str, requested: int) -> ByteGrant:
        """Grant a bounded prefix, or distinguish temporary contention from end."""
        with self._lock:
            tunnel, established = self._connection(connection_id)
            if (self._job_id is None or job_id != self._job_id or tunnel_id != tunnel or
                    direction not in ("send", "receive") or
                    type(direction) is not str or type(operation) is not str or not operation or
                    type(requested) is not int or requested <= 0 or not established):
                raise ValueError("invalid byte reservation scope/request")
            if self._byte_modes.get(connection_id) == "legacy":
                raise ValueError("legacy transfer connections cannot reserve bytes")
            key = (connection_id, direction, operation)
            if key in self._operations:
                raise ValueError("operation already in flight")
            decision = self.poll_bytes(connection_id)
            if not decision.allowed:
                return ByteGrant(False, decision.reason, scope=decision.scope)
            amount = requested
            for scope, counter, limits in (
                ("attempt", self._attempt, self._attempt_limits),
                (tunnel, self._tunnels[tunnel], self._tunnel_limits),
            ):
                amount = min(amount, limits.total_bytes - counter.total_bytes - counter.reserved_bytes)
            if amount == 0:
                return ByteGrant(False, "WOULD_BLOCK")
            token = ByteReservation(job_id, tunnel, connection_id, direction, operation, amount)
            self._tokens[id(token)] = token
            self._operations.add(key)
            self._byte_modes[connection_id] = "reservation"
            for counter in (self._attempt, self._tunnels[tunnel]):
                counter.reserved_bytes += amount
            return ByteGrant(True, "ALLOW", token)

    def settle_bytes(self, token: ByteReservation, *, job_id: str, tunnel_id: str,
                     connection_id: int, direction: str, operation: str,
                     actual: int | None) -> None:
        """Settle exactly once, including after stop/close. None means unknown."""
        with self._lock:
            if (type(token) is not ByteReservation or self._tokens.get(id(token)) is not token or
                    (job_id, tunnel_id, connection_id, direction, operation) !=
                    (token.job_id, token.tunnel_id, token.connection_id, token.direction, token.operation) or
                    type(connection_id) is not int):
                raise ValueError("foreign, settled, or mismatched reservation")
            if actual is not None and (type(actual) is not int or not 0 <= actual <= token.amount):
                raise ValueError("actual exceeds reservation or is invalid")
            charged = token.amount if actual is None else actual
            for counter in (self._attempt, self._tunnels[token.tunnel_id]):
                counter.reserved_bytes -= token.amount
                counter.total_bytes += charged
                if actual is None:
                    counter.uncertain_bytes += charged
            del self._tokens[id(token)]
            self._operations.remove((token.connection_id, token.direction, token.operation))

    def snapshot(self, tunnel_id: str | None = None) -> BudgetSnapshot:
        with self._lock:
            if tunnel_id is not None and tunnel_id not in self._tunnels:
                raise ValueError("unknown tunnel")
            counter = self._attempt if tunnel_id is None else self._tunnels[tunnel_id]
            return counter.snapshot()
