"""Cooperative termination values only; no clock, timer or resource ownership."""

from dataclasses import dataclass
import math


@dataclass(frozen=True)
class TerminationLimits:
    connection_timeout_seconds: float
    idle_timeout_seconds: float

    def __post_init__(self):
        for value in (self.connection_timeout_seconds, self.idle_timeout_seconds):
            try:
                valid = (type(value) in (int, float) and
                         math.isfinite(value) and value > 0)
            except OverflowError:
                valid = False
            if not valid:
                raise ValueError("explicit positive finite timeouts required")


@dataclass(frozen=True)
class TerminationSnapshot:
    state: str
    reason: str | None
    pending_connects: int
    in_flight_io: int
    reserved_bytes: int
    occupied_connections: int
    buffered_bytes: int
    unconfirmed_handles: int
    cleanup_in_progress: int
