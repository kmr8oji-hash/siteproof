"""Deterministic failure injection (test aid; inert unless armed)."""
from __future__ import annotations

from typing import Callable, Optional


class InjectedFailure(Exception):
    """Simulates an ordinary, catchable failure (I/O error, lost commit ack...)."""


class SimulatedCrash(BaseException):
    """Simulates the process dying at this point. Deliberately not an Exception,
    so no `except Exception` handler can turn it into a clean failure."""


class Failpoints:
    def __init__(self) -> None:
        self._hooks: dict[str, Callable[[], None]] = {}
        self.hits: list[str] = []

    def on(self, name: str, action: Callable[[], None]) -> "Failpoints":
        self._hooks[name] = action
        return self

    def fail(self, name: str, message: str = "injected") -> "Failpoints":
        def _raise() -> None:
            raise InjectedFailure(f"{name}: {message}")
        return self.on(name, _raise)

    def crash(self, name: str) -> "Failpoints":
        def _raise() -> None:
            raise SimulatedCrash(name)
        return self.on(name, _raise)

    def hit(self, name: str) -> None:
        self.hits.append(name)
        hook = self._hooks.get(name)
        if hook is not None:
            hook()


NO_FAILPOINTS: Optional[Failpoints] = None


def hit(fp: Optional[Failpoints], name: str) -> None:
    if fp is not None:
        fp.hit(name)
