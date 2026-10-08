"""Injectable clocks for correlation TTL / window tests (no sleep())."""

from __future__ import annotations

import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class TimeProvider(Protocol):
    def monotonic(self) -> float:
        ...

    def wall_time(self) -> float:
        """POSIX seconds (for tests that need wall clock)."""
        ...


class RealTimeProvider:
    def monotonic(self) -> float:
        return time.monotonic()

    def wall_time(self) -> float:
        return time.time()


class FakeTimeProvider:
    """Deterministic clock for unit tests."""

    def __init__(self, start: float = 0.0) -> None:
        self._t = float(start)

    def monotonic(self) -> float:
        return self._t

    def wall_time(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += float(seconds)

    def set(self, seconds: float) -> None:
        self._t = float(seconds)
