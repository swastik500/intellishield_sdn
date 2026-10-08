"""Injectable monotonic clock for alert policy tests (no sleep)."""

from __future__ import annotations

import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class TimeProvider(Protocol):
    def monotonic(self) -> float:
        """Monotonic seconds (for windows / expiration)."""
        ...


class RealTimeProvider:
    """Production clock — time.monotonic()."""

    def monotonic(self) -> float:
        return time.monotonic()


class FakeTimeProvider:
    """Deterministic clock for unit tests."""

    def __init__(self, start: float = 0.0) -> None:
        self._now = float(start)

    def monotonic(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += float(seconds)

    def set(self, seconds: float) -> None:
        self._now = float(seconds)
