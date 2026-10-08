"""Bounded non-blocking per-key rate limiter (R8.2)."""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Deque, Optional
import threading

from alerting.clock import RealTimeProvider, TimeProvider


@dataclass
class RateLimitDecision:
    allowed: bool
    key: str
    count_in_window: int
    limit: int


class BoundedRateLimiter:
    """
    Sliding-window rate limiter (no sleep).

    Policy:
      - Per-key: at most ``limit`` events per ``window_sec``.
      - Key cardinality capped at ``max_keys`` (FIFO eviction of idle keys).
      - Uses monotonic clock; injectable for tests.
      - Global storm protection: keys are bounded — attackers cannot grow
        unbounded limiter state via unique identities.

    Not a token bucket (sliding window is simpler to test deterministically).
    """

    def __init__(
        self,
        *,
        limit: int = 30,
        window_sec: float = 60.0,
        max_keys: int = 256,
        clock: Optional[TimeProvider] = None,
    ) -> None:
        if limit < 0:
            raise ValueError("limit must be >= 0")
        if window_sec < 0:
            raise ValueError("window_sec must be >= 0")
        if max_keys < 1:
            raise ValueError("max_keys must be >= 1")
        self.limit = int(limit)
        self.window_sec = float(window_sec)
        self.max_keys = int(max_keys)
        self.clock: TimeProvider = clock or RealTimeProvider()
        self._windows: "OrderedDict[str, Deque[float]]" = OrderedDict()
        self.total_suppressed: int = 0
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()
            self.total_suppressed = 0

    def size(self) -> int:
        with self._lock:
            return len(self._windows)

    def allow(self, key: str) -> RateLimitDecision:
        normalized = _normalize_key(key)
        with self._lock:
            now = self.clock.monotonic()

            if self.limit == 0:
                self.total_suppressed += 1
                return RateLimitDecision(False, normalized, 0, self.limit)

            q = self._windows.get(normalized)
            if q is None:
                self._ensure_capacity()
                q = deque()
                self._windows[normalized] = q
            else:
                self._windows.move_to_end(normalized)

            self._prune(q, now)
            if len(q) >= self.limit:
                self.total_suppressed += 1
                return RateLimitDecision(False, normalized, len(q), self.limit)

            q.append(now)
            return RateLimitDecision(True, normalized, len(q), self.limit)

    def _prune(self, q: Deque[float], now: float) -> None:
        if self.window_sec <= 0:
            q.clear()
            return
        cutoff = now - self.window_sec
        while q and q[0] <= cutoff:
            q.popleft()

    def _ensure_capacity(self) -> None:
        while len(self._windows) >= self.max_keys:
            self._windows.popitem(last=False)


def _normalize_key(key: str) -> str:
    if key is None:
        return "UNKNOWN||||"
    text = str(key).strip()
    return text if text else "UNKNOWN||||"
