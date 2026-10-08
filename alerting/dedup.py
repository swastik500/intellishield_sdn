"""Bounded time-window alert deduplication (R8.2)."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import Optional
import threading

from alerting.clock import RealTimeProvider, TimeProvider


@dataclass
class DedupDecision:
    is_duplicate: bool
    key: str
    suppressed_total: int  # total suppressions for this key (lifetime of entry)


class BoundedDeduplicator:
    """
    Time-window dedup with bounded key cardinality.

    Policy (auditable, simple):
      - First sighting of a key within the window → not duplicate; record timestamp.
      - Repeat within window → duplicate; increment suppression counter;
        **do not persist / dispatch** (manager responsibility).
      - After window expires → treat as new; reset suppression for that key.
      - No suppression-summary persistence in R8.2 (counters only).

    Eviction: when over max_keys, drop oldest inserted key (OrderedDict FIFO).
    """

    def __init__(
        self,
        *,
        window_sec: float = 60.0,
        max_keys: int = 256,
        clock: Optional[TimeProvider] = None,
    ) -> None:
        if window_sec < 0:
            raise ValueError("window_sec must be >= 0")
        if max_keys < 1:
            raise ValueError("max_keys must be >= 1")
        self.window_sec = float(window_sec)
        self.max_keys = int(max_keys)
        self.clock: TimeProvider = clock or RealTimeProvider()
        # key → (last_seen_monotonic, suppress_count)
        self._entries: "OrderedDict[str, tuple]" = OrderedDict()
        self.total_suppressed: int = 0
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()
            self.total_suppressed = 0

    def size(self) -> int:
        with self._lock:
            return len(self._entries)

    def observe(self, key: str) -> DedupDecision:
        """
        Observe a candidate alert key.

        Records the key when not a duplicate (including first sighting after
        expiry). Callers should invoke this before rate-limit so storms collapse
        to DUPLICATE after the first attempt in-window.
        """
        normalized = _normalize_key(key)
        with self._lock:
            now = self.clock.monotonic()
            self._expire(now)

            if normalized in self._entries:
                last_seen, suppressed = self._entries[normalized]
                suppressed += 1
                self._entries[normalized] = (last_seen, suppressed)
                self._entries.move_to_end(normalized)
                self.total_suppressed += 1
                return DedupDecision(True, normalized, suppressed)

            self._ensure_capacity()
            self._entries[normalized] = (now, 0)
            return DedupDecision(False, normalized, 0)

    def _expire(self, now: float) -> None:
        if self.window_sec <= 0:
            self._entries.clear()
            return
        stale = [
            k
            for k, (ts, _) in self._entries.items()
            if (now - ts) >= self.window_sec
        ]
        for k in stale:
            del self._entries[k]

    def _ensure_capacity(self) -> None:
        while len(self._entries) >= self.max_keys:
            self._entries.popitem(last=False)


def _normalize_key(key: str) -> str:
    if key is None:
        return "UNKNOWN||||"
    text = str(key).strip()
    return text if text else "UNKNOWN||||"
