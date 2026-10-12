"""
Per-attack-key cooldown tracker for email alerts.

Prevents duplicate emails for the same attack within the configured cooldown window.
Thread-safe via simple dict with timestamps.

Supports reservation for in-flight attempts:
- reserve(key): atomically check cooldown and reserve if available; returns True if reserved
- confirm(key): record successful send timestamp (starts cooldown)
- release(key): release reservation after failure (allows retry)
"""

from __future__ import annotations

import threading
import time
from typing import Dict, Optional


class EmailCooldownTracker:
    """
    Track last-email timestamps per attack key.

    Keys are stable identifiers like ``{alert_type}|{source}|{attack_hint}``.

    States per key:
    - None: never sent, can reserve
    - timestamp (float): cooldown active, cannot reserve
    - "reserved": in-flight attempt, cannot reserve another
    """

    def __init__(self, cooldown_seconds: int = 300) -> None:
        self._cooldown = max(0, cooldown_seconds)
        self._lock = threading.Lock()
        self._state: Dict[str, Optional[float] | str] = {}  # key -> timestamp | "reserved" | None

    @property
    def cooldown_seconds(self) -> int:
        return self._cooldown

    def _is_available(self, now: float, value: Optional[float] | str) -> bool:
        if value is None:
            return True
        if value == "reserved":
            return False
        return (now - value) >= self._cooldown

    def may_send(self, key: str) -> bool:
        """Check whether cooldown has elapsed for *key* (does NOT update)."""
        with self._lock:
            val = self._state.get(key)
            if val is None:
                return True
            if val == "reserved":
                return False
            return (time.monotonic() - val) >= self._cooldown

    def record_sent(self, key: str) -> None:
        """Record that an email was just sent for *key* (starts cooldown)."""
        with self._lock:
            self._state[key] = time.monotonic()

    def reserve(self, key: str) -> bool:
        """
        Atomically check cooldown and reserve the key for an in-flight attempt.

        Returns True if key was available and is now reserved.
        Returns False if cooldown active or already reserved.
        """
        with self._lock:
            now = time.monotonic()
            val = self._state.get(key)
            if not self._is_available(now, val):
                return False
            self._state[key] = "reserved"
            return True

    def confirm(self, key: str) -> None:
        """Record successful send timestamp (starts cooldown)."""
        with self._lock:
            self._state[key] = time.monotonic()

    def release(self, key: str) -> None:
        """Release reservation after failure (allows retry)."""
        with self._lock:
            val = self._state.get(key)
            if val == "reserved":
                self._state[key] = None

    def try_send(self, key: str) -> bool:
        """
        Legacy atomic check-and-record (for backward compatibility).

        Returns True if cooldown has elapsed (and records the send).
        Returns False if still within cooldown window.
        """
        with self._lock:
            now = time.monotonic()
            val = self._state.get(key)
            if val == "reserved":
                return False
            if val is not None and (now - val) < self._cooldown:
                return False
            self._state[key] = now
            return True

    def clear(self) -> None:
        """Reset all tracked keys (tests / reconnect)."""
        with self._lock:
            self._state.clear()

    def active_keys(self) -> int:
        """Number of tracked keys."""
        with self._lock:
            return len(self._state)
