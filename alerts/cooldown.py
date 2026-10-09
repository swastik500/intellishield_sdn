"""
Per-attack-key cooldown tracker for email alerts.

Prevents duplicate emails for the same attack within the configured cooldown window.
Thread-safe via simple dict with timestamps.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, Optional


class EmailCooldownTracker:
    """
    Track last-email timestamps per attack key.

    Keys are stable identifiers like ``{alert_type}|{source}|{attack_hint}``.
    """

    def __init__(self, cooldown_seconds: int = 300) -> None:
        self._cooldown = max(0, cooldown_seconds)
        self._lock = threading.Lock()
        self._last_sent: Dict[str, float] = {}

    @property
    def cooldown_seconds(self) -> int:
        return self._cooldown

    def may_send(self, key: str) -> bool:
        """Check whether cooldown has elapsed for *key* (does NOT update)."""
        with self._lock:
            last = self._last_sent.get(key)
            if last is None:
                return True
            return (time.monotonic() - last) >= self._cooldown

    def record_sent(self, key: str) -> None:
        """Record that an email was just sent for *key*."""
        with self._lock:
            self._last_sent[key] = time.monotonic()

    def try_send(self, key: str) -> bool:
        """
        Atomic check-and-record.

        Returns True if cooldown has elapsed (and records the send).
        Returns False if still within cooldown window.
        """
        with self._lock:
            now = time.monotonic()
            last = self._last_sent.get(key)
            if last is not None and (now - last) < self._cooldown:
                return False
            self._last_sent[key] = now
            return True

    def clear(self) -> None:
        """Reset all tracked keys (tests / reconnect)."""
        with self._lock:
            self._last_sent.clear()

    def active_keys(self) -> int:
        """Number of tracked keys."""
        with self._lock:
            return len(self._last_sent)
