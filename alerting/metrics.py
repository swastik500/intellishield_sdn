"""Alert pipeline metrics / counters (no Prometheus dependency)."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class AlertMetrics:
    """
    Mutable counters for AlertManager observability.

    Increments are lock-guarded for cooperative / multi-call safety.
    OsKen is typically single-threaded cooperative; the lock is cheap insurance.
    """

    alerts_received: int = 0
    alerts_created: int = 0
    alerts_skipped: int = 0
    alerts_dispatched: int = 0
    alerts_persisted: int = 0
    alerts_deduplicated: int = 0  # reserved R8.2
    alerts_rate_limited: int = 0  # reserved R8.2
    adapter_failures: int = 0
    persistence_failures: int = 0
    manager_failures: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def incr(self, name: str, amount: int = 1) -> None:
        with self._lock:
            current = getattr(self, name, None)
            if not isinstance(current, int):
                raise AttributeError(f"unknown counter {name!r}")
            setattr(self, name, current + int(amount))

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "alerts_received": int(self.alerts_received),
                "alerts_created": int(self.alerts_created),
                "alerts_skipped": int(self.alerts_skipped),
                "alerts_dispatched": int(self.alerts_dispatched),
                "alerts_persisted": int(self.alerts_persisted),
                "alerts_deduplicated": int(self.alerts_deduplicated),
                "alerts_rate_limited": int(self.alerts_rate_limited),
                "adapter_failures": int(self.adapter_failures),
                "persistence_failures": int(self.persistence_failures),
                "manager_failures": int(self.manager_failures),
            }

    def reset(self) -> None:
        with self._lock:
            self.alerts_received = 0
            self.alerts_created = 0
            self.alerts_skipped = 0
            self.alerts_dispatched = 0
            self.alerts_persisted = 0
            self.alerts_deduplicated = 0
            self.alerts_rate_limited = 0
            self.adapter_failures = 0
            self.persistence_failures = 0
            self.manager_failures = 0
