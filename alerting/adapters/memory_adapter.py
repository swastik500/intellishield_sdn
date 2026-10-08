"""In-memory adapter for tests and local inspection."""

from __future__ import annotations

from typing import List

from shared_contracts.models import AlertEvent


class MemoryNotificationAdapter:
    """
    Records alerts in-process. No I/O / network.

    Suitable for unit tests and later dashboard buffering.
    Set ``enabled=False`` to skip dispatch (manager honours this flag).
    """

    name = "memory"

    def __init__(self, *, max_retained: int = 256, enabled: bool = True) -> None:
        if max_retained < 1:
            raise ValueError("max_retained must be >= 1")
        self.enabled = bool(enabled)
        self._max = int(max_retained)
        self.sent: List[AlertEvent] = []

    def send(self, alert: AlertEvent) -> None:
        if not self.enabled:
            return
        self.sent.append(alert)
        if len(self.sent) > self._max:
            overflow = len(self.sent) - self._max
            del self.sent[:overflow]

    def clear(self) -> None:
        self.sent.clear()
