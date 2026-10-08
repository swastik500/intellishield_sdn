"""Notification adapter protocol (R8.1)."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from shared_contracts.models import AlertEvent


@runtime_checkable
class NotificationAdapter(Protocol):
    """
    Minimal notification sink.

    Implementations MUST:
      - never raise into the controller (manager also isolates)
      - never mutate AlertEvent
      - never read secrets from alert payloads
    """

    name: str

    def send(self, alert: AlertEvent) -> None:
        """Deliver one alert. May raise; manager records and continues."""
        ...
