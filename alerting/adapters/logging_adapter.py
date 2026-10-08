"""Stdlib logging adapter — dependency-free notification sink."""

from __future__ import annotations

import logging

from shared_contracts.models import AlertEvent

logger = logging.getLogger("intellishield.alerting.notify")


class LoggingNotificationAdapter:
    """Emits a structured log line for each alert (dashboard-independent)."""

    name = "logging"

    def __init__(self, *, level: int = logging.WARNING) -> None:
        self._level = level

    def send(self, alert: AlertEvent) -> None:
        sev = getattr(alert.severity, "value", alert.severity)
        atype = getattr(alert.alert_type, "value", alert.alert_type)
        logger.log(
            self._level,
            "[ALERT] id=%s severity=%s type=%s title=%s source=%s",
            alert.alert_id,
            sev,
            atype,
            alert.title,
            alert.source,
        )
