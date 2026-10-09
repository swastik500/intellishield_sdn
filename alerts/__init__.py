"""
IntelliShield SDN — Email Alert Notifications.

Isolated email notification module for confirmed-attack alerts
from the R6 Fusion → R7 Verification pipeline.

Quick start:
    from alerts import build_email_adapter

    adapter = build_email_adapter()
    if adapter is not None:
        alert_manager.add_adapter(adapter)
"""

from __future__ import annotations

import logging
from typing import Optional

from alerts.config import EmailAlertConfig, load_email_alert_config
from alerts.cooldown import EmailCooldownTracker
from alerts.email_adapter import EmailNotificationAdapter
from alerts.formatter import (
    format_attack_html,
    format_attack_subject,
    format_recovery_html,
    format_recovery_subject,
)

from alerts.test_email import send_test_email

logger = logging.getLogger("intellishield.alerts")

__all__ = [
    "EmailAlertConfig",
    "EmailCooldownTracker",
    "EmailNotificationAdapter",
    "build_email_adapter",
    "format_attack_html",
    "format_attack_subject",
    "format_recovery_html",
    "format_recovery_subject",
    "load_email_alert_config",
    "send_test_email",
]


def build_email_adapter(
    config: Optional[EmailAlertConfig] = None,
) -> Optional[EmailNotificationAdapter]:
    """
    Factory: build and return an EmailNotificationAdapter if configuration
    is valid and ALERT_EMAIL_ENABLED=true, otherwise return None.

    Never raises — safe for controller init.
    """
    try:
        cfg = config or load_email_alert_config()
        if not cfg.is_configured:
            logger.info("[EmailAlert] Email alerts disabled or unconfigured — adapter not created")
            return None
        return EmailNotificationAdapter(config=cfg)
    except Exception as exc:
        logger.error("[EmailAlert] Failed to build email adapter: %s", exc)
        return None
