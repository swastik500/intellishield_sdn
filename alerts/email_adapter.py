"""
Email notification adapter for IntelliShield SDN alert pipeline.

Implements the existing ``alerting.adapters.base.NotificationAdapter`` protocol
so it plugs directly into the R8 AlertManager dispatch chain.

Features:
  - Gmail SMTP with STARTTLS (App Password)
  - Per-attack-key cooldown to prevent duplicate emails
  - Async email sending via threading (never blocks detection pipeline)
  - Recovery emails when attacks end (optional)
  - All SMTP failures are logged but never propagate to detection/verification
  - Credentials are never logged or included in error messages

Integration:
  Registered alongside LoggingNotificationAdapter in controller/flow_monitor.py
  via the existing AlertManager.add_adapter() mechanism.
"""

from __future__ import annotations

import logging
import smtplib
import threading
import traceback
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from shared_contracts.models import AlertEvent
from alerts.config import EmailAlertConfig, load_email_alert_config
from alerts.cooldown import EmailCooldownTracker
from alerts.formatter import (
    format_attack_html,
    format_attack_subject,
    format_recovery_html,
    format_recovery_subject,
)

logger = logging.getLogger("intellishield.alerts.email")


def _build_cooldown_key(alert: AlertEvent) -> str:
    """Stable key for cooldown dedup — matches alert type + hint + source."""
    atype = str(getattr(alert.alert_type, "value", alert.alert_type))
    hint = ""
    if isinstance(alert.evidence, dict):
        hint = str(alert.evidence.get("attack_hint") or alert.evidence.get("attack_type_hint") or "")
    return f"email|{atype}|{alert.source or ''}|{hint}"


class EmailNotificationAdapter:
    """
    NotificationAdapter implementation that sends attack alert emails via Gmail SMTP.

    Conforms to the ``alerting.adapters.base.NotificationAdapter`` protocol:
      - ``name: str``
      - ``send(alert: AlertEvent) -> None``

    SMTP failures raise (caught by AlertManager._dispatch); never interrupt detection.
    """

    name = "email"

    def __init__(
        self,
        config: Optional[EmailAlertConfig] = None,
        cooldown: Optional[EmailCooldownTracker] = None,
    ) -> None:
        self._config = config or load_email_alert_config()
        self._cooldown = cooldown or EmailCooldownTracker(
            cooldown_seconds=self._config.cooldown_seconds
        )
        self.enabled: bool = self._config.is_configured
        self._send_count: int = 0
        self._fail_count: int = 0

        if self.enabled:
            logger.info(
                "[EmailAlert] Email notifications ENABLED  to=%s host=%s:%d cooldown=%ds",
                self._config.recipient,
                self._config.smtp_host,
                self._config.smtp_port,
                self._config.cooldown_seconds,
            )
        else:
            logger.info("[EmailAlert] Email notifications DISABLED (missing config or ALERT_EMAIL_ENABLED!=true)")

    @property
    def send_count(self) -> int:
        return self._send_count

    @property
    def fail_count(self) -> int:
        return self._fail_count

    def send(self, alert: AlertEvent) -> None:
        """
        Dispatch attack alert email (called by AlertManager._dispatch).

        Checks cooldown first; if within window, silently skips.
        Sends asynchronously via a daemon thread to avoid blocking detection.
        """
    def send(self, alert: AlertEvent) -> None:
        """
        Dispatch attack alert email (called by AlertManager._dispatch).

        Checks cooldown first; if within window, silently skips.
        Sends asynchronously via a daemon thread to avoid blocking detection.
        """
        if not self.enabled:
            logger.info("[EmailAlert] Email disabled/unconfigured — skipping alert_id=%s", alert.alert_id)
            return

        key = _build_cooldown_key(alert)
        if not self._cooldown.try_send(key):
            logger.info("[EmailAlert] Cooldown active for key=%s — skipping email for alert_id=%s", key, alert.alert_id)
            return

        logger.info("[EmailAlert] Triggering email dispatch for alert_id=%s title='%s' to=%s", alert.alert_id, alert.title, self._config.recipient)

        # Send in background thread — never block the detection pipeline
        thread = threading.Thread(
            target=self._send_email_safe,
            args=(alert, False),
            daemon=True,
            name="intellishield-email-alert",
        )
        thread.start()

    def send_recovery(self, alert: AlertEvent) -> None:
        """Send a recovery notification email (optional, called explicitly)."""
        if not self.enabled or not self._config.recovery_enabled:
            return

        thread = threading.Thread(
            target=self._send_email_safe,
            args=(alert, True),
            daemon=True,
            name="intellishield-email-recovery",
        )
        thread.start()

    def send_sync(self, alert: AlertEvent, is_recovery: bool = False) -> bool:
        """
        Synchronous send for testing — returns True on success.

        Production code should use send() / send_recovery() (async).
        """
        return self._send_email_safe(alert, is_recovery)

    def _send_email_safe(self, alert: AlertEvent, is_recovery: bool = False) -> bool:
        """Actual SMTP send — never raises, returns success bool."""
        try:
            cfg = self._config
            logger.info(
                "[EmailAlert] Connecting to SMTP host=%s:%d to send alert_id=%s to=%s",
                cfg.smtp_host,
                cfg.smtp_port,
                getattr(alert, "alert_id", "?"),
                cfg.recipient,
            )

            # Build MIME message
            msg = MIMEMultipart("alternative")
            msg["From"] = cfg.smtp_user
            msg["To"] = cfg.recipient

            if is_recovery:
                msg["Subject"] = format_recovery_subject(alert)
                html_body = format_recovery_html(alert)
            else:
                msg["Subject"] = format_attack_subject(alert)
                html_body = format_attack_html(alert)

            msg.attach(MIMEText(html_body, "html", "utf-8"))

            # Connect via STARTTLS
            with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(cfg.smtp_user, cfg.smtp_password)
                server.sendmail(cfg.smtp_user, [cfg.recipient], msg.as_string())

            self._send_count += 1
            logger.info(
                "[EmailAlert] ✅ Email DELIVERED (%s) to=%s alert_id=%s title='%s'",
                "recovery" if is_recovery else "attack",
                cfg.recipient,
                alert.alert_id,
                alert.title,
            )
            return True

        except Exception as exc:
            self._fail_count += 1
            err_str = str(exc)
            if self._config.smtp_password and self._config.smtp_password in err_str:
                err_str = err_str.replace(self._config.smtp_password, "*****")
            # Log error without exposing credentials
            logger.error(
                "[EmailAlert] ❌ Failed to send email alert_id=%s: %s",
                getattr(alert, "alert_id", "?"),
                err_str,
            )
            return False
