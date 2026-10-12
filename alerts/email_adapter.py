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
  - Tracks delivery status per attempt: queued, sending, sent, failed, suppressed_by_cooldown

Integration:
  Registered alongside LoggingNotificationAdapter in controller/flow_monitor.py
  via the existing AlertManager.add_adapter() mechanism.
"""

from __future__ import annotations

import logging
import smtplib
import threading
import time
import traceback
import uuid
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from typing import Optional, Dict, Callable

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


class DeliveryStatus(str, Enum):
    """Terminal delivery status for an email attempt."""
    QUEUED = "queued"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"
    SUPPRESSED_BY_COOLDOWN = "suppressed_by_cooldown"


@dataclass
class EmailAttempt:
    """Tracks a single email send attempt."""
    attempt_id: str
    alert_id: str
    key: str
    is_recovery: bool
    status: DeliveryStatus = DeliveryStatus.QUEUED
    error: Optional[str] = None
    start_time: float = 0.0
    end_time: Optional[float] = None
    _event: threading.Event = None

    def __post_init__(self):
        if self._event is None:
            self._event = threading.Event()

    def wait(self, timeout: float = 30.0) -> bool:
        """Wait for attempt to reach terminal state. Returns True if completed."""
        return self._event.wait(timeout)

    def mark_sending(self) -> None:
        self.status = DeliveryStatus.SENDING

    def mark_sent(self) -> None:
        self.status = DeliveryStatus.SENT
        self.end_time = time.monotonic()
        self._event.set()

    def mark_failed(self, error: str) -> None:
        self.status = DeliveryStatus.FAILED
        self.error = error
        self.end_time = time.monotonic()
        self._event.set()


def _build_cooldown_key(alert: AlertEvent) -> str:
    """Stable key for cooldown dedup — matches alert type + hint + source."""
    atype = str(getattr(alert.alert_type, "value", alert.alert_type))
    hint = ""
    if isinstance(alert.evidence, dict):
        hint = str(alert.evidence.get("attack_hint") or alert.evidence.get("attack_type_hint") or "")
    return f"email|{atype}|{alert.source or ''}|{hint}"


def _sanitize_error(exc: Exception, secret: Optional[str] = None) -> str:
    """Return a safe exception type/message without leaking credentials."""
    import re

    msg = str(exc) or type(exc).__name__
    if secret and secret in msg:
        msg = msg.replace(secret, "*****")
    # Redact values assigned to common credential keys, e.g.
    # "password=xyz", "token: abc", "api_key=123".
    msg = re.sub(
        r"(?i)(password|passwd|secret|token|api[_-]?key|credential|"
        r"authorization|private[_-]?key)\s*[=:]\s*\S+",
        r"\1=*****",
        msg,
    )
    # Keep the exception class + sanitized message, bounded in length.
    safe = f"{type(exc).__name__}: {msg}"
    return safe[:500]


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
        self._lock = threading.Lock()
        self._attempts: Dict[str, EmailAttempt] = {}
        self._completion_callbacks: Dict[str, Callable[[EmailAttempt], None]] = {}

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
        with self._lock:
            return self._send_count

    @property
    def fail_count(self) -> int:
        with self._lock:
            return self._fail_count

    def _dispatch_async(self, alert: AlertEvent, is_recovery: bool = False) -> Optional[str]:
        """
        Reserve the cooldown key and spawn the async email worker.

        Returns the attempt_id (str) when an attempt was queued, or None
        when the adapter is disabled or the key is reserved/cooled down.
        Never blocks; the worker records a terminal outcome on every path.
        """
        if not self.enabled:
            logger.info("[DIAG] Email disabled/unconfigured — skipping alert_id=%s", alert.alert_id)
            return None

        key = _build_cooldown_key(alert)

        # Reserve the cooldown key for this attempt (thread-safe).
        # A failed attempt releases the reservation so a retry is possible;
        # a successful attempt confirms it, starting the cooldown window.
        if not self._cooldown.reserve(key):
            logger.info(
                "[DIAG] Cooldown active or reserved for key=%s — skipping email for alert_id=%s",
                key, alert.alert_id,
            )
            return None

        logger.info(
            "[DIAG] Triggering email dispatch for alert_id=%s title='%s' to=%s",
            alert.alert_id, alert.title, self._config.recipient,
        )

        attempt = EmailAttempt(
            attempt_id=str(uuid.uuid4())[:8],
            alert_id=alert.alert_id,
            key=key,
            is_recovery=is_recovery,
            start_time=time.monotonic(),
        )
        with self._lock:
            self._attempts[attempt.attempt_id] = attempt

        thread = threading.Thread(
            target=self._send_email_worker,
            args=(attempt, alert, is_recovery),
            daemon=True,
            name=(
                "intellishield-email-recovery" if is_recovery else "intellishield-email-alert"
            ),
        )
        thread.start()
        return attempt.attempt_id

    def send(self, alert: AlertEvent) -> Optional[str]:
        """
        Dispatch attack alert email (called by AlertManager._dispatch).

        Checks cooldown first; if within window, silently skips.
        Sends asynchronously via a daemon thread to avoid blocking detection.

        Returns the attempt_id when queued, or None when suppressed/disabled.
        Callers that ignore the return value are unaffected (additive).
        """
        return self._dispatch_async(alert, is_recovery=False)

    def send_recovery(self, alert: AlertEvent) -> Optional[str]:
        """Send a recovery notification email (optional, called explicitly)."""
        if not self._config.recovery_enabled:
            return None
        return self._dispatch_async(alert, is_recovery=True)

    def send_sync(self, alert: AlertEvent, is_recovery: bool = False) -> bool:
        """
        Synchronous send for testing — returns True on success.

        Production code should use send() / send_recovery() (async).
        """
        if not self.enabled:
            logger.info("[DIAG] Email disabled/unconfigured — skipping sync send for alert_id=%s", alert.alert_id)
            return False

        key = _build_cooldown_key(alert)

        # For sync send, reserve the key and send directly
        if not self._cooldown.reserve(key):
            logger.info("[DIAG] Cooldown active or reserved for key=%s — skipping sync send for alert_id=%s", key, alert.alert_id)
            return False

        try:
            error = self._send_email_safe(alert, is_recovery)
            if error is None:
                self._cooldown.confirm(key)
                with self._lock:
                    self._send_count += 1
                return True
            self._cooldown.release(key)
            with self._lock:
                self._fail_count += 1
            return False
        except Exception:
            self._cooldown.release(key)
            with self._lock:
                self._fail_count += 1
            return False

    def wait_for_attempt(self, attempt_id: str, timeout: float = 30.0) -> Optional[EmailAttempt]:
        """Wait for a specific attempt to complete. Returns the attempt or None if not found."""
        attempt = self._attempts.get(attempt_id)
        if attempt is None:
            return None
        attempt.wait(timeout)
        return attempt

    def get_attempt(self, attempt_id: str) -> Optional[EmailAttempt]:
        """Get attempt by ID without waiting."""
        return self._attempts.get(attempt_id)

    def _send_email_worker(self, attempt: EmailAttempt, alert: AlertEvent, is_recovery: bool) -> None:
        """Worker thread: send email and record a terminal outcome on every path."""
        try:
            attempt.mark_sending()
            error = self._send_email_safe(alert, is_recovery)
            if error is None:
                # SMTP accepted the message — only now count a successful send.
                attempt.mark_sent()
                self._cooldown.confirm(attempt.key)
                with self._lock:
                    self._send_count += 1
            else:
                attempt.mark_failed(error)
                # Release the reservation so a subsequent alert can retry.
                self._cooldown.release(attempt.key)
                with self._lock:
                    self._fail_count += 1
        except Exception as exc:  # noqa: BLE001 — never leave an attempt pending
            sanitized = _sanitize_error(exc, self._config.smtp_password)
            attempt.mark_failed(sanitized)
            try:
                self._cooldown.release(attempt.key)
            except Exception:
                pass
            with self._lock:
                self._fail_count += 1
            logger.error(
                "[DIAG] Email worker unexpected failure alert_id=%s: %s",
                getattr(alert, "alert_id", "?"),
                sanitized,
            )

        # Clean up attempt after a delay to allow inspection.
        def _cleanup():
            time.sleep(10.0)  # Keep for 10s for diagnostics
            with self._lock:
                self._attempts.pop(attempt.attempt_id, None)

        threading.Thread(target=_cleanup, daemon=True).start()

    def _send_email_safe(self, alert: AlertEvent, is_recovery: bool = False) -> Optional[str]:
        """
        Actual SMTP send — never raises.

        Returns None on success, or a sanitized error string on failure.
        Credentials are never included in the returned error.
        """
        try:
            cfg = self._config
            logger.info(
                "[DIAG] Connecting to SMTP host=%s:%d to send alert_id=%s to=%s",
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

            logger.info(
                "[DIAG] ✅ Email DELIVERED (%s) to=%s alert_id=%s title='%s'",
                "recovery" if is_recovery else "attack",
                cfg.recipient,
                alert.alert_id,
                alert.title,
            )
            return None

        except Exception as exc:
            sanitized = _sanitize_error(exc, self._config.smtp_password)
            # Log error without exposing credentials
            logger.error(
                "[DIAG] ❌ Failed to send email alert_id=%s: %s",
                getattr(alert, "alert_id", "?"),
                sanitized,
            )
            return sanitized
