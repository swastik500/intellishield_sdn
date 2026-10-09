"""
Diagnostic test email function and CLI utility for IntelliShield SDN.

Sends a single labeled test email using the project's existing .env settings
and EmailNotificationAdapter without requiring a real network attack.
"""

from __future__ import annotations

import logging
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from shared_contracts.enums import AlertType, Severity
from shared_contracts.models import AlertEvent
from alerts.config import EmailAlertConfig, load_email_alert_config
from alerts.email_adapter import EmailNotificationAdapter

logger = logging.getLogger("intellishield.alerts.test_email")


def send_test_email(
    config: Optional[EmailAlertConfig] = None,
) -> Dict[str, Any]:
    """
    Send a single diagnostic test email to ALERT_EMAIL_TO.

    Returns a dict summary with status, recipient, host, and safe message.
    Never exposes passwords or sensitive credentials.
    """
    try:
        cfg = config or load_email_alert_config()

        if not cfg.is_configured:
            reasons = []
            if not cfg.enabled:
                reasons.append("ALERT_EMAIL_ENABLED!=true")
            if not cfg.recipient:
                reasons.append("ALERT_EMAIL_TO is empty")
            if not cfg.smtp_user:
                reasons.append("ALERT_SMTP_USER is empty")
            if not cfg.smtp_password:
                reasons.append("ALERT_SMTP_PASSWORD is empty")

            reason_str = ", ".join(reasons) if reasons else "unconfigured"
            return {
                "ok": False,
                "status": "UNCONFIGURED",
                "message": (
                    f"Email alerts are disabled or incomplete ({reason_str}). "
                    "Please set ALERT_EMAIL_ENABLED=true and configure recipient/SMTP credentials in .env."
                ),
                "recipient": cfg.recipient or "(unconfigured)",
                "smtp_host": cfg.smtp_host,
                "smtp_port": cfg.smtp_port,
                "smtp_user": cfg.smtp_user or "(unconfigured)",
            }

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Build a synthetic test AlertEvent
        test_alert = AlertEvent(
            alert_id=f"TEST-ALERT-{int(time.time())}",
            timestamp=datetime.now(timezone.utc),
            severity=Severity.LOW,
            alert_type=AlertType.SYSTEM,
            title="IntelliShield SDN — Diagnostic Test Email",
            message="Diagnostic test email triggered by administrator.",
            event_id=f"evt_test_{int(time.time())}",
            source="192.168.1.100",
            evidence={
                "attack_hint": "DIAGNOSTIC TEST",
                "target_ip": "10.0.0.1",
                "description": "This is a manual diagnostic test email to verify SMTP configuration and delivery.",
                "triggered_at": now_str,
                "verification_confidence": 1.0,
                "detector_source": "manual_test_trigger",
            },
        )

        adapter = EmailNotificationAdapter(config=cfg)
        success = adapter.send_sync(test_alert)

        if success:
            return {
                "ok": True,
                "status": "SENT",
                "message": f"Test email sent successfully to {cfg.recipient} via {cfg.smtp_host}:{cfg.smtp_port}.",
                "recipient": cfg.recipient,
                "smtp_host": cfg.smtp_host,
                "smtp_port": cfg.smtp_port,
                "smtp_user": cfg.smtp_user,
            }
        else:
            return {
                "ok": False,
                "status": "FAILED",
                "message": (
                    f"Failed to send email to {cfg.recipient}. Check SMTP credentials (App Password), "
                    f"port ({cfg.smtp_port}), host ({cfg.smtp_host}), and network connectivity."
                ),
                "recipient": cfg.recipient,
                "smtp_host": cfg.smtp_host,
                "smtp_port": cfg.smtp_port,
                "smtp_user": cfg.smtp_user,
            }

    except Exception as exc:  # noqa: BLE001
        # Sanitize exception message to prevent any accidental credential leak
        err_msg = str(exc)
        if config and config.smtp_password and config.smtp_password in err_msg:
            err_msg = err_msg.replace(config.smtp_password, "*****")

        logger.error("[TestEmail] Diagnostic email execution failed: %s", err_msg)
        return {
            "ok": False,
            "status": "ERROR",
            "message": f"An error occurred while sending test email: {err_msg}",
            "recipient": getattr(config, "recipient", "") or "(unknown)",
            "smtp_host": getattr(config, "smtp_host", "smtp.gmail.com"),
            "smtp_port": getattr(config, "smtp_port", 587),
        }


def main() -> None:
    """CLI entrypoint: python -m alerts.test_email"""
    print("=" * 64)
    print("IntelliShield SDN — Diagnostic Test Email")
    print("=" * 64)

    res = send_test_email()

    print(f"Status       : {res['status']}")
    print(f"Recipient    : {res.get('recipient', '(none)')}")
    print(f"SMTP Host    : {res.get('smtp_host', '')}:{res.get('smtp_port', '')}")
    print(f"SMTP User    : {res.get('smtp_user', '(none)')}")
    print(f"Message      : {res['message']}")
    print("=" * 64)

    if not res["ok"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
