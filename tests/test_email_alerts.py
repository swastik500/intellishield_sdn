"""
Tests for IntelliShield SDN Email Alert Notifications.

Covers:
  1. EmailAlertConfig loading from environment
  2. EmailCooldownTracker dedup/cooldown logic
  3. Email formatter output (attack + recovery)
  4. EmailNotificationAdapter with mocked SMTP
  5. Cooldown prevents duplicate emails
  6. Disabled alerts skip entirely
  7. SMTP failure handling (never propagates)
  8. Recovery email functionality
  9. Async send via threading
  10. Integration with existing AlertManager dispatch

All SMTP calls are mocked — no real emails are sent.
"""

from __future__ import annotations

import os
import threading
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

from shared_contracts.enums import AlertType, Severity, VerificationStatus
from shared_contracts.models import AlertEvent, VerificationResult

# Module under test
from alerts.config import EmailAlertConfig, load_email_alert_config
from alerts.cooldown import EmailCooldownTracker
from alerts.email_adapter import EmailNotificationAdapter, _build_cooldown_key
from alerts.formatter import (
    format_attack_html,
    format_attack_subject,
    format_recovery_html,
    format_recovery_subject,
)
from alerts import build_email_adapter, send_test_email


def _make_alert(
    alert_id: str = "alert_001",
    severity: Severity = Severity.HIGH,
    title: str = "DDoS Flood Detected on Switch s1",
    attack_hint: str = "DDoS_Flood",
    source: str = "verification",
    event_id: str = "evt_abc123",
) -> AlertEvent:
    """Build a realistic AlertEvent for testing."""
    return AlertEvent(
        alert_id=alert_id,
        timestamp=datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc),
        severity=severity,
        alert_type=AlertType.DETECTION,
        title=title,
        message="Anomalous traffic pattern detected — mitigation recommended.",
        event_id=event_id,
        source=source,
        evidence={
            "attack_hint": attack_hint,
            "detector_path": "r6_fusion",
            "fusion_linked": True,
            "fusion_id": "fuse_xyz",
            "fused_decision": "ATTACK",
            "fused_confidence": 0.92,
            "correlation_linked": True,
            "correlation_id": "corr_123",
            "correlation_score": 0.85,
            "rca_linked": True,
        },
        rca_report_id="rca_456",
    )


def _make_config(**overrides) -> EmailAlertConfig:
    """Build a test config with all required fields populated."""
    defaults = dict(
        enabled=True,
        recipient="test@example.com",
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        smtp_user="sender@gmail.com",
        smtp_password="test_app_password",
        cooldown_seconds=300,
        recovery_enabled=False,
    )
    defaults.update(overrides)
    return EmailAlertConfig(**defaults)


class TestEmailAlertConfig(unittest.TestCase):
    """Test environment-based configuration loading."""

    def test_default_config_disabled(self):
        """Default config (no env vars) should be disabled."""
        cfg = EmailAlertConfig()
        self.assertFalse(cfg.enabled)
        self.assertFalse(cfg.is_configured)

    def test_configured_when_all_fields_set(self):
        cfg = _make_config()
        self.assertTrue(cfg.enabled)
        self.assertTrue(cfg.is_configured)

    def test_not_configured_when_password_missing(self):
        cfg = _make_config(smtp_password="")
        self.assertFalse(cfg.is_configured)

    def test_not_configured_when_disabled(self):
        cfg = _make_config(enabled=False)
        self.assertFalse(cfg.is_configured)

    def test_repr_hides_password(self):
        cfg = _make_config(smtp_password="super_secret_123")
        r = repr(cfg)
        self.assertNotIn("super_secret_123", r)
        self.assertIn("***", r)

    @patch.dict(os.environ, {
        "ALERT_EMAIL_ENABLED": "true",
        "ALERT_EMAIL_TO": "ops@example.com",
        "ALERT_SMTP_HOST": "smtp.gmail.com",
        "ALERT_SMTP_PORT": "587",
        "ALERT_SMTP_USER": "sender@gmail.com",
        "ALERT_SMTP_PASSWORD": "app_pass_xyz",
        "ALERT_EMAIL_COOLDOWN_SECONDS": "120",
        "ALERT_EMAIL_RECOVERY": "yes",
    })
    def test_load_from_env(self):
        cfg = load_email_alert_config()
        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.recipient, "ops@example.com")
        self.assertEqual(cfg.smtp_port, 587)
        self.assertEqual(cfg.cooldown_seconds, 120)
        self.assertTrue(cfg.recovery_enabled)
        self.assertTrue(cfg.is_configured)


class TestEmailCooldownTracker(unittest.TestCase):
    """Test cooldown deduplication."""

    def test_first_send_allowed(self):
        tracker = EmailCooldownTracker(cooldown_seconds=60)
        self.assertTrue(tracker.try_send("key_a"))

    def test_duplicate_within_cooldown_blocked(self):
        tracker = EmailCooldownTracker(cooldown_seconds=60)
        self.assertTrue(tracker.try_send("key_a"))
        self.assertFalse(tracker.try_send("key_a"))

    def test_different_keys_independent(self):
        tracker = EmailCooldownTracker(cooldown_seconds=60)
        self.assertTrue(tracker.try_send("key_a"))
        self.assertTrue(tracker.try_send("key_b"))

    def test_zero_cooldown_always_allows(self):
        tracker = EmailCooldownTracker(cooldown_seconds=0)
        self.assertTrue(tracker.try_send("key_a"))
        self.assertTrue(tracker.try_send("key_a"))

    def test_clear_resets(self):
        tracker = EmailCooldownTracker(cooldown_seconds=9999)
        tracker.try_send("key_a")
        tracker.clear()
        self.assertTrue(tracker.try_send("key_a"))

    def test_may_send_does_not_record(self):
        tracker = EmailCooldownTracker(cooldown_seconds=60)
        self.assertTrue(tracker.may_send("key_x"))
        self.assertTrue(tracker.may_send("key_x"))  # still allowed — no record

    def test_active_keys_count(self):
        tracker = EmailCooldownTracker(cooldown_seconds=60)
        tracker.try_send("a")
        tracker.try_send("b")
        self.assertEqual(tracker.active_keys(), 2)


class TestEmailFormatter(unittest.TestCase):
    """Test email body formatting."""

    def test_attack_subject_contains_severity(self):
        alert = _make_alert(severity=Severity.CRITICAL)
        subject = format_attack_subject(alert)
        self.assertIn("CRITICAL", subject)
        self.assertIn("IntelliShield", subject)

    def test_attack_html_contains_key_fields(self):
        alert = _make_alert()
        html = format_attack_html(alert)
        self.assertIn("alert_001", html)
        self.assertIn("DDoS_Flood", html)
        self.assertIn("r6_fusion", html)
        self.assertIn("IntelliShield SDN", html)
        self.assertIn("evt_abc123", html)

    def test_attack_html_includes_fusion_refs(self):
        alert = _make_alert()
        html = format_attack_html(alert)
        self.assertIn("R6 Fusion Decision", html)
        self.assertIn("ATTACK", html)
        self.assertIn("fuse_xyz", html)

    def test_attack_html_includes_correlation_refs(self):
        alert = _make_alert()
        html = format_attack_html(alert)
        self.assertIn("R4 Correlation", html)
        self.assertIn("corr_123", html)

    def test_attack_html_includes_rca_ref(self):
        alert = _make_alert()
        html = format_attack_html(alert)
        self.assertIn("R5 RCA Report", html)
        self.assertIn("rca_456", html)

    def test_recovery_subject(self):
        alert = _make_alert()
        subject = format_recovery_subject(alert)
        self.assertIn("RECOVERY", subject)

    def test_recovery_html(self):
        alert = _make_alert()
        html = format_recovery_html(alert)
        self.assertIn("Attack Recovered", html)
        self.assertIn("alert_001", html)


class TestEmailNotificationAdapter(unittest.TestCase):
    """Test adapter with mocked SMTP."""

    def _make_adapter(self, **config_overrides) -> EmailNotificationAdapter:
        cfg = _make_config(**config_overrides)
        return EmailNotificationAdapter(config=cfg)

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_send_sync_success(self, mock_smtp_cls):
        """Successful synchronous email send via mocked SMTP."""
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        adapter = self._make_adapter()
        alert = _make_alert()
        result = adapter.send_sync(alert)

        self.assertTrue(result)
        self.assertEqual(adapter.send_count, 1)
        self.assertEqual(adapter.fail_count, 0)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once()
        mock_server.sendmail.assert_called_once()

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_send_sync_smtp_failure(self, mock_smtp_cls):
        """SMTP failure is caught and logged, never propagates."""
        mock_smtp_cls.return_value.__enter__ = MagicMock(
            side_effect=smtplib.SMTPAuthenticationError(535, b"Bad credentials")
        )
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        adapter = self._make_adapter()
        alert = _make_alert()

        # Should NOT raise
        result = adapter.send_sync(alert)
        self.assertFalse(result)
        self.assertEqual(adapter.fail_count, 1)
        self.assertEqual(adapter.send_count, 0)

    def test_disabled_adapter_skips(self):
        """When not configured, send() does nothing."""
        adapter = self._make_adapter(enabled=False)
        self.assertFalse(adapter.enabled)

        alert = _make_alert()
        adapter.send(alert)  # should not raise or send
        self.assertEqual(adapter.send_count, 0)

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_cooldown_prevents_duplicate(self, mock_smtp_cls):
        """Second send for same attack key within cooldown is skipped."""
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        adapter = self._make_adapter(cooldown_seconds=9999)
        alert = _make_alert()

        # Manually consume the cooldown key first
        key = _build_cooldown_key(alert)
        self.assertTrue(adapter._cooldown.try_send(key))

        # Second attempt should be blocked
        self.assertFalse(adapter._cooldown.try_send(key))
        self.assertFalse(adapter._cooldown.may_send(key))

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_recovery_email_when_enabled(self, mock_smtp_cls):
        """Recovery email is sent when recovery_enabled=True."""
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        adapter = self._make_adapter(recovery_enabled=True)
        alert = _make_alert()
        result = adapter.send_sync(alert, is_recovery=True)

        self.assertTrue(result)
        # Check recovery subject was used (via sendmail call)
        call_args = mock_server.sendmail.call_args
        sent_msg = call_args[0][2]
        self.assertIn("RECOVERY", sent_msg)

    def test_recovery_email_disabled_by_default(self):
        """Recovery emails are not sent when recovery_enabled=False."""
        adapter = self._make_adapter(recovery_enabled=False)
        alert = _make_alert()
        adapter.send_recovery(alert)  # should silently skip
        self.assertEqual(adapter.send_count, 0)

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_async_send_uses_thread(self, mock_smtp_cls):
        """send() dispatches email in a daemon thread."""
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        adapter = self._make_adapter(cooldown_seconds=0)
        alert = _make_alert()
        adapter.send(alert)

        # Wait briefly for daemon thread to complete
        time.sleep(0.5)
        self.assertGreaterEqual(adapter.send_count, 1)

    def test_cooldown_key_stability(self):
        """Same alert produces the same cooldown key."""
        alert = _make_alert()
        k1 = _build_cooldown_key(alert)
        k2 = _build_cooldown_key(alert)
        self.assertEqual(k1, k2)
        self.assertIn("DETECTION", k1)
        self.assertIn("DDoS_Flood", k1)


class TestBuildEmailAdapterFactory(unittest.TestCase):
    """Test the safe factory function."""

    @patch.dict(os.environ, {
        "ALERT_EMAIL_ENABLED": "true",
        "ALERT_EMAIL_TO": "test@example.com",
        "ALERT_SMTP_USER": "sender@gmail.com",
        "ALERT_SMTP_PASSWORD": "app_pass",
    })
    def test_factory_returns_adapter_when_configured(self):
        adapter = build_email_adapter()
        self.assertIsNotNone(adapter)
        self.assertIsInstance(adapter, EmailNotificationAdapter)

    @patch.dict(os.environ, {"ALERT_EMAIL_ENABLED": "false"}, clear=False)
    def test_factory_returns_none_when_disabled(self):
        cfg = EmailAlertConfig(enabled=False)
        adapter = build_email_adapter(config=cfg)
        self.assertIsNone(adapter)

    def test_factory_returns_none_on_missing_config(self):
        cfg = EmailAlertConfig()  # all defaults — not configured
        adapter = build_email_adapter(config=cfg)
        self.assertIsNone(adapter)


class TestAlertManagerIntegration(unittest.TestCase):
    """Test EmailNotificationAdapter integrates with existing AlertManager."""

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_manager_dispatches_to_email_adapter(self, mock_smtp_cls):
        """Email adapter receives alerts through the standard AlertManager flow."""
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        from alerting import AlertManager, AlertingConfig, LoggingNotificationAdapter

        cfg = _make_config(cooldown_seconds=0)
        email_adapter = EmailNotificationAdapter(config=cfg)

        # Build AlertManager with both existing + new adapters
        manager = AlertManager(
            config=AlertingConfig(
                enabled=True,
                dedup_enabled=False,  # disable dedup for this test
                rate_limit_enabled=False,
            ),
            adapters=[LoggingNotificationAdapter(), email_adapter],
        )

        alert = _make_alert()
        result = manager.process_alert(alert)

        from alerting.manager import AlertDisposition
        self.assertEqual(result.disposition, AlertDisposition.NEW)
        self.assertEqual(result.adapters_ok, 2)  # logging + email
        self.assertEqual(result.adapters_failed, 0)

        # Wait for async thread
        time.sleep(0.5)


class TestSendTestEmail(unittest.TestCase):
    """Test send_test_email diagnostic utility."""

    def test_send_test_email_unconfigured(self):
        cfg = EmailAlertConfig(enabled=False)
        res = send_test_email(config=cfg)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "UNCONFIGURED")
        self.assertIn("disabled or incomplete", res["message"])

    @patch("smtplib.SMTP")
    def test_send_test_email_success(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        cfg = _make_config()
        res = send_test_email(config=cfg)

        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], "SENT")
        self.assertIn("test@example.com", res["message"])
        self.assertNotIn("secret_app_password_123", str(res))
        mock_server.sendmail.assert_called_once()

    @patch("smtplib.SMTP")
    def test_send_test_email_smtp_failure(self, mock_smtp_cls):
        mock_smtp_cls.side_effect = Exception("SMTP auth error password=secret_app_password_123")

        cfg = _make_config()
        res = send_test_email(config=cfg)

        self.assertFalse(res["ok"])
        self.assertIn(res["status"], ("FAILED", "ERROR"))
        self.assertNotIn("secret_app_password_123", str(res))


class TestEmailAlertApiEndpoints(unittest.TestCase):
    """Test FastApi endpoints /api/alerts/email/status and /api/alerts/test-email."""

    def setUp(self):
        from dashboard.api import app
        from fastapi.testclient import TestClient
        self.client = TestClient(app)

    def test_get_email_alert_status_endpoint(self):
        r = self.client.get("/api/alerts/email/status")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn("enabled", data)
        self.assertIn("is_configured", data)
        self.assertIn("recipient", data)
        self.assertNotIn("smtp_password", data)

    @patch("smtplib.SMTP")
    def test_post_test_email_endpoint(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        with patch("alerts.config.load_email_alert_config", return_value=_make_config()):
            r = self.client.post("/api/alerts/test-email")
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertIn("ok", data)
            self.assertIn("status", data)
            self.assertNotIn("secret_app_password_123", str(data))


import smtplib  # needed for SMTPAuthenticationError reference in test


if __name__ == "__main__":
    unittest.main()
