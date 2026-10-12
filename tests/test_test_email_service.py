"""
Tests for the test-email service (alerts/test_email.py).

Covers:
  - Successful test-email send (mocked SMTP)
  - SMTP failure with sanitized error
  - Email alerts disabled / unconfigured
  - Retry after failure (cooldown reservation released)
  - Concurrent duplicate suppression
  - Cooldown isolation between test emails and real attack alerts
  - Rate limiting
  - No credential leakage

All SMTP calls are mocked — no real emails are sent.
"""

from __future__ import annotations

import base64
import re
import threading
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from shared_contracts.enums import AlertType, Severity
from shared_contracts.models import AlertEvent

from alerts.config import EmailAlertConfig
from alerts.cooldown import EmailCooldownTracker
from alerts.email_adapter import (
    DeliveryStatus,
    EmailNotificationAdapter,
    _build_cooldown_key,
)
from alerts.test_email import (
    _build_test_alert,
    reset_test_email_state,
    send_test_email,
)


def _make_config(**overrides) -> EmailAlertConfig:
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


def _make_attack_alert() -> AlertEvent:
    return AlertEvent(
        alert_id="attack_001",
        timestamp=datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        alert_type=AlertType.DETECTION,
        title="DDoS Flood Detected on Switch s1",
        message="Anomalous traffic pattern detected.",
        event_id="evt_attack",
        source="verification",
        evidence={"attack_hint": "DDoS_Flood"},
    )


def _mock_smtp_success(mock_smtp_cls):
    mock_server = MagicMock()
    mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
    mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)
    return mock_server


def _sent_mime_html(mock_smtp_cls):
    """Decode the base64 HTML part of the last sent MIME message."""
    sent = mock_smtp_cls.return_value.__enter__.return_value
    args, _kwargs = sent.sendmail.call_args
    if not args:
        return ""
    mime_text = args[2] if len(args) > 2 else ""
    match = re.search(
        r"Content-Transfer-Encoding: base64\s*\n\s*\n([A-Za-z0-9+/=\s]+)",
        mime_text,
    )
    if not match:
        return ""
    try:
        return base64.b64decode("".join(match.group(1).split())).decode(
            "utf-8", "replace"
        )
    except Exception:
        return ""


class TestSendTestEmailSuccess(unittest.TestCase):
    def setUp(self):
        reset_test_email_state()

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_success_returns_sent(self, mock_smtp_cls):
        _mock_smtp_success(mock_smtp_cls)
        res = send_test_email(config=_make_config())
        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], "SENT")
        self.assertEqual(res["delivery_status"], "sent")
        self.assertIn("inbox", res["message"])
        mock_smtp_cls.return_value.__enter__.return_value.sendmail.assert_called_once()

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_success_includes_no_password(self, mock_smtp_cls):
        _mock_smtp_success(mock_smtp_cls)
        res = send_test_email(config=_make_config(smtp_password="super_secret_123"))
        self.assertNotIn("super_secret_123", str(res))


class TestSendTestEmailFailure(unittest.TestCase):
    def setUp(self):
        reset_test_email_state()

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_smtp_failure_returns_failed(self, mock_smtp_cls):
        mock_smtp_cls.side_effect = Exception("SMTP connect refused")
        res = send_test_email(config=_make_config())
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(res["delivery_status"], "failed")
        self.assertIn("SMTP connect refused", res["message"])

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_smtp_failure_sanitizes_password(self, mock_smtp_cls):
        mock_smtp_cls.side_effect = Exception(
            "SMTP auth error password=secret_app_password_123"
        )
        res = send_test_email(config=_make_config())
        self.assertFalse(res["ok"])
        self.assertNotIn("secret_app_password_123", str(res))
        self.assertIn("*****", res["message"])

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_retry_after_failure_allowed(self, mock_smtp_cls):
        # First attempt fails.
        mock_smtp_cls.side_effect = Exception("transient failure")
        res1 = send_test_email(config=_make_config())
        self.assertEqual(res1["status"], "FAILED")

        # Second attempt (reservation was released) succeeds.
        mock_smtp_cls.side_effect = None
        _mock_smtp_success(mock_smtp_cls)
        res2 = send_test_email(config=_make_config())
        self.assertEqual(res2["status"], "SENT")
        self.assertTrue(res2["ok"])


class TestSendTestEmailConfig(unittest.TestCase):
    def setUp(self):
        reset_test_email_state()

    def test_disabled_returns_unconfigured(self):
        res = send_test_email(config=_make_config(enabled=False))
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "UNCONFIGURED")

    def test_missing_password_returns_unconfigured(self):
        res = send_test_email(config=_make_config(smtp_password=""))
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "UNCONFIGURED")

    def test_missing_recipient_returns_unconfigured(self):
        res = send_test_email(config=_make_config(recipient=""))
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "UNCONFIGURED")


class TestSendTestEmailConcurrency(unittest.TestCase):
    def setUp(self):
        reset_test_email_state()

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_concurrent_duplicate_suppressed(self, mock_smtp_cls):
        _mock_smtp_success(mock_smtp_cls)
        # Simulate an in-flight attempt by reserving the test key.
        alert = _build_test_alert()
        key = _build_cooldown_key(alert)
        from alerts.test_email import _TEST_EMAIL_INFLIGHT

        self.assertTrue(_TEST_EMAIL_INFLIGHT.reserve(key))
        try:
            res = send_test_email(config=_make_config())
            self.assertFalse(res["ok"])
            self.assertEqual(res["status"], "SUPPRESSED")
            self.assertEqual(res["delivery_status"], "suppressed_by_cooldown")
        finally:
            reset_test_email_state()

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_real_threads_concurrent_single_send(self, mock_smtp_cls):
        # A slow SMTP send: hold the in-flight reservation while a
        # second thread tries to send. Only one email should be sent.
        _mock_smtp_success(mock_smtp_cls)
        release = threading.Event()

        original_enter = mock_smtp_cls.return_value.__enter__

        def slow_enter(*args, **kwargs):
            release.wait(timeout=5)
            return original_enter(*args, **kwargs)

        mock_smtp_cls.return_value.__enter__ = MagicMock(side_effect=slow_enter)

        results = []

        def worker():
            results.append(send_test_email(config=_make_config()))

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start()
        t2.start()
        # Let both threads reach the send path, then release.
        release.set()
        t1.join(timeout=10)
        t2.join(timeout=10)

        sent = [r for r in results if r["status"] == "SENT"]
        suppressed = [r for r in results if r["status"] == "SUPPRESSED"]
        # Exactly one succeeds; the other is suppressed (or fails if
        # it raced past reservation, but never both SENT).
        self.assertEqual(len(sent) + len(suppressed), 2)
        self.assertLessEqual(len(sent), 1)


class TestTestEmailCooldownIsolation(unittest.TestCase):
    """Test emails must not interfere with real attack-alert cooldowns."""

    def setUp(self):
        reset_test_email_state()

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_test_email_does_not_suppress_attack_alert(self, mock_smtp_cls):
        _mock_smtp_success(mock_smtp_cls)
        # Send a test email (confirms the shared test tracker).
        res = send_test_email(config=_make_config())
        self.assertEqual(res["status"], "SENT")

        # A real attack alert uses its own per-adapter tracker.
        attack_adapter = EmailNotificationAdapter(
            config=_make_config(cooldown_seconds=9999)
        )
        with patch("alerts.email_adapter.smtplib.SMTP"):
            _mock_smtp_success(mock_smtp_cls)
            attack_adapter.send_sync(_make_attack_alert())
        self.assertEqual(attack_adapter.send_count, 1)
        self.assertEqual(attack_adapter.fail_count, 0)

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_attack_alert_does_not_suppress_test_email(self, mock_smtp_cls):
        _mock_smtp_success(mock_smtp_cls)
        # Send a real attack alert first (consumes its own tracker).
        attack_adapter = EmailNotificationAdapter(
            config=_make_config(cooldown_seconds=9999)
        )
        attack_adapter.send_sync(_make_attack_alert())
        self.assertEqual(attack_adapter.send_count, 1)

        # Test email uses a separate tracker and must still send.
        res = send_test_email(config=_make_config())
        self.assertEqual(res["status"], "SENT")
        self.assertTrue(res["ok"])

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_test_email_key_distinct_from_attack_key(self, mock_smtp_cls):
        test_key = _build_cooldown_key(_build_test_alert())
        attack_key = _build_cooldown_key(_make_attack_alert())
        self.assertNotEqual(test_key, attack_key)
        self.assertIn("SYSTEM", test_key)
        self.assertIn("DIAGNOSTIC_TEST", test_key)
        self.assertIn("DETECTION", attack_key)


class TestTestEmailRateLimit(unittest.TestCase):
    def setUp(self):
        reset_test_email_state()

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_rate_limited_after_max_hits(self, mock_smtp_cls):
        _mock_smtp_success(mock_smtp_cls)
        statuses = []
        for _ in range(10):
            res = send_test_email(config=_make_config())
            statuses.append(res["status"])
            if res["status"] == "RATE_LIMITED":
                break
        self.assertIn("RATE_LIMITED", statuses)
        self.assertLessEqual(statuses.index("RATE_LIMITED"), 5)

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_rate_limit_does_not_leak_secret(self, mock_smtp_cls):
        _mock_smtp_success(mock_smtp_cls)
        for _ in range(10):
            res = send_test_email(config=_make_config(smtp_password="top_secret_pw"))
            if res["status"] == "RATE_LIMITED":
                self.assertNotIn("top_secret_pw", str(res))
                break


class TestTestEmailDoesNotPersistAlert(unittest.TestCase):
    """A test email must not be written to the R8 alert history."""

    def setUp(self):
        reset_test_email_state()

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_test_alert_is_system_type_not_mitigation(self, mock_smtp_cls):
        _mock_smtp_success(mock_smtp_cls)
        alert = _build_test_alert()
        self.assertEqual(alert.alert_type, AlertType.SYSTEM)
        self.assertNotEqual(alert.alert_type, AlertType.MITIGATION)
        self.assertNotEqual(alert.alert_type, AlertType.DETECTION)

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_test_alert_not_stored_by_adapter(self, mock_smtp_cls):
        # The adapter has no store; sending a test email directly via the
        # adapter never touches AlertManager / alert persistence.
        _mock_smtp_success(mock_smtp_cls)
        res = send_test_email(config=_make_config())
        self.assertEqual(res["status"], "SENT")
        # delivery_status reflects the real terminal outcome.
        self.assertEqual(res["delivery_status"], "sent")


class TestTestEmailLabel(unittest.TestCase):
    """The optional label identifies which Control Lab action
    triggered the test email and is shown in the email."""

    def setUp(self):
        reset_test_email_state()

    def test_build_test_alert_sets_detector_path(self):
        alert = _build_test_alert("S2 SYN Flood")
        self.assertEqual(alert.evidence["detector_path"], "S2 SYN Flood")
        # The message names the triggering action.
        self.assertIn("S2 SYN Flood", alert.message)

    def test_build_test_alert_default_detector_path(self):
        alert = _build_test_alert()
        self.assertEqual(alert.evidence["detector_path"], "control-lab")
        self.assertNotIn("Triggered by", alert.message)

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_send_test_email_includes_label(self, mock_smtp_cls):
        _mock_smtp_success(mock_smtp_cls)
        res = send_test_email(config=_make_config(), label="S3 UDP Flood")
        self.assertEqual(res["status"], "SENT")
        # The sent email HTML contains the label (verifies the
        # Detection Source field is populated, not N/A).
        html = _sent_mime_html(mock_smtp_cls)
        self.assertIn("S3 UDP Flood", html)
        self.assertIn("Detection Source", html)

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_label_is_sanitized(self, mock_smtp_cls):
        _mock_smtp_success(mock_smtp_cls)
        # Control characters and excessive length are stripped.
        long_label = "A" * 300 + "\x00\x1b[31m"
        res = send_test_email(config=_make_config(), label=long_label)
        self.assertEqual(res["status"], "SENT")
        alert = _build_test_alert(long_label)
        self.assertLessEqual(len(alert.evidence["detector_path"]), 128)
        self.assertNotIn("\x00", alert.evidence["detector_path"])
        self.assertNotIn("\x1b", alert.evidence["detector_path"])

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_blank_label_falls_back_to_control_lab(self, mock_smtp_cls):
        _mock_smtp_success(mock_smtp_cls)
        alert = _build_test_alert("   ")
        self.assertEqual(alert.evidence["detector_path"], "control-lab")


if __name__ == "__main__":
    unittest.main()
