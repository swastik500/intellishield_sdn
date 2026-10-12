"""
Tests for the POST /api/alerts/test-email endpoint.

Covers:
  - Successful test-email send (mocked SMTP)
  - SMTP failure with sanitized error response
  - Email alerts disabled / unconfigured
  - Unauthorized when authentication is configured (401)
  - Authorized with a valid session (200)
  - Rate limited (429)
  - No credential leakage

All SMTP calls are mocked — no real emails are sent.
"""

from __future__ import annotations

import base64
import re
import unittest
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from dashboard.api import app
from dashboard.auth.config import AuthConfig
from dashboard.auth.sessions import SESSION_STORE


def _make_config(**overrides):
    from alerts.config import EmailAlertConfig

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


def _configured_auth() -> AuthConfig:
    return AuthConfig(
        enabled=True,
        secret_key="test-secret-key",
        username="admin",
        password_hash="pbkdf2:sha256:600000$abc$def",
        session_ttl_seconds=3600,
        cookie_name="is_session",
        cookie_secure=False,
        cookie_samesite="lax",
        login_max_attempts=10,
        login_window_seconds=300,
        cors_origins=[],
        roles=["VIEWER"],
        rbac_enabled=True,
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


class TestPostTestEmailEndpoint(unittest.TestCase):
    def setUp(self):
        from alerts.test_email import reset_test_email_state

        reset_test_email_state()
        self.client = TestClient(app)

    @patch("alerts.email_adapter.smtplib.SMTP")
    @patch("alerts.config.load_email_alert_config")
    def test_success_returns_200_ok(self, mock_load_cfg, mock_smtp_cls):
        mock_load_cfg.return_value = _make_config()
        _mock_smtp_success(mock_smtp_cls)

        r = self.client.post("/api/alerts/test-email")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["status"], "SENT")
        self.assertEqual(data["delivery_status"], "sent")
        self.assertNotIn("test_app_password", str(data))
        mock_smtp_cls.return_value.__enter__.return_value.sendmail.assert_called_once()

    @patch("alerts.email_adapter.smtplib.SMTP")
    @patch("alerts.config.load_email_alert_config")
    def test_smtp_failure_returns_200_sanitized(self, mock_load_cfg, mock_smtp_cls):
        mock_load_cfg.return_value = _make_config()
        mock_smtp_cls.side_effect = Exception(
            "SMTP auth error password=secret_app_password_123"
        )

        r = self.client.post("/api/alerts/test-email")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "FAILED")
        self.assertNotIn("secret_app_password_123", str(data))

    @patch("alerts.config.load_email_alert_config")
    def test_unconfigured_returns_200_not_ok(self, mock_load_cfg):
        mock_load_cfg.return_value = _make_config(enabled=False)

        r = self.client.post("/api/alerts/test-email")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "UNCONFIGURED")

    @patch("alerts.email_adapter.smtplib.SMTP")
    @patch("alerts.config.load_email_alert_config")
    def test_rate_limited_returns_429(self, mock_load_cfg, mock_smtp_cls):
        mock_load_cfg.return_value = _make_config()
        _mock_smtp_success(mock_smtp_cls)

        statuses = []
        for _ in range(10):
            r = self.client.post("/api/alerts/test-email")
            statuses.append(r.status_code)
            if r.status_code == 429:
                break
        self.assertIn(429, statuses)
        # The 429 body is still a truthful result dict.
        data = self.client.post("/api/alerts/test-email").json()
        self.assertFalse(data["ok"])
        self.assertEqual(data["status"], "RATE_LIMITED")


    @patch("alerts.email_adapter.smtplib.SMTP")
    @patch("alerts.config.load_email_alert_config")
    def test_success_with_label(self, mock_load_cfg, mock_smtp_cls):
        mock_load_cfg.return_value = _make_config()
        _mock_smtp_success(mock_smtp_cls)

        r = self.client.post(
            "/api/alerts/test-email", json={"label": "S2 SYN Flood"}
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["status"], "SENT")
        # The sent email HTML contains the label (Detection Source).
        html = _sent_mime_html(mock_smtp_cls)
        self.assertIn("S2 SYN Flood", html)
        self.assertIn("Detection Source", html)

    @patch("alerts.email_adapter.smtplib.SMTP")
    @patch("alerts.config.load_email_alert_config")
    def test_rejects_oversized_label(self, mock_load_cfg, mock_smtp_cls):
        mock_load_cfg.return_value = _make_config()
        _mock_smtp_success(mock_smtp_cls)

        # Pydantic max_length=128 rejects oversized labels (422).
        r = self.client.post(
            "/api/alerts/test-email", json={"label": "X" * 200}
        )
        self.assertEqual(r.status_code, 422)


class TestPostTestEmailAuth(unittest.TestCase):
    def setUp(self):
        from alerts.test_email import reset_test_email_state

        reset_test_email_state()
        self.client = TestClient(app)

    @patch("alerts.email_adapter.smtplib.SMTP")
    @patch("alerts.config.load_email_alert_config")
    @patch("dashboard.api.load_auth_config")
    def test_unauthorized_when_auth_configured(
        self, mock_auth_cfg, mock_load_cfg, mock_smtp_cls
    ):
        mock_auth_cfg.return_value = _configured_auth()
        mock_load_cfg.return_value = _make_config()
        _mock_smtp_success(mock_smtp_cls)

        # No session / bearer token → 401.
        r = self.client.post("/api/alerts/test-email")
        self.assertEqual(r.status_code, 401)
        # SMTP must NOT have been called for an unauthorized request.
        mock_smtp_cls.return_value.__enter__.return_value.sendmail.assert_not_called()

    @patch("alerts.email_adapter.smtplib.SMTP")
    @patch("alerts.config.load_email_alert_config")
    @patch("dashboard.api.load_auth_config")
    def test_authorized_with_valid_session(
        self, mock_auth_cfg, mock_load_cfg, mock_smtp_cls
    ):
        mock_auth_cfg.return_value = _configured_auth()
        mock_load_cfg.return_value = _make_config()
        _mock_smtp_success(mock_smtp_cls)

        rec = SESSION_STORE.create(
            principal_id="user:admin",
            username="admin",
            roles=["VIEWER"],
            ttl_seconds=3600,
        )
        try:
            headers = {"Authorization": f"Bearer {rec.session_id}"}
            r = self.client.post(
                "/api/alerts/test-email", headers=headers
            )
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertTrue(data["ok"])
            self.assertEqual(data["status"], "SENT")
        finally:
            SESSION_STORE.revoke(rec.session_id)

    @patch("alerts.email_adapter.smtplib.SMTP")
    @patch("alerts.config.load_email_alert_config")
    @patch("dashboard.api.load_auth_config")
    def test_client_role_headers_never_elevate(
        self, mock_auth_cfg, mock_load_cfg, mock_smtp_cls
    ):
        mock_auth_cfg.return_value = _configured_auth()
        mock_load_cfg.return_value = _make_config()
        _mock_smtp_success(mock_smtp_cls)

        # Forged role headers must not authenticate an unauthenticated request.
        r = self.client.post(
            "/api/alerts/test-email",
            headers={"x-role": "ADMIN", "x-permissions": "MANAGE_CONFIGURATION"},
        )
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main()
