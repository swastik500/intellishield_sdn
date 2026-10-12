#!/usr/bin/env python3
"""
Integration test: Verified attack → AlertManager → EmailAdapter → SMTP.

This test simulates the complete pipeline from a verified attack
to email delivery, using mocked SMTP to avoid sending real emails.
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import VerificationStatus
from shared_contracts.models import VerificationResult, VerificationStageResult, new_id
from shared_contracts.timeutil import utc_now

from alerting import AlertManager, AlertingConfig, MemoryAlertStore
from alerting.factory import AlertFactoryContext
from alerting.runtime import build_runtime_alert_context, safe_emit_verification_alert
from alerts import build_email_adapter
from alerts.config import EmailAlertConfig
from alerts.email_adapter import EmailNotificationAdapter
from verification.config import VerificationConfig
from verification.engine import VerificationEngine
from verification.runtime import run_verified_mitigation


def _make_verified_result(
    event_id: str = None,
    attacker_mac: str = "00:00:00:00:00:01",
    victim_mac: str = "00:00:00:00:00:02",
    confidence: float = 0.95,
    hint: str = "SYN_FLOOD",
) -> VerificationResult:
    """Create a VERIFIED VerificationResult for testing."""
    stages = [
        VerificationStageResult(stage_name="WARMUP", passed=True, reason="warmup_complete", details={}),
        VerificationStageResult(stage_name="DETECTION_EVIDENCE", passed=True, reason="status=ATTACK", details={}),
        VerificationStageResult(stage_name="ATTACK_CONFIRMATION", passed=True, reason="attack_confirmed", details={}),
        VerificationStageResult(stage_name="CONFIDENCE_GATE", passed=True, reason="confidence_ok", details={}),
        VerificationStageResult(stage_name="ATTACKER_IDENTIFICATION", passed=True, reason=f"attacker={attacker_mac} victim={victim_mac}", details={}),
        VerificationStageResult(stage_name="MITIGATION_ELIGIBILITY", passed=True, reason="mitigation_eligible", details={}),
    ]
    return VerificationResult(
        verification_id=new_id(),
        timestamp=utc_now(),
        event_id=event_id or new_id(),
        status=VerificationStatus.VERIFIED,
        confidence=confidence,
        stages=stages,
        attacker_mac=attacker_mac,
        victim_mac=victim_mac,
        mitigation_eligible=True,
        reason="verified_mitigation_eligible",
    )


def _make_flow_features(rate=10000.0):
    return [
        {"src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02", "packet_rate": rate, "priority": 1, "byte_rate": rate * 64},
    ]


def _make_prediction():
    return {"status": "ATTACK", "confidence": 95.0, "source": "ml"}


def _make_explanation():
    return {"attack_type_hint": "SYN_FLOOD"}


class MockMitigation:
    def __init__(self):
        self.calls = 0
    
    def handle_alert(self, **kwargs):
        self.calls += 1
    
    def _identify_attackers(self, flow_features, explanation):
        return [("00:00:00:00:00:01", "00:00:00:00:00:02")]
    
    def _select_block_strategy(self, hint, dst):
        return "FLOW_PAIR"
    
    def _min_confidence_to_block(self, prediction=None):
        return 60.0


class TestAttackToEmailIntegration(unittest.TestCase):
    """Test complete attack-to-email pipeline."""

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_verified_attack_triggers_email(self, mock_smtp_cls):
        """Verified attack should trigger email dispatch through AlertManager."""
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        # Build AlertManager with email adapter
        cfg = EmailAlertConfig(
            enabled=True,
            recipient="test@example.com",
            smtp_host="smtp.gmail.com",
            smtp_port=587,
            smtp_user="sender@gmail.com",
            smtp_password="test_app_password",
            cooldown_seconds=0,  # No cooldown for test
            recovery_enabled=False,
        )
        email_adapter = EmailNotificationAdapter(config=cfg)

        store = MemoryAlertStore()
        am = AlertManager(
            config=AlertingConfig(
                enabled=True,
                alert_on_pending=False,
                dedup_enabled=False,
                rate_limit_enabled=False,
            ),
            adapters=[email_adapter],
            store=store,
        )

        # Create verified result
        result = _make_verified_result()

        # Simulate the on_verified callback from flow_monitor
        ctx = build_runtime_alert_context(
            dpid=1,
            prediction=_make_prediction(),
            explanation=_make_explanation(),
            detector_path="ml",
            event_id=result.event_id,
        )
        safe_emit_verification_alert(am, result, ctx)

        # Wait for async thread
        import time
        time.sleep(0.5)

        # Verify email was sent
        self.assertEqual(email_adapter.send_count, 1)
        self.assertEqual(email_adapter.fail_count, 0)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once()
        mock_server.sendmail.assert_called_once()

        # Verify alert was persisted
        self.assertEqual(len(store.records), 1)
        self.assertEqual(store.records[0].alert_type.value, "MITIGATION")

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_full_pipeline_with_verification_engine(self, mock_smtp_cls):
        """Test full pipeline: VerificationEngine → run_verified_mitigation → AlertManager → Email."""
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        # Build email adapter
        cfg = EmailAlertConfig(
            enabled=True,
            recipient="test@example.com",
            smtp_host="smtp.gmail.com",
            smtp_port=587,
            smtp_user="sender@gmail.com",
            smtp_password="test_app_password",
            cooldown_seconds=0,
            recovery_enabled=False,
        )
        email_adapter = EmailNotificationAdapter(config=cfg)

        # Build AlertManager
        store = MemoryAlertStore()
        am = AlertManager(
            config=AlertingConfig(
                enabled=True,
                alert_on_pending=False,
                dedup_enabled=False,
                rate_limit_enabled=False,
            ),
            adapters=[email_adapter],
            store=store,
        )

        # Build verification engine
        mit = MockMitigation()
        engine = VerificationEngine(
            config=VerificationConfig(),
            identify_attackers=mit._identify_attackers,
            select_strategy=mit._select_block_strategy,
        )

        # Run verified mitigation
        outcome = run_verified_mitigation(
            engine=engine,
            mitigation=mit,
            dpid=1,
            prediction=_make_prediction(),
            explanation=_make_explanation(),
            flow_features=_make_flow_features(),
            warmup_cycles_done=10,
            attack_streak=2,
            on_verified=lambda r: safe_emit_verification_alert(
                am, r,
                build_runtime_alert_context(
                    dpid=1,
                    prediction=_make_prediction(),
                    explanation=_make_explanation(),
                    detector_path="ml",
                    event_id=r.event_id,
                ),
            ),
        )

        # Wait for async thread
        import time
        time.sleep(0.5)

        # Verify mitigation was called
        self.assertTrue(outcome.handle_alert_called)
        self.assertEqual(mit.calls, 1)

        # Verify email was sent
        self.assertEqual(email_adapter.send_count, 1)
        self.assertEqual(email_adapter.fail_count, 0)
        mock_server.sendmail.assert_called_once()

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_cooldown_prevents_duplicate_emails(self, mock_smtp_cls):
        """Cooldown should prevent duplicate emails for same attack."""
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        cfg = EmailAlertConfig(
            enabled=True,
            recipient="test@example.com",
            smtp_host="smtp.gmail.com",
            smtp_port=587,
            smtp_user="sender@gmail.com",
            smtp_password="test_app_password",
            cooldown_seconds=9999,  # Long cooldown
            recovery_enabled=False,
        )
        email_adapter = EmailNotificationAdapter(config=cfg)

        store = MemoryAlertStore()
        am = AlertManager(
            config=AlertingConfig(enabled=True, dedup_enabled=False, rate_limit_enabled=False),
            adapters=[email_adapter],
            store=store,
        )

        # Create two verified results with same attacker/victim/hint
        result1 = _make_verified_result(event_id="evt_1")
        result2 = _make_verified_result(event_id="evt_2")

        ctx1 = build_runtime_alert_context(
            dpid=1, prediction=_make_prediction(), explanation=_make_explanation(),
            detector_path="ml", event_id=result1.event_id,
        )
        ctx2 = build_runtime_alert_context(
            dpid=1, prediction=_make_prediction(), explanation=_make_explanation(),
            detector_path="ml", event_id=result2.event_id,
        )

        # First attack
        safe_emit_verification_alert(am, result1, ctx1)
        import time
        time.sleep(0.2)

        # Second attack (same attacker/victim/hint)
        safe_emit_verification_alert(am, result2, ctx2)
        time.sleep(0.2)

        # Only first email should be sent
        self.assertEqual(email_adapter.send_count, 1)
        self.assertEqual(mock_server.sendmail.call_count, 1)

    @patch("alerts.email_adapter.smtplib.SMTP")
    def test_email_adapter_via_build_factory(self, mock_smtp_cls):
        """Test email adapter created via build_email_adapter factory."""
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        # Use environment variables (from .env)
        with patch.dict(os.environ, {
            "ALERT_EMAIL_ENABLED": "true",
            "ALERT_EMAIL_TO": "test@example.com",
            "ALERT_SMTP_HOST": "smtp.gmail.com",
            "ALERT_SMTP_PORT": "587",
            "ALERT_SMTP_USER": "sender@gmail.com",
            "ALERT_SMTP_PASSWORD": "test_app_password",
            "ALERT_EMAIL_COOLDOWN_SECONDS": "0",
        }):
            adapter = build_email_adapter()
            self.assertIsNotNone(adapter)
            self.assertIsInstance(adapter, EmailNotificationAdapter)

            # Send test alert
            from shared_contracts.models import AlertEvent
            from shared_contracts.enums import AlertType, Severity
            alert = AlertEvent(
                alert_id="test_001",
                timestamp=datetime.now(timezone.utc),
                severity=Severity.HIGH,
                alert_type=AlertType.DETECTION,
                title="Test Attack",
                message="Test",
                event_id="evt_test",
                source="verification",
                evidence={"attack_hint": "SYN_FLOOD"},
            )
            adapter.send_sync(alert)

            import time
            time.sleep(0.2)

            self.assertEqual(adapter.send_count, 1)
            mock_server.sendmail.assert_called_once()


if __name__ == "__main__":
    unittest.main()