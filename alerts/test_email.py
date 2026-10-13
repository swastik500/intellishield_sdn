"""
Diagnostic test email function and CLI utility for IntelliShield SDN.

Sends a single labeled test email using the project's existing .env settings
and EmailNotificationAdapter without requiring a real network attack.

Design notes:
  - Uses a dedicated, narrowly scoped test-email path that shares the existing
    SMTP configuration and sending implementation (EmailNotificationAdapter).
  - Does NOT create a fake verified attack, security event, or mitigation
    alert, and does NOT write anything into the R8 alert history (alerts.jsonl).
  - Uses the adapter's asynchronous attempt tracking and waits for the exact
    terminal outcome (sent / failed) — never reports success merely because a
    background thread was started.
  - Test emails are isolated from real attack-alert cooldowns via a separate
    shared tracker keyed to the SYSTEM/DIAGNOSTIC-TEST alert identity, so a
    test email can never suppress (or be suppressed by) a genuine security
    alert.
  - A small in-memory rate limiter prevents abuse / duplicate concurrent sends.
  - SMTP credentials are never returned or logged.
"""

from __future__ import annotations

import logging
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Optional

from shared_contracts.enums import AlertType, Severity
from shared_contracts.models import AlertEvent
from alerts.config import EmailAlertConfig, load_email_alert_config
from alerts.cooldown import EmailCooldownTracker
from alerts.email_adapter import DeliveryStatus, EmailNotificationAdapter

logger = logging.getLogger("intellishield.alerts.test_email")

# The adapter's SMTP connect timeout is 15s; wait longer than that so a slow
# (but still in-flight) attempt is never misreported as a timeout.
_WAIT_TIMEOUT_SEC = 30.0

# Abuse control: max test emails per client key per window.
_RATE_LIMIT_MAX_HITS = 5
_RATE_LIMIT_WINDOW_SEC = 60


class _RateLimiter:
    """Tiny thread-safe sliding-window rate limiter (no distributed infra)."""

    def __init__(self, max_hits: int, window_seconds: int) -> None:
        self._max_hits = max(1, max_hits)
        self._window_seconds = max(1, window_seconds)
        self._lock = threading.Lock()
        self._hits: Dict[str, Deque[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            q = self._hits.setdefault(key, deque())
            cutoff = now - self._window_seconds
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= self._max_hits:
                return False
            q.append(now)
            return True

    def reset(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)


# Shared, resettable state for test-email concurrency + abuse control.
# cooldown_seconds=0 makes the tracker act as a pure in-flight mutex:
# a key can be reserved exactly once at a time and is immediately
# available again after the attempt finishes (no persistent cooldown),
# so sequential retries always work while concurrent duplicate sends
# are suppressed.
_TEST_EMAIL_INFLIGHT = EmailCooldownTracker(cooldown_seconds=0)
_TEST_EMAIL_RATE_LIMIT = _RateLimiter(
    max_hits=_RATE_LIMIT_MAX_HITS, window_seconds=_RATE_LIMIT_WINDOW_SEC
)


def reset_test_email_state() -> None:
    """Reset shared test-email state (tests / reconnect)."""
    _TEST_EMAIL_INFLIGHT.clear()
    _TEST_EMAIL_RATE_LIMIT.reset()


def _build_test_alert(label: Optional[str] = None) -> AlertEvent:
    """Build a clearly identified, non-security test AlertEvent.

    alert_type=SYSTEM (not DETECTION/MITIGATION) and a DIAGNOSTIC_TEST hint
    keep it distinct from any real attack alert.

    ``label`` (e.g. "S2 SYN Flood") identifies which Control Lab
    action triggered the test. It is surfaced in the email's
    "Detection Source" field (``detector_path``) and in the
    message body so the recipient can see which button was used.
    """
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    # Sanitize the label (bounded length, printable only) so it
    # can never inject control characters into the email.
    safe_label = None
    if label:
        cleaned = "".join(
            ch for ch in str(label) if ch.isprintable()
        ).strip()[:128]
        if cleaned:
            safe_label = cleaned
    detector = safe_label or "control-lab"
    message = (
        "This is a email-delivery initiated from the "
        "IntelliShield Control Lab. security event occurred."
    )
    if safe_label:
        message = f"Triggered by Control Lab action: {safe_label}. " + message
    return AlertEvent(
        alert_id=f"TEST-EMAIL-{int(time.time() * 1000)}",
        timestamp=datetime.now(timezone.utc),
        severity=Severity.LOW,
        alert_type=AlertType.SYSTEM,
        title="IntelliShield SDN — Test Email",
        message=message,
        event_id=f"evt_test_email_{int(time.time() * 1000)}",
        source="control-lab",
        evidence={
            "attack_hint": "DIAGNOSTIC_TEST",
            "description": (
                "Manual SMTP delivery test triggered from the Control Lab panel."
            ),
            "triggered_at": now_str,
            "detector_path": detector,
            "detector_source": "manual_test_trigger",
        },
    )


def _result(
    ok: bool,
    status: str,
    message: str,
    cfg: EmailAlertConfig,
    *,
    delivery_status: str = "",
    attempt_id: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "ok": ok,
        "status": status,
        "message": message,
        "recipient": cfg.recipient or "(unconfigured)",
        "smtp_host": cfg.smtp_host,
        "smtp_port": cfg.smtp_port,
        "smtp_user": cfg.smtp_user or "(unconfigured)",
        "cooldown_seconds": cfg.cooldown_seconds,
        "delivery_status": delivery_status,
        "attempt_id": attempt_id,
    }


def send_test_email(
    config: Optional[EmailAlertConfig] = None,
    *,
    client_key: Optional[str] = None,
    label: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Send a single diagnostic test email to ALERT_EMAIL_TO.

    ``label`` (e.g. "S2 SYN Flood") identifies which Control Lab
    action triggered the test and is shown in the email's
    "Detection Source" field and message body.

    Returns a dict summary with a truthful status:
      SENT, FAILED, UNCONFIGURED, SUPPRESSED, RATE_LIMITED, TIMEOUT, ERROR.

    Never exposes passwords or sensitive credentials.
    """
    # Lazy import so tests can patch alerts.config.load_email_alert_config.
    from alerts.config import load_email_alert_config as _load_cfg

    cfg = config or _load_cfg()

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
        return _result(
            False,
            "UNCONFIGURED",
            (
                f"Email alerts are disabled or incomplete ({reason_str}). "
                "Please set ALERT_EMAIL_ENABLED=true and configure "
                "recipient/SMTP credentials in .env."
            ),
            cfg,
        )

    # Abuse control (per client key).
    key = client_key or "anonymous"
    if not _TEST_EMAIL_RATE_LIMIT.allow(key):
        return _result(
            False,
            "RATE_LIMITED",
            (
                f"Too many test emails (limit {_RATE_LIMIT_MAX_HITS} per "
                f"{_RATE_LIMIT_WINDOW_SEC}s). Please wait before retrying."
            ),
            cfg,
            delivery_status="rate_limited",
        )

    # _build_test_alert sanitizes the label (bounded, printable).
    test_alert = _build_test_alert(label)

    # Dedicated adapter that shares SMTP config + sending implementation, but
    # uses the isolated test-email in-flight tracker (never the real attack
    # alert cooldown).
    adapter = EmailNotificationAdapter(config=cfg, cooldown=_TEST_EMAIL_INFLIGHT)

    # Queue the async attempt. Returns None when suppressed (concurrent
    # duplicate in-flight for the same key).
    attempt_id = adapter.send(test_alert)
    if attempt_id is None:
        return _result(
            False,
            "SUPPRESSED",
            (
                "A test email is already in progress for this recipient. "
                "Please wait for it to finish before sending another."
            ),
            cfg,
            delivery_status="suppressed_by_cooldown",
        )

    # Wait for the exact attempt to reach a terminal state.
    attempt = adapter.wait_for_attempt(attempt_id, timeout=_WAIT_TIMEOUT_SEC)
    if attempt is None:
        return _result(
            False,
            "TIMEOUT",
            (
                "Timed out waiting for the email attempt to complete "
                f"({_WAIT_TIMEOUT_SEC}s)."
            ),
            cfg,
            delivery_status="timeout",
            attempt_id=attempt_id,
        )

    if attempt.status == DeliveryStatus.SENT:
        return _result(
            True,
            "SENT",
            f"Test email sent successfully to {cfg.recipient}. Check your inbox and spam folder.",
            cfg,
            delivery_status="sent",
            attempt_id=attempt_id,
        )

    # FAILED (or any other terminal state).
    reason = attempt.error or "unknown error"
    return _result(
        False,
        "FAILED",
        f"Test email failed: {reason}",
        cfg,
        delivery_status="failed",
        attempt_id=attempt_id,
    )


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
