#!/usr/bin/env python3
"""
Diagnostic: Simulate the exact R7 -> AlertManager -> EmailAdapter pipeline
without needing Mininet/osken.

Run from the project root:
    python scripts/diagnose_alert_pipeline.py

This script:
  1. Loads email config from .env
  2. Builds AlertManager with EmailNotificationAdapter (same as controller)
  3. Creates a fake VerificationResult with status=VERIFIED
  4. Calls process_verification() and logs every step
  5. Reports exactly which gate passed or failed
"""
from __future__ import annotations

import os
import sys
import logging

# Ensure project root is on path
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Load .env before importing config
try:
    from dotenv import load_dotenv
    env_path = os.path.join(_PROJECT_ROOT, ".env")
    if os.path.isfile(env_path):
        load_dotenv(dotenv_path=env_path, override=True)
        print(f"[.env] Loaded from {env_path}")
    else:
        print(f"[.env] WARNING: .env not found at {env_path}")
except ImportError:
    print("[.env] WARNING: python-dotenv not installed")

# Configure logging to show everything
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("diagnose_alert_pipeline")

print("\n" + "=" * 70)
print("IntelliShield Alert Pipeline Diagnostic")
print("=" * 70)

# ── Step 1: Email config ──────────────────────────────────────────────────────
print("\n[1] Loading email alert config from environment...")
from alerts.config import load_email_alert_config
cfg = load_email_alert_config()
print(f"    enabled          : {cfg.enabled}")
print(f"    is_configured    : {cfg.is_configured}")
print(f"    recipient        : {cfg.recipient}")
print(f"    smtp_host        : {cfg.smtp_host}:{cfg.smtp_port}")
print(f"    smtp_user        : {cfg.smtp_user}")
print(f"    smtp_password    : {'SET' if cfg.smtp_password else 'EMPTY'}")
print(f"    cooldown_seconds : {cfg.cooldown_seconds}")

if not cfg.is_configured:
    print("\n    ERROR: Email adapter is NOT configured. Check your .env file.")
    print("       Required: ALERT_EMAIL_ENABLED=true, ALERT_EMAIL_TO, ALERT_SMTP_USER, ALERT_SMTP_PASSWORD")
    sys.exit(1)

# ── Step 2: Build adapter ─────────────────────────────────────────────────────
print("\n[2] Building EmailNotificationAdapter...")
from alerts import build_email_adapter
adapter = build_email_adapter(config=cfg)
if adapter is None:
    print("    ERROR: build_email_adapter() returned None!")
    sys.exit(1)
print(f"    adapter.enabled  : {adapter.enabled}")

# ── Step 3: Build AlertManager ────────────────────────────────────────────────
print("\n[3] Building AlertManager with logging + email adapters...")
from alerting import AlertManager, AlertingConfig, LoggingNotificationAdapter

manager = AlertManager(
    config=AlertingConfig(
        enabled=True,
        alert_on_pending=False,
        alert_on_ineligible=False,
        alert_on_rejected=False,
        dedup_enabled=True,
        dedup_window_sec=60.0,
        rate_limit_enabled=True,
        rate_limit_per_window=30,
        rate_limit_window_sec=60.0,
    ),
    adapters=[LoggingNotificationAdapter(), adapter],
)
print(f"    AlertManager built with {len(manager._adapters)} adapters")

# ── Step 4: Create a fake VERIFIED VerificationResult ────────────────────────
print("\n[4] Creating fake VerificationResult (status=VERIFIED, mitigation_eligible=True)...")
from shared_contracts.enums import VerificationStatus
from shared_contracts.models import VerificationResult, VerificationStageResult, new_id
from shared_contracts.timeutil import utc_now

fake_result = VerificationResult(
    verification_id=new_id(),
    timestamp=utc_now(),
    event_id=new_id(),
    status=VerificationStatus.VERIFIED,
    confidence=0.92,
    stages=[
        VerificationStageResult(
            stage_name="ATTACK_CONFIRMATION",
            passed=True,
            reason="attack_confirmed",
            details={"attack_streak": 3, "attack_confirm": 2},
        ),
    ],
    attacker_mac="00:00:00:00:00:01",
    victim_mac="00:00:00:00:00:02",
    mitigation_eligible=True,
    reason="verified_mitigation_eligible",
)
print(f"    event_id : {fake_result.event_id}")
print(f"    status   : {fake_result.status}")
print(f"    eligible : {fake_result.mitigation_eligible}")

# ── Step 5: Build context ─────────────────────────────────────────────────────
print("\n[5] Building AlertFactoryContext...")
from alerting.runtime import build_runtime_alert_context
ctx = build_runtime_alert_context(
    dpid=1,
    prediction={
        "status": "ATTACK",
        "confidence": 92.0,
        "source": "ml",
    },
    explanation={
        "attack_type_hint": "SYN_FLOOD",
    },
    detector_path="ml",
    event_id=fake_result.event_id,
)
print(f"    source_tag   : {ctx.source_tag}")
print(f"    attack_hint  : {ctx.attack_hint}")

# ── Step 6: Call process_verification ────────────────────────────────────────
print("\n[6] Calling AlertManager.process_verification()...")
from alerting.manager import AlertDisposition
result = manager.process_verification(fake_result, ctx)
print(f"    disposition     : {result.disposition}")
print(f"    adapters_ok     : {result.adapters_ok}")
print(f"    adapters_failed : {result.adapters_failed}")
print(f"    adapters_skipped: {result.adapters_skipped}")
print(f"    persisted       : {result.persisted}")
print(f"    reason          : {result.reason}")

if result.disposition == AlertDisposition.NEW:
    print("\n    Alert created and dispatched.")
    print("    Waiting for async email attempt to complete...")
    import time
    # Wait for the email attempt to complete (max 30s)
    # The adapter tracks attempts; we need to wait for the worker thread
    start_wait = time.monotonic()
    timeout = 30.0
    last_send_count = adapter.send_count
    last_fail_count = adapter.fail_count
    
    while time.monotonic() - start_wait < timeout:
        time.sleep(0.5)
        if adapter.send_count > last_send_count or adapter.fail_count > last_fail_count:
            break
    
    print(f"    EmailAdapter send_count : {adapter.send_count}")
    print(f"    EmailAdapter fail_count : {adapter.fail_count}")
    
    if adapter.send_count > last_send_count:
        print("    SUCCESS: Email was sent (check your inbox).")
        sys.exit(0)
    elif adapter.fail_count > last_fail_count:
        print("    FAILURE: Email FAILED -- check SMTP credentials in .env")
        sys.exit(1)
    else:
        print("    TIMEOUT: Email attempt did not complete within 30s")
        sys.exit(2)
elif result.disposition == AlertDisposition.DUPLICATE:
    print("\n    WARNING: Alert DEDUPLICATED -- same key seen within 60s window.")
    print("       This is expected on repeated runs. Reset state and retry.")
    sys.exit(3)
elif result.disposition == AlertDisposition.RATE_LIMITED:
    print("\n    WARNING: Alert RATE LIMITED.")
    sys.exit(3)
elif result.disposition == AlertDisposition.SKIPPED:
    print("\n    ERROR: Alert SKIPPED -- factory returned None.")
    print(f"       reason: {result.reason}")
    sys.exit(1)
elif result.disposition == AlertDisposition.DISABLED:
    print("\n    ERROR: Alert DISABLED -- AlertingConfig.enabled=False")
    sys.exit(1)
else:
    print(f"\n    ERROR: Unexpected disposition: {result.disposition}  reason={result.reason}")
    sys.exit(1)

print("\n" + "=" * 70)
print("Diagnostic complete.")
print("=" * 70)
