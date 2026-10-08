#!/usr/bin/env python3
"""R8.2 — Severity / dedup / rate-limit policy tests (injectable clock)."""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import AlertType, Severity, VerificationStatus
from shared_contracts.models import (
    AlertEvent,
    VerificationResult,
    VerificationStageResult,
    new_id,
)
from alerting import (
    AlertDisposition,
    AlertFactory,
    AlertFactoryContext,
    AlertManager,
    AlertingConfig,
    BoundedDeduplicator,
    BoundedRateLimiter,
    DefaultSeverityPolicy,
    FakeTimeProvider,
    MemoryAlertStore,
    MemoryNotificationAdapter,
    SeverityEvidence,
    build_dedup_key,
)


def _vr(**kwargs):
    base = dict(
        verification_id=new_id(),
        timestamp=datetime.now(timezone.utc),
        event_id=new_id(),
        status=VerificationStatus.VERIFIED,
        confidence=0.95,
        stages=[
            VerificationStageResult(
                stage_name="MITIGATION_ELIGIBILITY",
                passed=True,
                reason="ok",
                details={"attack_hint": "SYN_FLOOD"},
            )
        ],
        attacker_mac="02:aa:aa:aa:aa:01",
        victim_mac="02:bb:bb:bb:bb:02",
        mitigation_eligible=True,
        reason="verified_mitigation_eligible",
    )
    base.update(kwargs)
    return VerificationResult(**base)


def _mgr(clock, config=None, store=None, adapters=None):
    cfg = config or AlertingConfig(
        dedup_window_sec=10.0,
        rate_limit_per_window=3,
        rate_limit_window_sec=10.0,
        dedup_max_keys=8,
        rate_limit_max_keys=8,
    )
    return AlertManager(
        config=cfg,
        clock=clock,
        store=store or MemoryAlertStore(),
        adapters=adapters if adapters is not None else [MemoryNotificationAdapter()],
    )


class TestSeverityPolicy(unittest.TestCase):
    def setUp(self):
        self.policy = DefaultSeverityPolicy(
            critical_confidence=0.90, high_confidence=0.75
        )

    def test_critical_by_confidence_boundary(self):
        ev = SeverityEvidence("VERIFIED", True, 0.90, "BURST")
        self.assertEqual(self.policy.assign(ev), Severity.CRITICAL)
        ev2 = SeverityEvidence("VERIFIED", True, 0.899, "BURST")
        self.assertEqual(self.policy.assign(ev2), Severity.HIGH)

    def test_critical_by_hint(self):
        ev = SeverityEvidence("VERIFIED", True, 0.5, "SYN_FLOOD")
        self.assertEqual(self.policy.assign(ev), Severity.CRITICAL)

    def test_pending_medium(self):
        ev = SeverityEvidence("PENDING", False, 0.99, "SYN_FLOOD")
        self.assertEqual(self.policy.assign(ev), Severity.MEDIUM)

    def test_ineligible_low_rejected_info(self):
        self.assertEqual(
            self.policy.assign(SeverityEvidence("INELIGIBLE", False, 0.9)),
            Severity.LOW,
        )
        self.assertEqual(
            self.policy.assign(SeverityEvidence("REJECTED", False, 0.9)),
            Severity.INFO,
        )

    def test_factory_uses_policy(self):
        alert = AlertFactory().from_verification(_vr(confidence=0.95))
        assert alert is not None
        self.assertEqual(alert.severity, Severity.CRITICAL)

    def test_verified_not_eligible_medium(self):
        alert = AlertFactory().from_verification(
            _vr(mitigation_eligible=False, confidence=0.99)
        )
        assert alert is not None
        self.assertEqual(alert.severity, Severity.MEDIUM)


class TestDedup(unittest.TestCase):
    def test_same_event_duplicate(self):
        clock = FakeTimeProvider()
        mem = MemoryNotificationAdapter()
        store = MemoryAlertStore()
        mgr = _mgr(clock, store=store, adapters=[mem])
        r1 = mgr.process_verification(_vr())
        r2 = mgr.process_verification(_vr())
        self.assertEqual(r1.disposition, AlertDisposition.NEW)
        self.assertEqual(r2.disposition, AlertDisposition.DUPLICATE)
        self.assertEqual(len(mem.sent), 1)
        self.assertEqual(len(store.records), 1)
        self.assertEqual(mgr.metrics.snapshot()["alerts_deduplicated"], 1)

    def test_different_source_not_duplicate(self):
        clock = FakeTimeProvider()
        mgr = _mgr(clock)
        a = mgr.process_verification(
            _vr(), AlertFactoryContext(source_tag="ml")
        )
        b = mgr.process_verification(
            _vr(), AlertFactoryContext(source_tag="entropy")
        )
        self.assertEqual(a.disposition, AlertDisposition.NEW)
        self.assertEqual(b.disposition, AlertDisposition.NEW)

    def test_different_attack_type_not_duplicate(self):
        clock = FakeTimeProvider()
        mgr = _mgr(clock)
        a = mgr.process_verification(
            _vr(), AlertFactoryContext(attack_hint="SYN_FLOOD")
        )
        b = mgr.process_verification(
            _vr(), AlertFactoryContext(attack_hint="VOLUMETRIC_FLOOD")
        )
        self.assertEqual(a.disposition, AlertDisposition.NEW)
        self.assertEqual(b.disposition, AlertDisposition.NEW)

    def test_dedup_expiration(self):
        clock = FakeTimeProvider()
        mgr = _mgr(clock)
        self.assertEqual(mgr.process_verification(_vr()).disposition, AlertDisposition.NEW)
        self.assertEqual(mgr.process_verification(_vr()).disposition, AlertDisposition.DUPLICATE)
        clock.advance(10.0)
        self.assertEqual(mgr.process_verification(_vr()).disposition, AlertDisposition.NEW)

    def test_bounded_dedup_state(self):
        clock = FakeTimeProvider()
        dedup = BoundedDeduplicator(window_sec=60, max_keys=3, clock=clock)
        for i in range(10):
            dedup.observe(f"key-{i}")
        self.assertLessEqual(dedup.size(), 3)

    def test_malformed_identity_stable(self):
        clock = FakeTimeProvider()
        mgr = _mgr(clock)
        alert = AlertEvent(
            alert_id="a1",
            timestamp=datetime.now(timezone.utc),
            severity=Severity.HIGH,
            alert_type=AlertType.DETECTION,
            title="x",
            dedup_key="",
            source="",
            evidence={},
        )
        r1 = mgr.process_alert(alert)
        r2 = mgr.process_alert(
            AlertEvent(
                alert_id="a2",
                timestamp=datetime.now(timezone.utc),
                severity=Severity.HIGH,
                alert_type=AlertType.DETECTION,
                title="y",
                dedup_key="",
                source="",
                evidence={},
            )
        )
        self.assertEqual(r1.disposition, AlertDisposition.NEW)
        self.assertEqual(r2.disposition, AlertDisposition.DUPLICATE)


class TestRateLimit(unittest.TestCase):
    def test_rate_limit_allowed_then_exceeded(self):
        clock = FakeTimeProvider()
        # Disable dedup so distinct keys aren't needed — use unique keys
        cfg = AlertingConfig(
            dedup_enabled=False,
            rate_limit_per_window=2,
            rate_limit_window_sec=10.0,
            rate_limit_max_keys=32,
        )
        mem = MemoryNotificationAdapter()
        mgr = AlertManager(config=cfg, clock=clock, adapters=[mem])
        outcomes = []
        for i in range(4):
            # same key via same verification identity
            outcomes.append(mgr.process_verification(_vr()).disposition)
        self.assertEqual(outcomes[0], AlertDisposition.NEW)
        self.assertEqual(outcomes[1], AlertDisposition.NEW)
        self.assertEqual(outcomes[2], AlertDisposition.RATE_LIMITED)
        self.assertEqual(outcomes[3], AlertDisposition.RATE_LIMITED)
        self.assertEqual(len(mem.sent), 2)

    def test_rate_limit_recovery(self):
        clock = FakeTimeProvider()
        cfg = AlertingConfig(
            dedup_enabled=False,
            rate_limit_per_window=1,
            rate_limit_window_sec=5.0,
        )
        mgr = AlertManager(config=cfg, clock=clock, adapters=[MemoryNotificationAdapter()])
        self.assertEqual(mgr.process_verification(_vr()).disposition, AlertDisposition.NEW)
        self.assertEqual(
            mgr.process_verification(_vr()).disposition, AlertDisposition.RATE_LIMITED
        )
        clock.advance(5.0)
        self.assertEqual(mgr.process_verification(_vr()).disposition, AlertDisposition.NEW)

    def test_bounded_rate_limit_keys(self):
        clock = FakeTimeProvider()
        rl = BoundedRateLimiter(limit=10, window_sec=60, max_keys=4, clock=clock)
        for i in range(20):
            rl.allow(f"k{i}")
        self.assertLessEqual(rl.size(), 4)


class TestPolicyOrderAndInteraction(unittest.TestCase):
    def test_dedup_before_rate_limit(self):
        """Duplicates must not consume rate-limit slots after first."""
        clock = FakeTimeProvider()
        cfg = AlertingConfig(
            dedup_enabled=True,
            dedup_window_sec=30.0,
            rate_limit_enabled=True,
            rate_limit_per_window=2,
            rate_limit_window_sec=30.0,
        )
        mgr = AlertManager(config=cfg, clock=clock, adapters=[MemoryNotificationAdapter()])
        self.assertEqual(mgr.process_verification(_vr()).disposition, AlertDisposition.NEW)
        # Same key storms → DUPLICATE (not RATE_LIMITED)
        for _ in range(5):
            self.assertEqual(
                mgr.process_verification(_vr()).disposition, AlertDisposition.DUPLICATE
            )
        snap = mgr.metrics.snapshot()
        self.assertEqual(snap["alerts_deduplicated"], 5)
        self.assertEqual(snap["alerts_rate_limited"], 0)
        self.assertEqual(snap["alerts_created"], 1)

    def test_duplicate_not_persisted(self):
        clock = FakeTimeProvider()
        store = MemoryAlertStore()
        mgr = _mgr(clock, store=store)
        mgr.process_verification(_vr())
        mgr.process_verification(_vr())
        self.assertEqual(len(store.records), 1)

    def test_policy_order_documented_path(self):
        """severity assigned in factory before manager policy gates."""
        clock = FakeTimeProvider()
        mgr = _mgr(clock)
        out = mgr.process_verification(_vr(confidence=0.95))
        self.assertEqual(out.alert.severity, Severity.CRITICAL)
        self.assertEqual(out.disposition, AlertDisposition.NEW)

    def test_reset_policy_state(self):
        clock = FakeTimeProvider()
        mgr = _mgr(clock)
        mgr.process_verification(_vr())
        mgr.process_verification(_vr())
        mgr.reset_policy_state()
        self.assertEqual(mgr.process_verification(_vr()).disposition, AlertDisposition.NEW)

    def test_r83_controller_wires_alerting(self):
        path = os.path.join(_ROOT, "controller", "flow_monitor.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("from alerting", src)
        self.assertIn("AlertManager", src)


if __name__ == "__main__":
    unittest.main()
