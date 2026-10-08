#!/usr/bin/env python3
"""R8.5 — Hardening: failure injection, bounds, observability, concurrency smoke."""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import AlertType, Severity
from shared_contracts.models import AlertEvent, new_id
from alerting import (
    AlertDisposition,
    AlertManager,
    AlertingConfig,
    FakeTimeProvider,
    JsonlAlertStore,
    MemoryNotificationAdapter,
    alert_history_stats,
    read_alert_history,
)
from alerting.dedup import BoundedDeduplicator
from alerting.rate_limit import BoundedRateLimiter
from alerting.runtime import safe_emit_verification_alert


def _alert(attacker="02:aa:aa:aa:aa:01", hint="SYN_FLOOD", **kwargs):
    base = dict(
        alert_id=new_id(),
        timestamp=datetime.now(timezone.utc),
        severity=Severity.CRITICAL,
        alert_type=AlertType.MITIGATION,
        title="test",
        message="m",
        source="verification",
        dedup_key=f"MITIGATION|verification|{attacker}|02:bb:bb:bb:bb:02|{hint}",
        evidence={"attacker_mac": attacker, "attack_hint": hint},
    )
    base.update(kwargs)
    return AlertEvent(**base)


class TestFailureInjection(unittest.TestCase):
    def test_adapter_exception_isolated(self):
        class Boom:
            name = "boom"
            enabled = True

            def send(self, alert):
                raise RuntimeError("adapter fail")

        healthy = MemoryNotificationAdapter()
        mgr = AlertManager(
            adapters=[Boom(), healthy],
            clock=FakeTimeProvider(),
            config=AlertingConfig(dedup_enabled=False, rate_limit_enabled=False),
        )
        out = mgr.process_alert(_alert())
        self.assertEqual(out.disposition, AlertDisposition.NEW)
        self.assertEqual(out.adapters_failed, 1)
        self.assertEqual(len(healthy.sent), 1)
        self.assertEqual(mgr.metrics.snapshot()["adapter_failures"], 1)

    def test_persistence_exception_and_false(self):
        class BoomStore:
            name = "boom"

            def append(self, alert):
                raise RuntimeError("disk full")

        class FalseStore:
            name = "false"

            def append(self, alert):
                return False

        mgr = AlertManager(
            adapters=[MemoryNotificationAdapter()],
            store=BoomStore(),
            clock=FakeTimeProvider(),
            config=AlertingConfig(dedup_enabled=False, rate_limit_enabled=False),
        )
        out = mgr.process_alert(_alert())
        self.assertEqual(out.disposition, AlertDisposition.NEW)
        self.assertFalse(out.persisted)
        self.assertEqual(out.adapters_ok, 1)
        self.assertEqual(mgr.metrics.snapshot()["persistence_failures"], 1)

        mgr2 = AlertManager(
            adapters=[MemoryNotificationAdapter()],
            store=FalseStore(),
            clock=FakeTimeProvider(),
            config=AlertingConfig(dedup_enabled=False, rate_limit_enabled=False),
        )
        out2 = mgr2.process_alert(_alert(attacker="02:cc:cc:cc:cc:03"))
        self.assertFalse(out2.persisted)
        self.assertEqual(mgr2.metrics.snapshot()["persistence_failures"], 1)

    def test_malformed_null_alert(self):
        mgr = AlertManager(clock=FakeTimeProvider())
        out = mgr.process_alert(None)  # type: ignore[arg-type]
        self.assertEqual(out.disposition, AlertDisposition.SKIPPED)

    def test_duplicate_storm(self):
        clock = FakeTimeProvider()
        mem = MemoryNotificationAdapter()
        mgr = AlertManager(
            adapters=[mem],
            clock=clock,
            config=AlertingConfig(rate_limit_enabled=False, dedup_window_sec=60),
        )
        first = mgr.process_alert(_alert())
        for _ in range(50):
            self.assertEqual(
                mgr.process_alert(_alert()).disposition, AlertDisposition.DUPLICATE
            )
        self.assertEqual(first.disposition, AlertDisposition.NEW)
        self.assertEqual(len(mem.sent), 1)
        self.assertEqual(mgr.metrics.snapshot()["alerts_deduplicated"], 50)

    def test_rate_limit_storm(self):
        clock = FakeTimeProvider()
        mem = MemoryNotificationAdapter()
        mgr = AlertManager(
            adapters=[mem],
            clock=clock,
            config=AlertingConfig(
                dedup_enabled=False,
                rate_limit_per_window=2,
                rate_limit_window_sec=60,
            ),
        )
        outs = [mgr.process_alert(_alert()).disposition for _ in range(10)]
        self.assertEqual(outs.count(AlertDisposition.NEW), 2)
        self.assertEqual(outs.count(AlertDisposition.RATE_LIMITED), 8)
        self.assertEqual(len(mem.sent), 2)

    def test_missing_log_directory_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "a", "b", "alerts.jsonl")
            store = JsonlAlertStore(path)
            self.assertTrue(store.append(_alert()))
            self.assertTrue(os.path.isfile(path))

    def test_unwritable_log_nonfatal(self):
        with tempfile.NamedTemporaryFile() as blocker:
            path = os.path.join(blocker.name, "alerts.jsonl")
            store = JsonlAlertStore(path)
            self.assertFalse(store.append(_alert()))

    def test_malformed_history_and_empty_dashboard_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "alerts.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("bad\n{}\n")
            self.assertEqual(read_alert_history(path, limit=10), [])
            stats = alert_history_stats(path)
            self.assertGreaterEqual(stats["malformed_skipped"], 1)

        dash = os.path.join(_ROOT, "dashboard")
        if dash not in sys.path:
            sys.path.insert(0, dash)
        from fastapi.testclient import TestClient
        import api as api_mod

        orig = api_mod.SECURITY_ALERTS_JSONL
        missing = Path(tempfile.mkdtemp()) / "nope.jsonl"
        api_mod.SECURITY_ALERTS_JSONL = missing
        try:
            client = TestClient(api_mod.app)
            res = client.get("/api/security-alerts")
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json()["alerts"], [])
        finally:
            api_mod.SECURITY_ALERTS_JSONL = orig

    def test_alert_manager_unavailable(self):
        self.assertIsNone(safe_emit_verification_alert(None, None))

    def test_repeated_same_attacker_and_many_unique(self):
        clock = FakeTimeProvider()
        dedup = BoundedDeduplicator(max_keys=16, window_sec=60, clock=clock)
        for _ in range(20):
            dedup.observe("same-key")
        self.assertEqual(dedup.size(), 1)
        self.assertEqual(dedup.total_suppressed, 19)

        rl = BoundedRateLimiter(limit=5, window_sec=60, max_keys=8, clock=clock)
        for i in range(40):
            rl.allow(f"attacker-{i}")
        self.assertLessEqual(rl.size(), 8)

    def test_observability_counters_present(self):
        mgr = AlertManager(
            adapters=[MemoryNotificationAdapter()],
            clock=FakeTimeProvider(),
            config=AlertingConfig(dedup_enabled=False, rate_limit_enabled=False),
        )
        mgr.process_alert(_alert())
        snap = mgr.metrics.snapshot()
        for key in (
            "alerts_received",
            "alerts_dispatched",
            "alerts_persisted",
            "alerts_deduplicated",
            "alerts_rate_limited",
            "adapter_failures",
            "persistence_failures",
        ):
            self.assertIn(key, snap)

    def test_concurrent_process_alert_smoke(self):
        """Thread smoke: counters remain consistent under concurrent emits."""
        clock = FakeTimeProvider()
        mgr = AlertManager(
            adapters=[MemoryNotificationAdapter()],
            clock=clock,
            config=AlertingConfig(
                dedup_enabled=False,
                rate_limit_enabled=False,
            ),
            store=JsonlAlertStore(
                os.path.join(tempfile.mkdtemp(), "alerts.jsonl")
            ),
        )
        errors = []

        def worker(n):
            try:
                for i in range(20):
                    mgr.process_alert(
                        _alert(attacker=f"02:aa:aa:aa:aa:{n:02x}", hint=f"H{i}")
                    )
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        snap = mgr.metrics.snapshot()
        self.assertEqual(snap["alerts_received"], 80)
        self.assertEqual(snap["alerts_created"], 80)
        self.assertEqual(snap["alerts_persisted"], 80)


if __name__ == "__main__":
    unittest.main()
