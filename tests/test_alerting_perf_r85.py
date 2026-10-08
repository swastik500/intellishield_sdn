#!/usr/bin/env python3
"""R8.5 — Synthetic AlertManager latency benchmark (local path only)."""

from __future__ import annotations

import json
import os
import statistics
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import AlertType, Severity
from shared_contracts.models import AlertEvent, new_id
from alerting import (
    AlertManager,
    AlertingConfig,
    FakeTimeProvider,
    JsonlAlertStore,
    MemoryNotificationAdapter,
    NullAlertStore,
)

N_ITERS = 300


def _percentile(sorted_vals, pct):
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def _alert(i: int) -> AlertEvent:
    mac = f"02:aa:aa:aa:{i // 256:02x}:{i % 256:02x}"
    return AlertEvent(
        alert_id=new_id(),
        timestamp=datetime.now(timezone.utc),
        severity=Severity.HIGH,
        alert_type=AlertType.MITIGATION,
        title="bench",
        message="bench",
        source="verification",
        dedup_key=f"MITIGATION|verification|{mac}|02:bb:bb:bb:bb:02|BURST",
        evidence={"attacker_mac": mac, "attack_hint": "BURST"},
    )


class TestAlertLatency(unittest.TestCase):
    def test_median_p95_without_and_with_persistence(self):
        clock = FakeTimeProvider()
        cfg = AlertingConfig(
            dedup_enabled=False,
            rate_limit_enabled=False,
        )
        # Warm path without persistence I/O
        mgr_mem = AlertManager(
            config=cfg,
            adapters=[MemoryNotificationAdapter()],
            store=NullAlertStore(),
            clock=clock,
        )
        for i in range(20):
            mgr_mem.process_alert(_alert(i))

        samples = []
        for i in range(N_ITERS):
            a = _alert(1000 + i)
            t0 = time.perf_counter()
            mgr_mem.process_alert(a)
            samples.append((time.perf_counter() - t0) * 1000.0)
        samples.sort()
        median = statistics.median(samples)
        p95 = _percentile(samples, 95)

        # Persistence cost (separate)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "alerts.jsonl")
            mgr_disk = AlertManager(
                config=cfg,
                adapters=[MemoryNotificationAdapter()],
                store=JsonlAlertStore(path),
                clock=FakeTimeProvider(),
            )
            for i in range(10):
                mgr_disk.process_alert(_alert(2000 + i))
            disk_samples = []
            for i in range(N_ITERS):
                a = _alert(3000 + i)
                t0 = time.perf_counter()
                mgr_disk.process_alert(a)
                disk_samples.append((time.perf_counter() - t0) * 1000.0)
            disk_samples.sort()
            disk_median = statistics.median(disk_samples)
            disk_p95 = _percentile(disk_samples, 95)

        payload = {
            "iterations": N_ITERS,
            "memory_store_median_ms": round(median, 4),
            "memory_store_p95_ms": round(p95, 4),
            "jsonl_persist_median_ms": round(disk_median, 4),
            "jsonl_persist_p95_ms": round(disk_p95, 4),
            "live_network": False,
            "external_adapter": False,
        }
        out = os.path.join(_ROOT, "logs", "r85_alert_latency.json")
        try:
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
                fh.write("\n")
        except OSError:
            pass

        self.assertLess(median, 5.0)
        self.assertLess(p95, 15.0)
        print(
            f"\n[R8.5 PERF] mem median={median:.4f}ms p95={p95:.4f}ms | "
            f"jsonl median={disk_median:.4f}ms p95={disk_p95:.4f}ms"
        )


if __name__ == "__main__":
    unittest.main()
