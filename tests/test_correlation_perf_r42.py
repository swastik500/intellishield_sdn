#!/usr/bin/env python3
"""R4.2 — Synthetic CorrelationEngine latency benchmark (local path only)."""

from __future__ import annotations

import json
import os
import statistics
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from correlation import (
    CorrelationEngine,
    SignalCategory,
    SignalEvent,
    build_entity_key,
)


def _percentile(samples, p):
    if not samples:
        return 0.0
    ordered = sorted(samples)
    idx = min(len(ordered) - 1, max(0, int(round((p / 100.0) * (len(ordered) - 1)))))
    return ordered[idx]


def _ts(sec=0):
    return datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=sec)


class TestR42Perf(unittest.TestCase):
    def test_synthetic_correlation_latency(self):
        engine = CorrelationEngine()
        ent = build_entity_key(src_mac="02:aa:aa:aa:aa:01", switch_id=1)
        signals = [
            SignalEvent(
                signal_id="ml",
                timestamp=_ts(0),
                category=SignalCategory.DETECTION,
                source="ml",
                name="status",
                value="ATTACK",
                entity_key=ent,
            ),
            SignalEvent(
                signal_id="en",
                timestamp=_ts(1),
                category=SignalCategory.DETECTION,
                source="entropy",
                name="status",
                value="ALERT",
                entity_key=ent,
            ),
            SignalEvent(
                signal_id="fl",
                timestamp=_ts(2),
                category=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                value=1000.0,
                normalized_score=0.85,
                entity_key=ent,
            ),
            SignalEvent(
                signal_id="cpu",
                timestamp=_ts(2),
                category=SignalCategory.CONTROL_PLANE,
                source="controller_stats",
                name="cpu_percent",
                value=72.0,
                unit="percent",
            ),
        ]

        # Warmup
        for _ in range(20):
            engine.correlate(signals, entity_key=ent, event_id="bench")

        samples = []
        n = 400
        for _ in range(n):
            t0 = time.perf_counter()
            engine.correlate(signals, entity_key=ent, event_id="bench")
            samples.append((time.perf_counter() - t0) * 1000.0)

        median = statistics.median(samples)
        p95 = _percentile(samples, 95)
        payload = {
            "n": n,
            "median_ms": round(median, 4),
            "p95_ms": round(p95, 4),
            "signal_count": len(signals),
            "note": "synthetic local CorrelationEngine only — not live Mininet",
        }
        out = os.path.join(_ROOT, "logs", "r42_correlation_latency.json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        self.assertLess(median, 5.0)
        self.assertLess(p95, 15.0)
        print(f"\n[R4.2 PERF] median={median:.4f}ms p95={p95:.4f}ms → {out}")


if __name__ == "__main__":
    unittest.main()
