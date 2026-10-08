#!/usr/bin/env python3
"""R4.5 — Performance + bounded-state memory behavior (synthetic)."""

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
    CorrelationWindow,
    FakeTimeProvider,
    SignalCategory,
    SignalEvent,
    build_entity_key,
    safe_correlate_cycle,
)
from correlation.adapters import from_flow_features, from_entropy, from_ml_prediction
from correlation.persistence import MemoryCorrelationStore


def _percentile(samples, p):
    ordered = sorted(samples)
    if not ordered:
        return 0.0
    idx = min(len(ordered) - 1, max(0, int(round((p / 100.0) * (len(ordered) - 1)))))
    return ordered[idx]


def _ts(sec=0):
    return datetime(2026, 7, 26, 17, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=sec)


class TestR45Perf(unittest.TestCase):
    def test_combined_path_latency_and_bounds(self):
        ent = build_entity_key(src_mac="02:aa:aa:aa:aa:01", switch_id=1)
        flows = [
            {
                "src_mac": "02:aa:aa:aa:aa:01",
                "dst_mac": "02:bb:bb:bb:bb:02",
                "switch_id": 1,
                "in_port": 1,
                "packet_rate": 7000.0,
                "byte_rate": 400000.0,
            }
        ]
        entropy = {"entropy_score": 0.22, "status": "ALERT", "confidence": 80.0}
        prediction = {"status": "ATTACK", "confidence": 92.0}
        controller = {"cpu_percent": 60.0, "memory_percent": 40.0}

        # Warmup
        for _ in range(30):
            safe_correlate_cycle(
                engine=CorrelationEngine(),
                store=MemoryCorrelationStore(),
                switch_id=1,
                feature_batch=flows,
                entropy=entropy,
                prediction=prediction,
                controller_stats=controller,
            )

        convert_ms = []
        window_ms = []
        corr_ms = []
        combined_ms = []

        engine = CorrelationEngine()
        n = 300
        for i in range(n):
            t0 = time.perf_counter()
            sigs = []
            sigs.extend(from_flow_features(flows, switch_id=1, timestamp=_ts(i % 10)))
            sigs.extend(from_entropy(entropy, switch_id=1, entity_key=ent, timestamp=_ts(i % 10)))
            sigs.extend(
                from_ml_prediction(prediction, switch_id=1, entity_key=ent, timestamp=_ts(i % 10))
            )
            convert_ms.append((time.perf_counter() - t0) * 1000.0)

            clock = FakeTimeProvider(float(i))
            w = CorrelationWindow(duration_sec=30.0, max_signals=64, clock=clock)
            t1 = time.perf_counter()
            for s in sigs:
                w.accept(s)
            window_ms.append((time.perf_counter() - t1) * 1000.0)

            t2 = time.perf_counter()
            engine.correlate(sigs, entity_key=ent)
            corr_ms.append((time.perf_counter() - t2) * 1000.0)

            t3 = time.perf_counter()
            safe_correlate_cycle(
                engine=engine,
                store=MemoryCorrelationStore(max_retained=64),
                switch_id=1,
                feature_batch=flows,
                entropy=entropy,
                prediction=prediction,
                controller_stats=controller,
            )
            combined_ms.append((time.perf_counter() - t3) * 1000.0)

        # Bounded window under storm
        clock = FakeTimeProvider(0.0)
        w = CorrelationWindow(duration_sec=60.0, max_signals=32, clock=clock)
        for i in range(500):
            w.accept(
                SignalEvent(
                    signal_id=f"s{i}",
                    timestamp=_ts(i % 50),
                    category=SignalCategory.DETECTION,
                    source="ml",
                    name="status",
                    value="ATTACK",
                    entity_key=ent,
                )
            )
        self.assertEqual(w.size(), 32)

        payload = {
            "n": n,
            "signal_conversion_median_ms": round(statistics.median(convert_ms), 4),
            "signal_conversion_p95_ms": round(_percentile(convert_ms, 95), 4),
            "window_insertion_median_ms": round(statistics.median(window_ms), 4),
            "window_insertion_p95_ms": round(_percentile(window_ms, 95), 4),
            "correlation_median_ms": round(statistics.median(corr_ms), 4),
            "correlation_p95_ms": round(_percentile(corr_ms, 95), 4),
            "combined_r4_path_median_ms": round(statistics.median(combined_ms), 4),
            "combined_r4_path_p95_ms": round(_percentile(combined_ms, 95), 4),
            "window_max_signals_bound": 32,
            "window_size_after_500_inserts": w.size(),
            "note": "synthetic local path only — not live Mininet",
        }
        out = os.path.join(_ROOT, "logs", "r45_correlation_latency.json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)

        self.assertLess(payload["combined_r4_path_median_ms"], 5.0)
        self.assertLess(payload["combined_r4_path_p95_ms"], 15.0)
        print(
            f"\n[R4.5 PERF] combined median={payload['combined_r4_path_median_ms']}ms "
            f"p95={payload['combined_r4_path_p95_ms']}ms → {out}"
        )


if __name__ == "__main__":
    unittest.main()
