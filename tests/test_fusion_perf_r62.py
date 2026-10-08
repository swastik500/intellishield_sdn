#!/usr/bin/env python3
"""R6.2 fusion performance — median / p95 latency on deterministic packs."""

from __future__ import annotations

import json
import os
import statistics
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.models import CorrelationResult
from fusion import (
    CollaborativeFusionEngine,
    adapt_adwin_alerts,
    adapt_entropy_metrics,
    adapt_hdbscan_summary,
    adapt_ml_prediction,
)

_TS = datetime(2026, 7, 27, 3, 30, 0, tzinfo=timezone.utc)
_ITERS = 400
_WARMUP = 50


def _pack():
    return [
        adapt_ml_prediction(
            {"status": "ATTACK", "confidence": 88.0}, timestamp=_TS
        ),
        adapt_entropy_metrics(
            {"status": "ALERT", "confidence": 80.0, "entropy_score": 0.2},
            timestamp=_TS,
        ),
        adapt_adwin_alerts([{"metric_name": "flow_count"}], timestamp=_TS),
        adapt_hdbscan_summary(
            {"n_attack": 0, "clusters": []}, timestamp=_TS
        ),
    ]


class TestR62FusionPerf(unittest.TestCase):
    def test_fusion_latency_median_p95(self):
        eng = CollaborativeFusionEngine()
        results = _pack()
        corr = CorrelationResult(
            correlation_id="perf",
            timestamp=_TS,
            score=0.7,
            evidence={"status": "CORRELATED"},
        )
        for _ in range(_WARMUP):
            eng.fuse(detector_results=results, correlation=corr, timestamp=_TS)

        samples_ms = []
        for i in range(_ITERS):
            t0 = time.perf_counter()
            eng.fuse(
                detector_results=results,
                correlation=corr,
                timestamp=_TS,
                fusion_id=f"perf-{i}",
            )
            samples_ms.append((time.perf_counter() - t0) * 1000.0)

        samples_ms.sort()
        median = statistics.median(samples_ms)
        p95 = samples_ms[min(len(samples_ms) - 1, int(round(0.95 * (len(samples_ms) - 1))))]
        artifact = {
            "iters": _ITERS,
            "median_ms": round(median, 4),
            "p95_ms": round(p95, 4),
            "max_ms": round(samples_ms[-1], 4),
            "budget_median_ms": 5.0,
            "budget_p95_ms": 15.0,
        }
        out = Path(_ROOT) / "logs" / "r62_fusion_perf.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(artifact, indent=2), encoding="utf-8")

        self.assertLess(median, 5.0, f"median {median:.3f}ms exceeds 5ms budget")
        self.assertLess(p95, 15.0, f"p95 {p95:.3f}ms exceeds 15ms budget")
        print(f"\n[R6.2 perf] median={median:.4f}ms p95={p95:.4f}ms → {out}")


if __name__ == "__main__":
    unittest.main()
