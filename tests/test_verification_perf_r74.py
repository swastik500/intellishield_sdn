#!/usr/bin/env python3
"""
R7.4 — VerificationEngine latency benchmark (synthetic, deterministic).

Does not measure live-network or Mininet performance.
Writes summary to logs/r74_verification_latency.json when writable.
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import time
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from verification.config import VerificationConfig
from verification.engine import VerificationEngine, VerificationInput

ATTACKER = "02:aa:aa:aa:aa:01"
VICTIM = "02:bb:bb:bb:bb:02"
N_ITERS = 400


def _percentile(sorted_vals, pct):
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


class TestVerificationLatency(unittest.TestCase):
    def test_median_and_p95_synthetic(self):
        engine = VerificationEngine(config=VerificationConfig())
        flows = [
            {
                "src_mac": ATTACKER,
                "dst_mac": VICTIM,
                "packet_rate": 9000.0,
                "priority": 1,
            },
            {
                "src_mac": "02:cc:cc:cc:cc:03",
                "dst_mac": VICTIM,
                "packet_rate": 50.0,
                "priority": 1,
            },
        ]
        inp = VerificationInput(
            dpid=1,
            prediction={"status": "ATTACK", "confidence": 95.0, "source": "ml"},
            explanation={"attack_type_hint": "SYN_FLOOD"},
            flow_features=flows,
            warmup_cycles_done=10,
            attack_streak=2,
        )

        # Warm-up JIT / imports
        for _ in range(20):
            engine.verify(inp)

        samples_ms = []
        for _ in range(N_ITERS):
            t0 = time.perf_counter()
            result = engine.verify(inp)
            dt_ms = (time.perf_counter() - t0) * 1000.0
            samples_ms.append(dt_ms)
            self.assertTrue(result.mitigation_eligible)

        samples_ms.sort()
        median = statistics.median(samples_ms)
        p95 = _percentile(samples_ms, 95)

        payload = {
            "iterations": N_ITERS,
            "median_ms": round(median, 4),
            "p95_ms": round(p95, 4),
            "min_ms": round(samples_ms[0], 4),
            "max_ms": round(samples_ms[-1], 4),
            "input": "synthetic_attack_verified_path",
            "live_network": False,
        }
        out_path = os.path.join(_ROOT, "logs", "r74_verification_latency.json")
        try:
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
                fh.write("\n")
        except OSError:
            pass

        # Controller poll cycle is ~5s; verification must stay negligible.
        self.assertLess(median, 5.0, f"median {median:.3f}ms too high")
        self.assertLess(p95, 15.0, f"p95 {p95:.3f}ms too high")
        print(
            f"\n[R7.4 PERF] median={median:.4f}ms  p95={p95:.4f}ms  "
            f"n={N_ITERS} (synthetic)"
        )


if __name__ == "__main__":
    unittest.main()
