#!/usr/bin/env python3
"""R5.5 — XAI / RCA / combined latency benchmark (synthetic, local)."""

from __future__ import annotations

import json
import os
import statistics
import sys
import time
import unittest

import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import VerificationStatus
from shared_contracts.models import VerificationResult, new_id
from shared_contracts.timeutil import utc_now
from ml_models.feature_builder import FEATURE_NAMES
from xai import XAIEngine
from rca import MemoryRCAStore, RCAContext, RootCauseEngine, safe_enrich_verified_event

N = 200


def _percentile(sorted_vals, pct):
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def _train():
    rng = np.random.RandomState(1)
    X_n = rng.normal(50, 5, size=(40, len(FEATURE_NAMES)))
    X_a = rng.normal(50, 5, size=(40, len(FEATURE_NAMES)))
    X_a[:, 1] = rng.normal(3000, 50, size=40)
    X = np.vstack([X_n, X_a])
    y = np.array([0] * 40 + [1] * 40)
    scaler = StandardScaler().fit(X)
    dt = DecisionTreeClassifier(max_depth=4, random_state=1)
    dt.fit(scaler.transform(X), y)
    return dt, scaler


class TestR5PerfR55(unittest.TestCase):
    def test_xai_rca_combined_latency(self):
        dt, scaler = _train()
        eng = XAIEngine()
        rca = RootCauseEngine()
        raw = list(scaler.inverse_transform([[0.0] * len(FEATURE_NAMES)])[0])
        raw[1] = 3200.0
        pred = {"status": "ATTACK", "confidence": 94.0, "dt_label": 1}

        # Warmup
        for _ in range(10):
            eng.explain(raw, pred, decision_tree=dt, scaler=scaler)

        xai_ms = []
        for i in range(N):
            v = list(raw)
            v[0] = float(i % 17)
            t0 = time.perf_counter()
            eng.explain(v, pred, decision_tree=dt, scaler=scaler)
            xai_ms.append((time.perf_counter() - t0) * 1000.0)

        rca_ms = []
        for i in range(N):
            result = VerificationResult(
                verification_id=new_id(),
                timestamp=utc_now(),
                event_id=f"e{i}",
                status=VerificationStatus.VERIFIED,
                confidence=0.9,
                stages=[],
                attacker_mac="02:aa:aa:aa:aa:01",
                victim_mac="02:bb:bb:bb:bb:02",
                mitigation_eligible=True,
                reason="bench",
            )
            expl = {"method": "DECISION_TREE_PATH", "summary": "bench", "attack_type_hint": "SYN_FLOOD"}
            t0 = time.perf_counter()
            rca.analyze(
                RCAContext(
                    event_id=result.event_id,
                    verification=result,
                    explanation=expl,
                    attack_hint="SYN_FLOOD",
                )
            )
            rca_ms.append((time.perf_counter() - t0) * 1000.0)

        comb_ms = []
        store = MemoryRCAStore()
        for i in range(N):
            result = VerificationResult(
                verification_id=new_id(),
                timestamp=utc_now(),
                event_id=f"c{i}",
                status=VerificationStatus.VERIFIED,
                confidence=0.9,
                stages=[],
                attacker_mac="02:aa:aa:aa:aa:01",
                victim_mac="02:bb:bb:bb:bb:02",
                mitigation_eligible=True,
                reason="bench",
            )
            t0 = time.perf_counter()
            safe_enrich_verified_event(
                result=result,
                prediction=pred,
                explanation={"attack_type_hint": "SYN_FLOOD", "vector_summary": dict(zip(FEATURE_NAMES, raw))},
                feature_vector=raw,
                detector=None,
                store=store,
                xai_engine=eng,
                rca_engine=rca,
            )
            # Need DT on enrich — pass via explain path: set decision through engine only
            comb_ms.append((time.perf_counter() - t0) * 1000.0)

        # Re-run combined with explicit DT via a thin wrapper
        class Det:
            decision_tree = dt
            scaler = None

            def __init__(self):
                self.scaler = scaler

        comb2 = []
        det = Det()
        for i in range(N):
            result = VerificationResult(
                verification_id=new_id(),
                timestamp=utc_now(),
                event_id=f"d{i}",
                status=VerificationStatus.VERIFIED,
                confidence=0.9,
                stages=[],
                attacker_mac="02:aa:aa:aa:aa:01",
                victim_mac="02:bb:bb:bb:bb:02",
                mitigation_eligible=True,
                reason="bench",
            )
            t0 = time.perf_counter()
            safe_enrich_verified_event(
                result=result,
                prediction=pred,
                explanation={"attack_type_hint": "SYN_FLOOD"},
                feature_vector=raw,
                detector=det,
                store=store,
                xai_engine=eng,
                rca_engine=rca,
            )
            comb2.append((time.perf_counter() - t0) * 1000.0)

        xai_ms.sort()
        rca_ms.sort()
        comb2.sort()
        payload = {
            "iterations": N,
            "xai_median_ms": round(statistics.median(xai_ms), 4),
            "xai_p95_ms": round(_percentile(xai_ms, 95), 4),
            "rca_median_ms": round(statistics.median(rca_ms), 4),
            "rca_p95_ms": round(_percentile(rca_ms, 95), 4),
            "combined_median_ms": round(statistics.median(comb2), 4),
            "combined_p95_ms": round(_percentile(comb2, 95), 4),
            "live_network": False,
            "shap": False,
        }
        out = os.path.join(_ROOT, "logs", "r55_xai_rca_latency.json")
        try:
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
                fh.write("\n")
        except OSError:
            pass

        self.assertLess(payload["xai_median_ms"], 20.0)
        self.assertLess(payload["rca_median_ms"], 20.0)
        print(
            f"\n[R5.5 PERF] XAI median={payload['xai_median_ms']}ms p95={payload['xai_p95_ms']}ms | "
            f"RCA median={payload['rca_median_ms']}ms p95={payload['rca_p95_ms']}ms | "
            f"combined median={payload['combined_median_ms']}ms p95={payload['combined_p95_ms']}ms"
        )


if __name__ == "__main__":
    unittest.main()
