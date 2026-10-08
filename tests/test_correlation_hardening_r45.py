#!/usr/bin/env python3
"""R4.5 — Correlation correctness scenarios + false-correlation + failure injection."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from correlation import (
    CorrelationConfig,
    CorrelationEngine,
    CorrelationWindow,
    FakeTimeProvider,
    SignalCategory,
    SignalEvent,
    build_entity_key,
    safe_correlate_cycle,
)
from correlation.adapters import from_flow_features, from_ml_prediction
from correlation.persistence import (
    JsonlCorrelationStore,
    MemoryCorrelationStore,
    read_correlation_history,
    safe_append_correlation,
)
from correlation.engine import CorrelationEngine as Eng


def _ts(sec=0):
    return datetime(2026, 7, 26, 15, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=sec)


ENT_A = build_entity_key(src_mac="02:aa:aa:aa:aa:01", switch_id=1)
ENT_B = build_entity_key(src_mac="02:bb:bb:bb:bb:02", switch_id=1)


def _sig(
    sid,
    sec,
    *,
    cat=SignalCategory.DETECTION,
    source="ml",
    name="status",
    value="ATTACK",
    entity=ENT_A,
    availability="AVAILABLE",
    normalized_score=None,
    unit="",
):
    return SignalEvent(
        signal_id=sid,
        timestamp=_ts(sec),
        category=cat,
        source=source,
        name=name,
        value=value,
        unit=unit,
        entity_key=entity,
        availability=availability,
        normalized_score=normalized_score,
    )


def _score(signals, **kwargs):
    r = CorrelationEngine().correlate(signals, entity_key=ENT_A, **kwargs)
    return float(r.score or 0.0), r


class TestR45CorrectnessScenarios(unittest.TestCase):
    """Deterministic A–J scenarios with justified ordering."""

    def test_scenario_ordering_A_through_G(self):
        # A Normal baseline — weak/no anomalous evidence
        a_sigs = [
            _sig("n1", 0, value="NORMAL", source="ml", name="status"),
            _sig(
                "n2",
                0,
                cat=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                value=20.0,
                normalized_score=0.05,
            ),
        ]
        # B Single weak anomaly
        b_sigs = [
            _sig("w1", 0, value="WARNING", source="entropy", name="status"),
        ]
        # C Strong ML only
        c_sigs = [_sig("m1", 0, value="ATTACK", source="ml", name="status")]
        # D Flow + entropy
        d_sigs = [
            _sig(
                "f1",
                0,
                cat=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                value=8000.0,
                normalized_score=0.9,
            ),
            _sig("e1", 1, value="ALERT", source="entropy", name="status"),
        ]
        # E Flow + ML
        e_sigs = [
            _sig(
                "f2",
                0,
                cat=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                value=8000.0,
                normalized_score=0.9,
            ),
            _sig("m2", 1, value="ATTACK", source="ml", name="status"),
        ]
        # F Flow + entropy + ML
        f_sigs = [
            _sig(
                "f3",
                0,
                cat=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                value=9000.0,
                normalized_score=0.95,
            ),
            _sig("e3", 1, value="ALERT", source="entropy", name="status"),
            _sig("m3", 2, value="ATTACK", source="ml", name="status"),
        ]
        # G Multi-category + controller
        g_sigs = f_sigs + [
            _sig(
                "c1",
                2,
                cat=SignalCategory.CONTROL_PLANE,
                source="controller_stats",
                name="cpu_percent",
                value=88.0,
                unit="percent",
                entity=None,
            )
        ]

        sa, _ = _score(a_sigs)
        sb, _ = _score(b_sigs)
        sc, _ = _score(c_sigs)
        sd, rd = _score(d_sigs)
        se, re = _score(e_sigs)
        sf, rf = _score(f_sigs)
        sg, rg = _score(g_sigs)

        # Justified ordering: normal < weak < strong-ML-only
        self.assertLess(sa, sb)
        self.assertLess(sb, sc)
        # Multi independent evidence > single-category strong ML
        self.assertGreater(sd, sc)
        self.assertGreater(se, sc)
        # Three categories (flow+entropy+ML) ≥ two-category pairs
        self.assertGreaterEqual(sf, sd)
        self.assertGreaterEqual(sf, se)
        # Controller adds optional diversity — score should not drop
        self.assertGreaterEqual(sg, sf * 0.98)
        self.assertGreaterEqual(rg.evidence["diversity_count"], rf.evidence["diversity_count"])

        artifact = {
            "scenarios": {
                "A_normal": sa,
                "B_weak": sb,
                "C_ml_only": sc,
                "D_flow_entropy": sd,
                "E_flow_ml": se,
                "F_flow_entropy_ml": sf,
                "G_plus_controller": sg,
            },
            "ordering_checks": [
                "A < B < C",
                "D,E > C",
                "F >= D,E",
                "G >= F (approx)",
            ],
            "note": "synthetic deterministic; not live Mininet",
        }
        out = os.path.join(_ROOT, "logs", "r45_correlation_correctness.json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(artifact, fh, indent=2)

    def test_H_unrelated_entities(self):
        signals = [
            _sig("a", 0, value="ATTACK", entity=ENT_A),
            _sig(
                "b",
                1,
                cat=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                normalized_score=0.95,
                value=1.0,
                entity=ENT_B,
            ),
        ]
        r = CorrelationEngine().correlate(signals, entity_key=ENT_A)
        self.assertEqual(r.evidence["entity_rejected_count"], 1)
        self.assertEqual(r.evidence["diversity_count"], 1)

    def test_I_stale_evidence_excluded(self):
        signals = [
            _sig("stale", 0, value="ATTACK", availability="STALE"),
            _sig(
                "flow",
                1,
                cat=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                normalized_score=0.2,
                value=1.0,
            ),
        ]
        r = CorrelationEngine().correlate(signals, entity_key=ENT_A)
        self.assertNotIn("stale", r.signal_ids)
        self.assertEqual(len(r.evidence["excluded_unavailable_or_stale"]), 1)

    def test_J_duplicate_storm_no_inflation(self):
        one = [_sig("m0", 0, value="ATTACK")]
        storm = [_sig(f"m{i}", 0, value="ATTACK") for i in range(40)]
        s1, _ = _score(one)
        s2, r2 = _score(storm)
        self.assertAlmostEqual(s1, s2, places=5)
        self.assertGreaterEqual(r2.evidence["duplicates_dropped"], 39)


class TestR45FalseCorrelation(unittest.TestCase):
    def test_outside_window(self):
        w = CorrelationWindow(start=_ts(0), end=_ts(5), max_signals=20)
        r = CorrelationEngine().correlate(
            [
                _sig("in", 2, value="ATTACK"),
                _sig("out", 40, value="ATTACK"),
            ],
            entity_key=ENT_A,
            window=w,
        )
        self.assertEqual(r.signal_ids, ["in"])

    def test_temporally_distant_lowers_score(self):
        near = [
            _sig("m", 0, value="ATTACK"),
            _sig(
                "f",
                2,
                cat=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                normalized_score=0.9,
                value=1.0,
            ),
        ]
        far = [
            _sig("m", 0, value="ATTACK"),
            _sig(
                "f",
                29,
                cat=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                normalized_score=0.9,
                value=1.0,
            ),
        ]
        sn, _ = _score(near)
        sf, _ = _score(far)
        self.assertGreater(sn, sf)

    def test_malformed_and_nan_inf_rejected(self):
        r = CorrelationEngine().correlate([{"bad": True}])  # type: ignore[list-item]
        self.assertEqual(r.evidence["status"], "ERROR")
        with self.assertRaises(ValueError):
            SignalEvent(
                signal_id="x",
                timestamp=_ts(),
                category=SignalCategory.DETECTION,
                source="ml",
                name="confidence",
                value=float("nan"),
            )
        with self.assertRaises(ValueError):
            SignalEvent(
                signal_id="y",
                timestamp=_ts(),
                category=SignalCategory.DETECTION,
                source="ml",
                name="confidence",
                value=1.0,
                normalized_score=float("inf"),
            )

    def test_unhealthy_degraded_and_not_available(self):
        healthy, _ = _score([_sig("h", 0, value="ATTACK")])
        degraded, _ = _score(
            [_sig("d", 0, value="ATTACK", availability="DEGRADED")]
        )
        self.assertGreater(healthy, degraded)
        r = CorrelationEngine().correlate(
            [
                _sig("na", 0, value="ATTACK", availability="NOT_AVAILABLE"),
                _sig(
                    "f",
                    0,
                    cat=SignalCategory.DATA_PLANE,
                    source="flow_stats",
                    name="packet_rate",
                    normalized_score=0.5,
                    value=1.0,
                ),
            ],
            entity_key=ENT_A,
        )
        self.assertNotIn("CONTROL_PLANE", r.evidence.get("participating_categories", []))

    def test_missing_timestamp_cannot_construct(self):
        with self.assertRaises(TypeError):
            SignalEvent(  # type: ignore[call-arg]
                signal_id="x",
                category=SignalCategory.DETECTION,
                source="ml",
                name="status",
                value="ATTACK",
            )


class TestR45FailureInjection(unittest.TestCase):
    def test_engine_exception_isolated(self):
        class Boom(Eng):
            def correlate(self, *a, **k):
                raise RuntimeError("engine boom")

        out = safe_correlate_cycle(
            engine=Boom(),
            store=MemoryCorrelationStore(),
            switch_id=1,
            feature_batch=[
                {
                    "src_mac": "02:aa:aa:aa:aa:01",
                    "dst_mac": "02:bb:bb:bb:bb:02",
                    "packet_rate": 1000.0,
                    "byte_rate": 1000.0,
                    "switch_id": 1,
                }
            ],
            prediction={"status": "ATTACK", "confidence": 90.0},
        )
        self.assertEqual(out.status, "ERROR")

    def test_adapter_exception_isolated(self):
        with mock.patch(
            "correlation.runtime.from_flow_features",
            side_effect=RuntimeError("adapter boom"),
        ):
            # build_cycle_signals catches and returns []
            from correlation.runtime import build_cycle_signals

            sigs = build_cycle_signals(switch_id=1, feature_batch=[{"x": 1}])
            self.assertEqual(sigs, [])

    def test_persistence_failure_isolated(self):
        class BoomStore:
            name = "boom"

            def append(self, result):
                raise OSError("disk full")

        out = safe_correlate_cycle(
            engine=CorrelationEngine(),
            store=BoomStore(),  # type: ignore[arg-type]
            switch_id=1,
            feature_batch=[
                {
                    "src_mac": "02:aa:aa:aa:aa:01",
                    "dst_mac": "02:bb:bb:bb:bb:02",
                    "packet_rate": 5000.0,
                    "byte_rate": 1e5,
                    "switch_id": 1,
                }
            ],
            entropy={"status": "ALERT", "entropy_score": 0.2},
            prediction={"status": "ATTACK", "confidence": 95.0},
        )
        self.assertTrue(out.ran)
        self.assertIsNotNone(out.result)
        self.assertFalse(out.persisted)

    def test_state_saturation_window(self):
        clock = FakeTimeProvider(0.0)
        w = CorrelationWindow(duration_sec=100.0, max_signals=5, clock=clock)
        for i in range(20):
            w.accept(_sig(f"s{i}", i, value="ATTACK"))
        self.assertEqual(w.size(), 5)

    def test_history_corruption_and_dashboard_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "correlation_results.jsonl")
            self.assertEqual(read_correlation_history(path, limit=5), [])
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{bad\nnot-json\n")
                fh.write(
                    json.dumps(
                        {
                            "correlation_id": "ok-1",
                            "timestamp": _ts().isoformat().replace("+00:00", "Z"),
                            "score": 0.5,
                            "signal_ids": [],
                            "evidence": {},
                        }
                    )
                    + "\n"
                )
            rows = read_correlation_history(path, limit=10)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["correlation_id"], "ok-1")

    def test_no_mitigation_from_r4(self):
        with mock.patch(
            "mitigation.mitigation_engine.MitigationEngine.handle_alert"
        ) as ha:
            safe_correlate_cycle(
                engine=CorrelationEngine(),
                store=MemoryCorrelationStore(),
                switch_id=1,
                prediction={"status": "ATTACK", "confidence": 99.0},
                entropy={"status": "ALERT", "entropy_score": 0.1},
                feature_batch=[
                    {
                        "src_mac": "02:aa:aa:aa:aa:01",
                        "dst_mac": "02:bb:bb:bb:bb:02",
                        "packet_rate": 9000.0,
                        "byte_rate": 1e6,
                        "switch_id": 1,
                    }
                ],
            )
            ha.assert_not_called()


if __name__ == "__main__":
    unittest.main()
