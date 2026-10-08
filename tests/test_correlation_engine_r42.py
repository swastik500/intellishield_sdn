#!/usr/bin/env python3
"""R4.2 — CorrelationEngine core unit tests."""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from correlation import (
    CorrelationConfig,
    CorrelationEngine,
    CorrelationWindow,
    SignalCategory,
    SignalEvent,
    build_entity_key,
)


def _ts(sec=0):
    return datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=sec)


def _sig(
    sid,
    sec,
    *,
    cat=SignalCategory.DETECTION,
    source="ml",
    name="status",
    value="ATTACK",
    entity=None,
    availability="AVAILABLE",
    normalized_score=None,
    unit="",
    event_id=None,
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
        event_id=event_id,
    )


ENT_A = build_entity_key(src_mac="02:aa:aa:aa:aa:01", switch_id=1)
ENT_B = build_entity_key(src_mac="02:bb:bb:bb:bb:02", switch_id=1)


class TestR42CorrelationEngine(unittest.TestCase):
    def setUp(self):
        self.engine = CorrelationEngine(CorrelationConfig())

    def test_single_signal(self):
        r = self.engine.correlate(
            [_sig("s1", 0, value="ATTACK", entity=ENT_A)],
            entity_key=ENT_A,
        )
        self.assertIsNotNone(r.score)
        self.assertGreater(r.score, 0.0)
        self.assertLessEqual(r.score, 1.0)
        self.assertEqual(r.evidence["diversity_count"], 1)
        self.assertEqual(r.evidence["status"], "WEAK_CORRELATED")  # 1 category
        self.assertFalse(r.evidence["mitigation_authorized"])

    def test_same_category_multiple_signals_no_inflation(self):
        # Many ML statuses — category uses max, not sum
        many = [
            _sig(f"m{i}", i, value="ATTACK", entity=ENT_A, source="ml")
            for i in range(8)
        ]
        one = [_sig("m0", 0, value="ATTACK", entity=ENT_A, source="ml")]
        r_many = self.engine.correlate(many, entity_key=ENT_A)
        r_one = self.engine.correlate(one, entity_key=ENT_A)
        self.assertAlmostEqual(r_many.score, r_one.score, places=5)

    def test_two_independent_categories(self):
        signals = [
            _sig("ml1", 0, value="ATTACK", entity=ENT_A),
            _sig(
                "en1",
                1,
                cat=SignalCategory.DETECTION,
                source="entropy",
                name="status",
                value="ALERT",
                entity=ENT_A,
            ),
            _sig(
                "fl1",
                2,
                cat=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                value=5000.0,
                entity=ENT_A,
                normalized_score=0.8,
            ),
        ]
        # ml+entropy still one DETECTION category; + flow → 2 cats
        r = self.engine.correlate(signals, entity_key=ENT_A)
        self.assertGreaterEqual(r.evidence["diversity_count"], 2)
        self.assertIn("DATA_PLANE", r.evidence["participating_categories"])
        self.assertIn("DETECTION", r.evidence["participating_categories"])

    def test_three_categories_score_higher_than_two(self):
        two = [
            _sig("ml", 0, value="ATTACK", entity=ENT_A),
            _sig(
                "fl",
                1,
                cat=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                normalized_score=0.9,
                value=1.0,
                entity=ENT_A,
            ),
        ]
        three = two + [
            _sig(
                "cpu",
                2,
                cat=SignalCategory.CONTROL_PLANE,
                source="controller_stats",
                name="cpu_percent",
                value=90.0,
                unit="percent",
                # switch-scoped (no entity)
            )
        ]
        r2 = self.engine.correlate(two, entity_key=ENT_A)
        r3 = self.engine.correlate(three, entity_key=ENT_A)
        self.assertGreater(r3.score, r2.score)
        self.assertEqual(r3.evidence["diversity_count"], 3)

    def test_weak_vs_strong_evidence(self):
        weak = [
            _sig("ml", 0, value="WARNING", entity=ENT_A),
            _sig(
                "fl",
                1,
                cat=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                normalized_score=0.2,
                value=1.0,
                entity=ENT_A,
            ),
        ]
        strong = [
            _sig("ml", 0, value="ATTACK", entity=ENT_A),
            _sig(
                "fl",
                1,
                cat=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                normalized_score=0.95,
                value=1.0,
                entity=ENT_A,
            ),
        ]
        rw = self.engine.correlate(weak, entity_key=ENT_A)
        rs = self.engine.correlate(strong, entity_key=ENT_A)
        self.assertGreater(rs.score, rw.score)

    def test_temporally_distant_evidence_reduces_score(self):
        near = [
            _sig("ml", 0, value="ATTACK", entity=ENT_A),
            _sig(
                "fl",
                2,
                cat=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                normalized_score=0.9,
                value=1.0,
                entity=ENT_A,
            ),
        ]
        far = [
            _sig("ml", 0, value="ATTACK", entity=ENT_A),
            _sig(
                "fl",
                28,
                cat=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                normalized_score=0.9,
                value=1.0,
                entity=ENT_A,
            ),
        ]
        rn = self.engine.correlate(near, entity_key=ENT_A)
        rf = self.engine.correlate(far, entity_key=ENT_A)
        self.assertGreater(rn.score, rf.score)

    def test_same_entity_keeps_both(self):
        r = self.engine.correlate(
            [
                _sig("a", 0, value="ATTACK", entity=ENT_A),
                _sig(
                    "b",
                    1,
                    cat=SignalCategory.DATA_PLANE,
                    source="flow_stats",
                    name="packet_rate",
                    normalized_score=0.8,
                    value=1.0,
                    entity=ENT_A,
                ),
            ],
            entity_key=ENT_A,
        )
        self.assertEqual(len(r.signal_ids), 2)

    def test_different_entity_rejected(self):
        r = self.engine.correlate(
            [
                _sig("a", 0, value="ATTACK", entity=ENT_A),
                _sig(
                    "b",
                    1,
                    cat=SignalCategory.DATA_PLANE,
                    source="flow_stats",
                    name="packet_rate",
                    normalized_score=0.9,
                    value=1.0,
                    entity=ENT_B,
                ),
            ],
            entity_key=ENT_A,
        )
        self.assertEqual(r.evidence["entity_rejected_count"], 1)
        self.assertEqual(r.evidence["diversity_count"], 1)

    def test_missing_controller_not_negative(self):
        # Only ML + flow — no controller. Completeness < 1 but score not zeroed.
        r = self.engine.correlate(
            [
                _sig("ml", 0, value="ATTACK", entity=ENT_A),
                _sig(
                    "fl",
                    1,
                    cat=SignalCategory.DATA_PLANE,
                    source="flow_stats",
                    name="packet_rate",
                    normalized_score=0.85,
                    value=1.0,
                    entity=ENT_A,
                ),
            ],
            entity_key=ENT_A,
        )
        self.assertGreater(r.score, 0.3)
        self.assertNotIn("CONTROL_PLANE", r.evidence["participating_categories"])
        self.assertLess(r.evidence["evidence_completeness"], 1.0)

    def test_missing_ml_signal(self):
        r = self.engine.correlate(
            [
                _sig(
                    "en",
                    0,
                    source="entropy",
                    name="status",
                    value="ALERT",
                    entity=ENT_A,
                ),
                _sig(
                    "fl",
                    1,
                    cat=SignalCategory.DATA_PLANE,
                    source="flow_stats",
                    name="packet_rate",
                    normalized_score=0.8,
                    value=1.0,
                    entity=ENT_A,
                ),
            ],
            entity_key=ENT_A,
        )
        self.assertGreater(r.score, 0.0)
        self.assertIn("DETECTION", r.evidence["participating_categories"])

    def test_duplicate_signal_storm(self):
        storm = [
            _sig("dup", i % 3, value="ATTACK", entity=ENT_A)  # same id → replace
            for i in range(50)
        ]
        # unique ids same type
        storm2 = [
            _sig(f"dup{i}", 0, value="ATTACK", entity=ENT_A) for i in range(50)
        ]
        r = self.engine.correlate(storm2, entity_key=ENT_A)
        self.assertGreaterEqual(r.evidence["duplicates_dropped"], 49)
        # Still single-category score
        self.assertEqual(r.evidence["diversity_count"], 1)

    def test_unhealthy_degraded_reduces_strength(self):
        healthy = [_sig("h", 0, value="ATTACK", entity=ENT_A)]
        degraded = [
            _sig("d", 0, value="ATTACK", entity=ENT_A, availability="DEGRADED")
        ]
        rh = self.engine.correlate(healthy, entity_key=ENT_A)
        rd = self.engine.correlate(degraded, entity_key=ENT_A)
        self.assertGreater(rh.score, rd.score)

    def test_stale_signal_excluded(self):
        r = self.engine.correlate(
            [
                _sig("stale", 0, value="ATTACK", entity=ENT_A, availability="STALE"),
                _sig(
                    "fl",
                    1,
                    cat=SignalCategory.DATA_PLANE,
                    source="flow_stats",
                    name="packet_rate",
                    normalized_score=0.7,
                    value=1.0,
                    entity=ENT_A,
                ),
            ],
            entity_key=ENT_A,
        )
        self.assertEqual(len(r.evidence["excluded_unavailable_or_stale"]), 1)
        self.assertNotIn("stale", r.signal_ids)

    def test_threshold_boundary_correlated(self):
        cfg = CorrelationConfig(correlated_min_score=0.45, correlated_min_categories=2)
        eng = CorrelationEngine(cfg)
        r = eng.correlate(
            [
                _sig("ml", 0, value="ATTACK", entity=ENT_A),
                _sig(
                    "fl",
                    1,
                    cat=SignalCategory.DATA_PLANE,
                    source="flow_stats",
                    name="packet_rate",
                    normalized_score=0.9,
                    value=1.0,
                    entity=ENT_A,
                ),
            ],
            entity_key=ENT_A,
        )
        self.assertIn(r.evidence["status"], ("CORRELATED", "WEAK_CORRELATED", "PARTIAL"))
        if r.score >= 0.45 and r.evidence["diversity_count"] >= 2:
            self.assertEqual(r.evidence["status"], "CORRELATED")

    def test_score_bounds(self):
        r = self.engine.correlate(
            [
                _sig("ml", 0, value="ATTACK", entity=ENT_A),
                _sig(
                    "en",
                    0,
                    source="entropy",
                    name="entropy_score",
                    value=0.1,
                    entity=ENT_A,
                ),
                _sig(
                    "fl",
                    1,
                    cat=SignalCategory.DATA_PLANE,
                    source="flow_stats",
                    name="packet_rate",
                    normalized_score=1.0,
                    value=1.0,
                    entity=ENT_A,
                ),
                _sig(
                    "cpu",
                    1,
                    cat=SignalCategory.CONTROL_PLANE,
                    source="controller_stats",
                    name="cpu_percent",
                    value=99.0,
                    unit="percent",
                ),
                _sig(
                    "ver",
                    2,
                    cat=SignalCategory.SECURITY_RESPONSE,
                    source="verification",
                    name="status",
                    value="VERIFIED",
                    entity=ENT_A,
                ),
            ],
            entity_key=ENT_A,
        )
        self.assertGreaterEqual(r.score, 0.0)
        self.assertLessEqual(r.score, 1.0)

    def test_determinism(self):
        signals = [
            _sig("ml", 0, value="ATTACK", entity=ENT_A, event_id="e1"),
            _sig(
                "fl",
                1,
                cat=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="packet_rate",
                normalized_score=0.8,
                value=1.0,
                entity=ENT_A,
                event_id="e1",
            ),
        ]
        r1 = self.engine.correlate(signals, entity_key=ENT_A, event_id="e1")
        r2 = self.engine.correlate(list(signals), entity_key=ENT_A, event_id="e1")
        self.assertEqual(r1.score, r2.score)
        self.assertEqual(r1.correlation_id, r2.correlation_id)
        self.assertEqual(r1.evidence["factors"], r2.evidence["factors"])

    def test_insertion_order_invariance(self):
        a = _sig("ml", 0, value="ATTACK", entity=ENT_A)
        b = _sig(
            "fl",
            1,
            cat=SignalCategory.DATA_PLANE,
            source="flow_stats",
            name="packet_rate",
            normalized_score=0.8,
            value=1.0,
            entity=ENT_A,
        )
        c = _sig(
            "cpu",
            2,
            cat=SignalCategory.CONTROL_PLANE,
            source="controller_stats",
            name="cpu_percent",
            value=80.0,
            unit="percent",
        )
        r1 = self.engine.correlate([a, b, c], entity_key=ENT_A)
        r2 = self.engine.correlate([c, a, b], entity_key=ENT_A)
        r3 = self.engine.correlate([b, c, a], entity_key=ENT_A)
        self.assertEqual(r1.score, r2.score)
        self.assertEqual(r2.score, r3.score)
        self.assertEqual(r1.signal_ids, r2.signal_ids)

    def test_empty_window(self):
        r = self.engine.correlate([])
        self.assertEqual(r.score, 0.0)
        self.assertEqual(r.evidence["status"], "EMPTY")

    def test_malformed_input(self):
        r = self.engine.correlate([{"not": "a signal"}])  # type: ignore[list-item]
        self.assertEqual(r.evidence["status"], "ERROR")
        self.assertEqual(r.score, 0.0)

    def test_not_available_controller_ignored(self):
        r = self.engine.correlate(
            [
                _sig("ml", 0, value="ATTACK", entity=ENT_A),
                _sig(
                    "cpu",
                    0,
                    cat=SignalCategory.CONTROL_PLANE,
                    source="controller_stats",
                    name="cpu_percent",
                    value=None,
                    availability="NOT_AVAILABLE",
                ),
            ],
            entity_key=ENT_A,
        )
        self.assertNotIn("CONTROL_PLANE", r.evidence["participating_categories"])
        self.assertEqual(len(r.evidence["excluded_unavailable_or_stale"]), 1)

    def test_window_bounds_filter(self):
        w = CorrelationWindow(
            start=_ts(0),
            end=_ts(0) + timedelta(seconds=5),
            max_signals=20,
        )
        r = self.engine.correlate(
            [
                _sig("in", 2, value="ATTACK", entity=ENT_A),
                _sig("out", 20, value="ATTACK", entity=ENT_A),
            ],
            entity_key=ENT_A,
            window=w,
        )
        self.assertEqual(r.signal_ids, ["in"])

    def test_no_mitigation_fields(self):
        r = self.engine.correlate(
            [_sig("ml", 0, value="ATTACK", entity=ENT_A)],
            entity_key=ENT_A,
        )
        self.assertFalse(r.evidence.get("mitigation_authorized"))
        self.assertNotIn("openflow", str(r.evidence).lower())


if __name__ == "__main__":
    unittest.main()
