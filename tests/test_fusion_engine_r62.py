#!/usr/bin/env python3
"""R6.2 — Reliability-aware CollaborativeFusionEngine (no production wiring)."""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import DetectionDecision, DetectorHealth, DetectorType
from shared_contracts.models import CorrelationResult, DetectorResult
from fusion import (
    CollaborativeFusionEngine,
    FusionConfig,
    adapt_adwin_alerts,
    adapt_correlation_result,
    adapt_entropy_metrics,
    adapt_hdbscan_summary,
    adapt_ml_prediction,
    classify_legacy_difference,
)
from fusion.legacy_compare import legacy_production_decision


def _ts(offset_s: float = 0.0) -> datetime:
    return datetime(2026, 7, 27, 3, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_s)


def _ml(status: str, conf: float, *, health=DetectorHealth.SUCCESS, t=0.0):
    return adapt_ml_prediction(
        {"status": status, "confidence": conf},
        timestamp=_ts(t),
        health=health,
    )


def _ent(status: str, conf: float, *, health=DetectorHealth.SUCCESS, t=0.0):
    return adapt_entropy_metrics(
        {"status": status, "confidence": conf, "entropy_score": 0.3},
        timestamp=_ts(t),
        health=health,
    )


def _corr(score: float, status: str = "CORRELATED", t: float = 0.0) -> CorrelationResult:
    return CorrelationResult(
        correlation_id="c-r62",
        timestamp=_ts(t),
        score=score,
        evidence={"status": status},
    )


class TestR62BothAgree(unittest.TestCase):
    def setUp(self):
        self.eng = CollaborativeFusionEngine()

    def test_ml_attack_entropy_attack(self):
        # entropy ALERT is attack-like
        fd = self.eng.fuse(
            detector_results=[_ml("ATTACK", 92), _ent("ALERT", 85)],
            timestamp=_ts(1),
            fusion_id="f-agree-atk",
        )
        self.assertEqual(fd.decision, DetectionDecision.ATTACK)
        self.assertFalse(fd.disagreement)
        self.assertIn("ML", fd.participating)
        self.assertIn("ENTROPY", fd.participating)
        self.assertGreaterEqual(fd.confidence or 0, 0.55)

    def test_ml_normal_entropy_normal(self):
        fd = self.eng.fuse(
            detector_results=[_ml("NORMAL", 80), _ent("NORMAL", 75)],
            timestamp=_ts(1),
        )
        self.assertEqual(fd.decision, DetectionDecision.NORMAL)
        self.assertFalse(fd.disagreement)


class TestR62Disagreement(unittest.TestCase):
    def setUp(self):
        self.eng = CollaborativeFusionEngine()

    def test_ml_attack_entropy_normal(self):
        fd = self.eng.fuse(
            detector_results=[_ml("ATTACK", 92), _ent("NORMAL", 85)],
            timestamp=_ts(1),
        )
        self.assertTrue(fd.disagreement)
        self.assertIn(fd.decision, (DetectionDecision.SUSPICIOUS, DetectionDecision.ATTACK))
        self.assertGreater(fd.evidence["scores"]["C"], 0.3)
        self.assertIn("primary_votes", fd.evidence)

    def test_ml_normal_entropy_attack(self):
        fd = self.eng.fuse(
            detector_results=[_ml("NORMAL", 85), _ent("ALERT", 90)],
            timestamp=_ts(1),
        )
        self.assertTrue(fd.disagreement)
        self.assertNotEqual(fd.decision, DetectionDecision.NONE)


class TestR62ReliabilitySkew(unittest.TestCase):
    def test_strong_ml_weak_entropy(self):
        cfg = FusionConfig(
            base_reliability={"ML": 1.0, "ENTROPY": 0.4},
        )
        # rebuild registry reliabilities via config only — engine uses registry for rho
        # Override by constructing votes through config.reliability when descriptor missing;
        # use custom registry descriptors.
        from fusion.registry import DetectorDescriptor, EvidenceRegistry
        from fusion.roles import EvidenceRole

        reg = EvidenceRegistry()
        reg.register(
            DetectorDescriptor(
                DetectorType.ML, EvidenceRole.PRIMARY_DETECTION, "ML", 1.0
            )
        )
        reg.register(
            DetectorDescriptor(
                DetectorType.ENTROPY, EvidenceRole.PRIMARY_DETECTION, "E", 0.4
            )
        )
        eng = CollaborativeFusionEngine(config=cfg, registry=reg)
        fd = eng.fuse(
            detector_results=[_ml("ATTACK", 95), _ent("NORMAL", 90)],
            timestamp=_ts(1),
        )
        # ML weight dominates → lean attack / suspicious, not pure NORMAL
        self.assertNotEqual(fd.decision, DetectionDecision.NORMAL)
        ml_w = next(v for v in fd.evidence["primary_votes"] if v["detector"] == "ML")
        en_w = next(v for v in fd.evidence["primary_votes"] if v["detector"] == "ENTROPY")
        self.assertGreater(ml_w["effective_weight"], en_w["effective_weight"])

    def test_weak_ml_strong_entropy(self):
        from fusion.registry import DetectorDescriptor, EvidenceRegistry
        from fusion.roles import EvidenceRole

        reg = EvidenceRegistry()
        reg.register(
            DetectorDescriptor(
                DetectorType.ML, EvidenceRole.PRIMARY_DETECTION, "ML", 0.4
            )
        )
        reg.register(
            DetectorDescriptor(
                DetectorType.ENTROPY, EvidenceRole.PRIMARY_DETECTION, "E", 1.0
            )
        )
        eng = CollaborativeFusionEngine(registry=reg)
        fd = eng.fuse(
            detector_results=[_ml("NORMAL", 90), _ent("ALERT", 95)],
            timestamp=_ts(1),
        )
        self.assertNotEqual(fd.decision, DetectionDecision.NORMAL)


class TestR62Missing(unittest.TestCase):
    def setUp(self):
        self.eng = CollaborativeFusionEngine()

    def test_ml_only(self):
        fd = self.eng.fuse(detector_results=[_ml("ATTACK", 90)], timestamp=_ts(1))
        self.assertEqual(fd.decision, DetectionDecision.ATTACK)
        self.assertIn("ENTROPY", fd.evidence["missing_detectors"])
        self.assertEqual(fd.participating, ["ML"])
        # Missing entropy must not invent a NORMAL vote
        self.assertNotIn(
            "NORMAL",
            [v["decision"] for v in fd.evidence["primary_votes"] if v["detector"] == "ENTROPY"],
        )
    def test_entropy_only(self):
        fd = self.eng.fuse(detector_results=[_ent("ALERT", 88)], timestamp=_ts(1))
        self.assertEqual(fd.decision, DetectionDecision.ATTACK)
        self.assertIn("ML", fd.evidence["missing_detectors"])

    def test_both_missing(self):
        fd = self.eng.fuse(detector_results=[], timestamp=_ts(1))
        self.assertEqual(fd.decision, DetectionDecision.NONE)
        self.assertIsNone(fd.confidence)
        self.assertEqual(fd.reason, "no_valid_primary_evidence")


class TestR62Health(unittest.TestCase):
    def setUp(self):
        self.eng = CollaborativeFusionEngine()

    def test_degraded_ml(self):
        fd = self.eng.fuse(
            detector_results=[
                _ml("ATTACK", 90, health=DetectorHealth.DEGRADED),
                _ent("NORMAL", 80),
            ],
            timestamp=_ts(1),
        )
        self.assertIn("ML", fd.evidence["degraded_detectors"])
        ml = next(v for v in fd.evidence["primary_votes"] if v["detector"] == "ML")
        self.assertAlmostEqual(ml["health_factor"], 0.5)

    def test_unavailable_excluded(self):
        bad = DetectorResult(
            detector=DetectorType.ML,
            timestamp=_ts(0),
            health=DetectorHealth.ERROR,
            decision=DetectionDecision.ATTACK,
            confidence=0.99,
            error_message="down",
        )
        fd = self.eng.fuse(
            detector_results=[bad, _ent("NORMAL", 80)],
            timestamp=_ts(1),
        )
        self.assertIn("ML", fd.evidence["unavailable_detectors"])
        self.assertNotIn("ML", fd.participating)
        self.assertEqual(fd.decision, DetectionDecision.NORMAL)


class TestR62Correlation(unittest.TestCase):
    def setUp(self):
        self.eng = CollaborativeFusionEngine()

    def test_r4_high_with_attack_support(self):
        base = self.eng.fuse(
            detector_results=[_ml("ATTACK", 70), _ent("ALERT", 70)],
            timestamp=_ts(1),
        )
        boosted = self.eng.fuse(
            detector_results=[_ml("ATTACK", 70), _ent("ALERT", 70)],
            correlation=_corr(0.95),
            timestamp=_ts(1),
        )
        self.assertGreaterEqual(boosted.confidence or 0, base.confidence or 0)
        self.assertTrue(boosted.evidence["correlation"].get("boost_applied"))

    def test_r4_high_all_normal_invariant(self):
        fd = self.eng.fuse(
            detector_results=[_ml("NORMAL", 90), _ent("NORMAL", 90)],
            correlation=_corr(0.99, "CORRELATED"),
            timestamp=_ts(1),
        )
        self.assertNotEqual(fd.decision, DetectionDecision.ATTACK)
        self.assertEqual(fd.decision, DetectionDecision.NORMAL)
        self.assertEqual(
            fd.evidence["correlation"].get("invariant"),
            "R4_cannot_convert_all_primary_NORMAL_to_ATTACK",
        )

    def test_r4_low_correlation(self):
        fd = self.eng.fuse(
            detector_results=[_ml("ATTACK", 80), _ent("ALERT", 80)],
            correlation=_corr(0.1, "PARTIAL"),
            timestamp=_ts(1),
        )
        self.assertFalse(fd.evidence["correlation"].get("boost_applied", False))


class TestR62Context(unittest.TestCase):
    def setUp(self):
        self.eng = CollaborativeFusionEngine()

    def test_adwin_only_no_attack(self):
        adwin = adapt_adwin_alerts(
            [{"metric_name": "flow_count"}], timestamp=_ts(0)
        )
        fd = self.eng.fuse(detector_results=[adwin], timestamp=_ts(1))
        self.assertEqual(fd.decision, DetectionDecision.NONE)
        self.assertNotEqual(fd.decision, DetectionDecision.ATTACK)

    def test_hdbscan_only_no_attack(self):
        h = adapt_hdbscan_summary(
            {"n_attack": 2, "clusters": [{"cluster_label": "ATTACK", "confidence": 0.9}]},
            timestamp=_ts(0),
        )
        fd = self.eng.fuse(detector_results=[h], timestamp=_ts(1))
        self.assertEqual(fd.decision, DetectionDecision.NONE)

    def test_adwin_hdbscan_only(self):
        adwin = adapt_adwin_alerts([{"metric_name": "entropy_score"}], timestamp=_ts(0))
        h = adapt_hdbscan_summary(
            {"n_attack": 1, "clusters": [{"cluster_label": "SUSPICIOUS", "confidence": 0.7}]},
            timestamp=_ts(0),
        )
        fd = self.eng.fuse(detector_results=[adwin, h], timestamp=_ts(1))
        self.assertNotEqual(fd.decision, DetectionDecision.ATTACK)

    def test_context_with_normal_may_suspicious(self):
        adwin = adapt_adwin_alerts([{"metric_name": "flow_count"}], timestamp=_ts(0))
        fd = self.eng.fuse(
            detector_results=[_ml("NORMAL", 70), _ent("NORMAL", 70), adwin],
            timestamp=_ts(1),
        )
        self.assertIn(fd.decision, (DetectionDecision.NORMAL, DetectionDecision.SUSPICIOUS))
        self.assertNotEqual(fd.decision, DetectionDecision.ATTACK)


class TestR62StaleEntityThresholds(unittest.TestCase):
    def setUp(self):
        self.eng = CollaborativeFusionEngine()

    def test_stale_excluded(self):
        stale_ml = _ml("ATTACK", 99, t=-100)
        fresh_ent = _ent("NORMAL", 80, t=0)
        fd = self.eng.fuse(
            detector_results=[stale_ml, fresh_ent],
            timestamp=_ts(0),
        )
        self.assertIn("ML", fd.evidence["stale_detectors"])
        self.assertNotIn("ML", fd.participating)
        self.assertEqual(fd.decision, DetectionDecision.NORMAL)

    def test_threshold_boundaries(self):
        cfg = FusionConfig(attack_threshold=0.55, suspicious_threshold=0.20)
        eng = CollaborativeFusionEngine(config=cfg)
        # Single strong ML attack → S ≈ confidence → ATTACK
        fd_hi = eng.fuse(detector_results=[_ml("ATTACK", 0.90)], timestamp=_ts(1))
        self.assertEqual(fd_hi.decision, DetectionDecision.ATTACK)
        # Weak suspicious
        fd_mid = eng.fuse(
            detector_results=[_ml("SUSPICIOUS", 0.50)], timestamp=_ts(1)
        )
        self.assertIn(
            fd_mid.decision,
            (DetectionDecision.SUSPICIOUS, DetectionDecision.NORMAL, DetectionDecision.NONE),
        )

    def test_confidence_boundaries_unit(self):
        fd = self.eng.fuse(
            detector_results=[_ml("ATTACK", 100), _ent("ALERT", 100)],
            timestamp=_ts(1),
        )
        self.assertIsNotNone(fd.confidence)
        self.assertGreaterEqual(fd.confidence, 0.0)
        self.assertLessEqual(fd.confidence, 1.0)

    def test_insertion_order_invariance(self):
        a = [_ml("ATTACK", 90), _ent("NORMAL", 80)]
        b = list(reversed(a))
        fa = self.eng.fuse(detector_results=a, timestamp=_ts(1), fusion_id="x")
        fb = self.eng.fuse(detector_results=b, timestamp=_ts(1), fusion_id="x")
        self.assertEqual(fa.decision, fb.decision)
        self.assertEqual(fa.confidence, fb.confidence)
        self.assertEqual(fa.disagreement, fb.disagreement)
        self.assertEqual(fa.evidence["scores"], fb.evidence["scores"])

    def test_determinism(self):
        pack = [_ml("ATTACK", 88), _ent("ALERT", 77)]
        results = [
            self.eng.fuse(detector_results=pack, timestamp=_ts(1), fusion_id="det")
            for _ in range(5)
        ]
        self.assertEqual(len({r.decision for r in results}), 1)
        self.assertEqual(len({r.confidence for r in results}), 1)

    def test_invalid_empty_safe(self):
        fd = self.eng.fuse(detector_results=None, timestamp=_ts(1))
        self.assertEqual(fd.decision, DetectionDecision.NONE)


class TestR62LegacyCompare(unittest.TestCase):
    def test_classifications(self):
        eng = CollaborativeFusionEngine()
        pack = [_ml("ATTACK", 90), _ent("NORMAL", 85)]
        fd = eng.fuse(detector_results=pack, timestamp=_ts(1))
        cmp = classify_legacy_difference(fd, pack)
        self.assertIn(
            cmp.classification,
            {
                "MATCH",
                "EXPECTED_IMPROVEMENT",
                "EXPECTED_UNCERTAINTY",
                "POTENTIAL_REGRESSION",
            },
        )
        self.assertEqual(legacy_production_decision(pack), "ATTACK")


class TestR62FailSafe(unittest.TestCase):
    def test_exception_not_attack(self):
        eng = CollaborativeFusionEngine()

        class Boom:
            def __iter__(self):
                raise RuntimeError("boom")

        fd = eng.fuse(detector_results=Boom(), timestamp=_ts(1))  # type: ignore[arg-type]
        self.assertEqual(fd.decision, DetectionDecision.NONE)
        self.assertTrue(fd.evidence.get("fail_safe"))


if __name__ == "__main__":
    unittest.main()
