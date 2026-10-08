#!/usr/bin/env python3
"""R6.1 — Detector adapters + bounded evidence registry (no fusion engine)."""

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
from shared_contracts.serialize import from_dict, to_dict
from fusion import (
    DetectorDescriptor,
    EvidenceRegistry,
    EvidenceRole,
    adapt_adwin_alerts,
    adapt_correlation_result,
    adapt_entropy_metrics,
    adapt_hdbscan_summary,
    adapt_ml_prediction,
    adapt_ssl_unavailable,
    build_default_registry,
    build_detection_event,
    degraded,
    entity_key_from,
    map_detector_health,
    to_unit_confidence,
    unavailable,
)


def _ts(offset_s: float = 0.0) -> datetime:
    return datetime(2026, 7, 27, 1, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_s)


class TestR61Normalize(unittest.TestCase):
    def test_unit_and_percent_matrix(self):
        self.assertAlmostEqual(to_unit_confidence(0.85), 0.85)
        self.assertAlmostEqual(to_unit_confidence(85), 0.85)
        self.assertAlmostEqual(to_unit_confidence(0), 0.0)
        self.assertAlmostEqual(to_unit_confidence(1), 1.0)
        self.assertAlmostEqual(to_unit_confidence(100), 1.0)

    def test_invalid_confidence(self):
        self.assertIsNone(to_unit_confidence(None))
        self.assertIsNone(to_unit_confidence(float("nan")))
        self.assertIsNone(to_unit_confidence(float("inf")))
        self.assertIsNone(to_unit_confidence("bad"))
        self.assertIsNone(to_unit_confidence(True))
        self.assertAlmostEqual(to_unit_confidence(-5), 0.0)


class TestR61Health(unittest.TestCase):
    def test_health_mapping(self):
        self.assertEqual(map_detector_health("HEALTHY"), DetectorHealth.SUCCESS)
        self.assertEqual(map_detector_health("DEGRADED"), DetectorHealth.DEGRADED)
        self.assertEqual(map_detector_health("UNAVAILABLE"), DetectorHealth.ERROR)

    def test_unavailable_not_normal(self):
        r = unavailable(DetectorType.ML, reason="down", timestamp=_ts())
        self.assertEqual(r.health, DetectorHealth.ERROR)
        self.assertEqual(r.decision, DetectionDecision.NONE)
        self.assertNotEqual(r.decision, DetectionDecision.NORMAL)

    def test_degraded_not_success_normal(self):
        r = degraded(
            DetectorType.ENTROPY,
            reason="partial",
            decision=DetectionDecision.WARNING,
            confidence=0.4,
            timestamp=_ts(),
        )
        self.assertEqual(r.health, DetectorHealth.DEGRADED)
        self.assertNotEqual(r.health, DetectorHealth.SUCCESS)


class TestR61Adapters(unittest.TestCase):
    def test_ml_primary_timestamp_entity_via_assembly(self):
        r = adapt_ml_prediction(
            {"status": "ATTACK", "confidence": 92.0, "iso_score": 0.8},
            timestamp=_ts(),
            explanation={"attack_type_hint": "SYN_FLOOD"},
        )
        self.assertEqual(r.detector, DetectorType.ML)
        self.assertEqual(r.decision, DetectionDecision.ATTACK)
        self.assertAlmostEqual(r.confidence, 0.92)
        self.assertEqual(r.timestamp, _ts())
        self.assertEqual(r.evidence.get("role"), EvidenceRole.PRIMARY_DETECTION.value)
        self.assertEqual(r.attack_hint, "SYN_FLOOD")

    def test_ml_missing_confidence(self):
        r = adapt_ml_prediction({"status": "SUSPICIOUS"}, timestamp=_ts())
        self.assertIsNone(r.confidence)
        self.assertEqual(r.decision, DetectionDecision.SUSPICIOUS)

    def test_ml_degraded_health(self):
        r = adapt_ml_prediction(
            {"status": "ATTACK", "confidence": 70.0},
            timestamp=_ts(),
            health="DEGRADED",
        )
        self.assertEqual(r.health, DetectorHealth.DEGRADED)
        self.assertEqual(r.decision, DetectionDecision.ATTACK)

    def test_entropy_primary(self):
        r = adapt_entropy_metrics(
            {"status": "ALERT", "confidence": 80.0, "entropy_score": 0.25},
            timestamp=_ts(),
        )
        self.assertEqual(r.detector, DetectorType.ENTROPY)
        self.assertEqual(r.decision, DetectionDecision.ALERT)
        self.assertAlmostEqual(r.confidence, 0.80)
        self.assertEqual(r.evidence.get("role"), EvidenceRole.PRIMARY_DETECTION.value)

    def test_correlation_supporting_native_and_adapter(self):
        corr = CorrelationResult(
            correlation_id="c1",
            timestamp=_ts(),
            score=0.9,
            evidence={
                "status": "CORRELATED",
                "participating_categories": ["ML"],
                "focal_entity_key": "dpid:1|src:02:aa:aa:aa:aa:01",
            },
        )
        r = adapt_correlation_result(corr)
        self.assertEqual(r.detector, DetectorType.CORRELATION)
        self.assertEqual(r.evidence.get("role"), EvidenceRole.SUPPORTING_EVIDENCE.value)
        self.assertEqual(r.evidence.get("native_contract"), "CorrelationResult")
        self.assertNotEqual(r.decision, DetectionDecision.ATTACK)
        self.assertEqual(r.decision, DetectionDecision.SUSPICIOUS)

    def test_adwin_context_only(self):
        r = adapt_adwin_alerts(
            [{"metric_name": "entropy_score", "old_mean": 0.9, "new_mean": 0.2}],
            timestamp=_ts(),
        )
        self.assertEqual(r.evidence.get("role"), EvidenceRole.CONTEXT_ONLY.value)
        self.assertEqual(r.decision, DetectionDecision.DRIFT)

    def test_hdbscan_context_only(self):
        r = adapt_hdbscan_summary(
            {
                "n_attack": 1,
                "clusters": [{"cluster_label": "ATTACK", "confidence": 0.8}],
            },
            timestamp=_ts(),
        )
        self.assertEqual(r.evidence.get("role"), EvidenceRole.CONTEXT_ONLY.value)
        self.assertEqual(r.decision, DetectionDecision.SUSPICIOUS)
        self.assertNotEqual(r.decision, DetectionDecision.ATTACK)

    def test_ssl_stub_unavailable(self):
        r = adapt_ssl_unavailable(timestamp=_ts())
        self.assertEqual(r.health, DetectorHealth.ERROR)
        self.assertNotEqual(r.decision, DetectionDecision.NORMAL)

    def test_determinism(self):
        payload = {"status": "ATTACK", "confidence": 88.0, "iso_score": 0.7}
        a = adapt_ml_prediction(payload, timestamp=_ts())
        b = adapt_ml_prediction(payload, timestamp=_ts())
        self.assertEqual(a.decision, b.decision)
        self.assertEqual(a.confidence, b.confidence)
        self.assertEqual(a.health, b.health)

    def test_serialization_roundtrip(self):
        r = adapt_ml_prediction(
            {"status": "ATTACK", "confidence": 91.0}, timestamp=_ts()
        )
        d = to_dict(r)
        back = from_dict(d, DetectorResult)
        self.assertEqual(back.detector, DetectorType.ML)
        self.assertAlmostEqual(back.confidence, 0.91)
        self.assertEqual(back.decision, DetectionDecision.ATTACK)


class TestR61RegistryStore(unittest.TestCase):
    def test_default_roles(self):
        reg = build_default_registry()
        self.assertEqual(reg.role_of(DetectorType.ML), EvidenceRole.PRIMARY_DETECTION)
        self.assertEqual(reg.role_of(DetectorType.ENTROPY), EvidenceRole.PRIMARY_DETECTION)
        self.assertEqual(
            reg.role_of(DetectorType.CORRELATION), EvidenceRole.SUPPORTING_EVIDENCE
        )
        self.assertEqual(reg.role_of(DetectorType.ADWIN), EvidenceRole.CONTEXT_ONLY)
        self.assertEqual(reg.role_of(DetectorType.HDBSCAN), EvidenceRole.CONTEXT_ONLY)
        self.assertFalse(reg.get(DetectorType.SSL).implemented)

    def test_put_replace_get_entity_isolation(self):
        reg = EvidenceRegistry(max_records=32, default_freshness_seconds=30.0)
        r1 = adapt_ml_prediction({"status": "ATTACK", "confidence": 90}, timestamp=_ts())
        r2 = adapt_ml_prediction({"status": "NORMAL", "confidence": 10}, timestamp=_ts(1))
        reg.put(result=r1, switch_id=1, src_mac="02:aa:aa:aa:aa:01")
        reg.put(result=r2, switch_id=1, src_mac="02:aa:aa:aa:aa:02")
        a = reg.get_current(DetectorType.ML, switch_id=1, src_mac="02:aa:aa:aa:aa:01")
        b = reg.get_current(DetectorType.ML, switch_id=1, src_mac="02:aa:aa:aa:aa:02")
        self.assertEqual(a.result.decision, DetectionDecision.ATTACK)
        self.assertEqual(b.result.decision, DetectionDecision.NORMAL)
        # supersede entity A
        r3 = adapt_ml_prediction({"status": "SUSPICIOUS", "confidence": 55}, timestamp=_ts(2))
        reg.put(result=r3, switch_id=1, src_mac="02:aa:aa:aa:aa:01")
        a2 = reg.get_current(DetectorType.ML, switch_id=1, src_mac="02:aa:aa:aa:aa:01")
        self.assertEqual(a2.result.decision, DetectionDecision.SUSPICIOUS)
        self.assertEqual(reg.size(), 2)

    def test_filter_by_detector_and_freshness_expiry(self):
        reg = EvidenceRegistry(max_records=64, default_freshness_seconds=10.0)
        old = adapt_entropy_metrics(
            {"status": "ALERT", "confidence": 80}, timestamp=_ts(0)
        )
        fresh = adapt_ml_prediction(
            {"status": "ATTACK", "confidence": 90}, timestamp=_ts(15)
        )
        reg.put(result=old, switch_id=1)
        reg.put(result=fresh, switch_id=1)
        now = _ts(20)  # entropy age=20s > 10s; ML age=5s ≤ 10s
        ekey = entity_key_from(switch_id=1)
        fresh_only = reg.filter_fresh(
            max_age_seconds=10.0, now=now, entity_key=ekey
        )
        types = {r.detector for r in fresh_only}
        self.assertIn(DetectorType.ML, types)
        self.assertNotIn(DetectorType.ENTROPY, types)
        removed = reg.expire_stale(max_age_seconds=10.0, now=now)
        self.assertEqual(removed, 1)
        self.assertEqual(reg.size(), 1)
        self.assertEqual(
            reg.list_evidence(detector=DetectorType.ML)[0].detector, DetectorType.ML
        )

    def test_bounded_state_evicts_oldest(self):
        reg = EvidenceRegistry(max_records=3, default_freshness_seconds=60.0)
        for i in range(5):
            r = adapt_ml_prediction(
                {"status": "NORMAL", "confidence": 10}, timestamp=_ts(i)
            )
            reg.put(result=r, switch_id=i + 1)  # distinct entities
        self.assertEqual(reg.size(), 3)
        # oldest switch_id=1,2 evicted
        self.assertIsNone(reg.get_current(DetectorType.ML, switch_id=1))
        self.assertIsNotNone(reg.get_current(DetectorType.ML, switch_id=5))

    def test_correlation_native_retained(self):
        reg = build_default_registry()
        corr = CorrelationResult(
            correlation_id="c-native",
            timestamp=_ts(),
            score=0.75,
            evidence={"status": "CORRELATED", "focal_entity_key": "dpid:1"},
        )
        adapted = adapt_correlation_result(corr)
        rec = reg.put(
            result=adapted,
            correlation=corr,
            entity_key="dpid:1",
        )
        self.assertIsNotNone(rec.correlation)
        self.assertEqual(rec.correlation.correlation_id, "c-native")
        self.assertEqual(rec.role, EvidenceRole.SUPPORTING_EVIDENCE)

    def test_future_detector_extensibility_without_redesign(self):
        """Generic OTHER detector registers like R2 will — no architecture change."""
        reg = EvidenceRegistry(max_records=16)

        def adapt_dummy(payload=None, *, timestamp=None, **_kw):
            if not payload:
                return unavailable(DetectorType.OTHER, reason="dummy_missing", timestamp=timestamp)
            return DetectorResult(
                detector=DetectorType.OTHER,
                timestamp=timestamp or _ts(),
                health=DetectorHealth.SUCCESS,
                decision=DetectionDecision.SUSPICIOUS,
                confidence=to_unit_confidence(payload.get("confidence")),
                evidence={"role": EvidenceRole.PRIMARY_DETECTION.value, "dummy": True},
            )

        reg.register(
            DetectorDescriptor(
                detector_type=DetectorType.OTHER,
                role=EvidenceRole.PRIMARY_DETECTION,
                name="DummyFutureDetector",
                reliability=0.8,
                notes="Test-only stand-in for future R2-style pluggable detector.",
            ),
            adapter=adapt_dummy,
        )
        self.assertEqual(reg.role_of(DetectorType.OTHER), EvidenceRole.PRIMARY_DETECTION)
        adapter = reg.adapter_for(DetectorType.OTHER)
        out = adapter({"confidence": 0.66}, timestamp=_ts())
        reg.put(result=out, switch_id=9, src_mac="02:bb:bb:bb:bb:01")
        cur = reg.get_current(
            DetectorType.OTHER, switch_id=9, src_mac="02:bb:bb:bb:bb:01"
        )
        self.assertEqual(cur.result.decision, DetectionDecision.SUSPICIOUS)
        self.assertAlmostEqual(cur.result.confidence, 0.66)

    def test_r62_engine_exists_but_no_module_level_fuse_autorun(self):
        import fusion
        from fusion import CollaborativeFusionEngine

        self.assertTrue(hasattr(fusion, "CollaborativeFusionEngine"))
        self.assertTrue(callable(CollaborativeFusionEngine().fuse))
        # No production auto-hook symbol
        self.assertFalse(hasattr(fusion, "apply_production_fusion"))

    def test_evidence_record_serialization(self):
        reg = EvidenceRegistry(max_records=8)
        r = adapt_ml_prediction({"status": "ATTACK", "confidence": 90}, timestamp=_ts())
        rec = reg.put(result=r, switch_id=1, src_mac="02:aa:aa:aa:aa:01")
        d = rec.to_dict()
        self.assertEqual(d["detector"], "ML")
        self.assertEqual(d["result"]["decision"], "ATTACK")
        self.assertIn("entity_key", d)


class TestR61Assembly(unittest.TestCase):
    def test_build_detection_event_roles(self):
        corr = CorrelationResult(
            correlation_id="c1",
            timestamp=_ts(),
            score=0.7,
            evidence={"status": "CORRELATED"},
        )
        ev = build_detection_event(
            switch_id=1,
            src_mac="02:aa:aa:aa:aa:01",
            ml_prediction={"status": "ATTACK", "confidence": 90.0},
            entropy_metrics={"status": "ALERT", "confidence": 75.0, "entropy_score": 0.2},
            correlation=corr,
            adwin_alerts=[{"metric_name": "flow_count"}],
            hdbscan_summary={"n_attack": 0, "clusters": []},
            include_ssl_stub=True,
            event_id="evt-r61",
            timestamp=_ts(),
        )
        self.assertEqual(ev.event_id, "evt-r61")
        self.assertEqual(ev.switch_id, 1)
        self.assertEqual(ev.src_mac, "02:aa:aa:aa:aa:01")
        types = {r.detector for r in ev.detector_results}
        self.assertIn(DetectorType.ML, types)
        self.assertIn(DetectorType.ENTROPY, types)
        self.assertIn(DetectorType.CORRELATION, types)
        self.assertIn(DetectorType.SSL, types)
        for r in ev.detector_results:
            if r.confidence is not None:
                self.assertGreaterEqual(r.confidence, 0.0)
                self.assertLessEqual(r.confidence, 1.0)
        self.assertEqual(ev.context.get("fusion_engine"), "NOT_RUN")
        self.assertGreaterEqual(ev.context.get("primary_count"), 2)
        self.assertGreaterEqual(ev.context.get("supporting_count"), 1)
        self.assertGreaterEqual(ev.context.get("context_count"), 1)
        # DetectionEvent serialization
        blob = to_dict(ev)
        back = from_dict(blob, type(ev))
        self.assertEqual(back.event_id, "evt-r61")

    def test_omit_missing_sources_no_fake_normal(self):
        ev = build_detection_event(
            ml_prediction={"status": "ATTACK", "confidence": 88.0},
            timestamp=_ts(),
        )
        types = [r.detector for r in ev.detector_results]
        self.assertEqual(types, [DetectorType.ML])
        self.assertNotIn(DetectionDecision.NORMAL, [r.decision for r in ev.detector_results])


if __name__ == "__main__":
    unittest.main()
