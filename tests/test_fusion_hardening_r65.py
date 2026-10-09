#!/usr/bin/env python3
"""R6.5 — Hardening: correctness matrix, safety, failure, stress, R2 plug-in."""

from __future__ import annotations

import json
import math
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import DetectionDecision, DetectorHealth, DetectorType
from shared_contracts.models import DetectorResult
from fusion.adapters import adapt_ml_prediction, unavailable
from fusion.config import FusionConfig
from fusion.engine import CollaborativeFusionEngine
from fusion.eval_packs import build_correctness_packs, _ts
from fusion.eval_r65 import (
    run_ablation,
    run_all_r65_artifacts,
    run_correctness_matrix,
    run_disagreement_analysis,
    run_legacy_comparison,
    run_performance,
    run_reliability_sensitivity,
    run_threshold_sensitivity,
)
from fusion.history import read_fused_decision_history
from fusion.registry import (
    DetectorDescriptor,
    EvidenceRegistry,
)
from fusion.roles import EvidenceRole
from fusion.runtime import prepare_collaborative_cycle
from fusion.trace import append_fusion_trace as _append


class TestR65CorrectnessMatrix(unittest.TestCase):
    def test_packs_a_through_r(self):
        report = run_correctness_matrix()
        failed = [r for r in report["rows"] if not r["pass"]]
        self.assertTrue(
            report["passed"],
            msg=f"correctness failures: {failed}",
        )


class TestR65SafetyInvariants(unittest.TestCase):
    def setUp(self):
        self.eng = CollaborativeFusionEngine()

    def test_r4_alone_no_attack(self):
        from shared_contracts.models import CorrelationResult

        corr = CorrelationResult(
            correlation_id="c",
            timestamp=_ts(0),
            score=0.99,
            evidence={"status": "CORRELATED"},
        )
        fd = self.eng.fuse(detector_results=[], correlation=corr, timestamp=_ts(1))
        self.assertNotEqual(fd.decision, DetectionDecision.ATTACK)

    def test_adwin_hdbscan_alone_no_attack(self):
        from fusion.adapters import adapt_adwin_alerts, adapt_hdbscan_summary

        for results in (
            [adapt_adwin_alerts([{"metric_name": "x"}], timestamp=_ts(0))],
            [
                adapt_hdbscan_summary(
                    {
                        "n_attack": 5,
                        "clusters": [{"cluster_label": "ATTACK", "confidence": 0.99}],
                    },
                    timestamp=_ts(0),
                )
            ],
            [
                adapt_adwin_alerts([{"metric_name": "x"}], timestamp=_ts(0)),
                adapt_hdbscan_summary(
                    {
                        "n_attack": 2,
                        "clusters": [{"cluster_label": "ATTACK", "confidence": 0.9}],
                    },
                    timestamp=_ts(0),
                ),
            ],
        ):
            fd = self.eng.fuse(detector_results=results, timestamp=_ts(1))
            self.assertNotEqual(fd.decision, DetectionDecision.ATTACK)

    def test_missing_and_unavailable_not_normal_votes(self):
        fd = self.eng.fuse(
            detector_results=[
                adapt_ml_prediction({"status": "ATTACK", "confidence": 90}, timestamp=_ts(0))
            ],
            timestamp=_ts(1),
        )
        self.assertIn("ENTROPY", fd.evidence["missing_detectors"])
        self.assertNotIn(
            "ENTROPY",
            [v["detector"] for v in fd.evidence["primary_votes"]],
        )
        bad = DetectorResult(
            detector=DetectorType.ENTROPY,
            timestamp=_ts(0),
            health=DetectorHealth.ERROR,
            decision=DetectionDecision.NORMAL,
            confidence=0.99,
            error_message="down",
        )
        fd2 = self.eng.fuse(
            detector_results=[
                adapt_ml_prediction({"status": "ATTACK", "confidence": 90}, timestamp=_ts(0)),
                bad,
            ],
            timestamp=_ts(1),
        )
        self.assertIn("ENTROPY", fd2.evidence["unavailable_detectors"])
        self.assertNotIn("ENTROPY", fd2.participating)

    def test_stale_and_cross_entity(self):
        packs = {p.pack_id: p for p in build_correctness_packs()}
        fd_k = self.eng.fuse(
            detector_results=list(packs["K"].detector_results),
            timestamp=_ts(1),
            switch_id=1,
            src_mac="02:aa:aa:aa:aa:01",
        )
        self.assertIn("ML", fd_k.evidence["stale_detectors"])
        self.assertNotIn("ML", fd_k.participating)

        fd_r = self.eng.fuse(
            detector_results=list(packs["R"].detector_results),
            timestamp=_ts(1),
            switch_id=1,
            src_mac="02:aa:aa:aa:aa:01",
        )
        self.assertTrue(fd_r.evidence.get("cross_entity_excluded"))
        self.assertEqual(fd_r.decision, DetectionDecision.NORMAL)
        self.assertNotEqual(fd_r.decision, DetectionDecision.ATTACK)

    def test_fusion_exception_no_mitigation(self):
        class Boom(CollaborativeFusionEngine):
            def fuse(self, **kwargs):
                raise RuntimeError("boom")

        # prepare path fail-safe
        out = prepare_collaborative_cycle(
            switch_id=1,
            ml_prediction={"status": "ATTACK", "confidence": 99},
            engine=Boom(),
            persist_trace=False,
            timestamp=_ts(1),
        )
        self.assertTrue(out.fallback_legacy)
        self.assertFalse(out.owned)
        # engine fail-safe wrapper
        eng = CollaborativeFusionEngine()
        with mock.patch.object(eng, "_fuse_impl", side_effect=RuntimeError("x")):
            fd = eng.fuse(detector_results=[], timestamp=_ts(1))
        self.assertEqual(fd.decision, DetectionDecision.NONE)
        self.assertTrue(fd.evidence.get("fail_safe"))
        self.assertFalse(fd.evidence.get("mitigation_authorized", False))


class TestR65DisagreementReliabilityThreshold(unittest.TestCase):
    def test_disagreement_lowers_certainty(self):
        report = run_disagreement_analysis()
        self.assertTrue(report["strong_disagreement_lowers_certainty_vs_agree_attack"])

    def test_sensitivity_and_threshold_artifacts_shape(self):
        sens = run_reliability_sensitivity()
        self.assertGreater(sens["grid_size"], 10)
        self.assertEqual(sens["normal_to_attack_count"], 0)
        thr = run_threshold_sensitivity()
        self.assertTrue(any(g["A_is_normal"] and g["B_is_attack"] for g in thr["grid"]))


class TestR65EvalArtifacts(unittest.TestCase):
    def test_write_all_artifacts(self):
        paths = run_all_r65_artifacts()
        for key, path in paths.items():
            self.assertTrue(os.path.isfile(path), key)
            data = json.loads(open(path, encoding="utf-8").read())
            self.assertIn("kind", data)
        abl = json.loads(open(paths["ablation"], encoding="utf-8").read())
        self.assertIsNone(abl["live_mininet_metrics"])
        self.assertIn("ml_entropy", abl["configurations"])
        self.assertIn("metrics", abl["configurations"]["ml_entropy"])
        leg = json.loads(open(paths["legacy"], encoding="utf-8").read())
        self.assertIn("counts", leg)
        perf = json.loads(open(paths["performance"], encoding="utf-8").read())
        self.assertLess(perf["fusion_only"]["median_ms"], 5.0)
        self.assertLess(perf["combined_r6_path"]["median_ms"], 15.0)


class TestR65StateStress(unittest.TestCase):
    def test_registry_bounded_under_load(self):
        reg = EvidenceRegistry(max_records=32, default_freshness_seconds=5.0)
        for i in range(200):
            r = adapt_ml_prediction(
                {"status": "NORMAL", "confidence": 10},
                timestamp=_ts(i * 0.01),
            )
            reg.put(result=r, switch_id=(i % 40) + 1, src_mac=f"02:aa:aa:aa:aa:{i%99:02x}")
        self.assertLessEqual(reg.size(), 32)
        # expire stale
        removed = reg.expire_stale(max_age_seconds=0.001, now=_ts(100))
        self.assertGreaterEqual(removed, 0)
        self.assertLessEqual(reg.size(), 32)


class TestR65FailureInjection(unittest.TestCase):
    def test_invalid_confidence_nan_inf_timestamp(self):
        r = adapt_ml_prediction(
            {"status": "ATTACK", "confidence": float("nan")},
            timestamp=_ts(0),
        )
        self.assertIsNone(r.confidence)
        r2 = adapt_ml_prediction(
            {"status": "ATTACK", "confidence": float("inf")},
            timestamp=_ts(0),
        )
        self.assertIsNone(r2.confidence)
        fd = CollaborativeFusionEngine().fuse(
            detector_results=[
                adapt_ml_prediction({"status": "ATTACK", "confidence": 90}, timestamp=_ts(0))
            ],
            timestamp=_ts(1),
        )
        self.assertIsNotNone(fd)

    def test_persistence_and_malformed_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fused_decisions.jsonl")
            fd = CollaborativeFusionEngine().fuse(
                detector_results=[
                    adapt_ml_prediction(
                        {"status": "ATTACK", "confidence": 90}, timestamp=_ts(0)
                    )
                ],
                timestamp=_ts(1),
            )
            self.assertTrue(_append(fd, path))
            with open(path, "a", encoding="utf-8") as fh:
                fh.write("{bad\n")
            rows = read_fused_decision_history(path, limit=10)
            self.assertEqual(len(rows), 1)
            with mock.patch("os.makedirs", side_effect=OSError("Permission denied")):
                self.assertFalse(_append(fd, "/proc/nope_r65/x.jsonl"))

    def test_r4_r5_r8_unavailable_paths(self):
        # Fusion works without R4/R5/R8 packages in the call
        out = prepare_collaborative_cycle(
            switch_id=1,
            ml_prediction={"status": "ATTACK", "confidence": 90},
            entropy_metrics={"status": "ALERT", "confidence": 85, "entropy_score": 0.2},
            correlation=None,
            persist_trace=False,
            timestamp=_ts(1),
        )
        self.assertTrue(out.owned)
        self.assertTrue(out.should_dispatch_r7)


class TestR65FutureR2Pluggability(unittest.TestCase):
    def test_synthetic_detector_registers_without_engine_edit(self):
        """Architectural validation — NOT SSL implementation."""
        reg = EvidenceRegistry()

        def adapt_future(payload=None, *, timestamp=None, **_kw):
            if not payload:
                return unavailable(DetectorType.OTHER, reason="missing", timestamp=timestamp)
            return DetectorResult(
                detector=DetectorType.OTHER,
                timestamp=timestamp or _ts(0),
                health=DetectorHealth.SUCCESS,
                decision=DetectionDecision.ATTACK,
                confidence=0.91,
                evidence={"role": EvidenceRole.PRIMARY_DETECTION.value, "synthetic": True},
            )

        reg.register(
            DetectorDescriptor(
                detector_type=DetectorType.OTHER,
                role=EvidenceRole.PRIMARY_DETECTION,
                name="SyntheticFutureDetector",
                reliability=0.85,
                notes="TEST-ONLY stand-in for future R2-style detector",
            ),
            adapter=adapt_future,
        )
        # Engine uses same class — no source edit
        eng = CollaborativeFusionEngine(registry=reg)
        result = adapt_future({"ok": True}, timestamp=_ts(0))
        fd = eng.fuse(detector_results=[result], timestamp=_ts(1), switch_id=1)
        self.assertIn("OTHER", fd.participating)
        self.assertEqual(fd.decision, DetectionDecision.ATTACK)


if __name__ == "__main__":
    unittest.main()
