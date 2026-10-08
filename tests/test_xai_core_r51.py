#!/usr/bin/env python3
"""R5.1 — XAI Core tests (checklist items 1–22; no RCA; no runtime wiring)."""

from __future__ import annotations

import json
import math
import os
import sys
import unittest

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ml_models.feature_builder import FEATURE_NAMES
from xai import (
    AttributionScope,
    EvidenceKind,
    ExplanationMethod,
    ExplanationStatus,
    XAIEngine,
    explanation_to_legacy_dict,
)
from xai.models import PredictionExplanation


def _vector(**overrides):
    base = {
        "packet_rate_mean": 50.0,
        "packet_rate_max": 80.0,
        "byte_rate_mean": 10000.0,
        "byte_rate_max": 20000.0,
        "flow_count": 8.0,
        "duration_mean": 10.0,
        "unique_src_count": 5.0,
        "unique_dst_count": 4.0,
        "src_entropy": 0.85,
        "dst_entropy": 0.80,
        "packet_entropy": 0.75,
        "byte_entropy": 0.75,
        "flow_entropy": 0.80,
        "entropy_score": 0.80,
        "flow_concentration": 0.15,
    }
    base.update(overrides)
    return [float(base[n]) for n in FEATURE_NAMES]


def _train_tiny_dt():
    rng = np.random.RandomState(0)
    X_n = rng.normal(loc=50, scale=5, size=(40, len(FEATURE_NAMES)))
    X_a = rng.normal(loc=50, scale=5, size=(40, len(FEATURE_NAMES)))
    X_a[:, 1] = rng.normal(loc=3000, scale=50, size=40)
    X = np.vstack([X_n, X_a])
    y = np.array([0] * 40 + [1] * 40)
    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)
    dt = DecisionTreeClassifier(max_depth=4, random_state=0)
    dt.fit(Xs, y)
    return dt, scaler


class TestXAICoreR51(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dt, cls.scaler = _train_tiny_dt()
        cls.eng = XAIEngine()

    # 1 supported model explanation
    def test_01_supported_model_explanation(self):
        out = self.eng.explain(
            _vector(packet_rate_max=3200.0),
            {"status": "ATTACK", "confidence": 94.0, "dt_label": 1, "dt_confidence": 0.94},
            decision_tree=self.dt,
            scaler=self.scaler,
            model_id="dt-test-v1",
        )
        self.assertEqual(out.status, ExplanationStatus.OK.value)
        self.assertTrue(out.model_available)
        self.assertEqual(out.model_id, "dt-test-v1")
        self.assertIn(
            out.method,
            (
                ExplanationMethod.DECISION_TREE_PATH.value,
                ExplanationMethod.COMPOSITE.value,
            ),
        )

    # 2 normal prediction
    def test_02_normal_prediction(self):
        out = self.eng.explain(
            _vector(),
            {"status": "NORMAL", "confidence": 12.0, "dt_label": 0},
            decision_tree=self.dt,
            scaler=self.scaler,
        )
        self.assertEqual(out.prediction_status, "NORMAL")
        self.assertIsInstance(out.summary, str)
        self.assertIn("NORMAL", out.summary)

    # 3 attack prediction
    def test_03_attack_prediction(self):
        out = self.eng.explain(
            _vector(packet_rate_max=3200.0),
            {"status": "ATTACK", "confidence": 94.0},
            decision_tree=self.dt,
            scaler=self.scaler,
        )
        self.assertEqual(out.prediction_status, "ATTACK")
        self.assertIn("ATTACK", out.summary)

    # 4 feature names preserved
    def test_04_feature_names_preserved(self):
        out = self.eng.explain(
            _vector(packet_rate_max=3200.0),
            {"status": "ATTACK", "confidence": 90.0},
            decision_tree=self.dt,
            scaler=self.scaler,
        )
        self.assertEqual(out.feature_names, list(FEATURE_NAMES))
        for step in out.decision_path:
            self.assertIn(step.feature, FEATURE_NAMES)

    # 5–7 decision path, thresholds, leaf
    def test_05_06_07_path_thresholds_leaf(self):
        out = self.eng.explain(
            _vector(packet_rate_max=3200.0),
            {"status": "ATTACK", "confidence": 90.0},
            decision_tree=self.dt,
            scaler=self.scaler,
        )
        self.assertGreater(len(out.decision_path), 0)
        for step in out.decision_path:
            self.assertIn(step.operator, ("<=", ">"))
            self.assertIsInstance(step.threshold, float)
            self.assertIsNotNone(step.threshold_distance)
            self.assertEqual(step.scope, AttributionScope.LOCAL_PATH.value)
        self.assertIsNotNone(out.leaf_decision)
        self.assertIsNotNone(out.leaf_node_id)

    # 8 confidence represented
    def test_08_confidence_represented(self):
        out = self.eng.explain(
            _vector(packet_rate_max=3200.0),
            {"status": "ATTACK", "confidence": 94.0},
            decision_tree=self.dt,
            scaler=self.scaler,
        )
        self.assertEqual(out.confidence_percent, 94.0)
        self.assertIn("0.94", out.summary)

    # 9 global importance distinguished
    def test_09_global_importance_distinguished(self):
        out = self.eng.explain(
            _vector(packet_rate_max=3200.0),
            {"status": "ATTACK", "confidence": 90.0},
            decision_tree=self.dt,
            scaler=self.scaler,
        )
        self.assertGreater(len(out.global_feature_importances), 0)
        for f in out.global_feature_importances:
            self.assertEqual(f.scope, AttributionScope.GLOBAL_IMPORTANCE.value)
            self.assertIn("GLOBAL", f.note)
            self.assertIn("not per-prediction", f.note.lower())

    # 10 local evidence distinguished
    def test_10_local_evidence_distinguished(self):
        out = self.eng.explain(
            _vector(packet_rate_max=3200.0),
            {"status": "ATTACK", "confidence": 90.0},
            decision_tree=self.dt,
            scaler=self.scaler,
        )
        self.assertGreater(len(out.local_path_features), 0)
        for f in out.local_path_features:
            self.assertEqual(f.scope, AttributionScope.LOCAL_PATH.value)
            self.assertIn("LOCAL", f.note)

    # 11 deterministic summary
    def test_11_deterministic_summary(self):
        out = self.eng.explain(
            _vector(packet_rate_max=3200.0),
            {"status": "ATTACK", "confidence": 94.0},
            decision_tree=self.dt,
            scaler=self.scaler,
        )
        self.assertTrue(out.summary)
        self.assertNotIn("LLM", out.summary)
        self.assertIn("Decision-path evidence", out.summary)

    # 12 same input → same explanation content
    def test_12_same_input_same_content(self):
        kwargs = dict(
            vector=_vector(packet_rate_max=3200.0),
            prediction={"status": "ATTACK", "confidence": 94.0, "dt_label": 1},
            decision_tree=self.dt,
            scaler=self.scaler,
            event_id="e1",
            model_id="m1",
        )
        a = self.eng.explain(**kwargs)
        b = self.eng.explain(**kwargs)
        self.assertEqual(a.content_fingerprint(), b.content_fingerprint())

    # 13 unsupported model
    def test_13_unsupported_model(self):
        rf = RandomForestClassifier(n_estimators=3, random_state=0)
        rf.fit(np.zeros((10, len(FEATURE_NAMES))), [0] * 5 + [1] * 5)
        out = self.eng.explain(
            _vector(),
            {"status": "ATTACK", "confidence": 80.0},
            decision_tree=rf,
            scaler=self.scaler,
        )
        self.assertEqual(out.method, ExplanationMethod.UNSUPPORTED_MODEL.value)
        self.assertEqual(out.status, ExplanationStatus.DEGRADED.value)

    # 14 model unavailable
    def test_14_model_unavailable(self):
        out = self.eng.explain(
            _vector(packet_rate_max=5000.0),
            {"status": "ATTACK", "confidence": 90.0},
        )
        self.assertFalse(out.model_available)
        self.assertIn("decision_tree:NOT_AVAILABLE", out.missing_evidence)

    # 15 feature-count mismatch
    def test_15_feature_count_mismatch(self):
        out = self.eng.explain(
            [1.0, 2.0, 3.0],
            {"status": "ATTACK", "confidence": 90.0},
            decision_tree=self.dt,
            scaler=self.scaler,
        )
        self.assertEqual(out.method, ExplanationMethod.FEATURE_MISMATCH.value)
        self.assertEqual(out.decision_path, [])

    # 16 NaN/invalid features
    def test_16_nan_invalid_features(self):
        bad = _vector()
        bad[1] = float("nan")
        out = self.eng.explain(
            bad,
            {"status": "ATTACK", "confidence": 90.0},
            decision_tree=self.dt,
            scaler=self.scaler,
        )
        self.assertTrue(any("nonfinite" in m for m in out.missing_evidence))
        self.assertEqual(out.decision_path, [])

        bad2 = _vector()
        bad2[0] = "x"  # type: ignore[assignment]
        out2 = self.eng.explain(
            bad2,
            {"status": "ATTACK", "confidence": 90.0},
            decision_tree=self.dt,
            scaler=self.scaler,
        )
        self.assertTrue(any("invalid" in m for m in out2.missing_evidence))

    # 17 missing confidence
    def test_17_missing_confidence(self):
        out = self.eng.explain(
            _vector(packet_rate_max=3200.0),
            {"status": "ATTACK"},
            decision_tree=self.dt,
            scaler=self.scaler,
        )
        self.assertIsNone(out.confidence_percent)
        self.assertIn("confidence:NOT_AVAILABLE", out.missing_evidence)
        self.assertIn("NOT_AVAILABLE", out.summary)

    # 18 serialization
    def test_18_serialization(self):
        out = self.eng.explain(
            _vector(packet_rate_max=3200.0),
            {"status": "ATTACK", "confidence": 90.0},
            decision_tree=self.dt,
            scaler=self.scaler,
        )
        payload = out.to_dict()
        encoded = json.dumps(payload)
        decoded = json.loads(encoded)
        self.assertEqual(decoded["_type"], "PredictionExplanation")
        self.assertIn("global_feature_importances", decoded)
        self.assertIn("local_path_features", decoded)
        self.assertIn("summary", decoded)

    # 19 no network access (no sockets opened by explain)
    def test_19_no_network_access(self):
        import socket

        original = socket.socket

        def blocked(*a, **k):
            raise RuntimeError("network forbidden in XAI test")

        socket.socket = blocked  # type: ignore[misc]
        try:
            out = self.eng.explain(
                _vector(packet_rate_max=3200.0),
                {"status": "ATTACK", "confidence": 90.0},
                decision_tree=self.dt,
                scaler=self.scaler,
            )
            self.assertIsInstance(out, PredictionExplanation)
        finally:
            socket.socket = original  # type: ignore[misc]

    # 20 no controller dependency
    def test_20_no_controller_dependency(self):
        import xai.engine as eng_mod

        src = open(eng_mod.__file__, encoding="utf-8").read()
        self.assertNotIn("flow_monitor", src)
        self.assertNotIn("controller.", src)

    # 21 no mitigation side effects
    def test_21_no_mitigation_side_effects(self):
        import xai.engine as eng_mod

        src = open(eng_mod.__file__, encoding="utf-8").read()
        self.assertNotIn("handle_alert", src)
        self.assertNotIn("FlowBlocker", src)
        self.assertNotIn("import mitigation", src)
        self.assertNotIn("from mitigation", src)

    # 22 explanation failure does not throw
    def test_22_failure_does_not_throw(self):
        class Boom:
            tree_ = object()

            def decision_path(self, X):
                raise RuntimeError("boom")

        out = self.eng.explain(
            _vector(),
            {"status": "ATTACK", "confidence": 90.0},
            decision_tree=Boom(),
            scaler=self.scaler,
        )
        self.assertIsInstance(out, PredictionExplanation)

        class BoomScaler:
            def transform(self, X):
                raise RuntimeError("boom")

        out2 = self.eng.explain(
            _vector(packet_rate_max=3000.0),
            {"status": "ATTACK", "confidence": 90.0},
            decision_tree=self.dt,
            scaler=BoomScaler(),
        )
        self.assertIsInstance(out2, PredictionExplanation)

    def test_legacy_bridge_and_inferred_evidence(self):
        out = self.eng.explain(
            _vector(packet_rate_max=5000.0, src_entropy=0.05),
            {"status": "ATTACK", "confidence": 91.0},
        )
        legacy = explanation_to_legacy_dict(out)
        self.assertIn("xai_summary", legacy)
        for a in out.anomalous_features:
            self.assertEqual(a.evidence_kind, EvidenceKind.INFERRED.value)
            self.assertEqual(a.scope, AttributionScope.HEURISTIC_DEVIATION.value)

    def test_no_rca_in_r51_package(self):
        import xai

        self.assertFalse(hasattr(xai, "RootCauseEngine"))
        self.assertFalse(hasattr(xai, "RootCauseAnalyzer"))

    def test_explain_from_detector(self):
        from ml_models.anomaly_detector import AnomalyDetector

        det = AnomalyDetector(auto_load=False)
        det._dt = self.dt
        det._scaler = self.scaler
        det._is_dt_trained = True
        out = self.eng.explain_from_detector(
            det,
            _vector(packet_rate_max=3100.0),
            {"status": "ATTACK", "confidence": 93.0, "dt_label": 1},
        )
        self.assertTrue(out.model_available)
        self.assertGreater(len(out.decision_path), 0)


if __name__ == "__main__":
    unittest.main()
