#!/usr/bin/env python3
"""R5.5 — Model-grounded XAI path faithfulness / correctness."""

from __future__ import annotations

import json
import os
import sys
import unittest

import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from ml_models.feature_builder import FEATURE_NAMES
from xai import AttributionScope, XAIEngine
from xai.faithfulness import faithfulness_rate, verify_path_against_model
from xai.tree_path import extract_decision_path


def _train_dt(seed=0):
    rng = np.random.RandomState(seed)
    X_n = rng.normal(loc=40, scale=5, size=(60, len(FEATURE_NAMES)))
    X_a = rng.normal(loc=40, scale=5, size=(60, len(FEATURE_NAMES)))
    X_a[:, 1] = rng.normal(loc=2800, scale=80, size=60)
    X_a[:, 8] = rng.uniform(0.01, 0.2, size=60)
    X = np.vstack([X_n, X_a])
    y = np.array([0] * 60 + [1] * 60)
    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)
    dt = DecisionTreeClassifier(max_depth=5, random_state=seed)
    dt.fit(Xs, y)
    return dt, scaler, Xs


class TestXAIFaithfulnessR55(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dt, cls.scaler, cls.Xs = _train_dt()

    def test_mechanical_path_feature_threshold_branch(self):
        vec = self.Xs[70]
        steps, leaf, _ = extract_decision_path(self.dt, vec, FEATURE_NAMES)
        self.assertGreater(len(steps), 0)
        result = verify_path_against_model(
            self.dt,
            vec,
            FEATURE_NAMES,
            reported_steps=steps,
            reported_leaf=leaf,
        )
        self.assertTrue(result.path_matches_sklearn, result.errors)
        self.assertTrue(result.leaf_matches_prediction, result.errors)
        self.assertTrue(result.ok, result.errors)
        for step in steps:
            self.assertEqual(step.scope, AttributionScope.LOCAL_PATH.value)
            self.assertIn(step.operator, ("<=", ">"))
            self.assertIn(step.direction, ("left", "right"))

    def test_faithfulness_rate_100_percent(self):
        # Deterministic holdout: first 40 normal + 40 attack scaled rows
        sample = list(self.Xs[:40]) + list(self.Xs[60:100])
        stats = faithfulness_rate(self.dt, sample, FEATURE_NAMES)
        payload = {
            "method": "native_decision_tree_path",
            "total": stats["total"],
            "correct": stats["correct"],
            "rate": stats["rate"],
            "failures": stats["failures"],
        }
        out = os.path.join(_ROOT, "logs", "r55_xai_faithfulness.json")
        try:
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
                fh.write("\n")
        except OSError:
            pass
        self.assertEqual(stats["total"], 80)
        self.assertEqual(stats["correct"], 80)
        self.assertEqual(stats["rate"], 1.0)
        self.assertEqual(stats["failures"], [])

    def test_xai_engine_path_faithful(self):
        eng = XAIEngine()
        raw = self.scaler.inverse_transform(self.Xs[75:76])[0]
        pred = {
            "status": "ATTACK",
            "confidence": 90.0,
            "dt_label": 1,
        }
        expl = eng.explain(
            list(raw),
            pred,
            decision_tree=self.dt,
            scaler=self.scaler,
        )
        self.assertGreater(len(expl.decision_path), 0)
        X_scaled = self.scaler.transform(np.asarray([list(raw)], dtype=float))[0]
        result = verify_path_against_model(
            self.dt,
            X_scaled,
            FEATURE_NAMES,
            reported_steps=expl.decision_path,
            reported_leaf=expl.leaf_decision,
        )
        self.assertTrue(result.ok, result.errors)

    def test_global_vs_local_not_confused(self):
        eng = XAIEngine()
        raw = self.scaler.inverse_transform(self.Xs[10:11])[0]
        expl = eng.explain(
            list(raw),
            {"status": "NORMAL", "confidence": 20.0},
            decision_tree=self.dt,
            scaler=self.scaler,
        )
        for f in expl.global_feature_importances:
            self.assertEqual(f.scope, AttributionScope.GLOBAL_IMPORTANCE.value)
            self.assertIn("not per-prediction", f.note.lower())
        for f in expl.local_path_features:
            self.assertEqual(f.scope, AttributionScope.LOCAL_PATH.value)


if __name__ == "__main__":
    unittest.main()
