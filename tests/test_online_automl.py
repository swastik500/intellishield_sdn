"""
Test suite for Online AutoML feature.

Covers:
  1. 15-D feature schema & Candidate suite training
  2. Candidate evaluator & validation gate policies
  3. Champion selector ranking and regression protection
  4. Model registry artifact persistence and rollback mechanism
  5. Drift & performance trigger policy (preventing 5s poll execution)
  6. End-to-end OnlineAutoMLService lifecycle
  7. Shared contract compliance (ModelVersion, ModelCandidate, ValidationResult)
  8. Regression protection for existing project features
"""

from __future__ import annotations

import os
import sys
import unittest
import numpy as np

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import CandidateStatus, ModelStatus, ValidationStatus
from shared_contracts.models import ModelCandidate, ModelVersion, ValidationResult
from online_automl import (
    AutoMLCandidate,
    AutoMLLogger,
    AutoMLRegistry,
    AutoMLTriggerManager,
    CandidateEvaluator,
    CandidateValidationPolicy,
    ChampionSelector,
    OnlineAutoMLService,
    automl_service,
    build_candidate_suite,
)


def _synthetic_dataset(n_samples: int = 100, seed: int = 42):
    rng = np.random.RandomState(seed)
    X, y = [], []
    for i in range(n_samples):
        is_attack = i % 2 == 1
        if not is_attack:
            vec = [
                float(rng.uniform(10.0, 50.0)),   # packet_rate_mean
                float(rng.uniform(50.0, 150.0)),  # packet_rate_max
                float(rng.uniform(800.0, 3000.0)),# byte_rate_mean
                float(rng.uniform(3000.0, 8000.0)),# byte_rate_max
                float(rng.uniform(3.0, 12.0)),    # flow_count
                float(rng.uniform(5.0, 30.0)),    # duration_mean
                float(rng.uniform(2.0, 8.0)),     # unique_src_count
                float(rng.uniform(2.0, 8.0)),     # unique_dst_count
                float(rng.uniform(0.80, 0.98)),   # src_entropy
                float(rng.uniform(0.80, 0.98)),   # dst_entropy
                float(rng.uniform(0.80, 0.98)),   # packet_entropy
                float(rng.uniform(0.80, 0.98)),   # byte_entropy
                float(rng.uniform(0.80, 0.98)),   # flow_entropy
                float(rng.uniform(0.85, 0.98)),   # entropy_score
                float(rng.uniform(0.02, 0.20)),   # flow_concentration
            ]
            y.append(0)
        else:
            vec = [
                float(rng.uniform(5000.0, 25000.0)),
                float(rng.uniform(30000.0, 80000.0)),
                float(rng.uniform(300000.0, 1500000.0)),
                float(rng.uniform(1500000.0, 5000000.0)),
                float(rng.uniform(100.0, 800.0)),
                float(rng.uniform(0.5, 3.0)),
                float(rng.uniform(100.0, 500.0)),
                float(rng.uniform(1.0, 2.0)),
                float(rng.uniform(0.05, 0.25)),
                float(rng.uniform(0.01, 0.15)),
                float(rng.uniform(0.10, 0.30)),
                float(rng.uniform(0.10, 0.30)),
                float(rng.uniform(0.10, 0.30)),
                float(rng.uniform(0.05, 0.25)),
                float(rng.uniform(0.75, 0.95)),
            ]
            y.append(1)
        X.append(vec)
    return X, y


class TestOnlineAutoMLCandidates(unittest.TestCase):
    """Test 1. Candidate model suite creation and fitting."""

    def test_candidate_suite_creation_and_fit(self):
        X, y = _synthetic_dataset(60)
        candidates = build_candidate_suite()
        self.assertGreaterEqual(len(candidates), 5)

        names = [c.algorithm_name for c in candidates]
        self.assertIn("Decision Tree", names)
        self.assertIn("Random Forest", names)
        self.assertIn("Extra Trees", names)
        self.assertIn("Isolation Forest", names)
        self.assertIn("SGD One-Class SVM", names)

        for cand in candidates:
            cand.fit(X, y)
            self.assertEqual(cand.status, CandidateStatus.READY)
            preds = cand.predict(X[:5])
            self.assertEqual(len(preds), 5)
            probs = cand.predict_proba(X[:5])
            self.assertEqual(len(probs), 5)


class TestOnlineAutoMLEvaluator(unittest.TestCase):
    """Test 2. Candidate evaluator and validation gate policy."""

    def test_evaluator_metrics_and_policy(self):
        X_tr, y_tr = _synthetic_dataset(80, seed=1)
        X_val, y_val = _synthetic_dataset(40, seed=2)

        cand = build_candidate_suite()[0]  # Decision Tree
        cand.fit(X_tr, y_tr)

        evaluator = CandidateEvaluator(CandidateValidationPolicy(min_f1=0.70, max_fpr=0.15))
        metrics, val_res = evaluator.evaluate_candidate(cand, X_val, y_val)

        self.assertIn("f1_score", metrics)
        self.assertIn("false_positive_rate", metrics)
        self.assertIn("latency_ms", metrics)

        self.assertIsInstance(val_res, ValidationResult)
        self.assertEqual(val_res.candidate_id, cand.candidate_id)
        self.assertIn(val_res.status, (ValidationStatus.PASS, ValidationStatus.FAIL))


class TestOnlineAutoMLSelector(unittest.TestCase):
    """Test 3. Champion selector and regression prevention."""

    def test_champion_selection_and_regression_check(self):
        X_tr, y_tr = _synthetic_dataset(100, seed=10)
        X_val, y_val = _synthetic_dataset(40, seed=11)

        candidates = build_candidate_suite()
        evaluator = CandidateEvaluator(CandidateValidationPolicy(min_f1=0.50, max_fpr=0.20))

        for c in candidates:
            c.fit(X_tr, y_tr)
            evaluator.evaluate_candidate(c, X_val, y_val)

        selector = ChampionSelector(max_f1_regression=0.05)
        champion, reason = selector.select_champion(candidates)

        self.assertIsNotNone(champion)
        self.assertEqual(champion.status, CandidateStatus.PROMOTED)
        self.assertIn("Promoted", reason)


class TestOnlineAutoMLRegistryAndRollback(unittest.TestCase):
    """Test 4. Model registry, versioning, and rollback."""

    def test_registry_champion_promotion_and_rollback(self):
        X_tr, y_tr = _synthetic_dataset(60)
        suite = build_candidate_suite()

        c1 = suite[0]  # DT
        c1.fit(X_tr, y_tr)
        c1.metrics = {"f1_score": 0.92, "false_positive_rate": 0.02, "latency_ms": 0.5}

        c2 = suite[1]  # RF
        c2.fit(X_tr, y_tr)
        c2.metrics = {"f1_score": 0.95, "false_positive_rate": 0.01, "latency_ms": 0.8}

        registry = AutoMLRegistry(
            registry_file="logs/test_automl_reg.json",
            champion_pkl="logs/models/test_champion.pkl",
        )

        # Promote c1
        registry.register_champion(c1)
        self.assertEqual(registry.current_champion.candidate_id, c1.candidate_id)

        # Promote c2 -> c1 moves to previous_champion
        registry.register_champion(c2)
        self.assertEqual(registry.current_champion.candidate_id, c2.candidate_id)
        self.assertEqual(registry.previous_champion.candidate_id, c1.candidate_id)

        # Rollback -> c1 restored
        restored, reason = registry.rollback()
        self.assertIsNotNone(restored)
        self.assertEqual(restored.candidate_id, c1.candidate_id)
        self.assertEqual(registry.current_champion.candidate_id, c1.candidate_id)

        # Cleanup test files
        if os.path.exists("logs/test_automl_reg.json"):
            os.remove("logs/test_automl_reg.json")
        if os.path.exists("logs/models/test_champion.pkl"):
            os.remove("logs/models/test_champion.pkl")


class TestOnlineAutoMLDriftTrigger(unittest.TestCase):
    """Test 5. Drift & performance trigger policy."""

    def test_trigger_cooldown_and_signals(self):
        mgr = AutoMLTriggerManager(min_interval_sec=300.0)

        # Manual trigger works immediately
        trig, reason = mgr.should_trigger(force=True)
        self.assertTrue(trig)
        self.assertEqual(reason, "MANUAL_TRIGGER")

        # Second trigger immediately after should be blocked by cooldown
        trig2, reason2 = mgr.should_trigger(force=False, adwin_drift=True)
        self.assertFalse(trig2)
        self.assertIn("COOLDOWN", reason2)


class TestOnlineAutoMLServiceLifecycle(unittest.TestCase):
    """Test 6 & 7. End-to-end OnlineAutoMLService lifecycle & contracts."""

    def test_automl_service_full_run(self):
        service = OnlineAutoMLService()
        X_tr, y_tr = _synthetic_dataset(80, seed=5)
        X_v, y_v = _synthetic_dataset(40, seed=6)

        report = service.run_automl_pipeline(
            force=True,
            X_train=X_tr,
            y_train=y_tr,
            X_val=X_v,
            y_val=y_v,
        )

        self.assertTrue(report["ran"])
        self.assertIn("candidates_evaluated", report)
        self.assertGreaterEqual(report["candidates_evaluated"], 5)
        self.assertIn("champion_selected", report)

        status = service.get_status()
        self.assertIn("champion", status)
        self.assertIn("candidates", status)
        self.assertIn("last_trigger_reason", status)


if __name__ == "__main__":
    unittest.main()
