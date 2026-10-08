"""
Test suite for Self-Supervised Zero-Day (SSL) Anomaly Detector.

Covers:
  1. 15-D feature vector validation
  2. Autoencoder training and reconstruction (MLPRegressor X -> X)
  3. Anomaly scoring (reconstruction MSE)
  4. Threshold calibration on normal-only data
  5. DetectorType.SSL / DetectorResult contract compliance
  6. Unseen Attack-X zero-day evaluation (Detection Rate, FPR, latency, score distributions)
  7. Integration with R6 fusion and R7 verification
  8. SSL failure isolation (fault tolerance)
  9. Regression protection for existing repository contracts
"""

from __future__ import annotations

import math
import os
import sys
import time
import unittest
from datetime import datetime, timezone
import numpy as np

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import DetectionDecision, DetectorHealth, DetectorType
from shared_contracts.models import DetectorResult
from shared_contracts.serialize import from_dict, to_dict
from fusion import (
    CollaborativeFusionEngine,
    DetectorDescriptor,
    EvidenceRegistry,
    EvidenceRole,
    adapt_entropy_metrics,
    adapt_ml_prediction,
    adapt_ssl_result,
)
from verification.adapters import detector_type_from_prediction, prediction_to_detector_result
from ssl_zero_day import (
    FEATURE_NAMES,
    N_FEATURES,
    FeatureWindow,
    SSLAutoencoder,
    SSLLogger,
    SSLScorer,
    SSLThresholdCalibrator,
    SSLTrainer,
    SSLZeroDayDetector,
    sanitize_15d_vector,
    validate_15d_vector,
)


def _synthetic_normal_vector(seed: int = 0) -> list[float]:
    """Generate a realistic 15-D normal traffic feature vector."""
    rng = np.random.RandomState(seed)
    return [
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
        float(rng.uniform(0.02, 0.20)),   # flow_concentration (1 - src_entropy)
    ]


def _synthetic_attack_x_vector(seed: int = 100) -> list[float]:
    """Generate an unseen Attack-X (novel DDoS flood) 15-D feature vector."""
    rng = np.random.RandomState(seed)
    return [
        float(rng.uniform(5000.0, 25000.0)),# packet_rate_mean (massive spike)
        float(rng.uniform(30000.0, 80000.0)),# packet_rate_max
        float(rng.uniform(300000.0, 1500000.0)),# byte_rate_mean
        float(rng.uniform(1500000.0, 5000000.0)),# byte_rate_max
        float(rng.uniform(100.0, 800.0)),  # flow_count
        float(rng.uniform(0.5, 3.0)),      # duration_mean
        float(rng.uniform(100.0, 500.0)),  # unique_src_count (botnet)
        float(rng.uniform(1.0, 2.0)),      # unique_dst_count (targeted victim)
        float(rng.uniform(0.05, 0.25)),    # src_entropy collapse
        float(rng.uniform(0.01, 0.15)),    # dst_entropy collapse
        float(rng.uniform(0.10, 0.30)),    # packet_entropy
        float(rng.uniform(0.10, 0.30)),    # byte_entropy
        float(rng.uniform(0.10, 0.30)),    # flow_entropy
        float(rng.uniform(0.05, 0.25)),    # entropy_score collapse
        float(rng.uniform(0.75, 0.95)),    # flow_concentration extreme
    ]


class TestSSL15DValidation(unittest.TestCase):
    """Test 1. 15-D Feature Vector Validation."""

    def test_feature_schema_length(self):
        self.assertEqual(len(FEATURE_NAMES), 15)
        self.assertEqual(N_FEATURES, 15)

    def test_vector_validation(self):
        valid_vec = _synthetic_normal_vector(1)
        self.assertTrue(validate_15d_vector(valid_vec))

        # Invalid lengths
        self.assertFalse(validate_15d_vector(valid_vec[:14]))
        self.assertFalse(validate_15d_vector(valid_vec + [1.0]))

        # Non-finite values
        invalid_nan = list(valid_vec)
        invalid_nan[3] = float("nan")
        self.assertFalse(validate_15d_vector(invalid_nan))

        invalid_inf = list(valid_vec)
        invalid_inf[0] = float("inf")
        self.assertFalse(validate_15d_vector(invalid_inf))

    def test_vector_sanitization(self):
        bad_vec = [1.0, 2.0, float("nan"), float("inf"), "invalid"]
        san = sanitize_15d_vector(bad_vec)
        self.assertEqual(len(san), 15)
        self.assertEqual(san[0], 1.0)
        self.assertEqual(san[1], 2.0)
        self.assertEqual(san[2], 0.0)
        self.assertEqual(san[3], 0.0)
        self.assertEqual(san[4], 0.0)

    def test_feature_window(self):
        window = FeatureWindow(window_size=5)
        self.assertEqual(window.current_size, 0)

        for i in range(7):
            window.add_vector(_synthetic_normal_vector(i))

        self.assertEqual(window.current_size, 5)
        self.assertTrue(window.is_full)
        matrix = window.get_matrix()
        self.assertEqual(matrix.shape, (5, 15))


class TestSSLAutoencoderTraining(unittest.TestCase):
    """Test 2 & 3. Autoencoder training (X -> X) and MSE Anomaly Scoring."""

    def setUp(self):
        self.X_normal = [_synthetic_normal_vector(i) for i in range(100)]
        self.X_attack = [_synthetic_attack_x_vector(i) for i in range(20)]

    def test_autoencoder_fit_and_reconstruct(self):
        autoencoder = SSLAutoencoder(hidden_layer_sizes=(12, 6, 12), max_iter=500, random_state=42)
        autoencoder.fit(self.X_normal)

        self.assertTrue(autoencoder.is_fitted)
        recon = autoencoder.reconstruct(self.X_normal[:5])
        self.assertEqual(recon.shape, (5, 15))

    def test_reconstruction_mse_scoring(self):
        autoencoder = SSLAutoencoder(hidden_layer_sizes=(12, 6, 12), max_iter=500, random_state=42)
        autoencoder.fit(self.X_normal)

        normal_mses = autoencoder.compute_mse(self.X_normal)
        attack_mses = autoencoder.compute_mse(self.X_attack)

        mean_normal_mse = float(np.mean(normal_mses))
        mean_attack_mse = float(np.mean(attack_mses))

        # Reconstruction error on unseen Attack-X must be significantly higher than on normal
        self.assertGreater(mean_attack_mse, mean_normal_mse * 5.0)


class TestSSLThresholdCalibration(unittest.TestCase):
    """Test 4. Threshold calibration on normal-only data."""

    def test_threshold_calibration_stats(self):
        X_normal = [_synthetic_normal_vector(i) for i in range(100)]
        autoencoder = SSLAutoencoder(hidden_layer_sizes=(12, 6, 12), max_iter=500, random_state=42)
        autoencoder.fit(X_normal)

        normal_mses = autoencoder.compute_mse(X_normal)
        calibrator = SSLThresholdCalibrator()
        stats = calibrator.calibrate(normal_mses, quantile=0.95, k_std=3.0)

        self.assertTrue(calibrator.is_calibrated)
        self.assertGreater(calibrator.attack_threshold, calibrator.normal_threshold)
        self.assertGreaterEqual(calibrator.normal_threshold, stats["mean_error"])


class TestSSLContractCompliance(unittest.TestCase):
    """Test 5. DetectorType.SSL and DetectorResult Contract Compliance."""

    def setUp(self):
        self.detector = SSLZeroDayDetector(auto_load=False)
        X_normal = [_synthetic_normal_vector(i) for i in range(80)]
        self.detector.train_normal(X_normal, persist=False)

    def test_detector_result_format(self):
        vec = _synthetic_normal_vector(99)
        result = self.detector.predict_result(vec, switch_id=1, src_mac="02:00:00:00:00:01")

        self.assertIsInstance(result, DetectorResult)
        self.assertEqual(result.detector, DetectorType.SSL)
        self.assertEqual(result.health, DetectorHealth.SUCCESS)
        self.assertIn(result.decision, (DetectionDecision.NORMAL, DetectionDecision.SUSPICIOUS, DetectionDecision.ATTACK))
        self.assertIsNotNone(result.confidence)
        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)
        self.assertIsNotNone(result.score)
        self.assertIsNotNone(result.threshold)
        self.assertIsInstance(result.evidence, dict)

    def test_serialization_roundtrip(self):
        vec = _synthetic_normal_vector(101)
        res = self.detector.predict_result(vec)
        data_dict = to_dict(res)

        self.assertEqual(data_dict["detector"], "SSL")
        deserialized = from_dict(data_dict, DetectorResult)
        self.assertEqual(deserialized.detector, DetectorType.SSL)
        self.assertEqual(deserialized.decision, res.decision)
        self.assertAlmostEqual(deserialized.confidence, res.confidence)


class TestSSLZeroDayEvaluation(unittest.TestCase):
    """Test 6. Zero-Day Evaluation: Unseen Attack-X detection & Metrics."""

    def test_unseen_attack_x_zero_day_metrics(self):
        # 1. Train strictly on normal-only dataset (X -> X)
        X_train_normal = [_synthetic_normal_vector(i) for i in range(150)]
        X_val_normal = [_synthetic_normal_vector(150 + i) for i in range(50)]

        detector = SSLZeroDayDetector(auto_load=False)
        detector.train_normal(X_train_normal, X_val_normal=X_val_normal, quantile=0.98, k_std=3.0, persist=False)

        # 2. Test dataset: 50 normal + 50 unseen Attack-X samples
        X_test_normal = [_synthetic_normal_vector(200 + i) for i in range(50)]
        X_test_attack_x = [_synthetic_attack_x_vector(500 + i) for i in range(50)]

        # Benchmark latencies
        start_time = time.perf_counter()
        normal_results = [detector.predict_result(v) for v in X_test_normal]
        attack_results = [detector.predict_result(v) for v in X_test_attack_x]
        total_latency = time.perf_counter() - start_time
        mean_latency = total_latency / (len(X_test_normal) + len(X_test_attack_x))

        # Compute confusion metrics for Attack-X detection
        # Positive = Attack-X, Negative = Normal
        tp = sum(1 for r in attack_results if r.decision in (DetectionDecision.ATTACK, DetectionDecision.SUSPICIOUS))
        fn = len(attack_results) - tp

        fp = sum(1 for r in normal_results if r.decision in (DetectionDecision.ATTACK, DetectionDecision.SUSPICIOUS))
        tn = len(normal_results) - fp

        detection_rate = tp / (tp + fn)
        false_positive_rate = fp / (fp + tn)

        normal_scores = [r.score for r in normal_results if r.score is not None]
        attack_scores = [r.score for r in attack_results if r.score is not None]

        metrics = {
            "detection_rate": detection_rate,
            "false_positive_rate": false_positive_rate,
            "mean_latency_sec": mean_latency,
            "normal_score_stats": {
                "mean": float(np.mean(normal_scores)),
                "std": float(np.std(normal_scores)),
                "max": float(np.max(normal_scores)),
                "median": float(np.median(normal_scores)),
            },
            "attack_score_stats": {
                "mean": float(np.mean(attack_scores)),
                "std": float(np.std(attack_scores)),
                "min": float(np.min(attack_scores)),
                "median": float(np.median(attack_scores)),
            },
        }

        # Log zero-day evaluation report
        SSLLogger().log_evaluation_report(metrics)

        # High Detection Rate on unseen Attack-X (>= 90%)
        self.assertGreaterEqual(detection_rate, 0.90)
        # Low False Positive Rate on normal traffic (<= 10%)
        self.assertLessEqual(false_positive_rate, 0.10)
        # Latency per sample < 10ms
        self.assertLess(mean_latency, 0.010)


class TestR6R7Integration(unittest.TestCase):
    """Test 7. Integration through existing R6 fusion and R7 verification flow."""

    def test_r6_fusion_with_ssl_detector(self):
        # Create normal SSL detector
        detector = SSLZeroDayDetector(auto_load=False)
        detector.train_normal([_synthetic_normal_vector(i) for i in range(50)], persist=False)

        # Generate detector results
        ml_res = adapt_ml_prediction({"status": "ATTACK", "confidence": 90.0})
        entropy_res = adapt_entropy_metrics({"status": "ALERT", "confidence": 85.0, "entropy_score": 0.2})
        ssl_res = detector.predict_result(_synthetic_attack_x_vector(99))

        self.assertEqual(ssl_res.detector, DetectorType.SSL)

        # Fuse primary votes in R6 CollaborativeFusionEngine
        engine = CollaborativeFusionEngine()
        fused = engine.fuse(detector_results=[ml_res, entropy_res, ssl_res])

        self.assertEqual(fused.decision, DetectionDecision.ATTACK)
        self.assertIn(DetectorType.SSL.value, fused.participating)
        self.assertIn(DetectorType.ML.value, fused.participating)
        self.assertIn(DetectorType.ENTROPY.value, fused.participating)

    def test_r7_verification_adapter_with_ssl(self):
        # Verification adapter mapping for SSL source
        pred_dict = {"source": "ssl", "status": "ATTACK", "confidence": 95.0}
        dt_type = detector_type_from_prediction(pred_dict)
        self.assertEqual(dt_type, DetectorType.SSL)

        result = prediction_to_detector_result(pred_dict)
        self.assertEqual(result.detector, DetectorType.SSL)
        self.assertEqual(result.decision, DetectionDecision.ATTACK)


class TestSSLFailureIsolation(unittest.TestCase):
    """Test 8. SSL Detector Fault Tolerance and Failure Isolation."""

    def test_unfitted_ssl_returns_error_health(self):
        unfitted_detector = SSLZeroDayDetector(auto_load=False)
        res = unfitted_detector.predict_result(_synthetic_normal_vector(1))

        self.assertEqual(res.detector, DetectorType.SSL)
        self.assertEqual(res.health, DetectorHealth.ERROR)
        self.assertEqual(res.decision, DetectionDecision.NONE)

    def test_ssl_failure_does_not_break_r6_fusion(self):
        unfitted_detector = SSLZeroDayDetector(auto_load=False)
        failed_ssl_res = unfitted_detector.predict_result(_synthetic_normal_vector(1))

        ml_res = adapt_ml_prediction({"status": "ATTACK", "confidence": 88.0})
        engine = CollaborativeFusionEngine()

        # R6 fusion gracefully handles ERROR health SSL result without crashing
        fused = engine.fuse(detector_results=[ml_res, failed_ssl_res])
        self.assertEqual(fused.decision, DetectionDecision.ATTACK)
        self.assertNotIn(DetectorType.SSL.value, fused.participating)


class TestRegressionProtection(unittest.TestCase):
    """Test 9. Regression protection for existing detectors and contracts."""

    def test_existing_detector_types_and_roles(self):
        self.assertEqual(DetectorType.SSL.value, "SSL")
        self.assertEqual(DetectorType.ML.value, "ML")
        self.assertEqual(DetectorType.ENTROPY.value, "ENTROPY")

    def test_adapt_ssl_result(self):
        res = adapt_ssl_result({"status": "ATTACK", "confidence": 92.0, "mse_score": 2.5})
        self.assertEqual(res.detector, DetectorType.SSL)
        self.assertEqual(res.decision, DetectionDecision.ATTACK)
        self.assertAlmostEqual(res.confidence, 0.92)


if __name__ == "__main__":
    unittest.main()
