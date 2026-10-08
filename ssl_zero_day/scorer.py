"""
SSL Anomaly Scorer for 15-D feature vectors.

Calculates reconstruction MSE score MSE(X, reconstructed_X) using trained SSLAutoencoder
and evaluates anomaly decision via SSLThresholdCalibrator.
Higher score = more anomalous.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence, Union

import numpy as np

from shared_contracts.enums import DetectionDecision
from ssl_zero_day.autoencoder import SSLAutoencoder
from ssl_zero_day.feature_window import sanitize_15d_vector
from ssl_zero_day.threshold import SSLThresholdCalibrator

logger = logging.getLogger("intellishield.ssl_zero_day.scorer")


class SSLScorer:
    """
    Computes reconstruction MSE anomaly scores and evaluates decisions.
    """

    def __init__(
        self,
        autoencoder: SSLAutoencoder,
        threshold_calibrator: Optional[SSLThresholdCalibrator] = None,
    ) -> None:
        self.autoencoder = autoencoder
        self.calibrator = threshold_calibrator or SSLThresholdCalibrator()

    def score_vector(self, vector: Sequence[float]) -> Dict[str, Any]:
        """
        Score a single 15-D feature vector.

        Args:
            vector: 15-dimensional feature vector.

        Returns:
            Dictionary containing:
              - score: raw MSE reconstruction score
              - decision: DetectionDecision (NORMAL, SUSPICIOUS, ATTACK)
              - confidence: normalized confidence float in [0.0, 1.0]
              - normal_threshold: calibrated normal threshold
              - attack_threshold: calibrated attack threshold
        """
        clean_vec = sanitize_15d_vector(vector)
        
        if not self.autoencoder.is_fitted:
            return {
                "score": 0.0,
                "decision": DetectionDecision.NONE,
                "confidence": 0.0,
                "normal_threshold": self.calibrator.normal_threshold,
                "attack_threshold": self.calibrator.attack_threshold,
                "status": "UNAVAILABLE",
                "reason": "autoencoder_not_fitted",
            }

        mse = float(self.autoencoder.compute_mse(clean_vec)[0])
        decision, confidence = self.calibrator.classify_score(mse)

        return {
            "score": round(mse, 6),
            "decision": decision,
            "confidence": round(confidence, 4),
            "normal_threshold": round(self.calibrator.normal_threshold, 6),
            "attack_threshold": round(self.calibrator.attack_threshold, 6),
            "status": decision.value,
        }

    def score_batch(
        self, vectors: Union[List[List[float]], np.ndarray]
    ) -> List[Dict[str, Any]]:
        """Score a batch of 15-D feature vectors."""
        return [self.score_vector(v) for v in vectors]
