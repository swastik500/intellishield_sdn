"""
Calibrated threshold manager for SSL Zero-Day detector.

Calibrates normal and attack thresholds strictly using normal/validation reconstruction errors (MSE).
Attack-X data is NEVER used for threshold calibration.
"""

from __future__ import annotations

import logging
import os
import pickle
from typing import Dict, Optional, Sequence, Tuple, Union

import numpy as np

from shared_contracts.enums import DetectionDecision

logger = logging.getLogger("intellishield.ssl_zero_day.threshold")


class SSLThresholdCalibrator:
    """
    Manages threshold calibration from normal traffic reconstruction errors.

    Determines:
      - normal_threshold: upper bound for normal traffic reconstruction MSE
      - attack_threshold: threshold above which traffic is classified as ATTACK
    """

    def __init__(
        self,
        normal_threshold: Optional[float] = None,
        attack_threshold: Optional[float] = None,
    ) -> None:
        self.normal_threshold: float = float(normal_threshold) if normal_threshold is not None else 0.5
        self.attack_threshold: float = float(attack_threshold) if attack_threshold is not None else 1.5
        self.mean_error: float = 0.0
        self.std_error: float = 0.0
        self.max_normal_error: float = 0.0
        self.quantile_95: float = 0.0
        self.quantile_99: float = 0.0
        self.is_calibrated: bool = normal_threshold is not None and attack_threshold is not None

    def calibrate(
        self,
        normal_errors: Union[Sequence[float], np.ndarray],
        quantile: float = 0.95,
        k_std: float = 3.0,
    ) -> Dict[str, float]:
        """
        Calibrate thresholds from normal/validation reconstruction errors.

        Args:
            normal_errors: List or array of MSE values computed on normal data.
            quantile: Quantile for normal threshold (default 0.95).
            k_std: Standard deviation multiplier for attack threshold (default 3.0).

        Returns:
            Dictionary of calibration metrics.
        """
        errors = np.array(normal_errors, dtype=float)
        if len(errors) == 0:
            raise ValueError("Cannot calibrate on empty reconstruction errors")

        self.mean_error = float(np.mean(errors))
        self.std_error = float(np.std(errors))
        self.max_normal_error = float(np.max(errors))
        self.quantile_95 = float(np.quantile(errors, quantile))
        self.quantile_99 = float(np.quantile(errors, min(0.99, quantile + 0.04)))

        # Normal threshold: 95th percentile or mean + 2*std, whichever is higher
        self.normal_threshold = max(self.quantile_95, self.mean_error + 2.0 * self.std_error)
        
        # Attack threshold: 99th percentile or mean + k_std*std, whichever is higher
        self.attack_threshold = max(
            self.quantile_99,
            self.mean_error + max(2.5, k_std) * self.std_error,
            self.normal_threshold * 1.5,
        )

        self.is_calibrated = True

        stats = {
            "mean_error": self.mean_error,
            "std_error": self.std_error,
            "max_normal_error": self.max_normal_error,
            "quantile_95": self.quantile_95,
            "quantile_99": self.quantile_99,
            "normal_threshold": self.normal_threshold,
            "attack_threshold": self.attack_threshold,
        }

        logger.info(
            "[SSLThresholdCalibrator] Calibrated on %d normal samples. "
            "Normal thresh: %.6f, Attack thresh: %.6f (mean: %.6f, std: %.6f)",
            len(errors),
            self.normal_threshold,
            self.attack_threshold,
            self.mean_error,
            self.std_error,
        )
        return stats

    def classify_score(self, mse_score: float) -> Tuple[DetectionDecision, float]:
        """
        Classify a single MSE reconstruction error and compute normalized confidence.

        Args:
            mse_score: Reconstruction error MSE.

        Returns:
            Tuple of (DetectionDecision, confidence_in_[0,1]).
        """
        score = max(0.0, float(mse_score))

        if not self.is_calibrated:
            # Uncalibrated fallback logic
            if score >= self.attack_threshold:
                return DetectionDecision.ATTACK, 0.80
            if score >= self.normal_threshold:
                return DetectionDecision.SUSPICIOUS, 0.50
            return DetectionDecision.NORMAL, 0.80

        if score >= self.attack_threshold:
            decision = DetectionDecision.ATTACK
            # Confidence scales with how far above attack threshold the score is
            excess = (score - self.attack_threshold) / (self.attack_threshold + 1e-6)
            confidence = min(1.0, 0.85 + 0.15 * min(1.0, excess))
        elif score >= self.normal_threshold:
            decision = DetectionDecision.SUSPICIOUS
            range_span = self.attack_threshold - self.normal_threshold
            fraction = (score - self.normal_threshold) / (range_span + 1e-6)
            confidence = min(0.85, 0.50 + 0.35 * fraction)
        else:
            decision = DetectionDecision.NORMAL
            # High confidence if score is well below normal threshold
            margin = (self.normal_threshold - score) / (self.normal_threshold + 1e-6)
            confidence = min(0.99, 0.70 + 0.29 * min(1.0, margin))

        return decision, float(np.clip(confidence, 0.0, 1.0))

    def save(self, filepath: str) -> None:
        """Save threshold calibrator state to disk."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        state = {
            "normal_threshold": self.normal_threshold,
            "attack_threshold": self.attack_threshold,
            "mean_error": self.mean_error,
            "std_error": self.std_error,
            "max_normal_error": self.max_normal_error,
            "quantile_95": self.quantile_95,
            "quantile_99": self.quantile_99,
            "is_calibrated": self.is_calibrated,
        }
        with open(filepath, "wb") as f:
            pickle.dump(state, f)
        logger.info("[SSLThresholdCalibrator] Saved threshold state to %s", filepath)

    @classmethod
    def load(cls, filepath: str) -> SSLThresholdCalibrator:
        """Load threshold calibrator from disk."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Threshold file not found: {filepath}")

        with open(filepath, "rb") as f:
            state = pickle.load(f)

        cal = cls(
            normal_threshold=state.get("normal_threshold"),
            attack_threshold=state.get("attack_threshold"),
        )
        cal.mean_error = state.get("mean_error", 0.0)
        cal.std_error = state.get("std_error", 0.0)
        cal.max_normal_error = state.get("max_normal_error", 0.0)
        cal.quantile_95 = state.get("quantile_95", 0.0)
        cal.quantile_99 = state.get("quantile_99", 0.0)
        cal.is_calibrated = state.get("is_calibrated", False)
        return cal
