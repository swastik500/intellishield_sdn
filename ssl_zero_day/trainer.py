"""
Self-Supervised Zero-Day (SSL) Model Trainer.

Trains SSLAutoencoder strictly on normal baseline traffic (X -> X)
and calibrates SSLThresholdCalibrator using normal/validation reconstruction errors.
Attack-X data is NEVER used for training, scaling, or threshold calibration.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import numpy as np

from ssl_zero_day.autoencoder import SSLAutoencoder
from ssl_zero_day.feature_window import sanitize_15d_vector
from ssl_zero_day.threshold import SSLThresholdCalibrator

logger = logging.getLogger("intellishield.ssl_zero_day.trainer")


class SSLTrainer:
    """
    Self-Supervised Trainer for training autoencoder on normal baseline data
    and calibrating reconstruction error thresholds.
    """

    def __init__(
        self,
        autoencoder: Optional[SSLAutoencoder] = None,
        calibrator: Optional[SSLThresholdCalibrator] = None,
    ) -> None:
        self.autoencoder = autoencoder or SSLAutoencoder()
        self.calibrator = calibrator or SSLThresholdCalibrator()

    def train(
        self,
        X_normal: Union[List[List[float]], np.ndarray],
        X_val_normal: Optional[Union[List[List[float]], np.ndarray]] = None,
        quantile: float = 0.95,
        k_std: float = 3.0,
    ) -> Tuple[SSLAutoencoder, SSLThresholdCalibrator, Dict[str, Any]]:
        """
        Train autoencoder and calibrate threshold strictly on normal data.

        Args:
            X_normal: List/Array of 15-D feature vectors from normal baseline traffic.
            X_val_normal: Optional separate normal validation set for threshold calibration.
            quantile: Normal threshold percentile (default 0.95).
            k_std: Attack threshold standard deviation multiplier (default 3.0).

        Returns:
            Tuple of (trained_autoencoder, calibrated_threshold, summary_metrics)
        """
        if X_normal is None or len(X_normal) == 0:
            raise ValueError("[SSLTrainer] X_normal training data cannot be empty")

        X_train_clean = [sanitize_15d_vector(v) for v in X_normal]
        logger.info("[SSLTrainer] Fitting SSL autoencoder on %d normal samples...", len(X_train_clean))

        # 1. Fit scaler & MLP autoencoder on normal training data (X -> X)
        self.autoencoder.fit(X_train_clean)

        # 2. Compute reconstruction errors (MSE) on normal data
        val_data = X_val_normal if (X_val_normal is not None and len(X_val_normal) > 0) else X_train_clean
        val_clean = [sanitize_15d_vector(v) for v in val_data]

        normal_mses = self.autoencoder.compute_mse(val_clean)

        # 3. Calibrate thresholds from normal reconstruction errors
        calib_stats = self.calibrator.calibrate(normal_mses, quantile=quantile, k_std=k_std)

        metrics = {
            "n_train": len(X_train_clean),
            "n_val": len(val_clean),
            "loss": float(self.autoencoder.model.loss_) if self.autoencoder.model else 0.0,
            "n_iter": int(self.autoencoder.model.n_iter_) if self.autoencoder.model else 0,
            "calibration_stats": calib_stats,
        }

        logger.info("[SSLTrainer] SSL training and threshold calibration complete.")
        return self.autoencoder, self.calibrator, metrics
