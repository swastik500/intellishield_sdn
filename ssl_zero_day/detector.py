"""
SSL Zero-Day Detector for IntelliShield SDN.

Operates on the repository's 15-dimensional feature vectors.
Pipeline:
  15-D features → scaler → MLPRegressor autoencoder → MSE score
  → calibrated threshold → DetectorResult(DetectorType.SSL)
  → existing R6 fusion → existing R7 verification

Fail-safe: Failure inside SSL detector returns DetectorResult(health=ERROR)
without raising exceptions or breaking other detectors in R6/R7 pipeline.
"""

from __future__ import annotations

import logging
import os
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Union

import numpy as np

from shared_contracts.enums import DetectionDecision, DetectorHealth, DetectorType
from shared_contracts.models import DetectorResult
from shared_contracts.timeutil import ensure_utc, utc_now
from fusion.roles import EvidenceRole
from ssl_zero_day.autoencoder import SSLAutoencoder
from ssl_zero_day.feature_window import (
    N_FEATURES,
    FeatureWindow,
    sanitize_15d_vector,
    validate_15d_vector,
)
from ssl_zero_day.logger import SSLLogger
from ssl_zero_day.scorer import SSLScorer
from ssl_zero_day.threshold import SSLThresholdCalibrator
from ssl_zero_day.trainer import SSLTrainer

logger = logging.getLogger("intellishield.ssl_zero_day.detector")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_MODELS_DIR = os.path.join(_BASE_DIR, "..", "logs", "models")
SSL_MODEL_PATH = os.path.join(_DEFAULT_MODELS_DIR, "ssl_autoencoder.pkl")
SSL_THRESH_PATH = os.path.join(_DEFAULT_MODELS_DIR, "ssl_threshold.pkl")


class SSLZeroDayDetector:
    """
    Self-Supervised Zero-Day (SSL) Anomaly Detector.

    Uses an MLPRegressor autoencoder trained strictly on normal traffic to detect
    unseen zero-day DDoS attacks by measuring feature reconstruction MSE.
    """

    def __init__(
        self,
        autoencoder: Optional[SSLAutoencoder] = None,
        calibrator: Optional[SSLThresholdCalibrator] = None,
        models_dir: Optional[str] = None,
        auto_load: bool = True,
    ) -> None:
        self.models_dir = models_dir or _DEFAULT_MODELS_DIR
        self.autoencoder = autoencoder or SSLAutoencoder()
        self.calibrator = calibrator or SSLThresholdCalibrator()
        self.scorer = SSLScorer(self.autoencoder, self.calibrator)
        self.trainer = SSLTrainer(self.autoencoder, self.calibrator)
        self.window = FeatureWindow(window_size=10)
        self.ssl_logger = SSLLogger()

        self.model_path = os.path.join(self.models_dir, "ssl_autoencoder.pkl")
        self.thresh_path = os.path.join(self.models_dir, "ssl_threshold.pkl")

        if auto_load:
            self._try_load_models()

    def train_normal(
        self,
        X_normal: Union[List[List[float]], np.ndarray],
        X_val_normal: Optional[Union[List[List[float]], np.ndarray]] = None,
        quantile: float = 0.95,
        k_std: float = 3.0,
        persist: bool = True,
    ) -> bool:
        """
        Train autoencoder and calibrate threshold strictly on normal baseline data.

        Attack-X data MUST NOT be passed to this method.
        """
        try:
            self.autoencoder, self.calibrator, _ = self.trainer.train(
                X_normal, X_val_normal=X_val_normal, quantile=quantile, k_std=k_std
            )
            self.scorer = SSLScorer(self.autoencoder, self.calibrator)
            if persist:
                self.save_models()
            return True
        except Exception:
            logger.error("[SSLZeroDayDetector.train_normal] Failed:\n%s", traceback.format_exc())
            return False

    def predict_result(
        self,
        vector: Sequence[float],
        timestamp: Optional[datetime] = None,
        switch_id: Optional[int] = None,
        src_mac: Optional[str] = None,
        dst_mac: Optional[str] = None,
    ) -> DetectorResult:
        """
        Main detection interface returning shared_contracts.DetectorResult.

        Fail-safe: Errors inside SSL detector return health=ERROR result
        and do not crash callers or other detectors.
        """
        ts = ensure_utc(timestamp or utc_now())
        evidence_meta: Dict[str, Any] = {
            "role": EvidenceRole.PRIMARY_DETECTION.value,
            "detector_name": "SSL Zero-Day Autoencoder",
            "model": "MLPRegressor_Autoencoder",
        }
        if switch_id is not None:
            evidence_meta["switch_id"] = switch_id
        if src_mac is not None:
            evidence_meta["src_mac"] = src_mac
        if dst_mac is not None:
            evidence_meta["dst_mac"] = dst_mac

        try:
            if not validate_15d_vector(vector):
                # Degraded / invalid input shape handling
                clean = sanitize_15d_vector(vector)
                if not any(clean):
                    return DetectorResult(
                        detector=DetectorType.SSL,
                        timestamp=ts,
                        health=DetectorHealth.ERROR,
                        decision=DetectionDecision.NONE,
                        confidence=None,
                        evidence={**evidence_meta, "availability": "UNAVAILABLE", "reason": "invalid_15d_vector"},
                        error_message="Invalid 15-D vector input",
                    )
            else:
                clean = list(vector)

            if not self.autoencoder.is_fitted or not self.calibrator.is_calibrated:
                return DetectorResult(
                    detector=DetectorType.SSL,
                    timestamp=ts,
                    health=DetectorHealth.ERROR,
                    decision=DetectionDecision.NONE,
                    confidence=None,
                    evidence={**evidence_meta, "availability": "UNAVAILABLE", "reason": "model_not_trained_or_calibrated"},
                    error_message="SSL detector model is not trained or calibrated",
                )

            # Score using SSLScorer (MSE reconstruction score)
            scored = self.scorer.score_vector(clean)

            decision = scored["decision"]
            conf = float(scored["confidence"])
            score = float(scored["score"])
            norm_thresh = float(scored["normal_threshold"])
            attack_thresh = float(scored["attack_threshold"])

            evidence_meta.update(
                {
                    "mse_score": score,
                    "normal_threshold": norm_thresh,
                    "attack_threshold": attack_thresh,
                    "is_zero_day_candidate": decision in (DetectionDecision.SUSPICIOUS, DetectionDecision.ATTACK),
                    "reconstruction_loss": score,
                }
            )

            attack_hint = "ZERO_DAY_ANOMALY" if decision is DetectionDecision.ATTACK else None

            res = DetectorResult(
                detector=DetectorType.SSL,
                timestamp=ts,
                health=DetectorHealth.SUCCESS,
                decision=decision,
                confidence=conf,
                score=score,
                threshold=attack_thresh,
                attack_hint=attack_hint,
                evidence=evidence_meta,
            )
            self.ssl_logger.log_result(res)
            return res

        except Exception as exc:
            logger.error("[SSLZeroDayDetector.predict_result] Fail-safe error:\n%s", traceback.format_exc())
            return DetectorResult(
                detector=DetectorType.SSL,
                timestamp=ts,
                health=DetectorHealth.ERROR,
                decision=DetectionDecision.NONE,
                confidence=None,
                evidence={**evidence_meta, "availability": "UNAVAILABLE", "reason": f"detector_error:{exc}"},
                error_message=str(exc),
            )

    def predict(self, vector: Sequence[float]) -> Dict[str, Any]:
        """
        Legacy dict-compatible prediction interface.
        """
        res = self.predict_result(vector)
        return {
            "status": res.decision.value,
            "confidence": (res.confidence or 0.0) * 100.0,
            "mse_score": res.score or 0.0,
            "threshold": res.threshold or 0.0,
            "health": res.health.value,
            "source": "ssl",
            "is_trained": self.autoencoder.is_fitted,
        }

    def save_models(self, models_dir: Optional[str] = None) -> None:
        """Persist model and threshold calibrator state."""
        target_dir = models_dir or self.models_dir
        os.makedirs(target_dir, exist_ok=True)
        m_path = os.path.join(target_dir, "ssl_autoencoder.pkl")
        t_path = os.path.join(target_dir, "ssl_threshold.pkl")
        self.autoencoder.save(m_path)
        self.calibrator.save(t_path)

    def load_models(self, models_dir: Optional[str] = None) -> bool:
        """Load model and threshold calibrator from disk."""
        target_dir = models_dir or self.models_dir
        m_path = os.path.join(target_dir, "ssl_autoencoder.pkl")
        t_path = os.path.join(target_dir, "ssl_threshold.pkl")

        if not os.path.exists(m_path) or not os.path.exists(t_path):
            return False

        try:
            self.autoencoder = SSLAutoencoder.load(m_path)
            self.calibrator = SSLThresholdCalibrator.load(t_path)
            self.scorer = SSLScorer(self.autoencoder, self.calibrator)
            self.trainer = SSLTrainer(self.autoencoder, self.calibrator)
            logger.info("[SSLZeroDayDetector] Successfully loaded SSL models from %s", target_dir)
            return True
        except Exception:
            logger.warning("[SSLZeroDayDetector] Could not load saved models from %s", target_dir)
            return False

    def _try_load_models(self) -> None:
        self.load_models()

    @property
    def is_ready(self) -> bool:
        return self.autoencoder.is_fitted and self.calibrator.is_calibrated
