"""
Structured logger for SSL Zero-Day detector events and zero-day evaluation reports.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, Optional, Sequence

from shared_contracts.models import DetectorResult
from shared_contracts.timeutil import utc_now

logger = logging.getLogger("intellishield.ssl_zero_day")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_LOGS_DIR = os.path.join(_BASE_DIR, "..", "logs")
SSL_LOG_PATH = os.path.join(_LOGS_DIR, "ssl_zero_day_detections.log")


class SSLLogger:
    """Handles logging and audit record persistence for SSL zero-day detection events."""

    def __init__(self, log_filepath: Optional[str] = None) -> None:
        self.log_filepath = log_filepath or SSL_LOG_PATH
        os.makedirs(os.path.dirname(os.path.abspath(self.log_filepath)), exist_ok=True)

    def log_result(
        self,
        result: DetectorResult,
        extra_meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a DetectorResult(DetectorType.SSL) event."""
        payload = {
            "timestamp": result.timestamp.isoformat(),
            "detector": result.detector.value,
            "health": result.health.value,
            "decision": result.decision.value,
            "confidence": result.confidence,
            "score": result.score,
            "threshold": result.threshold,
            "evidence": result.evidence,
            "error_message": result.error_message,
        }
        if extra_meta:
            payload["extra"] = extra_meta

        logger.info(
            "[SSL Zero-Day] decision=%s score=%.6f threshold=%.6f confidence=%s health=%s",
            result.decision.value,
            result.score or 0.0,
            result.threshold or 0.0,
            f"{result.confidence:.4f}" if result.confidence is not None else "None",
            result.health.value,
        )

        try:
            with open(self.log_filepath, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")
        except Exception as exc:  # noqa: BLE001
            logger.debug("[SSLLogger] Write failed: %s", exc)

    def log_evaluation_report(self, metrics: Dict[str, Any]) -> None:
        """Log zero-day evaluation metrics (Detection Rate, FPR, latency, score stats)."""
        logger.info("==================================================")
        logger.info("       SSL Zero-Day Anomaly Detection Report      ")
        logger.info("==================================================")
        logger.info("Detection Rate (Recall) : %.4f (%.2f%%)", metrics.get("detection_rate", 0.0), metrics.get("detection_rate", 0.0) * 100)
        logger.info("False Positive Rate     : %.4f (%.2f%%)", metrics.get("false_positive_rate", 0.0), metrics.get("false_positive_rate", 0.0) * 100)
        logger.info("Mean Latency (sec)      : %.6f s", metrics.get("mean_latency_sec", 0.0))
        
        normal_stats = metrics.get("normal_score_stats", {})
        attack_stats = metrics.get("attack_score_stats", {})
        logger.info("Normal MSE Score  [mean: %.6f, std: %.6f, max: %.6f]", normal_stats.get("mean", 0.0), normal_stats.get("std", 0.0), normal_stats.get("max", 0.0))
        logger.info("Attack-X MSE Score[mean: %.6f, std: %.6f, min: %.6f]", attack_stats.get("mean", 0.0), attack_stats.get("std", 0.0), attack_stats.get("min", 0.0))
        logger.info("==================================================")
