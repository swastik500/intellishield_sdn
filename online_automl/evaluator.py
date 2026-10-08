"""
Candidate model evaluator and gate validation for Online AutoML.

Computes F1 score, False Positive Rate (FPR), Precision, Recall, Accuracy,
and prediction latency (ms/sample) on validation datasets.
Enforces strict gate policies using shared_contracts.models.ValidationResult.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

from shared_contracts.enums import CandidateStatus, ValidationStatus
from shared_contracts.models import ValidationResult, new_id
from shared_contracts.timeutil import utc_now
from online_automl.candidates import AutoMLCandidate

logger = logging.getLogger("intellishield.online_automl.evaluator")


@dataclass(frozen=True)
class CandidateValidationPolicy:
    """Pass/fail validation policy for AutoML candidates."""

    min_f1: float = 0.75
    max_fpr: float = 0.10
    max_latency_ms: float = 15.0
    min_precision: float = 0.70
    min_recall: float = 0.70


class CandidateEvaluator:
    """
    Evaluates AutoML candidate models on validation datasets.
    """

    def __init__(self, policy: Optional[CandidateValidationPolicy] = None) -> None:
        self.policy = policy or CandidateValidationPolicy()

    def evaluate_candidate(
        self,
        candidate: AutoMLCandidate,
        X_val: Union[List[List[float]], np.ndarray],
        y_val: Union[List[int], np.ndarray],
    ) -> Tuple[Dict[str, Any], ValidationResult]:
        """
        Evaluate candidate on (X_val, y_val), calculate metrics, and check validation gate.

        Returns:
            Tuple of (metrics_dict, ValidationResult)
        """
        X_arr = np.array(X_val, dtype=float)
        y_arr = np.array(y_val, dtype=int)

        if len(X_arr) == 0 or len(y_arr) == 0 or len(X_arr) != len(y_arr):
            raise ValueError("Invalid validation data: X_val and y_val must be non-empty and matched")

        # Benchmark latency
        start_time = time.perf_counter()
        y_pred = candidate.predict(X_arr)
        total_time = time.perf_counter() - start_time
        latency_ms = (total_time / len(X_arr)) * 1000.0

        acc = float(accuracy_score(y_arr, y_pred))
        prec = float(precision_score(y_arr, y_pred, zero_division=0))
        rec = float(recall_score(y_arr, y_pred, zero_division=0))
        f1 = float(f1_score(y_arr, y_pred, zero_division=0))

        # Compute FPR = FP / (FP + TN)
        tn = int(np.sum((y_arr == 0) & (y_pred == 0)))
        fp = int(np.sum((y_arr == 0) & (y_pred == 1)))
        fn = int(np.sum((y_arr == 1) & (y_pred == 0)))
        tp = int(np.sum((y_arr == 1) & (y_pred == 1)))

        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        metrics = {
            "f1_score": round(f1, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "false_positive_rate": round(fpr, 4),
            "latency_ms": round(latency_ms, 4),
            "accuracy": round(acc, 4),
            "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "fit_time_sec": round(candidate.fit_time_sec, 4),
            "algorithm": candidate.algorithm_name,
            "model_type": candidate.model_type,
        }
        candidate.metrics = metrics

        # Gate checks against policy
        policy = self.policy
        reasons = []
        if f1 < policy.min_f1:
            reasons.append(f"F1 {f1:.4f} < min_f1 {policy.min_f1:.4f}")
        if fpr > policy.max_fpr:
            reasons.append(f"FPR {fpr:.4f} > max_fpr {policy.max_fpr:.4f}")
        if latency_ms > policy.max_latency_ms:
            reasons.append(f"Latency {latency_ms:.2f}ms > max {policy.max_latency_ms:.2f}ms")
        if prec < policy.min_precision:
            reasons.append(f"Precision {prec:.4f} < min {policy.min_precision:.4f}")

        passed = len(reasons) == 0
        v_status = ValidationStatus.PASS if passed else ValidationStatus.FAIL
        candidate.status = CandidateStatus.READY if passed else CandidateStatus.REJECTED

        val_result = ValidationResult(
            validation_id=f"val_{new_id()[:8]}",
            timestamp=utc_now(),
            status=v_status,
            model_id=candidate.model_id,
            candidate_id=candidate.candidate_id,
            metrics=metrics,
            reason="Validation passed" if passed else f"Gate failed: {'; '.join(reasons)}",
            artifact_uri=f"logs/models/{candidate.model_id}.pkl",
        )

        logger.info(
            "[CandidateEvaluator] Candidate %s (%s): status=%s F1=%.4f FPR=%.4f latency=%.3fms reason='%s'",
            candidate.algorithm_name,
            candidate.candidate_id,
            v_status.value,
            f1,
            fpr,
            latency_ms,
            val_result.reason,
        )
        return metrics, val_result
