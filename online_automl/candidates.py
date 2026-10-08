"""
Candidate model definitions and wrappers for Online AutoML.

Provides supervised (DecisionTree, RandomForest, ExtraTrees) and unsupervised
(IsolationForest, OneClassSVM) model candidate architectures operating on
the repository's 15-dimensional feature schema.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, IsolationForest, RandomForestClassifier
from sklearn.linear_model import SGDOneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from shared_contracts.enums import CandidateStatus, ModelStatus
from shared_contracts.models import ModelCandidate, ModelVersion, new_id
from shared_contracts.timeutil import utc_now
from ml_models.feature_builder import FEATURE_NAMES

logger = logging.getLogger("intellishield.online_automl.candidates")

N_FEATURES = len(FEATURE_NAMES)  # 15


def sanitize_vector(vec: List[float]) -> List[float]:
    """Sanitize vector to 15 finite floats."""
    out = []
    for i in range(N_FEATURES):
        if i < len(vec):
            try:
                v = float(vec[i])
                out.append(v if np.isfinite(v) else 0.0)
            except (TypeError, ValueError):
                out.append(0.0)
        else:
            out.append(0.0)
    return out


class AutoMLCandidate:
    """
    Wrapper around a scikit-learn candidate estimator for Online AutoML.
    """

    def __init__(
        self,
        algorithm_name: str,
        estimator: Any,
        model_type: str = "supervised",
        candidate_id: Optional[str] = None,
        parent_model_id: Optional[str] = None,
    ) -> None:
        self.candidate_id = candidate_id or f"cand_{uuid.uuid4().hex[:8]}"
        self.algorithm_name = algorithm_name
        self.estimator = estimator
        self.model_type = model_type  # "supervised" or "unsupervised"
        self.parent_model_id = parent_model_id
        self.scaler = StandardScaler()
        self.status = CandidateStatus.PENDING
        self.metrics: Dict[str, Any] = {}
        self.fit_time_sec: float = 0.0
        self.model_id = f"mod_{algorithm_name.lower().replace(' ', '_')}_{uuid.uuid4().hex[:6]}"
        self.created_at = utc_now()

    def fit(self, X: Union[List[List[float]], np.ndarray], y: Optional[Union[List[int], np.ndarray]] = None) -> AutoMLCandidate:
        """
        Fit scaler and estimator on training samples.
        """
        self.status = CandidateStatus.TRAINING
        start = time.perf_counter()
        X_clean = np.array([sanitize_vector(v) for v in X], dtype=float)

        X_scaled = self.scaler.fit_transform(X_clean)

        if self.model_type == "supervised":
            if y is None or len(y) != len(X):
                raise ValueError("Supervised training requires matching labels y")
            y_clean = np.array(y, dtype=int)
            self.estimator.fit(X_scaled, y_clean)
        else:
            # Unsupervised anomaly detection (IsolationForest, OneClassSVM)
            if y is not None:
                # Fit only on normal samples if labels are provided
                normal_idx = np.where(np.array(y) == 0)[0]
                if len(normal_idx) > 10:
                    X_scaled = X_scaled[normal_idx]
            self.estimator.fit(X_scaled)

        self.fit_time_sec = time.perf_counter() - start
        self.status = CandidateStatus.READY
        logger.info("[AutoMLCandidate] Fit %s in %.4fs (%d samples)", self.algorithm_name, self.fit_time_sec, len(X_clean))
        return self

    def predict(self, X: Union[List[List[float]], np.ndarray]) -> np.ndarray:
        """
        Predict binary labels (0 = NORMAL, 1 = ATTACK).
        """
        X_clean = np.array([sanitize_vector(v) for v in X], dtype=float)
        X_scaled = self.scaler.transform(X_clean)

        if self.model_type == "supervised":
            return self.estimator.predict(X_scaled)
        else:
            # IsolationForest / OneClassSVM output: 1 = normal, -1 = anomaly
            raw_pred = self.estimator.predict(X_scaled)
            return np.where(raw_pred == -1, 1, 0)

    def predict_proba(self, X: Union[List[List[float]], np.ndarray]) -> np.ndarray:
        """
        Predict probability of ATTACK (class 1).
        """
        X_clean = np.array([sanitize_vector(v) for v in X], dtype=float)
        X_scaled = self.scaler.transform(X_clean)

        if hasattr(self.estimator, "predict_proba"):
            probs = self.estimator.predict_proba(X_scaled)
            if probs.shape[1] > 1:
                return probs[:, 1]
            return probs[:, 0]
        elif hasattr(self.estimator, "decision_function"):
            scores = self.estimator.decision_function(X_scaled)
            # Normalize decision_function scores to [0, 1]
            # Invert: lower decision score -> higher anomaly probability
            min_s, max_s = np.min(scores), np.max(scores)
            if max_s == min_s:
                return np.zeros(len(scores))
            norm = (scores - min_s) / (max_s - min_s + 1e-6)
            return 1.0 - norm
        else:
            preds = self.predict(X)
            return preds.astype(float)

    def to_contracts(self, version_str: str = "1.0.0") -> Tuple[ModelVersion, ModelCandidate]:
        """
        Convert to shared_contracts.models.ModelVersion and ModelCandidate.
        """
        mv_status = ModelStatus.CHAMPION if self.status == CandidateStatus.PROMOTED else (
            ModelStatus.FAILED if self.status == CandidateStatus.REJECTED else ModelStatus.CANDIDATE
        )
        mv = ModelVersion(
            model_id=self.model_id,
            version=version_str,
            algorithm=self.algorithm_name,
            created_at=self.created_at,
            artifact_uri=f"logs/models/{self.model_id}.pkl",
            feature_schema="FEATURE_NAMES_v1",
            metrics=self.metrics,
            status=mv_status,
        )
        mc = ModelCandidate(
            candidate_id=self.candidate_id,
            model=mv,
            status=self.status,
            created_at=self.created_at,
            parent_model_id=self.parent_model_id,
            notes=f"AutoML candidate: {self.algorithm_name} (type: {self.model_type})",
        )
        return mv, mc


def build_candidate_suite() -> List[AutoMLCandidate]:
    """
    Factory function building the candidate model suite:
      1. Decision Tree
      2. Random Forest
      3. Extra Trees
      4. Isolation Forest (unsupervised)
      5. SGD One-Class SVM (unsupervised second anomaly model)
    """
    suite = [
        AutoMLCandidate(
            algorithm_name="Decision Tree",
            estimator=DecisionTreeClassifier(max_depth=8, random_state=42, class_weight="balanced"),
            model_type="supervised",
        ),
        AutoMLCandidate(
            algorithm_name="Random Forest",
            estimator=RandomForestClassifier(n_estimators=50, max_depth=8, random_state=42, class_weight="balanced"),
            model_type="supervised",
        ),
        AutoMLCandidate(
            algorithm_name="Extra Trees",
            estimator=ExtraTreesClassifier(n_estimators=50, max_depth=8, random_state=42, class_weight="balanced"),
            model_type="supervised",
        ),
        AutoMLCandidate(
            algorithm_name="Isolation Forest",
            estimator=IsolationForest(n_estimators=50, contamination=0.1, random_state=42),
            model_type="unsupervised",
        ),
        AutoMLCandidate(
            algorithm_name="SGD One-Class SVM",
            estimator=SGDOneClassSVM(nu=0.1, random_state=42),
            model_type="unsupervised",
        ),
    ]
    return suite
