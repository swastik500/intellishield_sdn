"""
================================================================================
IntelliShield SDN — Phase 4: ML-Based Anomaly Detection
================================================================================

File        : ml_models/anomaly_detector.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 4 — ML Anomaly Detection

Description:
    Dual-model anomaly detection engine combining:

        1. Isolation Forest (unsupervised)
           - Detects anomalies without labelled training data
           - Ideal for zero-day / novel attack detection
           - Suitable when only normal-traffic data is available

        2. Decision Tree Classifier (supervised)
           - Trained on labelled normal + attack data from Phase 3 experiments
           - Produces NORMAL / SUSPICIOUS / ATTACK classifications
           - Fully explainable: feature importance + decision path

    Both models operate on the 15-dimensional feature vectors from
    FeatureBuilder. Each monitoring cycle produces a combined prediction
    with a confidence score and status label.

    Detection pipeline:
        Flow features + Entropy metrics
            → FeatureBuilder.build() → 15-dim vector
            → IsolationForest.predict() → anomaly score
            → DecisionTree.predict() → class label (if trained)
            → Ensemble vote → final status + confidence
            → MLLogger.log()

IEEE Relevance:
    The dual-model approach (unsupervised + supervised) enables detection
    of both known attack patterns (supervised) and novel unknown attacks
    (unsupervised). This hybrid strategy is the novelty claimed in the
    IntelliShield IEEE research contribution.

Future Integration Points:
    - [HOOK] Phase 5 → mitigation/flow_blocker.py reacts to ATTACK status
    - [HOOK] Phase 6 → HDBSCAN clusters feature vectors for profiling
    - [HOOK] Phase 7 → PPO RL adjusts decision_threshold dynamically

================================================================================
"""

import os
import logging
import traceback
import pickle
from typing import Optional, List, Tuple, Dict

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler

from ml_models.ml_utils import (
    sanitize_vector,
    validate_vector,
    label_to_str,
    anomaly_score_to_status,
    format_confidence,
    clamp,
)
from ml_models.feature_builder import FEATURE_NAMES

logger = logging.getLogger("intellishield.anomaly_detector")

# ─── Model Persistence Paths ──────────────────────────────────────────────────

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_MODELS_DIR = os.path.join(_BASE_DIR, "..", "logs", "models")

ISO_MODEL_PATH    = os.path.join(_MODELS_DIR, "isolation_forest.pkl")
DT_MODEL_PATH     = os.path.join(_MODELS_DIR, "decision_tree.pkl")
SCALER_MODEL_PATH = os.path.join(_MODELS_DIR, "scaler.pkl")

N_FEATURES = len(FEATURE_NAMES)   # 15

# ─── Detection Thresholds ────────────────────────────────────────────────────
# [HOOK] Phase 7 → PPO RL replaces these with dynamically learned thresholds

ISO_CONTAMINATION   = 0.1   # Expected fraction of anomalous samples (10%)
NORMAL_THRESHOLD    = 0.3   # Anomaly score below this → NORMAL
ATTACK_THRESHOLD    = 0.65  # Anomaly score above this → ATTACK


# ─── Anomaly Detector ─────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    IntelliShield SDN — Dual-Model ML Anomaly Detector.

    Two detection modes:
        1. Unsupervised (Isolation Forest) — always available
        2. Supervised (Decision Tree)      — available after training

    Prediction output for each monitoring cycle:
        {
            "status"        : "NORMAL" / "SUSPICIOUS" / "ATTACK",
            "confidence"    : 0.0–100.0  (float),
            "iso_score"     : float,      raw isolation forest score
            "dt_label"      : int or None, decision tree class
            "dt_confidence" : float,      DT prediction probability
            "is_trained"    : bool,       whether DT model is available
        }
    """

    def __init__(self,
                 contamination: float = ISO_CONTAMINATION,
                 auto_load: bool = True):
        """
        Args:
            contamination: IsolationForest contamination rate (0.0–0.5).
            auto_load    : If True, attempt to load saved models on init.
        """
        self.contamination = contamination
        self._scaler: Optional[StandardScaler]         = None
        self._iso:    Optional[IsolationForest]        = None
        self._dt:     Optional[DecisionTreeClassifier] = None
        self._is_iso_trained = False
        self._is_dt_trained  = False

        os.makedirs(_MODELS_DIR, exist_ok=True)

        if auto_load:
            self._try_load_models()

        logger.info("[AnomalyDetector] Initialised.")
        logger.info("  IsolationForest trained : %s", self._is_iso_trained)
        logger.info("  DecisionTree trained    : %s", self._is_dt_trained)

    # ─── Model Training ───────────────────────────────────────────────────────

    def train_isolation_forest(self,
                                X_normal: List[List[float]],
                                n_estimators: int = 100) -> bool:
        """
        Train the Isolation Forest on normal (benign) traffic feature vectors.

        Isolation Forest learns the structure of normal traffic and flags
        anything that doesn't fit as anomalous. No attack labels needed.

        Args:
            X_normal    : List of feature vectors from NORMAL traffic.
                          (Generated by FeatureBuilder during Scenario 1 runs)
            n_estimators: Number of trees (100 is standard for research).

        Returns:
            bool: True if training succeeded.
        """
        if not X_normal:
            logger.error("[train_isolation_forest] No training data provided.")
            return False

        try:
            X = np.array([sanitize_vector(v) for v in X_normal], dtype=float)

            # Fit scaler
            self._scaler = StandardScaler()
            X_scaled = self._scaler.fit_transform(X)

            # Train isolation forest
            self._iso = IsolationForest(
                n_estimators    = n_estimators,
                contamination   = self.contamination,
                random_state    = 42,
                n_jobs          = -1,
            )
            self._iso.fit(X_scaled)
            self._is_iso_trained = True

            self._save_model(self._iso,    ISO_MODEL_PATH)
            self._save_model(self._scaler, SCALER_MODEL_PATH)

            logger.info("[train_isolation_forest] Trained on %d normal samples. Saved.", len(X))
            return True

        except Exception:
            logger.error("[train_isolation_forest] %s", traceback.format_exc())
            return False

    def train_decision_tree(self,
                             X: List[List[float]],
                             y: List[int],
                             max_depth: int = 8) -> Dict:
        """
        Train the supervised Decision Tree on labelled data.

        Requires labelled samples: 0 = NORMAL, 1 = ATTACK.
        Typically trained after running Phase 3 experiments that generate
        both normal traffic (Scenario 1) and attack traffic (Scenarios 2–5).

        Args:
            X         : Feature vectors (labelled dataset).
            y         : Integer labels (0=NORMAL, 1=ATTACK).
            max_depth : Max tree depth (controls overfitting). Default 8.

        Returns:
            dict: Training metrics {accuracy, n_samples, feature_importance}
        """
        if not X or not y or len(X) != len(y):
            logger.error("[train_decision_tree] Invalid training data.")
            return {}

        try:
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import accuracy_score, classification_report

            X_arr = np.array([sanitize_vector(v) for v in X], dtype=float)
            y_arr = np.array(y)

            # Scale using existing scaler (or fit new one)
            if self._scaler is None:
                self._scaler = StandardScaler()
                X_scaled = self._scaler.fit_transform(X_arr)
                self._save_model(self._scaler, SCALER_MODEL_PATH)
            else:
                X_scaled = self._scaler.transform(X_arr)

            # Train/test split (80/20)
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, y_arr, test_size=0.2, random_state=42, stratify=y_arr
            )

            self._dt = DecisionTreeClassifier(
                max_depth    = max_depth,
                random_state = 42,
                class_weight = "balanced",   # Handle class imbalance
            )
            self._dt.fit(X_train, y_train)
            self._is_dt_trained = True

            # Evaluate
            y_pred = self._dt.predict(X_test)
            acc    = accuracy_score(y_test, y_pred)
            report = classification_report(y_test, y_pred,
                                           target_names=["NORMAL", "ATTACK"],
                                           output_dict=True)

            # Feature importance
            importance = dict(zip(
                FEATURE_NAMES,
                [round(float(v), 6) for v in self._dt.feature_importances_]
            ))
            top_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:5]

            self._save_model(self._dt, DT_MODEL_PATH)

            metrics = {
                "accuracy"          : round(acc, 4),
                "n_train"           : len(X_train),
                "n_test"            : len(X_test),
                "feature_importance": importance,
                "top_features"      : top_features,
                "report"            : report,
            }

            logger.info("[train_decision_tree] Accuracy: %.4f on %d test samples",
                        acc, len(X_test))
            logger.info("[train_decision_tree] Top features: %s", top_features)
            return metrics

        except Exception:
            logger.error("[train_decision_tree] %s", traceback.format_exc())
            return {}

    # ─── Prediction ───────────────────────────────────────────────────────────

    def predict(self, vector: List[float]) -> Dict:
        """
        Classify a single 15-dimensional feature vector.

        Always runs IsolationForest (if trained) for unsupervised detection.
        Also runs DecisionTree if supervised model is available.
        Combines both scores for a final ensemble prediction.

        Args:
            vector: 15-element feature vector from FeatureBuilder.build().

        Returns:
            dict: Detection result with keys:
                status        : "NORMAL" / "SUSPICIOUS" / "ATTACK"
                confidence    : 0.0–100.0
                iso_score     : Raw IF anomaly score (0=normal, 1=anomaly)
                dt_label      : DT prediction (0/1) or None
                dt_confidence : DT class probability
                is_trained    : Whether DT model was used
                top_features  : Top contributing features (if DT available)
        """
        result = {
            "status"        : "UNKNOWN",
            "confidence"    : 0.0,
            "iso_score"     : 0.0,
            "dt_label"      : None,
            "dt_confidence" : 0.0,
            "is_trained"    : self._is_dt_trained,
            "top_features"  : [],
        }

        try:
            vec = sanitize_vector(vector)
            if not validate_vector(vec, N_FEATURES):
                logger.warning("[predict] Invalid vector — returning UNKNOWN.")
                return result

            X = np.array([vec], dtype=float)

            # ── Isolation Forest prediction ───────────────────────────────────
            iso_score = 0.5   # Default neutral score
            if self._is_iso_trained and self._iso is not None and self._scaler is not None:
                X_scaled   = self._scaler.transform(X)
                raw_score  = self._iso.decision_function(X_scaled)[0]

                # Convert raw_score to [0, 1]:
                # IF decision_function: negative = anomaly, positive = normal
                # Invert and scale to [0, 1]
                iso_score = clamp(0.5 - raw_score, 0.0, 1.0)
                result["iso_score"] = round(float(iso_score), 4)

            # ── Decision Tree prediction ──────────────────────────────────────
            dt_confidence = 0.0
            dt_label      = None
            if self._is_dt_trained and self._dt is not None and self._scaler is not None:
                X_scaled      = self._scaler.transform(X)
                dt_label      = int(self._dt.predict(X_scaled)[0])
                proba         = self._dt.predict_proba(X_scaled)[0]
                dt_confidence = float(proba[dt_label])

                result["dt_label"]      = dt_label
                result["dt_confidence"] = round(dt_confidence, 4)

                # Top contributing features via feature importance
                importance = self._dt.feature_importances_
                top = sorted(
                    zip(FEATURE_NAMES, importance),
                    key=lambda x: x[1], reverse=True
                )[:5]
                result["top_features"] = [(n, round(float(v), 4)) for n, v in top]

            # ── Ensemble decision (DT-primary when supervised model is trained) ──
            if self._is_dt_trained and dt_label is not None:
                pkt_max = float(vec[1])   # packet_rate_max
                pkt_ent = float(vec[10])  # packet_entropy

                if dt_label == 1:
                    final_status = "ATTACK"
                    confidence = clamp(
                        max(dt_confidence, iso_score * 0.4) * 100,
                        0.0, 100.0,
                    )
                elif pkt_max >= 1000.0 and pkt_ent <= 0.30:
                    # DT false negative during obvious flood — trust traffic features
                    final_status = "ATTACK"
                    confidence = clamp(
                        max(dt_confidence, iso_score, pkt_max / 5000.0) * 100,
                        0.0, 100.0,
                    )
                elif iso_score > 0.75 and pkt_max < 100.0:
                    # IF hot on truly quiet baseline — trust DT, report NORMAL
                    final_status = "NORMAL"
                    confidence = clamp(dt_confidence * 100, 0.0, 100.0)
                elif iso_score > 0.75 and pkt_max < 500.0:
                    # Elevated but not flooding — downgrade to SUSPICIOUS, not ATTACK
                    final_status = "SUSPICIOUS"
                    confidence = clamp(iso_score * 100, 0.0, 100.0)
                else:
                    final_status = "NORMAL"
                    confidence = clamp(dt_confidence * 100, 0.0, 100.0)
            else:
                # Isolation Forest only
                final_status = anomaly_score_to_status(
                    iso_score, NORMAL_THRESHOLD, ATTACK_THRESHOLD
                )
                confidence = clamp(iso_score * 100, 0.0, 100.0)

            result["status"]     = final_status
            result["confidence"] = round(confidence, 2)

        except Exception:
            logger.error("[predict] %s", traceback.format_exc())

        return result

    # ─── Batch Predict ────────────────────────────────────────────────────────

    def predict_batch(self, vectors: List[List[float]]) -> List[Dict]:
        """
        Classify a batch of feature vectors (for offline evaluation).

        Args:
            vectors: List of 15-dim feature vectors.

        Returns:
            List of prediction result dicts.
        """
        return [self.predict(v) for v in vectors]

    # ─── Model Persistence ────────────────────────────────────────────────────

    def _save_model(self, model, path: str) -> None:
        """Pickle a model to disk."""
        try:
            with open(path, "wb") as f:
                pickle.dump(model, f)
            logger.info("[_save_model] Saved: %s", os.path.basename(path))
        except Exception:
            logger.error("[_save_model] Failed for %s:\n%s", path, traceback.format_exc())

    def _try_load_models(self) -> None:
        """Attempt to load previously saved models from disk."""
        try:
            if os.path.exists(ISO_MODEL_PATH) and os.path.exists(SCALER_MODEL_PATH):
                with open(ISO_MODEL_PATH,    "rb") as f: self._iso    = pickle.load(f)
                with open(SCALER_MODEL_PATH, "rb") as f: self._scaler = pickle.load(f)
                self._is_iso_trained = True
                logger.info("[_try_load_models] IsolationForest loaded from disk.")

            if os.path.exists(DT_MODEL_PATH):
                with open(DT_MODEL_PATH, "rb") as f: self._dt = pickle.load(f)
                self._is_dt_trained = True
                logger.info("[_try_load_models] DecisionTree loaded from disk.")
        except Exception:
            logger.warning("[_try_load_models] Could not load saved models — will train fresh.")
            self._iso = self._dt = self._scaler = None
            self._is_iso_trained = self._is_dt_trained = False

    @property
    def is_ready(self) -> bool:
        """True if at least the IsolationForest model is trained."""
        return self._is_iso_trained

    # ─── Read-only accessors (R5.1 XAI; no behaviour change) ───────────────────

    @property
    def decision_tree(self) -> Optional[DecisionTreeClassifier]:
        """Trained DecisionTreeClassifier or None (for native path XAI)."""
        return self._dt

    @property
    def scaler(self) -> Optional[StandardScaler]:
        """Fitted StandardScaler or None."""
        return self._scaler

    @property
    def is_dt_trained(self) -> bool:
        """True when supervised Decision Tree is available."""
        return bool(self._is_dt_trained)
