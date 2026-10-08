"""
Model registry and artifact manager for Online AutoML.

Manages model versions, champion promotion, artifact serialization to disk,
and automated rollback if live deployment validation fails.
Reuses shared_contracts.models: ModelVersion, ModelCandidate, ValidationResult.
"""

from __future__ import annotations

import json
import logging
import os
import pickle
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from shared_contracts.enums import CandidateStatus, ModelStatus
from shared_contracts.models import ModelCandidate, ModelVersion, ValidationResult
from shared_contracts.serialize import from_dict, to_dict
from online_automl.candidates import AutoMLCandidate

logger = logging.getLogger("intellishield.online_automl.registry")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_LOGS_DIR = os.path.join(_BASE_DIR, "..", "logs")
_MODELS_DIR = os.path.join(_LOGS_DIR, "models")
REGISTRY_JSON_PATH = os.path.join(_LOGS_DIR, "automl_registry.json")
CHAMPION_PKL_PATH = os.path.join(_MODELS_DIR, "automl_champion.pkl")


class AutoMLRegistry:
    """
    Model Registry for tracking champion models, candidate history, and rollback state.
    """

    def __init__(self, registry_file: Optional[str] = None, champion_pkl: Optional[str] = None) -> None:
        self.registry_file = registry_file or REGISTRY_JSON_PATH
        self.champion_pkl = champion_pkl or CHAMPION_PKL_PATH
        os.makedirs(os.path.dirname(os.path.abspath(self.registry_file)), exist_ok=True)
        os.makedirs(os.path.dirname(os.path.abspath(self.champion_pkl)), exist_ok=True)

        self.current_champion: Optional[AutoMLCandidate] = None
        self.previous_champion: Optional[AutoMLCandidate] = None
        self.version_history: List[Dict[str, Any]] = []
        self.last_validation: Optional[ValidationResult] = None
        self.last_rollback_reason: Optional[str] = None
        self._load_state()

    def register_champion(self, candidate: AutoMLCandidate, validation_res: Optional[ValidationResult] = None) -> None:
        """
        Promote candidate to Champion, save artifact, and preserve previous champion for rollback.
        """
        if self.current_champion is not None:
            # Shift current champion to rollback stack
            self.previous_champion = self.current_champion
            self.previous_champion.status = CandidateStatus.READY

        self.current_champion = candidate
        self.current_champion.status = CandidateStatus.PROMOTED
        self.last_validation = validation_res

        # Save champion artifact pickle
        self._save_champion_artifact(candidate)

        # Log to version history
        mv, mc = candidate.to_contracts()
        hist_entry = {
            "version_id": mv.model_id,
            "algorithm": candidate.algorithm_name,
            "promoted_at": datetime.now().isoformat(),
            "metrics": candidate.metrics,
            "status": "CHAMPION",
            "candidate_id": candidate.candidate_id,
        }
        self.version_history.append(hist_entry)
        self._save_state()

        logger.info("[AutoMLRegistry] Registered new Champion: %s (%s)", candidate.algorithm_name, candidate.candidate_id)

    def rollback(self) -> Tuple[Optional[AutoMLCandidate], str]:
        """
        Rollback current champion to previous champion.
        """
        if self.previous_champion is None:
            reason = "Rollback failed: No previous champion available in history"
            logger.warning("[AutoMLRegistry] %s", reason)
            return None, reason

        rolled_back = self.current_champion
        if rolled_back is not None:
            rolled_back.status = CandidateStatus.ROLLED_BACK

        # Restore previous champion
        self.current_champion = self.previous_champion
        self.current_champion.status = CandidateStatus.PROMOTED
        self.previous_champion = None

        # Re-save champion artifact
        self._save_champion_artifact(self.current_champion)

        reason = f"Rolled back from {rolled_back.algorithm_name if rolled_back else 'unknown'} to {self.current_champion.algorithm_name}"
        self.last_rollback_reason = reason
        self._save_state()

        logger.info("[AutoMLRegistry] %s", reason)
        return self.current_champion, reason

    def _save_champion_artifact(self, candidate: AutoMLCandidate) -> None:
        """Pickle candidate model & scaler to disk."""
        try:
            artifact = {
                "algorithm": candidate.algorithm_name,
                "model_type": candidate.model_type,
                "model_id": candidate.model_id,
                "candidate_id": candidate.candidate_id,
                "metrics": candidate.metrics,
                "scaler": candidate.scaler,
                "estimator": candidate.estimator,
            }
            with open(self.champion_pkl, "wb") as f:
                pickle.dump(artifact, f)
            logger.info("[AutoMLRegistry] Saved champion pickle to %s", self.champion_pkl)
        except Exception as exc:
            logger.error("[AutoMLRegistry] Failed to save champion pickle: %s", exc)

    def _save_state(self) -> None:
        """Save JSON metadata registry state."""
        try:
            data = {
                "current_champion": self.current_champion.algorithm_name if self.current_champion else None,
                "current_champion_id": self.current_champion.candidate_id if self.current_champion else None,
                "current_champion_metrics": self.current_champion.metrics if self.current_champion else {},
                "previous_champion_id": self.previous_champion.candidate_id if self.previous_champion else None,
                "version_history": self.version_history,
                "last_rollback_reason": self.last_rollback_reason,
            }
            with open(self.registry_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            logger.error("[AutoMLRegistry] Failed to save registry JSON: %s", exc)

    def _load_state(self) -> None:
        """Load JSON metadata registry state on init."""
        if not os.path.exists(self.registry_file):
            return
        try:
            with open(self.registry_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.version_history = data.get("version_history", [])
            self.last_rollback_reason = data.get("last_rollback_reason")
        except Exception as exc:
            logger.warning("[AutoMLRegistry] Could not load registry state: %s", exc)
