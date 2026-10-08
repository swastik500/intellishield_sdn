"""
Online AutoML Package for IntelliShield SDN.

Provides controlled online model retraining, drift/performance triggers,
candidate suite training & evaluation, champion selection, model versioning,
deployment, and automated rollback management.
"""

from online_automl.candidates import AutoMLCandidate, build_candidate_suite
from online_automl.drift_trigger import AutoMLTriggerManager
from online_automl.evaluator import CandidateEvaluator, CandidateValidationPolicy
from online_automl.logger import AutoMLLogger
from online_automl.registry import AutoMLRegistry
from online_automl.selector import ChampionSelector
from online_automl.service import OnlineAutoMLService, automl_service

__all__ = [
    "AutoMLCandidate",
    "build_candidate_suite",
    "AutoMLTriggerManager",
    "CandidateEvaluator",
    "CandidateValidationPolicy",
    "ChampionSelector",
    "AutoMLRegistry",
    "AutoMLLogger",
    "OnlineAutoMLService",
    "automl_service",
]
