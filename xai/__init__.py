"""
IntelliShield XAI package (Requirement R5).

R5.1: Prediction explanation core (native Decision Tree path + evidence tagging).
R5.2: RootCauseEngine lives in sibling package ``rca/`` (not here).
"""

from xai.config import XAIConfig
from xai.engine import XAIEngine
from xai.faithfulness import faithfulness_rate, verify_path_against_model
from xai.models import (
    AttributionScope,
    DecisionPathStep,
    EvidenceKind,
    ExplanationMethod,
    ExplanationStatus,
    FeatureAttribution,
    PredictionExplanation,
)
from xai.legacy_bridge import explanation_to_legacy_dict

__all__ = [
    "AttributionScope",
    "XAIConfig",
    "XAIEngine",
    "DecisionPathStep",
    "EvidenceKind",
    "ExplanationMethod",
    "ExplanationStatus",
    "FeatureAttribution",
    "PredictionExplanation",
    "explanation_to_legacy_dict",
    "faithfulness_rate",
    "verify_path_against_model",
]
