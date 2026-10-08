"""
IntelliShield Multi-Stage Verification Engine (Requirement R7).

R7.1: core engine.
R7.2: legacy adapters + golden compatibility.
R7.3: runtime helper + verification_trace (wired from flow_monitor).
"""

from verification.adapters import (
    build_detection_event,
    build_verification_input,
    confidence_to_percent,
    confidence_to_unit,
    normalize_prediction_confidence,
    prediction_to_detector_result,
)
from verification.config import VerificationConfig
from verification.confirmation_state import AttackConfirmationState
from verification.engine import VerificationEngine, VerificationInput, is_warmup_active
from verification.legacy_decision import (
    LegacyDecision,
    evaluate_legacy_decision,
    verification_matches_legacy,
)
from verification.runtime import VerifiedMitigationOutcome, run_verified_mitigation
from verification.stages import STAGE_ORDER, VerificationStage
from verification.trace import append_verification_trace, default_trace_path

__all__ = [
    "AttackConfirmationState",
    "LegacyDecision",
    "STAGE_ORDER",
    "VerificationConfig",
    "VerificationEngine",
    "VerificationInput",
    "VerificationStage",
    "VerifiedMitigationOutcome",
    "append_verification_trace",
    "build_detection_event",
    "build_verification_input",
    "confidence_to_percent",
    "confidence_to_unit",
    "default_trace_path",
    "evaluate_legacy_decision",
    "is_warmup_active",
    "normalize_prediction_confidence",
    "prediction_to_detector_result",
    "run_verified_mitigation",
    "verification_matches_legacy",
]
