"""
R6.3 — FusedDecision → legacy R7 verification payload.

R7 continues to consume prediction/explanation dicts via VerificationInput.
This adapter is the only bridge; R7 does not import fusion internals.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from shared_contracts.enums import DetectionDecision
from shared_contracts.models import FusedDecision


def fused_decision_to_r7_payload(
    fused: FusedDecision,
    *,
    base_explanation: Optional[Dict[str, Any]] = None,
    attack_hint: Optional[str] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Convert FusedDecision → (prediction, explanation) for run_verified_mitigation.

    Confidence is percent 0–100 with confidence_scale=\"percent\" (R7 contract).
    source=\"r6_fusion\" so entropy confidence floor is NOT forced.
    """
    decision = fused.decision
    if decision is DetectionDecision.ALERT:
        status = DetectionDecision.ATTACK.value
    elif decision in (
        DetectionDecision.ATTACK,
        DetectionDecision.SUSPICIOUS,
        DetectionDecision.NORMAL,
        DetectionDecision.WARNING,
    ):
        status = (
            DetectionDecision.SUSPICIOUS.value
            if decision is DetectionDecision.WARNING
            else decision.value
        )
    else:
        # NONE / UNKNOWN / DRIFT / NOISE → non-actuating
        status = DetectionDecision.NORMAL.value

    conf_unit = float(fused.confidence) if fused.confidence is not None else 0.0
    conf_unit = max(0.0, min(1.0, conf_unit))
    conf_percent = conf_unit * 100.0

    hint = attack_hint
    if not hint and isinstance(base_explanation, dict):
        hint = base_explanation.get("attack_type_hint")
    if not hint:
        hint = "UNKNOWN"

    prediction: Dict[str, Any] = {
        "status": status,
        "confidence": conf_percent,
        "confidence_scale": "percent",
        "source": "r6_fusion",
        "fusion_id": fused.fusion_id,
        "disagreement": bool(fused.disagreement),
        "event_id": fused.event_id,
    }

    explanation: Dict[str, Any] = {
        "attack_type_hint": str(hint),
        "summary": (fused.reason or "")[:240],
        "fusion_id": fused.fusion_id,
        "participating": list(fused.participating or []),
        "disagreement": bool(fused.disagreement),
        "r6_decision": fused.decision.value,
        "r6_confidence_unit": conf_unit,
    }
    if isinstance(base_explanation, dict):
        for key in ("top_features", "entropy_conf", "rate_conf", "max_packet_rate"):
            if key in base_explanation and base_explanation[key] is not None:
                explanation[key] = base_explanation[key]

    return prediction, explanation


def fused_should_enter_verification(fused: FusedDecision) -> bool:
    """Only ATTACK/SUSPICIOUS (and mapped WARNING/ALERT) enter the R7 gate."""
    return fused.decision in (
        DetectionDecision.ATTACK,
        DetectionDecision.SUSPICIOUS,
        DetectionDecision.ALERT,
        DetectionDecision.WARNING,
    )
