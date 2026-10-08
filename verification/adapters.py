"""
Legacy ↔ VerificationEngine adapters (R7.2).

Maps existing ML/entropy dict payloads into VerificationInput / DetectionEvent
without changing production runtime behaviour.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

from shared_contracts.enums import (
    DetectionDecision,
    DetectorHealth,
    DetectorType,
    parse_detection_decision,
)
from shared_contracts.models import DetectionEvent, DetectorResult, new_id
from shared_contracts.timeutil import utc_now
from verification.engine import VerificationInput


def confidence_to_percent(
    value: Any,
    *,
    scale: str = "percent",
) -> float:
    """
    Normalize confidence at the adapter boundary.

    scale:
      - \"percent\" (default, production ML/entropy): treat value as 0–100
      - \"unit\": treat value as 0–1 and convert to percent

    Non-finite / invalid → 0.0 (fail closed). Does not invent scale from
    magnitude alone (avoids silent P0.1-style mis-scaling).
    """
    try:
        conf = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(conf):
        return 0.0
    if scale == "unit":
        if conf < 0.0:
            return 0.0
        if conf > 1.0:
            # Already looks like percent; accept defensively
            return conf
        return conf * 100.0
    # percent
    return conf


def confidence_to_unit(percent: float) -> float:
    """Convert percent confidence to FOUNDATION [0, 1] unit interval."""
    try:
        p = float(percent)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(p):
        return 0.0
    return max(0.0, min(1.0, p / 100.0))


def resolve_confidence_scale(prediction: Dict[str, Any]) -> str:
    """
    Explicit scale from prediction metadata only.

    Recognises prediction[\"confidence_scale\"] in {\"percent\", \"unit\"}.
    Defaults to percent (repository production path).
    """
    scale = str(prediction.get("confidence_scale", "percent")).lower()
    if scale in ("unit", "normalized", "fraction"):
        return "unit"
    return "percent"


def normalize_prediction_confidence(prediction: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a shallow copy of prediction with confidence as percent 0–100.

    Original dict is not mutated.
    """
    out = dict(prediction or {})
    scale = resolve_confidence_scale(out)
    out["confidence"] = confidence_to_percent(
        out.get("confidence", 0.0), scale=scale,
    )
    out["confidence_scale"] = "percent"
    return out


def map_status_to_decision(status: Any) -> DetectionDecision:
    return parse_detection_decision(status)


def detector_type_from_prediction(prediction: Dict[str, Any]) -> DetectorType:
    source = str((prediction or {}).get("source", "ml")).lower()
    if source == "entropy":
        return DetectorType.ENTROPY
    if source == "ssl":
        return DetectorType.SSL
    return DetectorType.ML


def prediction_to_detector_result(
    prediction: Dict[str, Any],
    explanation: Optional[Dict[str, Any]] = None,
) -> DetectorResult:
    """Map one legacy prediction dict → DetectorResult."""
    pred = normalize_prediction_confidence(prediction or {})
    explanation = explanation or {}
    percent = float(pred.get("confidence", 0.0) or 0.0)
    return DetectorResult(
        detector=detector_type_from_prediction(pred),
        timestamp=utc_now(),
        health=DetectorHealth.SUCCESS,
        decision=map_status_to_decision(pred.get("status")),
        confidence=confidence_to_unit(percent),
        score=percent,
        attack_hint=str(
            explanation.get("attack_type_hint")
            or pred.get("attack_type_hint")
            or ""
        )
        or None,
        evidence={
            "source": str(pred.get("source", "ml")),
            "status": str(pred.get("status", "NORMAL")),
        },
    )


def build_detection_event(
    *,
    dpid: int,
    prediction: Dict[str, Any],
    explanation: Optional[Dict[str, Any]] = None,
    src_mac: Optional[str] = None,
    dst_mac: Optional[str] = None,
    event_id: Optional[str] = None,
    extra_results: Optional[List[DetectorResult]] = None,
) -> DetectionEvent:
    """Build a DetectionEvent from legacy ML/entropy dicts."""
    primary = prediction_to_detector_result(prediction, explanation)
    results = [primary]
    if extra_results:
        results.extend(extra_results)
    return DetectionEvent(
        event_id=event_id or new_id(),
        timestamp=utc_now(),
        switch_id=int(dpid),
        src_mac=src_mac,
        dst_mac=dst_mac,
        detector_results=results,
        context={
            "source": str((prediction or {}).get("source", "ml")),
            "status": str((prediction or {}).get("status", "NORMAL")),
        },
    )


def build_verification_input(
    *,
    dpid: int,
    prediction: Dict[str, Any],
    explanation: Dict[str, Any],
    flow_features: List[dict],
    warmup_cycles_done: int,
    attack_streak: int,
    event_id: Optional[str] = None,
    min_confidence_percent: Optional[float] = None,
    force_entropy_confidence_floor: Optional[bool] = None,
) -> VerificationInput:
    """
    Bridge legacy monitor payloads into VerificationInput.

    Confidence is normalized to percent. Entropy source forces static floor
    unless explicitly overridden.
    """
    pred = normalize_prediction_confidence(prediction or {})
    explanation = dict(explanation or {})
    source = str(pred.get("source", "ml")).lower()
    entropy_floor = (
        force_entropy_confidence_floor
        if force_entropy_confidence_floor is not None
        else source == "entropy"
    )
    return VerificationInput(
        dpid=int(dpid),
        prediction=pred,
        explanation=explanation,
        flow_features=list(flow_features or []),
        warmup_cycles_done=int(warmup_cycles_done),
        attack_streak=int(attack_streak),
        event_id=event_id,
        min_confidence_percent=min_confidence_percent,
        force_entropy_confidence_floor=bool(entropy_floor),
    )
