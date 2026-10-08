"""Bridge PredictionExplanation ↔ legacy Explainer.explain() dict shape."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from xai.models import PredictionExplanation


def explanation_to_legacy_dict(expl: PredictionExplanation) -> Dict[str, Any]:
    """
    Produce a dict compatible with existing consumers of Explainer.explain().

    Keys preserved: status, confidence, anomalous_features, attack_type_hint,
    narrative, top_features, vector_summary (empty unless callers merge).
    """
    anomalous: List[Tuple] = []
    for a in expl.anomalous_features:
        anomalous.append(
            (a.feature, a.value if a.value is not None else 0.0, a.deviation or "", a.note)
        )

    top_features: List[Tuple[str, float]] = []
    for f in expl.global_feature_importances:
        if f.importance is not None:
            top_features.append((f.feature, float(f.importance)))

    return {
        "status": expl.prediction_status,
        "confidence": expl.confidence_percent
        if expl.confidence_percent is not None
        else 0.0,
        "anomalous_features": anomalous,
        "attack_type_hint": expl.attack_type_hint
        if expl.attack_type_hint not in ("NOT_AVAILABLE", "UNKNOWN")
        else expl.attack_type_hint,
        "narrative": expl.narrative,
        "top_features": top_features,
        "vector_summary": {},
        # R5.1 extensions (ignored by legacy printers if unknown)
        "xai_explanation_id": expl.explanation_id,
        "xai_method": expl.method,
        "xai_status": expl.status,
        "xai_summary": expl.summary,
        "xai_leaf_decision": expl.leaf_decision,
        "xai_model_available": expl.model_available,
        "xai_missing_evidence": list(expl.missing_evidence),
    }
