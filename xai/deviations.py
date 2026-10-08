"""Heuristic feature-deviation analysis vs NORMAL_RANGES (INFERRED)."""

from __future__ import annotations

from typing import List, Sequence

from ml_models.explainer import FEATURE_DESCRIPTIONS, NORMAL_RANGES
from ml_models.feature_builder import FEATURE_NAMES
from xai.models import AttributionScope, EvidenceKind, FeatureAttribution


def find_anomalous_features(
    vector: Sequence[float],
    *,
    max_features: int = 10,
) -> List[FeatureAttribution]:
    """
    Compare raw feature values to static NORMAL_RANGES.

    Marked INFERRED: ranges are research heuristics, not model-computed
    attributions and not live baselines from R3/R9.
    """
    anomalous: List[FeatureAttribution] = []
    for i, name in enumerate(FEATURE_NAMES):
        if i >= len(vector):
            break
        lo_hi = NORMAL_RANGES.get(name)
        if not lo_hi:
            continue
        lo, hi = lo_hi
        value = float(vector[i])
        _desc, note = FEATURE_DESCRIPTIONS.get(name, ("", ""))
        if value < lo:
            anomalous.append(
                FeatureAttribution(
                    feature=name,
                    value=round(value, 6),
                    deviation=f"BELOW heuristic_normal ({value:.4f} < {lo})",
                    note=note,
                    evidence_kind=EvidenceKind.INFERRED.value,
                    scope=AttributionScope.HEURISTIC_DEVIATION.value,
                )
            )
        elif value > hi:
            anomalous.append(
                FeatureAttribution(
                    feature=name,
                    value=round(value, 6),
                    deviation=f"ABOVE heuristic_normal ({value:.4f} > {hi})",
                    note=note,
                    evidence_kind=EvidenceKind.INFERRED.value,
                    scope=AttributionScope.HEURISTIC_DEVIATION.value,
                )
            )
    return anomalous[: max(0, int(max_features))]
