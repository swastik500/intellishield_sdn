"""
Normalization design for R4 (documentation + classification only in R4.1).

R4.2 will apply transforms; R4.1 only classifies how each signal becomes
comparable evidence. Do not invent magic weights here.
"""

from __future__ import annotations

from enum import Enum


class NormalizationClass(str, Enum):
    """How a signal can become comparable evidence for R4.2."""

    ALREADY_NORMALIZED = "ALREADY_NORMALIZED"  # e.g. entropy [0,1], iso_score
    REQUIRES_BASELINE = "REQUIRES_BASELINE"  # rates vs rolling baseline / z-score
    BINARY_CATEGORICAL = "BINARY_CATEGORICAL"  # status enums, drift bool
    THRESHOLD_RELATIVE = "THRESHOLD_RELATIVE"  # value vs configured threshold
    UNIT_INTERVAL_FROM_PERCENT = "UNIT_INTERVAL_FROM_PERCENT"  # 0–100 → [0,1] (P0.1)
    NOT_SUITABLE_NUMERIC_FUSION = "NOT_SUITABLE_NUMERIC_FUSION"  # narrative, vectors, GT


# Guidance notes for R4.2 (not executed in R4.1).
NORMALIZATION_NOTES: dict[str, str] = {
    NormalizationClass.ALREADY_NORMALIZED.value: (
        "Use value as evidence score in [0,1] (or 1-value when low=anomalous, e.g. entropy)."
    ),
    NormalizationClass.REQUIRES_BASELINE.value: (
        "Do not fuse raw pkt/s or byte/s; require baseline, percentile, or log-scale map."
    ),
    NormalizationClass.BINARY_CATEGORICAL.value: (
        "Map statuses to ordered evidence ranks (e.g. NORMAL=0 … ATTACK=1) explicitly."
    ),
    NormalizationClass.THRESHOLD_RELATIVE.value: (
        "Evidence from (value op threshold), not raw magnitude alone."
    ),
    NormalizationClass.UNIT_INTERVAL_FROM_PERCENT.value: (
        "Divide by 100; preserve P0.1 confidence semantics (never treat 94 as [0,1])."
    ),
    NormalizationClass.NOT_SUITABLE_NUMERIC_FUSION.value: (
        "Keep as structured evidence / labels only; do not average into correlation score."
    ),
}
