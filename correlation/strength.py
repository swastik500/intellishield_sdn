"""
R4.2 signal strength extraction (deterministic, no ML).

Maps SignalEvent → strength ∈ [0, 1] for fusion, or None if unsuitable.
Missing / unsuitable → omit from numeric fusion (not zero-penalty).
"""

from __future__ import annotations

from typing import Any, Optional, Tuple

from correlation.models import SignalEvent

# Ordered anomalousness for categorical security statuses.
_STATUS_STRENGTH = {
    "NORMAL": 0.0,
    "NONE": 0.0,
    "NOISE": 0.05,
    "UNKNOWN": 0.15,
    "WARNING": 0.45,
    "SUSPICIOUS": 0.65,
    "DRIFT": 0.55,
    "ALERT": 0.85,
    "ATTACK": 1.0,
    "VERIFIED": 0.80,
    "REJECTED": 0.20,
    "INELIGIBLE": 0.10,
    "PENDING": 0.25,
    "BLOCK": 0.75,
    "UNBLOCK": 0.15,
    "INFO": 0.20,
    "LOW": 0.35,
    "MEDIUM": 0.55,
    "HIGH": 0.75,
    "CRITICAL": 0.95,
    "TRUE": 0.70,
    "FALSE": 0.0,
}

# Entropy-like metrics: low value ⇒ anomalous.
_LOW_IS_ANOMALOUS = frozenset(
    {
        "entropy_score",
        "src_entropy",
        "dst_entropy",
        "packet_entropy",
        "byte_entropy",
        "flow_entropy",
    }
)


def extract_strength(signal: SignalEvent) -> Tuple[Optional[float], str]:
    """
    Return (strength, method) with strength in [0,1], or (None, reason).

    Prefer ``normalized_score`` when set (caller/R4.3 may pre-normalize).
    """
    if signal.availability in ("NOT_AVAILABLE", "STALE"):
        return None, f"excluded_{signal.availability.lower()}"

    if signal.normalized_score is not None:
        s = float(signal.normalized_score)
        return _clamp01(s), "normalized_score"

    # Explicit strength in evidence (e.g. baseline-normalized rate anomaly)
    ev = signal.evidence or {}
    if "strength" in ev:
        try:
            return _clamp01(float(ev["strength"])), "evidence.strength"
        except (TypeError, ValueError):
            pass

    name = (signal.name or "").lower()
    value = signal.value

    # Boolean drift / flags
    if isinstance(value, bool):
        return (0.70 if value else 0.0), "bool"

    # Categorical strings
    if isinstance(value, str):
        key = value.strip().upper()
        if key in _STATUS_STRENGTH:
            return _STATUS_STRENGTH[key], "categorical_status"
        # Unknown string labels are not fused numerically
        return None, "unsuitable_string_label"

    # Percents (P0.1): confidence / cpu_percent style
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        v = float(value)
        unit = (signal.unit or "").lower()
        if "percent" in unit or name in ("confidence", "cpu_percent", "memory_percent"):
            # Heuristic: values > 1 treated as 0–100 percent
            if v > 1.0:
                return _clamp01(v / 100.0), "percent_to_unit"
            return _clamp01(v), "unit_confidence"

        if name in _LOW_IS_ANOMALOUS:
            return _clamp01(1.0 - v), "entropy_invert"

        # Already unit-interval scores (iso_score, dt_confidence, rca_confidence)
        if 0.0 <= v <= 1.0 and name.endswith(("score", "confidence", "iso_score")):
            return _clamp01(v), "unit_score"

        # Baseline-relative if evidence provides baseline
        if "baseline" in ev:
            try:
                b = float(ev["baseline"])
                if b > 0:
                    # Excess over baseline, soft-capped
                    excess = max(0.0, (v - b) / b)
                    return _clamp01(min(1.0, excess / 2.0)), "baseline_relative"
            except (TypeError, ValueError):
                pass

        # Raw rates/counts without baseline: unsuitable for numeric fusion
        return None, "requires_baseline"

    # Lists / dicts (feature vectors, narratives)
    return None, "not_suitable_numeric_fusion"


def apply_health(strength: float, signal: SignalEvent, degraded_factor: float) -> float:
    if signal.availability == "DEGRADED":
        return _clamp01(strength * float(degraded_factor))
    return _clamp01(strength)


def _clamp01(x: float) -> float:
    if x != x:  # NaN
        return 0.0
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)
