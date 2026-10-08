"""
R4.2 CorrelationEngine configuration — explicit weights & thresholds.

Weights reflect independence and reliability of evidence categories,
not arbitrary magic. See IMPLEMENTED/R4_2_CORRELATION_ENGINE_CORE.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from correlation.categories import SignalCategory


def _default_category_weights() -> Dict[str, float]:
    """
    Relative category importance when present.

    Rationale:
    - DETECTION (1.00): primary security judgments (entropy/ML) on the live path.
    - DATA_PLANE (0.85): independent forwarding-plane volume/error evidence.
    - SECURITY_RESPONSE (0.70): verification/mitigation/alert confirmation
      (downstream; useful agreement, not a substitute for detectors).
    - CONTROL_PLANE (0.55): optional controller stress / policy context —
      supportive, never required.
    - DRIFT_CLUSTERING (0.50): observational ADWIN/HDBSCAN; lower trust for
      mitigation-grade correlation.
    - UNKNOWN (0.00): lab GT / unspecified — excluded from numeric fusion.
    """
    return {
        SignalCategory.DETECTION.value: 1.00,
        SignalCategory.DATA_PLANE.value: 0.85,
        SignalCategory.SECURITY_RESPONSE.value: 0.70,
        SignalCategory.CONTROL_PLANE.value: 0.55,
        SignalCategory.DRIFT_CLUSTERING.value: 0.50,
        SignalCategory.UNKNOWN.value: 0.00,
    }


@dataclass(frozen=True)
class CorrelationConfig:
    """Tunable correlation parameters (all justified / documented)."""

    # Temporal
    window_duration_sec: float = 30.0
    temporal_min: float = 0.55  # floor when signals span full window

    # Diversity: target distinct categories for full diversity boost
    diversity_target: int = 3
    diversity_floor: float = 0.55  # single-category still allowed to score

    # Dedup / caps
    max_signals_per_type: int = 1  # keep strongest per (source,name,entity)
    # Categories present still contribute via max; no multi-signal sum

    # Health
    degraded_strength_factor: float = 0.5
    # STALE / NOT_AVAILABLE excluded entirely (missing ≠ negative)

    # Agreement among DETECTION statuses
    agreement_boost: float = 1.08
    disagreement_factor: float = 0.90

    # Persistence (multiple strong timestamps)
    persistence_boost_max: float = 0.06
    persistence_min_strong: int = 2
    strong_strength_threshold: float = 0.5

    # Score → severity
    severity_low: float = 0.25
    severity_medium: float = 0.45
    severity_high: float = 0.65
    severity_critical: float = 0.85

    # Status label thresholds (evidence only — not mitigation)
    correlated_min_score: float = 0.45
    correlated_min_categories: int = 2

    # Entity
    # switch-scoped signals (no MAC) may join a MAC-scoped focal entity
    allow_switch_scoped_with_entity: bool = True

    category_weights: Dict[str, float] = field(default_factory=_default_category_weights)

    def weight_for(self, category: SignalCategory) -> float:
        return float(self.category_weights.get(category.value, 0.0))
