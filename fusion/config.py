"""
R6.2 fusion configuration — explicit, documented, no scattered magic numbers.

Base reliabilities are conservative defaults (not dynamically learned).
Health factors scale effective weight: w = ρ × h.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from shared_contracts.enums import DetectorHealth, DetectorType


# Conservative defaults — lab ensemble; not claimed as online-learned reliability.
DEFAULT_BASE_RELIABILITY: Dict[str, float] = {
    DetectorType.ML.value: 1.00,       # primary ensemble on live path
    DetectorType.ENTROPY.value: 0.95,  # strong independent signal; slightly below ML
    DetectorType.SSL.value: 0.90,      # reserved R2
    DetectorType.CORRELATION.value: 0.70,
    DetectorType.ADWIN.value: 0.55,
    DetectorType.HDBSCAN.value: 0.55,
    DetectorType.OTHER.value: 0.80,
}

# DetectorHealth → multiplicative health factor (UNAVAILABLE/ERROR → 0 participation)
DEFAULT_HEALTH_FACTORS: Dict[str, float] = {
    DetectorHealth.SUCCESS.value: 1.00,
    DetectorHealth.DEGRADED.value: 0.50,
    DetectorHealth.ERROR.value: 0.00,
}


@dataclass(frozen=True)
class FusionConfig:
    """
    Reliability-aware collaborative fusion policy (R6.2).

    Decision thresholds apply to signed score S ∈ [-1, 1]:
      S >= attack_threshold              → ATTACK
      suspicious_threshold <= S < attack → SUSPICIOUS
      S <= -normal_threshold             → NORMAL
      else (mid band)                    → SUSPICIOUS if conflict/context else NORMAL/NONE
    """

    base_reliability: Dict[str, float] = field(
        default_factory=lambda: dict(DEFAULT_BASE_RELIABILITY)
    )
    health_factors: Dict[str, float] = field(
        default_factory=lambda: dict(DEFAULT_HEALTH_FACTORS)
    )

    # Freshness: exclude evidence older than this relative to fusion clock
    freshness_seconds: float = 30.0

    # Disagreement shrinks |S|: S' = S * (1 - disagreement_penalty * C)
    disagreement_penalty: float = 0.45

    # R4 correlation boost strength β (only when primary attack-leaning)
    correlation_support_strength: float = 0.25

    # Context uncertainty γ: shrinks |S|; can tip mid-band → SUSPICIOUS
    context_uncertainty_strength: float = 0.35
    adwin_uncertainty: float = 0.20
    hdbscan_uncertainty: float = 0.15

    # Decision thresholds on signed score S
    attack_threshold: float = 0.55
    suspicious_threshold: float = 0.20
    normal_threshold: float = 0.20  # NORMAL when S <= -normal_threshold

    # Minimum primary weight to attempt a security decision
    min_primary_weight: float = 1e-6

    # Default confidence when decision present but producer omitted confidence
    default_decision_confidence: float = 0.50

    # Agreement-aware confidence calibration (does not change the ATTACK/NORMAL
    # decision rule on S — only the reported posterior used by R7 gates).
    # When primaries unanimously attack-lean (high G, low C), boost confidence
    # so under-shrunk S (context U) does not starve mitigation.
    agreement_confidence_boost: float = 0.25
    correlation_confidence_boost_cap: float = 0.15
    uncertainty_confidence_penalty: float = 0.50  # scales context_uncertainty_strength*U

    def reliability_of(self, detector: DetectorType | str) -> float:
        key = detector.value if isinstance(detector, DetectorType) else str(detector)
        return float(self.base_reliability.get(key, 0.75))

    def health_factor(self, health: DetectorHealth | str) -> float:
        key = health.value if isinstance(health, DetectorHealth) else str(health)
        return float(self.health_factors.get(key, 0.0))

    def validate(self) -> None:
        if not (0.0 < self.attack_threshold <= 1.0):
            raise ValueError("attack_threshold must be in (0, 1]")
        if not (0.0 <= self.suspicious_threshold < self.attack_threshold):
            raise ValueError("suspicious_threshold must satisfy 0 <= susp < attack")
        if not (0.0 <= self.normal_threshold <= 1.0):
            raise ValueError("normal_threshold must be in [0, 1]")
        if self.freshness_seconds <= 0:
            raise ValueError("freshness_seconds must be > 0")
        if not (0.0 <= self.disagreement_penalty <= 1.0):
            raise ValueError("disagreement_penalty must be in [0, 1]")
        for k, v in self.health_factors.items():
            if not (0.0 <= float(v) <= 1.0):
                raise ValueError(f"health_factor[{k}] must be in [0, 1]")
        for k, v in self.base_reliability.items():
            if not (0.0 < float(v) <= 1.0):
                raise ValueError(f"base_reliability[{k}] must be in (0, 1]")
        if not (0.0 <= self.agreement_confidence_boost <= 1.0):
            raise ValueError("agreement_confidence_boost must be in [0, 1]")
        if not (0.0 <= self.correlation_confidence_boost_cap <= 1.0):
            raise ValueError("correlation_confidence_boost_cap must be in [0, 1]")
        if not (0.0 <= self.uncertainty_confidence_penalty <= 1.0):
            raise ValueError("uncertainty_confidence_penalty must be in [0, 1]")
