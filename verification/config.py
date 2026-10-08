"""Configuration for VerificationEngine — single source aligned with legacy gates."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet

# Import legacy constants so we do not duplicate threshold truth.
from mitigation.mitigation_engine import (
    ATTACK_RATE_THRESHOLD,
    AUTO_MITIGATE_STATUS,
    MIN_CONFIDENCE_TO_BLOCK,
    MITIGATE_ON_STATUS,
    RATE_DOMINANCE_RATIO,
)


@dataclass(frozen=True)
class VerificationConfig:
    """
    Verification thresholds.

    Defaults mirror controller/flow_monitor.py and mitigation_engine.py.
    Callers (controller) should inject the same numbers they already use.
    """

    warmup_threshold: int = 3
    attack_confirm: int = 2
    min_confidence_to_block: float = MIN_CONFIDENCE_TO_BLOCK  # percent 0–100
    auto_mitigate: bool = True
    mitigate_on_status: FrozenSet[str] = field(
        default_factory=lambda: frozenset(MITIGATE_ON_STATUS)
    )
    auto_mitigate_status: FrozenSet[str] = field(
        default_factory=lambda: frozenset(AUTO_MITIGATE_STATUS)
    )
    attack_rate_threshold: float = ATTACK_RATE_THRESHOLD
    rate_dominance_ratio: float = RATE_DOMINANCE_RATIO

    def __post_init__(self) -> None:
        if self.warmup_threshold < 0:
            raise ValueError("warmup_threshold must be >= 0")
        if self.attack_confirm < 1:
            raise ValueError("attack_confirm must be >= 1")
        if self.min_confidence_to_block < 0 or self.min_confidence_to_block > 100:
            raise ValueError("min_confidence_to_block must be in [0, 100]")
