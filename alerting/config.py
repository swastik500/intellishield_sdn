"""Alerting configuration — R8.1 core + R8.2 policy knobs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Tuple


@dataclass(frozen=True)
class AlertingConfig:
    """R8 configuration including severity / dedup / rate-limit policy."""

    enabled: bool = True
    alert_on_pending: bool = False  # R8.3 production default: VERIFIED only
    alert_on_ineligible: bool = False
    alert_on_rejected: bool = False

    # Severity thresholds (unit confidence)
    severity_critical_confidence: float = 0.90
    severity_high_confidence: float = 0.75

    # Dedup
    dedup_enabled: bool = True
    dedup_window_sec: float = 60.0
    dedup_max_keys: int = 256

    # Rate limit (per dedup-key sliding window)
    rate_limit_enabled: bool = True
    rate_limit_per_window: int = 30
    rate_limit_window_sec: float = 60.0
    rate_limit_max_keys: int = 256

    dispatch_enabled: bool = True
    default_source: str = "verification"
    evidence_denied_keys: Tuple[str, ...] = field(
        default_factory=lambda: (
            "password",
            "token",
            "secret",
            "api_key",
            "private_key",
            "credential",
            "authorization",
        )
    )

    def __post_init__(self) -> None:
        if self.dedup_window_sec < 0:
            raise ValueError("dedup_window_sec must be >= 0")
        if self.rate_limit_per_window < 0:
            raise ValueError("rate_limit_per_window must be >= 0")
        if self.rate_limit_window_sec < 0:
            raise ValueError("rate_limit_window_sec must be >= 0")
        if self.dedup_max_keys < 1:
            raise ValueError("dedup_max_keys must be >= 1")
        if self.rate_limit_max_keys < 1:
            raise ValueError("rate_limit_max_keys must be >= 1")
        if not (0.0 <= self.severity_critical_confidence <= 1.0):
            raise ValueError("severity_critical_confidence must be in [0, 1]")
        if not (0.0 <= self.severity_high_confidence <= 1.0):
            raise ValueError("severity_high_confidence must be in [0, 1]")
