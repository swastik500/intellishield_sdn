"""RCA configuration (R5.2)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RCAConfig:
    """Deterministic RCA knobs — no LLM, no R6 fusion."""

    enabled: bool = True
    # Confidence weights (sum of available bonuses, clamped to [0, 1])
    w_verification: float = 0.25
    w_source: float = 0.15
    w_target: float = 0.10
    w_xai: float = 0.15
    w_attack_hint: float = 0.10
    w_detector_or_entropy: float = 0.10
    w_mitigation_evidence: float = 0.10
    w_baseline: float = 0.05

    # R5.3 invocation policy (security-relevant default = VERIFIED only)
    run_on_verified: bool = True
    run_on_pending: bool = False
    run_on_ineligible: bool = False
    run_on_rejected: bool = False
    persist_enabled: bool = True
    max_summary_chars: int = 240
