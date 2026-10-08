"""
Deterministic RCA confidence policy (unit interval [0, 1]).

Semantics:
  RCA confidence measures completeness/agreement of *available RCA evidence*
  for explaining the security event outcome. It is NOT a copy of ML confidence
  and is NOT a collaborative fusion score (R6 not implemented).
"""

from __future__ import annotations

from rca.config import RCAConfig


def compute_rca_confidence(
    *,
    config: RCAConfig,
    has_verification: bool,
    has_source: bool,
    has_target: bool,
    has_xai: bool,
    has_attack_hint: bool,
    has_detector_or_entropy: bool,
    has_mitigation_evidence: bool,
    has_baseline: bool,
) -> float:
    score = 0.0
    if has_verification:
        score += config.w_verification
    if has_source:
        score += config.w_source
    if has_target:
        score += config.w_target
    if has_xai:
        score += config.w_xai
    if has_attack_hint:
        score += config.w_attack_hint
    if has_detector_or_entropy:
        score += config.w_detector_or_entropy
    if has_mitigation_evidence:
        score += config.w_mitigation_evidence
    if has_baseline:
        score += config.w_baseline
    if score < 0.0:
        return 0.0
    if score > 1.0:
        return 1.0
    return round(float(score), 4)


def confidence_breakdown(
    *,
    config: RCAConfig,
    flags: dict,
) -> dict:
    """Auditable map of which bonuses applied (for contributing_features)."""
    applied = {}
    mapping = [
        ("verification", "has_verification", config.w_verification),
        ("source", "has_source", config.w_source),
        ("target", "has_target", config.w_target),
        ("xai", "has_xai", config.w_xai),
        ("attack_hint", "has_attack_hint", config.w_attack_hint),
        ("detector_or_entropy", "has_detector_or_entropy", config.w_detector_or_entropy),
        ("mitigation_evidence", "has_mitigation_evidence", config.w_mitigation_evidence),
        ("baseline", "has_baseline", config.w_baseline),
    ]
    for name, key, weight in mapping:
        applied[name] = {
            "present": bool(flags.get(key)),
            "weight": weight if flags.get(key) else 0.0,
        }
    return applied
