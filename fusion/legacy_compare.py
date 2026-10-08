"""
R6.2 golden / legacy decision comparison (offline analysis only).

Compares CollaborativeFusionEngine output to a simplified model of today's
production branch logic (ML ATTACK/SUSPICIOUS path + entropy ALERT secondary).

Does NOT change production. Classifies differences for review before R6.3.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence

from shared_contracts.enums import DetectionDecision, DetectorType
from shared_contracts.models import DetectorResult, FusedDecision


@dataclass(frozen=True)
class LegacyComparison:
    legacy_decision: str
    fused_decision: str
    classification: str  # EXPECTED_IMPROVEMENT | EXPECTED_UNCERTAINTY | POTENTIAL_REGRESSION | MATCH
    note: str


def legacy_production_decision(
    detector_results: Sequence[DetectorResult],
) -> str:
    """
    Approximate current production preference:

    1. ML ATTACK → ATTACK
    2. ML SUSPICIOUS → SUSPICIOUS
    3. Else entropy ALERT → ATTACK-like (entropy mitigation path uses ALERT)
    4. Else entropy WARNING → SUSPICIOUS
    5. Else ML/entropy NORMAL → NORMAL
    6. Else NONE
    """
    by_type = {r.detector: r for r in detector_results}
    ml = by_type.get(DetectorType.ML)
    ent = by_type.get(DetectorType.ENTROPY)

    if ml is not None and ml.decision is DetectionDecision.ATTACK:
        return "ATTACK"
    if ml is not None and ml.decision is DetectionDecision.SUSPICIOUS:
        return "SUSPICIOUS"
    if ent is not None and ent.decision is DetectionDecision.ALERT:
        return "ATTACK"  # entropy ALERT historically drives mitigation path
    if ent is not None and ent.decision is DetectionDecision.WARNING:
        return "SUSPICIOUS"
    if ml is not None and ml.decision is DetectionDecision.NORMAL:
        return "NORMAL"
    if ent is not None and ent.decision is DetectionDecision.NORMAL:
        return "NORMAL"
    return "NONE"


def classify_legacy_difference(
    fused: FusedDecision,
    detector_results: Sequence[DetectorResult],
) -> LegacyComparison:
    legacy = legacy_production_decision(detector_results)
    fused_d = fused.decision.value

    if legacy == fused_d:
        return LegacyComparison(legacy, fused_d, "MATCH", "same label")

    # Disagreement → SUSPICIOUS is expected uncertainty
    if fused.disagreement and fused_d == "SUSPICIOUS":
        return LegacyComparison(
            legacy,
            fused_d,
            "EXPECTED_UNCERTAINTY",
            "primary disagreement → fused SUSPICIOUS",
        )

    # Legacy ATTACK but fused SUSPICIOUS with disagreement/missing → uncertainty
    if legacy == "ATTACK" and fused_d == "SUSPICIOUS":
        return LegacyComparison(
            legacy,
            fused_d,
            "EXPECTED_UNCERTAINTY",
            "collaboration reduced certainty vs single-detector legacy ATTACK",
        )

    # Legacy NORMAL, fused not ATTACK (invariant) — if SUSPICIOUS from context
    if legacy == "NORMAL" and fused_d == "SUSPICIOUS":
        return LegacyComparison(
            legacy,
            fused_d,
            "EXPECTED_UNCERTAINTY",
            "context/uncertainty elevated NORMAL → SUSPICIOUS",
        )

    # Fused catches attack when only entropy ALERT and ML missing — improvement path
    if legacy == "ATTACK" and fused_d == "ATTACK":
        return LegacyComparison(legacy, fused_d, "MATCH", "aligned attack")

    # Fused ATTACK when legacy NONE — potential over-trigger
    if fused_d == "ATTACK" and legacy in ("NONE", "NORMAL"):
        return LegacyComparison(
            legacy,
            fused_d,
            "POTENTIAL_REGRESSION",
            "fused ATTACK where legacy would not attack",
        )

    # Fused NORMAL when legacy ATTACK without disagreement — potential miss
    if legacy == "ATTACK" and fused_d == "NORMAL":
        return LegacyComparison(
            legacy,
            fused_d,
            "POTENTIAL_REGRESSION",
            "fused NORMAL where legacy ATTACK",
        )

    # Agreement ATTACK when legacy SUSPICIOUS — expected improvement
    if legacy == "SUSPICIOUS" and fused_d == "ATTACK" and not fused.disagreement:
        return LegacyComparison(
            legacy,
            fused_d,
            "EXPECTED_IMPROVEMENT",
            "multi-detector agreement escalated SUSPICIOUS → ATTACK",
        )

    if legacy == "NONE" and fused_d in ("NORMAL", "SUSPICIOUS"):
        return LegacyComparison(
            legacy,
            fused_d,
            "EXPECTED_IMPROVEMENT",
            "fusion produced a concrete decision from available evidence",
        )

    return LegacyComparison(
        legacy,
        fused_d,
        "EXPECTED_UNCERTAINTY",
        "label differs; review before R6.3 production switch",
    )


def comparison_to_dict(c: LegacyComparison) -> Dict[str, Any]:
    return {
        "legacy_decision": c.legacy_decision,
        "fused_decision": c.fused_decision,
        "classification": c.classification,
        "note": c.note,
    }
