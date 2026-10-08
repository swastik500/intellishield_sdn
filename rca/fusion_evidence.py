"""
R6.4 helpers — attach optional FusedDecision to RCA without claiming causation.

Fusion evidence is deterministic formula output (OBSERVED), not a trained model.
Disagree / support interpretations may be INFERRED.
ADWIN/HDBSCAN appear as CONTEXT only — never "attack detected".
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from shared_contracts.models import FusedDecision
from rca.evidence import EvidenceItem, EvidenceKind


def fusion_evidence_items(
    fused: Optional[FusedDecision],
) -> Tuple[List[EvidenceItem], List[str], Dict[str, Any]]:
    """
    Build OBSERVED / INFERRED evidence from an optional FusedDecision.

    Returns (items, signal_tags, features_block).
    """
    if fused is None:
        return [], [], {}

    ev = fused.evidence if isinstance(fused.evidence, dict) else {}
    scores = ev.get("scores") if isinstance(ev.get("scores"), dict) else {}
    votes = ev.get("primary_votes") if isinstance(ev.get("primary_votes"), list) else []
    corr = ev.get("correlation") if isinstance(ev.get("correlation"), dict) else {}
    ctx_u = (
        ev.get("context_uncertainty")
        if isinstance(ev.get("context_uncertainty"), dict)
        else {}
    )
    context_notes = ev.get("context") if isinstance(ev.get("context"), list) else []

    decision = getattr(fused.decision, "value", fused.decision)
    conf = fused.confidence
    conf_s = f"{float(conf):.4f}" if isinstance(conf, (int, float)) else "UNAVAILABLE"

    # Compact primary vote summary (no giant telemetry)
    vote_summaries = []
    for v in votes[:8]:
        if not isinstance(v, dict):
            continue
        vote_summaries.append(
            {
                "detector": v.get("detector"),
                "decision": v.get("decision"),
                "confidence": v.get("confidence"),
                "health": v.get("health"),
                "effective_weight": v.get("effective_weight"),
                "camp": v.get("camp"),
            }
        )

    # Context indicators — labelled as context, never attack-detected
    context_indicators = []
    for note in context_notes[:8]:
        if not isinstance(note, dict):
            continue
        det = str(note.get("detector") or "")
        role = str(note.get("role") or "")
        if role == "CONTEXT_ONLY" or det in ("ADWIN", "HDBSCAN"):
            context_indicators.append(
                {
                    "detector": det,
                    "decision": note.get("decision"),
                    "role": "CONTEXT",
                    "note": "Context / novelty indicator — not an attack detector.",
                }
            )

    signals_ctx = list(ctx_u.get("signals") or [])

    items: List[EvidenceItem] = [
        EvidenceItem(
            key="fusion_decision",
            statement=(
                f"Collaborative fusion decision is {decision} "
                f"with confidence {conf_s} (observed FusedDecision output)."
            ),
            kind=EvidenceKind.OBSERVED.value,
            value={
                "fusion_id": fused.fusion_id,
                "decision": str(decision),
                "confidence": conf,
            },
            source="FusedDecision",
        ),
        EvidenceItem(
            key="fusion_participants",
            statement=(
                "Primary detectors participating in fusion: "
                + (", ".join(fused.participating) if fused.participating else "none")
                + "."
            ),
            kind=EvidenceKind.OBSERVED.value,
            value={
                "participating": [str(x) for x in (fused.participating or [])],
                "vote_lines": [
                    f"{v.get('detector')}:{v.get('decision')}@"
                    f"{v.get('confidence')}/{v.get('health')}"
                    for v in vote_summaries
                ],
                "missing": [str(x) for x in (ev.get("missing_detectors") or [])],
                "degraded": [str(x) for x in (ev.get("degraded_detectors") or [])],
            },
            source="FusedDecision.participating/evidence.primary_votes",
        ),
        EvidenceItem(
            key="fusion_agreement",
            statement=(
                "Primary detectors "
                + (
                    "disagreed (conflict recorded)."
                    if fused.disagreement
                    else "agreed (no hard conflict recorded)."
                )
            ),
            kind=EvidenceKind.OBSERVED.value,
            value={
                "disagreement": bool(fused.disagreement),
                "G": scores.get("G"),
                "C": scores.get("C"),
            },
            source="FusedDecision.disagreement",
        ),
    ]

    if corr.get("present"):
        items.append(
            EvidenceItem(
                key="fusion_r4_support",
                statement=(
                    "R4 correlation contributed supporting evidence to fusion "
                    f"(boost_applied={bool(corr.get('boost_applied'))}; "
                    "support only — not causation)."
                ),
                kind=EvidenceKind.OBSERVED.value,
                value={
                    "correlation_id": corr.get("correlation_id"),
                    "score": corr.get("score"),
                    "boost_applied": bool(corr.get("boost_applied")),
                    "R": scores.get("R"),
                },
                source="FusedDecision.evidence.correlation",
            )
        )

    if context_indicators or signals_ctx:
        items.append(
            EvidenceItem(
                key="fusion_context",
                statement=(
                    "Context indicators (ADWIN drift / HDBSCAN behaviour) were "
                    "present as uncertainty/novelty context — not labelled as "
                    "attack detected."
                ),
                kind=EvidenceKind.OBSERVED.value,
                value={
                    "indicator_lines": [
                        f"{c.get('detector')}:{c.get('decision')}"
                        for c in context_indicators
                    ],
                    "uncertainty_signals": [str(s) for s in signals_ctx],
                    "U": scores.get("U"),
                },
                source="FusedDecision.evidence.context*",
            )
        )

    # INFERRED: why the final label was selected (formula rule, not causation)
    items.append(
        EvidenceItem(
            key="fusion_decision_rule",
            statement=(
                "Final fused label follows the deterministic fusion rule "
                f"'{ev.get('decision_rule') or 'UNAVAILABLE'}' "
                "(inferred explanation of the score map — not causal proof)."
            ),
            kind=EvidenceKind.INFERRED.value,
            value={
                "decision_rule": str(ev.get("decision_rule") or "UNAVAILABLE"),
                "S": scores.get("S"),
                "A": scores.get("A"),
                "N": scores.get("N"),
                "reason": (fused.reason or "")[:240],
            },
            source="FusedDecision.evidence.decision_rule",
        )
    )

    features = {
        "fusion_id": fused.fusion_id,
        "fusion_decision": str(decision),
        "fusion_confidence": conf,
        "fusion_disagreement": bool(fused.disagreement),
        "fusion_participating": [str(x) for x in (fused.participating or [])],
        "fusion_vote_lines": [
            f"{v.get('detector')}:{v.get('decision')}@"
            f"{v.get('confidence')}/{v.get('health')}"
            for v in vote_summaries
        ],
        "fusion_missing": [str(x) for x in (ev.get("missing_detectors") or [])],
        "fusion_degraded": [str(x) for x in (ev.get("degraded_detectors") or [])],
        "fusion_scores": {
            "A": scores.get("A"),
            "N": scores.get("N"),
            "S": scores.get("S"),
            "G": scores.get("G"),
            "C": scores.get("C"),
            "R": scores.get("R"),
            "U": scores.get("U"),
        },
        "fusion_r4_support": {
            "present": bool(corr.get("present")),
            "boost_applied": bool(corr.get("boost_applied")),
            "correlation_id": corr.get("correlation_id"),
        },
        "fusion_context": {
            "indicator_lines": [
                f"{c.get('detector')}:{c.get('decision')}" for c in context_indicators
            ],
            "signals": [str(s) for s in signals_ctx],
        },
        "fusion_decision_rule": str(ev.get("decision_rule") or "UNAVAILABLE"),
        "note": (
            "FusedDecision is deterministic collaborative evidence; "
            "not model-specific XAI; does not prove causation."
        ),
    }
    return items, ["fusion"], features


def fusion_alert_refs(
    fused: Optional[FusedDecision],
    *,
    max_reason: int = 160,
) -> Dict[str, Any]:
    """Compact refs for R8 AlertEvent.evidence (no nested detector dumps)."""
    if fused is None:
        return {"fusion_linked": False}
    reason = str(fused.reason or "")
    if len(reason) > max_reason:
        reason = reason[: max_reason - 3] + "..."
    return {
        "fusion_linked": True,
        "fusion_id": fused.fusion_id,
        "fused_decision": getattr(fused.decision, "value", fused.decision),
        "fused_confidence": fused.confidence,
        "fusion_disagreement": bool(fused.disagreement),
        "fusion_participating": list(fused.participating or [])[:8],
        "fusion_reason": reason,
    }
