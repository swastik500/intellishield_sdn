"""
R4.4 helpers — attach optional CorrelationResult to RCA without claiming causation.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from shared_contracts.models import CorrelationResult
from rca.evidence import EvidenceItem, EvidenceKind


def correlation_evidence_items(
    correlation: Optional[CorrelationResult],
) -> Tuple[List[EvidenceItem], List[str], Dict[str, Any]]:
    """
    Build OBSERVED / INFERRED evidence from an optional CorrelationResult.

    OBSERVED: co-occurrence / score / categories / window.
    INFERRED: combined pattern supports the security event (not causation).

    Returns (items, signal_tags, features_block).
    """
    if correlation is None:
        return [], [], {}

    evidence = correlation.evidence if isinstance(correlation.evidence, dict) else {}
    cats = evidence.get("participating_categories") or []
    if not isinstance(cats, list):
        cats = []
    cat_list = [str(c) for c in cats]
    # Enforce R4.1 vocabulary — never invent "Application Layer"
    score = correlation.score
    score_s = f"{float(score):.4f}" if isinstance(score, (int, float)) else "UNAVAILABLE"
    n_signals = len(correlation.signal_ids or [])
    summary = str(
        evidence.get("summary")
        or evidence.get("reason")
        or "Cross-layer correlation evidence available."
    )
    if len(summary) > 240:
        summary = summary[:237] + "..."

    w_start = correlation.window_start
    w_end = correlation.window_end
    window_stmt = "Correlation time window recorded."
    if w_start is not None and w_end is not None:
        window_stmt = (
            f"Correlation window spans {w_start.isoformat()} → {w_end.isoformat()} "
            "(event-time co-occurrence scope)."
        )

    items: List[EvidenceItem] = [
        EvidenceItem(
            key="correlation_cooccurrence",
            statement=(
                "Multiple telemetry categories produced temporally correlated "
                "evidence (signals co-occurred within a shared window; "
                "co-occurrence only — not causation)."
            ),
            kind=EvidenceKind.OBSERVED.value,
            value={
                "correlation_id": correlation.correlation_id,
                "categories": cat_list,
                "signal_count": n_signals,
            },
            source="CorrelationResult",
        ),
        EvidenceItem(
            key="correlation_score",
            statement=f"Correlation engine score is {score_s} (observed output).",
            kind=EvidenceKind.OBSERVED.value,
            value=score,
            source="CorrelationResult.score",
        ),
        EvidenceItem(
            key="correlation_categories",
            statement=(
                "Participating categories: "
                + (", ".join(cat_list) if cat_list else "none listed")
                + "."
            ),
            kind=EvidenceKind.OBSERVED.value,
            value=cat_list,
            source="CorrelationResult.evidence.participating_categories",
        ),
        EvidenceItem(
            key="correlation_window",
            statement=window_stmt,
            kind=EvidenceKind.OBSERVED.value,
            value={
                "window_start": w_start.isoformat() if w_start else None,
                "window_end": w_end.isoformat() if w_end else None,
            },
            source="CorrelationResult.window_*",
        ),
        EvidenceItem(
            key="correlation_pattern_support",
            statement=(
                "Their combined pattern supports the security event under analysis "
                "(inferred support only — does not claim one signal caused another)."
            ),
            kind=EvidenceKind.INFERRED.value,
            value={"summary": summary},
            source="CorrelationResult.evidence.summary",
        ),
    ]

    features = {
        "correlation_id": correlation.correlation_id,
        "correlation_score": score,
        "correlation_summary": summary,
        "correlation_categories": cat_list,
        "correlation_signal_count": n_signals,
        "correlation_status": evidence.get("status"),
        "note": "Correlation expresses co-occurrence, not causation.",
    }
    return items, ["correlation"], features


def correlation_alert_refs(
    correlation: Optional[CorrelationResult],
    *,
    max_summary: int = 160,
) -> Dict[str, Any]:
    """Compact refs for R8 AlertEvent.evidence (no giant histories)."""
    if correlation is None:
        return {"correlation_linked": False}
    evidence = correlation.evidence if isinstance(correlation.evidence, dict) else {}
    summary = str(evidence.get("summary") or evidence.get("reason") or "")
    if len(summary) > max_summary:
        summary = summary[: max_summary - 3] + "..."
    cats = evidence.get("participating_categories") or []
    if not isinstance(cats, list):
        cats = []
    return {
        "correlation_linked": True,
        "correlation_id": correlation.correlation_id,
        "correlation_score": correlation.score,
        "correlation_summary": summary,
        "correlation_categories": [str(c) for c in cats[:8]],
    }
