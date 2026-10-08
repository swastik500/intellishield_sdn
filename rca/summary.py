"""Deterministic RootCauseReport summary text (no LLM)."""

from __future__ import annotations

from typing import List, Optional


def build_summary(
    *,
    event_id: str,
    verification_status: Optional[str],
    suspected_source: Optional[str],
    affected_target: Optional[str],
    attack_hint: Optional[str],
    mitigation_eligible: Optional[bool],
    mitigation_strategy: Optional[str],
    missing: List[str],
    baseline_available: bool,
    rca_confidence: float,
) -> str:
    parts: List[str] = []
    status = verification_status or "UNKNOWN"
    parts.append(f"Event {event_id}: verification_status={status}.")

    if suspected_source:
        parts.append(
            f"Suspected source (not proven causation)={suspected_source}."
        )
    else:
        parts.append("Suspected source=UNKNOWN.")

    if affected_target:
        parts.append(f"Affected target={affected_target}.")
    else:
        parts.append("Affected target=UNKNOWN.")

    if attack_hint and attack_hint not in ("UNKNOWN", "NOT_AVAILABLE", ""):
        parts.append(f"Attack classification/hint={attack_hint}.")
    else:
        parts.append("Attack classification/hint=NOT_AVAILABLE.")

    if mitigation_eligible is True:
        strat = mitigation_strategy or "NOT_AVAILABLE"
        parts.append(
            f"Mitigation eligible=True; strategy_evidence={strat}."
        )
    elif mitigation_eligible is False:
        parts.append("Mitigation eligible=False.")
    else:
        parts.append("Mitigation eligibility=NOT_AVAILABLE.")

    if baseline_available:
        parts.append("Baseline evidence=AVAILABLE.")
    else:
        parts.append("Baseline evidence=NOT_AVAILABLE.")

    if missing:
        parts.append("Missing: " + ", ".join(missing[:6]) + ".")

    parts.append(f"RCA confidence={rca_confidence:.2f} (evidence completeness).")
    return " ".join(parts)
