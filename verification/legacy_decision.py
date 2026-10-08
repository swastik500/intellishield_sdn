"""
Legacy decision oracle for R7.2 golden compatibility tests.

Reproduces the *combined* flow_monitor gating + MitigationEngine.handle_alert
decision WITHOUT installing OpenFlow rules or mutating blocklists.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from mitigation.mitigation_engine import (
    AUTO_MITIGATE_STATUS,
    MIN_CONFIDENCE_TO_BLOCK,
    MITIGATE_ON_STATUS,
    MitigationEngine,
)
from verification.adapters import normalize_prediction_confidence
from verification.config import VerificationConfig


@dataclass(frozen=True)
class LegacyDecision:
    """Outcome of the legacy verification+eligibility path (no actuation)."""

    would_call_handle_alert: bool
    would_block: bool
    pending_confirmation: bool
    reason: str
    recommended_strategy: Optional[str] = None
    attacker_mac: Optional[str] = None
    victim_mac: Optional[str] = None
    status: str = "NORMAL"
    confidence_percent: float = 0.0


def evaluate_legacy_decision(
    *,
    warmup_cycles_done: int,
    attack_streak: int,
    prediction: Dict[str, Any],
    explanation: Dict[str, Any],
    flow_features: List[dict],
    config: Optional[VerificationConfig] = None,
    datapath_available: bool = True,
    mitigation: Optional[MitigationEngine] = None,
) -> LegacyDecision:
    """
    Mirror production decision semantics:

    1. Warm-up (flow_monitor): cycles_done <= warmup_threshold → no mitigation
    2. Streak (flow_monitor): ATTACK with streak < confirm → pending, no handle_alert
       SUSPICIOUS still calls handle_alert
    3. handle_alert gates: status, auto_mitigate, confidence, identify, datapath
    """
    cfg = config or VerificationConfig()
    pred = normalize_prediction_confidence(prediction or {})
    expl = dict(explanation or {})
    status = str(pred.get("status", "NORMAL")).upper()
    confidence = float(pred.get("confidence", 0.0) or 0.0)
    hint = str(expl.get("attack_type_hint", "UNKNOWN"))

    # 1) Warm-up
    if warmup_cycles_done <= cfg.warmup_threshold:
        return LegacyDecision(
            would_call_handle_alert=False,
            would_block=False,
            pending_confirmation=False,
            reason="warmup_active",
            status=status,
            confidence_percent=confidence,
        )

    # 2) No actionable status for streak path (NORMAL etc.)
    if status not in ("ATTACK", "SUSPICIOUS"):
        return LegacyDecision(
            would_call_handle_alert=False,
            would_block=False,
            pending_confirmation=False,
            reason="no_detection_evidence",
            status=status,
            confidence_percent=confidence,
        )

    # 3) ATTACK pending confirmation
    if status == "ATTACK" and attack_streak < cfg.attack_confirm:
        return LegacyDecision(
            would_call_handle_alert=False,
            would_block=False,
            pending_confirmation=True,
            reason="attack_pending_confirmation",
            status=status,
            confidence_percent=confidence,
        )

    # 4) Would call handle_alert — evaluate its gates (no OpenFlow)
    helper = mitigation or MitigationEngine(auto_mitigate=cfg.auto_mitigate)

    if status not in MITIGATE_ON_STATUS:
        return LegacyDecision(
            would_call_handle_alert=True,
            would_block=False,
            pending_confirmation=False,
            reason="status_not_in_mitigate_on",
            status=status,
            confidence_percent=confidence,
        )

    if helper.auto_mitigate and status not in AUTO_MITIGATE_STATUS:
        return LegacyDecision(
            would_call_handle_alert=True,
            would_block=False,
            pending_confirmation=False,
            reason="status_not_auto_mitigated",
            status=status,
            confidence_percent=confidence,
        )

    # Align with VerificationConfig / engine (static floor). If a live
    # MitigationEngine with RL adapter is injected, defer to its gate.
    if mitigation is not None and pred.get("source") != "entropy":
        min_conf = float(mitigation._min_confidence_to_block(pred))  # noqa: SLF001
    else:
        min_conf = float(cfg.min_confidence_to_block)
    if confidence < min_conf:
        return LegacyDecision(
            would_call_handle_alert=True,
            would_block=False,
            pending_confirmation=False,
            reason="confidence_below_threshold",
            status=status,
            confidence_percent=confidence,
        )

    attackers = helper._identify_attackers(flow_features, expl)  # noqa: SLF001
    if not attackers:
        return LegacyDecision(
            would_call_handle_alert=True,
            would_block=False,
            pending_confirmation=False,
            reason="attacker_not_identified",
            status=status,
            confidence_percent=confidence,
        )

    src_mac, dst_mac = attackers[0]
    strategy = helper._select_block_strategy(hint, dst_mac or "")  # noqa: SLF001

    if not datapath_available:
        return LegacyDecision(
            would_call_handle_alert=True,
            would_block=False,
            pending_confirmation=False,
            reason="datapath_missing",
            recommended_strategy=strategy,
            attacker_mac=src_mac,
            victim_mac=dst_mac,
            status=status,
            confidence_percent=confidence,
        )

    return LegacyDecision(
        would_call_handle_alert=True,
        would_block=True,
        pending_confirmation=False,
        reason="would_block",
        recommended_strategy=strategy,
        attacker_mac=src_mac,
        victim_mac=dst_mac,
        status=status,
        confidence_percent=confidence,
    )


def extract_recommended_strategy(result: Any) -> Optional[str]:
    """Pull strategy recommendation from VerificationResult stage details."""
    stages = getattr(result, "stages", None) or []
    for stage in reversed(list(stages)):
        details = getattr(stage, "details", None) or {}
        strat = details.get("recommended_strategy")
        if strat:
            return str(strat)
    return None


def verification_matches_legacy(legacy: LegacyDecision, result: Any) -> Tuple[bool, str]:
    """
    Compare legacy oracle to a VerificationResult.

    Compares final decision semantics (pending / would_block), not stage order.
    Returns (ok, detail).
    """
    from shared_contracts.enums import VerificationStatus

    status = getattr(result.status, "value", result.status)
    status_name = str(status)
    mitigation_eligible = bool(getattr(result, "mitigation_eligible", False))
    pending = status_name == VerificationStatus.PENDING.value
    attacker_mac = getattr(result, "attacker_mac", None)
    victim_mac = getattr(result, "victim_mac", None)
    recommended_strategy = extract_recommended_strategy(result)

    # Pending
    if legacy.pending_confirmation:
        if not pending:
            return False, f"expected PENDING, got {status_name}"
        if mitigation_eligible:
            return False, "pending must not be mitigation_eligible"
        return True, "pending_ok"

    # Would block
    if legacy.would_block:
        if status_name != VerificationStatus.VERIFIED.value:
            return False, f"expected VERIFIED, got {status_name}"
        if not mitigation_eligible:
            return False, "expected mitigation_eligible"
        if legacy.attacker_mac and attacker_mac != legacy.attacker_mac:
            return False, f"attacker mismatch {attacker_mac}!={legacy.attacker_mac}"
        if legacy.victim_mac and victim_mac != legacy.victim_mac:
            return False, f"victim mismatch {victim_mac}!={legacy.victim_mac}"
        if (
            legacy.recommended_strategy
            and recommended_strategy
            and recommended_strategy != legacy.recommended_strategy
        ):
            return False, (
                f"strategy mismatch {recommended_strategy}!="
                f"{legacy.recommended_strategy}"
            )
        return True, "block_ok"

    # No block
    if mitigation_eligible:
        return False, f"legacy no-block but eligible ({legacy.reason})"
    if status_name == VerificationStatus.VERIFIED.value:
        return False, f"legacy no-block but VERIFIED ({legacy.reason})"
    if pending:
        return False, (
            f"legacy no-block/pending-false but engine PENDING ({legacy.reason})"
        )
    return True, f"no_block_ok:{legacy.reason}"
