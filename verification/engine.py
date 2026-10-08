"""
VerificationEngine — ordered multi-stage gating before mitigation.

Stage order (repository semantics):
  WARMUP
    → DETECTION_EVIDENCE
    → ATTACK_CONFIRMATION
    → CONFIDENCE_GATE
    → ATTACKER_IDENTIFICATION
    → MITIGATION_ELIGIBILITY

Status semantics:
  PENDING     — temporal confirmation incomplete (streak)
  REJECTED    — no actionable detection evidence this cycle
  INELIGIBLE  — evidence exists but mitigation safety gates failed
                (or warm-up / engine error fail-closed)
  VERIFIED    — mitigation-eligible under current policy

Attacker identification boundary (R7.1):
  Reuses MitigationEngine._identify_attackers / _select_block_strategy via
  injectable callables (default lazy helper). No duplicated P0.4 logic.
  No OpenFlow / blocklist side effects in verify().
"""

from __future__ import annotations

import logging
import math
import traceback
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from shared_contracts.enums import VerificationStatus
from shared_contracts.models import (
    VerificationResult,
    VerificationStageResult,
    new_id,
)
from shared_contracts.timeutil import utc_now
from verification.config import VerificationConfig
from verification.stages import STAGE_ORDER, VerificationStage

logger = logging.getLogger("intellishield.verification")

IdentifyFn = Callable[[List[dict], dict], List[Tuple[str, str]]]
StrategyFn = Callable[[str, str], str]


@dataclass
class VerificationInput:
    """
    One verification cycle input (R7-specific; not a live controller context).

    ``attack_streak`` must already reflect this cycle's update
    (same semantics as flow_monitor after incrementing on ATTACK/SUSPICIOUS
    or entropy ALERT). Prefer AttackConfirmationState.update() in R7.2+.
    """

    dpid: int
    prediction: Dict[str, Any]
    explanation: Dict[str, Any]
    flow_features: List[dict]
    warmup_cycles_done: int
    attack_streak: int
    event_id: Optional[str] = None
    # Percent threshold override (e.g. RL adapter). None → config default /
    # entropy static floor logic.
    min_confidence_percent: Optional[float] = None
    # When True, treat source=entropy for static confidence floor.
    force_entropy_confidence_floor: bool = False


class VerificationEngine:
    """
    Pure decision engine: evidence in → VerificationResult out.

    Does not touch OpenFlow datapaths, blocklists, or mitigation actions.

    Concurrency (OsKen):
      ``verify()`` is designed for the cooperative greenlet model used by
      OsKen ``hub``. It does not sleep/yield and does not mutate caller-owned
      streak dictionaries. Production streak / warm-up state lives on
      ``flow_monitor`` and is updated in the flow-stats reply handler before
      ``verify()`` is called. No lock is required under single-threaded
      cooperative scheduling. ``AttackConfirmationState`` is an optional
      utility and is not the production path.
    """

    def __init__(
        self,
        config: Optional[VerificationConfig] = None,
        identify_attackers: Optional[IdentifyFn] = None,
        select_strategy: Optional[StrategyFn] = None,
    ) -> None:
        self.config = config or VerificationConfig()
        self._identify_fn = identify_attackers
        self._strategy_fn = select_strategy
        self._mitigation_helper = None  # lazy; only if defaults needed

    def verify(self, inp: VerificationInput) -> VerificationResult:
        """
        Run ordered verification stages.

        Fail-safe: unexpected exceptions → INELIGIBLE (no mitigation).
        """
        try:
            return self._verify_inner(inp)
        except Exception as exc:  # noqa: BLE001 — fail-safe boundary
            logger.error(
                "[VerificationEngine] unexpected failure (fail-closed):\n%s",
                traceback.format_exc(),
            )
            return VerificationResult(
                verification_id=new_id(),
                timestamp=utc_now(),
                event_id=inp.event_id,
                status=VerificationStatus.INELIGIBLE,
                confidence=None,
                stages=[
                    VerificationStageResult(
                        stage_name="ENGINE_ERROR",
                        passed=False,
                        reason=f"verification exception: {type(exc).__name__}",
                        details={"error_type": type(exc).__name__},
                    )
                ],
                mitigation_eligible=False,
                reason="verification_error_fail_closed",
            )

    # ─── Attacker / strategy boundary ─────────────────────────────────────────

    def _get_identify_fn(self) -> IdentifyFn:
        if self._identify_fn is not None:
            return self._identify_fn
        helper = self._lazy_mitigation_helper()
        return helper._identify_attackers  # noqa: SLF001

    def _get_strategy_fn(self) -> StrategyFn:
        if self._strategy_fn is not None:
            return self._strategy_fn
        helper = self._lazy_mitigation_helper()
        return helper._select_block_strategy  # noqa: SLF001

    def _lazy_mitigation_helper(self):
        if self._mitigation_helper is None:
            from mitigation.mitigation_engine import MitigationEngine

            # auto_mitigate=False — helper must never install DROP rules.
            self._mitigation_helper = MitigationEngine(auto_mitigate=False)
        return self._mitigation_helper

    # ─── Internal pipeline ────────────────────────────────────────────────────

    def _verify_inner(self, inp: VerificationInput) -> VerificationResult:
        stages: List[VerificationStageResult] = []
        status = str(inp.prediction.get("status", "NORMAL")).upper()
        raw_conf = self._parse_confidence_percent(inp.prediction.get("confidence", 0.0))
        conf_unit = max(0.0, min(1.0, raw_conf / 100.0))
        attack_hint = str(
            inp.explanation.get("attack_type_hint")
            or inp.prediction.get("attack_type_hint")
            or "UNKNOWN"
        )
        source = str(inp.prediction.get("source", "ml")).lower()
        entropy_floor = (
            inp.force_entropy_confidence_floor or source == "entropy"
        )

        # 1) WARMUP
        warmup_ok = inp.warmup_cycles_done > self.config.warmup_threshold
        stages.append(
            VerificationStageResult(
                stage_name=VerificationStage.WARMUP.value,
                passed=warmup_ok,
                reason=(
                    "warmup_complete"
                    if warmup_ok
                    else (
                        f"warmup_active cycle={inp.warmup_cycles_done}/"
                        f"{self.config.warmup_threshold}"
                    )
                ),
                details={
                    "warmup_cycles_done": int(inp.warmup_cycles_done),
                    "warmup_threshold": int(self.config.warmup_threshold),
                    "observed_value": int(inp.warmup_cycles_done),
                    "threshold": int(self.config.warmup_threshold),
                },
            )
        )
        if not warmup_ok:
            return self._result(
                inp, VerificationStatus.INELIGIBLE, stages, conf_unit,
                reason="warmup_active",
            )

        # 2) DETECTION_EVIDENCE
        evidence_ok = status in self.config.mitigate_on_status
        stages.append(
            VerificationStageResult(
                stage_name=VerificationStage.DETECTION_EVIDENCE.value,
                passed=evidence_ok,
                reason=(
                    f"status={status}"
                    if evidence_ok
                    else f"status={status} not in mitigate_on_status"
                ),
                details={
                    "status": status,
                    "source": source,
                    "mitigate_on_status": sorted(self.config.mitigate_on_status),
                    "observed_value": status,
                },
            )
        )
        if not evidence_ok:
            return self._result(
                inp, VerificationStatus.REJECTED, stages, conf_unit,
                reason="no_detection_evidence",
            )

        # 3) ATTACK_CONFIRMATION
        if status == "ATTACK":
            confirmed = inp.attack_streak >= self.config.attack_confirm
            stages.append(
                VerificationStageResult(
                    stage_name=VerificationStage.ATTACK_CONFIRMATION.value,
                    passed=confirmed,
                    reason=(
                        "attack_confirmed"
                        if confirmed
                        else (
                            f"pending_confirmation "
                            f"{inp.attack_streak}/{self.config.attack_confirm}"
                        )
                    ),
                    details={
                        "attack_streak": int(inp.attack_streak),
                        "attack_confirm": int(self.config.attack_confirm),
                        "status": status,
                        "observed_value": int(inp.attack_streak),
                        "threshold": int(self.config.attack_confirm),
                    },
                )
            )
            if not confirmed:
                return self._result(
                    inp, VerificationStatus.PENDING, stages, conf_unit,
                    reason="attack_pending_confirmation",
                )
        else:
            stages.append(
                VerificationStageResult(
                    stage_name=VerificationStage.ATTACK_CONFIRMATION.value,
                    passed=True,
                    reason=f"no_streak_required_for_{status}",
                    details={
                        "attack_streak": int(inp.attack_streak),
                        "attack_confirm": int(self.config.attack_confirm),
                        "status": status,
                        "observed_value": int(inp.attack_streak),
                        "threshold": int(self.config.attack_confirm),
                    },
                )
            )

        # 4) CONFIDENCE_GATE
        min_conf = self._resolve_min_confidence(inp, entropy_floor)
        conf_ok = raw_conf >= min_conf
        stages.append(
            VerificationStageResult(
                stage_name=VerificationStage.CONFIDENCE_GATE.value,
                passed=conf_ok,
                reason=(
                    "confidence_ok"
                    if conf_ok
                    else f"confidence {raw_conf:.1f}% < {min_conf:.1f}%"
                ),
                details={
                    "confidence_percent": raw_conf,
                    "min_confidence_percent": min_conf,
                    "confidence_unit": conf_unit,
                    "entropy_static_floor": bool(entropy_floor),
                    "observed_value": raw_conf,
                    "threshold": min_conf,
                },
            )
        )
        if not conf_ok:
            return self._result(
                inp, VerificationStatus.INELIGIBLE, stages, conf_unit,
                reason="confidence_below_threshold",
            )

        # 5) ATTACKER_IDENTIFICATION
        attackers = self._get_identify_fn()(inp.flow_features, inp.explanation)
        id_ok = bool(attackers)
        attacker_mac = attackers[0][0] if attackers else None
        victim_mac = attackers[0][1] if attackers else None
        stages.append(
            VerificationStageResult(
                stage_name=VerificationStage.ATTACKER_IDENTIFICATION.value,
                passed=id_ok,
                reason=(
                    f"attacker={attacker_mac} victim={victim_mac}"
                    if id_ok
                    else "attacker_not_identified"
                ),
                details={
                    "attacker_mac": attacker_mac or "",
                    "victim_mac": victim_mac or "",
                    "attack_rate_threshold": self.config.attack_rate_threshold,
                    "rate_dominance_ratio": self.config.rate_dominance_ratio,
                    "n_attackers": len(attackers),
                    "observed_value": attacker_mac or "",
                },
            )
        )
        if not id_ok:
            return self._result(
                inp, VerificationStatus.INELIGIBLE, stages, conf_unit,
                reason="attacker_not_identified",
            )

        # 6) MITIGATION_ELIGIBILITY
        auto_ok = (not self.config.auto_mitigate) or (
            status in self.config.auto_mitigate_status
        )
        strategy = self._get_strategy_fn()(attack_hint, victim_mac or "")
        stages.append(
            VerificationStageResult(
                stage_name=VerificationStage.MITIGATION_ELIGIBILITY.value,
                passed=auto_ok,
                reason=(
                    "mitigation_eligible"
                    if auto_ok
                    else f"auto_mitigate_excludes_{status}"
                ),
                details={
                    "auto_mitigate": bool(self.config.auto_mitigate),
                    "status": status,
                    "auto_mitigate_status": sorted(self.config.auto_mitigate_status),
                    "recommended_strategy": strategy,
                    "attack_hint": attack_hint,
                    "observed_value": status,
                },
            )
        )
        if not auto_ok:
            return self._result(
                inp, VerificationStatus.INELIGIBLE, stages, conf_unit,
                reason="status_not_auto_mitigated",
                attacker_mac=attacker_mac,
                victim_mac=victim_mac,
            )

        return self._result(
            inp, VerificationStatus.VERIFIED, stages, conf_unit,
            reason="verified_mitigation_eligible",
            attacker_mac=attacker_mac,
            victim_mac=victim_mac,
            mitigation_eligible=True,
        )

    @staticmethod
    def _parse_confidence_percent(value: Any) -> float:
        """
        Parse legacy confidence as percent (0–100), matching handle_alert.

        Production ML/entropy paths pass percent. Non-finite / invalid → 0.0
        so the confidence gate fails closed. Values in (0, 1] are NOT auto-
        scaled here (would change legacy semantics); adapters belong in R7.2.
        """
        try:
            conf = float(value)
        except (TypeError, ValueError):
            return 0.0
        if not math.isfinite(conf):
            return 0.0
        return conf

    def _resolve_min_confidence(
        self, inp: VerificationInput, entropy_floor: bool
    ) -> float:
        if entropy_floor:
            return float(self.config.min_confidence_to_block)
        if inp.min_confidence_percent is not None:
            return float(inp.min_confidence_percent)
        return float(self.config.min_confidence_to_block)

    @staticmethod
    def _result(
        inp: VerificationInput,
        status: VerificationStatus,
        stages: Sequence[VerificationStageResult],
        conf_unit: float,
        reason: str,
        attacker_mac: Optional[str] = None,
        victim_mac: Optional[str] = None,
        mitigation_eligible: bool = False,
    ) -> VerificationResult:
        return VerificationResult(
            verification_id=new_id(),
            timestamp=utc_now(),
            event_id=inp.event_id,
            status=status,
            confidence=conf_unit,
            stages=list(stages),
            attacker_mac=attacker_mac,
            victim_mac=victim_mac,
            mitigation_eligible=mitigation_eligible,
            reason=reason,
        )


def is_warmup_active(cycles_done: int, threshold: int = 3) -> bool:
    """Match flow_monitor: in_warmup when cycles_done <= threshold."""
    return cycles_done <= threshold
