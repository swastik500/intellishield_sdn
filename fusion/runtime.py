"""
R6.3 collaborative cycle runtime — fuse evidence, prepare R7 payload.

Does NOT call MitigationEngine / OpenFlow.
Does NOT bypass R7 — caller must still run VerificationEngine.

Fail-safe: exceptions → fallback_legacy=True, owned=False.
"""

from __future__ import annotations

import logging
import os
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

from shared_contracts.enums import DetectionDecision
from shared_contracts.models import CorrelationResult, DetectorResult, FusedDecision, new_id
from shared_contracts.timeutil import utc_now
from fusion.adapters import (
    adapt_adwin_alerts,
    adapt_correlation_result,
    adapt_entropy_metrics,
    adapt_hdbscan_summary,
    adapt_ml_prediction,
)
from fusion.config import FusionConfig
from fusion.engine import CollaborativeFusionEngine
from fusion.r7_adapter import (
    fused_decision_to_r7_payload,
    fused_should_enter_verification,
)
from fusion.registry import EvidenceRegistry, build_default_registry
from fusion.trace import append_fusion_trace, default_fusion_trace_path

logger = logging.getLogger("intellishield.fusion.runtime")


def r6_fusion_enabled_from_env() -> bool:
    """Default ON. Set INTELLISHIELD_R6_FUSION=0 to force legacy dual-path."""
    raw = os.environ.get("INTELLISHIELD_R6_FUSION", "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


@dataclass
class CollaborativeCycleOutcome:
    ran: bool = False
    owned: bool = False
    """True ⇒ skip legacy ML + entropy mitigation dispatches this cycle."""
    fallback_legacy: bool = True
    fused: Optional[FusedDecision] = None
    prediction: Optional[Dict[str, Any]] = None
    explanation: Optional[Dict[str, Any]] = None
    should_dispatch_r7: bool = False
    trace_written: bool = False
    error: Optional[str] = None
    event_id: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


def _build_detector_results(
    *,
    ml_prediction: Optional[dict],
    ml_explanation: Optional[dict],
    entropy_metrics: Optional[dict],
    correlation: Optional[CorrelationResult],
    adwin_alerts: Optional[Sequence[dict]],
    hdbscan_summary: Optional[dict],
    timestamp: datetime,
) -> List[DetectorResult]:
    results: List[DetectorResult] = []
    if ml_prediction is not None:
        results.append(
            adapt_ml_prediction(
                ml_prediction, timestamp=timestamp, explanation=ml_explanation
            )
        )
    if entropy_metrics is not None:
        results.append(adapt_entropy_metrics(entropy_metrics, timestamp=timestamp))
    if correlation is not None:
        results.append(adapt_correlation_result(correlation, timestamp=timestamp))
    if adwin_alerts is not None:
        results.append(adapt_adwin_alerts(adwin_alerts, timestamp=timestamp))
    if hdbscan_summary is not None:
        results.append(adapt_hdbscan_summary(hdbscan_summary, timestamp=timestamp))
    return results


def prepare_collaborative_cycle(
    *,
    switch_id: int,
    ml_prediction: Optional[dict] = None,
    ml_explanation: Optional[dict] = None,
    entropy_metrics: Optional[dict] = None,
    correlation: Optional[CorrelationResult] = None,
    adwin_alerts: Optional[Sequence[dict]] = None,
    hdbscan_summary: Optional[dict] = None,
    src_mac: Optional[str] = None,
    dst_mac: Optional[str] = None,
    event_id: Optional[str] = None,
    timestamp: Optional[datetime] = None,
    engine: Optional[CollaborativeFusionEngine] = None,
    registry: Optional[EvidenceRegistry] = None,
    config: Optional[FusionConfig] = None,
    trace_path: Optional[str] = None,
    persist_trace: bool = True,
) -> CollaborativeCycleOutcome:
    """
    Adapt → fuse → R7 payload. Never mitigates.

    Ownership:
      - Fusion status OK with ≥1 valid primary → owned=True (suppresses legacy paths)
      - No valid primary / fusion ERROR → fallback_legacy=True, owned=False
    """
    eid = event_id or new_id()
    now = timestamp or utc_now()
    try:
        eng = engine or CollaborativeFusionEngine(
            config=config, registry=registry or build_default_registry()
        )
        results = _build_detector_results(
            ml_prediction=ml_prediction,
            ml_explanation=ml_explanation,
            entropy_metrics=entropy_metrics,
            correlation=correlation,
            adwin_alerts=adwin_alerts,
            hdbscan_summary=hdbscan_summary,
            timestamp=now,
        )
        if not results:
            return CollaborativeCycleOutcome(
                ran=True,
                owned=False,
                fallback_legacy=True,
                event_id=eid,
                error="no_detector_results",
                extra={"reason": "empty_evidence"},
            )

        fused = eng.fuse(
            detector_results=results,
            correlation=correlation,
            event_id=eid,
            timestamp=now,
            switch_id=switch_id,
            src_mac=src_mac,
            dst_mac=dst_mac,
            fusion_id=new_id(),
        )

        status = str((fused.evidence or {}).get("status") or "")
        if status in ("UNAVAILABLE", "ERROR") or fused.decision is DetectionDecision.NONE and not fused.participating:
            # Insufficient primary evidence — do not suppress legacy
            if status == "ERROR" or (fused.evidence or {}).get("fail_safe"):
                return CollaborativeCycleOutcome(
                    ran=True,
                    owned=False,
                    fallback_legacy=True,
                    fused=fused,
                    event_id=eid,
                    error="fusion_unavailable_or_error",
                    extra={"fusion_status": status},
                )
            if not fused.participating:
                return CollaborativeCycleOutcome(
                    ran=True,
                    owned=False,
                    fallback_legacy=True,
                    fused=fused,
                    event_id=eid,
                    error="no_valid_primary",
                    extra={"fusion_status": status},
                )

        hint = None
        if isinstance(ml_explanation, dict):
            hint = ml_explanation.get("attack_type_hint")
        pred, expl = fused_decision_to_r7_payload(
            fused, base_explanation=ml_explanation, attack_hint=hint
        )
        should = fused_should_enter_verification(fused)

        trace_written = False
        if persist_trace and trace_path:
            trace_written = append_fusion_trace(
                fused,
                trace_path,
                extra={
                    "dpid": int(switch_id),
                    "src_mac": src_mac,
                    "phase": "R6.3",
                },
            )

        return CollaborativeCycleOutcome(
            ran=True,
            owned=True,
            fallback_legacy=False,
            fused=fused,
            prediction=pred,
            explanation=expl,
            should_dispatch_r7=should,
            trace_written=trace_written,
            event_id=eid,
            extra={
                "fusion_status": status or "OK",
                "disagreement": fused.disagreement,
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "[prepare_collaborative_cycle] fail-safe fallback:\n%s",
            traceback.format_exc(),
        )
        return CollaborativeCycleOutcome(
            ran=True,
            owned=False,
            fallback_legacy=True,
            event_id=eid,
            error=f"{type(exc).__name__}:{exc}",
            extra={"fail_safe": True},
        )


def link_verification_to_fusion_trace(
    *,
    fused: Optional[FusedDecision],
    trace_path: Optional[str],
    verification_id: Optional[str],
    dpid: Optional[int] = None,
) -> bool:
    """Best-effort second line linking verification_id (non-fatal)."""
    if fused is None or not trace_path or not verification_id:
        return False
    return append_fusion_trace(
        fused,
        trace_path,
        extra={
            "verification_id": verification_id,
            "dpid": dpid,
            "link": "verification",
        },
    )
