"""
Fail-isolated alert emission helpers for controller integration (R8.3).

Alerting must never raise into the mitigation path.
"""

from __future__ import annotations

import logging
import traceback
from typing import Any, Optional

from shared_contracts.models import VerificationResult
from alerting.factory import AlertFactoryContext
from alerting.manager import AlertManager, AlertProcessResult

logger = logging.getLogger("intellishield.alerting.runtime")


def safe_emit_verification_alert(
    manager: Optional[AlertManager],
    result: Optional[VerificationResult],
    context: Optional[AlertFactoryContext] = None,
) -> Optional[AlertProcessResult]:
    """
    Process a VerificationResult through AlertManager.

    Returns the process result, or None on skip/failure.
    Never raises.
    """
    if manager is None or result is None:
        return None
    try:
        return manager.process_verification(result, context)
    except Exception:  # noqa: BLE001
        logger.error(
            "[safe_emit_verification_alert] AlertManager failure (isolated):\n%s",
            traceback.format_exc(),
        )
        return None


def build_runtime_alert_context(
    *,
    dpid: int,
    prediction: dict,
    explanation: dict,
    detector_path: str,
    event_id: Optional[str] = None,
    rca_report_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    fusion_id: Optional[str] = None,
    extra_evidence: Optional[dict] = None,
) -> AlertFactoryContext:
    """
    Build factory context for controller hooks.

    ``source_tag`` is always ``verification`` so ML and entropy paths share
    the same dedup identity for the same attacker/victim/hint (avoids dual-
    path double alerts). Detector path is retained in evidence only.

    R5.3: optional ``rca_report_id`` + small RCA/XAI status fields in evidence
    (prefer references over nested RootCauseReport payloads).

    R4.4: optional ``correlation_id`` + compact score/summary in evidence
    (prefer references over full signal histories).

    R6.4: optional ``fusion_id`` + compact fused decision/confidence/agreement
    (prefer references over nested detector dumps).
    """
    hint = ""
    if isinstance(explanation, dict):
        hint = str(explanation.get("attack_type_hint") or "")
    status = ""
    if isinstance(prediction, dict):
        status = str(prediction.get("status") or "")
    evidence = {
        "detector_path": str(detector_path or ""),
    }
    if extra_evidence:
        for key, value in extra_evidence.items():
            if value is None:
                continue
            evidence[str(key)] = value
    if rca_report_id:
        evidence["rca_report_id"] = str(rca_report_id)
        evidence["rca_linked"] = True
    else:
        evidence.setdefault("rca_linked", False)
    cid = correlation_id or evidence.get("correlation_id")
    if cid:
        evidence["correlation_id"] = str(cid)
        evidence["correlation_linked"] = True
    else:
        evidence.setdefault("correlation_linked", False)
    fid = fusion_id or evidence.get("fusion_id") or (
        prediction.get("fusion_id") if isinstance(prediction, dict) else None
    )
    if fid:
        evidence["fusion_id"] = str(fid)
        evidence["fusion_linked"] = True
        # Compact fields if not already provided via fusion_alert_refs
        if "fused_decision" not in evidence and isinstance(prediction, dict):
            evidence.setdefault("fused_decision", prediction.get("status"))
        if "fused_confidence" not in evidence and isinstance(prediction, dict):
            # prediction confidence is percent; store unit if present on explanation
            if isinstance(explanation, dict) and explanation.get("r6_confidence_unit") is not None:
                evidence.setdefault(
                    "fused_confidence", explanation.get("r6_confidence_unit")
                )
        if "fusion_disagreement" not in evidence and isinstance(prediction, dict):
            evidence.setdefault(
                "fusion_disagreement", bool(prediction.get("disagreement"))
            )
    else:
        evidence.setdefault("fusion_linked", False)
    return AlertFactoryContext(
        dpid=int(dpid),
        source_tag="verification",
        attack_hint=hint,
        prediction_status=status,
        event_id=event_id,
        rca_report_id=rca_report_id,
        correlation_id=str(cid) if cid else None,
        fusion_id=str(fid) if fid else None,
        extra_evidence=evidence,
    )
