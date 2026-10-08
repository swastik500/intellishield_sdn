"""
Thin runtime helper: adapter → VerificationEngine → optional MitigationEngine.

Keeps controller orchestration small. Does not install OpenFlow itself —
MitigationEngine.handle_alert remains the actuation boundary.
"""

from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from shared_contracts.enums import VerificationStatus
from shared_contracts.models import VerificationResult, VerificationStageResult, new_id
from shared_contracts.timeutil import utc_now
from verification.adapters import build_verification_input
from verification.engine import VerificationEngine
from verification.trace import append_verification_trace

logger = logging.getLogger("intellishield.verification.runtime")

# Optional post-verify hook: alert fan-out lives here so mitigation stays independent.
OnVerifiedFn = Callable[[VerificationResult], None]


@dataclass
class VerifiedMitigationOutcome:
    result: VerificationResult
    handle_alert_called: bool
    trace_written: bool


def _fail_closed_result(
    *,
    event_id: Optional[str],
    reason: str,
) -> VerificationResult:
    return VerificationResult(
        verification_id=new_id(),
        timestamp=utc_now(),
        event_id=event_id,
        status=VerificationStatus.INELIGIBLE,
        confidence=None,
        stages=[
            VerificationStageResult(
                stage_name="RUNTIME_ERROR",
                passed=False,
                reason=reason,
                details={},
            )
        ],
        mitigation_eligible=False,
        reason="verification_runtime_fail_closed",
    )


def run_verified_mitigation(
    *,
    engine: VerificationEngine,
    mitigation: Any,
    dpid: int,
    prediction: Dict[str, Any],
    explanation: Dict[str, Any],
    flow_features: List[dict],
    warmup_cycles_done: int,
    attack_streak: int,
    min_confidence_percent: Optional[float] = None,
    event_id: Optional[str] = None,
    trace_path: Optional[str] = None,
    source_tag: str = "ml",
    on_verified: Optional[OnVerifiedFn] = None,
) -> VerifiedMitigationOutcome:
    """
    Verify, optionally notify (on_verified), then optionally mitigate.

    Fan-out order (independence):
      VerificationResult
            ├─ on_verified(...)   # e.g. AlertManager — fail-isolated
            └─ handle_alert(...)  # MitigationEngine — fail-isolated

    Alert/notify failure never prevents mitigation.
    Mitigation failure never rolls back a prior successful notify.
    Fail-safe: verification exceptions → no handle_alert.
    """
    eid = event_id or new_id()
    try:
        vin = build_verification_input(
            dpid=dpid,
            prediction=prediction,
            explanation=explanation,
            flow_features=flow_features,
            warmup_cycles_done=warmup_cycles_done,
            attack_streak=attack_streak,
            event_id=eid,
            min_confidence_percent=min_confidence_percent,
        )
        result = engine.verify(vin)
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "[run_verified_mitigation] verification failed (fail-closed):\n%s",
            traceback.format_exc(),
        )
        result = _fail_closed_result(
            event_id=eid,
            reason=f"runtime exception: {type(exc).__name__}",
        )

    trace_written = False
    if trace_path:
        trace_written = append_verification_trace(
            result,
            trace_path,
            extra={"dpid": int(dpid), "source_tag": str(source_tag)},
        )

    # Alert / observe fan-out BEFORE mitigation so mitigation exceptions
    # cannot erase an already-recorded alert attempt.
    if on_verified is not None:
        try:
            on_verified(result)
        except Exception:  # noqa: BLE001
            logger.error(
                "[run_verified_mitigation] on_verified failed (isolated):\n%s",
                traceback.format_exc(),
            )

    handle_alert_called = False
    if (
        result.mitigation_eligible
        and mitigation is not None
        and hasattr(mitigation, "handle_alert")
    ):
        try:
            mitigation.handle_alert(
                dpid=dpid,
                prediction=prediction,
                explanation=explanation,
                flow_features=flow_features,
            )
            handle_alert_called = True
        except Exception:
            logger.error(
                "[run_verified_mitigation] handle_alert error:\n%s",
                traceback.format_exc(),
            )

    return VerifiedMitigationOutcome(
        result=result,
        handle_alert_called=handle_alert_called,
        trace_written=trace_written,
    )
