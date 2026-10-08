"""
R6.1 DetectionEvent assembly — collect adapted DetectorResults (no fusion).

Does not produce FusedDecision. Does not authorize mitigation.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

from shared_contracts.enums import DetectorHealth, DetectorType
from shared_contracts.models import DetectionEvent, DetectorResult, new_id
from shared_contracts.timeutil import utc_now
from fusion.adapters import (
    adapt_adwin_alerts,
    adapt_correlation_result,
    adapt_entropy_metrics,
    adapt_hdbscan_summary,
    adapt_ml_prediction,
)
from fusion.registry import EvidenceRegistry, build_default_registry
from fusion.roles import EvidenceRole

logger = logging.getLogger("intellishield.fusion.assembly")


def build_detection_event(
    *,
    switch_id: Optional[int] = None,
    src_mac: Optional[str] = None,
    dst_mac: Optional[str] = None,
    event_id: Optional[str] = None,
    timestamp: Optional[datetime] = None,
    ml_prediction: Optional[dict] = None,
    ml_explanation: Optional[dict] = None,
    entropy_metrics: Optional[dict] = None,
    correlation: Any = None,
    adwin_alerts: Optional[Sequence[dict]] = None,
    hdbscan_summary: Optional[dict] = None,
    include_ssl_stub: bool = False,
    registry: Optional[EvidenceRegistry] = None,
    context: Optional[Dict[str, Any]] = None,
) -> DetectionEvent:
    """
    Assemble a DetectionEvent from available cycle evidence.

    Missing sources are omitted or recorded as ERROR/UNAVAILABLE results
    without inventing NORMAL votes.
    """
    reg = registry or build_default_registry()
    ts = timestamp or utc_now()
    results: List[DetectorResult] = []

    # PRIMARY
    if ml_prediction is not None:
        results.append(
            adapt_ml_prediction(
                ml_prediction, timestamp=ts, explanation=ml_explanation
            )
        )
    if entropy_metrics is not None:
        results.append(adapt_entropy_metrics(entropy_metrics, timestamp=ts))

    # SUPPORTING
    if correlation is not None:
        results.append(adapt_correlation_result(correlation, timestamp=ts))
    if adwin_alerts is not None:
        results.append(adapt_adwin_alerts(adwin_alerts, timestamp=ts))
    if hdbscan_summary is not None:
        results.append(adapt_hdbscan_summary(hdbscan_summary, timestamp=ts))
    if include_ssl_stub:
        adapter = reg.adapter_for(DetectorType.SSL)
        if adapter is not None:
            results.append(adapter(timestamp=ts))

    def _ok(r: DetectorResult) -> bool:
        return r.health != DetectorHealth.ERROR

    ctx: Dict[str, Any] = {
        "assembly": "R6.1",
        "fusion_engine": "NOT_RUN",
        "primary_count": sum(
            1
            for r in results
            if reg.role_of(r.detector) == EvidenceRole.PRIMARY_DETECTION and _ok(r)
        ),
        "supporting_count": sum(
            1
            for r in results
            if reg.role_of(r.detector) == EvidenceRole.SUPPORTING_EVIDENCE and _ok(r)
        ),
        "context_count": sum(
            1
            for r in results
            if reg.role_of(r.detector) == EvidenceRole.CONTEXT_ONLY and _ok(r)
        ),
        "note": "Evidence assembly only — CollaborativeFusionEngine is R6.2.",
    }
    if context:
        for k, v in context.items():
            if v is not None:
                ctx[str(k)] = v

    return DetectionEvent(
        event_id=event_id or new_id(),
        timestamp=ts,
        switch_id=switch_id,
        src_mac=src_mac,
        dst_mac=dst_mac,
        detector_results=results,
        context=ctx,
    )
