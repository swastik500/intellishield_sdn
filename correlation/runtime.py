"""
R4.3 fail-isolated runtime correlation (advisory only).

Never authorizes mitigation. Never raises to the controller.
No disk reads on the decision path (persist is append-only write).
"""

from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

from shared_contracts.models import CorrelationResult
from correlation.adapters import (
    dominant_flow_entity,
    from_adwin_alerts,
    from_controller_stats,
    from_entropy,
    from_flow_features,
    from_hdbscan_summary,
    from_ml_prediction,
)
from correlation.config import CorrelationConfig
from correlation.engine import CorrelationEngine
from correlation.models import SignalEvent
from correlation.persistence import CorrelationStore, safe_append_correlation

logger = logging.getLogger("intellishield.correlation.runtime")


@dataclass
class RuntimeCorrelationOutcome:
    ran: bool = False
    status: str = "NOT_RUN"  # OK|EMPTY|ERROR|SKIPPED
    result: Optional[CorrelationResult] = None
    persisted: bool = False
    signal_count: int = 0
    error: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CorrelationRuntimeConfig:
    enabled: bool = True
    persist: bool = True
    # Do not correlate empty feature batches (noise)
    require_flows: bool = False


def build_cycle_signals(
    *,
    switch_id: int,
    feature_batch: Optional[Sequence[dict]] = None,
    entropy: Optional[dict] = None,
    prediction: Optional[dict] = None,
    explanation: Optional[dict] = None,
    controller_stats: Optional[dict] = None,
    drift_alerts: Optional[Sequence[dict]] = None,
    cluster_summary: Optional[dict] = None,
    timestamp: Optional[datetime] = None,
) -> List[SignalEvent]:
    """Assemble SignalEvents from in-memory cycle telemetry. Never raises."""
    signals: List[SignalEvent] = []
    try:
        batch = list(feature_batch or [])
        entity = dominant_flow_entity(batch, switch_id)
        signals.extend(
            from_flow_features(batch, switch_id=switch_id, timestamp=timestamp)
        )
        signals.extend(
            from_entropy(
                entropy, switch_id=switch_id, timestamp=timestamp, entity_key=entity
            )
        )
        signals.extend(
            from_ml_prediction(
                prediction,
                switch_id=switch_id,
                timestamp=timestamp,
                entity_key=entity,
                explanation=explanation,
            )
        )
        signals.extend(from_controller_stats(controller_stats, timestamp=timestamp))
        signals.extend(
            from_adwin_alerts(
                drift_alerts, switch_id=switch_id, timestamp=timestamp
            )
        )
        signals.extend(
            from_hdbscan_summary(
                cluster_summary, switch_id=switch_id, timestamp=timestamp
            )
        )
    except Exception:  # noqa: BLE001
        logger.warning("[build_cycle_signals] isolated failure", exc_info=True)
    return signals


def safe_correlate_cycle(
    *,
    engine: Optional[CorrelationEngine] = None,
    store: Optional[CorrelationStore] = None,
    config: Optional[CorrelationRuntimeConfig] = None,
    switch_id: int,
    feature_batch: Optional[Sequence[dict]] = None,
    entropy: Optional[dict] = None,
    prediction: Optional[dict] = None,
    explanation: Optional[dict] = None,
    controller_stats: Optional[dict] = None,
    drift_alerts: Optional[Sequence[dict]] = None,
    cluster_summary: Optional[dict] = None,
    event_id: Optional[str] = None,
    entity_key: Optional[str] = None,
    correlation_config: Optional[CorrelationConfig] = None,
) -> RuntimeCorrelationOutcome:
    """
    Build signals → CorrelationEngine.correlate → optional JSONL append.

    Failures are isolated. Does not call MitigationEngine / OpenFlow.
    """
    out = RuntimeCorrelationOutcome()
    cfg = config or CorrelationRuntimeConfig()
    if not cfg.enabled:
        out.status = "SKIPPED"
        return out

    try:
        if cfg.require_flows and not feature_batch:
            out.status = "SKIPPED"
            out.extra["reason"] = "no_flows"
            return out

        signals = build_cycle_signals(
            switch_id=switch_id,
            feature_batch=feature_batch,
            entropy=entropy,
            prediction=prediction,
            explanation=explanation,
            controller_stats=controller_stats,
            drift_alerts=drift_alerts,
            cluster_summary=cluster_summary,
        )
        out.signal_count = len(signals)

        eng = engine or CorrelationEngine(correlation_config or CorrelationConfig())
        focal = entity_key or dominant_flow_entity(
            list(feature_batch or []), switch_id
        )

        try:
            result = eng.correlate(
                signals,
                entity_key=focal,
                event_id=event_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "[safe_correlate_cycle] engine failed (isolated):\n%s",
                traceback.format_exc(),
            )
            out.status = "ERROR"
            out.error = str(exc)
            out.ran = True
            return out

        out.ran = True
        out.result = result
        out.status = str((result.evidence or {}).get("status") or "OK")

        if result is not None:
            try:
                ev = dict(result.evidence or {})
                ev["advisory_only"] = True
                ev["runtime_hook"] = "R4.3"
                ev["switch_id"] = int(switch_id)
                ev["mitigation_authorized"] = False
                result = replace(result, evidence=ev)
                out.result = result
            except Exception:  # noqa: BLE001
                pass

        if cfg.persist and store is not None and result is not None:
            out.persisted = safe_append_correlation(store, result)

        return out
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "[safe_correlate_cycle] outer failure (isolated):\n%s",
            traceback.format_exc(),
        )
        out.status = "ERROR"
        out.error = str(exc)
        return out
