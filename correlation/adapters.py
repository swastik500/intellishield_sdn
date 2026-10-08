"""
R4.3 adapters — convert live IntelliShield telemetry dicts → SignalEvent.

Never raise to callers (return [] / skip on malformed).
Do not mutate producer outputs.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from correlation.categories import SignalCategory
from correlation.identity import build_entity_key
from correlation.models import SignalEvent, new_signal_id
from shared_contracts.timeutil import utc_now

logger = logging.getLogger("intellishield.correlation.adapters")


def _now(ts: Any = None) -> datetime:
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts
    return utc_now()


def _safe_float(value: Any) -> Optional[float]:
    try:
        if value is None or isinstance(value, bool):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def dominant_flow_entity(feature_batch: Sequence[dict], switch_id: int) -> Optional[str]:
    """Entity key from highest packet_rate flow (deterministic tie-break on src_mac)."""
    best = None
    best_rate = -1.0
    best_src = ""
    for feat in feature_batch or []:
        if not isinstance(feat, dict):
            continue
        rate = _safe_float(feat.get("packet_rate")) or 0.0
        src = str(feat.get("src_mac") or "")
        if rate > best_rate or (rate == best_rate and src < best_src):
            best_rate = rate
            best_src = src
            best = feat
    if best is None:
        return build_entity_key(switch_id=switch_id)
    return build_entity_key(
        src_mac=best.get("src_mac"),
        dst_mac=best.get("dst_mac"),
        switch_id=int(best.get("switch_id", switch_id)),
        in_port=best.get("in_port"),
    )


def from_flow_features(
    feature_batch: Sequence[dict],
    *,
    switch_id: int,
    timestamp: Optional[datetime] = None,
    max_flows: int = 3,
) -> List[SignalEvent]:
    """DATA_PLANE signals from OF flow feature dicts (in-memory only)."""
    out: List[SignalEvent] = []
    ts = _now(timestamp)
    try:
        out.append(
            SignalEvent(
                signal_id=new_signal_id(),
                timestamp=ts,
                category=SignalCategory.DATA_PLANE,
                source="flow_stats",
                name="active_flow_count",
                value=len(list(feature_batch or [])),
                unit="count",
                switch_id=switch_id,
                entity_key=build_entity_key(switch_id=switch_id),
            )
        )
        # Top flows by packet_rate for volume evidence (capped)
        ranked = []
        for feat in feature_batch or []:
            if not isinstance(feat, dict):
                continue
            rate = _safe_float(feat.get("packet_rate"))
            if rate is None:
                continue
            ranked.append((rate, str(feat.get("src_mac") or ""), feat))
        ranked.sort(key=lambda t: (-t[0], t[1]))
        for rate, _, feat in ranked[: max(0, max_flows)]:
            ek = build_entity_key(
                src_mac=feat.get("src_mac"),
                dst_mac=feat.get("dst_mac"),
                switch_id=int(feat.get("switch_id", switch_id)),
                in_port=feat.get("in_port"),
            )
            # Soft anomaly hint vs lab-typical baseline 100 pkt/s (documented)
            baseline = 100.0
            strength = max(0.0, min(1.0, (rate - baseline) / (baseline * 4.0)))
            out.append(
                SignalEvent(
                    signal_id=new_signal_id(),
                    timestamp=ts,
                    category=SignalCategory.DATA_PLANE,
                    source="flow_stats",
                    name="packet_rate",
                    value=rate,
                    unit="pkt/s",
                    switch_id=switch_id,
                    entity_key=ek,
                    normalized_score=strength if strength > 0 else None,
                    evidence={"baseline": baseline, "strength": strength},
                )
            )
            br = _safe_float(feat.get("byte_rate"))
            if br is not None:
                b_base = 50_000.0
                b_strength = max(0.0, min(1.0, (br - b_base) / (b_base * 4.0)))
                out.append(
                    SignalEvent(
                        signal_id=new_signal_id(),
                        timestamp=ts,
                        category=SignalCategory.DATA_PLANE,
                        source="flow_stats",
                        name="byte_rate",
                        value=br,
                        unit="B/s",
                        switch_id=switch_id,
                        entity_key=ek,
                        normalized_score=b_strength if b_strength > 0 else None,
                        evidence={"baseline": b_base, "strength": b_strength},
                    )
                )
    except Exception:  # noqa: BLE001
        logger.debug("[from_flow_features] skip malformed batch", exc_info=True)
    return out


def from_entropy(
    entropy_metrics: Optional[dict],
    *,
    switch_id: int,
    timestamp: Optional[datetime] = None,
    entity_key: Optional[str] = None,
) -> List[SignalEvent]:
    if not isinstance(entropy_metrics, dict) or not entropy_metrics:
        return []
    out: List[SignalEvent] = []
    ts = _now(timestamp)
    ek = entity_key or build_entity_key(switch_id=switch_id)
    try:
        score = _safe_float(entropy_metrics.get("entropy_score"))
        if score is not None:
            out.append(
                SignalEvent(
                    signal_id=new_signal_id(),
                    timestamp=ts,
                    category=SignalCategory.DETECTION,
                    source="entropy",
                    name="entropy_score",
                    value=score,
                    unit="nats_norm",
                    switch_id=switch_id,
                    entity_key=ek,
                )
            )
        status = entropy_metrics.get("status")
        if isinstance(status, str) and status.strip():
            out.append(
                SignalEvent(
                    signal_id=new_signal_id(),
                    timestamp=ts,
                    category=SignalCategory.DETECTION,
                    source="entropy",
                    name="status",
                    value=status.strip().upper(),
                    switch_id=switch_id,
                    entity_key=ek,
                )
            )
        conf = _safe_float(entropy_metrics.get("confidence"))
        if conf is not None:
            out.append(
                SignalEvent(
                    signal_id=new_signal_id(),
                    timestamp=ts,
                    category=SignalCategory.DETECTION,
                    source="entropy",
                    name="confidence",
                    value=conf,
                    unit="percent",
                    switch_id=switch_id,
                    entity_key=ek,
                )
            )
    except Exception:  # noqa: BLE001
        logger.debug("[from_entropy] skip", exc_info=True)
    return out


def from_ml_prediction(
    prediction: Optional[dict],
    *,
    switch_id: int,
    timestamp: Optional[datetime] = None,
    entity_key: Optional[str] = None,
    explanation: Optional[dict] = None,
) -> List[SignalEvent]:
    if not isinstance(prediction, dict) or not prediction:
        return []
    out: List[SignalEvent] = []
    ts = _now(timestamp)
    ek = entity_key or build_entity_key(switch_id=switch_id)
    try:
        status = prediction.get("status")
        if isinstance(status, str) and status.strip():
            out.append(
                SignalEvent(
                    signal_id=new_signal_id(),
                    timestamp=ts,
                    category=SignalCategory.DETECTION,
                    source="ml",
                    name="status",
                    value=status.strip().upper(),
                    switch_id=switch_id,
                    entity_key=ek,
                )
            )
        conf = _safe_float(prediction.get("confidence"))
        if conf is not None:
            out.append(
                SignalEvent(
                    signal_id=new_signal_id(),
                    timestamp=ts,
                    category=SignalCategory.DETECTION,
                    source="ml",
                    name="confidence",
                    value=conf,
                    unit="percent",
                    switch_id=switch_id,
                    entity_key=ek,
                )
            )
        iso = _safe_float(prediction.get("iso_score"))
        if iso is not None:
            out.append(
                SignalEvent(
                    signal_id=new_signal_id(),
                    timestamp=ts,
                    category=SignalCategory.DETECTION,
                    source="ml",
                    name="iso_score",
                    value=iso,
                    switch_id=switch_id,
                    entity_key=ek,
                )
            )
        if isinstance(explanation, dict):
            hint = explanation.get("attack_type_hint")
            if isinstance(hint, str) and hint.strip():
                out.append(
                    SignalEvent(
                        signal_id=new_signal_id(),
                        timestamp=ts,
                        category=SignalCategory.DETECTION,
                        source="ml",
                        name="attack_type_hint",
                        value=hint.strip(),
                        switch_id=switch_id,
                        entity_key=ek,
                    )
                )
    except Exception:  # noqa: BLE001
        logger.debug("[from_ml_prediction] skip", exc_info=True)
    return out


def from_controller_stats(
    row: Optional[dict],
    *,
    timestamp: Optional[datetime] = None,
) -> List[SignalEvent]:
    if not isinstance(row, dict) or not row:
        return []
    out: List[SignalEvent] = []
    ts = _now(timestamp)
    try:
        cpu = _safe_float(row.get("cpu_percent"))
        if cpu is not None:
            out.append(
                SignalEvent(
                    signal_id=new_signal_id(),
                    timestamp=ts,
                    category=SignalCategory.CONTROL_PLANE,
                    source="controller_stats",
                    name="cpu_percent",
                    value=cpu,
                    unit="percent",
                )
            )
        mem = _safe_float(row.get("memory_percent"))
        if mem is not None:
            out.append(
                SignalEvent(
                    signal_id=new_signal_id(),
                    timestamp=ts,
                    category=SignalCategory.CONTROL_PLANE,
                    source="controller_stats",
                    name="memory_percent",
                    value=mem,
                    unit="percent",
                )
            )
        rss = _safe_float(row.get("memory_rss_mb"))
        if rss is not None:
            out.append(
                SignalEvent(
                    signal_id=new_signal_id(),
                    timestamp=ts,
                    category=SignalCategory.CONTROL_PLANE,
                    source="controller_stats",
                    name="memory_rss_mb",
                    value=rss,
                    unit="MB",
                    evidence={"strength": min(1.0, rss / 1024.0)},
                    normalized_score=min(1.0, rss / 1024.0),
                )
            )
    except Exception:  # noqa: BLE001
        logger.debug("[from_controller_stats] skip", exc_info=True)
        return []
    if not out:
        # Explicit missing optional plane
        out.append(
            SignalEvent(
                signal_id=new_signal_id(),
                timestamp=ts,
                category=SignalCategory.CONTROL_PLANE,
                source="controller_stats",
                name="cpu_percent",
                value=None,
                availability="NOT_AVAILABLE",
                evidence={"reason": "empty_row"},
            )
        )
    return out


def from_adwin_alerts(
    alerts: Optional[Sequence[dict]],
    *,
    switch_id: int,
    timestamp: Optional[datetime] = None,
) -> List[SignalEvent]:
    out: List[SignalEvent] = []
    ts = _now(timestamp)
    ek = build_entity_key(switch_id=switch_id)
    try:
        for alert in alerts or []:
            if not isinstance(alert, dict):
                continue
            metric = str(alert.get("metric_name") or "unknown")
            out.append(
                SignalEvent(
                    signal_id=new_signal_id(),
                    timestamp=ts,
                    category=SignalCategory.DRIFT_CLUSTERING,
                    source="adwin",
                    name="drift_alert",
                    value=True,
                    switch_id=switch_id,
                    entity_key=ek,
                    evidence={
                        "metric_name": metric,
                        "old_mean": alert.get("old_mean"),
                        "new_mean": alert.get("new_mean"),
                    },
                )
            )
    except Exception:  # noqa: BLE001
        logger.debug("[from_adwin_alerts] skip", exc_info=True)
    return out


def from_hdbscan_summary(
    summary: Optional[dict],
    *,
    switch_id: int,
    timestamp: Optional[datetime] = None,
) -> List[SignalEvent]:
    if not isinstance(summary, dict) or not summary:
        return []
    out: List[SignalEvent] = []
    ts = _now(timestamp)
    ek = build_entity_key(switch_id=switch_id)
    try:
        clusters = summary.get("clusters") or []
        # Prefer strongest non-NORMAL label if any
        best_label = None
        best_conf = -1.0
        for c in clusters:
            if not isinstance(c, dict):
                continue
            label = str(c.get("cluster_label") or "").upper()
            conf = _safe_float(c.get("confidence")) or 0.0
            if label in ("ATTACK", "SUSPICIOUS", "NOISE") and conf >= best_conf:
                best_conf = conf
                best_label = label
        if best_label:
            out.append(
                SignalEvent(
                    signal_id=new_signal_id(),
                    timestamp=ts,
                    category=SignalCategory.DRIFT_CLUSTERING,
                    source="hdbscan",
                    name="cluster_label",
                    value=best_label,
                    switch_id=switch_id,
                    entity_key=ek,
                )
            )
            if best_conf >= 0:
                out.append(
                    SignalEvent(
                        signal_id=new_signal_id(),
                        timestamp=ts,
                        category=SignalCategory.DRIFT_CLUSTERING,
                        source="hdbscan",
                        name="confidence",
                        value=best_conf,
                        switch_id=switch_id,
                        entity_key=ek,
                    )
                )
        n_attack = summary.get("n_attack")
        if n_attack is not None:
            out.append(
                SignalEvent(
                    signal_id=new_signal_id(),
                    timestamp=ts,
                    category=SignalCategory.DRIFT_CLUSTERING,
                    source="hdbscan",
                    name="n_attack",
                    value=int(n_attack),
                    switch_id=switch_id,
                    entity_key=ek,
                    evidence={
                        "strength": min(1.0, float(n_attack) / 3.0),
                    },
                    normalized_score=min(1.0, float(n_attack) / 3.0),
                )
            )
    except Exception:  # noqa: BLE001
        logger.debug("[from_hdbscan_summary] skip", exc_info=True)
    return out
