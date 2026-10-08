"""
R6.1 adapters — convert live telemetry dicts → shared_contracts.DetectorResult.

Never raise to callers (return ERROR / empty-safe results).
Normalize confidence to [0,1] at the boundary (P0.1).
Do not mutate producer outputs.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from shared_contracts.enums import DetectionDecision, DetectorHealth, DetectorType
from shared_contracts.models import DetectorResult
from shared_contracts.timeutil import utc_now
from fusion.normalize import finite_or_none, to_unit_confidence
from fusion.roles import EvidenceRole

logger = logging.getLogger("intellishield.fusion.adapters")


def _ts(value: Any = None) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    return utc_now()


def _decision_from_status(status: Any, *, default: DetectionDecision = DetectionDecision.NONE) -> DetectionDecision:
    if status is None:
        return default
    key = str(status).strip().upper()
    try:
        return DetectionDecision(key)
    except ValueError:
        return default


def map_detector_health(value: Any = None, *, default: DetectorHealth = DetectorHealth.SUCCESS) -> DetectorHealth:
    """
    Map producer health / exception signals → DetectorHealth.

    Exceptions and explicit unavailable markers are NEVER SUCCESS + NORMAL.
    """
    if value is None:
        return default
    if isinstance(value, DetectorHealth):
        return value
    key = str(value).strip().upper()
    aliases = {
        "OK": DetectorHealth.SUCCESS,
        "HEALTHY": DetectorHealth.SUCCESS,
        "SUCCESS": DetectorHealth.SUCCESS,
        "DEGRADED": DetectorHealth.DEGRADED,
        "WARN": DetectorHealth.DEGRADED,
        "WARNING": DetectorHealth.DEGRADED,
        "ERROR": DetectorHealth.ERROR,
        "FAILED": DetectorHealth.ERROR,
        "FAIL": DetectorHealth.ERROR,
        "UNAVAILABLE": DetectorHealth.ERROR,
        "MISSING": DetectorHealth.ERROR,
    }
    return aliases.get(key, default)


def unavailable(
    detector: DetectorType,
    *,
    reason: str,
    timestamp: Optional[datetime] = None,
) -> DetectorResult:
    return DetectorResult(
        detector=detector,
        timestamp=_ts(timestamp),
        health=DetectorHealth.ERROR,
        decision=DetectionDecision.NONE,
        confidence=None,
        evidence={"availability": "UNAVAILABLE", "reason": reason},
        error_message=reason,
    )


def degraded(
    detector: DetectorType,
    *,
    reason: str,
    decision: DetectionDecision = DetectionDecision.NONE,
    confidence: Optional[float] = None,
    timestamp: Optional[datetime] = None,
    evidence: Optional[Dict[str, Any]] = None,
) -> DetectorResult:
    """Partial/degraded detector output — not a healthy NORMAL vote."""
    ev = {"availability": "DEGRADED", "reason": reason}
    if evidence:
        ev.update(evidence)
    return DetectorResult(
        detector=detector,
        timestamp=_ts(timestamp),
        health=DetectorHealth.DEGRADED,
        decision=decision,
        confidence=to_unit_confidence(confidence) if confidence is not None else None,
        evidence=ev,
        error_message=reason,
    )


def adapt_ml_prediction(
    prediction: Optional[dict] = None,
    *,
    timestamp: Optional[datetime] = None,
    explanation: Optional[dict] = None,
    health: Any = DetectorHealth.SUCCESS,
) -> DetectorResult:
    """ML AnomalyDetector.predict dict → DetectorResult (PRIMARY)."""
    try:
        if not isinstance(prediction, dict) or not prediction:
            return unavailable(DetectorType.ML, reason="ml_prediction_missing", timestamp=timestamp)
        mapped_health = map_detector_health(health)
        if mapped_health is DetectorHealth.ERROR:
            return unavailable(
                DetectorType.ML,
                reason="ml_health_error",
                timestamp=timestamp,
            )
        status = prediction.get("status")
        decision = _decision_from_status(status, default=DetectionDecision.UNKNOWN)
        conf = to_unit_confidence(prediction.get("confidence"))
        score = finite_or_none(prediction.get("iso_score"))
        hint = None
        if isinstance(explanation, dict):
            h = explanation.get("attack_type_hint")
            if isinstance(h, str) and h.strip():
                hint = h.strip()
        evidence = {
            "role": EvidenceRole.PRIMARY_DETECTION.value,
            "raw_status": status,
            "confidence_percent_legacy": prediction.get("confidence"),
            "dt_label": prediction.get("dt_label"),
            "dt_confidence": prediction.get("dt_confidence"),
            "isolation_forest": "embedded_in_ml_not_separate",
        }
        return DetectorResult(
            detector=DetectorType.ML,
            timestamp=_ts(timestamp),
            health=mapped_health,
            decision=decision,
            confidence=conf,
            score=score,
            attack_hint=hint,
            evidence=evidence,
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("[adapt_ml_prediction] failed", exc_info=True)
        return unavailable(DetectorType.ML, reason=f"adapter_error:{exc}", timestamp=timestamp)


def adapt_entropy_metrics(
    entropy_metrics: Optional[dict] = None,
    *,
    timestamp: Optional[datetime] = None,
    health: Any = DetectorHealth.SUCCESS,
) -> DetectorResult:
    """EntropyDetector.analyze dict → DetectorResult (PRIMARY)."""
    try:
        if not isinstance(entropy_metrics, dict) or not entropy_metrics:
            return unavailable(
                DetectorType.ENTROPY, reason="entropy_metrics_missing", timestamp=timestamp
            )
        mapped_health = map_detector_health(health)
        if mapped_health is DetectorHealth.ERROR:
            return unavailable(
                DetectorType.ENTROPY, reason="entropy_health_error", timestamp=timestamp
            )
        status = entropy_metrics.get("status")
        decision = _decision_from_status(status, default=DetectionDecision.NONE)
        conf = to_unit_confidence(entropy_metrics.get("confidence"))
        score = finite_or_none(entropy_metrics.get("entropy_score"))
        return DetectorResult(
            detector=DetectorType.ENTROPY,
            timestamp=_ts(timestamp),
            health=mapped_health,
            decision=decision,
            confidence=conf,
            score=score,
            evidence={
                "role": EvidenceRole.PRIMARY_DETECTION.value,
                "raw_status": status,
                "confidence_percent_legacy": entropy_metrics.get("confidence"),
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("[adapt_entropy_metrics] failed", exc_info=True)
        return unavailable(
            DetectorType.ENTROPY, reason=f"adapter_error:{exc}", timestamp=timestamp
        )


def adapt_correlation_result(
    correlation: Any = None,
    *,
    timestamp: Optional[datetime] = None,
) -> DetectorResult:
    """
    CorrelationResult → DetectorResult (SUPPORTING).

    Correlation is co-occurrence support — decision stays NONE/SUSPICIOUS
    based on score bands; never maps alone to ATTACK.
    """
    try:
        if correlation is None:
            return unavailable(
                DetectorType.CORRELATION,
                reason="correlation_missing",
                timestamp=timestamp,
            )
        score = finite_or_none(getattr(correlation, "score", None))
        evidence_map = getattr(correlation, "evidence", None) or {}
        if not isinstance(evidence_map, dict):
            evidence_map = {}
        status = str(evidence_map.get("status") or "")
        # Supporting only — do not emit ATTACK from correlation alone
        if score is not None and score >= 0.65 and status in (
            "CORRELATED",
            "WEAK_CORRELATED",
        ):
            decision = DetectionDecision.SUSPICIOUS
        elif score is not None and score >= 0.45:
            decision = DetectionDecision.WARNING
        else:
            decision = DetectionDecision.NONE
        ts = getattr(correlation, "timestamp", None) or timestamp
        return DetectorResult(
            detector=DetectorType.CORRELATION,
            timestamp=_ts(ts),
            health=DetectorHealth.SUCCESS,
            decision=decision,
            confidence=score,  # already [0,1] from R4
            score=score,
            evidence={
                "role": EvidenceRole.SUPPORTING_EVIDENCE.value,
                "correlation_id": getattr(correlation, "correlation_id", None),
                "correlation_status": status,
                "participating_categories": evidence_map.get("participating_categories"),
                "focal_entity_key": evidence_map.get("focal_entity_key"),
                "native_contract": "CorrelationResult",
                "note": "Co-occurrence support — not an independent attack detector.",
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("[adapt_correlation_result] failed", exc_info=True)
        return unavailable(
            DetectorType.CORRELATION, reason=f"adapter_error:{exc}", timestamp=timestamp
        )


def adapt_adwin_alerts(
    alerts: Optional[Sequence[dict]] = None,
    *,
    timestamp: Optional[datetime] = None,
) -> DetectorResult:
    """ADWIN drift alerts → DetectorResult (SUPPORTING). Drift ≠ DDoS."""
    try:
        alerts = list(alerts or [])
        if not alerts:
            return DetectorResult(
                detector=DetectorType.ADWIN,
                timestamp=_ts(timestamp),
                health=DetectorHealth.SUCCESS,
                decision=DetectionDecision.NONE,
                confidence=None,
                evidence={
                    "role": EvidenceRole.CONTEXT_ONLY.value,
                    "drift_detected": False,
                    "note": "No drift — distribution change context only when True.",
                },
            )
        metrics = [
            str(a.get("metric_name") or "")
            for a in alerts
            if isinstance(a, dict)
        ]
        return DetectorResult(
            detector=DetectorType.ADWIN,
            timestamp=_ts(timestamp),
            health=DetectorHealth.SUCCESS,
            decision=DetectionDecision.DRIFT,
            confidence=min(1.0, 0.4 + 0.15 * len(alerts)),
            evidence={
                "role": EvidenceRole.CONTEXT_ONLY.value,
                "drift_detected": True,
                "alert_count": len(alerts),
                "metrics": metrics[:8],
                "note": "Distribution changed — not automatically DDoS detected.",
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("[adapt_adwin_alerts] failed", exc_info=True)
        return unavailable(
            DetectorType.ADWIN, reason=f"adapter_error:{exc}", timestamp=timestamp
        )


def adapt_hdbscan_summary(
    summary: Optional[dict] = None,
    *,
    timestamp: Optional[datetime] = None,
) -> DetectorResult:
    """HDBSCAN cluster summary → DetectorResult (SUPPORTING). Outlier ≠ DDoS."""
    try:
        if not isinstance(summary, dict) or not summary:
            return unavailable(
                DetectorType.HDBSCAN, reason="hdbscan_summary_missing", timestamp=timestamp
            )
        n_attack = int(summary.get("n_attack") or 0)
        clusters = summary.get("clusters") or []
        best = "NONE"
        best_conf = None
        for c in clusters if isinstance(clusters, list) else []:
            if not isinstance(c, dict):
                continue
            label = str(c.get("cluster_label") or "").upper()
            if label in ("ATTACK", "SUSPICIOUS", "NOISE"):
                best = label
                best_conf = to_unit_confidence(c.get("confidence"))
                if label == "ATTACK":
                    break
        if n_attack > 0:
            decision = DetectionDecision.SUSPICIOUS  # supporting — not ATTACK
        elif best == "SUSPICIOUS":
            decision = DetectionDecision.SUSPICIOUS
        elif best == "NOISE":
            decision = DetectionDecision.NOISE
        elif best == "ATTACK":
            decision = DetectionDecision.SUSPICIOUS
        else:
            decision = DetectionDecision.NORMAL if summary else DetectionDecision.NONE
        return DetectorResult(
            detector=DetectorType.HDBSCAN,
            timestamp=_ts(timestamp),
            health=DetectorHealth.SUCCESS,
            decision=decision,
            confidence=best_conf if best_conf is not None else (
                min(1.0, n_attack / 3.0) if n_attack else None
            ),
            evidence={
                "role": EvidenceRole.CONTEXT_ONLY.value,
                "n_attack": n_attack,
                "best_label": best,
                "note": "Behavioural outlier/cluster context — not automatically DDoS.",
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("[adapt_hdbscan_summary] failed", exc_info=True)
        return unavailable(
            DetectorType.HDBSCAN, reason=f"adapter_error:{exc}", timestamp=timestamp
        )


def adapt_ssl_unavailable(
    *_args: Any,
    timestamp: Optional[datetime] = None,
    **_kwargs: Any,
) -> DetectorResult:
    """Future R2 SSL adapter stub — always UNAVAILABLE until R2 implements."""
    return unavailable(
        DetectorType.SSL,
        reason="ssl_zero_day_not_implemented_r2_pending",
        timestamp=timestamp,
    )
