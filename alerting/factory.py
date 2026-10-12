"""
AlertFactory — build FOUNDATION AlertEvent from VerificationResult.

Severity via injectable SeverityPolicy (R8.2). AlertEvent schema unchanged.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

from shared_contracts.enums import AlertType, VerificationStatus
from shared_contracts.models import AlertEvent, VerificationResult, new_id
from shared_contracts.timeutil import utc_now
from alerting.config import AlertingConfig
from alerting.severity import (
    DefaultSeverityPolicy,
    SeverityEvidence,
    SeverityPolicy,
)

logger = logging.getLogger("intellishield.alerting.factory")


@dataclass(frozen=True)
class AlertFactoryContext:
    """Optional controller/detector context accompanying a VerificationResult."""

    dpid: Optional[int] = None
    source_tag: str = "verification"
    attack_hint: str = ""
    prediction_status: str = ""
    mitigation_ref: Optional[str] = None
    mitigation_status: Optional[str] = None
    rca_report_id: Optional[str] = None
    correlation_id: Optional[str] = None
    fusion_id: Optional[str] = None
    alert_id: Optional[str] = None
    event_id: Optional[str] = None
    extra_evidence: Optional[Dict[str, Any]] = None


def build_dedup_key(
    *,
    alert_type: AlertType,
    source: str,
    attacker_mac: Optional[str],
    victim_mac: Optional[str],
    attack_hint: str,
) -> str:
    """
    Stable dedup key — fixed-order pipe-joined components (no dict ordering).
    """
    parts = [
        str(getattr(alert_type, "value", alert_type)),
        str(source or ""),
        str(attacker_mac or ""),
        str(victim_mac or ""),
        str(attack_hint or "UNKNOWN"),
    ]
    return "|".join(parts)


def map_alert_type(result: VerificationResult) -> AlertType:
    if result.mitigation_eligible:
        return AlertType.MITIGATION
    status = result.status
    if status == VerificationStatus.PENDING or status == VerificationStatus.VERIFIED:
        return AlertType.DETECTION
    if status == VerificationStatus.INELIGIBLE:
        return AlertType.DETECTION
    return AlertType.SYSTEM


class AlertFactory:
    """Construct AlertEvent instances from R7 VerificationResult."""

    def __init__(
        self,
        config: Optional[AlertingConfig] = None,
        severity_policy: Optional[SeverityPolicy] = None,
    ) -> None:
        self.config = config or AlertingConfig()
        self.severity_policy: SeverityPolicy = severity_policy or DefaultSeverityPolicy(
            critical_confidence=self.config.severity_critical_confidence,
            high_confidence=self.config.severity_high_confidence,
        )

    def should_create(self, result: VerificationResult) -> bool:
        status = result.status
        if status == VerificationStatus.VERIFIED:
            return True
        if status == VerificationStatus.PENDING:
            return bool(self.config.alert_on_pending)
        if status == VerificationStatus.INELIGIBLE:
            return bool(self.config.alert_on_ineligible)
        if status == VerificationStatus.REJECTED:
            return bool(self.config.alert_on_rejected)
        return False

    def from_verification(
        self,
        result: VerificationResult,
        context: Optional[AlertFactoryContext] = None,
    ) -> Optional[AlertEvent]:
        if not self.config.enabled:
            logger.info("[DIAG] AlertFactory: config disabled, returning None")
            return None
        if not self.should_create(result):
            logger.info("[DIAG] AlertFactory: should_create=False for status=%s, returning None", getattr(result, "status", "?"))
            return None

        ctx = context or AlertFactoryContext()
        attack_hint = ctx.attack_hint or _hint_from_stages(result)
        evidence = SeverityEvidence.from_verification(result, attack_hint=attack_hint)
        severity = self.severity_policy.assign(evidence)
        alert_type = map_alert_type(result)
        source = ctx.source_tag or self.config.default_source

        dedup_key = build_dedup_key(
            alert_type=alert_type,
            source=source,
            attacker_mac=result.attacker_mac,
            victim_mac=result.victim_mac,
            attack_hint=attack_hint,
        )

        status_v = getattr(result.status, "value", result.status)
        title = _title(status_v, attack_hint, result.mitigation_eligible)
        message = (
            f"verification={status_v} eligible={bool(result.mitigation_eligible)} "
            f"reason={result.reason or ''}"
        ).strip()

        evidence_map = self._safe_evidence(
            {
                "verification_id": result.verification_id,
                "verification_status": status_v,
                "mitigation_eligible": bool(result.mitigation_eligible),
                "reason": result.reason or "",
                "confidence": result.confidence,
                "attacker_mac": result.attacker_mac or "",
                "victim_mac": result.victim_mac or "",
                "attack_hint": attack_hint,
                "dpid": ctx.dpid,
                "prediction_status": ctx.prediction_status or "",
                "stage_count": len(result.stages or []),
            },
            ctx.extra_evidence,
        )

        logger.info("[DIAG] AlertFactory: created alert alert_id=%s type=%s severity=%s hint=%s", 
                   new_id(), alert_type, severity, attack_hint)
        return AlertEvent(
            alert_id=(ctx.alert_id or new_id()),
            timestamp=utc_now(),
            severity=severity,
            alert_type=alert_type,
            title=title,
            message=message,
            event_id=ctx.event_id if ctx.event_id is not None else result.event_id,
            source=source,
            rca_report_id=ctx.rca_report_id,
            mitigation_ref=ctx.mitigation_ref,
            mitigation_status=ctx.mitigation_status,
            dedup_key=dedup_key,
            evidence=evidence_map,
        )

    def _safe_evidence(
        self,
        base: Dict[str, Any],
        extra: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        denied = {k.lower() for k in self.config.evidence_denied_keys}
        out: Dict[str, Any] = {}
        for key, value in base.items():
            if str(key).lower() in denied:
                continue
            if value is None:
                continue
            out[str(key)] = value
        if extra:
            for key, value in extra.items():
                lk = str(key).lower()
                if lk in denied:
                    continue
                if value is None:
                    continue
                out[str(key)] = value
        return out


def _hint_from_stages(result: VerificationResult) -> str:
    for stage in reversed(list(result.stages or [])):
        details = getattr(stage, "details", None) or {}
        hint = details.get("attack_hint")
        if hint:
            return str(hint)
    return ""


def _title(status: str, attack_hint: str, eligible: bool) -> str:
    hint = attack_hint or "UNKNOWN"
    if eligible:
        return f"Mitigation-eligible attack ({hint})"
    if status == VerificationStatus.PENDING.value:
        return f"Attack pending confirmation ({hint})"
    return f"Verification {status} ({hint})"
