"""
Fail-isolated XAI+RCA enrichment for verified-event pipeline (R5.3).

Runs inside R8 on_verified fan-out BEFORE mitigation.
Failures never propagate to AlertManager or MitigationEngine.
"""

from __future__ import annotations

import logging
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from shared_contracts.enums import VerificationStatus
from shared_contracts.models import RootCauseReport, VerificationResult
from rca.config import RCAConfig
from rca.context import MitigationEvidence, RCAContext
from rca.engine import RootCauseEngine
from rca.persistence import RCAStore, safe_append_rca

logger = logging.getLogger("intellishield.rca.runtime")


@dataclass
class RuntimeEnrichment:
    """Small enrichment bag for AlertFactoryContext (prefer refs over blobs)."""

    ran: bool = False
    xai_status: str = "NOT_RUN"  # OK|DEGRADED|UNAVAILABLE|NOT_RUN|ERROR|SKIPPED
    rca_status: str = "NOT_RUN"
    rca_report_id: Optional[str] = None
    rca_summary: Optional[str] = None
    xai_summary: Optional[str] = None
    explanation: Any = None
    report: Optional[RootCauseReport] = None
    persisted: bool = False
    extra_evidence: Dict[str, Any] = field(default_factory=dict)


def status_allows_xai_rca(
    status: Any,
    config: Optional[RCAConfig] = None,
) -> bool:
    """
    Default policy: VERIFIED only.

    Rationale: matches R8 default alert_on_pending/ineligible/rejected=False;
    DT path XAI is the expensive step — reserve for security-relevant verified
    events. PENDING/INELIGIBLE/REJECTED skip unless config enables them.
    """
    cfg = config or RCAConfig()
    value = getattr(status, "value", status)
    value = str(value)
    if value == VerificationStatus.VERIFIED.value:
        return bool(cfg.run_on_verified)
    if value == VerificationStatus.PENDING.value:
        return bool(cfg.run_on_pending)
    if value == VerificationStatus.INELIGIBLE.value:
        return bool(cfg.run_on_ineligible)
    if value == VerificationStatus.REJECTED.value:
        return bool(cfg.run_on_rejected)
    return False


def _vector_from_explanation(explanation: Optional[dict]) -> Optional[List[float]]:
    if not isinstance(explanation, dict):
        return None
    summary = explanation.get("vector_summary")
    if not isinstance(summary, dict) or not summary:
        return None
    try:
        from ml_models.feature_builder import FEATURE_NAMES

        out = []
        for name in FEATURE_NAMES:
            if name not in summary:
                return None
            out.append(float(summary[name]))
        return out
    except Exception:  # noqa: BLE001
        return None


def safe_enrich_verified_event(
    *,
    result: Optional[VerificationResult],
    prediction: Optional[dict] = None,
    explanation: Optional[dict] = None,
    feature_vector: Optional[Sequence[float]] = None,
    detector: Any = None,
    entropy_evidence: Optional[Dict[str, Any]] = None,
    mitigation: Optional[MitigationEvidence] = None,
    baseline_evidence: Optional[Dict[str, Any]] = None,
    store: Optional[RCAStore] = None,
    config: Optional[RCAConfig] = None,
    xai_engine: Any = None,
    rca_engine: Optional[RootCauseEngine] = None,
    correlation: Any = None,
    fused_decision: Any = None,
) -> RuntimeEnrichment:
    """
    XAI → RCA → optional persist → enrichment refs.

    Never raises. Never authorizes mitigation.
    """
    cfg = config or RCAConfig()
    out = RuntimeEnrichment()
    if not cfg.enabled:
        out.xai_status = "SKIPPED"
        out.rca_status = "SKIPPED"
        out.extra_evidence = {"rca_status": "SKIPPED", "xai_status": "SKIPPED"}
        return out
    if result is None:
        out.xai_status = "SKIPPED"
        out.rca_status = "SKIPPED"
        return out
    if not status_allows_xai_rca(result.status, cfg):
        out.xai_status = "SKIPPED"
        out.rca_status = "SKIPPED"
        out.extra_evidence = {
            "rca_status": "SKIPPED",
            "xai_status": "SKIPPED",
            "rca_policy": "verified_only_default",
        }
        return out

    out.ran = True
    pred = prediction if isinstance(prediction, dict) else {}
    expl_legacy = explanation if isinstance(explanation, dict) else {}

    # ── XAI (isolated) ──
    prediction_explanation = None
    try:
        from xai import XAIEngine

        engine = xai_engine or XAIEngine()
        vector = (
            list(feature_vector)
            if feature_vector is not None
            else _vector_from_explanation(expl_legacy)
        )
        if detector is not None:
            prediction_explanation = engine.explain_from_detector(
                detector,
                vector,
                pred,
                event_id=result.event_id,
            )
        else:
            prediction_explanation = engine.explain(
                vector,
                pred,
                event_id=result.event_id,
            )
        out.explanation = prediction_explanation
        out.xai_status = getattr(
            prediction_explanation, "status", "OK"
        ) or "OK"
        out.xai_summary = getattr(prediction_explanation, "summary", None)
    except Exception:  # noqa: BLE001
        logger.error(
            "[safe_enrich_verified_event] XAI failed (isolated):\n%s",
            traceback.format_exc(),
        )
        out.xai_status = "ERROR"
        prediction_explanation = None

    # ── RCA (isolated) ──
    report: Optional[RootCauseReport] = None
    try:
        rca = rca_engine or RootCauseEngine(cfg)
        attack_hint = ""
        if expl_legacy.get("attack_type_hint"):
            attack_hint = str(expl_legacy.get("attack_type_hint"))
        elif prediction_explanation is not None:
            attack_hint = str(
                getattr(prediction_explanation, "attack_type_hint", "") or ""
            )

        mit = mitigation
        if mit is None:
            mit = MitigationEvidence(
                eligible=bool(result.mitigation_eligible),
                reason=result.reason or None,
            )

        ctx = RCAContext(
            event_id=str(result.event_id or result.verification_id),
            verification=result,
            explanation=prediction_explanation,
            attack_hint=attack_hint or None,
            entropy_evidence=entropy_evidence,
            mitigation=mit,
            baseline_evidence=baseline_evidence,
            correlation=correlation,
            fused_decision=fused_decision,
        )
        report = rca.analyze(ctx)
        out.report = report
        out.rca_report_id = report.report_id
        summary = report.summary or ""
        if len(summary) > cfg.max_summary_chars:
            summary = summary[: cfg.max_summary_chars - 3] + "..."
        out.rca_summary = summary
        out.rca_status = "OK" if report.confidence and report.confidence > 0 else "DEGRADED"
        if out.xai_status == "ERROR":
            # RCA may still be OK with missing XAI
            missing = (report.contributing_features or {}).get("missing_evidence") or []
            if any(str(m).startswith("xai:") for m in missing):
                out.rca_status = "DEGRADED"
    except Exception:  # noqa: BLE001
        logger.error(
            "[safe_enrich_verified_event] RCA failed (isolated):\n%s",
            traceback.format_exc(),
        )
        out.rca_status = "ERROR"
        out.rca_report_id = None
        out.rca_summary = None
        report = None

    # ── Persist (isolated) ──
    if report is not None and cfg.persist_enabled:
        try:
            out.persisted = safe_append_rca(store, report)
            if store is not None and not out.persisted:
                out.extra_evidence["rca_persist"] = "FAILED"
        except Exception:  # noqa: BLE001
            logger.error(
                "[safe_enrich_verified_event] RCA persist failed (isolated):\n%s",
                traceback.format_exc(),
            )
            out.persisted = False
            out.extra_evidence["rca_persist"] = "ERROR"

    out.extra_evidence.update(
        {
            "rca_status": out.rca_status,
            "xai_status": out.xai_status,
            "rca_persisted": bool(out.persisted),
        }
    )
    if out.rca_summary:
        out.extra_evidence["rca_summary"] = out.rca_summary
    if out.xai_summary:
        # keep short
        xs = out.xai_summary
        if len(xs) > cfg.max_summary_chars:
            xs = xs[: cfg.max_summary_chars - 3] + "..."
        out.extra_evidence["xai_summary"] = xs

    # Compact R4 correlation refs for R8 (prefer refs over histories)
    try:
        from rca.correlation_evidence import correlation_alert_refs

        out.extra_evidence.update(correlation_alert_refs(correlation))
    except Exception:  # noqa: BLE001
        out.extra_evidence.setdefault("correlation_linked", False)

    # Compact R6 fusion refs for R8
    try:
        from rca.fusion_evidence import fusion_alert_refs

        out.extra_evidence.update(fusion_alert_refs(fused_decision))
    except Exception:  # noqa: BLE001
        out.extra_evidence.setdefault("fusion_linked", False)

    return out
