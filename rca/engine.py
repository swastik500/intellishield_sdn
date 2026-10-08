"""
RootCauseEngine — evidence-based RCA → shared_contracts.RootCauseReport.

Fail-safe: never raises to callers; never authorizes mitigation; never invents
baseline or causal claims beyond OBSERVED / INFERRED / UNKNOWN tags.
"""

from __future__ import annotations

import logging
import traceback
from typing import Any, Dict, List, Optional, Tuple

from shared_contracts.enums import VerificationStatus
from shared_contracts.models import RootCauseReport, new_id
from shared_contracts.serialize import to_dict
from shared_contracts.timeutil import utc_now
from rca.confidence import compute_rca_confidence, confidence_breakdown
from rca.config import RCAConfig
from rca.context import RCAContext
from rca.evidence import EvidenceItem, EvidenceKind
from rca.summary import build_summary

logger = logging.getLogger("intellishield.rca")

_DENIED_KEYS = frozenset(
    {
        "password",
        "token",
        "secret",
        "api_key",
        "private_key",
        "credential",
        "authorization",
    }
)


class RootCauseEngine:
    """Build RootCauseReport from RCAContext."""

    def __init__(self, config: Optional[RCAConfig] = None) -> None:
        self.config = config or RCAConfig()

    def analyze(self, context: Optional[RCAContext]) -> RootCauseReport:
        """Primary entry. Never raises."""
        try:
            if not self.config.enabled:
                return self._unavailable(
                    event_id=_safe_event_id(context),
                    reason="rca_disabled",
                )
            if context is None:
                return self._unavailable(event_id="UNKNOWN", reason="null_context")
            return self._analyze_inner(context)
        except Exception:  # noqa: BLE001
            logger.error("[RootCauseEngine.analyze] fail-safe:\n%s", traceback.format_exc())
            return self._unavailable(
                event_id=_safe_event_id(context),
                reason="rca_internal_error",
            )

    def _analyze_inner(self, ctx: RCAContext) -> RootCauseReport:
        items: List[EvidenceItem] = []
        missing: List[str] = []
        refs: List[str] = list(ctx.extra_refs) if ctx.extra_refs else []
        signals: List[str] = []

        # ── Verification ──
        v = ctx.verification
        v_status: Optional[str] = None
        mitigation_eligible: Optional[bool] = None
        if v is None:
            missing.append("verification:NOT_AVAILABLE")
        else:
            refs.append("VerificationResult")
            signals.append("verification")
            v_status = getattr(v.status, "value", str(v.status))
            items.append(
                EvidenceItem(
                    key="verification_status",
                    statement=f"Verification status is {v_status}.",
                    kind=EvidenceKind.OBSERVED.value,
                    value=v_status,
                    source="VerificationResult.status",
                )
            )
            mitigation_eligible = bool(v.mitigation_eligible)
            items.append(
                EvidenceItem(
                    key="mitigation_eligible",
                    statement=(
                        f"Verification recorded mitigation_eligible="
                        f"{mitigation_eligible}."
                    ),
                    kind=EvidenceKind.OBSERVED.value,
                    value=mitigation_eligible,
                    source="VerificationResult.mitigation_eligible",
                )
            )
            if v.reason:
                items.append(
                    EvidenceItem(
                        key="verification_reason",
                        statement=f"Verification reason: {v.reason}.",
                        kind=EvidenceKind.OBSERVED.value,
                        value=v.reason,
                        source="VerificationResult.reason",
                    )
                )
            for stage in v.stages or []:
                signals.append(f"stage:{stage.stage_name}")
                items.append(
                    EvidenceItem(
                        key=f"stage_{stage.stage_name}",
                        statement=(
                            f"Stage {stage.stage_name} passed={stage.passed}"
                            + (f" ({stage.reason})" if stage.reason else "")
                            + "."
                        ),
                        kind=EvidenceKind.OBSERVED.value,
                        value={"passed": stage.passed, "reason": stage.reason},
                        source="VerificationResult.stages",
                    )
                )
            refs.append(f"verification_id:{v.verification_id}")

        # ── Identities (source / target) ──
        source, source_kind, source_src = _resolve_source(ctx)
        target, target_kind, target_src = _resolve_target(ctx)

        if source:
            if source_kind == EvidenceKind.OBSERVED.value:
                stmt = (
                    f"Source MAC {source} appeared in verification/detection "
                    "identity fields (observed identity; not proven causation)."
                )
            else:
                stmt = (
                    f"Source MAC {source} is a suspected attack origin "
                    "(inferred from available identity fields)."
                )
            items.append(
                EvidenceItem(
                    key="suspected_source",
                    statement=stmt,
                    kind=source_kind,
                    value=source,
                    source=source_src,
                )
            )
        else:
            missing.append("source:UNKNOWN")
            items.append(
                EvidenceItem(
                    key="suspected_source",
                    statement="Suspected source is UNKNOWN.",
                    kind=EvidenceKind.UNKNOWN.value,
                    value=None,
                    source="",
                )
            )

        if target:
            items.append(
                EvidenceItem(
                    key="affected_target",
                    statement=(
                        f"Affected target MAC {target} recorded in evidence."
                    ),
                    kind=target_kind,
                    value=target,
                    source=target_src,
                )
            )
        else:
            missing.append("target:UNKNOWN")
            items.append(
                EvidenceItem(
                    key="affected_target",
                    statement="Affected target is UNKNOWN.",
                    kind=EvidenceKind.UNKNOWN.value,
                    value=None,
                    source="",
                )
            )

        # ── Attack hint ──
        hint = _resolve_attack_hint(ctx)
        if hint:
            items.append(
                EvidenceItem(
                    key="attack_hint",
                    statement=(
                        f"Attack classification/hint={hint} "
                        "(inferred heuristic unless supplied as observed label)."
                    ),
                    kind=EvidenceKind.INFERRED.value,
                    value=hint,
                    source=_hint_source(ctx),
                )
            )
            signals.append(f"attack_hint:{hint}")
        else:
            missing.append("attack_hint:NOT_AVAILABLE")

        # ── DetectionEvent ──
        has_detector = False
        if ctx.detection is None:
            missing.append("detection:NOT_AVAILABLE")
        else:
            refs.append("DetectionEvent")
            refs.append(f"event_id:{ctx.detection.event_id}")
            signals.append("detection")
            for dr in ctx.detection.detector_results or []:
                has_detector = True
                det_name = getattr(dr.detector, "value", str(dr.detector))
                decision = getattr(dr.decision, "value", str(dr.decision))
                signals.append(f"detector:{det_name}")
                items.append(
                    EvidenceItem(
                        key=f"detector_{det_name}",
                        statement=(
                            f"Detector {det_name} decision={decision}."
                        ),
                        kind=EvidenceKind.OBSERVED.value,
                        value={
                            "decision": decision,
                            "confidence": dr.confidence,
                            "attack_hint": dr.attack_hint,
                        },
                        source="DetectionEvent.detector_results",
                    )
                )
            if not has_detector:
                missing.append("detector_results:NOT_AVAILABLE")

        # ── Entropy ──
        has_entropy = False
        if ctx.entropy_evidence is None:
            missing.append("entropy:NOT_AVAILABLE")
        else:
            clean_ent = _sanitize_mapping(ctx.entropy_evidence)
            if clean_ent:
                has_entropy = True
                refs.append("entropy_evidence")
                signals.append("entropy")
                items.append(
                    EvidenceItem(
                        key="entropy_evidence",
                        statement="Entropy evidence snapshot supplied by caller.",
                        kind=EvidenceKind.OBSERVED.value,
                        value=clean_ent,
                        source="RCAContext.entropy_evidence",
                    )
                )
            else:
                missing.append("entropy:EMPTY")

        # ── XAI ──
        has_xai = False
        expl_summary: Optional[str] = None
        xai_features: Dict[str, Any] = {}
        if ctx.explanation is None:
            missing.append("xai:NOT_AVAILABLE")
        else:
            expl_dict = _explanation_as_dict(ctx.explanation)
            if expl_dict is None:
                missing.append("xai:MALFORMED")
            else:
                has_xai = True
                refs.append("PredictionExplanation")
                signals.append("xai")
                expl_summary = (
                    expl_dict.get("summary")
                    or expl_dict.get("narrative")
                    or None
                )
                if isinstance(expl_summary, str):
                    expl_summary = expl_summary[:500]
                method = expl_dict.get("method")
                leaf = expl_dict.get("leaf_decision")
                path = expl_dict.get("decision_path") or []
                items.append(
                    EvidenceItem(
                        key="xai_method",
                        statement=f"XAI method={method}.",
                        kind=EvidenceKind.OBSERVED.value,
                        value=method,
                        source="PredictionExplanation.method",
                    )
                )
                if leaf is not None:
                    items.append(
                        EvidenceItem(
                            key="xai_leaf",
                            statement=f"XAI leaf_decision={leaf}.",
                            kind=EvidenceKind.OBSERVED.value,
                            value=leaf,
                            source="PredictionExplanation.leaf_decision",
                        )
                    )
                local = expl_dict.get("local_path_features") or []
                local_names = []
                for f in local:
                    if isinstance(f, dict) and f.get("feature"):
                        local_names.append(str(f["feature"]))
                    elif hasattr(f, "feature"):
                        local_names.append(str(f.feature))
                if local_names:
                    xai_features["local_path_features"] = local_names
                    items.append(
                        EvidenceItem(
                            key="xai_local_path_features",
                            statement=(
                                "XAI local decision-path features: "
                                + ", ".join(local_names)
                                + " (decision-path evidence, not root cause)."
                            ),
                            kind=EvidenceKind.OBSERVED.value,
                            value=local_names,
                            source="PredictionExplanation.local_path_features",
                        )
                    )
                if isinstance(path, list) and path:
                    xai_features["decision_path_steps"] = len(path)

        # ── Mitigation (only if supplied) ──
        mit_strategy: Optional[str] = None
        has_mitigation_evidence = False
        if ctx.mitigation is None:
            missing.append("mitigation:NOT_AVAILABLE")
        else:
            has_mitigation_evidence = True
            refs.append("MitigationEvidence")
            signals.append("mitigation_evidence")
            m = ctx.mitigation
            if m.eligible is not None:
                mitigation_eligible = m.eligible
                items.append(
                    EvidenceItem(
                        key="mitigation_eligible_supplied",
                        statement=(
                            f"Caller-supplied mitigation eligible={m.eligible}."
                        ),
                        kind=EvidenceKind.OBSERVED.value,
                        value=m.eligible,
                        source="MitigationEvidence.eligible",
                    )
                )
            if m.strategy:
                mit_strategy = m.strategy
                items.append(
                    EvidenceItem(
                        key="mitigation_strategy",
                        statement=(
                            f"Mitigation strategy selected/recorded={m.strategy}."
                        ),
                        kind=EvidenceKind.OBSERVED.value,
                        value=m.strategy,
                        source="MitigationEvidence.strategy",
                    )
                )
            if m.result:
                items.append(
                    EvidenceItem(
                        key="mitigation_result",
                        statement=f"Mitigation result={m.result}.",
                        kind=EvidenceKind.OBSERVED.value,
                        value=m.result,
                        source="MitigationEvidence.result",
                    )
                )
            if m.reason:
                items.append(
                    EvidenceItem(
                        key="mitigation_reason",
                        statement=f"Mitigation reason={m.reason}.",
                        kind=EvidenceKind.OBSERVED.value,
                        value=m.reason,
                        source="MitigationEvidence.reason",
                    )
                )

        # ── Optional R4 CorrelationResult (co-occurrence ≠ causation) ──
        corr_features: Dict[str, Any] = {}
        if ctx.correlation is None:
            missing.append("correlation:NOT_AVAILABLE")
            items.append(
                EvidenceItem(
                    key="correlation",
                    statement="Cross-layer correlation evidence is NOT_AVAILABLE.",
                    kind=EvidenceKind.NOT_AVAILABLE.value,
                    value="NOT_AVAILABLE",
                    source="",
                )
            )
        else:
            from rca.correlation_evidence import correlation_evidence_items

            corr_items, corr_signals, corr_features = correlation_evidence_items(
                ctx.correlation
            )
            items.extend(corr_items)
            signals.extend(corr_signals)
            refs.append("CorrelationResult")
            refs.append(f"correlation_id:{ctx.correlation.correlation_id}")

        # ── Optional R6 FusedDecision (collaborative ≠ causation; not ML-XAI) ──
        fusion_features: Dict[str, Any] = {}
        if ctx.fused_decision is None:
            missing.append("fusion:NOT_AVAILABLE")
            items.append(
                EvidenceItem(
                    key="fusion",
                    statement="Collaborative fusion evidence is NOT_AVAILABLE.",
                    kind=EvidenceKind.NOT_AVAILABLE.value,
                    value="NOT_AVAILABLE",
                    source="",
                )
            )
        else:
            from rca.fusion_evidence import fusion_evidence_items

            fus_items, fus_signals, fusion_features = fusion_evidence_items(
                ctx.fused_decision
            )
            items.extend(fus_items)
            signals.extend(fus_signals)
            refs.append("FusedDecision")
            refs.append(f"fusion_id:{ctx.fused_decision.fusion_id}")

        # ── Baseline ──
        has_baseline = False
        baseline_block: Any
        if ctx.baseline_evidence is None:
            baseline_block = "NOT_AVAILABLE"
            missing.append("baseline:NOT_AVAILABLE")
            items.append(
                EvidenceItem(
                    key="baseline_evidence",
                    statement="Baseline evidence is NOT_AVAILABLE.",
                    kind=EvidenceKind.NOT_AVAILABLE.value,
                    value="NOT_AVAILABLE",
                    source="",
                )
            )
        else:
            clean_base = _sanitize_mapping(ctx.baseline_evidence)
            if clean_base:
                has_baseline = True
                baseline_block = clean_base
                refs.append("baseline_evidence")
                signals.append("baseline")
                items.append(
                    EvidenceItem(
                        key="baseline_evidence",
                        statement=(
                            "Baseline evidence supplied; delta statements only "
                            "use these provided values."
                        ),
                        kind=EvidenceKind.OBSERVED.value,
                        value=clean_base,
                        source="RCAContext.baseline_evidence",
                    )
                )
            else:
                baseline_block = "NOT_AVAILABLE"
                missing.append("baseline:EMPTY")

        flags = {
            "has_verification": v is not None,
            "has_source": source is not None,
            "has_target": target is not None,
            "has_xai": has_xai,
            "has_attack_hint": hint is not None,
            "has_detector_or_entropy": has_detector or has_entropy,
            "has_mitigation_evidence": has_mitigation_evidence,
            "has_baseline": has_baseline,
        }
        conf = compute_rca_confidence(config=self.config, **flags)
        breakdown = confidence_breakdown(config=self.config, flags=flags)

        summary = build_summary(
            event_id=ctx.event_id,
            verification_status=v_status,
            suspected_source=source,
            affected_target=target,
            attack_hint=hint,
            mitigation_eligible=mitigation_eligible,
            mitigation_strategy=mit_strategy,
            missing=missing,
            baseline_available=has_baseline,
            rca_confidence=conf,
        )

        contributing_features: Dict[str, Any] = {
            "evidence_items": [i.to_dict() for i in items],
            "missing_evidence": list(missing),
            "baseline_evidence": baseline_block,
            "rca_confidence_policy": {
                "semantics": (
                    "completeness of RCA evidence for explaining the event; "
                    "not ML confidence; not R6 fusion"
                ),
                "breakdown": breakdown,
                "value": conf,
            },
            "attack_hint": hint,
            "verification_status": v_status,
            "mitigation_eligible": mitigation_eligible,
            "mitigation_strategy": mit_strategy,
            "xai": xai_features or "NOT_AVAILABLE",
            "correlation": corr_features or "NOT_AVAILABLE",
            "fusion": fusion_features or "NOT_AVAILABLE",
        }

        # Deduplicate signals preserving order
        seen = set()
        uniq_signals = []
        for s in signals:
            if s not in seen:
                seen.add(s)
                uniq_signals.append(s)

        return RootCauseReport(
            report_id=ctx.report_id or new_id(),
            event_id=ctx.event_id,
            timestamp=utc_now(),
            summary=summary,
            suspected_source=source,
            affected_target=target,
            contributing_signals=uniq_signals,
            contributing_features=contributing_features,
            evidence_refs=refs,
            confidence=conf,
            explanation_summary=expl_summary,
        )

    def _unavailable(self, *, event_id: str, reason: str) -> RootCauseReport:
        eid = event_id if event_id and event_id.strip() else "UNKNOWN"
        return RootCauseReport(
            report_id=new_id(),
            event_id=eid,
            timestamp=utc_now(),
            summary=f"RCA UNAVAILABLE: {reason}.",
            suspected_source=None,
            affected_target=None,
            contributing_signals=[],
            contributing_features={
                "missing_evidence": [reason],
                "baseline_evidence": "NOT_AVAILABLE",
                "rca_confidence_policy": {
                    "semantics": (
                        "completeness of RCA evidence; not ML confidence"
                    ),
                    "value": 0.0,
                },
            },
            evidence_refs=[],
            confidence=0.0,
            explanation_summary=None,
        )


def _safe_event_id(context: Optional[RCAContext]) -> str:
    if context is None:
        return "UNKNOWN"
    try:
        return str(context.event_id)
    except Exception:  # noqa: BLE001
        return "UNKNOWN"


def _resolve_source(ctx: RCAContext) -> Tuple[Optional[str], str, str]:
    if ctx.verification is not None and ctx.verification.attacker_mac:
        return (
            str(ctx.verification.attacker_mac),
            EvidenceKind.OBSERVED.value,
            "VerificationResult.attacker_mac",
        )
    if ctx.detection is not None and ctx.detection.src_mac:
        # Present as flow source identity — suspected origin is INFERRED
        return (
            str(ctx.detection.src_mac),
            EvidenceKind.INFERRED.value,
            "DetectionEvent.src_mac",
        )
    if ctx.source_mac:
        return (
            str(ctx.source_mac),
            EvidenceKind.INFERRED.value,
            "RCAContext.source_mac",
        )
    return None, EvidenceKind.UNKNOWN.value, ""


def _resolve_target(ctx: RCAContext) -> Tuple[Optional[str], str, str]:
    if ctx.verification is not None and ctx.verification.victim_mac:
        return (
            str(ctx.verification.victim_mac),
            EvidenceKind.OBSERVED.value,
            "VerificationResult.victim_mac",
        )
    if ctx.detection is not None and ctx.detection.dst_mac:
        return (
            str(ctx.detection.dst_mac),
            EvidenceKind.OBSERVED.value,
            "DetectionEvent.dst_mac",
        )
    if ctx.target_mac:
        return (
            str(ctx.target_mac),
            EvidenceKind.INFERRED.value,
            "RCAContext.target_mac",
        )
    return None, EvidenceKind.UNKNOWN.value, ""


def _resolve_attack_hint(ctx: RCAContext) -> Optional[str]:
    if ctx.attack_hint and str(ctx.attack_hint).strip():
        h = str(ctx.attack_hint).strip()
        if h not in ("UNKNOWN", "NOT_AVAILABLE", "NORMAL"):
            return h
        if h == "NORMAL":
            return h
    # From explanation
    if ctx.explanation is not None:
        d = _explanation_as_dict(ctx.explanation)
        if d:
            h = d.get("attack_type_hint")
            if h and str(h) not in ("", "NOT_AVAILABLE", "UNKNOWN"):
                return str(h)
    # From detection detectors
    if ctx.detection is not None:
        for dr in ctx.detection.detector_results or []:
            if dr.attack_hint and str(dr.attack_hint) not in ("", "UNKNOWN"):
                return str(dr.attack_hint)
    return None


def _hint_source(ctx: RCAContext) -> str:
    if ctx.attack_hint:
        return "RCAContext.attack_hint"
    if ctx.explanation is not None:
        return "PredictionExplanation.attack_type_hint"
    return "DetectionEvent.detector_results"


def _explanation_as_dict(explanation: Any) -> Optional[Dict[str, Any]]:
    if explanation is None:
        return None
    if isinstance(explanation, dict):
        return _sanitize_mapping(explanation)
    if hasattr(explanation, "to_dict"):
        try:
            return _sanitize_mapping(explanation.to_dict())
        except Exception:  # noqa: BLE001
            return None
    # Attempt shared serialize for dataclasses
    try:
        return _sanitize_mapping(to_dict(explanation))
    except Exception:  # noqa: BLE001
        return None


def _sanitize_mapping(data: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(data, dict):
        return None
    out: Dict[str, Any] = {}
    for k, v in data.items():
        key = str(k)
        if key.lower() in _DENIED_KEYS or any(
            d in key.lower() for d in _DENIED_KEYS
        ):
            continue
        if _is_json_safe(v):
            out[key] = v
    return out


def _is_json_safe(value: Any, depth: int = 0) -> bool:
    if depth > 4:
        return False
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return value == value and value not in (float("inf"), float("-inf"))
    if isinstance(value, list):
        return all(_is_json_safe(v, depth + 1) for v in value)
    if isinstance(value, dict):
        return all(
            isinstance(k, str) and _is_json_safe(v, depth + 1)
            for k, v in value.items()
        )
    return False
