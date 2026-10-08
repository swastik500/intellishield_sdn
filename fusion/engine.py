"""
R6.2 CollaborativeFusionEngine — reliability-aware evidence fusion.

Produces shared_contracts.FusedDecision only.
Does NOT mitigate, does NOT call OpenFlow / blocklist, does NOT wire production.

Mathematical summary (see IMPLEMENTED/R6_2_RELIABILITY_AWARE_FUSION.md):

  w_i = ρ_i × h_i                         # effective weight
  A = Σ w_i a_i / Σ w_i                   # attack support
  N = Σ w_i n_i / Σ w_i                   # normal support
  S0 = A − N                              # signed primary score
  C = conflict among primary polarities   # ∈ [0,1]
  S1 = S0 × (1 − δ C)                     # disagreement shrink
  S2 = S1 + β R (1−|S1|) if attack-lean   # R4 support (gated)
  S  = S2 × (1 − γ U)                     # context uncertainty shrink

  Map S → DetectionDecision via thresholds; never invent ATTACK from
  correlation/context alone when all primaries are NORMAL-like.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from shared_contracts.enums import DetectionDecision, DetectorHealth, DetectorType
from shared_contracts.models import (
    CorrelationResult,
    DetectorResult,
    FusedDecision,
    new_id,
)
from shared_contracts.timeutil import ensure_utc, utc_now
from fusion.config import FusionConfig
from fusion.evidence import entity_key_from
from fusion.normalize import to_unit_confidence
from fusion.registry import EvidenceRegistry, build_default_registry
from fusion.roles import EvidenceRole

logger = logging.getLogger("intellishield.fusion.engine")

# Primary decisions that count as attack-leaning polarity
_ATTACK_LIKE = frozenset(
    {
        DetectionDecision.ATTACK,
        DetectionDecision.ALERT,
    }
)
_NORMAL_LIKE = frozenset({DetectionDecision.NORMAL})
_PARTIAL_LIKE = frozenset(
    {
        DetectionDecision.SUSPICIOUS,
        DetectionDecision.WARNING,
    }
)


@dataclass(frozen=True)
class _PrimaryVote:
    detector: str
    decision: str
    confidence: float
    base_reliability: float
    health: str
    health_factor: float
    weight: float
    attack_polarity: float
    normal_polarity: float
    camp: str  # "ATTACK" | "NORMAL" | "PARTIAL" | "NONE"


class CollaborativeFusionEngine:
    """
    Fuse available detector evidence into one FusedDecision.

    Fail-safe: exceptions → NONE / ERROR evidence, never ATTACK.
    """

    def __init__(
        self,
        config: Optional[FusionConfig] = None,
        registry: Optional[EvidenceRegistry] = None,
    ) -> None:
        self.config = config or FusionConfig()
        self.config.validate()
        self.registry = registry or build_default_registry()

    def fuse(
        self,
        *,
        detector_results: Optional[Sequence[DetectorResult]] = None,
        correlation: Optional[CorrelationResult] = None,
        event_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        entity_key: Optional[str] = None,
        switch_id: Optional[int] = None,
        src_mac: Optional[str] = None,
        dst_mac: Optional[str] = None,
        fusion_id: Optional[str] = None,
    ) -> FusedDecision:
        """
        Reliability-aware fusion over provided results (+ optional correlation).

        Missing / ERROR / stale primaries do not vote NORMAL.
        """
        try:
            return self._fuse_impl(
                detector_results=list(detector_results or []),
                correlation=correlation,
                event_id=event_id,
                timestamp=timestamp,
                entity_key=entity_key,
                switch_id=switch_id,
                src_mac=src_mac,
                dst_mac=dst_mac,
                fusion_id=fusion_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("[CollaborativeFusionEngine.fuse] failed", exc_info=True)
            return FusedDecision(
                fusion_id=fusion_id or new_id(),
                timestamp=ensure_utc(timestamp or utc_now()),
                event_id=event_id,
                decision=DetectionDecision.NONE,
                confidence=None,
                participating=[],
                disagreement=False,
                reason=f"fusion_error:{exc}",
                evidence={
                    "status": "ERROR",
                    "fail_safe": True,
                    "note": "Fusion failure must not authorize mitigation.",
                },
            )

    # ── core ────────────────────────────────────────────────────────────

    def _fuse_impl(
        self,
        *,
        detector_results: List[DetectorResult],
        correlation: Optional[CorrelationResult],
        event_id: Optional[str],
        timestamp: Optional[datetime],
        entity_key: Optional[str],
        switch_id: Optional[int],
        src_mac: Optional[str],
        dst_mac: Optional[str],
        fusion_id: Optional[str],
    ) -> FusedDecision:
        cfg = self.config
        now = ensure_utc(timestamp or utc_now())
        scope = entity_key_from(
            entity_key=entity_key,
            switch_id=switch_id,
            src_mac=src_mac,
            dst_mac=dst_mac,
        )

        # Deterministic order: by detector type name (insertion-order invariant)
        ordered = sorted(detector_results, key=lambda r: r.detector.value)

        missing_primary = self._missing_primaries(ordered)
        degraded: List[str] = []
        unavailable: List[str] = []
        stale: List[str] = []
        cross_entity: List[str] = []
        primary_votes: List[_PrimaryVote] = []
        context_notes: List[Dict[str, Any]] = []
        corr_view: Optional[DetectorResult] = None

        for r in ordered:
            # Entity isolation: explicit mismatched entity_key/switch_id excluded
            if self._entity_mismatch(r, scope=scope, switch_id=switch_id):
                cross_entity.append(r.detector.value)
                continue

            role = self.registry.role_of(r.detector)
            age = (now - ensure_utc(r.timestamp)).total_seconds()
            is_stale = age > cfg.freshness_seconds

            if r.health is DetectorHealth.ERROR:
                unavailable.append(r.detector.value)
                continue
            if r.health is DetectorHealth.DEGRADED:
                degraded.append(r.detector.value)
            if is_stale:
                stale.append(r.detector.value)
                continue

            if role is EvidenceRole.PRIMARY_DETECTION:
                vote = self._primary_vote(r)
                if vote.weight > 0 and vote.camp != "NONE":
                    primary_votes.append(vote)
                elif vote.weight <= 0:
                    unavailable.append(r.detector.value)
                else:
                    # weight>0 but camp NONE (UNKNOWN etc.) — skip vote, note
                    context_notes.append(
                        {
                            "detector": r.detector.value,
                            "role": "PRIMARY_DETECTION",
                            "skipped": "non_polar_decision",
                            "decision": r.decision.value,
                        }
                    )
            elif role is EvidenceRole.SUPPORTING_EVIDENCE:
                if r.detector is DetectorType.CORRELATION:
                    corr_view = r
                context_notes.append(
                    {
                        "detector": r.detector.value,
                        "role": "SUPPORTING_EVIDENCE",
                        "decision": r.decision.value,
                        "confidence": r.confidence,
                    }
                )
            elif role is EvidenceRole.CONTEXT_ONLY:
                context_notes.append(
                    {
                        "detector": r.detector.value,
                        "role": "CONTEXT_ONLY",
                        "decision": r.decision.value,
                        "confidence": r.confidence,
                    }
                )
            else:
                # Unregistered — treat OTHER as primary if decision polar
                if r.detector is DetectorType.OTHER:
                    vote = self._primary_vote(r)
                    if vote.weight > 0 and vote.camp != "NONE":
                        primary_votes.append(vote)

        # Native CorrelationResult preferred for R score when provided
        r4_score, r4_status, r4_meta = self._correlation_support(
            correlation, corr_view, now
        )

        W = sum(v.weight for v in primary_votes)
        if W < cfg.min_primary_weight:
            return FusedDecision(
                fusion_id=fusion_id or new_id(),
                timestamp=now,
                event_id=event_id,
                decision=DetectionDecision.NONE,
                confidence=None,
                participating=[],
                disagreement=False,
                reason="no_valid_primary_evidence",
                evidence=self._evidence_blob(
                    status="UNAVAILABLE",
                    entity_key=scope,
                    primary_votes=[],
                    A=0.0,
                    N=0.0,
                    S0=0.0,
                    C=0.0,
                    G=0.0,
                    S=0.0,
                    R=r4_score,
                    U=0.0,
                    missing=missing_primary,
                    degraded=degraded,
                    unavailable=unavailable,
                    stale=stale,
                    context_notes=context_notes,
                    r4_meta=r4_meta,
                    decision_rule="no_valid_primary",
                    cross_entity=cross_entity,
                ),
            )

        A = sum(v.weight * v.attack_polarity for v in primary_votes) / W
        N = sum(v.weight * v.normal_polarity for v in primary_votes) / W
        S0 = A - N

        G, C, agree_meta = self._agreement(primary_votes)
        S1 = S0 * (1.0 - cfg.disagreement_penalty * C)

        # R4: strengthen attack-leaning only; never invent ATTACK from all-NORMAL
        all_normal_primary = all(v.camp == "NORMAL" for v in primary_votes)
        has_attack_camp = any(v.camp == "ATTACK" for v in primary_votes)
        has_partial = any(v.camp == "PARTIAL" for v in primary_votes)
        R = 0.0
        if r4_score > 0 and not all_normal_primary and (has_attack_camp or has_partial):
            if S1 > 0:
                R = cfg.correlation_support_strength * r4_score
                S2 = S1 + R * (1.0 - abs(S1))
            elif has_partial and S1 >= 0:
                R = 0.5 * cfg.correlation_support_strength * r4_score
                S2 = S1 + R * (1.0 - abs(S1))
            else:
                S2 = S1
        else:
            S2 = S1
            if all_normal_primary and r4_score > 0:
                r4_meta = {
                    **r4_meta,
                    "boost_applied": False,
                    "invariant": "R4_cannot_convert_all_primary_NORMAL_to_ATTACK",
                }

        U, ctx_meta = self._context_uncertainty(
            ordered, now, scope=scope, switch_id=switch_id
        )
        S = S2 * (1.0 - cfg.context_uncertainty_strength * U)
        # clamp soft
        S = max(-1.0, min(1.0, S))

        decision, confidence, rule = self._decide(
            S=S,
            A=A,
            N=N,
            C=C,
            G=G,
            U=U,
            R=R,
            all_normal_primary=all_normal_primary,
            has_attack_camp=has_attack_camp,
        )

        participating = [v.detector for v in primary_votes]
        # Include supporting/context names that were fresh & healthy for trace
        for note in context_notes:
            d = note.get("detector")
            if d and d not in participating and d not in stale and d not in unavailable:
                # listed under evidence, not as primary participants
                pass

        disagreement = bool(C >= 0.35)

        reason = (
            f"S={S:.3f} A={A:.3f} N={N:.3f} G={G:.3f} C={C:.3f} "
            f"R={R:.3f} U={U:.3f} rule={rule}"
        )

        return FusedDecision(
            fusion_id=fusion_id or new_id(),
            timestamp=now,
            event_id=event_id,
            decision=decision,
            confidence=confidence,
            participating=participating,
            disagreement=disagreement,
            reason=reason,
            evidence=self._evidence_blob(
                status="OK",
                entity_key=scope,
                primary_votes=primary_votes,
                A=A,
                N=N,
                S0=S0,
                C=C,
                G=G,
                S=S,
                R=R,
                U=U,
                missing=missing_primary,
                degraded=degraded,
                unavailable=unavailable,
                stale=stale,
                context_notes=context_notes,
                r4_meta={**r4_meta, "boost_applied": R > 0, "R": R},
                context_meta=ctx_meta,
                agreement_meta=agree_meta,
                decision_rule=rule,
                S1=S1,
                S2=S2,
                cross_entity=cross_entity,
            ),
        )

    # ── helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _entity_mismatch(
        result: DetectorResult,
        *,
        scope: str,
        switch_id: Optional[int],
    ) -> bool:
        """True when result carries an explicit identity that conflicts with fuse scope."""
        ev = result.evidence if isinstance(result.evidence, dict) else {}
        r_ek = ev.get("entity_key")
        if scope and r_ek and str(r_ek) != str(scope):
            return True
        r_sw = ev.get("switch_id")
        if switch_id is not None and r_sw is not None:
            try:
                if int(r_sw) != int(switch_id):
                    return True
            except (TypeError, ValueError):
                return True
        return False

    def _missing_primaries(self, results: Sequence[DetectorResult]) -> List[str]:
        present = {r.detector for r in results}
        missing = []
        for d in self.registry.primary_types():
            desc = self.registry.get(d)
            if desc is not None and not desc.implemented:
                continue  # future stub not "missing" as failure
            if d not in present:
                missing.append(d.value)
        return missing

    def _primary_vote(self, r: DetectorResult) -> _PrimaryVote:
        cfg = self.config
        rho = cfg.reliability_of(r.detector)
        # Prefer registry reliability when registered
        desc = self.registry.get(r.detector)
        if desc is not None:
            rho = float(desc.reliability)
        h = cfg.health_factor(r.health)
        w = rho * h
        conf = to_unit_confidence(r.confidence)
        if conf is None:
            conf = cfg.default_decision_confidence if r.decision not in (
                DetectionDecision.NONE,
                DetectionDecision.UNKNOWN,
            ) else 0.0

        a, n, camp = self._polarity(r.decision, conf)
        return _PrimaryVote(
            detector=r.detector.value,
            decision=r.decision.value,
            confidence=float(conf),
            base_reliability=float(rho),
            health=r.health.value,
            health_factor=float(h),
            weight=float(w),
            attack_polarity=float(a),
            normal_polarity=float(n),
            camp=camp,
        )

    @staticmethod
    def _polarity(
        decision: DetectionDecision, confidence: float
    ) -> Tuple[float, float, str]:
        c = max(0.0, min(1.0, float(confidence)))
        if decision in _ATTACK_LIKE:
            return c, 0.0, "ATTACK"
        if decision in _NORMAL_LIKE:
            return 0.0, c, "NORMAL"
        if decision is DetectionDecision.SUSPICIOUS:
            return 0.55 * c, 0.20 * c, "PARTIAL"
        if decision is DetectionDecision.WARNING:
            return 0.40 * c, 0.30 * c, "PARTIAL"
        return 0.0, 0.0, "NONE"

    @staticmethod
    def _agreement(
        votes: Sequence[_PrimaryVote],
    ) -> Tuple[float, float, Dict[str, Any]]:
        """
        G = agreement, C = conflict among ATTACK vs NORMAL camps (PARTIAL ignored for camps).
        With <2 camp voters: G=1, C=0.
        """
        wa = sum(v.weight for v in votes if v.camp == "ATTACK")
        wn = sum(v.weight for v in votes if v.camp == "NORMAL")
        camp_w = wa + wn
        meta = {"W_attack_camp": wa, "W_normal_camp": wn}
        if camp_w <= 0:
            # only partial / none
            return 1.0, 0.0, {**meta, "mode": "no_hard_camps"}
        if wa <= 0 or wn <= 0:
            return 1.0, 0.0, {**meta, "mode": "unanimous_camp"}
        # Equal weight → C=1, G=0; unanimous one side already handled
        C = 2.0 * min(wa, wn) / camp_w
        G = 1.0 - C
        return float(G), float(C), {**meta, "mode": "conflict"}

    def _correlation_support(
        self,
        correlation: Optional[CorrelationResult],
        corr_view: Optional[DetectorResult],
        now: datetime,
    ) -> Tuple[float, str, Dict[str, Any]]:
        cfg = self.config
        meta: Dict[str, Any] = {"present": False}
        score = None
        status = ""
        ts = None
        cid = None
        if correlation is not None:
            score = correlation.score
            status = str((correlation.evidence or {}).get("status") or "")
            ts = correlation.timestamp
            cid = correlation.correlation_id
            meta["source"] = "CorrelationResult"
        elif corr_view is not None:
            score = corr_view.confidence if corr_view.confidence is not None else corr_view.score
            status = str((corr_view.evidence or {}).get("correlation_status") or "")
            ts = corr_view.timestamp
            cid = (corr_view.evidence or {}).get("correlation_id")
            meta["source"] = "DetectorResult_view"

        if score is None:
            return 0.0, status, meta
        if ts is not None and (now - ensure_utc(ts)).total_seconds() > cfg.freshness_seconds:
            meta.update({"present": True, "stale": True, "correlation_id": cid})
            return 0.0, status, meta

        s = max(0.0, min(1.0, float(score)))
        # Only CORRELATED / WEAK_CORRELATED contribute support
        if status not in ("CORRELATED", "WEAK_CORRELATED", ""):
            # empty status with high score still allows mild support
            if status and status not in ("CORRELATED", "WEAK_CORRELATED"):
                meta.update(
                    {
                        "present": True,
                        "score": s,
                        "status": status,
                        "usable": False,
                        "correlation_id": cid,
                    }
                )
                return 0.0, status, meta
        if status == "WEAK_CORRELATED":
            s *= 0.6
        meta.update(
            {
                "present": True,
                "score": s,
                "status": status or "UNSPECIFIED",
                "usable": True,
                "correlation_id": cid,
            }
        )
        return s, status, meta

    def _context_uncertainty(
        self,
        results: Sequence[DetectorResult],
        now: datetime,
        *,
        scope: str = "",
        switch_id: Optional[int] = None,
    ) -> Tuple[float, Dict[str, Any]]:
        cfg = self.config
        U = 0.0
        bits: List[str] = []
        for r in results:
            if self._entity_mismatch(r, scope=scope, switch_id=switch_id):
                continue
            role = self.registry.role_of(r.detector)
            if role is not EvidenceRole.CONTEXT_ONLY:
                continue
            if r.health is DetectorHealth.ERROR:
                continue
            if (now - ensure_utc(r.timestamp)).total_seconds() > cfg.freshness_seconds:
                continue
            if r.detector is DetectorType.ADWIN and r.decision is DetectionDecision.DRIFT:
                U += cfg.adwin_uncertainty
                bits.append("ADWIN_DRIFT")
            if r.detector is DetectorType.HDBSCAN and r.decision in (
                DetectionDecision.SUSPICIOUS,
                DetectionDecision.NOISE,
            ):
                U += cfg.hdbscan_uncertainty
                bits.append(f"HDBSCAN_{r.decision.value}")
        U = max(0.0, min(1.0, U))
        return U, {"signals": bits, "U": U}

    def _calibrate_confidence(
        self,
        *,
        decision: DetectionDecision,
        S: float,
        A: float,
        N: float,
        C: float,
        G: float,
        U: float,
        R: float,
    ) -> float:
        """
        Map fusion score components to a gate-facing confidence in [0, 1].

        Decision remains thresholded on S. Confidence is agreement-calibrated so
        unanimous attack evidence is not under-reported after context shrink.
        """
        cfg = self.config
        base = abs(float(S))
        if decision is DetectionDecision.ATTACK:
            margin = max(0.0, float(S) - cfg.attack_threshold)
            agree = cfg.agreement_confidence_boost * float(G) * (1.0 - float(C))
            corr = min(cfg.correlation_confidence_boost_cap, max(0.0, float(R)))
            unc = (
                cfg.uncertainty_confidence_penalty
                * cfg.context_uncertainty_strength
                * max(0.0, float(U))
            )
            conf = base + agree * (0.5 + margin) + corr - unc
            # Unanimous attack camp: blend with primary attack polarity floor
            if float(G) >= 0.99 and float(C) < 0.05 and float(A) > 0:
                conf = max(conf, 0.5 * base + 0.5 * float(A) + agree)
            return max(0.0, min(1.0, conf))
        if decision is DetectionDecision.SUSPICIOUS:
            return max(0.0, min(1.0, max(base, 0.5 * float(A), 0.5 * float(U), 0.5 * float(C))))
        if decision is DetectionDecision.NORMAL:
            return max(0.0, min(1.0, N if N > 0 else base if base > 0 else cfg.default_decision_confidence))
        return max(0.0, min(1.0, base))

    def _decide(
        self,
        *,
        S: float,
        A: float,
        N: float,
        C: float,
        G: float,
        U: float,
        R: float,
        all_normal_primary: bool,
        has_attack_camp: bool,
    ) -> Tuple[DetectionDecision, Optional[float], str]:
        cfg = self.config
        # Hard invariant: all NORMAL primaries → never ATTACK
        if all_normal_primary and not has_attack_camp:
            conf = max(0.0, min(1.0, N if N > 0 else abs(S)))
            if U >= 0.25 or C >= 0.5:
                return DetectionDecision.SUSPICIOUS, max(conf * 0.5, U * 0.4), "all_normal_with_context_uncertainty"
            return DetectionDecision.NORMAL, conf if conf > 0 else cfg.default_decision_confidence, "all_primary_normal"

        if S >= cfg.attack_threshold:
            conf = self._calibrate_confidence(
                decision=DetectionDecision.ATTACK, S=S, A=A, N=N, C=C, G=G, U=U, R=R
            )
            return DetectionDecision.ATTACK, conf, "S_ge_attack_threshold"
        if S >= cfg.suspicious_threshold:
            conf = self._calibrate_confidence(
                decision=DetectionDecision.SUSPICIOUS, S=S, A=A, N=N, C=C, G=G, U=U, R=R
            )
            return DetectionDecision.SUSPICIOUS, conf, "S_ge_suspicious_threshold"
        if S <= -cfg.normal_threshold:
            conf = self._calibrate_confidence(
                decision=DetectionDecision.NORMAL, S=S, A=A, N=N, C=C, G=G, U=U, R=R
            )
            return DetectionDecision.NORMAL, conf, "S_le_neg_normal_threshold"

        # Mid-band (-normal_threshold, suspicious_threshold)
        if U > 0 or C >= 0.35:
            return (
                DetectionDecision.SUSPICIOUS,
                max(0.0, min(1.0, max(abs(S), 0.5 * U, 0.5 * C))),
                "midband_conflict_or_context",
            )
        if N >= A:
            return (
                DetectionDecision.NORMAL,
                max(0.0, min(1.0, N if N > 0 else cfg.default_decision_confidence)),
                "midband_normal_majority",
            )
        if A > 0:
            return DetectionDecision.SUSPICIOUS, max(0.0, min(1.0, A)), "midband_weak_attack"
        return DetectionDecision.NONE, None, "midband_none"

    @staticmethod
    def _evidence_blob(
        *,
        status: str,
        entity_key: str,
        primary_votes: Sequence[_PrimaryVote],
        A: float,
        N: float,
        S0: float,
        C: float,
        G: float,
        S: float,
        R: float,
        U: float,
        missing: List[str],
        degraded: List[str],
        unavailable: List[str],
        stale: List[str],
        context_notes: List[Dict[str, Any]],
        r4_meta: Dict[str, Any],
        decision_rule: str,
        context_meta: Optional[Dict[str, Any]] = None,
        agreement_meta: Optional[Dict[str, Any]] = None,
        S1: Optional[float] = None,
        S2: Optional[float] = None,
        cross_entity: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        return {
            "status": status,
            "engine": "CollaborativeFusionEngine",
            "version": "R6.2",
            "entity_key": entity_key or None,
            "formula": {
                "w_i": "rho_i * h_i",
                "A": "sum(w_i * a_i) / W",
                "N": "sum(w_i * n_i) / W",
                "S0": "A - N",
                "S1": "S0 * (1 - delta * C)",
                "S2": "S1 + R * (1 - |S1|) if attack-lean gated",
                "S": "S2 * (1 - gamma * U)",
            },
            "scores": {
                "A": round(A, 6),
                "N": round(N, 6),
                "S0": round(S0, 6),
                "S1": round(S1, 6) if S1 is not None else None,
                "S2": round(S2, 6) if S2 is not None else None,
                "S": round(S, 6),
                "G": round(G, 6),
                "C": round(C, 6),
                "R": round(R, 6),
                "U": round(U, 6),
            },
            "primary_votes": [
                {
                    "detector": v.detector,
                    "decision": v.decision,
                    "confidence": round(v.confidence, 6),
                    "base_reliability": round(v.base_reliability, 6),
                    "health": v.health,
                    "health_factor": round(v.health_factor, 6),
                    "effective_weight": round(v.weight, 6),
                    "attack_polarity": round(v.attack_polarity, 6),
                    "normal_polarity": round(v.normal_polarity, 6),
                    "camp": v.camp,
                }
                for v in primary_votes
            ],
            "missing_detectors": list(missing),
            "degraded_detectors": list(degraded),
            "unavailable_detectors": list(unavailable),
            "stale_detectors": list(stale),
            "cross_entity_excluded": list(cross_entity or []),
            "context": context_notes,
            "context_uncertainty": context_meta or {},
            "correlation": r4_meta,
            "agreement": agreement_meta or {},
            "decision_rule": decision_rule,
            "mitigation_authorized": False,
        }
