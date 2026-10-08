"""
R4.2 CorrelationEngine — deterministic cross-layer correlation.

Produces shared_contracts.CorrelationResult evidence only.
Does not authorize mitigation or emit R6 FusedDecision.
"""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from shared_contracts.enums import Severity
from shared_contracts.models import CorrelationResult, new_id
from shared_contracts.timeutil import ensure_utc, utc_now

from correlation.categories import SignalCategory
from correlation.config import CorrelationConfig
from correlation.models import CorrelationWindow, SignalEvent
from correlation.strength import apply_health, extract_strength


class CorrelationEngine:
    """
    Lightweight evidence-driven correlator.

    Score model (documented in IMPLEMENTED/R4_2_CORRELATION_ENGINE_CORE.md):

        S = Σ_{c ∈ C+} (w_c · σ_c) / Σ_{c ∈ C+} w_c
        T = temporal_min + (1 - temporal_min) · (1 - span/W)_+
        D = diversity_floor + (1 - diversity_floor) · clamp((k-1)/(K*-1), 0, 1)
        A = agreement factor ∈ {disagreement_factor, 1, agreement_boost}
        P = 1 + persistence_boost  (capped)

        score = clamp(S · T · D · A · P, 0, 1)

    Missing categories are omitted from C+ (not zero-filled).
    """

    def __init__(self, config: Optional[CorrelationConfig] = None) -> None:
        self.config = config or CorrelationConfig()

    def correlate(
        self,
        signals: Sequence[SignalEvent],
        *,
        entity_key: Optional[str] = None,
        event_id: Optional[str] = None,
        window: Optional[CorrelationWindow] = None,
        reference_ts: Optional[datetime] = None,
        correlation_id: Optional[str] = None,
    ) -> CorrelationResult:
        """
        Correlate temporally related SignalEvents into a CorrelationResult.

        Insertion order does not affect the score: inputs are sorted by
        (timestamp, signal_id) before processing.
        """
        cfg = self.config
        try:
            cleaned = self._validate_and_sort(signals)
        except ValueError as exc:
            return self._empty_result(
                reason=f"malformed_input: {exc}",
                event_id=event_id,
                correlation_id=correlation_id,
                status="ERROR",
            )

        if not cleaned:
            return self._empty_result(
                reason="empty_window",
                event_id=event_id,
                correlation_id=correlation_id,
                status="EMPTY",
            )

        # Optional fixed window filter
        if window is not None and window.start is not None and window.end is not None:
            cleaned = [
                s
                for s in cleaned
                if window.start <= s.timestamp <= window.end
            ]
            if not cleaned:
                return self._empty_result(
                    reason="no_signals_in_window_bounds",
                    event_id=event_id,
                    correlation_id=correlation_id,
                    window_start=window.start,
                    window_end=window.end,
                    status="EMPTY",
                )

        focal = entity_key
        if focal is None:
            focal = self._infer_focal_entity(cleaned)
        matched, rejected_entity = self._filter_entity(cleaned, focal)

        # Exclude missing/stale from fusion; track separately
        usable: List[SignalEvent] = []
        excluded: List[Dict[str, Any]] = []
        for s in matched:
            if s.availability in ("NOT_AVAILABLE", "STALE"):
                excluded.append(
                    {
                        "signal_id": s.signal_id,
                        "availability": s.availability,
                        "signal_key": s.signal_key,
                    }
                )
                continue
            usable.append(s)

        if not usable:
            return self._empty_result(
                reason="no_usable_signals",
                event_id=event_id or _first_event_id(matched),
                correlation_id=correlation_id,
                status="NO_EVIDENCE",
                extra={"excluded": excluded, "entity_rejected": rejected_entity},
            )

        # Dedup: strongest per (source, name, entity_key)
        deduped, dup_dropped = self._dedup(usable)

        # Per-signal strengths
        strengths: List[Tuple[SignalEvent, float, str]] = []
        unsuitable: List[Dict[str, Any]] = []
        for s in deduped:
            raw, method = extract_strength(s)
            if raw is None:
                unsuitable.append(
                    {
                        "signal_id": s.signal_id,
                        "signal_key": s.signal_key,
                        "reason": method,
                    }
                )
                continue
            st = apply_health(raw, s, cfg.degraded_strength_factor)
            strengths.append((s, st, method))

        if not strengths:
            return self._empty_result(
                reason="no_numeric_strength",
                event_id=event_id or _first_event_id(usable),
                correlation_id=correlation_id,
                status="NO_EVIDENCE",
                extra={
                    "excluded": excluded,
                    "unsuitable": unsuitable,
                    "entity_rejected": rejected_entity,
                    "duplicates_dropped": dup_dropped,
                },
            )

        # Category maxima σ_c
        cat_max: Dict[str, float] = {}
        cat_signal: Dict[str, str] = {}
        cat_methods: Dict[str, str] = {}
        for s, st, method in strengths:
            key = s.category.value
            if st >= cat_max.get(key, -1.0):
                cat_max[key] = st
                cat_signal[key] = s.signal_id
                cat_methods[key] = method

        # Drop zero-weight categories from fusion set C+
        c_plus = {
            c: sigma
            for c, sigma in cat_max.items()
            if cfg.weight_for(SignalCategory(c)) > 0.0 and sigma > 0.0
        }

        if not c_plus:
            return self._empty_result(
                reason="no_positive_category_evidence",
                event_id=event_id or _first_event_id(usable),
                correlation_id=correlation_id,
                status="NO_EVIDENCE",
                extra={"category_max": cat_max, "duplicates_dropped": dup_dropped},
            )

        weight_sum = sum(cfg.weight_for(SignalCategory(c)) for c in c_plus)
        strength_S = (
            sum(cfg.weight_for(SignalCategory(c)) * c_plus[c] for c in c_plus)
            / weight_sum
        )

        # Temporal factor
        ts_list = [s.timestamp for s, _, _ in strengths]
        t_min, t_max = min(ts_list), max(ts_list)
        span = max(0.0, (t_max - t_min).total_seconds())
        W = max(cfg.window_duration_sec, 1e-9)
        # If span exceeds W, still allow but temporal collapses to floor via clamp
        temporal_T = cfg.temporal_min + (1.0 - cfg.temporal_min) * max(
            0.0, 1.0 - (span / W)
        )

        # Diversity factor
        k = len(c_plus)
        k_star = max(cfg.diversity_target, 2)
        diversity_raw = _clamp01((k - 1) / (k_star - 1))
        diversity_D = cfg.diversity_floor + (1.0 - cfg.diversity_floor) * diversity_raw

        # Agreement among DETECTION categorical statuses
        agreement_A = self._agreement_factor(strengths)

        # Persistence
        persistence_P = self._persistence_factor(strengths)

        score = _clamp01(strength_S * temporal_T * diversity_D * agreement_A * persistence_P)

        severity = self._severity_for(score)
        status = self._status_for(score, k)

        participating_ids = sorted({s.signal_id for s, _, _ in strengths})
        participating_categories = sorted(c_plus.keys())

        # Completeness: how many of the five primary categories appeared
        primary = {
            SignalCategory.DATA_PLANE.value,
            SignalCategory.CONTROL_PLANE.value,
            SignalCategory.DETECTION.value,
            SignalCategory.DRIFT_CLUSTERING.value,
            SignalCategory.SECURITY_RESPONSE.value,
        }
        completeness = len(set(participating_categories) & primary) / float(len(primary))

        reason = self._reason(
            score=score,
            status=status,
            categories=participating_categories,
            S=strength_S,
            T=temporal_T,
            D=diversity_D,
            A=agreement_A,
            P=persistence_P,
        )

        evidence: Dict[str, Any] = {
            "status": status,
            "reason": reason,
            "summary": reason,
            "participating_categories": participating_categories,
            "category_strength": {c: round(c_plus[c], 6) for c in participating_categories},
            "category_weights_used": {
                c: cfg.weight_for(SignalCategory(c)) for c in participating_categories
            },
            "factors": {
                "strength_S": round(strength_S, 6),
                "temporal_T": round(temporal_T, 6),
                "diversity_D": round(diversity_D, 6),
                "agreement_A": round(agreement_A, 6),
                "persistence_P": round(persistence_P, 6),
            },
            "span_sec": round(span, 6),
            "window_duration_sec": cfg.window_duration_sec,
            "evidence_completeness": round(completeness, 6),
            "diversity_count": k,
            "duplicates_dropped": dup_dropped,
            "excluded_unavailable_or_stale": excluded,
            "unsuitable_for_numeric_fusion": unsuitable,
            "entity_rejected_count": rejected_entity,
            "focal_entity_key": focal,
            "signal_strength_methods": {
                s.signal_id: method for s, _, method in strengths
            },
            "note": (
                "Correlation expresses co-occurrence of evidence within a time "
                "window — not causation."
            ),
            "mitigation_authorized": False,
        }

        eid = event_id or _first_event_id([s for s, _, _ in strengths])
        cid = correlation_id or self._deterministic_id(
            participating_ids, t_min, t_max, round(score, 6), eid
        )
        ref = ensure_utc(reference_ts) if reference_ts is not None else t_max

        return CorrelationResult(
            correlation_id=cid,
            timestamp=ref,
            event_id=eid,
            score=score,
            severity=severity,
            window_start=t_min,
            window_end=t_max,
            signal_ids=participating_ids,
            evidence=evidence,
        )

    # ── helpers ─────────────────────────────────────────────────────────────

    def _validate_and_sort(
        self, signals: Sequence[SignalEvent]
    ) -> List[SignalEvent]:
        if signals is None:
            raise ValueError("signals is None")
        if not isinstance(signals, (list, tuple)):
            raise ValueError("signals must be a sequence")
        out: List[SignalEvent] = []
        for item in signals:
            if not isinstance(item, SignalEvent):
                raise ValueError("all items must be SignalEvent")
            out.append(item)
        out.sort(key=lambda s: (s.timestamp, s.signal_id))
        return out

    def _infer_focal_entity(self, signals: List[SignalEvent]) -> Optional[str]:
        """
        When caller omits entity_key, pick a deterministic focal among
        non-null keys (lexicographically smallest of the most frequent).
        Prevents silently merging Host A with Host B.
        """
        counts: Dict[str, int] = defaultdict(int)
        for s in signals:
            if s.entity_key:
                counts[s.entity_key] += 1
        if not counts:
            return None
        best_count = max(counts.values())
        candidates = sorted(k for k, n in counts.items() if n == best_count)
        return candidates[0]

    def _filter_entity(
        self, signals: List[SignalEvent], focal: Optional[str]
    ) -> Tuple[List[SignalEvent], int]:
        """
        Deterministic entity matching.

        Rules:
        1. If no focal entity → keep all (all switch/global scoped).
        2. If focal set → keep signals whose entity_key == focal.
        3. Signals with entity_key is None are switch/global scoped: keep if
           allow_switch_scoped_with_entity (default True).
        4. Different non-null entity_key ≠ focal → reject.
        """
        if not focal:
            return signals, 0
        cfg = self.config
        kept: List[SignalEvent] = []
        rejected = 0
        for s in signals:
            if s.entity_key is None:
                if cfg.allow_switch_scoped_with_entity:
                    kept.append(s)
                else:
                    rejected += 1
                continue
            if s.entity_key == focal:
                kept.append(s)
            else:
                rejected += 1
        return kept, rejected

    def _dedup(
        self, signals: List[SignalEvent]
    ) -> Tuple[List[SignalEvent], int]:
        """Keep strongest candidate per (source, name, entity_key)."""
        cfg = self.config
        buckets: Dict[Tuple[str, str, str], List[SignalEvent]] = defaultdict(list)
        for s in signals:
            key = (s.source, s.name, s.entity_key or "")
            buckets[key].append(s)

        kept: List[SignalEvent] = []
        dropped = 0
        for key, group in sorted(buckets.items()):
            # Rank by extractable strength desc, then signal_id for stability
            ranked = []
            for s in group:
                raw, _ = extract_strength(s)
                st = (
                    apply_health(raw, s, cfg.degraded_strength_factor)
                    if raw is not None
                    else -1.0
                )
                ranked.append((st, s.signal_id, s))
            ranked.sort(key=lambda t: (-t[0], t[1]))
            take = ranked[: max(1, cfg.max_signals_per_type)]
            kept.extend(s for _, _, s in take)
            dropped += max(0, len(ranked) - len(take))
        kept.sort(key=lambda s: (s.timestamp, s.signal_id))
        return kept, dropped

    def _agreement_factor(
        self, strengths: List[Tuple[SignalEvent, float, str]]
    ) -> float:
        cfg = self.config
        statuses = []
        for s, st, _ in strengths:
            if s.category != SignalCategory.DETECTION:
                continue
            if isinstance(s.value, str):
                statuses.append(s.value.strip().upper())
        if len(statuses) < 2:
            return 1.0
        anomalous = {"ALERT", "ATTACK", "SUSPICIOUS", "WARNING"}
        normalish = {"NORMAL", "NONE"}
        has_anom = any(x in anomalous for x in statuses)
        has_norm = any(x in normalish for x in statuses)
        if has_anom and has_norm:
            return cfg.disagreement_factor
        anom_vals = [x for x in statuses if x in anomalous]
        if len(anom_vals) >= 2:
            return cfg.agreement_boost
        return 1.0

    def _persistence_factor(
        self, strengths: List[Tuple[SignalEvent, float, str]]
    ) -> float:
        cfg = self.config
        strong_ts = {
            s.timestamp
            for s, st, _ in strengths
            if st >= cfg.strong_strength_threshold
        }
        if len(strong_ts) < cfg.persistence_min_strong:
            return 1.0
        # Linear boost up to persistence_boost_max
        extra = min(
            1.0,
            (len(strong_ts) - 1) / float(max(cfg.persistence_min_strong, 1)),
        )
        return 1.0 + cfg.persistence_boost_max * extra

    def _severity_for(self, score: float) -> Severity:
        cfg = self.config
        if score >= cfg.severity_critical:
            return Severity.CRITICAL
        if score >= cfg.severity_high:
            return Severity.HIGH
        if score >= cfg.severity_medium:
            return Severity.MEDIUM
        if score >= cfg.severity_low:
            return Severity.LOW
        return Severity.INFO

    def _status_for(self, score: float, n_categories: int) -> str:
        cfg = self.config
        if (
            score >= cfg.correlated_min_score
            and n_categories >= cfg.correlated_min_categories
        ):
            return "CORRELATED"
        if score >= cfg.correlated_min_score:
            return "WEAK_CORRELATED"
        if n_categories >= 1 and score > 0:
            return "PARTIAL"
        return "NONE"

    def _reason(
        self,
        *,
        score: float,
        status: str,
        categories: List[str],
        S: float,
        T: float,
        D: float,
        A: float,
        P: float,
    ) -> str:
        cats = ",".join(categories) if categories else "none"
        return (
            f"{status}: score={score:.4f} from categories [{cats}] "
            f"(S={S:.3f}, T={T:.3f}, D={D:.3f}, A={A:.3f}, P={P:.3f}); "
            f"co-occurrence only — not causation"
        )

    def _deterministic_id(
        self,
        signal_ids: List[str],
        t_min: datetime,
        t_max: datetime,
        score: float,
        event_id: Optional[str],
    ) -> str:
        payload = "|".join(
            [
                ",".join(signal_ids),
                t_min.isoformat(),
                t_max.isoformat(),
                f"{score:.6f}",
                event_id or "",
            ]
        )
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
        return f"corr-{digest}"

    def _empty_result(
        self,
        *,
        reason: str,
        event_id: Optional[str],
        correlation_id: Optional[str],
        status: str = "EMPTY",
        window_start: Optional[datetime] = None,
        window_end: Optional[datetime] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> CorrelationResult:
        evidence: Dict[str, Any] = {
            "status": status,
            "reason": reason,
            "summary": reason,
            "participating_categories": [],
            "evidence_completeness": 0.0,
            "mitigation_authorized": False,
            "note": "Correlation expresses co-occurrence — not causation.",
        }
        if extra:
            evidence.update(extra)
        return CorrelationResult(
            correlation_id=correlation_id or new_id(),
            timestamp=utc_now(),
            event_id=event_id,
            score=0.0,
            severity=Severity.INFO,
            window_start=window_start,
            window_end=window_end,
            signal_ids=[],
            evidence=evidence,
        )


def _first_event_id(signals: Iterable[SignalEvent]) -> Optional[str]:
    for s in signals:
        if s.event_id:
            return s.event_id
    return None


def _clamp01(x: float) -> float:
    if not math.isfinite(x):
        return 0.0
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)
