"""
R6.5 deterministic evidence packs for correctness / ablation / sensitivity.

Synthetic labeled scenarios only — not live Mininet metrics.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from shared_contracts.enums import DetectionDecision, DetectorHealth, DetectorType
from shared_contracts.models import CorrelationResult, DetectorResult
from fusion.adapters import (
    adapt_adwin_alerts,
    adapt_correlation_result,
    adapt_entropy_metrics,
    adapt_hdbscan_summary,
    adapt_ml_prediction,
)


def _ts(offset_s: float = 0.0) -> datetime:
    return datetime(2026, 7, 27, 6, 0, 0, tzinfo=timezone.utc) + timedelta(
        seconds=offset_s
    )


@dataclass(frozen=True)
class EvidencePack:
    """One deterministic fusion input pack."""

    pack_id: str
    label: str  # ground-truth for synthetic ablation: ATTACK|NORMAL|NONE
    expected_decision: Tuple[str, ...]  # allowed fused decisions
    detector_results: Tuple[DetectorResult, ...]
    correlation: Optional[CorrelationResult] = None
    switch_id: Optional[int] = 1
    src_mac: Optional[str] = "02:aa:aa:aa:aa:01"
    notes: str = ""


def _ml(
    status: str,
    conf: float,
    *,
    health: DetectorHealth = DetectorHealth.SUCCESS,
    t: float = 0.0,
    entity_key: Optional[str] = None,
    switch_id: Optional[int] = None,
) -> DetectorResult:
    r = adapt_ml_prediction(
        {"status": status, "confidence": conf},
        timestamp=_ts(t),
        health=health,
    )
    if entity_key or switch_id is not None:
        ev = dict(r.evidence or {})
        if entity_key:
            ev["entity_key"] = entity_key
        if switch_id is not None:
            ev["switch_id"] = int(switch_id)
        object.__setattr__(r, "evidence", ev)
    return r


def _ent(
    status: str,
    conf: float,
    *,
    health: DetectorHealth = DetectorHealth.SUCCESS,
    t: float = 0.0,
    entity_key: Optional[str] = None,
    switch_id: Optional[int] = None,
) -> DetectorResult:
    r = adapt_entropy_metrics(
        {"status": status, "confidence": conf, "entropy_score": 0.3},
        timestamp=_ts(t),
        health=health,
    )
    if entity_key or switch_id is not None:
        ev = dict(r.evidence or {})
        if entity_key:
            ev["entity_key"] = entity_key
        if switch_id is not None:
            ev["switch_id"] = int(switch_id)
        object.__setattr__(r, "evidence", ev)
    return r


def _corr(score: float, status: str = "CORRELATED", t: float = 0.0) -> CorrelationResult:
    return CorrelationResult(
        correlation_id="corr-r65",
        timestamp=_ts(t),
        score=score,
        evidence={"status": status},
    )


def build_correctness_packs() -> List[EvidencePack]:
    """Packs A–R for fusion correctness matrix."""
    ek = "dpid:1|src:02:aa:aa:aa:aa:01"
    other = "dpid:2|src:02:ff:ff:ff:ff:ff"
    return [
        EvidencePack(
            "A",
            "NORMAL",
            ("NORMAL",),
            (_ml("NORMAL", 80, entity_key=ek), _ent("NORMAL", 75, entity_key=ek)),
            notes="both normal",
        ),
        EvidencePack(
            "B",
            "ATTACK",
            ("ATTACK",),
            (_ml("ATTACK", 92, entity_key=ek), _ent("ALERT", 88, entity_key=ek)),
            notes="both attack-like",
        ),
        EvidencePack(
            "C",
            "ATTACK",
            ("SUSPICIOUS", "ATTACK"),
            (_ml("ATTACK", 92, entity_key=ek), _ent("NORMAL", 85, entity_key=ek)),
            notes="disagreement ML attack",
        ),
        EvidencePack(
            "D",
            "ATTACK",
            ("SUSPICIOUS", "ATTACK"),
            (_ml("NORMAL", 85, entity_key=ek), _ent("ALERT", 90, entity_key=ek)),
            notes="disagreement entropy attack",
        ),
        EvidencePack(
            "E",
            "ATTACK",
            ("ATTACK",),
            (_ml("ATTACK", 95, entity_key=ek),),
            notes="high-conf ML only",
        ),
        EvidencePack(
            "F",
            "ATTACK",
            ("SUSPICIOUS", "ATTACK", "NONE"),
            (_ml("ATTACK", 35, entity_key=ek),),
            notes="low-conf ML only",
        ),
        EvidencePack(
            "G",
            "ATTACK",
            ("ATTACK",),
            (_ent("ALERT", 90, entity_key=ek),),
            notes="entropy only",
        ),
        EvidencePack(
            "H",
            "NONE",
            ("NONE",),
            tuple(),
            notes="both unavailable",
        ),
        EvidencePack(
            "I",
            "ATTACK",
            ("ATTACK", "SUSPICIOUS", "NORMAL"),
            (
                _ml("ATTACK", 90, health=DetectorHealth.DEGRADED, entity_key=ek),
                _ent("NORMAL", 80, entity_key=ek),
            ),
            notes="degraded ML",
        ),
        EvidencePack(
            "J",
            "ATTACK",
            ("SUSPICIOUS", "ATTACK", "NORMAL"),
            (
                _ml("ATTACK", 90, health=DetectorHealth.DEGRADED, entity_key=ek),
                _ent("ALERT", 90, health=DetectorHealth.DEGRADED, entity_key=ek),
            ),
            notes="both degraded",
        ),
        EvidencePack(
            "K",
            "NORMAL",
            ("NORMAL",),
            (_ml("ATTACK", 99, t=-100, entity_key=ek), _ent("NORMAL", 80, entity_key=ek)),
            notes="stale ML excluded",
        ),
        EvidencePack(
            "L",
            "ATTACK",
            ("ATTACK",),
            (_ml("ATTACK", 90, entity_key=ek), _ent("ALERT", 90, t=-100, entity_key=ek)),
            notes="stale entropy excluded",
        ),
        EvidencePack(
            "M",
            "ATTACK",
            ("ATTACK",),
            (_ml("ATTACK", 70, entity_key=ek), _ent("ALERT", 70, entity_key=ek)),
            correlation=_corr(0.95),
            notes="R4 high + attack",
        ),
        EvidencePack(
            "N",
            "NORMAL",
            ("NORMAL",),
            (_ml("NORMAL", 90, entity_key=ek), _ent("NORMAL", 90, entity_key=ek)),
            correlation=_corr(0.99),
            notes="R4 high + all normal invariant",
        ),
        EvidencePack(
            "O",
            "NONE",
            ("NONE",),
            (adapt_adwin_alerts([{"metric_name": "flow_count"}], timestamp=_ts(0)),),
            notes="ADWIN only",
        ),
        EvidencePack(
            "P",
            "NONE",
            ("NONE",),
            (
                adapt_hdbscan_summary(
                    {
                        "n_attack": 2,
                        "clusters": [{"cluster_label": "ATTACK", "confidence": 0.9}],
                    },
                    timestamp=_ts(0),
                ),
            ),
            notes="HDBSCAN only",
        ),
        EvidencePack(
            "Q",
            "NONE",
            ("NONE",),
            (
                adapt_adwin_alerts([{"metric_name": "entropy_score"}], timestamp=_ts(0)),
                adapt_hdbscan_summary(
                    {
                        "n_attack": 1,
                        "clusters": [{"cluster_label": "SUSPICIOUS", "confidence": 0.8}],
                    },
                    timestamp=_ts(0),
                ),
            ),
            notes="ADWIN+HDBSCAN only",
        ),
        EvidencePack(
            "R",
            "NORMAL",
            ("NORMAL", "NONE"),
            (
                _ml("NORMAL", 80, entity_key=ek, switch_id=1),
                # Unrelated entity attack must not participate when fusing ek
                _ml("ATTACK", 99, entity_key=other, switch_id=2),
            ),
            switch_id=1,
            src_mac="02:aa:aa:aa:aa:01",
            notes="cross-entity excluded",
        ),
    ]


def build_synthetic_ablation_dataset() -> List[EvidencePack]:
    """
    Labeled synthetic scenarios for structural ablation metrics.

    Labels are scenario-authored ground truth for offline comparison only —
    not live Mininet measurements.
    """
    ek = "dpid:1|src:02:aa:aa:aa:aa:01"
    packs: List[EvidencePack] = []
    # Attack scenarios
    for i, (mc, ec) in enumerate([(95, 90), (88, 85), (80, 78), (92, 40), (40, 92)]):
        packs.append(
            EvidencePack(
                f"atk-{i}",
                "ATTACK",
                ("ATTACK", "SUSPICIOUS"),
                (_ml("ATTACK", mc, entity_key=ek), _ent("ALERT", ec, entity_key=ek)),
                correlation=_corr(0.8) if i < 3 else None,
            )
        )
    # Normal scenarios
    for i, (mc, ec) in enumerate([(90, 85), (70, 75), (60, 65), (55, 50)]):
        packs.append(
            EvidencePack(
                f"nrm-{i}",
                "NORMAL",
                ("NORMAL",),
                (_ml("NORMAL", mc, entity_key=ek), _ent("NORMAL", ec, entity_key=ek)),
                correlation=_corr(0.9) if i == 0 else None,
            )
        )
    # Disagreement (still labeled ATTACK by scenario design for recall pressure)
    packs.append(
        EvidencePack(
            "atk-dis",
            "ATTACK",
            ("SUSPICIOUS", "ATTACK"),
            (_ml("ATTACK", 90, entity_key=ek), _ent("NORMAL", 85, entity_key=ek)),
        )
    )
    return packs
