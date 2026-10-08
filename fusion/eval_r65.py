"""
R6.5 evaluation runners — sensitivity, ablation, threshold, legacy, perf.

Writes artifacts under logs/. Synthetic labels only where noted.
Does NOT fabricate live Mininet classification metrics.
"""

from __future__ import annotations

import json
import os
import statistics
import time
from collections import Counter
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from shared_contracts.enums import DetectionDecision, DetectorHealth, DetectorType
from shared_contracts.models import DetectorResult
from fusion.adapters import (
    adapt_adwin_alerts,
    adapt_entropy_metrics,
    adapt_hdbscan_summary,
    adapt_ml_prediction,
)
from fusion.config import FusionConfig
from fusion.engine import CollaborativeFusionEngine
from fusion.eval_packs import (
    EvidencePack,
    build_correctness_packs,
    build_synthetic_ablation_dataset,
    _ts,
)
from fusion.legacy_compare import (
    classify_legacy_difference,
    comparison_to_dict,
    legacy_production_decision,
)
from fusion.registry import EvidenceRegistry, DetectorDescriptor, build_default_registry
from fusion.roles import EvidenceRole
from fusion.runtime import prepare_collaborative_cycle


def _root() -> Path:
    return Path(__file__).resolve().parents[1]


def _logs() -> Path:
    p = _root() / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _write(name: str, payload: Dict[str, Any]) -> str:
    path = _logs() / name
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return str(path)


def _fuse_pack(
    pack: EvidencePack,
    *,
    config: Optional[FusionConfig] = None,
    registry: Optional[EvidenceRegistry] = None,
) -> Any:
    eng = CollaborativeFusionEngine(config=config, registry=registry)
    return eng.fuse(
        detector_results=list(pack.detector_results),
        correlation=pack.correlation,
        timestamp=_ts(1),
        switch_id=pack.switch_id,
        src_mac=pack.src_mac,
        fusion_id=f"eval-{pack.pack_id}",
    )


def run_correctness_matrix() -> Dict[str, Any]:
    rows = []
    for pack in build_correctness_packs():
        fd = _fuse_pack(pack)
        ok = fd.decision.value in pack.expected_decision
        rows.append(
            {
                "pack_id": pack.pack_id,
                "notes": pack.notes,
                "label": pack.label,
                "expected": list(pack.expected_decision),
                "decision": fd.decision.value,
                "confidence": fd.confidence,
                "disagreement": fd.disagreement,
                "participating": list(fd.participating),
                "scores": (fd.evidence or {}).get("scores"),
                "pass": ok,
            }
        )
    return {
        "kind": "correctness_matrix",
        "passed": all(r["pass"] for r in rows),
        "rows": rows,
    }


def run_disagreement_analysis() -> Dict[str, Any]:
    cases = [
        p
        for p in build_correctness_packs()
        if p.pack_id in ("B", "C", "D", "A")
    ]
    out = []
    for pack in cases:
        fd = _fuse_pack(pack)
        scores = (fd.evidence or {}).get("scores") or {}
        out.append(
            {
                "pack_id": pack.pack_id,
                "notes": pack.notes,
                "decision": fd.decision.value,
                "confidence": fd.confidence,
                "disagreement": fd.disagreement,
                "A": scores.get("A"),
                "N": scores.get("N"),
                "C": scores.get("C"),
                "G": scores.get("G"),
                "S": scores.get("S"),
            }
        )
    # Strong disagreement should lower |S| vs unanimous attack
    by_id = {r["pack_id"]: r for r in out}
    lowered = (
        by_id["C"]["confidence"] is not None
        and by_id["B"]["confidence"] is not None
        and float(by_id["C"]["confidence"]) <= float(by_id["B"]["confidence"]) + 1e-9
        and by_id["C"]["disagreement"] is True
    )
    return {
        "kind": "disagreement_analysis",
        "cases": out,
        "strong_disagreement_lowers_certainty_vs_agree_attack": lowered,
    }


def run_reliability_sensitivity() -> Dict[str, Any]:
    base_pack = next(p for p in build_correctness_packs() if p.pack_id == "C")
    normal_pack = next(p for p in build_correctness_packs() if p.pack_id == "A")
    grid = []
    for ml_r in (0.6, 0.8, 1.0):
        for ent_r in (0.4, 0.7, 0.95):
            for delta in (0.2, 0.45, 0.7):
                for beta in (0.1, 0.25, 0.4):
                    reg = EvidenceRegistry()
                    reg.register(
                        DetectorDescriptor(
                            DetectorType.ML,
                            EvidenceRole.PRIMARY_DETECTION,
                            "ML",
                            ml_r,
                        )
                    )
                    reg.register(
                        DetectorDescriptor(
                            DetectorType.ENTROPY,
                            EvidenceRole.PRIMARY_DETECTION,
                            "E",
                            ent_r,
                        )
                    )
                    cfg = FusionConfig(
                        disagreement_penalty=delta,
                        correlation_support_strength=beta,
                    )
                    fd_c = _fuse_pack(base_pack, config=cfg, registry=reg)
                    fd_n = _fuse_pack(normal_pack, config=cfg, registry=reg)
                    grid.append(
                        {
                            "ml_reliability": ml_r,
                            "entropy_reliability": ent_r,
                            "disagreement_penalty": delta,
                            "r4_strength": beta,
                            "disagree_pack_decision": fd_c.decision.value,
                            "disagree_pack_confidence": fd_c.confidence,
                            "normal_pack_decision": fd_n.decision.value,
                            "normal_stays_non_attack": fd_n.decision.value != "ATTACK",
                        }
                    )
    fp_risk = sum(
        1 for g in grid if g["normal_pack_decision"] == "ATTACK"
    )
    return {
        "kind": "reliability_sensitivity",
        "note": (
            "Swept ML/entropy reliability, disagreement penalty, R4 strength "
            "on disagreement + all-normal packs. Not tuned for max recall."
        ),
        "grid_size": len(grid),
        "normal_to_attack_count": fp_risk,
        "grid": grid,
    }


def _subset_results(
    results: Sequence[DetectorResult],
    *,
    include_ml: bool,
    include_entropy: bool,
    include_context: bool,
) -> List[DetectorResult]:
    out = []
    for r in results:
        if r.detector is DetectorType.ML and include_ml:
            out.append(r)
        elif r.detector is DetectorType.ENTROPY and include_entropy:
            out.append(r)
        elif r.detector in (DetectorType.ADWIN, DetectorType.HDBSCAN) and include_context:
            out.append(r)
    return out


def _clf_metrics(y_true: List[str], y_pred: List[str]) -> Dict[str, Any]:
    """Binary ATTACK vs non-ATTACK metrics on synthetic labels."""
    tp = fp = tn = fn = 0
    for yt, yp in zip(y_true, y_pred):
        atk_t = yt == "ATTACK"
        atk_p = yp == "ATTACK"
        if atk_t and atk_p:
            tp += 1
        elif not atk_t and atk_p:
            fp += 1
        elif not atk_t and not atk_p:
            tn += 1
        else:
            fn += 1
    total = tp + fp + tn + fn
    prec = tp / (tp + fp) if (tp + fp) else None
    rec = tp / (tp + fn) if (tp + fn) else None
    f1 = None
    if prec is not None and rec is not None and (prec + rec) > 0:
        f1 = 2 * prec * rec / (prec + rec)
    acc = (tp + tn) / total if total else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    fnr = fn / (fn + tp) if (fn + tp) else None
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": round(acc, 4) if acc is not None else None,
        "precision": round(prec, 4) if prec is not None else None,
        "recall": round(rec, 4) if rec is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
        "fpr": round(fpr, 4) if fpr is not None else None,
        "fnr": round(fnr, 4) if fnr is not None else None,
        "n": total,
    }


def run_ablation() -> Dict[str, Any]:
    """
    Structural/synthetic ablation over authored labels.

    Configurations: ML only, Entropy only, ML+Entropy, +R4, +context.
    Metrics are against synthetic scenario labels — NOT live Mininet.
    """
    dataset = build_synthetic_ablation_dataset()
    # Enrich with context for full config
    enriched: List[EvidencePack] = []
    for p in dataset:
        extra = list(p.detector_results)
        if p.label == "ATTACK":
            extra.append(
                adapt_adwin_alerts([{"metric_name": "flow_count"}], timestamp=_ts(0))
            )
        enriched.append(
            EvidencePack(
                pack_id=p.pack_id,
                label=p.label,
                expected_decision=p.expected_decision,
                detector_results=tuple(extra),
                correlation=p.correlation,
                switch_id=p.switch_id,
                src_mac=p.src_mac,
                notes=p.notes,
            )
        )

    configs = [
        ("ml_only", True, False, False, False),
        ("entropy_only", False, True, False, False),
        ("ml_entropy", True, True, False, False),
        ("ml_entropy_r4", True, True, True, False),
        ("ml_entropy_r4_context", True, True, True, True),
    ]
    results = {}
    for name, use_ml, use_ent, use_r4, use_ctx in configs:
        y_true: List[str] = []
        y_pred: List[str] = []
        for pack in enriched:
            subset = _subset_results(
                pack.detector_results,
                include_ml=use_ml,
                include_entropy=use_ent,
                include_context=use_ctx,
            )
            corr = pack.correlation if use_r4 else None
            fd = CollaborativeFusionEngine().fuse(
                detector_results=subset,
                correlation=corr,
                timestamp=_ts(1),
                switch_id=pack.switch_id,
                src_mac=pack.src_mac,
            )
            y_true.append(pack.label)
            y_pred.append(fd.decision.value)
        results[name] = {
            "metrics": _clf_metrics(y_true, y_pred),
            "pred_counts": dict(Counter(y_pred)),
        }
    return {
        "kind": "fusion_ablation",
        "label_source": "synthetic_scenario_labels",
        "live_mininet_metrics": None,
        "note": (
            "Synthetic structural ablation only. Live Mininet S1–S5 metrics "
            "require Phase J / VM checklist — not fabricated here."
        ),
        "n_scenarios": len(enriched),
        "configurations": results,
    }


def run_legacy_comparison() -> Dict[str, Any]:
    rows = []
    counts = Counter()
    for pack in build_correctness_packs():
        if not pack.detector_results:
            continue
        fd = _fuse_pack(pack)
        cmp = classify_legacy_difference(fd, pack.detector_results)
        legacy = legacy_production_decision(pack.detector_results)
        # Confidence delta when both produce attack-like labels
        delta = None
        if fd.confidence is not None and legacy in ("ATTACK", "SUSPICIOUS"):
            # approximate legacy conf as max primary confidence
            confs = [
                r.confidence
                for r in pack.detector_results
                if r.confidence is not None
                and r.detector in (DetectorType.ML, DetectorType.ENTROPY)
            ]
            if confs:
                delta = float(fd.confidence) - max(confs)
        category = "agreement"
        if cmp.classification == "MATCH":
            category = "agreement"
        elif fd.confidence is not None and delta is not None and delta < -0.05:
            category = "R6_reduced_confidence"
        elif fd.confidence is not None and delta is not None and delta > 0.05:
            category = "R6_increased_confidence"
        if cmp.legacy_decision != cmp.fused_decision:
            category = "R6_changed_decision"
        counts[category] += 1
        rows.append(
            {
                "pack_id": pack.pack_id,
                "legacy": cmp.legacy_decision,
                "fused": cmp.fused_decision,
                "classification": cmp.classification,
                "category": category,
                "confidence_delta_approx": delta,
                "note": cmp.note,
            }
        )
    return {
        "kind": "legacy_comparison",
        "counts": dict(counts),
        "rows": rows,
        "note": "Differences are inspected, not assumed improvements.",
    }


def run_threshold_sensitivity() -> Dict[str, Any]:
    packs = [p for p in build_correctness_packs() if p.pack_id in ("A", "B", "C", "E", "F")]
    grid = []
    for atk in (0.45, 0.55, 0.65):
        for sus in (0.10, 0.20, 0.30):
            if sus >= atk:
                continue
            cfg = FusionConfig(attack_threshold=atk, suspicious_threshold=sus)
            decisions = {}
            for p in packs:
                fd = _fuse_pack(p, config=cfg)
                decisions[p.pack_id] = {
                    "decision": fd.decision.value,
                    "confidence": fd.confidence,
                }
            grid.append(
                {
                    "attack_threshold": atk,
                    "suspicious_threshold": sus,
                    "decisions": decisions,
                    "A_is_normal": decisions["A"]["decision"] == "NORMAL",
                    "B_is_attack": decisions["B"]["decision"] == "ATTACK",
                }
            )
    return {
        "kind": "threshold_sensitivity",
        "note": (
            "Threshold sweep on deterministic packs only — not tuned against "
            "held-out live labels."
        ),
        "grid": grid,
    }


def run_performance(iters: int = 300) -> Dict[str, Any]:
    pack = next(p for p in build_correctness_packs() if p.pack_id == "B")
    eng = CollaborativeFusionEngine()

    def _ms(samples: List[float]) -> Dict[str, float]:
        samples = sorted(samples)
        p95 = samples[min(len(samples) - 1, int(round(0.95 * (len(samples) - 1))))]
        return {
            "median_ms": round(statistics.median(samples), 4),
            "p95_ms": round(p95, 4),
            "max_ms": round(samples[-1], 4),
        }

    # adapter conversion
    adapt_s = []
    for _ in range(iters):
        t0 = time.perf_counter()
        adapt_ml_prediction({"status": "ATTACK", "confidence": 90.0}, timestamp=_ts(0))
        adapt_entropy_metrics(
            {"status": "ALERT", "confidence": 85.0, "entropy_score": 0.2},
            timestamp=_ts(0),
        )
        adapt_s.append((time.perf_counter() - t0) * 1000.0)

    # registry update
    reg_s = []
    for i in range(iters):
        reg = EvidenceRegistry(max_records=64)
        t0 = time.perf_counter()
        r = adapt_ml_prediction({"status": "ATTACK", "confidence": 90.0}, timestamp=_ts(0))
        reg.put(result=r, switch_id=(i % 16) + 1)
        reg_s.append((time.perf_counter() - t0) * 1000.0)

    # fusion only
    fus_s = []
    results = list(pack.detector_results)
    for i in range(iters):
        t0 = time.perf_counter()
        eng.fuse(
            detector_results=results,
            correlation=pack.correlation,
            timestamp=_ts(1),
            switch_id=1,
            src_mac="02:aa:aa:aa:aa:01",
            fusion_id=f"perf-{i}",
        )
        fus_s.append((time.perf_counter() - t0) * 1000.0)

    # combined R6 path (prepare_collaborative_cycle)
    comb_s = []
    for i in range(iters):
        t0 = time.perf_counter()
        prepare_collaborative_cycle(
            switch_id=1,
            ml_prediction={"status": "ATTACK", "confidence": 92.0},
            entropy_metrics={"status": "ALERT", "confidence": 88.0, "entropy_score": 0.2},
            adwin_alerts=[{"metric_name": "flow_count"}],
            timestamp=_ts(1),
            persist_trace=False,
        )
        comb_s.append((time.perf_counter() - t0) * 1000.0)

    return {
        "kind": "r65_performance",
        "iters": iters,
        "adapter_conversion": _ms(adapt_s),
        "registry_update": _ms(reg_s),
        "fusion_only": _ms(fus_s),
        "combined_r6_path": _ms(comb_s),
    }


def run_all_r65_artifacts() -> Dict[str, str]:
    paths = {}
    paths["correctness"] = _write(
        "r65_fusion_correctness.json", run_correctness_matrix()
    )
    paths["disagreement"] = _write(
        "r65_disagreement_analysis.json", run_disagreement_analysis()
    )
    paths["reliability"] = _write(
        "r65_reliability_sensitivity.json", run_reliability_sensitivity()
    )
    paths["ablation"] = _write("r65_fusion_ablation.json", run_ablation())
    paths["legacy"] = _write("r65_legacy_comparison.json", run_legacy_comparison())
    paths["threshold"] = _write(
        "r65_threshold_sensitivity.json", run_threshold_sensitivity()
    )
    paths["performance"] = _write("r65_fusion_perf.json", run_performance())
    return paths
