"""Offline deterministic twin experiment harness (not live Mininet)."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from twin.experiment_plan import ExperimentEvidence, TwinExperimentPlan
from twin.manifest import build_manifest


def synthetic_evidence_for_plan(
    plan: TwinExperimentPlan,
    *,
    metrics_by_scenario: Optional[Mapping[str, Mapping[str, Any]]] = None,
    experiment_ok: bool = True,
    experiment_error: str = "",
    missing_artifacts: Optional[Sequence[str]] = None,
) -> List[ExperimentEvidence]:
    """
    Build deterministic ExperimentEvidence from caller-supplied metrics.

    Explicitly tagged source=offline_synthetic — not live Twin validation.
    """
    metrics_by_scenario = metrics_by_scenario or {}
    missing = list(missing_artifacts or [])
    out: List[ExperimentEvidence] = []
    for sp in plan.scenario_plans:
        raw = dict(metrics_by_scenario.get(sp.scenario_id, {}))
        out.append(
            ExperimentEvidence(
                scenario_id=sp.scenario_id,
                metrics=raw,
                seed=plan.seed,
                profile_fingerprint=plan.profile_fingerprint,
                scenario_manifest=build_manifest(sp),
                missing_artifacts=list(missing),
                experiment_ok=experiment_ok,
                experiment_error=experiment_error if not experiment_ok else "",
                source="offline_synthetic",
            )
        )
    return out


def good_offline_metrics() -> Dict[str, Any]:
    """Metrics that pass the default twin policy."""
    return {
        "precision": 0.90,
        "recall": 0.88,
        "f1_score": 0.89,
        "false_positive_rate": 0.05,
        "false_negative_rate": 0.12,
        "detection_latency_s": 8.0,
        "runtime_latency_s": 0.05,
        "accuracy": 0.92,
    }


def poor_f1_metrics() -> Dict[str, Any]:
    m = good_offline_metrics()
    m["f1_score"] = 0.40
    m["precision"] = 0.45
    m["recall"] = 0.36
    return m


def high_fpr_metrics() -> Dict[str, Any]:
    m = good_offline_metrics()
    m["false_positive_rate"] = 0.45
    m["precision"] = 0.55
    return m


def high_latency_metrics() -> Dict[str, Any]:
    m = good_offline_metrics()
    m["detection_latency_s"] = 90.0
    return m


def low_recall_metrics() -> Dict[str, Any]:
    m = good_offline_metrics()
    m["recall"] = 0.20
    m["false_negative_rate"] = 0.80
    m["f1_score"] = 0.33
    return m
