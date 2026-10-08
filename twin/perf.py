"""Software-side R3 microbenchmarks (not Mininet wall-clock)."""

from __future__ import annotations

import time
from typing import Any, Dict

from shared_contracts.models import ModelCandidate, ModelVersion
from shared_contracts.timeutil import utc_now
from twin.experiment_plan import ExperimentEvidence
from twin.fidelity import build_fidelity_report
from twin.fingerprint import fingerprint_profile
from twin.offline import good_offline_metrics
from twin.planner import plan_scenario
from twin.profile import build_default_twin_profile, default_validation_policy
from twin.validation_engine import TwinValidationEngine


def _ns() -> int:
    return time.perf_counter_ns()


def benchmark_r3_software(*, iterations: int = 20) -> Dict[str, Any]:
    """Median latencies in milliseconds for core twin operations."""
    cand = ModelCandidate(
        candidate_id="bench",
        model=ModelVersion(
            model_id="m",
            version="1",
            algorithm="IF",
            created_at=utc_now(),
            artifact_uri="/tmp/nonexistent_bench.pkl",
        ),
    )
    engine = TwinValidationEngine(policy=default_validation_policy())
    metrics = good_offline_metrics()

    def med(samples: list) -> float:
        s = sorted(samples)
        return round(s[len(s) // 2] / 1e6, 4)  # ns → ms

    t_profile, t_fp, t_plan, t_val = [], [], [], []
    for _ in range(iterations):
        a = _ns()
        p = build_default_twin_profile()
        t_profile.append(_ns() - a)

        a = _ns()
        fingerprint_profile(p)
        t_fp.append(_ns() - a)

        a = _ns()
        plan_scenario("S2", profile=p, seed=42)
        t_plan.append(_ns() - a)

        evidence = [
            ExperimentEvidence(
                scenario_id="S1",
                metrics=metrics,
                seed=42,
                profile_fingerprint=p.config_fingerprint,
                source="offline_synthetic",
            ),
            ExperimentEvidence(
                scenario_id="S2",
                metrics=metrics,
                seed=42,
                profile_fingerprint=p.config_fingerprint,
                source="offline_synthetic",
            ),
        ]
        a = _ns()
        engine.evaluate(candidate=cand, evidence=evidence)
        t_val.append(_ns() - a)

    a = _ns()
    build_fidelity_report(plan=plan_scenario("S2", seed=1), seed=1)
    fidelity_ms = round((_ns() - a) / 1e6, 4)

    return {
        "schema": "intellishield.twin.perf_benchmark.v1",
        "iterations": iterations,
        "unit": "ms_median",
        "excludes": "Mininet experiment wall-clock",
        "profile_load_ms": med(t_profile),
        "fingerprint_ms": med(t_fp),
        "scenario_planning_ms": med(t_plan),
        "validation_calculation_ms": med(t_val),
        "fidelity_report_ms": fidelity_ms,
    }
