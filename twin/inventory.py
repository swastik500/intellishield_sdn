"""R3.1 simulation foundation inventory (code-audited; not aspirational)."""

from __future__ import annotations

from typing import Any, Dict, List


SIMULATION_INVENTORY: Dict[str, Any] = {
    "definition": (
        "security-oriented SDN digital twin — reproducible software "
        "representation of the protected Mininet lab environment"
    ),
    "explicit_non_claim": "Mininet + attack scripts alone are NOT the Digital Twin",
    "reuse_do_not_rebuild": [
        {
            "component": "IntelliShieldTopo",
            "path": "traffic_generator/traffic_scheduler.py",
            "role": "star topology s1 + h1..hN",
        },
        {
            "component": "TrafficScheduler",
            "path": "traffic_generator/traffic_scheduler.py",
            "role": "Mininet start/stop + scenario orchestration",
        },
        {
            "component": "S1-S5 scenarios",
            "path": "traffic_generator/attack_scenarios.py",
            "role": "scenario control + ATTACK_START/STOP ground truth",
        },
        {
            "component": "AttackGenerator",
            "path": "traffic_generator/attack_generator.py",
            "role": "lab-only floods with subnet safety guard",
        },
        {
            "component": "traffic_profiles",
            "path": "traffic_generator/traffic_profiles.py",
            "role": "NormalTrafficProfile / AttackProfile / SCENARIO_TEMPLATES",
        },
        {
            "component": "experiment_windows",
            "path": "evaluation/experiment_windows.py",
            "role": "parse scenario/attack windows as ground truth",
        },
        {
            "component": "ieee_metrics",
            "path": "evaluation/ieee_metrics.py",
            "role": "precision/recall/F1/FPR and system metrics",
        },
        {
            "component": "experiment_bundle",
            "path": "evaluation/experiment_bundle.py",
            "role": "traceable experiment artifact packages",
        },
        {
            "component": "ModelCandidate/ValidationResult",
            "path": "shared_contracts/models.py",
            "role": "future twin validation gate boundary",
        },
    ],
    "r31_delivered": [
        "TwinProfile / TwinTopology / TwinScenario contracts",
        "TwinRun / TwinObservation / TwinValidationPolicy shapes",
        "default profile + topology export helpers",
        "topology/profile/scenario validation",
        "baseline S1–S5 scenario catalog with expected_* fields",
        "S1–S5 controllable vs hardcoded parameter audit",
        "config fingerprint helper (SHA-256)",
        "lab target safety helper",
        "this inventory",
    ],
    "deferred": {},
    "r33_delivered": [
        "TwinExperimentPlan + lifecycle statuses",
        "TwinExperimentRunner (offline harness)",
        "TwinValidationEngine → ValidationResult",
        "candidate isolation from logs/models/",
        "validate_candidate() boundary",
        "safe subprocess allow-list helper",
        "twin experiment manifest sidecar",
    ],
    "r34_delivered": [
        "TwinDatasetGenerator (scenario-control labels)",
        "feature schema hash/version checks",
        "dataset CSV + JSON manifest",
        "scenario/run-level split provenance",
        "read-only digital-twin dashboard APIs",
        "twin history reader",
    ],
    "r35_delivered": [
        "multi-dimension fidelity model + report",
        "scenario diversity matrix (bounded)",
        "dataset leakage detection",
        "resource bounds + concurrent run guard",
        "software-side R3 microbenchmarks",
        "offline research artifact emitter",
        "acceptance/failure-injection tests",
        "live Mininet checklist (NOT RUN if unavailable)",
    ],
    "ground_truth_rule": (
        "Labels originate from scenario control / attack logs only — "
        "never from ML, R6, or mitigation outcomes"
    ),
    "safety_rule": (
        "Twin attack generation remains lab/Mininet-only; "
        "no Internet-target attack mechanisms"
    ),
    "isolation_rule": (
        "R3 orchestration must not alter production detection on failure; "
        "controller runtime is not modified; twin never calls mitigation"
    ),
    "r36_delivered": [
        "bounded experiment-log snapshot (TwinObservation)",
        "scenario event replay vs expected S1–S5 timeline",
        "plan-space what-if vs observed windows",
        "ieee_metrics / metrics_report evidence (not synthetic)",
        "ingest_experiment_logs observational live path",
        "read-only snapshot/replay/simulation dashboard APIs",
    ],
    "auto_promotion_forbidden": True,
}


def inventory_summary() -> Dict[str, Any]:
    """Compact summary for tests / docs generators."""
    reuse: List[str] = [r["component"] for r in SIMULATION_INVENTORY["reuse_do_not_rebuild"]]
    return {
        "reuse_count": len(reuse),
        "reuse": reuse,
        "r31_count": len(SIMULATION_INVENTORY["r31_delivered"]),
        "deferred_phases": list(SIMULATION_INVENTORY["deferred"].keys()),
        "auto_promotion_forbidden": SIMULATION_INVENTORY["auto_promotion_forbidden"],
        "r32_complete": True,
        "r33_complete": "r33_delivered" in SIMULATION_INVENTORY,
        "r34_complete": "r34_delivered" in SIMULATION_INVENTORY,
        "r35_complete": "r35_delivered" in SIMULATION_INVENTORY,
        "r36_complete": "r36_delivered" in SIMULATION_INVENTORY,
    }
