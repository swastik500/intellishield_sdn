"""
IntelliShield SDN — Digital Twin plane (R3).

R3.1 model/audit · R3.2 parameterized scenarios · R3.3 validation
R3.4 training data + dashboard · R3.5 fidelity/safety/acceptance
R3.6 observational snapshot / replay / what-if (read-only vs live SDN)

Does NOT auto-promote models or train AutoML/adaptive challengers.
"""

from twin.dataset import TwinDatasetGenerator
from twin.diversity import build_scenario_diversity_matrix, write_scenario_diversity_matrix
from twin.dry_run import describe_plan, dry_run_scenario
from twin.engine import plan_and_manifest
from twin.evidence_from_logs import evidence_for_plan_from_logs, evidence_metrics_from_logs
from twin.pipeline import ingest_experiment
from twin.replay import replay_scenario
from twin.snapshot import capture_snapshot
from twin.whatif import simulate_whatif
from twin.experiment_runner import TwinExperimentRunner, validate_candidate
from twin.feature_schema import FEATURE_SCHEMA_VERSION, canonical_feature_schema
from twin.fidelity import (
    FIDELITY_DIMENSIONS,
    VALID_FIDELITY_STATUSES,
    build_fidelity_report,
    compact_fidelity_summary,
    observed_from_snapshot,
    overall_verdict,
    write_fidelity_report,
)
from twin.fingerprint import fingerprint_profile
from twin.history import (
    get_twin_run,
    get_twin_snapshot,
    read_twin_datasets,
    read_twin_replays,
    read_twin_runs,
    read_twin_simulations,
    read_twin_snapshots,
    read_twin_validations,
    twin_history_stats,
)
from twin.intensity import intensity_documentation
from twin.inventory import SIMULATION_INVENTORY, inventory_summary
from twin.leakage import assert_no_leakage, detect_dataset_leakage
from twin.manifest import build_manifest, manifest_to_json, write_manifest
from twin.offline import (
    good_offline_metrics,
    high_fpr_metrics,
    high_latency_metrics,
    low_recall_metrics,
    poor_f1_metrics,
)
from twin.perf import benchmark_r3_software
from twin.planner import default_plan, plan_scenario
from twin.profile import (
    build_default_twin_profile,
    default_validation_policy,
    with_seed,
    with_version,
)
from twin.research import emit_research_artifacts
from twin.scenario_audit import scenario_parameter_audit
from twin.scenario_spec import GENERATOR_VERSION, ScenarioPlan
from twin.scenarios import baseline_scenario_catalog, get_baseline_scenario
from twin.subprocess_safe import run_python_module
from twin.topology import build_default_topology, export_topology_dict
from twin.validate import (
    TwinValidationError,
    validate_scenario_id,
    validate_topology,
    validate_twin_profile,
)
from twin.validation_engine import TwinValidationEngine
from twin.variants import generate_variants

__all__ = [
    "FEATURE_SCHEMA_VERSION",
    "FIDELITY_DIMENSIONS",
    "VALID_FIDELITY_STATUSES",
    "GENERATOR_VERSION",
    "SIMULATION_INVENTORY",
    "ScenarioPlan",
    "TwinDatasetGenerator",
    "TwinExperimentRunner",
    "TwinValidationEngine",
    "TwinValidationError",
    "assert_no_leakage",
    "baseline_scenario_catalog",
    "benchmark_r3_software",
    "build_default_topology",
    "build_default_twin_profile",
    "build_fidelity_report",
    "compact_fidelity_summary",
    "observed_from_snapshot",
    "overall_verdict",
    "build_manifest",
    "build_scenario_diversity_matrix",
    "canonical_feature_schema",
    "default_plan",
    "default_validation_policy",
    "describe_plan",
    "detect_dataset_leakage",
    "dry_run_scenario",
    "emit_research_artifacts",
    "export_topology_dict",
    "fingerprint_profile",
    "generate_variants",
    "get_baseline_scenario",
    "capture_snapshot",
    "evidence_for_plan_from_logs",
    "evidence_metrics_from_logs",
    "get_twin_run",
    "get_twin_snapshot",
    "ingest_experiment",
    "good_offline_metrics",
    "high_fpr_metrics",
    "high_latency_metrics",
    "intensity_documentation",
    "inventory_summary",
    "low_recall_metrics",
    "manifest_to_json",
    "plan_and_manifest",
    "plan_scenario",
    "poor_f1_metrics",
    "read_twin_datasets",
    "read_twin_replays",
    "read_twin_runs",
    "read_twin_simulations",
    "read_twin_snapshots",
    "read_twin_validations",
    "replay_scenario",
    "run_python_module",
    "scenario_parameter_audit",
    "simulate_whatif",
    "twin_history_stats",
    "validate_candidate",
    "validate_scenario_id",
    "validate_topology",
    "validate_twin_profile",
    "with_seed",
    "with_version",
    "write_fidelity_report",
    "write_manifest",
    "write_scenario_diversity_matrix",
]

__version__ = "0.6.0"
