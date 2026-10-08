"""Emit offline research artifacts for R3 (explicitly not live Mininet)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Union

from shared_contracts.serialize import to_dict
from twin.diversity import write_scenario_diversity_matrix
from twin.fidelity import build_fidelity_report, write_fidelity_report
from twin.isolation import project_root
from twin.manifest import build_manifest, write_manifest
from twin.offline import good_offline_metrics, poor_f1_metrics
from twin.planner import plan_scenario
from twin.profile import build_default_twin_profile
from twin.experiment_runner import TwinExperimentRunner
from shared_contracts.models import ModelCandidate, ModelVersion
from shared_contracts.timeutil import utc_now

PathLike = Union[str, Path]


def emit_research_artifacts(*, root: Optional[PathLike] = None) -> dict:
    """
    Write reproducible offline research artifacts under logs/twin/research/.

    Does not claim live Mininet results.
    """
    base = Path(root) if root else project_root()
    out_dir = base / "logs" / "twin" / "research"
    out_dir.mkdir(parents=True, exist_ok=True)

    profile = build_default_twin_profile(random_seed=42)
    (out_dir / "twin_profile_example.json").write_text(
        json.dumps(to_dict(profile), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    plan = plan_scenario("S2", seed=42)
    write_manifest(plan, out_dir / "scenario_manifest_example.json")

    matrix_path = write_scenario_diversity_matrix(root=base, seed=100, max_rows=9)

    report = build_fidelity_report(
        plan=plan,
        profile_fingerprint=profile.config_fingerprint,
        seed=42,
        candidate_isolated=True,
        mode="offline",
    )
    fidelity_path = write_fidelity_report(
        report, path=base / "logs" / "twin_fidelity_report.json", root=base
    )
    # Also copy under research/
    (out_dir / "twin_fidelity_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # Candidate validation example (offline synthetic)
    art = out_dir / "candidate_artifact.pkl"
    art.write_bytes(b"research-candidate")
    cand = ModelCandidate(
        candidate_id="research-cand-good",
        model=ModelVersion(
            model_id="ml-if-dt",
            version="research-1",
            algorithm="IsolationForest+DecisionTree",
            created_at=utc_now(),
            artifact_uri=str(art),
        ),
    )
    runner = TwinExperimentRunner(mode="offline", root=base)
    good = runner.validate_candidate(
        cand,
        seed=42,
        metrics_by_scenario={"S1": good_offline_metrics(), "S2": good_offline_metrics()},
    )
    bad_cand = ModelCandidate(
        candidate_id="research-cand-bad",
        model=ModelVersion(
            model_id="ml-if-dt",
            version="research-bad",
            algorithm="IsolationForest+DecisionTree",
            created_at=utc_now(),
            artifact_uri=str(art),
        ),
    )
    bad = runner.validate_candidate(
        bad_cand,
        seed=42,
        metrics_by_scenario={"S1": poor_f1_metrics(), "S2": poor_f1_metrics()},
    )
    (out_dir / "candidate_validation_example.json").write_text(
        json.dumps(
            {
                "mode": "offline_synthetic",
                "live_mininet": False,
                "good": to_dict(good),
                "bad": to_dict(bad),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    # Dataset manifest example (minimal synthetic features)
    from twin.dataset import TwinDatasetGenerator
    from evaluation.experiment_windows import AttackWindow
    from datetime import datetime, timedelta
    import csv
    from ml_models.feature_builder import FEATURE_NAMES

    logs = out_dir / "demo_logs"
    logs.mkdir(exist_ok=True)
    feats = logs / "ml_features.csv"
    base_ts = datetime(2026, 7, 27, 15, 0, 0)
    fmt = "%Y-%m-%d %H:%M:%S"
    with feats.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "switch_id", "label"] + list(FEATURE_NAMES))
        w.writerow([(base_ts + timedelta(seconds=5)).strftime(fmt), "1", "", *[0.1] * 15])
        w.writerow([(base_ts + timedelta(seconds=30)).strftime(fmt), "1", "", *[0.9] * 15])
    windows = [
        AttackWindow(
            scenario="SCENARIO_2_SYN_FLOOD",
            attack_start=base_ts + timedelta(seconds=20),
            attack_stop=base_ts + timedelta(seconds=50),
        )
    ]
    ds = TwinDatasetGenerator(root=base).generate(
        run_id="research-run-1",
        profile_id=profile.profile_id,
        profile_fingerprint=profile.config_fingerprint,
        scenario_id="S2",
        seed=42,
        features_csv=feats,
        logs_dir=logs,
        windows=windows,
        pad_sec=0,
        output_root=out_dir / "datasets",
        dataset_id="research-dataset-example",
    )
    # Copy manifest to well-known name
    (out_dir / "dataset_manifest_example.json").write_text(
        json.dumps(ds.manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    index = {
        "schema": "intellishield.twin.research_index.v1",
        "mode": "offline",
        "live_mininet": False,
        "artifacts": {
            "twin_profile_example": str(out_dir / "twin_profile_example.json"),
            "scenario_manifest_example": str(out_dir / "scenario_manifest_example.json"),
            "scenario_diversity_matrix": str(matrix_path),
            "twin_fidelity_report": str(fidelity_path),
            "candidate_validation_example": str(out_dir / "candidate_validation_example.json"),
            "dataset_manifest_example": str(out_dir / "dataset_manifest_example.json"),
        },
    }
    (out_dir / "index.json").write_text(
        json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return index
