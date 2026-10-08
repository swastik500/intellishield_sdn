"""
Observational twin pipeline: experiment logs → snapshot → replay / what-if / gates.

Does not launch Mininet, does not call mitigation, does not write logs/models/.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Union

from shared_contracts.models import ModelCandidate, ModelVersion, TwinProfile
from twin.experiment_runner import TwinExperimentRunner
from twin.fidelity import (
    build_fidelity_report,
    compact_fidelity_summary,
    observed_from_snapshot,
    overall_verdict,
    write_fidelity_report,
)
from twin.isolation import project_root
from twin.planner import plan_scenario
from twin.replay import replay_scenario
from twin.snapshot import capture_snapshot
from twin.validate import TwinValidationError
from twin.whatif import simulate_whatif

PathLike = Union[str, Path]

LIVE_MININET_NOT_RUN_MSG = (
    "LIVE_MININET_NOT_RUN: twin does not launch Mininet; "
    "use completed experiment logs via ingest_experiment(logs_dir). "
    "see docs/R3_LIVE_MININET_VALIDATION_CHECKLIST.md / "
    "docs/R3_LEVEL_A_COMPLETION_ROADMAP.md"
)


def ingest_experiment(
    logs_dir: PathLike,
    *,
    scenario_id: str = "S2",
    seed: int = 42,
    overrides: Optional[Mapping[str, Any]] = None,
    root: Optional[PathLike] = None,
    profile: Optional[TwinProfile] = None,
    persist: bool = True,
    candidate: Optional[ModelCandidate] = None,
    baseline: Optional[ModelVersion] = None,
    validate: bool = True,
) -> Dict[str, Any]:
    """
    Minimum safe live-experiment integration:

        completed lab logs → bounded snapshot → replay + what-if + optional gate

    Level A summary contract (stable keys):
        snapshot_id, replay.sequence_ok, temporal_error_sec,
        fidelity / fidelity_summary / overall, package, safety flags.
    """
    t0 = time.perf_counter()
    snap = capture_snapshot(
        logs_dir, root=root, profile=profile, persist=persist
    )
    t_snap = time.perf_counter()
    replay = replay_scenario(
        snap, scenario_id, seed=seed, persist=persist, root=root
    )
    t_replay = time.perf_counter()
    sim = simulate_whatif(
        snap,
        scenario_id,
        overrides=overrides,
        seed=seed,
        persist=persist,
        root=root,
    )
    t_sim = time.perf_counter()

    plan = plan_scenario(scenario_id, seed=seed, profile=profile)
    observed = observed_from_snapshot(snap, replay=replay)
    live_pipeline_seen = bool(
        (snap.get("jsonl_counts") or {}).get("fused_decisions.jsonl")
        or (snap.get("jsonl_counts") or {}).get("verification_trace.jsonl")
        or (snap.get("csv_counts") or {}).get("ml_predictions.csv")
    )
    fidelity = build_fidelity_report(
        plan=plan,
        profile_fingerprint=snap.get("profile_fingerprint") or "",
        seed=seed,
        candidate_isolated=True,
        observed=observed,
        live_pipeline_seen=live_pipeline_seen,
        mode="experiment_logs",
    )
    if persist:
        base = Path(root) if root else project_root()
        write_fidelity_report(
            fidelity,
            path=base
            / "logs"
            / "twin"
            / "snapshots"
            / snap["snapshot_id"]
            / "fidelity_report.json",
            root=base,
        )

    validation: Optional[Dict[str, Any]] = None
    if validate and candidate is not None:
        runner = TwinExperimentRunner(mode="offline", root=root)
        validation = runner.ingest_experiment_logs(
            logs_dir,
            candidate=candidate,
            scenario_ids=[scenario_id],
            seed=seed,
            profile=profile,
            baseline=baseline,
        )
        validation = {
            "status": validation.status.value,
            "reason": validation.reason,
            "metrics": validation.metrics,
            "candidate_id": validation.candidate_id,
            "artifact_uri": validation.artifact_uri,
        }

    elapsed_ms = {
        "snapshot_ms": round((t_snap - t0) * 1000, 3),
        "replay_ms": round((t_replay - t_snap) * 1000, 3),
        "whatif_ms": round((t_sim - t_replay) * 1000, 3),
        "total_ms": round((time.perf_counter() - t0) * 1000, 3),
        "measurement": "software_wall_clock",
        "live_mininet": False,
    }

    artifact_dir = str(snap.get("artifact_dir") or "")
    package = {
        "twin_snapshot.json": bool(artifact_dir)
        and (Path(artifact_dir) / "twin_snapshot.json").is_file(),
        "twin_observation.json": bool(artifact_dir)
        and (Path(artifact_dir) / "twin_observation.json").is_file(),
        "fidelity_report.json": bool(artifact_dir)
        and (Path(artifact_dir) / "fidelity_report.json").is_file(),
    }
    if persist:
        # fidelity just written — recompute package flag
        package["fidelity_report.json"] = (
            Path(artifact_dir) / "fidelity_report.json"
        ).is_file() if artifact_dir else False

    temporal_error = replay.get("temporal_error")
    fidelity_summary = dict(fidelity.get("summary") or {})
    return {
        "schema": "intellishield.twin.ingest.v1",
        "snapshot_id": snap.get("snapshot_id"),
        "snapshot": snap,
        "replay": replay,
        "whatif": sim,
        "fidelity": fidelity,
        "fidelity_summary": fidelity_summary,
        "overall": fidelity.get("overall") or overall_verdict(fidelity_summary),
        "fidelity_compact": compact_fidelity_summary(fidelity),
        "sequence_ok": bool(replay.get("sequence_ok")),
        "temporal_error_sec": temporal_error,
        "temporal_error": temporal_error,
        "package": package,
        "validation": validation,
        "performance": elapsed_ms,
        "control": "READ_ONLY",
        "mutates_mitigation": False,
        "mutates_controller": False,
        "launches_mininet": False,
        "launches_traffic": False,
        "live_mininet_note": LIVE_MININET_NOT_RUN_MSG,
    }


def require_logs_dir(logs_dir: PathLike) -> Path:
    path = Path(logs_dir)
    if not path.is_dir():
        raise TwinValidationError(f"experiment logs dir missing: {path}")
    return path
