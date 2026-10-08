"""Twin experiment runner + validate_candidate boundary (R3.3)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union
from uuid import uuid4

from evaluation.experiment_bundle import get_git_version
from shared_contracts.enums import TwinRunPurpose, TwinRunStatus
from shared_contracts.models import (
    ModelCandidate,
    ModelVersion,
    TwinProfile,
    TwinValidationPolicy,
    ValidationResult,
)
from shared_contracts.serialize import to_dict
from shared_contracts.timeutil import utc_now
from twin.experiment_plan import (
    ExperimentEvidence,
    TwinExperimentPlan,
    validate_experiment_plan,
)
from twin.isolation import (
    assert_candidate_isolated,
    ensure_paths_not_written,
    production_model_paths,
    project_root,
    twin_candidate_dir,
)
from twin.offline import synthetic_evidence_for_plan
from twin.planner import plan_scenario
from twin.profile import build_default_twin_profile, default_validation_policy
from twin.run_guard import acquire_twin_run_slot
from twin.validate import TwinValidationError
from twin.validation_engine import TwinValidationEngine


PathLike = Union[str, Path]


class TwinExperimentRunner:
    """
    Orchestrate twin experiment planning → evidence → ValidationResult.

    Default mode is offline (synthetic metrics). Live Mininet execution is
    intentionally not claimed complete in R3.3.
    """

    def __init__(
        self,
        *,
        mode: str = "offline",
        root: Optional[PathLike] = None,
        policy: Optional[TwinValidationPolicy] = None,
    ) -> None:
        if mode not in ("offline", "live_mininet"):
            raise TwinValidationError(f"unsupported mode: {mode!r}")
        self.mode = mode
        self.root = Path(root) if root else project_root()
        self.policy = policy or default_validation_policy()
        self.engine = TwinValidationEngine(policy=self.policy)
        self._written: List[Path] = []

    def build_plan(
        self,
        *,
        candidate: ModelCandidate,
        scenario_ids: Sequence[str],
        seed: int = 42,
        profile: Optional[TwinProfile] = None,
        baseline: Optional[ModelVersion] = None,
        overrides_by_scenario: Optional[Mapping[str, Mapping[str, Any]]] = None,
        run_id: Optional[str] = None,
    ) -> TwinExperimentPlan:
        profile = profile or build_default_twin_profile(random_seed=seed)
        assert_candidate_isolated(candidate, root=self.root, allow_missing_artifact=True)

        plans = []
        ov_map = overrides_by_scenario or {}
        for sid in scenario_ids:
            plans.append(
                plan_scenario(
                    sid,
                    overrides=ov_map.get(sid),
                    profile=profile,
                    seed=seed,
                )
            )

        git = get_git_version(str(self.root))
        artifact_dir = twin_candidate_dir(candidate.candidate_id, root=self.root) / (
            run_id or "pending"
        )

        plan = TwinExperimentPlan(
            run_id=run_id or f"twinrun-{uuid4().hex[:12]}",
            profile=profile,
            scenario_plans=plans,
            seed=seed,
            candidate=candidate,
            baseline=baseline,
            purpose=TwinRunPurpose.VALIDATION,
            status=TwinRunStatus.PLANNED,
            artifact_dir=str(artifact_dir),
            git_commit=str(git.get("commit", "unknown")),
            expected_ground_truth={
                sp.scenario_id: {
                    "expected_attack": sp.expected_attack,
                    "family": sp.expected_attack_family,
                    "timeline": sp.expected_timeline(),
                }
                for sp in plans
            },
            parameters={
                "scenario_ids": list(scenario_ids),
                "seed": seed,
                "mode": self.mode,
                "profile_fingerprint": profile.config_fingerprint,
            },
            mode=self.mode,
        )
        validate_experiment_plan(plan)
        plan.status = TwinRunStatus.VALIDATED
        return plan

    def run_offline(
        self,
        plan: TwinExperimentPlan,
        *,
        metrics_by_scenario: Optional[Mapping[str, Mapping[str, Any]]] = None,
        baseline_metrics: Optional[Dict[str, Any]] = None,
        experiment_ok: bool = True,
        experiment_error: str = "",
        missing_artifacts: Optional[Sequence[str]] = None,
    ) -> ValidationResult:
        """
        Execute offline validation using synthetic/precomputed metrics.

        Distinguishes:
          - experiment failure → ValidationStatus.ERROR / EXPERIMENT_FAILED
          - candidate quality failure → ValidationStatus.FAIL
        Experiment SUCCEEDED can still yield FAIL ValidationResult.
        """
        with acquire_twin_run_slot():
            return self._run_offline_unlocked(
                plan,
                metrics_by_scenario=metrics_by_scenario,
                baseline_metrics=baseline_metrics,
                experiment_ok=experiment_ok,
                experiment_error=experiment_error,
                missing_artifacts=missing_artifacts,
            )

    def _run_offline_unlocked(
        self,
        plan: TwinExperimentPlan,
        *,
        metrics_by_scenario: Optional[Mapping[str, Mapping[str, Any]]] = None,
        baseline_metrics: Optional[Dict[str, Any]] = None,
        experiment_ok: bool = True,
        experiment_error: str = "",
        missing_artifacts: Optional[Sequence[str]] = None,
    ) -> ValidationResult:
        if plan.mode != "offline" and self.mode != "offline":
            # Still allow offline evaluation of a live-labelled plan for tests
            pass
        evidence = synthetic_evidence_for_plan(
            plan,
            metrics_by_scenario=metrics_by_scenario,
            experiment_ok=experiment_ok,
            experiment_error=experiment_error,
            missing_artifacts=missing_artifacts,
        )
        return self._persist_evaluation(
            plan, evidence, baseline_metrics=baseline_metrics
        )

    def validate_candidate(
        self,
        candidate: ModelCandidate,
        *,
        scenario_ids: Optional[Sequence[str]] = None,
        seed: int = 42,
        profile: Optional[TwinProfile] = None,
        baseline: Optional[ModelVersion] = None,
        baseline_metrics: Optional[Dict[str, Any]] = None,
        metrics_by_scenario: Optional[Mapping[str, Mapping[str, Any]]] = None,
        missing_artifacts: Optional[Sequence[str]] = None,
        experiment_ok: bool = True,
        experiment_error: str = "",
    ) -> ValidationResult:
        """
        Stable boundary for future R9/R1:

            validate_candidate(candidate) -> ValidationResult
        """
        scenario_ids = list(scenario_ids or self.policy.require_scenario_ids or ["S1", "S2"])
        plan = self.build_plan(
            candidate=candidate,
            scenario_ids=scenario_ids,
            seed=seed,
            profile=profile,
            baseline=baseline,
        )
        if self.mode == "live_mininet":
            # Twin must not launch Mininet. Observational ingest is the live path.
            plan.mode = "live_mininet"
            plan.status = TwinRunStatus.FAILED
            return self.run_offline(
                plan,
                metrics_by_scenario={},
                experiment_ok=False,
                experiment_error=(
                    "LIVE_MININET_NOT_RUN: twin does not launch Mininet; "
                    "use ingest_experiment_logs(logs_dir) for observational live evidence. "
                    "see docs/R3_LIVE_MININET_VALIDATION_CHECKLIST.md"
                ),
            )
        return self.run_offline(
            plan,
            metrics_by_scenario=metrics_by_scenario,
            baseline_metrics=baseline_metrics,
            experiment_ok=experiment_ok,
            experiment_error=experiment_error,
            missing_artifacts=missing_artifacts,
        )

    def ingest_experiment_logs(
        self,
        logs_dir: PathLike,
        *,
        candidate: ModelCandidate,
        scenario_ids: Optional[Sequence[str]] = None,
        seed: int = 42,
        profile: Optional[TwinProfile] = None,
        baseline: Optional[ModelVersion] = None,
        baseline_metrics: Optional[Dict[str, Any]] = None,
    ) -> ValidationResult:
        """
        Observational live/historical integration.

        Reads a completed experiment directory (no Mininet launch, no
        mitigation/OpenFlow writes) and evaluates the candidate against
        ieee_metrics / metrics_report evidence.
        """
        from twin.evidence_from_logs import evidence_for_plan_from_logs
        from twin.snapshot import capture_snapshot

        scenario_ids = list(scenario_ids or self.policy.require_scenario_ids or ["S1", "S2"])
        plan = self.build_plan(
            candidate=candidate,
            scenario_ids=scenario_ids,
            seed=seed,
            profile=profile,
            baseline=baseline,
        )
        plan.mode = "experiment_logs"
        snap = capture_snapshot(logs_dir, root=self.root, profile=plan.profile, persist=True)
        evidence = evidence_for_plan_from_logs(
            plan.scenario_plans,
            logs_dir,
            seed=seed,
            profile_fingerprint=plan.profile_fingerprint,
            metrics_report_path=snap.get("metrics_report") or None,
        )
        return self._persist_evaluation(
            plan,
            evidence,
            baseline_metrics=baseline_metrics,
        )

    def _persist_evaluation(
        self,
        plan: TwinExperimentPlan,
        evidence: Sequence[ExperimentEvidence],
        *,
        baseline_metrics: Optional[Dict[str, Any]] = None,
    ) -> ValidationResult:
        validate_experiment_plan(plan)
        assert_candidate_isolated(
            plan.candidate, root=self.root, allow_missing_artifact=True
        )
        prod_snapshot = {
            p: (p.stat().st_mtime_ns if p.exists() else None)
            for p in production_model_paths(root=self.root)
        }
        plan.status = TwinRunStatus.RUNNING
        plan.started_at = utc_now()
        artifact_dir = Path(plan.artifact_dir)
        if artifact_dir.name == "pending":
            artifact_dir = twin_candidate_dir(
                plan.candidate.candidate_id, root=self.root
            ) / plan.run_id
            plan.artifact_dir = str(artifact_dir)
        artifact_dir.mkdir(parents=True, exist_ok=True)

        evidence_list = list(evidence)
        self._write_json(artifact_dir / "experiment_plan.json", self._plan_dict(plan))
        self._write_json(
            artifact_dir / "scenario_manifests.json",
            {e.scenario_id: e.scenario_manifest for e in evidence_list},
        )
        self._write_json(
            artifact_dir / "evidence.json",
            [self._evidence_dict(e) for e in evidence_list],
        )
        if any(not e.experiment_ok for e in evidence_list):
            plan.status = TwinRunStatus.FAILED
            plan.experiment_error = next(
                (e.experiment_error for e in evidence_list if not e.experiment_ok),
                "experiment failed",
            )
            plan.finished_at = utc_now()
            result = self.engine.evaluate(
                candidate=plan.candidate,
                evidence=evidence_list,
                baseline_metrics=baseline_metrics,
                artifact_uri=str(artifact_dir),
            )
            self._write_json(artifact_dir / "validation_result.json", to_dict(result))
            self._assert_production_untouched(prod_snapshot)
            return result

        result = self.engine.evaluate(
            candidate=plan.candidate,
            evidence=evidence_list,
            baseline_metrics=baseline_metrics,
            artifact_uri=str(artifact_dir),
        )
        self._write_json(artifact_dir / "validation_result.json", to_dict(result))
        self._write_twin_bundle_sidecar(plan, result, evidence_list, artifact_dir)
        plan.status = TwinRunStatus.SUCCEEDED
        plan.finished_at = utc_now()
        self._assert_production_untouched(prod_snapshot)
        ensure_paths_not_written(self._written, root=self.root)
        return result

    def _write_json(self, path: Path, data: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._written.append(path)

    def _assert_production_untouched(self, snapshot: Dict[Path, Optional[int]]) -> None:
        for p, before in snapshot.items():
            after = p.stat().st_mtime_ns if p.exists() else None
            if before != after:
                raise TwinValidationError(
                    f"production model path changed during twin run: {p}"
                )

    def _write_twin_bundle_sidecar(
        self,
        plan: TwinExperimentPlan,
        result: ValidationResult,
        evidence: List[ExperimentEvidence],
        artifact_dir: Path,
    ) -> None:
        """Twin-specific manifest extending experiment bundle concepts."""
        checksums = {}
        for f in artifact_dir.iterdir():
            if f.is_file():
                import hashlib

                checksums[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()
        sidecar = {
            "schema": "intellishield.twin.experiment_bundle.v1",
            "run_id": plan.run_id,
            "profile_id": plan.profile.profile_id,
            "profile_version": plan.profile.version,
            "profile_fingerprint": plan.profile_fingerprint,
            "seed": plan.seed,
            "git_commit": plan.git_commit,
            "candidate_id": plan.candidate.candidate_id,
            "model_id": plan.candidate.model.model_id,
            "baseline_model_id": plan.baseline.model_id if plan.baseline else "",
            "scenario_ids": plan.scenario_ids,
            "mode": plan.mode,
            "validation_status": result.status.value,
            "outcome_code": result.metrics.get("outcome_code"),
            "metrics": {
                k: result.metrics.get(k)
                for k in (
                    "precision",
                    "recall",
                    "f1_score",
                    "false_positive_rate",
                    "detection_latency_s",
                )
            },
            "checksums": checksums,
            "notes": (
                "Offline synthetic evidence is not live Mininet twin validation."
                if any(e.source == "offline_synthetic" for e in evidence)
                else (
                    "Observational experiment-log evidence; twin did not launch Mininet."
                    if any(e.source == "experiment_logs" for e in evidence)
                    else ""
                )
            ),
        }
        self._write_json(artifact_dir / "twin_experiment_manifest.json", sidecar)

    def _plan_dict(self, plan: TwinExperimentPlan) -> Dict[str, Any]:
        return {
            "run_id": plan.run_id,
            "status": plan.status.value,
            "seed": plan.seed,
            "mode": plan.mode,
            "profile": to_dict(plan.profile),
            "candidate": to_dict(plan.candidate),
            "baseline": to_dict(plan.baseline) if plan.baseline else None,
            "scenario_ids": plan.scenario_ids,
            "expected_ground_truth": plan.expected_ground_truth,
            "parameters": plan.parameters,
            "artifact_dir": plan.artifact_dir,
            "git_commit": plan.git_commit,
            "profile_fingerprint": plan.profile_fingerprint,
        }

    def _evidence_dict(self, e: ExperimentEvidence) -> Dict[str, Any]:
        return {
            "scenario_id": e.scenario_id,
            "metrics": e.metrics,
            "seed": e.seed,
            "profile_fingerprint": e.profile_fingerprint,
            "missing_artifacts": e.missing_artifacts,
            "experiment_ok": e.experiment_ok,
            "experiment_error": e.experiment_error,
            "source": e.source,
        }


def validate_candidate(
    candidate: ModelCandidate,
    *,
    policy: Optional[TwinValidationPolicy] = None,
    scenario_ids: Optional[Sequence[str]] = None,
    seed: int = 42,
    metrics_by_scenario: Optional[Mapping[str, Mapping[str, Any]]] = None,
    baseline_metrics: Optional[Dict[str, Any]] = None,
    mode: str = "offline",
    root: Optional[PathLike] = None,
) -> ValidationResult:
    """Module-level stable API for R9/R1 integration later."""
    runner = TwinExperimentRunner(mode=mode, root=root, policy=policy)
    return runner.validate_candidate(
        candidate,
        scenario_ids=scenario_ids,
        seed=seed,
        metrics_by_scenario=metrics_by_scenario,
        baseline_metrics=baseline_metrics,
    )
