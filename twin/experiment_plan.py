"""Twin experiment plan + evidence records (R3.3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from shared_contracts.enums import TwinRunPurpose, TwinRunStatus
from shared_contracts.models import ModelCandidate, ModelVersion, TwinProfile
from shared_contracts.timeutil import utc_now
from twin.scenario_spec import ScenarioPlan
from twin.validate import TwinValidationError, validate_scenario_id


@dataclass
class TwinExperimentPlan:
    """
    Mutable plan/run record for a twin experiment lifecycle.

    Distinguishes experiment failure (status=FAILED) from candidate
    validation failure (status may still be SUCCEEDED with ValidationResult.FAIL).
    """

    run_id: str
    profile: TwinProfile
    scenario_plans: List[ScenarioPlan]
    seed: int
    candidate: ModelCandidate
    baseline: Optional[ModelVersion] = None
    purpose: TwinRunPurpose = TwinRunPurpose.VALIDATION
    status: TwinRunStatus = TwinRunStatus.PLANNED
    artifact_dir: str = ""
    git_commit: str = ""
    expected_ground_truth: Dict[str, Any] = field(default_factory=dict)
    parameters: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utc_now)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    notes: str = ""
    # Experiment infrastructure outcome (not model quality)
    experiment_error: str = ""
    mode: str = "offline"  # offline | live_mininet | experiment_logs

    @property
    def profile_fingerprint(self) -> str:
        return self.profile.config_fingerprint

    @property
    def scenario_ids(self) -> List[str]:
        return [p.scenario_id for p in self.scenario_plans]


@dataclass(frozen=True)
class ExperimentEvidence:
    """
    Metrics + provenance for validation.

    Offline harness supplies synthetic metrics; experiment_logs mode fills
    from ieee_metrics / completed lab logs. Never claim live Mininet launch.
    """

    scenario_id: str
    metrics: Dict[str, Any]
    seed: int
    profile_fingerprint: str
    scenario_manifest: Dict[str, Any] = field(default_factory=dict)
    missing_artifacts: List[str] = field(default_factory=list)
    experiment_ok: bool = True
    experiment_error: str = ""
    source: str = "offline_synthetic"  # never claim live when synthetic

    def metric(self, key: str) -> Optional[float]:
        val = self.metrics.get(key)
        if val is None:
            return None
        try:
            return float(val)
        except (TypeError, ValueError):
            return None


def validate_experiment_plan(plan: TwinExperimentPlan) -> None:
    if not plan.run_id or not str(plan.run_id).strip():
        raise TwinValidationError("run_id required")
    if not plan.scenario_plans:
        raise TwinValidationError("at least one scenario plan required")
    if plan.seed < 0:
        raise TwinValidationError("seed must be >= 0")
    if plan.mode not in ("offline", "live_mininet", "experiment_logs"):
        raise TwinValidationError(f"unsupported experiment mode: {plan.mode!r}")
    for sp in plan.scenario_plans:
        validate_scenario_id(sp.scenario_id)
    if plan.candidate is None:
        raise TwinValidationError("candidate required")
