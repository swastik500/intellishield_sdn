"""
R3.2 Twin scenario orchestration facade.

Parameterizes S1–S5 around existing attack_scenarios / TrafficScheduler.
Does not replace TrafficScheduler. Does not auto-launch Mininet.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Union
from pathlib import Path

from shared_contracts.models import TwinProfile
from twin.dry_run import describe_plan, dry_run_scenario
from twin.intensity import intensity_documentation
from twin.manifest import build_manifest, manifest_to_json, write_manifest
from twin.planner import default_plan, plan_scenario
from twin.scenario_spec import GENERATOR_VERSION, ScenarioPlan
from twin.variants import generate_variants

__all__ = [
    "GENERATOR_VERSION",
    "ScenarioPlan",
    "build_manifest",
    "default_plan",
    "describe_plan",
    "dry_run_scenario",
    "generate_variants",
    "intensity_documentation",
    "manifest_to_json",
    "plan_scenario",
    "write_manifest",
]


def plan_and_manifest(
    scenario_id: str | int,
    *,
    overrides: Optional[Mapping[str, Any]] = None,
    profile: Optional[TwinProfile] = None,
    seed: Optional[int] = None,
    manifest_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Convenience: plan → optional write manifest → return manifest dict."""
    plan = plan_scenario(
        scenario_id, overrides=overrides, profile=profile, seed=seed
    )
    manifest = build_manifest(plan)
    if manifest_path is not None:
        write_manifest(plan, manifest_path)
    return manifest
