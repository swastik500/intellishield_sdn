"""Dry-run planning for twin scenarios (no Mininet / traffic)."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from shared_contracts.models import TwinProfile
from twin.manifest import build_manifest
from twin.planner import plan_scenario
from twin.scenario_spec import ScenarioPlan
from twin.topology import build_default_topology, export_topology_dict


def dry_run_scenario(
    scenario_id: str | int,
    *,
    overrides: Optional[Mapping[str, Any]] = None,
    profile: Optional[TwinProfile] = None,
    seed: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Validate and describe a twin scenario without launching Mininet/traffic.

    Returns topology summary, parameters, targets, expected outputs, manifest.
    """
    plan = plan_scenario(
        scenario_id,
        overrides=overrides,
        profile=profile,
        seed=seed,
    )
    return describe_plan(plan, profile=profile)


def describe_plan(
    plan: ScenarioPlan,
    *,
    profile: Optional[TwinProfile] = None,
) -> Dict[str, Any]:
    topo = profile.topology if profile is not None else build_default_topology()
    return {
        "dry_run": True,
        "launches_mininet": False,
        "launches_traffic": False,
        "topology": {
            "topology_id": topo.topology_id,
            "host_count": topo.host_count,
            "switch_count": topo.switch_count,
            "controller": f"{topo.controller_host}:{topo.controller_port}",
            "hosts": [h.host_id for h in topo.hosts],
            "export": export_topology_dict(topo),
        },
        "scenario": {
            "scenario_id": plan.scenario_id,
            "scenario_version": plan.scenario_version,
            "family": plan.scenario_family,
            "label": plan.label,
            "seed": plan.seed,
        },
        "parameters": dict(plan.parameters),
        "run_kwargs": dict(plan.run_kwargs),
        "target": {
            "source_host": plan.source_host,
            "target_host": plan.target_host,
            "source_ip": plan.source_ip,
            "target_ip": plan.target_ip,
        },
        "expected_outputs": {
            "expected_attack": plan.expected_attack,
            "expected_attack_family": plan.expected_attack_family,
            "ground_truth_events": list(plan.ground_truth_events),
            "timeline": plan.expected_timeline(),
        },
        "manifest": build_manifest(plan),
    }
