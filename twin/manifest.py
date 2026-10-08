"""JSON-safe scenario manifests for twin plans."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Union

from twin.scenario_spec import GENERATOR_VERSION, ScenarioPlan


def build_manifest(plan: ScenarioPlan) -> Dict[str, Any]:
    """Build a JSON-safe manifest for a ScenarioPlan."""
    return {
        "schema": "intellishield.twin.scenario_manifest.v1",
        "generator_version": plan.generator_version or GENERATOR_VERSION,
        "scenario_id": plan.scenario_id,
        "scenario_version": plan.scenario_version,
        "scenario_family": plan.scenario_family,
        "label": plan.label,
        "profile_id": plan.profile_id,
        "profile_fingerprint": plan.profile_fingerprint,
        "seed": plan.seed,
        "parameters": dict(plan.parameters),
        "run_kwargs": dict(plan.run_kwargs),
        "expected_ground_truth": {
            "expected_attack": plan.expected_attack,
            "expected_attack_family": plan.expected_attack_family,
            "events": list(plan.ground_truth_events),
            "timeline": plan.expected_timeline(),
            "source_host": plan.source_host,
            "target_host": plan.target_host,
            "source_ip": plan.source_ip,
            "target_ip": plan.target_ip,
            "label_source": "SCENARIO_CONTROL",
        },
        "notes": plan.notes,
    }


def write_manifest(
    plan: ScenarioPlan,
    path: Union[str, Path],
    *,
    indent: int = 2,
) -> Path:
    """Write manifest JSON to *path* (creates parent dirs)."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    data = build_manifest(plan)
    out.write_text(json.dumps(data, indent=indent, sort_keys=True) + "\n", encoding="utf-8")
    return out


def manifest_to_json(plan: ScenarioPlan, *, indent: Optional[int] = 2) -> str:
    return json.dumps(build_manifest(plan), indent=indent, sort_keys=True)
