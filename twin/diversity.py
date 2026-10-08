"""Bounded deterministic scenario diversity matrix (R3.5)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from twin.bounds import MAX_SCENARIO_MATRIX_ROWS
from twin.isolation import project_root
from twin.manifest import build_manifest
from twin.planner import plan_scenario
from twin.validate import TwinValidationError

PathLike = Union[str, Path]


def build_scenario_diversity_matrix(
    *,
    seed: int = 100,
    max_rows: int = 16,
) -> List[Dict[str, Any]]:
    """
    Controlled, bounded variation of scenario / intensity / duration / seed / hosts.

    Does not launch Mininet. Hard-capped by MAX_SCENARIO_MATRIX_ROWS.
    """
    if max_rows < 1:
        raise TwinValidationError("max_rows must be >= 1")
    if max_rows > MAX_SCENARIO_MATRIX_ROWS:
        raise TwinValidationError(
            f"max_rows {max_rows} exceeds bound {MAX_SCENARIO_MATRIX_ROWS}"
        )

    specs: List[Dict[str, Any]] = [
        {"scenario_id": "S1", "overrides": {}, "seed": seed},
        {"scenario_id": "S2", "overrides": {}, "seed": seed},
        {"scenario_id": "S2", "overrides": {"intensity": 1000, "attack_sec": 20}, "seed": seed + 1},
        {"scenario_id": "S2", "overrides": {"intensity": 10000, "attack_sec": 30, "source_host": "h3", "target_host": "h4"}, "seed": seed + 2},
        {"scenario_id": "S3", "overrides": {"intensity": "5M"}, "seed": seed + 3},
        {"scenario_id": "S3", "overrides": {"attack_sec": 25}, "seed": seed + 4},
        {"scenario_id": "S4", "overrides": {"burst_sec": 5}, "seed": seed + 5},
        {"scenario_id": "S4", "overrides": {"burst_count": 2, "inter_burst_interval_sec": 5}, "seed": seed + 6},
        {"scenario_id": "S5", "overrides": {"attack1_sec": 15, "attack2_sec": 15}, "seed": seed + 7},
    ]
    rows: List[Dict[str, Any]] = []
    for spec in specs[:max_rows]:
        plan = plan_scenario(
            spec["scenario_id"],
            overrides=spec.get("overrides"),
            seed=int(spec["seed"]),
        )
        rows.append(
            {
                "scenario_id": plan.scenario_id,
                "seed": plan.seed,
                "source_host": plan.source_host,
                "target_host": plan.target_host,
                "duration_sec": plan.duration_sec,
                "syn_rate": plan.syn_rate,
                "udp_bandwidth": plan.udp_bandwidth,
                "burst_sec": plan.burst_sec,
                "burst_count": plan.burst_count,
                "expected_attack": plan.expected_attack,
                "expected_attack_family": plan.expected_attack_family,
                "profile_fingerprint": plan.profile_fingerprint,
                "manifest_digest_keys": sorted(build_manifest(plan).keys()),
            }
        )
    return rows


def write_scenario_diversity_matrix(
    rows: Optional[Sequence[Mapping[str, Any]]] = None,
    *,
    path: Optional[PathLike] = None,
    root: Optional[PathLike] = None,
    seed: int = 100,
    max_rows: int = 16,
) -> Path:
    base = Path(root) if root else project_root()
    out = Path(path) if path else base / "logs" / "twin" / "research" / "scenario_diversity_matrix.json"
    data = {
        "schema": "intellishield.twin.scenario_diversity_matrix.v1",
        "seed_base": seed,
        "row_count": 0,
        "max_rows_bound": MAX_SCENARIO_MATRIX_ROWS,
        "mode": "offline_deterministic",
        "rows": list(rows) if rows is not None else build_scenario_diversity_matrix(seed=seed, max_rows=max_rows),
    }
    data["row_count"] = len(data["rows"])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out
