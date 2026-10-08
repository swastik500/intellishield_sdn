"""Bounded what-if simulation in plan space vs an ingested snapshot."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Union

from shared_contracts.timeutil import format_ts, utc_now
from twin.isolation import project_root
from twin.planner import plan_scenario
from twin.replay import _observed_attack_duration
from twin.snapshot import load_snapshot
from twin.validate import TwinValidationError

PathLike = Union[str, Path]


def _attack_duration(plan: Any) -> float:
    sid = plan.scenario_id
    if sid == "S1":
        return 0.0
    if sid == "S4":
        extra = (plan.burst_count - 1) * (plan.burst_sec + plan.inter_burst_interval_sec)
        return float(plan.burst_sec + extra)
    if sid == "S5":
        return float(plan.attack1_sec + plan.attack2_sec)
    return float(plan.attack_sec)


def simulate_whatif(
    snapshot: Mapping[str, Any],
    scenario_id: str,
    *,
    overrides: Optional[Mapping[str, Any]] = None,
    seed: int = 42,
    persist: bool = True,
    root: Optional[PathLike] = None,
) -> Dict[str, Any]:
    """
    Compare baseline S1–S5 plan vs a bounded parameter variant and the
    observed attack window from a snapshot.

    Does not generate packets, does not call detectors, does not mitigate.
    """
    sid = str(scenario_id).strip().upper()
    if sid not in {"S1", "S2", "S3", "S4", "S5"}:
        raise TwinValidationError(f"unsupported scenario_id: {scenario_id!r}")
    ov = dict(overrides or {})
    baseline = plan_scenario(sid, seed=seed)
    variant = plan_scenario(sid, overrides=ov, seed=seed)

    b_dur = _attack_duration(baseline)
    v_dur = _attack_duration(variant)
    observed = _observed_attack_duration(snapshot, sid)

    param_delta: Dict[str, Any] = {}
    for key in sorted(set(baseline.parameters) | set(variant.parameters)):
        bv = baseline.parameters.get(key)
        vv = variant.parameters.get(key)
        if bv != vv:
            param_delta[key] = {"baseline": bv, "variant": vv}

    bva = snapshot.get("baseline_vs_attack") or {}
    intensity_note = ""
    if sid == "S2" and (
        ov.get("intensity") is not None or ov.get("syn_rate") is not None
    ):
        observed_rate = bva.get("attack_mean_pkt_s")
        intensity_note = (
            f"variant syn_rate={variant.syn_rate}; "
            f"observed attack mean pkt/s={observed_rate}"
        )

    sim_id = "twinsim-" + hashlib.sha256(
        json.dumps(
            {
                "snap": snapshot.get("snapshot_id"),
                "sid": sid,
                "seed": seed,
                "ov": ov,
            },
            sort_keys=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()[:12]

    result: Dict[str, Any] = {
        "schema": "intellishield.twin.whatif.v1",
        "simulation_id": sim_id,
        "created_at": format_ts(utc_now()),
        "snapshot_id": snapshot.get("snapshot_id"),
        "scenario_id": sid,
        "seed": seed,
        "overrides": ov,
        "parameter_delta": param_delta,
        "baseline_attack_duration_sec": b_dur,
        "variant_attack_duration_sec": v_dur,
        "observed_attack_duration_sec": observed,
        "duration_delta_sec": round(v_dur - b_dur, 3),
        "variant_vs_observed_error": (
            round(abs(v_dur - observed) / observed, 4)
            if observed and observed > 0
            else None
        ),
        "baseline_vs_observed_error": (
            round(abs(b_dur - observed) / observed, 4)
            if observed and observed > 0
            else None
        ),
        "baseline_vs_attack": bva,
        "intensity_note": intensity_note,
        "control": "READ_ONLY",
        "mutates_controller": False,
        "mutates_mitigation": False,
        "launches_mininet": False,
        "notes": (
            "Plan-space what-if against recorded observations. "
            "Does not resimulate packet traces or detector cycles."
        ),
    }

    if persist:
        base = Path(root) if root else project_root()
        out_dir = base / "logs" / "twin" / "simulations" / sim_id
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / "whatif_result.json"
        path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        result["artifact_dir"] = str(out_dir)
        result["simulation_path"] = str(path)
    return result


def simulate_whatif_from_path(
    snapshot_path: PathLike, scenario_id: str, **kwargs: Any
) -> Dict[str, Any]:
    snap = load_snapshot(snapshot_path)
    if snap is None:
        raise TwinValidationError(f"snapshot not found: {snapshot_path}")
    return simulate_whatif(snap, scenario_id, **kwargs)
