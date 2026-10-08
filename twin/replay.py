"""Replay recorded scenario events against expected twin timelines."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Union

from shared_contracts.timeutil import format_ts, utc_now
from twin.evidence_from_logs import evidence_metrics_from_logs
from twin.isolation import project_root
from twin.planner import plan_scenario
from twin.scenario_map import scenario_id_matches_name
from twin.snapshot import load_snapshot
from twin.validate import TwinValidationError

PathLike = Union[str, Path]


def _observed_event_types(snapshot: Mapping[str, Any], scenario_id: str) -> List[str]:
    out: List[str] = []
    for ev in snapshot.get("scenario_events") or []:
        if not isinstance(ev, dict):
            continue
        name = str(ev.get("scenario_name") or ev.get("scenario_id") or "")
        sid = str(ev.get("scenario_id") or "")
        if sid == scenario_id or scenario_id_matches_name(scenario_id, name):
            et = str(ev.get("event_type") or "").upper()
            if et:
                out.append(et)
    return out


def _observed_attack_duration(
    snapshot: Mapping[str, Any],
    scenario_id: str,
    *,
    expected_sec: Optional[float] = None,
) -> Optional[float]:
    durs: List[float] = []
    for w in snapshot.get("windows") or []:
        if not isinstance(w, dict):
            continue
        if str(w.get("scenario_id") or "") == scenario_id or scenario_id_matches_name(
            scenario_id, str(w.get("scenario") or "")
        ):
            try:
                durs.append(float(w.get("duration_sec") or 0))
            except (TypeError, ValueError):
                continue
    if not durs:
        return None
    if expected_sec and expected_sec > 0:
        return round(min(durs, key=lambda d: abs(d - expected_sec)), 3)
    return round(durs[-1], 3)


def replay_scenario(
    snapshot: Mapping[str, Any],
    scenario_id: str,
    *,
    seed: int = 42,
    persist: bool = True,
    root: Optional[PathLike] = None,
) -> Dict[str, Any]:
    """
    Compare expected S1–S5 timeline vs observed scenario_logs events.

    Does not launch traffic or call mitigation.
    """
    sid = str(scenario_id).strip().upper()
    if sid not in {"S1", "S2", "S3", "S4", "S5"}:
        raise TwinValidationError(f"unsupported scenario_id: {scenario_id!r}")
    plan = plan_scenario(sid, seed=seed)
    expected = [str(e.get("event") or "") for e in plan.expected_timeline()]
    observed = _observed_event_types(snapshot, sid)
    expected_set = [e for e in expected if e]
    matched = [e for e in expected_set if e in observed]
    missing = [e for e in expected_set if e not in observed]
    extra = [e for e in observed if e not in expected_set and e not in {"SCHEDULER_DISPATCH", "PHASE", "PHASE_A"}]

    expected_attack = (
        float(plan.burst_sec)
        if sid == "S4"
        else float(plan.attack1_sec + plan.attack2_sec)
        if sid == "S5"
        else float(plan.attack_sec)
        if sid != "S1"
        else 0.0
    )
    observed_attack = _observed_attack_duration(
        snapshot, sid, expected_sec=expected_attack
    )
    temporal_error = None
    if observed_attack is not None and expected_attack > 0:
        temporal_error = round(abs(observed_attack - expected_attack) / expected_attack, 4)

    logs_dir = snapshot.get("source_logs_dir") or ""
    packed = (
        evidence_metrics_from_logs(
            logs_dir,
            sid,
            metrics_report_path=snapshot.get("metrics_report") or None,
        )
        if logs_dir
        else {"metrics": {}, "missing_artifacts": ["source_logs_dir"]}
    )

    replay_id = "twinreplay-" + hashlib.sha256(
        f"{snapshot.get('snapshot_id','')}|{sid}|{seed}".encode("utf-8")
    ).hexdigest()[:12]

    result: Dict[str, Any] = {
        "schema": "intellishield.twin.replay.v1",
        "replay_id": replay_id,
        "created_at": format_ts(utc_now()),
        "snapshot_id": snapshot.get("snapshot_id"),
        "scenario_id": sid,
        "seed": seed,
        "expected_events": expected_set,
        "observed_events": observed,
        "matched_events": matched,
        "missing_events": missing,
        "extra_events": extra,
        "expected_attack_duration_sec": expected_attack,
        "observed_attack_duration_sec": observed_attack,
        "temporal_error": temporal_error,
        "baseline_vs_attack": snapshot.get("baseline_vs_attack") or {},
        "detection_metrics": packed.get("metrics") or {},
        "missing_artifacts": packed.get("missing_artifacts") or [],
        "sequence_ok": not missing,
        "control": "READ_ONLY",
        "mutates_controller": False,
        "mutates_mitigation": False,
        "launches_mininet": False,
        "notes": "Event replay from recorded scenario_logs; not packet-level replay.",
    }

    if persist:
        base = Path(root) if root else project_root()
        out_dir = base / "logs" / "twin" / "replays" / replay_id
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / "replay_result.json"
        path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        result["artifact_dir"] = str(out_dir)
        result["replay_path"] = str(path)
    return result


def replay_from_path(
    snapshot_path: PathLike,
    scenario_id: str,
    **kwargs: Any,
) -> Dict[str, Any]:
    snap = load_snapshot(snapshot_path)
    if snap is None:
        raise TwinValidationError(f"snapshot not found: {snapshot_path}")
    return replay_scenario(snap, scenario_id, **kwargs)
