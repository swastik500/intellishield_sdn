"""
Bounded observational snapshot of a completed experiment log directory.

READ-ONLY with respect to the live SDN: never imports controller or
mitigation, never writes OpenFlow, never launches traffic.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

from evaluation.csv_log_io import KNOWN_CSV_HEADERS, load_csv_rows
from evaluation.experiment_windows import load_experiment_windows, parse_ts
from evaluation.ieee_metrics import compute_system_metrics
from shared_contracts.models import TwinObservation, TwinProfile
from shared_contracts.serialize import to_dict
from shared_contracts.timeutil import format_ts, utc_now
from twin.bounds import MAX_SNAPSHOT_CSV_ROWS, MAX_SNAPSHOT_JSONL_LINES, assert_history_limit
from twin.isolation import project_root
from twin.profile import build_default_twin_profile
from twin.scenario_map import scenario_name_to_id
from twin.validate import TwinValidationError

logger = logging.getLogger("intellishield.twin.snapshot")

PathLike = Union[str, Path]

CSV_FILES = (
    "scenario_logs.csv",
    "attack_logs.csv",
    "flow_stats.csv",
    "entropy_logs.csv",
    "ml_predictions.csv",
    "ml_alerts.csv",
    "detection_alerts.csv",
    "mitigation_actions.csv",
    "port_stats.csv",
    "controller_stats.csv",
    "ml_features.csv",
    "traffic_logs.csv",
)

JSONL_FILES = (
    "alerts.jsonl",
    "root_cause_reports.jsonl",
    "correlation_results.jsonl",
    "fused_decisions.jsonl",
    "verification_trace.jsonl",
)

# Safety contract — imported by tests. These modules must never be imported here.
FORBIDDEN_IMPORTS = (
    "controller.flow_monitor",
    "mitigation.mitigation_engine",
    "mitigation",
    "traffic_generator.traffic_scheduler",
)


def _bounded_csv(path: Path, *, limit: int = MAX_SNAPSHOT_CSV_ROWS) -> List[dict]:
    if not path.is_file():
        return []
    rows = load_csv_rows(path, fallback_headers=KNOWN_CSV_HEADERS.get(path.name))
    if len(rows) > limit:
        return rows[-limit:]
    return rows


def _count_jsonl(path: Path, *, limit: int = MAX_SNAPSHOT_JSONL_LINES) -> int:
    if not path.is_file():
        return 0
    n = 0
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    n += 1
                if n >= limit:
                    return n
    except OSError:
        logger.debug("jsonl count failed: %s", path, exc_info=True)
        return 0
    return n


def _window_dicts(logs_dir: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        windows = load_experiment_windows(str(logs_dir))
    except Exception:  # noqa: BLE001
        logger.debug("load_experiment_windows failed", exc_info=True)
        return []
    for w in windows:
        sid = scenario_name_to_id(getattr(w, "scenario", "") or "")
        out.append(
            {
                "scenario": getattr(w, "scenario", ""),
                "scenario_id": sid or "",
                "attack_start": w.attack_start.strftime("%Y-%m-%d %H:%M:%S"),
                "attack_stop": w.attack_stop.strftime("%Y-%m-%d %H:%M:%S"),
                "duration_sec": round(
                    (w.attack_stop - w.attack_start).total_seconds(), 3
                ),
                "source": getattr(w, "source", "scenario_logs"),
            }
        )
    return out


def _mean_pkt(rows: Iterable[dict]) -> Optional[float]:
    vals: List[float] = []
    for row in rows:
        try:
            vals.append(float(row.get("packet_rate", 0) or 0))
        except (TypeError, ValueError):
            continue
    if not vals:
        return None
    return round(sum(vals) / len(vals), 3)


_ATTACK_LIKE_TRAFFIC_TOKENS = (
    "SYN",
    "UDP",
    "FLOOD",
    "BURST",
    "HTTP",
    "SLOWLORIS",
    "ICMP_FLOOD",
)


def _attack_like_traffic_stats(traffic_rows: List[dict]) -> Dict[str, Any]:
    """Extract flood-like rates from traffic_logs; ignore baseline ICMP_CONTINUOUS."""
    attack_rows: List[dict] = []
    for row in traffic_rows:
        t = str(row.get("traffic_type") or row.get("protocol") or "").upper()
        if not t or t in ("ICMP_CONTINUOUS", "ALL", "NORMAL", "ICMP"):
            continue
        if any(tok in t for tok in _ATTACK_LIKE_TRAFFIC_TOKENS):
            attack_rows.append(row)
    mean_rate = _mean_pkt(attack_rows)
    bandwidth = None
    for row in attack_rows:
        bw = row.get("bandwidth")
        if bw not in (None, "", "N/A", "n/a"):
            bandwidth = str(bw)
            break
    return {
        "attack_like_traffic_mean_pkt_s": mean_rate,
        "attack_like_traffic_bandwidth": bandwidth,
        "n_attack_like_traffic_rows": len(attack_rows),
        "n_traffic_log_rows": len(traffic_rows),
    }


def _split_baseline_attack(
    flow_rows: List[dict], windows: List[Dict[str, Any]]
) -> Dict[str, Any]:
    if not flow_rows:
        return {
            "baseline_mean_pkt_s": None,
            "attack_mean_pkt_s": None,
            "n_baseline_rows": 0,
            "n_attack_rows": 0,
        }
    spans = []
    for w in windows:
        start = parse_ts(w.get("attack_start", ""))
        stop = parse_ts(w.get("attack_stop", ""))
        if start is not None and stop is not None:
            spans.append((start, stop))
    base_rows: List[dict] = []
    atk_rows: List[dict] = []
    for row in flow_rows:
        ts = parse_ts(row.get("timestamp", ""))
        if ts is None:
            continue
        inside = any(start <= ts <= stop for start, stop in spans)
        if inside:
            atk_rows.append(row)
        else:
            base_rows.append(row)
    return {
        "baseline_mean_pkt_s": _mean_pkt(base_rows),
        "attack_mean_pkt_s": _mean_pkt(atk_rows),
        "n_baseline_rows": len(base_rows),
        "n_attack_rows": len(atk_rows),
    }


def _find_metrics_report(logs_dir: Path) -> Optional[Path]:
    candidates = [
        logs_dir / "metrics_report.json",
        logs_dir.parent / "metrics_report.json",
    ]
    try:
        for child in logs_dir.parent.iterdir():
            if child.is_dir() and child.name.startswith("metrics"):
                candidates.append(child / "metrics_report.json")
    except OSError:
        pass
    for p in candidates:
        if p.is_file():
            return p
    return None


def _snapshot_id_for(logs_dir: Path) -> str:
    h = hashlib.sha256()
    h.update(str(logs_dir.resolve()).encode("utf-8"))
    try:
        st = logs_dir.stat()
        h.update(str(int(st.st_mtime)).encode("utf-8"))
    except OSError:
        pass
    for name in ("scenario_logs.csv", "ml_predictions.csv", "metrics_report.json"):
        p = logs_dir / name
        try:
            if p.is_file():
                h.update(str(int(p.stat().st_mtime)).encode("utf-8"))
                h.update(str(p.stat().st_size).encode("utf-8"))
        except OSError:
            continue
    return "twinsnap-" + h.hexdigest()[:12]


def capture_snapshot(
    logs_dir: PathLike,
    *,
    root: Optional[PathLike] = None,
    profile: Optional[TwinProfile] = None,
    snapshot_id: Optional[str] = None,
    persist: bool = True,
) -> Dict[str, Any]:
    """
    Ingest a completed experiment directory into a bounded twin snapshot.

    Missing files are tolerated (empty refs). Malformed CSVs yield [].
    Never mutates the source logs directory (except reading).
    """
    src = Path(logs_dir)
    if not str(logs_dir).strip():
        raise TwinValidationError("logs_dir required")
    if not src.exists():
        raise TwinValidationError(f"experiment logs dir missing: {src}")
    if not src.is_dir():
        raise TwinValidationError(f"logs_dir is not a directory: {src}")

    profile = profile or build_default_twin_profile()
    sid = snapshot_id or _snapshot_id_for(src)
    artifact_refs: Dict[str, str] = {}
    csv_counts: Dict[str, int] = {}
    loaded: Dict[str, List[dict]] = {}

    for name in CSV_FILES:
        path = src / name
        rows = _bounded_csv(path)
        loaded[name] = rows
        csv_counts[name] = len(rows)
        if path.is_file():
            artifact_refs[name] = str(path)

    jsonl_counts: Dict[str, int] = {}
    for name in JSONL_FILES:
        path = src / name
        n = _count_jsonl(path)
        jsonl_counts[name] = n
        if path.is_file():
            artifact_refs[name] = str(path)

    windows = _window_dicts(src)
    events = [
        {
            "timestamp": r.get("timestamp", ""),
            "scenario_name": r.get("scenario_name", ""),
            "event_type": r.get("event_type", ""),
            "scenario_id": scenario_name_to_id(str(r.get("scenario_name", "") or ""))
            or "",
        }
        for r in loaded.get("scenario_logs.csv", [])
        if r.get("event_type")
    ]
    events = events[-assert_history_limit(MAX_SNAPSHOT_CSV_ROWS) :]

    blocks = [
        r
        for r in loaded.get("mitigation_actions.csv", [])
        if str(r.get("action", "")).upper() == "BLOCK"
        and str(r.get("status", "")).upper() == "SUCCESS"
    ]
    baseline_attack = _split_baseline_attack(loaded.get("flow_stats.csv", []), windows)
    baseline_attack.update(
        _attack_like_traffic_stats(loaded.get("traffic_logs.csv", []))
    )

    metrics_path = _find_metrics_report(src)
    if metrics_path is not None:
        artifact_refs["metrics_report.json"] = str(metrics_path)

    system = compute_system_metrics(
        loaded.get("flow_stats.csv", []),
        loaded.get("port_stats.csv", []),
        loaded.get("controller_stats.csv", []),
    )

    observation = TwinObservation(
        observation_id=f"obs-{sid}",
        timestamp=utc_now(),
        profile_id=profile.profile_id,
        run_id=sid,
        artifact_refs=dict(artifact_refs),
        summary={
            "n_windows": len(windows),
            "n_scenario_events": len(events),
            "n_flow_rows": csv_counts.get("flow_stats.csv", 0),
            "n_ml_rows": csv_counts.get("ml_predictions.csv", 0),
            "n_mitigation_blocks": len(blocks),
            "jsonl_counts": jsonl_counts,
            "source_logs_dir": str(src.resolve()),
        },
    )

    payload: Dict[str, Any] = {
        "schema": "intellishield.twin.snapshot.v1",
        "snapshot_id": sid,
        "created_at": format_ts(utc_now()),
        "source_logs_dir": str(src.resolve()),
        "profile_id": profile.profile_id,
        "profile_version": profile.version,
        "profile_fingerprint": profile.config_fingerprint,
        "artifact_refs": artifact_refs,
        "windows": windows,
        "scenario_events": events,
        "csv_counts": csv_counts,
        "jsonl_counts": jsonl_counts,
        "system": system,
        "baseline_vs_attack": baseline_attack,
        "metrics_report": str(metrics_path) if metrics_path else "",
        "observation": to_dict(observation),
        "control": "READ_ONLY",
        "mutates_controller": False,
        "mutates_mitigation": False,
        "launches_mininet": False,
        "launches_traffic": False,
        "notes": (
            "Bounded observational snapshot of completed experiment logs. "
            "Not a live OpenFlow replica."
        ),
    }

    if persist:
        base = Path(root) if root else project_root()
        out_dir = base / "logs" / "twin" / "snapshots" / sid
        out_dir.mkdir(parents=True, exist_ok=True)
        snap_path = out_dir / "twin_snapshot.json"
        obs_path = out_dir / "twin_observation.json"
        snap_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        obs_path.write_text(
            json.dumps(to_dict(observation), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        payload["artifact_dir"] = str(out_dir)
        payload["snapshot_path"] = str(snap_path)
    else:
        payload["artifact_dir"] = ""
        payload["snapshot_path"] = ""

    return payload


def load_snapshot(path: PathLike) -> Optional[Dict[str, Any]]:
    p = Path(path)
    try:
        if p.is_dir():
            p = p / "twin_snapshot.json"
        if not p.is_file():
            return None
        obj = json.loads(p.read_text(encoding="utf-8"))
        return obj if isinstance(obj, dict) else None
    except Exception:  # noqa: BLE001
        logger.debug("load_snapshot failed: %s", path, exc_info=True)
        return None
