"""Bounded twin run / validation / dataset history for dashboard (read-only)."""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from twin.bounds import assert_history_limit
from twin.fidelity import compact_fidelity_summary

logger = logging.getLogger("intellishield.twin.history")

MAX_SCAN_RUNS = 200
MAX_DATASETS = 100


def twin_root(logs_dir: str) -> Path:
    return Path(logs_dir) / "twin"


def _safe_load_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        if not path.is_file():
            return None
        obj = json.loads(path.read_text(encoding="utf-8"))
        return obj if isinstance(obj, dict) else None
    except Exception:  # noqa: BLE001
        logger.debug("malformed twin json: %s", path, exc_info=True)
        return None


def _iter_run_dirs(logs_dir: str) -> List[Path]:
    root = twin_root(logs_dir) / "candidates"
    if not root.is_dir():
        return []
    dirs: List[Path] = []
    try:
        for cand in sorted(root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not cand.is_dir():
                continue
            for run in sorted(cand.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
                if run.is_dir():
                    dirs.append(run)
                if len(dirs) >= MAX_SCAN_RUNS:
                    return dirs
    except Exception:  # noqa: BLE001
        logger.debug("iter run dirs failed", exc_info=True)
    return dirs


def load_twin_run(run_dir: Path) -> Optional[Dict[str, Any]]:
    """Assemble a dashboard record from a twin run artifact directory."""
    try:
        manifest = _safe_load_json(run_dir / "twin_experiment_manifest.json")
        plan = _safe_load_json(run_dir / "experiment_plan.json")
        validation = _safe_load_json(run_dir / "validation_result.json")
        if manifest is None and plan is None and validation is None:
            return None
        run_id = (
            (manifest or {}).get("run_id")
            or (plan or {}).get("run_id")
            or run_dir.name
        )
        profile = (plan or {}).get("profile") or {}
        return {
            "run_id": run_id,
            "status": (plan or {}).get("status") or (manifest or {}).get("mode"),
            "mode": (manifest or {}).get("mode") or (plan or {}).get("mode"),
            "seed": (manifest or {}).get("seed") or (plan or {}).get("seed"),
            "profile_id": (manifest or {}).get("profile_id")
            or profile.get("profile_id"),
            "profile_version": (manifest or {}).get("profile_version")
            or profile.get("version"),
            "profile_fingerprint": (manifest or {}).get("profile_fingerprint")
            or profile.get("config_fingerprint"),
            "scenario_ids": (manifest or {}).get("scenario_ids")
            or (plan or {}).get("scenario_ids")
            or [],
            "candidate_id": (manifest or {}).get("candidate_id")
            or ((plan or {}).get("candidate") or {}).get("candidate_id"),
            "model_id": (manifest or {}).get("model_id"),
            "validation_status": (manifest or {}).get("validation_status")
            or (validation or {}).get("status"),
            "outcome_code": (manifest or {}).get("outcome_code")
            or ((validation or {}).get("metrics") or {}).get("outcome_code"),
            "metrics": (manifest or {}).get("metrics")
            or {
                k: ((validation or {}).get("metrics") or {}).get(k)
                for k in (
                    "precision",
                    "recall",
                    "f1_score",
                    "false_positive_rate",
                    "detection_latency_s",
                )
            },
            "artifact_dir": str(run_dir),
            "artifact_refs": {
                "twin_experiment_manifest": str(run_dir / "twin_experiment_manifest.json")
                if (run_dir / "twin_experiment_manifest.json").is_file()
                else "",
                "validation_result": str(run_dir / "validation_result.json")
                if (run_dir / "validation_result.json").is_file()
                else "",
                "experiment_plan": str(run_dir / "experiment_plan.json")
                if (run_dir / "experiment_plan.json").is_file()
                else "",
            },
            "git_commit": (manifest or {}).get("git_commit")
            or (plan or {}).get("git_commit"),
            "notes": (manifest or {}).get("notes") or "",
        }
    except Exception:  # noqa: BLE001
        logger.debug("load_twin_run failed for %s", run_dir, exc_info=True)
        return None


def read_twin_runs(
    logs_dir: str,
    *,
    limit: int = 20,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    limit = assert_history_limit(limit if limit > 0 else 20)
    out: List[Dict[str, Any]] = []
    for run_dir in _iter_run_dirs(logs_dir):
        rec = load_twin_run(run_dir)
        if rec is None:
            continue
        if status and str(rec.get("validation_status") or rec.get("status") or "").upper() != status.upper():
            continue
        out.append(rec)
        if len(out) >= limit:
            break
    return out


def get_twin_run(logs_dir: str, run_id: str) -> Optional[Dict[str, Any]]:
    if not run_id or not str(run_id).strip():
        return None
    needle = str(run_id).strip()
    for run_dir in _iter_run_dirs(logs_dir):
        rec = load_twin_run(run_dir)
        if rec and str(rec.get("run_id")) == needle:
            return rec
        if run_dir.name == needle:
            return rec
    return None


def read_twin_validations(
    logs_dir: str, *, limit: int = 20
) -> List[Dict[str, Any]]:
    runs = read_twin_runs(logs_dir, limit=max(limit, 50))
    out = []
    for r in runs:
        if not r.get("validation_status") and not r.get("outcome_code"):
            continue
        out.append(
            {
                "run_id": r.get("run_id"),
                "candidate_id": r.get("candidate_id"),
                "validation_status": r.get("validation_status"),
                "outcome_code": r.get("outcome_code"),
                "metrics": r.get("metrics") or {},
                "artifact_refs": r.get("artifact_refs") or {},
                "profile_fingerprint": r.get("profile_fingerprint"),
                "seed": r.get("seed"),
            }
        )
        if len(out) >= limit:
            break
    return out


def read_twin_profiles_summary(logs_dir: str) -> List[Dict[str, Any]]:
    """Distinct profiles observed in twin run artifacts (read-only)."""
    seen: Dict[str, Dict[str, Any]] = {}
    for r in read_twin_runs(logs_dir, limit=100):
        pid = str(r.get("profile_id") or "")
        fp = str(r.get("profile_fingerprint") or "")
        key = f"{pid}:{fp}"
        if not pid or key in seen:
            continue
        seen[key] = {
            "profile_id": pid,
            "profile_version": r.get("profile_version"),
            "profile_fingerprint": fp,
            "example_run_id": r.get("run_id"),
        }
    # Also expose default profile without requiring runs
    try:
        from twin.profile import build_default_twin_profile

        p = build_default_twin_profile()
        key = f"{p.profile_id}:{p.config_fingerprint}"
        if key not in seen:
            seen[key] = {
                "profile_id": p.profile_id,
                "profile_version": p.version,
                "profile_fingerprint": p.config_fingerprint,
                "example_run_id": "",
                "source": "default_factory",
            }
    except Exception:  # noqa: BLE001
        pass
    return list(seen.values())


def read_twin_datasets(logs_dir: str, *, limit: int = 20) -> List[Dict[str, Any]]:
    root = twin_root(logs_dir) / "datasets"
    if not root.is_dir():
        return []
    out: List[Dict[str, Any]] = []
    try:
        dirs = sorted(
            [p for p in root.iterdir() if p.is_dir()],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    except Exception:  # noqa: BLE001
        return []
    for d in dirs[:MAX_DATASETS]:
        man = _safe_load_json(d / "dataset_manifest.json")
        if man is None:
            continue
        out.append(
            {
                "dataset_id": man.get("dataset_id") or d.name,
                "created_at": man.get("created_at"),
                "sample_count": man.get("sample_count"),
                "class_distribution": man.get("class_distribution"),
                "split_distribution": man.get("split_distribution"),
                "feature_schema_version": man.get("feature_schema_version"),
                "run_ids": man.get("run_ids"),
                "scenario_list": man.get("scenario_list"),
                "label_source": man.get("label_source"),
                "artifact_dir": str(d),
            }
        )
        if len(out) >= limit:
            break
    return out


def twin_history_stats(logs_dir: str) -> Dict[str, Any]:
    runs = read_twin_runs(logs_dir, limit=100)
    validations = read_twin_validations(logs_dir, limit=100)
    datasets = read_twin_datasets(logs_dir, limit=50)
    status_counts = Counter(
        str(r.get("validation_status") or r.get("status") or "UNKNOWN") for r in runs
    )
    outcome_counts = Counter(
        str(v.get("outcome_code") or "UNKNOWN") for v in validations
    )
    snapshots = read_twin_snapshots(logs_dir, limit=50)
    replays = read_twin_replays(logs_dir, limit=50)
    simulations = read_twin_simulations(logs_dir, limit=50)
    return {
        "runs": len(runs),
        "validations": len(validations),
        "datasets": len(datasets),
        "snapshots": len(snapshots),
        "replays": len(replays),
        "simulations": len(simulations),
        "validation_status_counts": dict(status_counts),
        "outcome_code_counts": dict(outcome_counts),
        "dataset_sample_total": sum(int(d.get("sample_count") or 0) for d in datasets),
        "source": "logs/twin/",
        "control": "READ_ONLY",
    }


def _iter_named_dirs(logs_dir: str, sub: str, filename: str) -> List[Dict[str, Any]]:
    root = twin_root(logs_dir) / sub
    if not root.is_dir():
        return []
    out: List[Dict[str, Any]] = []
    try:
        dirs = sorted(
            [p for p in root.iterdir() if p.is_dir()],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    except Exception:  # noqa: BLE001
        return []
    for d in dirs[:MAX_SCAN_RUNS]:
        rec = _safe_load_json(d / filename)
        if rec is None:
            continue
        rec.setdefault("artifact_dir", str(d))
        out.append(rec)
    return out


def _fidelity_artifact(artifact_dir: Optional[str]) -> Optional[Dict[str, Any]]:
    if not artifact_dir:
        return None
    return _safe_load_json(Path(artifact_dir) / "fidelity_report.json")


def _package_flags(artifact_dir: Optional[str]) -> Dict[str, bool]:
    if not artifact_dir:
        return {
            "twin_snapshot.json": False,
            "twin_observation.json": False,
            "fidelity_report.json": False,
        }
    base = Path(artifact_dir)
    return {
        "twin_snapshot.json": (base / "twin_snapshot.json").is_file(),
        "twin_observation.json": (base / "twin_observation.json").is_file(),
        "fidelity_report.json": (base / "fidelity_report.json").is_file(),
    }


def read_twin_snapshots(logs_dir: str, *, limit: int = 20) -> List[Dict[str, Any]]:
    limit = assert_history_limit(limit if limit > 0 else 20)
    rows = _iter_named_dirs(logs_dir, "snapshots", "twin_snapshot.json")
    compact = []
    for rec in rows[:limit]:
        artifact_dir = rec.get("artifact_dir")
        fidelity = _fidelity_artifact(str(artifact_dir) if artifact_dir else None)

        compact.append(
            {
                "snapshot_id": rec.get("snapshot_id"),
                "created_at": rec.get("created_at"),
                "source_logs_dir": rec.get("source_logs_dir"),
                "profile_id": rec.get("profile_id"),
                "n_windows": len(rec.get("windows") or []),
                "csv_counts": rec.get("csv_counts") or {},
                "jsonl_counts": rec.get("jsonl_counts") or {},
                "baseline_vs_attack": rec.get("baseline_vs_attack") or {},
                "control": rec.get("control") or "READ_ONLY",
                "mutates_mitigation": rec.get("mutates_mitigation", False),
                "launches_mininet": rec.get("launches_mininet", False),
                "artifact_dir": rec.get("artifact_dir"),
                "fidelity": compact_fidelity_summary(fidelity),
                "package": _package_flags(str(artifact_dir) if artifact_dir else None),
            }
        )
    return compact


def get_twin_snapshot(logs_dir: str, snapshot_id: str) -> Optional[Dict[str, Any]]:
    if not snapshot_id or not str(snapshot_id).strip():
        return None
    needle = str(snapshot_id).strip()
    for rec in _iter_named_dirs(logs_dir, "snapshots", "twin_snapshot.json"):
        if str(rec.get("snapshot_id")) == needle or Path(str(rec.get("artifact_dir") or "")).name == needle:
            artifact_dir = rec.get("artifact_dir")
            fidelity = _fidelity_artifact(str(artifact_dir) if artifact_dir else None)
            out = dict(rec)
            out["fidelity_report"] = fidelity
            out["fidelity"] = compact_fidelity_summary(fidelity)
            out["package"] = _package_flags(str(artifact_dir) if artifact_dir else None)
            return out
    return None


def read_twin_replays(logs_dir: str, *, limit: int = 20) -> List[Dict[str, Any]]:
    limit = assert_history_limit(limit if limit > 0 else 20)
    rows = _iter_named_dirs(logs_dir, "replays", "replay_result.json")
    return rows[:limit]


def read_twin_simulations(logs_dir: str, *, limit: int = 20) -> List[Dict[str, Any]]:
    limit = assert_history_limit(limit if limit > 0 else 20)
    rows = _iter_named_dirs(logs_dir, "simulations", "whatif_result.json")
    return rows[:limit]
