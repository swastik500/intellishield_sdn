"""Build ExperimentEvidence from experiment logs / IEEE metrics (not synthetic)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from evaluation.csv_log_io import load_csv_rows
from evaluation.experiment_windows import (
    MONITOR_INTERVAL_DEFAULT,
    load_experiment_windows,
    parse_ts,
)
from evaluation.ieee_metrics import compute_classification_metrics
from twin.experiment_plan import ExperimentEvidence
from twin.manifest import build_manifest
from twin.planner import plan_scenario
from twin.scenario_map import scenario_id_matches_name
from twin.scenario_spec import ScenarioPlan
from twin.validate import TwinValidationError

logger = logging.getLogger("intellishield.twin.evidence")

PathLike = Union[str, Path]

POSITIVE_PREDICTION = {"ATTACK", "SUSPICIOUS"}


def _rows_in_span(rows: List[dict], start: Any, stop: Any) -> List[dict]:
    if start is None or stop is None:
        return list(rows)
    filtered: List[dict] = []
    for row in rows:
        ts = parse_ts(row.get("timestamp", ""))
        if ts is not None and start <= ts <= stop:
            filtered.append(row)
    return filtered


def _classification_counts(
    rows: List[dict], windows: Sequence[Any], pad_sec: float
) -> Dict[str, int]:
    tp = fp = tn = fn = 0
    for row in rows:
        ts = parse_ts(row.get("timestamp", ""))
        if ts is None:
            continue
        pred_pos = str(row.get("status", "")).upper() in POSITIVE_PREDICTION
        actual_pos = any(w.contains(ts, pad_sec=pad_sec) for w in windows)
        if pred_pos and actual_pos:
            tp += 1
        elif pred_pos and not actual_pos:
            fp += 1
        elif not pred_pos and not actual_pos:
            tn += 1
        else:
            fn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}

logger = logging.getLogger("intellishield.twin.evidence")

PathLike = Union[str, Path]


def _safe_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _metrics_from_classification(clf: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "precision": clf.get("precision"),
        "recall": clf.get("recall"),
        "f1_score": clf.get("f1_score"),
        "false_positive_rate": clf.get("false_positive_rate"),
        "false_negative_rate": clf.get("false_negative_rate"),
        "accuracy": clf.get("accuracy"),
        "tp": clf.get("tp"),
        "fp": clf.get("fp"),
        "tn": clf.get("tn"),
        "fn": clf.get("fn"),
        "samples": clf.get("samples"),
    }


def _load_metrics_report(path: Path) -> Optional[Dict[str, Any]]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        return obj if isinstance(obj, dict) else None
    except Exception:  # noqa: BLE001
        logger.debug("metrics_report unreadable: %s", path, exc_info=True)
        return None


def _run_for_scenario(
    report: Mapping[str, Any], scenario_id: str
) -> Optional[Dict[str, Any]]:
    for run in report.get("runs") or []:
        if not isinstance(run, dict):
            continue
        name = str(run.get("scenario") or "")
        if scenario_id_matches_name(scenario_id, name):
            return run
    return None


def evidence_metrics_from_logs(
    logs_dir: PathLike,
    scenario_id: str,
    *,
    metrics_report_path: Optional[PathLike] = None,
) -> Dict[str, Any]:
    """
    Derive detector/mitigation evaluation metrics for one S1–S5 scenario.

    Prefers metrics_report.json (IEEE). Falls back to ml_predictions.csv +
    experiment windows. Missing inputs yield null metrics + missing_artifacts.
    """
    src = Path(logs_dir)
    missing: List[str] = []
    report_path = Path(metrics_report_path) if metrics_report_path else src / "metrics_report.json"
    if not report_path.is_file():
        parent = src.parent / "metrics_report.json"
        if parent.is_file():
            report_path = parent

    metrics: Dict[str, Any] = {
        "precision": None,
        "recall": None,
        "f1_score": None,
        "false_positive_rate": None,
        "false_negative_rate": None,
        "detection_latency_s": None,
        "runtime_latency_s": None,
        "false_mitigations": None,
        "mitigation_latency_s": None,
        "accuracy": None,
    }

    if report_path.is_file():
        report = _load_metrics_report(report_path)
        if report is None:
            missing.append("metrics_report.json")
        else:
            run = _run_for_scenario(report, scenario_id)
            summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
            clf = {}
            if run:
                clf = run.get("classification") or {}
                metrics["detection_latency_s"] = _safe_float(run.get("detection_latency_s"))
                metrics["mitigation_latency_s"] = _safe_float(run.get("mitigation_latency_s"))
                metrics["false_mitigations"] = _safe_float(run.get("false_positive_blocks"))
            elif summary.get("classification"):
                clf = summary.get("classification") or {}
                metrics["detection_latency_s"] = _safe_float(
                    summary.get("avg_detection_latency_s")
                )
                metrics["false_mitigations"] = _safe_float(
                    summary.get("total_false_positive_blocks")
                )
            else:
                missing.append(f"metrics_report:{scenario_id}")
            metrics.update(_metrics_from_classification(clf))
            if metrics.get("runtime_latency_s") is None:
                metrics["runtime_latency_s"] = 0.0
            metrics["evidence_origin"] = "metrics_report.json"
            return {"metrics": metrics, "missing_artifacts": missing}

    ml_path = src / "ml_predictions.csv"
    if not ml_path.is_file():
        missing.append("ml_predictions.csv")
        missing.append("metrics_report.json")
        metrics["evidence_origin"] = "insufficient"
        return {"metrics": metrics, "missing_artifacts": missing}

    try:
        windows = load_experiment_windows(str(src))
    except Exception:  # noqa: BLE001
        windows = []
    scoped = [
        w
        for w in windows
        if scenario_id_matches_name(scenario_id, getattr(w, "scenario", "") or "")
    ]
    if not scoped and scenario_id != "S1":
        missing.append(f"attack_windows:{scenario_id}")

    rows = load_csv_rows(ml_path)
    if scoped:
        start = min(w.attack_start for w in scoped)
        stop = max(w.attack_stop for w in scoped)
        rows = _rows_in_span(rows, start, stop)
    clf = compute_classification_metrics(
        _classification_counts(rows, scoped or windows, MONITOR_INTERVAL_DEFAULT)
    )
    metrics.update(_metrics_from_classification(clf))
    if metrics.get("runtime_latency_s") is None:
        metrics["runtime_latency_s"] = 0.0
    metrics["evidence_origin"] = "ml_predictions.csv"
    if clf.get("samples") in (0, None):
        missing.append("ml_prediction_samples")
    return {"metrics": metrics, "missing_artifacts": missing}


def evidence_for_plan_from_logs(
    plans: Sequence[ScenarioPlan],
    logs_dir: PathLike,
    *,
    seed: int,
    profile_fingerprint: str,
    metrics_report_path: Optional[PathLike] = None,
) -> List[ExperimentEvidence]:
    src = Path(logs_dir)
    if not src.is_dir():
        raise TwinValidationError(f"experiment logs dir missing: {src}")
    out: List[ExperimentEvidence] = []
    for plan in plans:
        packed = evidence_metrics_from_logs(
            src, plan.scenario_id, metrics_report_path=metrics_report_path
        )
        missing = list(packed.get("missing_artifacts") or [])
        metrics = dict(packed.get("metrics") or {})
        required = ("precision", "recall", "f1_score", "false_positive_rate")
        if any(metrics.get(k) is None for k in required):
            if "required_metrics" not in missing:
                missing.append("required_metrics")
        out.append(
            ExperimentEvidence(
                scenario_id=plan.scenario_id,
                metrics=metrics,
                seed=seed,
                profile_fingerprint=profile_fingerprint,
                scenario_manifest=build_manifest(plan),
                missing_artifacts=missing,
                experiment_ok=src.is_dir(),
                experiment_error="",
                source="experiment_logs",
            )
        )
    return out


def plans_for_scenarios(
    scenario_ids: Sequence[str],
    *,
    seed: int = 42,
) -> List[ScenarioPlan]:
    return [plan_scenario(sid, seed=seed) for sid in scenario_ids]
