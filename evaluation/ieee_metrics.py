"""
IEEE-quality evaluation metrics for IntelliShield SDN experiments.

Extends latency/FP block statistics with classification metrics (accuracy,
precision, recall, F1, FPR, FNR) and system metrics (throughput, packet
loss, controller CPU/memory) derived from experiment logs.
"""

from __future__ import annotations

import csv
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from evaluation.experiment_windows import (
    MONITOR_INTERVAL_DEFAULT,
    load_experiment_windows,
    parse_ts,
    TS_FMT,
)

REPORT_VERSION = "2.0.0"

# Positive ML prediction labels for detection evaluation
POSITIVE_PREDICTION = {"ATTACK", "SUSPICIOUS"}

METRIC_DEFINITIONS = {
    "accuracy": {
        "formula"    : "(TP + TN) / (TP + TN + FP + FN)",
        "interpretation": "Fraction of monitoring cycles correctly classified.",
    },
    "precision": {
        "formula"    : "TP / (TP + FP)",
        "interpretation": "When the detector raises ATTACK/SUSPICIOUS, how often it is correct.",
    },
    "recall": {
        "formula"    : "TP / (TP + FN)",
        "interpretation": "Fraction of attack-window cycles that are detected (sensitivity).",
    },
    "f1_score": {
        "formula"    : "2 × (Precision × Recall) / (Precision + Recall)",
        "interpretation": "Harmonic mean of precision and recall.",
    },
    "false_positive_rate": {
        "formula"    : "FP / (FP + TN)",
        "interpretation": "Fraction of normal cycles incorrectly flagged as attack.",
    },
    "false_negative_rate": {
        "formula"    : "FN / (FN + TP)",
        "interpretation": "Fraction of attack cycles missed by the detector.",
    },
    "detection_latency_s": {
        "formula"    : "min(first_entropy_alert, first_ml_attack) − attack_start",
        "interpretation": "Seconds from attack onset to first confirmed detection.",
    },
    "mitigation_latency_s": {
        "formula"    : "first_successful_block − attack_start",
        "interpretation": "Seconds from attack onset to first OpenFlow DROP rule.",
    },
    "throughput_pkt_s": {
        "formula"    : "Σ packet_rate per monitoring cycle / n_cycles",
        "interpretation": "Mean aggregate packet rate across all flows (proxy for network load).",
    },
    "packet_loss_rate": {
        "formula"    : "Δ(rx_errors + tx_errors) / Δ(rx_packets + tx_packets)",
        "interpretation": "Port error ratio from OpenFlow port statistics.",
    },
    "controller_cpu_percent": {
        "formula"    : "mean(psutil.Process().cpu_percent()) per poll",
        "interpretation": "Average controller process CPU during the experiment.",
    },
    "controller_memory_rss_mb": {
        "formula"    : "mean(psutil.Process().memory_info().rss) / 1e6",
        "interpretation": "Average controller resident memory during the experiment.",
    },
}


def _safe_div(num: float, den: float) -> Optional[float]:
    if den == 0:
        return None
    return round(num / den, 4)


def _classification_counts(rows: List[dict], windows: List, pad_sec: float) -> Dict[str, int]:
    """Confusion matrix from ML predictions vs ground-truth attack windows."""
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


def compute_classification_metrics(counts: Dict[str, int]) -> Dict:
    """Derive accuracy, precision, recall, F1, FPR, FNR from confusion counts."""
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    total = tp + fp + tn + fn
    if total == 0:
        return {
            "tp": 0, "fp": 0, "tn": 0, "fn": 0,
            "accuracy": None, "precision": None, "recall": None,
            "f1_score": None, "false_positive_rate": None,
            "false_negative_rate": None, "samples": 0,
        }
    prec = _safe_div(tp, tp + fp)
    rec = _safe_div(tp, tp + fn)
    f1 = None
    if prec is not None and rec is not None and (prec + rec) > 0:
        f1 = round(2 * prec * rec / (prec + rec), 4)
    return {
        **counts,
        "samples"            : total,
        "accuracy"           : _safe_div(tp + tn, total),
        "precision"          : prec,
        "recall"             : rec,
        "f1_score"           : f1,
        "false_positive_rate": _safe_div(fp, fp + tn),
        "false_negative_rate": _safe_div(fn, fn + tp),
    }


def _rows_in_span(rows: List[dict], start: Optional[datetime],
                  stop: Optional[datetime]) -> List[dict]:
    if start is None or stop is None:
        return rows
    filtered = []
    for row in rows:
        ts = parse_ts(row.get("timestamp", ""))
        if ts is not None and start <= ts <= stop:
            filtered.append(row)
    return filtered


def _experiment_span(windows: List) -> Tuple[Optional[datetime], Optional[datetime]]:
    if not windows:
        return None, None
    starts = [w.attack_start for w in windows]
    stops = [w.attack_stop for w in windows]
    return min(starts), max(stops)


def compute_system_metrics(flow_rows: List[dict],
                           port_rows: List[dict],
                           controller_rows: List[dict],
                           start: Optional[datetime] = None,
                           stop: Optional[datetime] = None) -> Dict:
    """Derive throughput, packet loss, and controller resource metrics."""
    flow_rows = _rows_in_span(flow_rows, start, stop)
    port_rows = _rows_in_span(port_rows, start, stop)
    controller_rows = _rows_in_span(controller_rows, start, stop)

    # Throughput: sum packet_rate per timestamp bucket
    by_ts: Dict[str, float] = {}
    byte_by_ts: Dict[str, float] = {}
    for row in flow_rows:
        ts_key = row.get("timestamp", "")
        try:
            rate = float(row.get("packet_rate", 0) or 0)
            brate = float(row.get("byte_rate", 0) or 0)
        except (TypeError, ValueError):
            rate = brate = 0.0
        by_ts[ts_key] = by_ts.get(ts_key, 0.0) + rate
        byte_by_ts[ts_key] = byte_by_ts.get(ts_key, 0.0) + brate

    pkt_rates = list(by_ts.values())
    byte_rates = list(byte_by_ts.values())

    throughput = {
        "mean_pkt_s"  : round(sum(pkt_rates) / len(pkt_rates), 2) if pkt_rates else None,
        "peak_pkt_s"  : round(max(pkt_rates), 2) if pkt_rates else None,
        "mean_bytes_s": round(sum(byte_rates) / len(byte_rates), 2) if byte_rates else None,
        "peak_bytes_s": round(max(byte_rates), 2) if byte_rates else None,
    }

    # Packet loss from port error deltas
    packet_loss_rate = None
    if len(port_rows) >= 2:
        sorted_ports = sorted(
            port_rows,
            key=lambda r: parse_ts(r.get("timestamp", "")) or datetime.min,
        )
        first, last = sorted_ports[0], sorted_ports[-1]
        try:
            rx0 = float(first.get("rx_packets", 0) or 0)
            tx0 = float(first.get("tx_packets", 0) or 0)
            rx1 = float(last.get("rx_packets", 0) or 0)
            tx1 = float(last.get("tx_packets", 0) or 0)
            err0 = float(first.get("rx_errors", 0) or 0) + float(first.get("tx_errors", 0) or 0)
            err1 = float(last.get("rx_errors", 0) or 0) + float(last.get("tx_errors", 0) or 0)
            pkt_delta = (rx1 + tx1) - (rx0 + tx0)
            err_delta = err1 - err0
            if pkt_delta > 0:
                packet_loss_rate = round(max(0.0, err_delta / pkt_delta), 6)
        except (TypeError, ValueError):
            pass

    # Controller CPU / memory
    cpu_vals, mem_vals = [], []
    for row in controller_rows:
        try:
            cpu_vals.append(float(row.get("cpu_percent", 0)))
            mem_vals.append(float(row.get("memory_rss_mb", 0)))
        except (TypeError, ValueError):
            continue

    def _avg(vals: List[float]) -> Optional[float]:
        return round(sum(vals) / len(vals), 2) if vals else None

    return {
        "throughput_mean_pkt_s"   : throughput["mean_pkt_s"],
        "throughput_peak_pkt_s"   : throughput["peak_pkt_s"],
        "throughput_mean_bytes_s" : throughput["mean_bytes_s"],
        "throughput_peak_bytes_s" : throughput["peak_bytes_s"],
        "packet_loss_rate"        : packet_loss_rate,
        "controller_cpu_mean_pct" : _avg(cpu_vals),
        "controller_cpu_peak_pct" : round(max(cpu_vals), 2) if cpu_vals else None,
        "controller_memory_mean_mb": _avg(mem_vals),
        "controller_memory_peak_mb": round(max(mem_vals), 2) if mem_vals else None,
    }


def enrich_run(run: Dict, logs_dir: str, windows: List,
               grace_sec: float, load_csv_fn) -> Dict:
    """Add classification and per-run system metrics to an existing run dict."""
    start = parse_ts(run.get("attack_start", ""))
    stop = parse_ts(run.get("attack_stop", ""))
    if stop and grace_sec > 0:
        stop = stop + timedelta(seconds=grace_sec)

    ml_rows = load_csv_fn(logs_dir, "ml_predictions.csv")
    flow_rows = load_csv_fn(logs_dir, "flow_stats.csv")
    port_rows = load_csv_fn(logs_dir, "port_stats.csv")
    ctrl_rows = load_csv_fn(logs_dir, "controller_stats.csv")

    span_ml = _rows_in_span(ml_rows, start, stop)
    counts = _classification_counts(span_ml, windows, MONITOR_INTERVAL_DEFAULT)
    clf = compute_classification_metrics(counts)

    # Combined detection latency: earliest of entropy or ML
    latencies = [
        run.get("entropy_alert_latency_s"),
        run.get("ml_attack_latency_s"),
    ]
    valid_lats = [l for l in latencies if l is not None]
    detection_latency = min(valid_lats) if valid_lats else None

    system = compute_system_metrics(flow_rows, port_rows, ctrl_rows, start, stop)

    run_enriched = dict(run)
    run_enriched["classification"] = clf
    run_enriched["detection_latency_s"] = detection_latency
    run_enriched["mitigation_latency_s"] = run.get("mitigation_latency_s")
    run_enriched["system"] = system
    return run_enriched


def build_ieee_summary(runs: List[Dict], global_clf: Dict,
                       global_system: Dict) -> Dict:
    """Merge per-run and global metrics into summary block."""
    def _avg_key(key: str) -> Optional[float]:
        vals = [r.get(key) for r in runs if r.get(key) is not None]
        return round(sum(vals) / len(vals), 2) if vals else None

    det_lats = [r.get("detection_latency_s") for r in runs if r.get("detection_latency_s") is not None]
    mit_lats = [r.get("mitigation_latency_s") for r in runs if r.get("mitigation_latency_s") is not None]

    return {
        # Legacy keys preserved for backward compatibility
        "runs_analysed"              : len(runs),
        "avg_entropy_alert_latency_s": _avg_key("entropy_alert_latency_s"),
        "avg_ml_attack_latency_s"    : _avg_key("ml_attack_latency_s"),
        "avg_mitigation_latency_s"   : _avg_key("mitigation_latency_s"),
        "total_false_positive_blocks": sum(r.get("false_positive_blocks", 0) for r in runs),
        "total_blocks_in_attacks"    : sum(r.get("blocks_in_window", 0) for r in runs),
        # IEEE classification metrics (global across all ML prediction cycles)
        "classification"             : global_clf,
        # Combined latencies
        "avg_detection_latency_s"    : round(sum(det_lats) / len(det_lats), 2) if det_lats else None,
        "avg_mitigation_latency_s_ieee": round(sum(mit_lats) / len(mit_lats), 2) if mit_lats else None,
        # System metrics
        "system"                     : global_system,
    }


def enrich_report(base_report: Dict, logs_dir: str, grace_sec: float,
                  load_csv_fn) -> Dict:
    """Enrich a compute_metrics build_report() result with IEEE metrics."""
    windows = load_experiment_windows(logs_dir)
    span_start, span_stop = _experiment_span(windows)
    if span_stop and grace_sec > 0:
        span_stop = span_stop + timedelta(seconds=grace_sec)

    ml_rows = load_csv_fn(logs_dir, "ml_predictions.csv")
    flow_rows = load_csv_fn(logs_dir, "flow_stats.csv")
    port_rows = load_csv_fn(logs_dir, "port_stats.csv")
    ctrl_rows = load_csv_fn(logs_dir, "controller_stats.csv")

    span_ml = _rows_in_span(ml_rows, span_start, span_stop) if span_start else ml_rows
    global_clf = compute_classification_metrics(
        _classification_counts(span_ml, windows, MONITOR_INTERVAL_DEFAULT),
    )
    global_system = compute_system_metrics(
        flow_rows, port_rows, ctrl_rows, span_start, span_stop,
    )

    enriched_runs = [
        enrich_run(dict(r), logs_dir, windows, grace_sec, load_csv_fn)
        for r in base_report.get("runs", [])
    ]

    summary = build_ieee_summary(enriched_runs, global_clf, global_system)

    return {
        "report_version"    : REPORT_VERSION,
        "generated_at"      : base_report.get("generated_at", datetime.now().strftime(TS_FMT)),
        "logs_dir"          : os.path.abspath(logs_dir),
        "parameters"        : {"grace_sec": grace_sec, "label_pad_sec": MONITOR_INTERVAL_DEFAULT},
        "summary"           : summary,
        "runs"              : enriched_runs,
        "metric_definitions": METRIC_DEFINITIONS,
    }
