"""
Export IEEE evaluation reports to JSON, CSV, and Markdown paper tables.
"""

from __future__ import annotations

import csv
import json
import os
from typing import Dict, List, Optional


def _fmt(val) -> str:
    if val is None:
        return "N/A"
    if isinstance(val, float):
        return f"{val:.4f}".rstrip("0").rstrip(".")
    return str(val)


def export_json(report: Dict, path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)


def export_csv(report: Dict, path: str) -> None:
    """Write per-run metrics plus a summary row to CSV."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fieldnames = [
        "row_type", "scenario", "attack_start", "attack_stop",
        "accuracy", "precision", "recall", "f1_score",
        "false_positive_rate", "false_negative_rate",
        "detection_latency_s", "mitigation_latency_s",
        "entropy_alert_latency_s", "ml_attack_latency_s",
        "throughput_mean_pkt_s", "throughput_peak_pkt_s",
        "packet_loss_rate", "controller_cpu_mean_pct",
        "controller_memory_mean_mb", "false_positive_blocks",
        "blocks_in_window", "tp", "fp", "tn", "fn",
    ]

    rows: List[Dict] = []
    for run in report.get("runs", []):
        clf = run.get("classification", {})
        sysm = run.get("system", {})
        rows.append({
            "row_type"                 : "run",
            "scenario"                 : run.get("scenario", ""),
            "attack_start"             : run.get("attack_start", ""),
            "attack_stop"              : run.get("attack_stop", ""),
            "accuracy"                 : clf.get("accuracy"),
            "precision"                : clf.get("precision"),
            "recall"                   : clf.get("recall"),
            "f1_score"                 : clf.get("f1_score"),
            "false_positive_rate"      : clf.get("false_positive_rate"),
            "false_negative_rate"      : clf.get("false_negative_rate"),
            "detection_latency_s"      : run.get("detection_latency_s"),
            "mitigation_latency_s"     : run.get("mitigation_latency_s"),
            "entropy_alert_latency_s"  : run.get("entropy_alert_latency_s"),
            "ml_attack_latency_s"      : run.get("ml_attack_latency_s"),
            "throughput_mean_pkt_s"    : sysm.get("throughput_mean_pkt_s"),
            "throughput_peak_pkt_s"    : sysm.get("throughput_peak_pkt_s"),
            "packet_loss_rate"         : sysm.get("packet_loss_rate"),
            "controller_cpu_mean_pct"  : sysm.get("controller_cpu_mean_pct"),
            "controller_memory_mean_mb": sysm.get("controller_memory_mean_mb"),
            "false_positive_blocks"    : run.get("false_positive_blocks"),
            "blocks_in_window"         : run.get("blocks_in_window"),
            "tp"                       : clf.get("tp"),
            "fp"                       : clf.get("fp"),
            "tn"                       : clf.get("tn"),
            "fn"                       : clf.get("fn"),
        })

    s = report.get("summary", {})
    gclf = s.get("classification", {})
    gsys = s.get("system", {})
    rows.append({
        "row_type"                 : "summary",
        "scenario"                 : "ALL",
        "attack_start"             : "",
        "attack_stop"              : "",
        "accuracy"                 : gclf.get("accuracy"),
        "precision"                : gclf.get("precision"),
        "recall"                   : gclf.get("recall"),
        "f1_score"                 : gclf.get("f1_score"),
        "false_positive_rate"      : gclf.get("false_positive_rate"),
        "false_negative_rate"      : gclf.get("false_negative_rate"),
        "detection_latency_s"      : s.get("avg_detection_latency_s"),
        "mitigation_latency_s"     : s.get("avg_mitigation_latency_s_ieee"),
        "entropy_alert_latency_s"  : s.get("avg_entropy_alert_latency_s"),
        "ml_attack_latency_s"      : s.get("avg_ml_attack_latency_s"),
        "throughput_mean_pkt_s"    : gsys.get("throughput_mean_pkt_s"),
        "throughput_peak_pkt_s"    : gsys.get("throughput_peak_pkt_s"),
        "packet_loss_rate"         : gsys.get("packet_loss_rate"),
        "controller_cpu_mean_pct"  : gsys.get("controller_cpu_mean_pct"),
        "controller_memory_mean_mb": gsys.get("controller_memory_mean_mb"),
        "false_positive_blocks"    : s.get("total_false_positive_blocks"),
        "blocks_in_window"         : s.get("total_blocks_in_attacks"),
        "tp"                       : gclf.get("tp"),
        "fp"                       : gclf.get("fp"),
        "tn"                       : gclf.get("tn"),
        "fn"                       : gclf.get("fn"),
    })

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def export_paper_tables_md(report: Dict, path: str) -> None:
    """Generate Markdown tables suitable for IEEE paper insertion."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    s = report.get("summary", {})
    clf = s.get("classification", {})
    sysm = s.get("system", {})
    defs = report.get("metric_definitions", {})
    generated = report.get("generated_at", "")

    lines = [
        "# IntelliShield SDN — Evaluation Tables",
        "",
        f"*Generated: {generated} | Report version: {report.get('report_version', '1.0')}*",
        "",
        "## Table I — Detection Classification Metrics",
        "",
        "| Metric | Value | Formula |",
        "|--------|------:|---------|",
    ]

    clf_rows = [
        ("Accuracy", clf.get("accuracy"), "accuracy"),
        ("Precision", clf.get("precision"), "precision"),
        ("Recall (Sensitivity)", clf.get("recall"), "recall"),
        ("F1 Score", clf.get("f1_score"), "f1_score"),
        ("False Positive Rate", clf.get("false_positive_rate"), "false_positive_rate"),
        ("False Negative Rate", clf.get("false_negative_rate"), "false_negative_rate"),
    ]
    for label, val, key in clf_rows:
        formula = defs.get(key, {}).get("formula", "")
        lines.append(f"| {label} | {_fmt(val)} | `{formula}` |")

    lines += [
        "",
        f"*Confusion matrix: TP={clf.get('tp', 0)}, FP={clf.get('fp', 0)}, "
        f"TN={clf.get('tn', 0)}, FN={clf.get('fn', 0)} "
        f"(n={clf.get('samples', 0)} monitoring cycles)*",
        "",
        "## Table II — Latency and Mitigation",
        "",
        "| Metric | Mean (s) |",
        "|--------|--------:|",
        f"| Detection latency (combined) | {_fmt(s.get('avg_detection_latency_s'))} |",
        f"| Entropy alert latency | {_fmt(s.get('avg_entropy_alert_latency_s'))} |",
        f"| ML ATTACK latency | {_fmt(s.get('avg_ml_attack_latency_s'))} |",
        f"| Mitigation latency | {_fmt(s.get('avg_mitigation_latency_s'))} |",
        f"| False-positive blocks (outside window) | {s.get('total_false_positive_blocks', 0)} |",
        "",
        "## Table III — System Performance",
        "",
        "| Metric | Value |",
        "|--------|------:|",
        f"| Mean throughput (pkt/s) | {_fmt(sysm.get('throughput_mean_pkt_s'))} |",
        f"| Peak throughput (pkt/s) | {_fmt(sysm.get('throughput_peak_pkt_s'))} |",
        f"| Mean throughput (bytes/s) | {_fmt(sysm.get('throughput_mean_bytes_s'))} |",
        f"| Packet loss rate | {_fmt(sysm.get('packet_loss_rate'))} |",
        f"| Controller CPU mean (%) | {_fmt(sysm.get('controller_cpu_mean_pct'))} |",
        f"| Controller CPU peak (%) | {_fmt(sysm.get('controller_cpu_peak_pct'))} |",
        f"| Controller memory mean (MB) | {_fmt(sysm.get('controller_memory_mean_mb'))} |",
        f"| Controller memory peak (MB) | {_fmt(sysm.get('controller_memory_peak_mb'))} |",
        "",
        "## Table IV — Per-Scenario Results",
        "",
        "| Scenario | Detection (s) | Mitigation (s) | F1 | FPR | Blocks |",
        "|----------|-------------:|---------------:|---:|----:|-------:|",
    ]

    for run in report.get("runs", []):
        rc = run.get("classification", {})
        lines.append(
            f"| {run.get('scenario', '')} "
            f"| {_fmt(run.get('detection_latency_s'))} "
            f"| {_fmt(run.get('mitigation_latency_s'))} "
            f"| {_fmt(rc.get('f1_score'))} "
            f"| {_fmt(rc.get('false_positive_rate'))} "
            f"| {run.get('blocks_in_window', 0)} |"
        )

    lines += [
        "",
        "## Metric Definitions",
        "",
    ]
    for name, meta in defs.items():
        lines.append(f"**{name}** — {meta.get('interpretation', '')}  ")
        lines.append(f"  Formula: `{meta.get('formula', '')}`  ")
        lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def export_all(report: Dict, json_path: str,
               csv_path: Optional[str] = None,
               paper_path: Optional[str] = None) -> Dict[str, str]:
    """Write JSON + derived CSV and paper_tables.md alongside JSON."""
    export_json(report, json_path)
    base_dir = os.path.dirname(os.path.abspath(json_path))
    base_name = os.path.splitext(os.path.basename(json_path))[0]

    csv_out = csv_path or os.path.join(base_dir, f"{base_name}.csv")
    paper_out = paper_path or os.path.join(base_dir, "paper_tables.md")

    export_csv(report, csv_out)
    export_paper_tables_md(report, paper_out)

    return {"json": json_path, "csv": csv_out, "paper_md": paper_out}
