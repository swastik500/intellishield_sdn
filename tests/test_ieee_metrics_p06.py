#!/usr/bin/env python3
"""
P0.6 — IEEE evaluation metrics and export tests.
"""

import csv
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from evaluation.ieee_metrics import (
    REPORT_VERSION,
    METRIC_DEFINITIONS,
    compute_classification_metrics,
    _classification_counts,
    compute_system_metrics,
)
from evaluation.report_export import export_all, export_csv, export_paper_tables_md
from scripts.compute_metrics import build_report, _load_csv

_TS = "%Y-%m-%d %H:%M:%S"


def _write_csv(path, headers, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for row in rows:
            w.writerow(row)


def _simulate_full_experiment(logs_dir):
    base = datetime(2026, 7, 8, 16, 0, 0)
    t = lambda s: (base + timedelta(seconds=s)).strftime(_TS)

    _write_csv(
        os.path.join(logs_dir, "scenario_logs.csv"),
        ["timestamp", "scenario_name", "event_type", "description", "status"],
        [
            {"timestamp": t(0),  "scenario_name": "SCENARIO_2_SYN_FLOOD",
             "event_type": "ATTACK_START", "description": "syn", "status": "OK"},
            {"timestamp": t(30), "scenario_name": "SCENARIO_2_SYN_FLOOD",
             "event_type": "ATTACK_STOP", "description": "stop", "status": "OK"},
        ],
    )

    ml_rows = []
    for i in range(12):
        sec = i * 5
        status = "ATTACK" if 10 <= sec <= 35 else "NORMAL"
        ml_rows.append({
            "timestamp": t(sec), "switch_id": "1", "status": status,
            "confidence": "90" if status == "ATTACK" else "5",
            "iso_score": "-0.5", "dt_label": "1", "dt_confidence": "0.9",
            "attack_type_hint": "SYN_FLOOD" if status == "ATTACK" else "NORMAL",
            "src_entropy": "0.04", "dst_entropy": "0.7", "entropy_score": "0.2",
            "packet_rate_mean": "8000", "flow_count": "3",
        })
    _write_csv(
        os.path.join(logs_dir, "ml_predictions.csv"),
        ["timestamp", "switch_id", "status", "confidence", "iso_score",
         "dt_label", "dt_confidence", "attack_type_hint", "src_entropy",
         "dst_entropy", "entropy_score", "packet_rate_mean", "flow_count"],
        ml_rows,
    )

    _write_csv(
        os.path.join(logs_dir, "entropy_logs.csv"),
        ["timestamp", "switch_id", "n_flows", "src_entropy", "dst_entropy",
         "packet_entropy", "byte_entropy", "flow_entropy", "entropy_score",
         "status", "confidence"],
        [{"timestamp": t(i * 5), "switch_id": "1", "n_flows": "10",
          "src_entropy": "0.8", "dst_entropy": "0.7", "packet_entropy": "0.6",
          "byte_entropy": "0.5", "flow_entropy": "0.4",
          "entropy_score": "0.3", "status": "ALERT" if i == 2 else "NORMAL",
          "confidence": "85"} for i in range(12)],
    )

    _write_csv(
        os.path.join(logs_dir, "detection_alerts.csv"),
        ["timestamp", "switch_id", "alert_type", "dimension", "entropy_value",
         "threshold", "entropy_score", "confidence", "status"],
        [{"timestamp": t(10), "switch_id": "1", "alert_type": "ALERT",
          "dimension": "src_entropy", "entropy_value": "0.04",
          "threshold": "0.3", "entropy_score": "0.2", "confidence": "85",
          "status": "ALERT"}],
    )

    _write_csv(
        os.path.join(logs_dir, "mitigation_actions.csv"),
        ["timestamp", "action", "dpid", "src_mac", "dst_mac", "block_type",
         "attack_hint", "confidence", "timeout_sec", "status", "reason"],
        [{"timestamp": t(18), "action": "BLOCK", "dpid": "1",
          "src_mac": "02:aa:aa:aa:aa:01", "dst_mac": "02:bb:bb:bb:bb:02",
          "block_type": "FLOW_PAIR", "attack_hint": "SYN_FLOOD",
          "confidence": "88", "timeout_sec": "60", "status": "SUCCESS",
          "reason": ""}],
    )

    flow_rows = []
    for i in range(12):
        flow_rows.append({
            "timestamp": t(i * 5), "switch_id": "1",
            "src_mac": "02:aa:aa:aa:aa:01", "dst_mac": "02:bb:bb:bb:bb:02",
            "in_port": "1", "priority": "1", "packet_count": "1000",
            "byte_count": "50000", "packet_rate": str(1000 + i * 500),
            "byte_rate": str(50000 + i * 10000), "duration_sec": "5",
        })
    _write_csv(
        os.path.join(logs_dir, "flow_stats.csv"),
        ["timestamp", "switch_id", "src_mac", "dst_mac", "in_port", "priority",
         "packet_count", "byte_count", "packet_rate", "byte_rate", "duration_sec"],
        flow_rows,
    )

    _write_csv(
        os.path.join(logs_dir, "port_stats.csv"),
        ["timestamp", "switch_id", "port_no", "rx_packets", "tx_packets",
         "rx_bytes", "tx_bytes", "rx_errors", "tx_errors"],
        [
            {"timestamp": t(0), "switch_id": "1", "port_no": "1",
             "rx_packets": "1000", "tx_packets": "1000",
             "rx_bytes": "50000", "tx_bytes": "50000",
             "rx_errors": "0", "tx_errors": "0"},
            {"timestamp": t(55), "switch_id": "1", "port_no": "1",
             "rx_packets": "50000", "tx_packets": "50000",
             "rx_bytes": "2500000", "tx_bytes": "2500000",
             "rx_errors": "5", "tx_errors": "3"},
        ],
    )

    _write_csv(
        os.path.join(logs_dir, "controller_stats.csv"),
        ["timestamp", "cpu_percent", "memory_rss_mb", "memory_percent"],
        [{"timestamp": t(i * 5), "cpu_percent": str(10 + i),
          "memory_rss_mb": str(120 + i), "memory_percent": "2.5"}
         for i in range(12)],
    )


def test_classification_metrics_known_values():
    counts = {"tp": 8, "fp": 1, "tn": 2, "fn": 1}
    m = compute_classification_metrics(counts)
    assert m["accuracy"] == 0.8333
    assert m["precision"] == 0.8889
    assert m["recall"] == 0.8889
    assert m["f1_score"] == 0.8889
    assert m["false_positive_rate"] == 0.3333
    assert m["false_negative_rate"] == 0.1111


def test_system_metrics_throughput_and_loss():
    flow = [{"timestamp": "2026-01-01 12:00:00", "packet_rate": "1000", "byte_rate": "50000"},
            {"timestamp": "2026-01-01 12:00:00", "packet_rate": "2000", "byte_rate": "80000"},
            {"timestamp": "2026-01-01 12:00:05", "packet_rate": "500", "byte_rate": "20000"}]
    port = [
        {"timestamp": "2026-01-01 12:00:00", "rx_packets": "1000", "tx_packets": "1000",
         "rx_errors": "0", "tx_errors": "0"},
        {"timestamp": "2026-01-01 12:01:00", "rx_packets": "11000", "tx_packets": "11000",
         "rx_errors": "2", "tx_errors": "1"},
    ]
    ctrl = [{"timestamp": "2026-01-01 12:00:00", "cpu_percent": "10", "memory_rss_mb": "100"}]
    sysm = compute_system_metrics(flow, port, ctrl)
    assert sysm["throughput_mean_pkt_s"] == 1750.0
    assert sysm["throughput_peak_pkt_s"] == 3000.0
    assert sysm["packet_loss_rate"] is not None
    assert sysm["controller_cpu_mean_pct"] == 10.0


def test_build_report_includes_ieee_fields():
    with tempfile.TemporaryDirectory() as tmp:
        _simulate_full_experiment(tmp)
        report = build_report(tmp)
        assert report["report_version"] == REPORT_VERSION
        assert "classification" in report["summary"]
        assert "system" in report["summary"]
        assert report["summary"]["classification"]["samples"] > 0
        assert report["runs"][0]["detection_latency_s"] is not None
        assert report["runs"][0]["mitigation_latency_s"] is not None
        assert "metric_definitions" in report


def test_export_all_three_formats():
    with tempfile.TemporaryDirectory() as tmp:
        _simulate_full_experiment(tmp)
        report = build_report(tmp)
        json_path = os.path.join(tmp, "metrics_report.json")
        paths = export_all(report, json_path)
        assert os.path.isfile(paths["json"])
        assert os.path.isfile(paths["csv"])
        assert os.path.isfile(paths["paper_md"])
        with open(paths["json"]) as f:
            loaded = json.load(f)
        assert loaded["report_version"] == REPORT_VERSION
        with open(paths["paper_md"]) as f:
            md = f.read()
        assert "Table I" in md
        assert "Accuracy" in md


def test_backward_compatible_summary_keys():
    with tempfile.TemporaryDirectory() as tmp:
        _simulate_full_experiment(tmp)
        report = build_report(tmp)
        s = report["summary"]
        for key in ("runs_analysed", "avg_entropy_alert_latency_s",
                    "avg_ml_attack_latency_s", "avg_mitigation_latency_s",
                    "total_false_positive_blocks", "total_blocks_in_attacks"):
            assert key in s


def test_metric_definitions_complete():
    required = [
        "accuracy", "precision", "recall", "f1_score",
        "false_positive_rate", "false_negative_rate",
        "detection_latency_s", "mitigation_latency_s",
        "throughput_pkt_s", "packet_loss_rate",
        "controller_cpu_percent", "controller_memory_rss_mb",
    ]
    for name in required:
        assert name in METRIC_DEFINITIONS
        assert "formula" in METRIC_DEFINITIONS[name]
        assert "interpretation" in METRIC_DEFINITIONS[name]


if __name__ == "__main__":
    tests = [
        test_classification_metrics_known_values,
        test_system_metrics_throughput_and_loss,
        test_build_report_includes_ieee_fields,
        test_export_all_three_formats,
        test_backward_compatible_summary_keys,
        test_metric_definitions_complete,
    ]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {fn.__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
