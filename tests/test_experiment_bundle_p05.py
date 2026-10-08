#!/usr/bin/env python3
"""
P0.5 — Reproducible experiment bundle tests.

Simulates one experiment run and verifies the bundle contains
experiment_manifest.json, artifacts, configuration, and directory tree.
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

from evaluation.experiment_bundle import (
    BUNDLE_VERSION,
    create_bundle,
    collect_config_snapshot,
    collect_scenario_metadata,
)
from scripts.compute_metrics import build_report

_TS = "%Y-%m-%d %H:%M:%S"


def _write_csv(path, headers, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for row in rows:
            w.writerow(row)


def _simulate_experiment_logs(logs_dir: str) -> None:
    """Create a minimal but complete experiment artifact set."""
    base = datetime(2026, 7, 8, 15, 0, 0)
    t = lambda s: (base + timedelta(seconds=s)).strftime(_TS)

    os.makedirs(os.path.join(logs_dir, "models"), exist_ok=True)

    # Ground truth
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

    # Entropy
    entropy_rows = [
        {"timestamp": t(i * 5), "switch_id": "1", "n_flows": "10",
         "src_entropy": "0.8", "dst_entropy": "0.7", "packet_entropy": "0.6",
         "byte_entropy": "0.5", "flow_entropy": "0.4",
         "entropy_score": str(0.9 - i * 0.1), "status": "NORMAL",
         "confidence": "10"}
        for i in range(8)
    ]
    _write_csv(
        os.path.join(logs_dir, "entropy_logs.csv"),
        ["timestamp", "switch_id", "n_flows", "src_entropy", "dst_entropy",
         "packet_entropy", "byte_entropy", "flow_entropy", "entropy_score",
         "status", "confidence"],
        entropy_rows,
    )

    _write_csv(
        os.path.join(logs_dir, "detection_alerts.csv"),
        ["timestamp", "switch_id", "alert_type", "dimension", "entropy_value",
         "threshold", "entropy_score", "confidence", "status"],
        [{"timestamp": t(12), "switch_id": "1", "alert_type": "ALERT",
          "dimension": "src_entropy", "entropy_value": "0.04",
          "threshold": "0.3", "entropy_score": "0.2", "confidence": "85",
          "status": "ALERT"}],
    )

    # ML
    _write_csv(
        os.path.join(logs_dir, "ml_predictions.csv"),
        ["timestamp", "switch_id", "status", "confidence", "iso_score",
         "dt_label", "dt_confidence", "attack_type_hint", "src_entropy",
         "dst_entropy", "entropy_score", "packet_rate_mean", "flow_count"],
        [{"timestamp": t(15), "switch_id": "1", "status": "ATTACK",
          "confidence": "88", "iso_score": "-0.5", "dt_label": "1",
          "dt_confidence": "0.9", "attack_type_hint": "SYN_FLOOD",
          "src_entropy": "0.04", "dst_entropy": "0.7", "entropy_score": "0.2",
          "packet_rate_mean": "8000", "flow_count": "3"}],
    )

    _write_csv(
        os.path.join(logs_dir, "ml_features.csv"),
        ["timestamp", "switch_id", "src_entropy", "dst_entropy",
         "packet_entropy", "byte_entropy", "flow_entropy",
         "packet_rate_mean", "packet_rate_max", "byte_rate_mean",
         "flow_count", "flow_concentration", "duration_mean",
         "entropy_score", "label"],
        [{"timestamp": t(15), "switch_id": "1", "src_entropy": "0.04",
          "dst_entropy": "0.7", "packet_entropy": "0.1", "byte_entropy": "0.2",
          "flow_entropy": "0.3", "packet_rate_mean": "8000",
          "packet_rate_max": "9000", "byte_rate_mean": "500000",
          "flow_count": "3", "flow_concentration": "0.8",
          "duration_mean": "5", "entropy_score": "0.2", "label": "1"}],
    )

    # Mitigation
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

    # Dummy model files
    for name in ("isolation_forest.pkl", "decision_tree.pkl", "scaler.pkl"):
        with open(os.path.join(logs_dir, "models", name), "wb") as f:
            f.write(b"INTELLISHIELD_TEST_MODEL_" + name.encode())

    # Metrics
    report = build_report(logs_dir)
    with open(os.path.join(logs_dir, "metrics_report.json"), "w") as f:
        json.dump(report, f, indent=2)


def test_manifest_has_required_fields():
    with tempfile.TemporaryDirectory() as tmp:
        _simulate_experiment_logs(tmp)
        result = create_bundle(tmp, bundle_id="test_run_001", generate_plots=False)
        with open(result["manifest_path"]) as f:
            manifest = json.load(f)

        required = [
            "bundle_version", "experiment_id", "created_at", "git",
            "dataset_checksums", "model_versions", "scenario_windows",
            "configuration", "artifacts", "metrics_summary",
        ]
        for key in required:
            assert key in manifest, f"missing manifest key: {key}"
        assert manifest["experiment_id"] == "test_run_001"
        assert manifest["bundle_version"] == BUNDLE_VERSION
        assert len(manifest["scenario_windows"]) == 1
        assert manifest["scenario_windows"][0]["scenario"] == "SCENARIO_2_SYN_FLOOD"


def test_all_artifacts_copied():
    with tempfile.TemporaryDirectory() as tmp:
        _simulate_experiment_logs(tmp)
        result = create_bundle(tmp, bundle_id="test_artifacts", generate_plots=False)

        expected = [
            "scenario_logs.csv",
            "entropy_logs.csv",
            "ml_predictions.csv",
            "ml_features.csv",
            "mitigation_actions.csv",
            "metrics_report.json",
            "models/isolation_forest.pkl",
            "models/decision_tree.pkl",
            "models/scaler.pkl",
        ]
        for rel in expected:
            path = os.path.join(result["bundle_dir"], "artifacts", rel)
            assert os.path.isfile(path), f"missing artifact: {rel}"


def test_directory_tree_generated():
    with tempfile.TemporaryDirectory() as tmp:
        _simulate_experiment_logs(tmp)
        result = create_bundle(tmp, bundle_id="test_tree", generate_plots=False)
        assert os.path.isfile(result["tree_path"])
        with open(result["tree_path"]) as f:
            tree = f.read()
        assert "experiment_manifest.json" in tree
        assert "artifacts/" in tree


def test_config_snapshot_includes_mitigation():
    cfg = collect_config_snapshot()
    assert "mitigation" in cfg
    assert "SYN_FLOOD" in cfg["mitigation"]["flow_pair_hints"]
    assert "VOLUMETRIC_FLOOD" in cfg["mitigation"]["src_mac_hints"]
    assert "scenarios" in cfg


def test_checksums_are_stable():
    with tempfile.TemporaryDirectory() as tmp:
        _simulate_experiment_logs(tmp)
        result = create_bundle(tmp, bundle_id="test_checksum", generate_plots=False)
        with open(result["manifest_path"]) as f:
            m1 = json.load(f)
        with open(result["manifest_path"]) as f:
            m2 = json.load(f)
        assert m1["dataset_checksums"] == m2["dataset_checksums"]
        assert len(m1["dataset_checksums"]) >= 5


if __name__ == "__main__":
    tests = [
        test_manifest_has_required_fields,
        test_all_artifacts_copied,
        test_directory_tree_generated,
        test_config_snapshot_includes_mitigation,
        test_checksums_are_stable,
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
