#!/usr/bin/env python3
"""
P0.3 — Shared experiment window provider tests.

Verifies label_inference, compute_metrics, and the canonical provider
all derive identical attack windows from the same log inputs.
"""

import csv
import os
import sys
import tempfile
from datetime import datetime, timedelta

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from evaluation.experiment_windows import (
    AttackWindow,
    load_experiment_windows,
    load_attack_windows,
    load_scenario_windows,
    load_attack_log_windows,
    parse_ts,
    MONITOR_INTERVAL_DEFAULT,
)
from ml_models.label_inference import LabelInferencer
from scripts.compute_metrics import _load_scenario_windows

_TS = "%Y-%m-%d %H:%M:%S"
_SCENARIO_HEADERS = ["timestamp", "scenario_name", "event_type", "description", "status"]
_ATTACK_HEADERS = ["timestamp", "attack_type", "source_host", "target_host",
                   "attack_rate", "duration", "status"]


def _write_csv(path: str, headers: list, rows: list) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _s2_scenario_rows(base: datetime) -> list:
    t = lambda s: (base + timedelta(seconds=s)).strftime(_TS)
    return [
        {"timestamp": t(0),  "scenario_name": "SCENARIO_2_SYN_FLOOD",
         "event_type": "ATTACK_START", "description": "syn", "status": "OK"},
        {"timestamp": t(30), "scenario_name": "SCENARIO_2_SYN_FLOOD",
         "event_type": "ATTACK_STOP", "description": "stop", "status": "OK"},
    ]


def _s4_fixed_rows(base: datetime, burst_sec: int = 8) -> list:
    t = lambda s: (base + timedelta(seconds=s)).strftime(_TS)
    stop = 15 + burst_sec
    return [
        {"timestamp": t(15), "scenario_name": "SCENARIO_4_BURST",
         "event_type": "ATTACK_START", "description": "burst", "status": "OK"},
        {"timestamp": t(stop), "scenario_name": "SCENARIO_4_BURST",
         "event_type": "ATTACK_STOP", "description": "stopped", "status": "OK"},
    ]


def _attack_log_row(base: datetime) -> dict:
    return {
        "timestamp"  : base.strftime(_TS),
        "attack_type": "SYN_FLOOD",
        "source_host": "h1",
        "target_host": "h2",
        "attack_rate": "10000",
        "duration"   : "20",
        "status"     : "RUNNING",
    }


def test_providers_agree_on_scenario_logs():
    base = datetime(2026, 7, 8, 10, 0, 0)
    with tempfile.TemporaryDirectory() as tmp:
        _write_csv(
            os.path.join(tmp, "scenario_logs.csv"),
            _SCENARIO_HEADERS,
            _s2_scenario_rows(base),
        )
        canonical = load_experiment_windows(tmp)
        tuples = load_attack_windows(tmp)
        metrics = _load_scenario_windows(tmp)

        assert len(canonical) == 1
        assert len(tuples) == 1
        assert len(metrics) == 1
        assert canonical[0].attack_start == tuples[0][0] == metrics[0]["attack_start"]
        assert canonical[0].attack_stop == tuples[0][1] == metrics[0]["attack_stop"]


def test_label_inference_matches_canonical_windows():
    base = datetime(2026, 7, 8, 11, 0, 0)
    with tempfile.TemporaryDirectory() as tmp:
        _write_csv(
            os.path.join(tmp, "scenario_logs.csv"),
            _SCENARIO_HEADERS,
            _s4_fixed_rows(base),
        )
        inferencer = LabelInferencer(logs_dir=tmp, refresh_sec=0)
        during = (base + timedelta(seconds=20)).strftime(_TS)
        after = (base + timedelta(seconds=30)).strftime(_TS)

        assert inferencer.infer(during) == 1
        assert inferencer.infer(after) == 0

        window = load_experiment_windows(tmp)[0]
        assert window.contains(parse_ts(during), pad_sec=MONITOR_INTERVAL_DEFAULT)
        assert not window.contains(parse_ts(after), pad_sec=MONITOR_INTERVAL_DEFAULT)


def test_metrics_and_labels_share_merged_sources():
    base = datetime(2026, 7, 8, 12, 0, 0)
    with tempfile.TemporaryDirectory() as tmp:
        _write_csv(
            os.path.join(tmp, "scenario_logs.csv"),
            _SCENARIO_HEADERS,
            _s2_scenario_rows(base),
        )
        _write_csv(
            os.path.join(tmp, "attack_logs.csv"),
            _ATTACK_HEADERS,
            [_attack_log_row(base + timedelta(seconds=60))],
        )

        canonical = load_experiment_windows(tmp)
        metrics = _load_scenario_windows(tmp)
        tuples = load_attack_windows(tmp)

        assert len(canonical) == 2
        assert len(metrics) == 2
        assert len(tuples) == 2
        for i, window in enumerate(canonical):
            assert metrics[i]["attack_start"] == window.attack_start
            assert metrics[i]["attack_stop"] == window.attack_stop
            assert tuples[i] == (window.attack_start, window.attack_stop)


def test_attack_window_duration_property():
    start = datetime(2026, 1, 1, 12, 0, 0)
    end = start + timedelta(seconds=8)
    w = AttackWindow("SCENARIO_4_BURST", start, end)
    assert w.duration_sec == 8.0


def test_legacy_s4_end_fallback():
    base = datetime(2026, 7, 8, 13, 0, 0)
    t = lambda s: (base + timedelta(seconds=s)).strftime(_TS)
    rows = [
        {"timestamp": t(15), "scenario_name": "SCENARIO_4_BURST",
         "event_type": "ATTACK_START", "description": "burst", "status": "OK"},
        {"timestamp": t(38), "scenario_name": "SCENARIO_4_BURST",
         "event_type": "END", "description": "done", "status": "OK"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        _write_csv(os.path.join(tmp, "scenario_logs.csv"), _SCENARIO_HEADERS, rows)
        windows = load_scenario_windows(tmp)
        assert len(windows) == 1
        assert windows[0].duration_sec == 23.0


if __name__ == "__main__":
    tests = [
        test_providers_agree_on_scenario_logs,
        test_label_inference_matches_canonical_windows,
        test_metrics_and_labels_share_merged_sources,
        test_attack_window_duration_property,
        test_legacy_s4_end_fallback,
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
