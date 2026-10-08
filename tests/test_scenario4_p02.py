#!/usr/bin/env python3
"""
P0.2 — Scenario 4 attack lifecycle consistency tests.

Validates ATTACK_START/ATTACK_STOP event sequences and attack-window parsing
via the shared evaluation.experiment_windows provider.
"""

import csv
import os
import sys
import tempfile
from datetime import datetime, timedelta

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from evaluation.experiment_windows import load_experiment_windows, load_attack_windows
from ml_models.label_inference import LabelInferencer
from scripts.compute_metrics import _load_scenario_windows

_TS = "%Y-%m-%d %H:%M:%S"
_HEADERS = ["timestamp", "scenario_name", "event_type", "description", "status"]


def _write_scenario_log(path: str, rows: list) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_HEADERS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _legacy_s4_rows(base: datetime) -> list:
    """Pre-P0.2: ATTACK_START then recovery then END (no ATTACK_STOP)."""
    t = lambda sec: (base + timedelta(seconds=sec)).strftime(_TS)
    return [
        {"timestamp": t(0),  "scenario_name": "SCENARIO_4_BURST",
         "event_type": "START", "description": "start", "status": "OK"},
        {"timestamp": t(15), "scenario_name": "SCENARIO_4_BURST",
         "event_type": "ATTACK_START", "description": "burst", "status": "OK"},
        {"timestamp": t(38), "scenario_name": "SCENARIO_4_BURST",
         "event_type": "END", "description": "done", "status": "OK"},
    ]


def _fixed_s4_rows(base: datetime, burst_sec: int = 8) -> list:
    """Post-P0.2: ATTACK_START → burst → ATTACK_STOP → recovery → END."""
    t = lambda sec: (base + timedelta(seconds=sec)).strftime(_TS)
    attack_stop = 15 + burst_sec
    end = attack_stop + 15
    return [
        {"timestamp": t(0),  "scenario_name": "SCENARIO_4_BURST",
         "event_type": "START", "description": "start", "status": "OK"},
        {"timestamp": t(15), "scenario_name": "SCENARIO_4_BURST",
         "event_type": "ATTACK_START", "description": "burst", "status": "OK"},
        {"timestamp": t(attack_stop), "scenario_name": "SCENARIO_4_BURST",
         "event_type": "ATTACK_STOP", "description": "burst stopped", "status": "OK"},
        {"timestamp": t(end), "scenario_name": "SCENARIO_4_BURST",
         "event_type": "END", "description": "done", "status": "OK"},
    ]


def test_legacy_logs_no_one_hour_fallback():
    base = datetime(2026, 7, 8, 12, 0, 0)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "scenario_logs.csv")
        _write_scenario_log(path, _legacy_s4_rows(base))
        windows = load_attack_windows(tmp)
        assert len(windows) == 1
        start, end = windows[0]
        assert end - start == timedelta(seconds=23)
        assert end - start < timedelta(hours=1)


def test_fixed_logs_bounded_attack_window():
    base = datetime(2026, 7, 8, 12, 0, 0)
    burst_sec = 8
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "scenario_logs.csv")
        _write_scenario_log(path, _fixed_s4_rows(base, burst_sec))
        windows = load_attack_windows(tmp)
        assert len(windows) == 1
        start, end = windows[0]
        assert end - start == timedelta(seconds=burst_sec)


def test_recovery_traffic_labeled_normal_after_fix():
    base = datetime(2026, 7, 8, 12, 0, 0)
    burst_sec = 8
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "scenario_logs.csv")
        _write_scenario_log(path, _fixed_s4_rows(base, burst_sec))

        inferencer = LabelInferencer(logs_dir=tmp, refresh_sec=0)

        during_attack = (base + timedelta(seconds=20)).strftime(_TS)
        during_recovery = (base + timedelta(seconds=30)).strftime(_TS)

        assert inferencer.infer(during_attack) == 1
        assert inferencer.infer(during_recovery) == 0


def test_compute_metrics_window_matches_label_inference():
    base = datetime(2026, 7, 8, 12, 0, 0)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "scenario_logs.csv")
        _write_scenario_log(path, _fixed_s4_rows(base))

        li_windows = load_attack_windows(tmp)
        met_windows = _load_scenario_windows(tmp)

        assert len(li_windows) == 1
        assert len(met_windows) == 1
        assert li_windows[0][0] == met_windows[0]["attack_start"]
        assert li_windows[0][1] == met_windows[0]["attack_stop"]


def test_scenario2_regression_unchanged():
    """S2 pattern must still parse after shared provider migration."""
    base = datetime(2026, 7, 8, 14, 0, 0)
    t = lambda sec: (base + timedelta(seconds=sec)).strftime(_TS)
    rows = [
        {"timestamp": t(0),  "scenario_name": "SCENARIO_2_SYN_FLOOD",
         "event_type": "ATTACK_START", "description": "syn", "status": "OK"},
        {"timestamp": t(30), "scenario_name": "SCENARIO_2_SYN_FLOOD",
         "event_type": "ATTACK_STOP", "description": "stop", "status": "OK"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        _write_scenario_log(os.path.join(tmp, "scenario_logs.csv"), rows)
        windows = load_experiment_windows(tmp)
        assert len(windows) == 1
        assert windows[0].duration_sec == 30.0


if __name__ == "__main__":
    tests = [
        test_legacy_logs_no_one_hour_fallback,
        test_fixed_logs_bounded_attack_window,
        test_recovery_traffic_labeled_normal_after_fix,
        test_compute_metrics_window_matches_label_inference,
        test_scenario2_regression_unchanged,
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
