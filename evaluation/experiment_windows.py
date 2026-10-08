"""
Single source of truth for Phase 3 attack-window parsing.

Consumes ground-truth logs produced by traffic_generator:
  - logs/scenario_logs.csv  (ATTACK_START / ATTACK_STOP lifecycle)
  - logs/attack_logs.csv    (LAUNCHED/RUNNING rows + duration)

Used by:
  - ml_models/label_inference.py   (training / live labels)
  - scripts/compute_metrics.py     (IEEE experiment metrics)
"""

from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

TS_FMT = "%Y-%m-%d %H:%M:%S"

ATTACK_START_EVENTS = frozenset({
    "ATTACK_START", "ATTACK_BEGIN", "ATTACK1_START", "ATTACK2_START",
})
ATTACK_STOP_EVENTS = frozenset({
    "ATTACK_STOP", "ATTACK_END", "ATTACK1_STOP", "ATTACK2_STOP",
})
SCENARIO_END_EVENTS = frozenset({"END"})

MONITOR_INTERVAL_DEFAULT = 5


@dataclass(frozen=True)
class AttackWindow:
    """One contiguous attack interval with provenance metadata."""

    scenario: str
    attack_start: datetime
    attack_stop: datetime
    source: str = "scenario_logs"

    @property
    def duration_sec(self) -> float:
        return (self.attack_stop - self.attack_start).total_seconds()

    def contains(self, ts: datetime, pad_sec: float = 0.0) -> bool:
        """Return True when *ts* falls inside the window (optional symmetric pad)."""
        pad = timedelta(seconds=pad_sec)
        return (self.attack_start - pad) <= ts <= (self.attack_stop + pad)

    def to_metrics_dict(self) -> dict:
        """Shape expected by scripts/compute_metrics.analyse_run()."""
        return {
            "scenario"    : self.scenario,
            "attack_start": self.attack_start,
            "attack_stop" : self.attack_stop,
        }


def parse_ts(value: str) -> Optional[datetime]:
    try:
        return datetime.strptime(str(value).strip(), TS_FMT)
    except (ValueError, TypeError, AttributeError):
        return None


def load_attack_log_windows(logs_dir: str) -> List[AttackWindow]:
    """Build windows from attack_logs.csv (LAUNCHED/RUNNING + duration)."""
    path = os.path.join(logs_dir, "attack_logs.csv")
    if not os.path.exists(path):
        return []

    windows: List[AttackWindow] = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if row.get("status", "").upper() not in ("LAUNCHED", "RUNNING"):
                continue
            start = parse_ts(row.get("timestamp", ""))
            if start is None:
                continue
            try:
                duration = int(float(row.get("duration") or 0))
            except (TypeError, ValueError):
                duration = 0
            end = start + timedelta(seconds=max(duration, MONITOR_INTERVAL_DEFAULT))
            scenario = row.get("attack_type", "ATTACK_LOG") or "ATTACK_LOG"
            windows.append(AttackWindow(
                scenario=scenario,
                attack_start=start,
                attack_stop=end,
                source="attack_logs",
            ))
    return windows


def load_scenario_windows(logs_dir: str) -> List[AttackWindow]:
    """Build windows from scenario_logs.csv lifecycle events."""
    path = os.path.join(logs_dir, "scenario_logs.csv")
    if not os.path.exists(path):
        return []

    windows: List[AttackWindow] = []
    open_start: Optional[datetime] = None
    open_name = "UNKNOWN"

    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            event = row.get("event_type", "").upper()
            ts = parse_ts(row.get("timestamp", ""))
            if ts is None:
                continue
            if event in ATTACK_START_EVENTS:
                open_start = ts
                open_name = row.get("scenario_name", "UNKNOWN") or "UNKNOWN"
            elif event in ATTACK_STOP_EVENTS and open_start is not None:
                windows.append(AttackWindow(
                    scenario=open_name,
                    attack_start=open_start,
                    attack_stop=ts,
                    source="scenario_logs",
                ))
                open_start = None
            elif event in SCENARIO_END_EVENTS and open_start is not None:
                # Legacy S4 logs: ATTACK_START without ATTACK_STOP closed at END
                windows.append(AttackWindow(
                    scenario=open_name,
                    attack_start=open_start,
                    attack_stop=ts,
                    source="scenario_logs",
                ))
                open_start = None

    if open_start is not None:
        windows.append(AttackWindow(
            scenario=open_name,
            attack_start=open_start,
            attack_stop=open_start,
            source="scenario_logs",
        ))
    return windows


def load_experiment_windows(logs_dir: str) -> List[AttackWindow]:
    """
    Merge scenario + attack log windows, sorted by attack_start.

    This is the canonical window list for labels and metrics.
    """
    merged = load_scenario_windows(logs_dir) + load_attack_log_windows(logs_dir)
    merged.sort(key=lambda w: w.attack_start)
    return merged


def load_attack_windows(logs_dir: str) -> List[Tuple[datetime, datetime]]:
    """Backward-compatible tuple API for label_inference consumers."""
    return [(w.attack_start, w.attack_stop) for w in load_experiment_windows(logs_dir)]
