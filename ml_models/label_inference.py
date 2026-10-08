"""
Infer ground-truth ML labels (0=NORMAL, 1=ATTACK) from Phase 3 traffic logs.

Joins monitoring-cycle timestamps against attack windows recorded in:
  - logs/attack_logs.csv   (LAUNCHED/RUNNING rows + duration)
  - logs/scenario_logs.csv (ATTACK_START … ATTACK_STOP intervals)

Window parsing is delegated to evaluation.experiment_windows (single source of truth).
"""

import os
import time
import logging
from typing import Optional

from evaluation.experiment_windows import (
    load_experiment_windows,
    load_attack_windows,
    parse_ts,
    MONITOR_INTERVAL_DEFAULT,
)

logger = logging.getLogger("intellishield.label_inference")

# Re-export for backward compatibility
__all__ = [
    "LabelInferencer",
    "load_attack_windows",
    "heuristic_label_from_features",
    "parse_ts",
    "MONITOR_INTERVAL_DEFAULT",
]

# Heuristic flood signature (matches entropy ALERT + Scenario 2 SYN flood)
HEURISTIC_ATTACK_PKT_MAX = 1000.0
HEURISTIC_ATTACK_PKT_ENT = 0.25


class LabelInferencer:
    """Map monitoring timestamps to NORMAL (0) or ATTACK (1) using Phase 3 logs."""

    def __init__(self, logs_dir: Optional[str] = None, refresh_sec: int = 30) -> None:
        base = os.path.dirname(os.path.abspath(__file__))
        self._logs_dir = logs_dir or os.path.join(base, "..", "logs")
        self._refresh_sec = refresh_sec
        self._windows = load_experiment_windows(self._logs_dir)
        self._last_load = 0.0
        self._has_logs = bool(self._windows)

    def _reload_if_stale(self) -> None:
        if time.time() - self._last_load < self._refresh_sec:
            return
        self._windows = load_experiment_windows(self._logs_dir)
        self._has_logs = bool(self._windows)
        self._last_load = time.time()
        if self._has_logs:
            logger.debug("[LabelInferencer] Loaded %d attack window(s)", len(self._windows))

    def infer(self, timestamp_str: str) -> Optional[int]:
        """
        Return 1 if timestamp falls in an attack window, 0 if outside,
        or None when no Phase 3 attack logs exist yet.
        """
        self._reload_if_stale()
        if not self._has_logs:
            return None

        ts = parse_ts(timestamp_str)
        if ts is None:
            return None

        for window in self._windows:
            if window.contains(ts, pad_sec=MONITOR_INTERVAL_DEFAULT):
                return 1
        return 0


def heuristic_label_from_features(row: dict) -> Optional[int]:
    """
    Infer ATTACK/NORMAL from feature values when log windows are sparse.

    SYN floods often keep src_entropy high in the 100-flow window, so
    packet_rate_max + packet_entropy collapse is a stronger training signal.
    """
    try:
        pkt_max = float(row.get("packet_rate_max", 0))
        pkt_ent = float(row.get("packet_entropy", 1))
        if pkt_max >= HEURISTIC_ATTACK_PKT_MAX and pkt_ent <= HEURISTIC_ATTACK_PKT_ENT:
            return 1
        if pkt_max >= 5000.0:
            return 1
        if pkt_max < 500.0 and pkt_ent > 0.5:
            return 0
    except (TypeError, ValueError):
        pass
    return None
