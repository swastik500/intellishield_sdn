"""
Shared CSV log helpers for IntelliShield log files.

Ensures header rows exist (including after dashboard archive while the
controller is still running) and provides resilient DictReader loading.
"""

from __future__ import annotations

import csv
import os
from pathlib import Path
from typing import Dict, List, Optional, Union

PathLike = Union[str, Path]

KNOWN_CSV_HEADERS: Dict[str, List[str]] = {
    "entropy_logs.csv": [
        "timestamp", "switch_id", "n_flows", "src_entropy", "dst_entropy",
        "packet_entropy", "byte_entropy", "flow_entropy", "entropy_score",
        "status", "confidence",
    ],
    "detection_alerts.csv": [
        "timestamp", "switch_id", "alert_type", "dimension", "entropy_value",
        "threshold", "entropy_score", "confidence", "status",
    ],
    "mitigation_actions.csv": [
        "timestamp", "action", "dpid", "src_mac", "dst_mac", "block_type",
        "attack_hint", "confidence", "timeout_sec", "status", "reason",
    ],
    "ml_predictions.csv": [
        "timestamp", "switch_id", "status", "confidence", "iso_score",
        "dt_label", "dt_confidence", "attack_type_hint", "src_entropy",
        "dst_entropy", "entropy_score", "packet_rate_mean", "flow_count",
    ],
    "ml_alerts.csv": [
        "timestamp", "switch_id", "status", "confidence",
        "attack_type_hint", "narrative",
    ],
    "flow_stats.csv": [
        "timestamp", "switch_id", "src_mac", "dst_mac",
        "in_port", "priority", "packet_count", "byte_count",
        "packet_rate", "byte_rate", "duration_sec",
    ],
    "port_stats.csv": [
        "timestamp", "switch_id", "port_no",
        "rx_packets", "tx_packets", "rx_bytes", "tx_bytes",
        "rx_errors", "tx_errors",
    ],
    "controller_stats.csv": [
        "timestamp", "cpu_percent", "memory_rss_mb", "memory_percent",
    ],
    "rl_decisions.csv": [
        "timestamp", "switch_id", "cycle",
        "pkt_rate_mean", "byte_rate_mean", "entropy_score", "flow_count",
        "ml_label", "ml_confidence",
        "action_pkt", "action_byte", "action_conf",
        "pkt_threshold", "byte_threshold", "conf_threshold",
        "reward",
    ],
    "rl_training.csv": [
        "timestamp", "update_number",
        "actor_loss", "critic_loss",
        "buffer_size",
    ],
    "drift_alerts.csv": [
        "timestamp", "metric_name", "switch_id",
        "window_size", "old_mean", "new_mean",
        "delta_mean", "epsilon_cut", "total_seen",
    ],
    "scenario_logs.csv": [
        "timestamp", "scenario_name", "event_type",
        "description", "status",
    ],
    "attack_logs.csv": [
        "timestamp", "attack_type", "source_host",
        "target_host", "attack_rate", "duration", "status",
    ],
    "traffic_logs.csv": [
        "timestamp", "traffic_type", "source_host",
        "destination_host", "protocol", "packet_rate",
        "bandwidth", "duration", "status",
    ],
}


def csv_has_valid_header(filepath: PathLike) -> bool:
    """Return True when the first row is a real header (has ``timestamp`` column)."""
    path = str(filepath)
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return False
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
    return "timestamp" in fields


def ensure_csv_header(filepath: PathLike, headers: List[str]) -> None:
    """
    Create a CSV with a header row, or prepend the header when missing.

    This repairs files created by append-only writers after ``archive_logs``
    moved the originals while the controller kept running.
    """
    path = str(filepath)
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)

    if not os.path.exists(path) or os.path.getsize(path) == 0:
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(headers)
        return

    if csv_has_valid_header(path):
        return

    with open(path, "r", encoding="utf-8") as f:
        body_lines = f.readlines()

    with open(path, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(headers)
        f.writelines(body_lines)


def load_csv_rows(
    filepath: PathLike,
    *,
    fallback_headers: Optional[List[str]] = None,
    tail_n: Optional[int] = None,
) -> List[dict]:
    """Load CSV rows, using known headers when the file is missing its header row."""
    path = str(filepath)
    if not os.path.exists(path):
        return []

    name = os.path.basename(path)
    headers = fallback_headers or KNOWN_CSV_HEADERS.get(name)

    try:
        if headers and not csv_has_valid_header(path):
            with open(path, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f, fieldnames=headers))
        else:
            with open(path, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        if tail_n is not None:
            rows = rows[-tail_n:]
        return rows
    except Exception:
        return []
