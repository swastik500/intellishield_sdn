"""
================================================================================
IntelliShield SDN — Phase 2: Entropy Detection Engine
================================================================================

File        : entropy_engine/entropy_logger.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 2 — Entropy-Based DDoS Detection

Description:
    Structured logging layer for entropy metrics and detection alerts.
    Handles three output targets simultaneously:

        1. logs/entropy_logs.csv      — per-cycle entropy values (time series)
        2. logs/detection_alerts.csv  — anomaly events with confidence
        3. logs/entropy_baselines.json — rolling baseline for adaptive tuning

    All CSV files use append mode — no data is ever overwritten during an
    experiment session. The JSON baseline is updated in-place after each cycle.

IEEE Relevance:
    Structured, timestamped logs are essential for research reproducibility.
    The CSV outputs can be imported directly into pandas/matplotlib for
    publication-quality entropy time-series plots.

Future Integration Points:
    - [HOOK] Phase 6 → ADWIN drift detector reads entropy_logs.csv
    - [HOOK] Phase 7 → PPO RL reads entropy_baselines.json for initial state
    - [HOOK] Phase 8 → Grafana dashboard ingests these CSVs via Prometheus

================================================================================
"""

import os
import csv
import json
import logging
import traceback
from datetime import datetime
from typing import Dict, List, Optional

# ─── Log File Paths ───────────────────────────────────────────────────────────

_BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
_LOGS_DIR     = os.path.join(_BASE_DIR, "..", "logs")

ENTROPY_CSV_PATH   = os.path.join(_LOGS_DIR, "entropy_logs.csv")
ALERTS_CSV_PATH    = os.path.join(_LOGS_DIR, "detection_alerts.csv")
BASELINE_JSON_PATH = os.path.join(_LOGS_DIR, "entropy_baselines.json")

# ─── CSV Column Schemas ───────────────────────────────────────────────────────

ENTROPY_CSV_HEADERS = [
    "timestamp",
    "switch_id",
    "n_flows",
    "src_entropy",
    "dst_entropy",
    "packet_entropy",
    "byte_entropy",
    "flow_entropy",
    "entropy_score",
    "status",
    "confidence",
]

ALERTS_CSV_HEADERS = [
    "timestamp",
    "switch_id",
    "alert_type",
    "dimension",
    "entropy_value",
    "threshold",
    "entropy_score",
    "confidence",
    "status",
]

# ─── Module Logger ────────────────────────────────────────────────────────────

logger = logging.getLogger("intellishield.entropy_logger")


# ─── Initialisation ───────────────────────────────────────────────────────────

def init_log_files() -> None:
    """
    Ensure all log files exist with correct headers.

    Creates the logs/ directory and initialises each CSV with its header row
    if the file does not already exist. The JSON baseline file is created
    with an empty skeleton if missing.

    Call once at application startup.
    """
    os.makedirs(_LOGS_DIR, exist_ok=True)

    _ensure_csv(ENTROPY_CSV_PATH,  ENTROPY_CSV_HEADERS)
    _ensure_csv(ALERTS_CSV_PATH,   ALERTS_CSV_HEADERS)
    _ensure_baseline_json(BASELINE_JSON_PATH)

    logger.info("[EntropyLogger] Log files initialised:")
    logger.info("  Entropy CSV  : %s", os.path.abspath(ENTROPY_CSV_PATH))
    logger.info("  Alerts  CSV  : %s", os.path.abspath(ALERTS_CSV_PATH))
    logger.info("  Baseline JSON: %s", os.path.abspath(BASELINE_JSON_PATH))


def _ensure_csv(filepath: str, headers: list) -> None:
    """Create CSV with header row, or repair a headerless file."""
    from evaluation.csv_log_io import ensure_csv_header
    ensure_csv_header(filepath, headers)


def _ensure_baseline_json(filepath: str) -> None:
    """Create empty baseline JSON skeleton if it does not already exist."""
    if not os.path.exists(filepath):
        baseline = {
            "description": "IntelliShield SDN — Entropy Baseline Store",
            "note": "Populated at runtime. Used by ADWIN (Phase 6) and PPO RL (Phase 7).",
            "switches": {}
        }
        with open(filepath, "w") as f:
            json.dump(baseline, f, indent=2)


# ─── Entropy Log Entry ────────────────────────────────────────────────────────

def log_entropy_metrics(metrics: dict) -> None:
    """
    Append a single entropy metrics snapshot to entropy_logs.csv.

    Args:
        metrics: Dict matching ENTROPY_CSV_HEADERS schema:
            {
                "timestamp"      : str,
                "switch_id"      : int,
                "n_flows"        : int,
                "src_entropy"    : float,
                "dst_entropy"    : float,
                "packet_entropy" : float,
                "byte_entropy"   : float,
                "flow_entropy"   : float,
                "entropy_score"  : float,
                "status"         : str,   e.g. "NORMAL" / "ALERT"
                "confidence"     : float, 0.0 – 100.0
            }
    """
    try:
        _ensure_csv(ENTROPY_CSV_PATH, ENTROPY_CSV_HEADERS)
        with open(ENTROPY_CSV_PATH, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=ENTROPY_CSV_HEADERS)
            row = {h: metrics.get(h, "") for h in ENTROPY_CSV_HEADERS}
            writer.writerow(row)
    except Exception:
        logger.error("[log_entropy_metrics] Failed:\n%s", traceback.format_exc())


# ─── Alert Log Entry ──────────────────────────────────────────────────────────

def log_alert(alert: dict) -> None:
    """
    Append a detection alert entry to detection_alerts.csv.

    Args:
        alert: Dict matching ALERTS_CSV_HEADERS schema:
            {
                "timestamp"    : str,
                "switch_id"    : int,
                "alert_type"   : str,   e.g. "SRC_ENTROPY_COLLAPSE"
                "dimension"    : str,   e.g. "src_entropy"
                "entropy_value": float,
                "threshold"    : float,
                "entropy_score": float,
                "confidence"   : float,
                "status"       : str,   "ALERT"
            }
    """
    try:
        _ensure_csv(ALERTS_CSV_PATH, ALERTS_CSV_HEADERS)
        with open(ALERTS_CSV_PATH, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=ALERTS_CSV_HEADERS)
            row = {h: alert.get(h, "") for h in ALERTS_CSV_HEADERS}
            writer.writerow(row)
    except Exception:
        logger.error("[log_alert] Failed:\n%s", traceback.format_exc())


# ─── Baseline JSON Update ─────────────────────────────────────────────────────

def update_baseline(switch_id: int, entropy_history: dict) -> None:
    """
    Update entropy baseline statistics for a switch in the JSON store.

    Stores moving averages and standard deviations per entropy dimension.
    This data will be used by:
        [HOOK] Phase 6 → ADWIN drift detector reads these as expected baseline
        [HOOK] Phase 7 → PPO RL initialises Q-values from these baselines

    Args:
        switch_id      : Integer datapath ID of the switch.
        entropy_history: Dict mapping dimension name → list of recent values.
            e.g. {"src_entropy": [3.8, 3.9, 3.7, ...], "dst_entropy": [...]}
    """
    try:
        # Load existing baseline
        if os.path.exists(BASELINE_JSON_PATH):
            with open(BASELINE_JSON_PATH, "r") as f:
                baseline = json.load(f)
        else:
            baseline = {"switches": {}}

        # Ensure switch entry exists
        sw_key = str(switch_id)
        if sw_key not in baseline["switches"]:
            baseline["switches"][sw_key] = {}

        from entropy_engine.entropy_utils import compute_mean, compute_std

        for dimension, values in entropy_history.items():
            if not values:
                continue
            mean = compute_mean(values)
            std  = compute_std(values, mean=mean)
            baseline["switches"][sw_key][dimension] = {
                "mean"        : round(mean, 6),
                "std"         : round(std, 6),
                "min"         : round(min(values), 6),
                "max"         : round(max(values), 6),
                "n_samples"   : len(values),
                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

        with open(BASELINE_JSON_PATH, "w") as f:
            json.dump(baseline, f, indent=2)

    except Exception:
        logger.error("[update_baseline] Failed:\n%s", traceback.format_exc())


def read_baseline(switch_id: int) -> dict:
    """
    Read stored baseline statistics for a switch.

    Args:
        switch_id: Integer datapath ID.

    Returns:
        Dict of per-dimension baseline stats, or empty dict if not found.
    """
    try:
        if not os.path.exists(BASELINE_JSON_PATH):
            return {}
        with open(BASELINE_JSON_PATH, "r") as f:
            baseline = json.load(f)
        return baseline.get("switches", {}).get(str(switch_id), {})
    except Exception:
        logger.error("[read_baseline] Failed:\n%s", traceback.format_exc())
        return {}


# ─── Console Printing ─────────────────────────────────────────────────────────

def print_entropy_report(metrics: dict) -> None:
    """
    Print a formatted entropy analysis block to console.

    Args:
        metrics: Entropy metrics dict (same schema as log_entropy_metrics).
    """
    status    = metrics.get("status", "UNKNOWN")
    score     = metrics.get("entropy_score", 0.0)
    confidence = metrics.get("confidence", 0.0)
    switch_id = metrics.get("switch_id", "?")
    n_flows   = metrics.get("n_flows", 0)

    border = "=" * 56
    print(f"\n{border}")
    print(f"  [ENTROPY ANALYSIS]  Switch: {switch_id}  |  {metrics.get('timestamp','')}")
    print(f"  Flows in window  : {n_flows}")
    print(f"{border}")
    print(f"  Source MAC Entropy    : {metrics.get('src_entropy', 0.0):.4f}")
    print(f"  Destination Entropy   : {metrics.get('dst_entropy', 0.0):.4f}")
    print(f"  Packet Distribution   : {metrics.get('packet_entropy', 0.0):.4f}")
    print(f"  Byte Distribution     : {metrics.get('byte_entropy', 0.0):.4f}")
    print(f"  Flow Distribution     : {metrics.get('flow_entropy', 0.0):.4f}")
    print(f"  ─{'─'*52}")
    print(f"  Overall Entropy Score : {score:.4f}")
    print(f"  Status                : {status}")
    if status == "ALERT":
        print(f"  Detection Confidence  : {confidence:.1f}%")
    print(f"{border}\n")


def print_alert_banner(alert: dict) -> None:
    """
    Print a high-visibility ALERT banner to console.

    Args:
        alert: Alert dict (same schema as log_alert).
    """
    border = "!" * 56
    print(f"\n{border}")
    print(f"  ⚠️   ENTROPY ALERT DETECTED")
    print(f"  Switch        : {alert.get('switch_id', '?')}")
    print(f"  Alert Type    : {alert.get('alert_type', '?')}")
    print(f"  Dimension     : {alert.get('dimension', '?')}")
    print(f"  Current Value : {alert.get('entropy_value', 0.0):.4f}")
    print(f"  Threshold     : {alert.get('threshold', 0.0):.4f}")
    print(f"  Overall Score : {alert.get('entropy_score', 0.0):.4f}")
    print(f"  Confidence    : {alert.get('confidence', 0.0):.1f}%")
    print(f"  Timestamp     : {alert.get('timestamp', '?')}")
    print(f"{border}\n")
