"""
================================================================================
IntelliShield SDN — Phase 4: ML-Based Anomaly Detection
================================================================================

File        : ml_models/ml_logger.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 4 — ML Anomaly Detection

Description:
    CSV and console logging for all ML prediction events.

    Maintains:
        logs/ml_predictions.csv  — per-cycle prediction log (time series)
        logs/ml_alerts.csv       — high-confidence attack events only
        logs/ml_summary.json     — session statistics

IEEE Relevance:
    Per-cycle ML prediction logs are the primary data source for the
    research results section. Plotting ml_predictions.csv over time
    shows detection latency, false positive rate, and accuracy curves.

================================================================================
"""

import os
import csv
import json
import logging
import traceback
from datetime import datetime
from typing import Dict, Optional

logger = logging.getLogger("intellishield.ml_logger")

_BASE_DIR         = os.path.dirname(os.path.abspath(__file__))
_LOGS_DIR         = os.path.join(_BASE_DIR, "..", "logs")

ML_PRED_CSV_PATH  = os.path.join(_LOGS_DIR, "ml_predictions.csv")
ML_ALERT_CSV_PATH = os.path.join(_LOGS_DIR, "ml_alerts.csv")
ML_SUMMARY_PATH   = os.path.join(_LOGS_DIR, "ml_summary.json")

ML_PRED_HEADERS = [
    "timestamp", "switch_id",
    "status", "confidence",
    "iso_score", "dt_label", "dt_confidence",
    "attack_type_hint",
    "src_entropy", "dst_entropy", "entropy_score",
    "packet_rate_mean", "flow_count",
]

ML_ALERT_HEADERS = [
    "timestamp", "switch_id",
    "status", "confidence",
    "attack_type_hint",
    "narrative",
]


def init_ml_logs() -> None:
    """Create ML log files with headers if they don't already exist."""
    os.makedirs(_LOGS_DIR, exist_ok=True)
    _ensure_csv(ML_PRED_CSV_PATH,  ML_PRED_HEADERS)
    _ensure_csv(ML_ALERT_CSV_PATH, ML_ALERT_HEADERS)
    _ensure_summary()
    logger.info("[MLLogger] Log files initialised.")


def _ensure_csv(path: str, headers: list) -> None:
    if not os.path.exists(path):
        with open(path, "w", newline="") as f:
            csv.writer(f).writerow(headers)


def _ensure_summary() -> None:
    if not os.path.exists(ML_SUMMARY_PATH):
        with open(ML_SUMMARY_PATH, "w") as f:
            json.dump({
                "description": "IntelliShield Phase 4 — ML Session Summary",
                "sessions": []
            }, f, indent=2)


def log_prediction(switch_id: int,
                   prediction: Dict,
                   explanation: Dict,
                   vector: list,
                   feature_names: list) -> None:
    """
    Log one ML prediction cycle to ml_predictions.csv.

    Args:
        switch_id  : Switch datapath ID.
        prediction : Dict from AnomalyDetector.predict().
        explanation: Dict from Explainer.explain().
        vector     : Feature vector (list of floats).
        feature_names: FEATURE_NAMES list.
    """
    try:
        feat = dict(zip(feature_names, vector))
        row = {
            "timestamp"        : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "switch_id"        : switch_id,
            "status"           : prediction.get("status", ""),
            "confidence"       : prediction.get("confidence", 0.0),
            "iso_score"        : prediction.get("iso_score", 0.0),
            "dt_label"         : prediction.get("dt_label", ""),
            "dt_confidence"    : prediction.get("dt_confidence", 0.0),
            "attack_type_hint" : explanation.get("attack_type_hint", ""),
            "src_entropy"      : feat.get("src_entropy", 0.0),
            "dst_entropy"      : feat.get("dst_entropy", 0.0),
            "entropy_score"    : feat.get("entropy_score", 0.0),
            "packet_rate_mean" : feat.get("packet_rate_mean", 0.0),
            "flow_count"       : feat.get("flow_count", 0.0),
        }
        _append_csv(ML_PRED_CSV_PATH, ML_PRED_HEADERS, row)
    except Exception:
        logger.error("[log_prediction] %s", traceback.format_exc())


def log_ml_alert(switch_id: int,
                  prediction: Dict,
                  explanation: Dict) -> None:
    """
    Log a high-confidence attack alert to ml_alerts.csv.
    Only called when status is SUSPICIOUS or ATTACK.
    """
    try:
        row = {
            "timestamp"        : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "switch_id"        : switch_id,
            "status"           : prediction.get("status", ""),
            "confidence"       : prediction.get("confidence", 0.0),
            "attack_type_hint" : explanation.get("attack_type_hint", ""),
            "narrative"        : explanation.get("narrative", "")[:200],
        }
        _append_csv(ML_ALERT_CSV_PATH, ML_ALERT_HEADERS, row)
    except Exception:
        logger.error("[log_ml_alert] %s", traceback.format_exc())


def print_ml_result(prediction: Dict, explanation: Dict) -> None:
    """Print a compact ML result line to console (not full explanation)."""
    status = prediction.get("status", "UNKNOWN")
    conf   = prediction.get("confidence", 0.0)
    hint   = explanation.get("attack_type_hint", "?")
    iso    = prediction.get("iso_score", 0.0)

    icon = {"NORMAL": "✅", "SUSPICIOUS": "⚠️ ", "ATTACK": "🚨"}.get(status, "❓")
    print(f"  {icon} [ML] {status:<12}  conf={conf:5.1f}%  "
          f"iso={iso:.3f}  hint={hint}")


def _append_csv(path: str, headers: list, row: dict) -> None:
    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writerow({h: row.get(h, "") for h in headers})


def update_ml_summary(switch_id: int, stats: dict) -> None:
    """
    Update the ML session summary JSON with latest statistics.

    [HOOK] Phase 8 → Dashboard reads this for live stats display.
    """
    try:
        with open(ML_SUMMARY_PATH, "r") as f:
            data = json.load(f)

        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "switch_id": switch_id,
            **stats
        }
        data.setdefault("sessions", []).append(entry)

        with open(ML_SUMMARY_PATH, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        logger.error("[update_ml_summary] %s", traceback.format_exc())
