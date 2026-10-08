"""
================================================================================
IntelliShield SDN — Phase 5: Automated Mitigation Engine
================================================================================

File        : mitigation/mitigation_logger.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 5 — Automated DDoS Mitigation

Description:
    Structured CSV and JSON logging for all mitigation actions.

    Maintains:
        logs/mitigation_actions.csv  — every block/unblock event
        logs/mitigation_summary.json — session-level stats

    Each log entry captures the full context needed for IEEE research:
        - When mitigation was triggered
        - What triggered it (attack type, confidence)
        - Which MAC was blocked
        - How long the block lasted
        - Whether it was a true or false positive (if ground truth is known)

================================================================================
"""

import os
import csv
import json
import logging
import traceback
from datetime import datetime

logger = logging.getLogger("intellishield.mitigation_logger")

_BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
_LOGS_DIR    = os.path.join(_BASE_DIR, "..", "logs")

MITIGATION_CSV_PATH     = os.path.join(_LOGS_DIR, "mitigation_actions.csv")
MITIGATION_SUMMARY_PATH = os.path.join(_LOGS_DIR, "mitigation_summary.json")

MITIGATION_CSV_HEADERS = [
    "timestamp",
    "action",           # BLOCK | UNBLOCK | BLOCK_FAILED | UNBLOCK_ALL
    "dpid",
    "src_mac",
    "dst_mac",
    "block_type",       # SRC_MAC | FLOW_PAIR
    "attack_hint",
    "confidence",
    "timeout_sec",
    "status",           # SUCCESS | FAILED | SKIPPED
    "reason",
]


def init_mitigation_logs() -> None:
    """Create mitigation log files if they don't already exist."""
    from evaluation.csv_log_io import ensure_csv_header
    os.makedirs(_LOGS_DIR, exist_ok=True)
    ensure_csv_header(MITIGATION_CSV_PATH, MITIGATION_CSV_HEADERS)
    if not os.path.exists(MITIGATION_SUMMARY_PATH):
        with open(MITIGATION_SUMMARY_PATH, "w") as f:
            json.dump({
                "description": "IntelliShield Phase 5 — Mitigation Session Summary",
                "sessions": []
            }, f, indent=2)
    logger.info("[MitigationLogger] Log files initialised.")


def log_block_action(dpid: int,
                     src_mac: str,
                     attack_hint: str,
                     confidence: float,
                     timeout_sec: int,
                     block_type: str = "SRC_MAC",
                     dst_mac: str   = "",
                     status: str    = "SUCCESS",
                     reason: str    = "") -> None:
    """Log a block mitigation action."""
    _append({
        "timestamp"  : _now(),
        "action"     : "BLOCK",
        "dpid"       : dpid,
        "src_mac"    : src_mac,
        "dst_mac"    : dst_mac,
        "block_type" : block_type,
        "attack_hint": attack_hint,
        "confidence" : round(confidence, 2),
        "timeout_sec": timeout_sec,
        "status"     : status,
        "reason"     : reason,
    })
    _print_mitigation_event("BLOCK", src_mac, dpid, attack_hint, confidence,
                             timeout_sec, status)


def log_unblock_action(dpid: int,
                        src_mac: str,
                        reason: str = "TIMEOUT",
                        status: str = "SUCCESS") -> None:
    """Log an unblock action (manual or timeout expiry)."""
    _append({
        "timestamp"  : _now(),
        "action"     : "UNBLOCK",
        "dpid"       : dpid,
        "src_mac"    : src_mac,
        "dst_mac"    : "",
        "block_type" : "",
        "attack_hint": "",
        "confidence" : 0,
        "timeout_sec": 0,
        "status"     : status,
        "reason"     : reason,
    })
    logger.info("[UNBLOCK] dpid=%d  mac=%s  reason=%s", dpid, src_mac, reason)


def log_skipped(dpid: int, src_mac: str, reason: str) -> None:
    """Log when a block was skipped (whitelisted, already blocked, etc.)."""
    _append({
        "timestamp"  : _now(),
        "action"     : "BLOCK",
        "dpid"       : dpid,
        "src_mac"    : src_mac,
        "status"     : "SKIPPED",
        "reason"     : reason,
        "dst_mac"    : "", "block_type": "", "attack_hint": "",
        "confidence" : 0, "timeout_sec": 0,
    })
    logger.info("[SKIPPED] dpid=%d  mac=%s  reason=%s", dpid, src_mac, reason)


def update_mitigation_summary(stats: dict) -> None:
    """Append current session stats to mitigation_summary.json."""
    try:
        with open(MITIGATION_SUMMARY_PATH, "r") as f:
            data = json.load(f)
        data.setdefault("sessions", []).append({
            "timestamp": _now(), **stats
        })
        with open(MITIGATION_SUMMARY_PATH, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        logger.error("[update_mitigation_summary] %s", traceback.format_exc())


def _append(row: dict) -> None:
    try:
        from evaluation.csv_log_io import ensure_csv_header
        ensure_csv_header(MITIGATION_CSV_PATH, MITIGATION_CSV_HEADERS)
        with open(MITIGATION_CSV_PATH, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=MITIGATION_CSV_HEADERS)
            writer.writerow({h: row.get(h, "") for h in MITIGATION_CSV_HEADERS})
    except Exception:
        logger.error("[_append] %s", traceback.format_exc())


def _print_mitigation_event(action, mac, dpid, hint, conf, timeout, status):
    icon   = "🚫" if status == "SUCCESS" else "⚠️ "
    border = "─" * 56
    print(f"\n{border}")
    print(f"  {icon} [MITIGATION] {action}  |  Status: {status}")
    print(f"  Switch DPID  : {dpid}")
    print(f"  Blocked MAC  : {mac}")
    print(f"  Attack Hint  : {hint}")
    print(f"  Confidence   : {conf:.1f}%")
    print(f"  Block Timeout: {timeout}s (auto-expires)")
    print(f"{border}\n")


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
