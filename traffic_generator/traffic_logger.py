"""
================================================================================
IntelliShield SDN — Phase 3: Traffic Generation & Attack Simulation Engine
================================================================================

File        : traffic_generator/traffic_logger.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 3 — Traffic Generation & Attack Simulation

Description:
    Structured logging for all Phase 3 traffic and attack events.
    Maintains three CSV files and one JSON profile store:

        logs/traffic_logs.csv    — normal traffic events
        logs/attack_logs.csv     — attack simulation events
        logs/scenario_logs.csv   — scenario lifecycle events
        logs/traffic_profiles.json — serialised profile snapshots

IEEE Relevance:
    Timestamped, structured logs allow post-experiment reconstruction
    of the exact traffic timeline. Combined with entropy_logs.csv from
    Phase 2, researchers can correlate traffic events with entropy changes.

================================================================================
"""

import os
import csv
import json
import logging
import traceback
from datetime import datetime
from typing import Dict, Any

# ─── Log File Paths ───────────────────────────────────────────────────────────

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_LOGS_DIR = os.path.join(_BASE_DIR, "..", "logs")

TRAFFIC_CSV_PATH  = os.path.join(_LOGS_DIR, "traffic_logs.csv")
ATTACK_CSV_PATH   = os.path.join(_LOGS_DIR, "attack_logs.csv")
SCENARIO_CSV_PATH = os.path.join(_LOGS_DIR, "scenario_logs.csv")
PROFILES_JSON_PATH = os.path.join(_LOGS_DIR, "traffic_profiles.json")

# ─── CSV Schemas ──────────────────────────────────────────────────────────────

TRAFFIC_CSV_HEADERS = [
    "timestamp", "traffic_type", "source_host",
    "destination_host", "protocol", "packet_rate",
    "bandwidth", "duration", "status",
]

ATTACK_CSV_HEADERS = [
    "timestamp", "attack_type", "source_host",
    "target_host", "attack_rate", "duration", "status",
]

SCENARIO_CSV_HEADERS = [
    "timestamp", "scenario_name", "event_type",
    "description", "status",
]

logger = logging.getLogger("intellishield.traffic_logger")


# ─── Initialisation ───────────────────────────────────────────────────────────

def init_traffic_logs() -> None:
    """Create all log files with headers if they don't already exist."""
    os.makedirs(_LOGS_DIR, exist_ok=True)
    _ensure_csv(TRAFFIC_CSV_PATH,  TRAFFIC_CSV_HEADERS)
    _ensure_csv(ATTACK_CSV_PATH,   ATTACK_CSV_HEADERS)
    _ensure_csv(SCENARIO_CSV_PATH, SCENARIO_CSV_HEADERS)
    _ensure_profiles_json()

    logger.info("[TrafficLogger] Log files initialised.")
    logger.info("  Traffic  CSV : %s", os.path.abspath(TRAFFIC_CSV_PATH))
    logger.info("  Attack   CSV : %s", os.path.abspath(ATTACK_CSV_PATH))
    logger.info("  Scenario CSV : %s", os.path.abspath(SCENARIO_CSV_PATH))


def _ensure_csv(filepath: str, headers: list) -> None:
    if not os.path.exists(filepath):
        with open(filepath, "w", newline="") as f:
            csv.writer(f).writerow(headers)


def _ensure_profiles_json() -> None:
    if not os.path.exists(PROFILES_JSON_PATH):
        with open(PROFILES_JSON_PATH, "w") as f:
            json.dump({"description": "IntelliShield SDN — Traffic Profile Log",
                       "sessions": []}, f, indent=2)


# ─── Traffic Log ──────────────────────────────────────────────────────────────

def log_traffic_event(traffic_type: str, source: str, destination: str,
                      protocol: str, packet_rate: float = 0,
                      bandwidth: str = "N/A", duration: int = 0,
                      status: str = "STARTED") -> None:
    """
    Append a normal traffic event to traffic_logs.csv.

    Args:
        traffic_type : e.g. "ICMP", "TCP", "UDP", "HTTP", "MIXED"
        source       : Source Mininet host name (e.g. "h1")
        destination  : Destination host name or IP
        protocol     : Protocol string
        packet_rate  : Estimated packets/sec (0 if unknown)
        bandwidth    : Bandwidth string (e.g. "1M") or "N/A"
        duration     : Duration in seconds
        status       : "STARTED", "RUNNING", "STOPPED", "ERROR"
    """
    try:
        row = {
            "timestamp"       : _now(),
            "traffic_type"    : traffic_type,
            "source_host"     : source,
            "destination_host": destination,
            "protocol"        : protocol,
            "packet_rate"     : packet_rate,
            "bandwidth"       : bandwidth,
            "duration"        : duration,
            "status"          : status,
        }
        _append_csv(TRAFFIC_CSV_PATH, TRAFFIC_CSV_HEADERS, row)
        _print_traffic_event(row)
    except Exception:
        logger.error("[log_traffic_event] %s", traceback.format_exc())


# ─── Attack Log ───────────────────────────────────────────────────────────────

def log_attack_event(attack_type: str, source: str, target: str,
                     attack_rate: int = 0, duration: int = 0,
                     status: str = "LAUNCHED") -> None:
    """
    Append an attack simulation event to attack_logs.csv.

    Args:
        attack_type : e.g. "SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", "BURST"
        source      : Attacker Mininet host name
        target      : Victim host name or IP
        attack_rate : Packets/sec
        duration    : Duration in seconds
        status      : "LAUNCHED", "RUNNING", "STOPPED", "ERROR"
    """
    try:
        row = {
            "timestamp"  : _now(),
            "attack_type": attack_type,
            "source_host": source,
            "target_host": target,
            "attack_rate": attack_rate,
            "duration"   : duration,
            "status"     : status,
        }
        _append_csv(ATTACK_CSV_PATH, ATTACK_CSV_HEADERS, row)
        _print_attack_event(row)
    except Exception:
        logger.error("[log_attack_event] %s", traceback.format_exc())


# ─── Scenario Log ─────────────────────────────────────────────────────────────

def log_scenario_event(scenario_name: str, event_type: str,
                       description: str, status: str = "OK") -> None:
    """
    Append a scenario lifecycle event to scenario_logs.csv.

    Args:
        scenario_name: Scenario identifier (e.g. "SCENARIO_2_SYN_FLOOD")
        event_type   : e.g. "START", "PHASE_CHANGE", "ATTACK_BEGIN", "END"
        description  : Human-readable description
        status       : "OK", "ERROR", "SKIPPED"
    """
    try:
        row = {
            "timestamp"    : _now(),
            "scenario_name": scenario_name,
            "event_type"   : event_type,
            "description"  : description,
            "status"       : status,
        }
        _append_csv(SCENARIO_CSV_PATH, SCENARIO_CSV_HEADERS, row)
        logger.info("[SCENARIO] %s | %s | %s", scenario_name, event_type, description)
    except Exception:
        logger.error("[log_scenario_event] %s", traceback.format_exc())


# ─── Profile JSON Snapshot ────────────────────────────────────────────────────

def log_session_profile(scenario_name: str, normal_profile: dict,
                        attack_profile: dict = None) -> None:
    """
    Append a session profile snapshot to traffic_profiles.json.

    Stores the exact profiles used in each experiment session so results
    can be reproduced precisely.

    [HOOK] Phase 5 → HDBSCAN profiler reads these to label traffic clusters.
    """
    try:
        with open(PROFILES_JSON_PATH, "r") as f:
            data = json.load(f)

        session = {
            "timestamp"      : _now(),
            "scenario"       : scenario_name,
            "normal_profile" : normal_profile,
            "attack_profile" : attack_profile or {},
        }
        data.setdefault("sessions", []).append(session)

        with open(PROFILES_JSON_PATH, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        logger.error("[log_session_profile] %s", traceback.format_exc())


# ─── Console Printing ─────────────────────────────────────────────────────────

def _print_traffic_event(row: dict) -> None:
    b = "=" * 54
    print(f"\n{b}")
    print(f"  [TRAFFIC GENERATOR]")
    print(f"  Traffic Type : {row['traffic_type']}")
    print(f"  Source       : {row['source_host']}")
    print(f"  Destination  : {row['destination_host']}")
    print(f"  Protocol     : {row['protocol']}")
    print(f"  Bandwidth    : {row['bandwidth']}")
    print(f"  Duration     : {row['duration']} sec")
    print(f"  Status       : {row['status']}")
    print(f"{b}\n")


def _print_attack_event(row: dict) -> None:
    b = "!" * 54
    print(f"\n{b}")
    print(f"  [ATTACK SIMULATION]")
    print(f"  Attack Type  : {row['attack_type']}")
    print(f"  Source Host  : {row['source_host']}")
    print(f"  Target Host  : {row['target_host']}")
    print(f"  Packet Rate  : {row['attack_rate']} pkt/s")
    print(f"  Duration     : {row['duration']} sec")
    print(f"  Status       : {row['status']}")
    print(f"{b}\n")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _append_csv(filepath: str, headers: list, row: dict) -> None:
    with open(filepath, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writerow({h: row.get(h, "") for h in headers})
