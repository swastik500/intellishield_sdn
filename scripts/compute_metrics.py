#!/usr/bin/env python3
"""
IntelliShield SDN — Experiment Metrics Reporter

Joins Phase 3 scenario logs with entropy, ML, and mitigation CSVs to produce
IEEE-ready detection/mitigation latency and false-positive statistics.

Usage:
    python3 scripts/compute_metrics.py
    python3 scripts/compute_metrics.py --logs-dir ~/intellishield-sdn/logs
    python3 scripts/compute_metrics.py --json-out logs/metrics_report.json
"""

import os
import sys
import csv
import json
import argparse
from datetime import datetime, timedelta
from typing import List, Optional, Dict

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from evaluation.experiment_windows import (
    load_experiment_windows,
    parse_ts,
    TS_FMT,
)
from evaluation.csv_log_io import KNOWN_CSV_HEADERS, load_csv_rows


def _load_scenario_windows(logs_dir: str) -> List[Dict]:
    """Load attack windows via shared provider (scenario + attack logs)."""
    return [w.to_metrics_dict() for w in load_experiment_windows(logs_dir)]


def _sort_by_ts(rows: List[dict], ts_field: str = "timestamp") -> List[dict]:
    def _key(row: dict):
        ts = parse_ts(row.get(ts_field, ""))
        return ts or datetime.min

    return sorted(rows, key=_key)


def _first_in_window(rows: List[dict], ts_field: str, start: datetime, stop: datetime,
                     predicate, grace_sec: float = 60.0) -> Optional[datetime]:
    """First matching row with start <= ts <= stop + grace (avoids cross-run bleed)."""
    end = stop
    if grace_sec > 0:
        end = stop + timedelta(seconds=grace_sec)

    for row in rows:
        ts = parse_ts(row.get(ts_field, ""))
        if ts is None or ts < start or ts > end:
            continue
        if predicate(row):
            return ts
    return None


def _load_csv(logs_dir: str, name: str) -> List[dict]:
    path = os.path.join(logs_dir, name)
    return load_csv_rows(path, fallback_headers=KNOWN_CSV_HEADERS.get(name))


def analyse_run(window: Dict, logs_dir: str, grace_sec: float = 60.0) -> Dict:
    start = window["attack_start"]
    stop  = window["attack_stop"]

    entropy_rows = _sort_by_ts(_load_csv(logs_dir, "entropy_logs.csv"))
    ml_rows      = _sort_by_ts(_load_csv(logs_dir, "ml_predictions.csv"))
    mit_rows     = _sort_by_ts(_load_csv(logs_dir, "mitigation_actions.csv"))
    alert_rows   = _sort_by_ts(_load_csv(logs_dir, "detection_alerts.csv"))

    ent_alert = _first_in_window(
        entropy_rows, "timestamp", start, stop,
        lambda r: str(r.get("status", "")).upper() in ("ALERT", "WARNING"),
        grace_sec=grace_sec,
    )
    ml_attack = _first_in_window(
        ml_rows, "timestamp", start, stop,
        lambda r: str(r.get("status", "")).upper() == "ATTACK",
        grace_sec=grace_sec,
    )
    ml_susp   = _first_in_window(
        ml_rows, "timestamp", start, stop,
        lambda r: str(r.get("status", "")).upper() == "SUSPICIOUS",
        grace_sec=grace_sec,
    )
    first_block = _first_in_window(
        mit_rows, "timestamp", start, stop,
        lambda r: (
            str(r.get("action", "")).upper() == "BLOCK"
            and str(r.get("status", "")).upper() == "SUCCESS"
        ),
        grace_sec=grace_sec,
    )

    # False positives: blocks outside attack window
    false_blocks = []
    for row in mit_rows:
        if str(row.get("action", "")).upper() != "BLOCK":
            continue
        if str(row.get("status", "")).upper() != "SUCCESS":
            continue
        ts = parse_ts(row.get("timestamp", ""))
        if ts is None:
            continue
        if ts < start or ts > stop:
            false_blocks.append(row)

    def _latency(first_ts: Optional[datetime]) -> Optional[float]:
        if first_ts is None:
            return None
        return round((first_ts - start).total_seconds(), 2)

    return {
        "scenario"              : window["scenario"],
        "attack_start"          : start.strftime(TS_FMT),
        "attack_stop"           : stop.strftime(TS_FMT),
        "attack_duration_sec"   : round((stop - start).total_seconds(), 1),
        "entropy_alert_latency_s" : _latency(ent_alert),
        "ml_attack_latency_s"     : _latency(ml_attack),
        "ml_suspicious_latency_s" : _latency(ml_susp),
        "mitigation_latency_s"    : _latency(first_block),
        "entropy_alerts_in_window": sum(
            1 for r in alert_rows
            if (ts := parse_ts(r.get("timestamp", "")))
            and start <= ts <= stop
        ),
        "ml_attack_cycles"      : sum(
            1 for r in ml_rows
            if (ts := parse_ts(r.get("timestamp", "")))
            and start <= ts <= stop
            and str(r.get("status", "")).upper() == "ATTACK"
        ),
        "blocks_in_window"      : sum(
            1 for r in mit_rows
            if (ts := parse_ts(r.get("timestamp", "")))
            and start <= ts <= stop + timedelta(seconds=grace_sec)
            and str(r.get("action", "")).upper() == "BLOCK"
            and str(r.get("status", "")).upper() == "SUCCESS"
        ),
        "false_positive_blocks" : len(false_blocks),
        "blocked_macs"          : [
            r.get("src_mac", "") for r in mit_rows
            if (ts := parse_ts(r.get("timestamp", "")))
            and start <= ts <= stop
            and str(r.get("action", "")).upper() == "BLOCK"
            and str(r.get("status", "")).upper() == "SUCCESS"
        ],
    }


def _avg(values: List[float]) -> Optional[float]:
    vals = [v for v in values if v is not None]
    if not vals:
        return None
    return round(sum(vals) / len(vals), 2)


def build_report(logs_dir: str, grace_sec: float = 60.0) -> Dict:
    windows = _load_scenario_windows(logs_dir)
    runs = [analyse_run(w, logs_dir, grace_sec=grace_sec) for w in windows]

    summary = {
        "runs_analysed"           : len(runs),
        "avg_entropy_alert_latency_s": _avg([r["entropy_alert_latency_s"] for r in runs]),
        "avg_ml_attack_latency_s"    : _avg([r["ml_attack_latency_s"] for r in runs]),
        "avg_mitigation_latency_s"   : _avg([r["mitigation_latency_s"] for r in runs]),
        "total_false_positive_blocks": sum(r["false_positive_blocks"] for r in runs),
        "total_blocks_in_attacks"    : sum(r["blocks_in_window"] for r in runs),
    }

    base = {"summary": summary, "runs": runs, "generated_at": datetime.now().strftime(TS_FMT)}

    from evaluation.ieee_metrics import enrich_report
    return enrich_report(base, logs_dir, grace_sec, _load_csv)


def print_report(report: Dict) -> None:
    s = report["summary"]
    clf = s.get("classification", {})
    sysm = s.get("system", {})

    def _lat(val):
        return f"{val}s" if val is not None else "N/A"

    print("\n" + "=" * 60)
    print("  IntelliShield SDN — Experiment Metrics Report")
    print("=" * 60)
    print(f"  Runs analysed          : {s['runs_analysed']}")
    print(f"  Avg detection lat.     : {_lat(s.get('avg_detection_latency_s'))}")
    print(f"  Avg entropy alert lat. : {_lat(s['avg_entropy_alert_latency_s'])}")
    print(f"  Avg ML ATTACK lat.     : {_lat(s['avg_ml_attack_latency_s'])}")
    print(f"  Avg mitigation lat.    : {_lat(s['avg_mitigation_latency_s'])}")
    print(f"  Accuracy / F1          : {clf.get('accuracy')} / {clf.get('f1_score')}")
    print(f"  Precision / Recall     : {clf.get('precision')} / {clf.get('recall')}")
    print(f"  FPR / FNR              : {clf.get('false_positive_rate')} / {clf.get('false_negative_rate')}")
    print(f"  Throughput (pkt/s)     : {sysm.get('throughput_mean_pkt_s')} (peak {sysm.get('throughput_peak_pkt_s')})")
    print(f"  Packet loss rate       : {sysm.get('packet_loss_rate')}")
    print(f"  Controller CPU / Mem   : {sysm.get('controller_cpu_mean_pct')}% / {sysm.get('controller_memory_mean_mb')} MB")
    print(f"  Blocks during attacks  : {s['total_blocks_in_attacks']}")
    print(f"  False-positive blocks  : {s['total_false_positive_blocks']}")
    print("-" * 60)
    for i, run in enumerate(report["runs"], 1):
        print(f"\n  Run {i}: {run['scenario']}")
        print(f"    Attack window : {run['attack_start']} → {run['attack_stop']}")
        print(f"    Entropy alert : {run['entropy_alert_latency_s']}s")
        print(f"    ML ATTACK     : {run['ml_attack_latency_s']}s")
        print(f"    Mitigation    : {run['mitigation_latency_s']}s")
        print(f"    Blocks        : {run['blocks_in_window']}  "
              f"(FP outside window: {run['false_positive_blocks']})")
        if run["blocked_macs"]:
            print(f"    Blocked MACs  : {', '.join(run['blocked_macs'])}")
    print("\n" + "=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(description="IntelliShield experiment metrics")
    parser.add_argument(
        "--logs-dir",
        default=os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs"),
    )
    parser.add_argument(
        "--grace-sec",
        type=float,
        default=60.0,
        help="Seconds after attack_stop to still count detections/blocks (default 60)",
    )
    parser.add_argument("--json-out", default="", help="Write JSON report to this path")
    parser.add_argument(
        "--csv-out", default="",
        help="Write CSV report (default: alongside --json-out)",
    )
    parser.add_argument(
        "--paper-out", default="",
        help="Write paper_tables.md (default: alongside --json-out)",
    )
    parser.add_argument(
        "--bundle",
        action="store_true",
        help="Create reproducible experiment bundle after metrics",
    )
    parser.add_argument(
        "--bundle-id",
        default="",
        help="Optional bundle folder name (default: timestamp)",
    )
    args = parser.parse_args()

    logs_dir = os.path.abspath(args.logs_dir)
    if not os.path.isdir(logs_dir):
        print(f"Logs directory not found: {logs_dir}", file=sys.stderr)
        sys.exit(1)

    report = build_report(logs_dir, grace_sec=args.grace_sec)
    print_report(report)

    if args.json_out:
        from evaluation.report_export import export_all
        paths = export_all(
            report,
            json_path=args.json_out,
            csv_path=args.csv_out or None,
            paper_path=args.paper_out or None,
        )
        print(f"JSON report written to {paths['json']}")
        print(f"CSV report written to {paths['csv']}")
        print(f"Paper tables written to {paths['paper_md']}")

    if args.bundle:
        from evaluation.experiment_bundle import create_bundle
        result = create_bundle(
            logs_dir=logs_dir,
            bundle_id=args.bundle_id or None,
            metrics_report=report,
        )
        print(f"Experiment bundle created: {result['bundle_dir']}")
        print(f"  Manifest : {result['manifest_path']}")
        print(f"  Artifacts: {len(result['artifacts'])} files")


if __name__ == "__main__":
    main()
