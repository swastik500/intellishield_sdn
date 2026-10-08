#!/usr/bin/env python3
"""
Create a reproducible IntelliShield experiment artifact bundle.

Usage:
    python3 scripts/bundle_experiment.py
    python3 scripts/bundle_experiment.py --logs-dir logs --bundle-id run_s2_001
    python3 scripts/bundle_experiment.py --with-metrics
"""

import argparse
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from evaluation.experiment_bundle import create_bundle
from scripts.compute_metrics import build_report


def main():
    parser = argparse.ArgumentParser(
        description="Bundle IntelliShield experiment artifacts for reproducibility",
    )
    parser.add_argument(
        "--logs-dir",
        default=os.path.join(_ROOT, "logs"),
        help="Source logs directory (default: logs/)",
    )
    parser.add_argument(
        "--bundle-id",
        default="",
        help="Bundle folder name (default: YYYYMMDD_HHMMSS timestamp)",
    )
    parser.add_argument(
        "--output-root",
        default="",
        help="Parent directory for bundles (default: logs/experiments/)",
    )
    parser.add_argument(
        "--with-metrics",
        action="store_true",
        help="Run compute_metrics.build_report() before bundling",
    )
    parser.add_argument(
        "--no-plots",
        action="store_true",
        help="Skip plot generation",
    )
    args = parser.parse_args()

    logs_dir = os.path.abspath(args.logs_dir)
    if not os.path.isdir(logs_dir):
        print(f"Logs directory not found: {logs_dir}", file=sys.stderr)
        sys.exit(1)

    metrics_report = None
    if args.with_metrics:
        metrics_report = build_report(logs_dir)
        metrics_path = os.path.join(logs_dir, "metrics_report.json")
        with open(metrics_path, "w") as f:
            json.dump(metrics_report, f, indent=2)
        print(f"Metrics report written to {metrics_path}")

    result = create_bundle(
        logs_dir=logs_dir,
        bundle_id=args.bundle_id or None,
        output_root=args.output_root or None,
        metrics_report=metrics_report,
        generate_plots=not args.no_plots,
    )

    print("\n" + "=" * 60)
    print("  IntelliShield — Experiment Bundle Created")
    print("=" * 60)
    print(f"  Bundle ID   : {result['bundle_id']}")
    print(f"  Directory   : {result['bundle_dir']}")
    print(f"  Manifest    : {result['manifest_path']}")
    print(f"  Artifacts   : {len(result['artifacts'])} files")
    print(f"  Plots       : {len(result['plots'])}")
    print(f"  Tree        : {result['tree_path']}")
    print("=" * 60 + "\n")

    if result["artifacts"]:
        print("Artifacts:")
        for name in result["artifacts"]:
            print(f"  - {name}")
    else:
        print("WARNING: No artifacts found — run a scenario first.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
