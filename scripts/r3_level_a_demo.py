#!/usr/bin/env python3
"""
IntelliShield SDN — R3 Level A Digital Twin demo

Runs: completed experiment logs → snapshot → S1–S5 replay → what-if → fidelity DoD.

Usage:
    export PYTHONPATH="$PWD"
    python3 scripts/r3_level_a_demo.py \\
      --logs-dir logs/live_vm_20260728T170330Z/logs/live_runs/slim_20260728T170330Z \\
      --scenario S2 \\
      --whatif attack_sec=25

Exit codes:
    0  PASS
    2  logs missing / incomplete
    3  replay or fidelity FAIL
    4  safety flag violated
"""

from __future__ import annotations

import argparse
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from twin.demo_level_a import (  # noqa: E402
    EXIT_LOGS_MISSING,
    parse_whatif_overrides,
    run_level_a_demo,
)
from twin.validate import TwinValidationError  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="R3 Level A observational Digital Twin demo (read-only vs live SDN)"
    )
    parser.add_argument(
        "--logs-dir",
        required=True,
        help="Completed experiment log directory (must contain scenario_logs.csv)",
    )
    parser.add_argument("--scenario", default="S2", help="Scenario id (default S2)")
    parser.add_argument("--seed", type=int, default=42, help="Twin plan seed")
    parser.add_argument(
        "--whatif",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="What-if override (repeatable), e.g. --whatif attack_sec=25",
    )
    parser.add_argument(
        "--root",
        default=None,
        help="Project root for twin artifact writes (default: repository root)",
    )
    parser.add_argument(
        "--json-out",
        default=None,
        help="Optional path to write machine-readable demo result JSON",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Print only the final OK/FAIL line",
    )
    args = parser.parse_args(argv)

    try:
        overrides = parse_whatif_overrides(args.whatif)
    except TwinValidationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return EXIT_LOGS_MISSING

    result = run_level_a_demo(
        args.logs_dir,
        scenario_id=args.scenario,
        seed=args.seed,
        whatif=overrides,
        root=args.root or _ROOT,
        persist=True,
    )

    if not args.quiet:
        for line in result.lines:
            print(line)
    else:
        print(result.message if result.exit_code == 0 else f"FAIL: {result.message}")

    if args.json_out:
        out_path = args.json_out
        parent = os.path.dirname(os.path.abspath(out_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(result.to_dict(), fh, indent=2, sort_keys=True)
            fh.write("\n")

    return int(result.exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
