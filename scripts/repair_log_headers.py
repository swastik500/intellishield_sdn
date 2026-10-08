#!/usr/bin/env python3
"""Repair headerless IntelliShield log CSV files in-place."""

import argparse
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from evaluation.csv_log_io import KNOWN_CSV_HEADERS, csv_has_valid_header, ensure_csv_header


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--logs-dir",
        default=os.path.join(_ROOT, "logs"),
        help="Directory containing log CSV files",
    )
    args = parser.parse_args()

    repaired = []
    for name, headers in sorted(KNOWN_CSV_HEADERS.items()):
        path = os.path.join(args.logs_dir, name)
        if not os.path.exists(path):
            continue
        if csv_has_valid_header(path):
            continue
        ensure_csv_header(path, headers)
        repaired.append(name)

    if repaired:
        print("Repaired header rows for:")
        for name in repaired:
            print(f"  - {name}")
    else:
        print("No headerless CSV files found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
