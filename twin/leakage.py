"""Dataset leakage detection for twin training exports (R3.5)."""

from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Union

from twin.validate import TwinValidationError

PathLike = Union[str, Path]

PROHIBITED_SPLIT_PAIRS = (
    ("TRAINING", "VALIDATION"),
    ("TRAINING", "TEST"),
    ("VALIDATION", "TEST"),
)


@dataclass
class LeakageFinding:
    code: str
    detail: str

    def to_dict(self) -> Dict[str, str]:
        return {"code": self.code, "detail": self.detail}


@dataclass
class LeakageReport:
    findings: List[LeakageFinding] = field(default_factory=list)
    ok: bool = True
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok and not self.findings,
            "findings": [f.to_dict() for f in self.findings],
            "limitations": list(self.limitations),
        }


def sample_key(row: Dict[str, str]) -> str:
    return "|".join(
        [
            row.get("run_id", ""),
            row.get("scenario_id", ""),
            row.get("timestamp", ""),
            row.get("switch_id", ""),
        ]
    )


def detect_dataset_leakage(samples_csv: PathLike) -> LeakageReport:
    """
    Detect prohibited train/val/test provenance overlaps.

    Checks:
      - same run_id appearing in TRAINING and VALIDATION/TEST
      - same sample key across different splits
      - same (scenario_id, seed) if seed column present across TRAIN vs TEST
        (seed may be only in manifest — limitation documented)
    """
    path = Path(samples_csv)
    if not path.is_file():
        raise TwinValidationError(f"samples CSV not found: {path}")

    report = LeakageReport(
        limitations=[
            "Seed is stored in dataset manifest, not per-row; "
            "scenario+seed cross-split checks require manifest join.",
            "Multi-run generate_from_runs may intentionally duplicate feature "
            "rows with different run_id provenance — those are not leakage.",
        ]
    )

    runs_by_split: Dict[str, Set[str]] = defaultdict(set)
    keys_by_split: Dict[str, Set[str]] = defaultdict(set)
    scenario_by_split: Dict[str, Set[str]] = defaultdict(set)

    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            split = str(row.get("split", "")).upper()
            run_id = str(row.get("run_id", ""))
            scenario_id = str(row.get("scenario_id", ""))
            key = sample_key(row)
            if split:
                runs_by_split[split].add(run_id)
                keys_by_split[split].add(key)
                scenario_by_split[split].add(scenario_id)

    for a, b in PROHIBITED_SPLIT_PAIRS:
        overlap_runs = runs_by_split.get(a, set()) & runs_by_split.get(b, set())
        overlap_runs.discard("")
        for rid in sorted(overlap_runs):
            report.findings.append(
                LeakageFinding(
                    "run_across_splits",
                    f"run_id {rid!r} appears in both {a} and {b}",
                )
            )
        overlap_keys = keys_by_split.get(a, set()) & keys_by_split.get(b, set())
        for key in sorted(list(overlap_keys)[:20]):
            report.findings.append(
                LeakageFinding(
                    "sample_key_across_splits",
                    f"sample key {key!r} appears in both {a} and {b}",
                )
            )

    report.ok = not report.findings
    return report


def assert_no_leakage(samples_csv: PathLike) -> LeakageReport:
    report = detect_dataset_leakage(samples_csv)
    if report.findings:
        raise TwinValidationError(
            "dataset leakage detected: "
            + "; ".join(f.detail for f in report.findings[:5])
        )
    return report
