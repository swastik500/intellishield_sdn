"""
Level A Digital Twin demo runner (R3 snapshot / replay / what-if / fidelity).

Does not launch Mininet, does not call mitigation, does not write OpenFlow.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from twin.pipeline import LIVE_MININET_NOT_RUN_MSG, ingest_experiment
from twin.validate import TwinValidationError

PathLike = Union[str, Path]

EXIT_PASS = 0
EXIT_LOGS_MISSING = 2
EXIT_REPLAY_OR_FIDELITY_FAIL = 3
EXIT_SAFETY_VIOLATION = 4


@dataclass
class LevelADemoResult:
    exit_code: int
    message: str
    ingest: Optional[Dict[str, Any]] = None
    checks: Dict[str, Any] = field(default_factory=dict)
    lines: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "message": self.message,
            "checks": self.checks,
            "snapshot_id": (self.ingest or {}).get("snapshot_id"),
            "overall": (self.ingest or {}).get("overall"),
            "sequence_ok": (self.ingest or {}).get("sequence_ok"),
            "fidelity_summary": (self.ingest or {}).get("fidelity_summary"),
            "package": (self.ingest or {}).get("package"),
            "live_mininet_note": LIVE_MININET_NOT_RUN_MSG,
        }


def parse_whatif_overrides(items: Optional[Sequence[str]]) -> Dict[str, Any]:
    """Parse ``key=value`` pairs (ints/floats when possible)."""
    out: Dict[str, Any] = {}
    if not items:
        return out
    for raw in items:
        if "=" not in raw:
            raise TwinValidationError(f"invalid --whatif {raw!r}; expected key=value")
        key, val = raw.split("=", 1)
        key = key.strip()
        val = val.strip()
        if not key:
            raise TwinValidationError(f"invalid --whatif {raw!r}; empty key")
        try:
            if "." in val:
                out[key] = float(val)
            else:
                out[key] = int(val)
        except ValueError:
            out[key] = val
    return out


def _print_fidelity_table(fidelity: Mapping[str, Any]) -> List[str]:
    lines = [
        "Fidelity dimensions:",
        f"  {'DIMENSION':<28} {'STATUS':<14} REASON",
        f"  {'-' * 28} {'-' * 14} {'-' * 40}",
    ]
    for dim in fidelity.get("dimensions") or []:
        reason = str(dim.get("reason") or dim.get("notes") or "")[:60]
        lines.append(
            f"  {str(dim.get('dimension') or ''):<28} "
            f"{str(dim.get('status') or ''):<14} {reason}"
        )
    summary = fidelity.get("summary") or {}
    lines.append(
        f"  summary PASS={summary.get('PASS', 0)} "
        f"FAIL={summary.get('FAIL', 0)} "
        f"NOT_AVAILABLE={summary.get('NOT_AVAILABLE', 0)} "
        f"overall={fidelity.get('overall')}"
    )
    return lines


def evaluate_level_a_dod(ingest: Mapping[str, Any]) -> Dict[str, Any]:
    """Return structured DoD check results (does not decide exit code alone)."""
    overall = str(ingest.get("overall") or "")
    sequence_ok = bool(ingest.get("sequence_ok"))
    package = dict(ingest.get("package") or {})
    return {
        "mutates_mitigation_false": ingest.get("mutates_mitigation") is False,
        "mutates_controller_false": ingest.get("mutates_controller") is False,
        "launches_mininet_false": ingest.get("launches_mininet") is False,
        "launches_traffic_false": ingest.get("launches_traffic") is False,
        "control_read_only": ingest.get("control") == "READ_ONLY",
        "sequence_ok": sequence_ok,
        "overall_not_fail": overall != "FAIL",
        "package_snapshot": bool(package.get("twin_snapshot.json")),
        "package_observation": bool(package.get("twin_observation.json")),
        "package_fidelity": bool(package.get("fidelity_report.json")),
        "overall": overall,
    }


def run_level_a_demo(
    logs_dir: PathLike,
    *,
    scenario_id: str = "S2",
    seed: int = 42,
    whatif: Optional[Mapping[str, Any]] = None,
    root: Optional[PathLike] = None,
    persist: bool = True,
) -> LevelADemoResult:
    """
    Run Level A path: ingest → replay → what-if → fidelity table → DoD gate.
    """
    lines: List[str] = []
    logs_path = Path(logs_dir)
    lines.append("=== IntelliShield R3 Level A Digital Twin Demo ===")
    lines.append(f"logs_dir={logs_path}")
    lines.append(f"scenario={scenario_id} seed={seed}")
    lines.append(f"whatif={dict(whatif or {})}")
    lines.append(LIVE_MININET_NOT_RUN_MSG)

    if not str(logs_dir).strip() or not logs_path.exists() or not logs_path.is_dir():
        msg = f"logs missing or not a directory: {logs_path}"
        lines.append(f"FAIL: {msg}")
        return LevelADemoResult(
            EXIT_LOGS_MISSING, msg, checks={"logs_present": False}, lines=lines
        )

    scenario_csv = logs_path / "scenario_logs.csv"
    if not scenario_csv.is_file():
        msg = f"incomplete experiment logs (missing scenario_logs.csv): {logs_path}"
        lines.append(f"FAIL: {msg}")
        return LevelADemoResult(
            EXIT_LOGS_MISSING,
            msg,
            checks={"logs_present": True, "scenario_logs": False},
            lines=lines,
        )

    try:
        ingest = ingest_experiment(
            logs_path,
            scenario_id=scenario_id,
            seed=seed,
            overrides=dict(whatif or {}),
            root=root,
            persist=persist,
            validate=False,
        )
    except TwinValidationError as exc:
        msg = str(exc)
        lines.append(f"FAIL: {msg}")
        code = EXIT_LOGS_MISSING if "missing" in msg.lower() else EXIT_REPLAY_OR_FIDELITY_FAIL
        return LevelADemoResult(code, msg, checks={"ingest_error": msg}, lines=lines)
    except Exception as exc:  # noqa: BLE001
        msg = f"ingest failed: {type(exc).__name__}: {exc}"
        lines.append(f"FAIL: {msg}")
        return LevelADemoResult(
            EXIT_REPLAY_OR_FIDELITY_FAIL, msg, checks={"ingest_error": msg}, lines=lines
        )

    lines.append(f"snapshot_id={ingest.get('snapshot_id')}")
    lines.append(f"sequence_ok={ingest.get('sequence_ok')}")
    lines.append(f"temporal_error_sec={ingest.get('temporal_error_sec')}")
    lines.append(f"package={json.dumps(ingest.get('package') or {})}")
    lines.extend(_print_fidelity_table(ingest.get("fidelity") or {}))

    checks = evaluate_level_a_dod(ingest)
    lines.append(f"DoD checks={json.dumps(checks, sort_keys=True)}")

    safety_ok = all(
        [
            checks["mutates_mitigation_false"],
            checks["mutates_controller_false"],
            checks["launches_mininet_false"],
            checks["launches_traffic_false"],
            checks["control_read_only"],
        ]
    )
    if not safety_ok:
        msg = "safety flag violated (mutates_* or launches_* or control)"
        lines.append(f"FAIL: {msg}")
        return LevelADemoResult(
            EXIT_SAFETY_VIOLATION, msg, ingest=ingest, checks=checks, lines=lines
        )

    if not checks["sequence_ok"] or not checks["overall_not_fail"]:
        msg = (
            f"replay/fidelity gate failed "
            f"(sequence_ok={checks['sequence_ok']}, overall={checks['overall']})"
        )
        lines.append(f"FAIL: {msg}")
        return LevelADemoResult(
            EXIT_REPLAY_OR_FIDELITY_FAIL, msg, ingest=ingest, checks=checks, lines=lines
        )

    if not (
        checks["package_snapshot"]
        and checks["package_observation"]
        and checks["package_fidelity"]
    ):
        # Only enforce package when persist=True (ingest already set flags).
        if persist:
            msg = f"incomplete snapshot package: {ingest.get('package')}"
            lines.append(f"FAIL: {msg}")
            return LevelADemoResult(
                EXIT_REPLAY_OR_FIDELITY_FAIL,
                msg,
                ingest=ingest,
                checks=checks,
                lines=lines,
            )

    msg = (
        f"Level A PASS — snapshot={ingest.get('snapshot_id')} "
        f"overall={ingest.get('overall')} sequence_ok={ingest.get('sequence_ok')}"
    )
    lines.append(f"OK: {msg}")
    return LevelADemoResult(EXIT_PASS, msg, ingest=ingest, checks=checks, lines=lines)
