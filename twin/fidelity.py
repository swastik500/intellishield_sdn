"""Twin fidelity dimensions and report generation (R3.5).

Not a single vague accuracy number. Dimensions may be PASS / FAIL / NOT_AVAILABLE.
Offline mode evaluates plan/config fidelity; live observations fill when present.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from shared_contracts.timeutil import format_ts, utc_now
from twin.isolation import project_root
from twin.planner import plan_scenario
from twin.profile import build_default_twin_profile
from twin.scenario_spec import ScenarioPlan
from twin.topology import build_default_topology

PathLike = Union[str, Path]

FIDELITY_DIMENSIONS = (
    "TOPOLOGY_FIDELITY",
    "TRAFFIC_FIDELITY",
    "TEMPORAL_FIDELITY",
    "SECURITY_RESPONSE_FIDELITY",
    "CONFIGURATION_FIDELITY",
)

VALID_FIDELITY_STATUSES = frozenset({"PASS", "FAIL", "NOT_AVAILABLE"})

TRAFFIC_NA_HINT = (
    "no usable attack traffic rates observed; provide flow_stats.csv "
    "(attack_mean_pkt_s) or traffic_logs.csv flood rows; plan parameters recorded only"
)


@dataclass
class FidelityCheck:
    dimension: str
    expected: Any
    observed: Any
    error: Optional[float]
    tolerance: Optional[float]
    status: str  # PASS | FAIL | NOT_AVAILABLE
    notes: str = ""

    def __post_init__(self) -> None:
        if self.status not in VALID_FIDELITY_STATUSES:
            raise ValueError(
                f"invalid fidelity status {self.status!r}; "
                f"expected one of {sorted(VALID_FIDELITY_STATUSES)}"
            )
        if not str(self.notes or "").strip():
            self.notes = f"{self.dimension}: no additional reason recorded"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dimension": self.dimension,
            "expected": self.expected,
            "observed": self.observed,
            "error": self.error,
            "tolerance": self.tolerance,
            "status": self.status,
            "notes": self.notes,
            "reason": self.notes,
        }


def overall_verdict(summary: Mapping[str, Any]) -> str:
    """Roll up dimension counts into a single Level A verdict."""
    fail = int(summary.get("FAIL") or 0)
    passed = int(summary.get("PASS") or 0)
    na = int(summary.get("NOT_AVAILABLE") or 0)
    if fail > 0:
        return "FAIL"
    if passed == 0 and na > 0:
        return "NOT_AVAILABLE"
    if na > 0:
        return "PASS_WITH_GAPS"
    if passed > 0:
        return "PASS"
    return "NOT_AVAILABLE"


def compact_fidelity_summary(report: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    """API-friendly fidelity summary for snapshot list rows."""
    if not report:
        return None
    summary = dict(report.get("summary") or {})
    return {
        "summary": {
            "PASS": int(summary.get("PASS") or 0),
            "FAIL": int(summary.get("FAIL") or 0),
            "NOT_AVAILABLE": int(summary.get("NOT_AVAILABLE") or 0),
        },
        "overall": overall_verdict(summary),
        "scenario_id": report.get("scenario_id"),
        "mode": report.get("mode"),
        "created_at": report.get("created_at"),
    }


def observed_from_snapshot(
    snapshot: Mapping[str, Any],
    *,
    replay: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Derive fidelity ``observed`` fields from a twin snapshot (+ optional replay).

    Prefer flow_stats attack means; fall back to attack-like traffic_logs rates.
    Never invent rates from baseline ICMP-only rows.
    """
    bva = dict(snapshot.get("baseline_vs_attack") or {})
    observed: Dict[str, Any] = {}

    rate = bva.get("attack_mean_pkt_s")
    if rate is None:
        rate = bva.get("attack_like_traffic_mean_pkt_s")
    if rate is not None:
        try:
            observed["syn_rate"] = float(rate)
        except (TypeError, ValueError):
            pass

    bw = bva.get("attack_like_traffic_bandwidth")
    if bw:
        observed["udp_bandwidth"] = str(bw)

    if replay is not None:
        if replay.get("observed_attack_duration_sec") is not None:
            observed["attack_duration_sec"] = replay.get("observed_attack_duration_sec")
    else:
        windows = list(snapshot.get("windows") or [])
        if windows:
            try:
                observed["attack_duration_sec"] = float(windows[0].get("duration_sec"))
            except (TypeError, ValueError):
                pass

    topo = snapshot.get("topology")
    if isinstance(topo, Mapping):
        observed["topology"] = dict(topo)

    # Surface availability hints for traffic dimension notes (non-scoring).
    observed["_traffic_sources"] = {
        "flow_stats_attack_mean_pkt_s": bva.get("attack_mean_pkt_s"),
        "traffic_logs_attack_like_mean_pkt_s": bva.get("attack_like_traffic_mean_pkt_s"),
        "n_flow_attack_rows": bva.get("n_attack_rows"),
        "n_traffic_log_attack_like_rows": bva.get("n_attack_like_traffic_rows"),
    }
    return observed


def _rel_error(expected: float, observed: float) -> float:
    if expected == 0:
        return 0.0 if observed == 0 else 1.0
    return abs(observed - expected) / abs(expected)


def evaluate_topology_fidelity(
    *,
    profile_topology_hosts: int,
    profile_topology_switches: int,
    profile_topology_links: int,
    observed: Optional[Mapping[str, Any]] = None,
    tolerance: float = 0.0,
) -> FidelityCheck:
    expected = {
        "host_count": profile_topology_hosts,
        "switch_count": profile_topology_switches,
        "link_count": profile_topology_links,
    }
    if observed is None:
        # Config self-consistency vs default IntelliShieldTopo model
        default = build_default_topology(n_hosts=profile_topology_hosts)
        observed = {
            "host_count": default.host_count,
            "switch_count": default.switch_count,
            "link_count": len(default.links),
        }
        notes = "offline: compared TwinProfile topology to IntelliShieldTopo model"
    else:
        notes = "live/observed topology counts"
    err = 0.0
    for k in expected:
        err = max(err, _rel_error(float(expected[k]), float(observed.get(k, -1))))
    status = "PASS" if err <= tolerance else "FAIL"
    return FidelityCheck(
        "TOPOLOGY_FIDELITY", expected, dict(observed), err, tolerance, status, notes
    )


def evaluate_traffic_fidelity(
    plan: ScenarioPlan,
    *,
    observed_rate: Optional[float] = None,
    observed_bandwidth: Optional[str] = None,
    tolerance: float = 0.25,
) -> FidelityCheck:
    expected: Dict[str, Any] = {
        "syn_rate": plan.syn_rate,
        "udp_bandwidth": plan.udp_bandwidth or None,
        "burst_rate": plan.burst_rate,
    }
    if observed_rate is None and observed_bandwidth is None:
        return FidelityCheck(
            "TRAFFIC_FIDELITY",
            expected,
            None,
            None,
            tolerance,
            "NOT_AVAILABLE",
            TRAFFIC_NA_HINT,
        )
    observed = {"rate": observed_rate, "bandwidth": observed_bandwidth}
    err = None
    notes = "live rate compare"
    if observed_rate is not None and plan.syn_rate:
        err = _rel_error(float(plan.syn_rate), float(observed_rate))
        notes = "live rate compare vs plan.syn_rate (flow_stats or traffic_logs)"
    elif observed_bandwidth is not None and plan.udp_bandwidth:
        # Bandwidth strings (e.g. "10M") — presence-only check for Level A.
        err = 0.0 if str(observed_bandwidth) == str(plan.udp_bandwidth) else 0.5
        notes = "live bandwidth compare vs plan.udp_bandwidth"
    status = "PASS" if err is not None and err <= tolerance else (
        "FAIL" if err is not None else "NOT_AVAILABLE"
    )
    if status == "NOT_AVAILABLE":
        notes = (
            "traffic observations present but not comparable to plan "
            f"(syn_rate={plan.syn_rate!r}, udp_bandwidth={plan.udp_bandwidth!r})"
        )
    return FidelityCheck(
        "TRAFFIC_FIDELITY", expected, observed, err, tolerance, status, notes
    )


def evaluate_temporal_fidelity(
    plan: ScenarioPlan,
    *,
    observed_attack_duration_sec: Optional[float] = None,
    observed_baseline_sec: Optional[float] = None,
    tolerance: float = 0.20,
) -> FidelityCheck:
    expected_attack = (
        plan.burst_sec
        if plan.scenario_id == "S4"
        else plan.attack_sec
        if plan.scenario_id in ("S2", "S3")
        else (plan.attack1_sec + plan.attack2_sec)
        if plan.scenario_id == "S5"
        else 0
    )
    expected = {
        "baseline_sec": plan.baseline_sec,
        "attack_duration_sec": expected_attack,
        "duration_sec": plan.duration_sec,
        "timeline_events": [e["event"] for e in plan.expected_timeline()],
    }
    if observed_attack_duration_sec is None and observed_baseline_sec is None:
        # Offline: timeline self-consistency (events ordered, duration >= attack)
        timeline = plan.expected_timeline()
        ok = bool(timeline) and timeline[0]["event"] == "START"
        if plan.expected_attack:
            ok = ok and any(e["event"] in ("ATTACK_START", "ATTACK1_START") for e in timeline)
            ok = ok and any(e["event"] in ("ATTACK_STOP", "ATTACK2_STOP", "END") for e in timeline)
        return FidelityCheck(
            "TEMPORAL_FIDELITY",
            expected,
            {"timeline_consistent": ok},
            0.0 if ok else 1.0,
            tolerance,
            "PASS" if ok else "FAIL",
            "offline: expected timeline internal consistency (not live packet timing)",
        )
    observed = {
        "attack_duration_sec": observed_attack_duration_sec,
        "baseline_sec": observed_baseline_sec,
    }
    err = 0.0
    if observed_attack_duration_sec is not None and expected_attack:
        err = max(err, _rel_error(float(expected_attack), float(observed_attack_duration_sec)))
    if observed_baseline_sec is not None and plan.baseline_sec:
        err = max(err, _rel_error(float(plan.baseline_sec), float(observed_baseline_sec)))
    return FidelityCheck(
        "TEMPORAL_FIDELITY",
        expected,
        observed,
        err,
        tolerance,
        "PASS" if err <= tolerance else "FAIL",
        "live temporal compare",
    )


def evaluate_security_response_fidelity(
    *,
    exercises_detection_stack: bool = True,
    live_r4_r6_r7_r5_r8_seen: Optional[bool] = None,
) -> FidelityCheck:
    expected = {
        "pipeline": ["entropy", "ML", "R4", "R6", "R7", "R5", "R8", "mitigation"],
        "twin_orchestrates_existing_stack": True,
    }
    if live_r4_r6_r7_r5_r8_seen is None:
        return FidelityCheck(
            "SECURITY_RESPONSE_FIDELITY",
            expected,
            {"configured": exercises_detection_stack, "live_observed": False},
            None,
            None,
            "NOT_AVAILABLE",
            "live Mininet not run; twin reuses existing IntelliShield stack by design",
        )
    status = "PASS" if live_r4_r6_r7_r5_r8_seen else "FAIL"
    return FidelityCheck(
        "SECURITY_RESPONSE_FIDELITY",
        expected,
        {"live_observed": live_r4_r6_r7_r5_r8_seen},
        0.0 if live_r4_r6_r7_r5_r8_seen else 1.0,
        0.0,
        status,
        "live pipeline evidence",
    )


def evaluate_configuration_fidelity(
    *,
    profile_fingerprint: str,
    seed: int,
    scenario_id: str,
    candidate_isolated: bool,
    model_artifact_uris: Optional[Mapping[str, str]] = None,
) -> FidelityCheck:
    expected = {
        "profile_fingerprint_nonempty": True,
        "seed_nonnegative": True,
        "scenario_id": scenario_id,
        "candidate_isolated": True,
    }
    observed = {
        "profile_fingerprint": profile_fingerprint,
        "seed": seed,
        "scenario_id": scenario_id,
        "candidate_isolated": candidate_isolated,
        "model_artifact_uris": dict(model_artifact_uris or {}),
    }
    ok = (
        bool(profile_fingerprint)
        and seed >= 0
        and bool(scenario_id)
        and candidate_isolated
    )
    return FidelityCheck(
        "CONFIGURATION_FIDELITY",
        expected,
        observed,
        0.0 if ok else 1.0,
        0.0,
        "PASS" if ok else "FAIL",
        "traceable profile fingerprint / seed / isolation",
    )


def build_fidelity_report(
    *,
    plan: Optional[ScenarioPlan] = None,
    profile_fingerprint: str = "",
    seed: int = 42,
    candidate_isolated: bool = True,
    observed: Optional[Mapping[str, Any]] = None,
    live_pipeline_seen: Optional[bool] = None,
    mode: str = "offline",
) -> Dict[str, Any]:
    """Assemble multi-dimension fidelity report (JSON-safe)."""
    observed = observed or {}
    if plan is None:
        plan = plan_scenario("S2", seed=seed)
    profile = build_default_twin_profile(random_seed=seed)
    # Drop internal hint keys from observed before scoring traffic/temporal.
    score_observed = {
        k: v for k, v in dict(observed).items() if not str(k).startswith("_")
    }
    checks = [
        evaluate_topology_fidelity(
            profile_topology_hosts=profile.topology.host_count,
            profile_topology_switches=profile.topology.switch_count,
            profile_topology_links=len(profile.topology.links),
            observed=score_observed.get("topology"),
        ),
        evaluate_traffic_fidelity(
            plan,
            observed_rate=score_observed.get("syn_rate"),
            observed_bandwidth=score_observed.get("udp_bandwidth"),
        ),
        evaluate_temporal_fidelity(
            plan,
            observed_attack_duration_sec=score_observed.get("attack_duration_sec"),
            observed_baseline_sec=score_observed.get("baseline_sec"),
        ),
        evaluate_security_response_fidelity(live_r4_r6_r7_r5_r8_seen=live_pipeline_seen),
        evaluate_configuration_fidelity(
            profile_fingerprint=profile_fingerprint or profile.config_fingerprint,
            seed=seed,
            scenario_id=plan.scenario_id,
            candidate_isolated=candidate_isolated,
            model_artifact_uris=profile.detector.model_artifact_uris,
        ),
    ]
    for check in checks:
        if check.status not in VALID_FIDELITY_STATUSES:
            raise RuntimeError(f"fidelity dimension emitted invalid status: {check}")
    statuses = [c.status for c in checks]
    summary = {
        "PASS": statuses.count("PASS"),
        "FAIL": statuses.count("FAIL"),
        "NOT_AVAILABLE": statuses.count("NOT_AVAILABLE"),
    }
    return {
        "schema": "intellishield.twin.fidelity_report.v1",
        "created_at": format_ts(utc_now()),
        "mode": mode,
        "live_mininet": mode == "live_mininet",
        "scenario_id": plan.scenario_id,
        "seed": seed,
        "profile_fingerprint": profile_fingerprint or profile.config_fingerprint,
        "dimensions": [c.to_dict() for c in checks],
        "summary": summary,
        "overall": overall_verdict(summary),
        "notes": (
            "Offline report evaluates plan/config fidelity. "
            "NOT_AVAILABLE dimensions require live observations. "
            "Does not claim bit-for-bit network timing determinism. "
            "LIVE_MININET_NOT_RUN: twin never launches Mininet; use completed logs."
        ),
    }


def write_fidelity_report(
    report: Mapping[str, Any],
    *,
    path: Optional[PathLike] = None,
    root: Optional[PathLike] = None,
) -> Path:
    base = Path(root) if root else project_root()
    out = Path(path) if path else base / "logs" / "twin_fidelity_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(dict(report), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out
