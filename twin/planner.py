"""Plan and validate parameterized twin scenarios (no Mininet launch)."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from shared_contracts.models import TwinProfile, TwinTopology
from twin.intensity import (
    resolve_burst_rate,
    resolve_syn_rate,
    resolve_udp_bandwidth,
)
from twin.profile import build_default_twin_profile
from twin.scenario_spec import (
    MAX_BURST_COUNT,
    MAX_DURATION_SEC,
    MIN_DURATION_SEC,
    ScenarioPlan,
)
from twin.scenarios import get_baseline_scenario
from twin.safety import assert_safe_twin_target, is_safe_twin_target
from twin.topology import build_default_topology
from twin.validate import TwinValidationError, validate_scenario_id, validate_seed


def _host_ip(topology: TwinTopology, host_id: str) -> str:
    for h in topology.hosts:
        if h.host_id == host_id:
            return h.ip
    raise TwinValidationError(f"unknown twin host: {host_id!r}")


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _require_known_host(topology: TwinTopology, host_id: str, *, role: str) -> str:
    if not host_id or not str(host_id).strip():
        raise TwinValidationError(f"{role} host must be non-empty")
    hid = str(host_id).strip()
    if _looks_like_ip(hid):
        if not is_safe_twin_target(hid):
            raise TwinValidationError(
                f"external {role} address {hid!r} rejected; "
                "twin scenarios may only use lab twin host ids"
            )
        raise TwinValidationError(
            f"{role} must be a twin host id (e.g. h1), not an IP address ({hid!r})"
        )
    known = {h.host_id for h in topology.hosts}
    if hid not in known:
        raise TwinValidationError(
            f"unknown {role} host {hid!r}; known twin hosts: {sorted(known)}"
        )
    ip = _host_ip(topology, hid)
    if ip:
        assert_safe_twin_target(ip)
    return hid


def _check_duration(name: str, value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TwinValidationError(f"invalid {name} type: {type(value)!r}")
    if value < MIN_DURATION_SEC or value > MAX_DURATION_SEC:
        raise TwinValidationError(
            f"invalid {name}={value}; allowed [{MIN_DURATION_SEC}, {MAX_DURATION_SEC}]"
        )
    return value


def _defaults_for(scenario_id: str) -> Dict[str, Any]:
    base = get_baseline_scenario(scenario_id, require=True)
    assert base is not None
    d: Dict[str, Any] = {
        "scenario_version": "1.0.0",
        "label": base.name,
        "scenario_family": base.expected_attack_family or "NORMAL",
        "expected_attack": base.expected_attack,
        "expected_attack_family": base.expected_attack_family,
        "ground_truth_events": list(base.ground_truth_events),
        "source_host": base.source_host or "h1",
        "target_host": base.target_host or "h2",
        "duration_sec": base.duration_sec,
        "baseline_sec": base.baseline_sec,
        "attack_sec": base.attack_sec,
        "recovery_sec": base.recovery_sec,
        "burst_sec": base.attack_sec if scenario_id == "S4" else 0,
        "burst_count": 1,
        "inter_burst_interval_sec": 0,
        "attack1_sec": 20 if scenario_id == "S5" else 0,
        "attack2_sec": 20 if scenario_id == "S5" else 0,
        "gap_sec": 10 if scenario_id == "S5" else 0,
        "syn_rate": base.packet_rate if scenario_id == "S2" else None,
        "udp_bandwidth": "10M" if scenario_id == "S3" else "",
        "burst_rate": base.packet_rate if scenario_id == "S4" else None,
        "rand_source": True if scenario_id == "S2" else False,
        "seed": 42,
    }
    if scenario_id == "S1":
        d["source_host"] = ""
        d["target_host"] = ""
        d["duration_sec"] = 60
    if scenario_id == "S4":
        d["burst_sec"] = 8
        d["baseline_sec"] = 15
        d["recovery_sec"] = 15
    if scenario_id == "S5":
        d["baseline_sec"] = 15
        d["duration_sec"] = 65
    return d


def plan_scenario(
    scenario_id: str | int,
    *,
    overrides: Optional[Mapping[str, Any]] = None,
    profile: Optional[TwinProfile] = None,
    topology: Optional[TwinTopology] = None,
    seed: Optional[int] = None,
) -> ScenarioPlan:
    """
    Build a validated ScenarioPlan from S1–S5 defaults + optional overrides.

    Does not launch traffic. Preserves defaults when overrides omitted.
    """
    sid = validate_scenario_id(scenario_id)
    base = get_baseline_scenario(sid, require=True)
    assert base is not None

    profile = profile or build_default_twin_profile()
    topology = topology or profile.topology or build_default_topology()

    cfg = _defaults_for(sid)
    raw = dict(overrides or {})

    # Normalize aliases → canonical keys
    if "attacker" in raw:
        raw["source_host"] = raw.pop("attacker")
    if "source" in raw:
        raw["source_host"] = raw.pop("source")
    if "target" in raw:
        raw["target_host"] = raw.pop("target")
    if "warmup" in raw:
        raw["baseline_sec"] = raw.pop("warmup")
    if "cooldown" in raw:
        raw["recovery_sec"] = raw.pop("cooldown")
    if "attack_start_offset" in raw:
        raw["baseline_sec"] = raw.pop("attack_start_offset")

    allowed = set(cfg.keys()) | {
        "intensity",
        "syn_rate",
        "udp_bandwidth",
        "burst_rate",
        "source_host",
        "target_host",
        "duration_sec",
        "baseline_sec",
        "attack_sec",
        "recovery_sec",
        "burst_sec",
        "burst_count",
        "inter_burst_interval_sec",
        "attack1_sec",
        "attack2_sec",
        "gap_sec",
        "rand_source",
        "seed",
        "scenario_version",
    }
    for k in raw:
        if k not in allowed:
            raise TwinValidationError(f"unsupported parameter override: {k!r}")
    cfg.update(raw)

    if seed is not None:
        cfg["seed"] = seed
    validate_seed(int(cfg["seed"]))

    # Intensity
    intensity = cfg.pop("intensity", None)
    if sid == "S2":
        cfg["syn_rate"] = resolve_syn_rate(
            intensity if intensity is not None else cfg.get("syn_rate"),
            default=10000,
        )
    elif sid == "S3":
        cfg["udp_bandwidth"] = resolve_udp_bandwidth(
            intensity if intensity is not None else cfg.get("udp_bandwidth") or None,
            default="10M",
        )
    elif sid == "S4":
        cfg["burst_rate"] = resolve_burst_rate(
            intensity if intensity is not None else cfg.get("burst_rate"),
            default=20000,
        )
    elif sid == "S5" and intensity is not None:
        cfg["syn_rate"] = resolve_syn_rate(intensity, default=1000)

    # Temporal validation
    if sid == "S1":
        cfg["duration_sec"] = _check_duration("duration_sec", int(cfg["duration_sec"]))
    else:
        cfg["baseline_sec"] = _check_duration("baseline_sec", int(cfg["baseline_sec"]))
        cfg["recovery_sec"] = _check_duration("recovery_sec", int(cfg["recovery_sec"]))
        if sid in ("S2", "S3"):
            cfg["attack_sec"] = _check_duration("attack_sec", int(cfg["attack_sec"]))
            cfg["duration_sec"] = (
                cfg["baseline_sec"] + cfg["attack_sec"] + cfg["recovery_sec"]
            )
        if sid == "S4":
            cfg["burst_sec"] = _check_duration("burst_sec", int(cfg["burst_sec"]))
            cfg["burst_count"] = int(cfg.get("burst_count", 1))
            if cfg["burst_count"] < 1 or cfg["burst_count"] > MAX_BURST_COUNT:
                raise TwinValidationError(
                    f"invalid burst_count={cfg['burst_count']}; "
                    f"allowed [1, {MAX_BURST_COUNT}]"
                )
            cfg["inter_burst_interval_sec"] = int(
                cfg.get("inter_burst_interval_sec", 0)
            )
            if cfg["inter_burst_interval_sec"] < 0:
                raise TwinValidationError("inter_burst_interval_sec must be >= 0")
            if cfg["inter_burst_interval_sec"] > MAX_DURATION_SEC:
                raise TwinValidationError("inter_burst_interval_sec too large")
            extra = (cfg["burst_count"] - 1) * (
                cfg["burst_sec"] + cfg["inter_burst_interval_sec"]
            )
            cfg["duration_sec"] = (
                cfg["baseline_sec"]
                + cfg["burst_sec"]
                + extra
                + cfg["recovery_sec"]
            )
            cfg["attack_sec"] = cfg["burst_sec"]
        if sid == "S5":
            cfg["attack1_sec"] = _check_duration("attack1_sec", int(cfg["attack1_sec"]))
            cfg["attack2_sec"] = _check_duration("attack2_sec", int(cfg["attack2_sec"]))
            cfg["gap_sec"] = _check_duration("gap_sec", int(cfg["gap_sec"]))
            cfg["duration_sec"] = (
                cfg["baseline_sec"]
                + cfg["attack1_sec"]
                + cfg["gap_sec"]
                + cfg["attack2_sec"]
            )

    source_host = ""
    target_host = ""
    source_ip = ""
    target_ip = ""
    if sid != "S1":
        source_host = _require_known_host(
            topology, str(cfg["source_host"]), role="source"
        )
        target_host = _require_known_host(
            topology, str(cfg["target_host"]), role="target"
        )
        if source_host == target_host:
            raise TwinValidationError("source and target hosts must differ")
        source_ip = _host_ip(topology, source_host)
        target_ip = _host_ip(topology, target_host)

    run_kwargs = _build_run_kwargs(sid, cfg, source_host, target_host)

    params = {
        "scenario_id": sid,
        "seed": int(cfg["seed"]),
        "source_host": source_host,
        "target_host": target_host,
        "duration_sec": int(cfg["duration_sec"]),
        "baseline_sec": int(cfg.get("baseline_sec", 0)),
        "attack_sec": int(cfg.get("attack_sec", 0)),
        "recovery_sec": int(cfg.get("recovery_sec", 0)),
        "burst_sec": int(cfg.get("burst_sec", 0)),
        "burst_count": int(cfg.get("burst_count", 1)),
        "inter_burst_interval_sec": int(cfg.get("inter_burst_interval_sec", 0)),
        "attack1_sec": int(cfg.get("attack1_sec", 0)),
        "attack2_sec": int(cfg.get("attack2_sec", 0)),
        "gap_sec": int(cfg.get("gap_sec", 0)),
        "syn_rate": cfg.get("syn_rate"),
        "udp_bandwidth": cfg.get("udp_bandwidth") or "",
        "burst_rate": cfg.get("burst_rate"),
        "rand_source": bool(cfg.get("rand_source", False)),
    }

    return ScenarioPlan(
        scenario_id=sid,
        scenario_version=str(cfg["scenario_version"]),
        scenario_family=str(cfg["scenario_family"]),
        label=str(cfg["label"]),
        seed=int(cfg["seed"]),
        source_host=source_host,
        target_host=target_host,
        source_ip=source_ip,
        target_ip=target_ip,
        expected_attack=bool(cfg["expected_attack"]),
        expected_attack_family=str(cfg["expected_attack_family"]),
        ground_truth_events=list(cfg["ground_truth_events"]),
        duration_sec=int(cfg["duration_sec"]),
        baseline_sec=int(cfg.get("baseline_sec", 0)),
        attack_sec=int(cfg.get("attack_sec", 0)),
        recovery_sec=int(cfg.get("recovery_sec", 0)),
        attack1_sec=int(cfg.get("attack1_sec", 0)),
        attack2_sec=int(cfg.get("attack2_sec", 0)),
        gap_sec=int(cfg.get("gap_sec", 0)),
        burst_sec=int(cfg.get("burst_sec", 0)),
        burst_count=int(cfg.get("burst_count", 1)),
        inter_burst_interval_sec=int(cfg.get("inter_burst_interval_sec", 0)),
        syn_rate=cfg.get("syn_rate"),
        udp_bandwidth=str(cfg.get("udp_bandwidth") or ""),
        burst_rate=cfg.get("burst_rate"),
        rand_source=bool(cfg.get("rand_source", False)),
        parameters=params,
        run_kwargs=run_kwargs,
        profile_id=profile.profile_id,
        profile_fingerprint=profile.config_fingerprint,
        notes="R3.2 plan — orchestration only; TrafficScheduler unchanged",
    )


def _build_run_kwargs(
    sid: str,
    cfg: Dict[str, Any],
    source_host: str,
    target_host: str,
) -> Dict[str, Any]:
    """Kwargs accepted by attack_scenarios functions (additive optional params)."""
    if sid == "S1":
        return {"duration": int(cfg["duration_sec"])}
    if sid == "S2":
        return {
            "baseline_sec": int(cfg["baseline_sec"]),
            "attack_sec": int(cfg["attack_sec"]),
            "recovery_sec": int(cfg["recovery_sec"]),
            "attacker": source_host,
            "target": target_host,
            "syn_rate": int(cfg["syn_rate"]),
            "rand_source": bool(cfg.get("rand_source", True)),
        }
    if sid == "S3":
        return {
            "baseline_sec": int(cfg["baseline_sec"]),
            "attack_sec": int(cfg["attack_sec"]),
            "recovery_sec": int(cfg["recovery_sec"]),
            "attacker": source_host,
            "target": target_host,
            "bandwidth": str(cfg["udp_bandwidth"]),
        }
    if sid == "S4":
        return {
            "baseline_sec": int(cfg["baseline_sec"]),
            "burst_sec": int(cfg["burst_sec"]),
            "recovery_sec": int(cfg["recovery_sec"]),
            "attacker": source_host,
            "target": target_host,
            "burst_rate": int(cfg["burst_rate"]) if cfg.get("burst_rate") else None,
            "burst_count": int(cfg.get("burst_count", 1)),
            "inter_burst_interval_sec": int(cfg.get("inter_burst_interval_sec", 0)),
        }
    if sid == "S5":
        kwargs = {
            "baseline_sec": int(cfg["baseline_sec"]),
            "attack1_sec": int(cfg["attack1_sec"]),
            "gap_sec": int(cfg["gap_sec"]),
            "attack2_sec": int(cfg["attack2_sec"]),
            "attacker": source_host,
            "target": target_host,
        }
        # Omit intensity kwargs when unset so live defaults match legacy S5
        if cfg.get("syn_rate") is not None:
            kwargs["syn_rate"] = int(cfg["syn_rate"])
        if cfg.get("udp_bandwidth"):
            kwargs["bandwidth"] = str(cfg["udp_bandwidth"])
        return kwargs
    raise TwinValidationError(f"unsupported scenario for run_kwargs: {sid}")


def default_plan(scenario_id: str | int, *, seed: int = 42) -> ScenarioPlan:
    """S1–S5 default plan (compatibility baseline)."""
    return plan_scenario(scenario_id, seed=seed)
