"""Twin model validation (topology, traffic, profile, scenario refs)."""

from __future__ import annotations

from typing import Iterable, Optional, Sequence, Set

from shared_contracts.models import (
    TwinDetectorConfig,
    TwinProfile,
    TwinTopology,
    TwinTrafficConfig,
)

# Supported baseline scenario ids (behavior unchanged; R3.1 mapping only).
SUPPORTED_SCENARIO_IDS: Set[str] = {"S1", "S2", "S3", "S4", "S5"}


class TwinValidationError(ValueError):
    """Raised when a twin model fails structural / semantic validation."""


def _node_ids(topology: TwinTopology) -> Set[str]:
    ids = {h.host_id for h in topology.hosts}
    ids.update(s.switch_id for s in topology.switches)
    return ids


def validate_topology(topology: TwinTopology) -> None:
    """
    Validate topology structure.

    Raises TwinValidationError on duplicate IDs, self-links, or unknown endpoints.
    """
    if not isinstance(topology, TwinTopology):
        raise TwinValidationError("topology must be a TwinTopology")
    if not topology.topology_id or not str(topology.topology_id).strip():
        raise TwinValidationError("topology_id must be non-empty")

    host_ids = [h.host_id for h in topology.hosts]
    if len(host_ids) != len(set(host_ids)):
        raise TwinValidationError(f"duplicate host IDs: {host_ids}")

    switch_ids = [s.switch_id for s in topology.switches]
    if len(switch_ids) != len(set(switch_ids)):
        raise TwinValidationError(f"duplicate switch IDs: {switch_ids}")

    if topology.controller_port <= 0 or topology.controller_port > 65535:
        raise TwinValidationError(
            f"invalid controller_port: {topology.controller_port}"
        )

    known = _node_ids(topology)
    for link in topology.links:
        if link.src == link.dst:
            raise TwinValidationError(
                f"invalid self-link: {link.src} -> {link.dst}"
            )
        if link.src not in known:
            raise TwinValidationError(
                f"invalid link: unknown endpoint {link.src!r}"
            )
        if link.dst not in known:
            raise TwinValidationError(
                f"invalid link: unknown endpoint {link.dst!r}"
            )


def validate_traffic_config(traffic: TwinTrafficConfig) -> None:
    """Validate traffic defaults (rates, durations, counts)."""
    if traffic.ping_count < 0:
        raise TwinValidationError(f"invalid ping_count: {traffic.ping_count}")
    if traffic.ping_interval < 0:
        raise TwinValidationError(
            f"invalid ping_interval: {traffic.ping_interval}"
        )
    if traffic.iperf_duration < 0:
        raise TwinValidationError(
            f"invalid iperf_duration: {traffic.iperf_duration}"
        )
    if traffic.tcp_connections < 0:
        raise TwinValidationError(
            f"invalid tcp_connections: {traffic.tcp_connections}"
        )
    if not isinstance(traffic.udp_bandwidth, str) or not traffic.udp_bandwidth.strip():
        raise TwinValidationError("udp_bandwidth must be a non-empty string")


def validate_detector_config(detector: TwinDetectorConfig) -> None:
    """Validate detector settings that the twin can honestly model."""
    if detector.monitor_interval_sec <= 0:
        raise TwinValidationError(
            f"invalid monitor_interval_sec: {detector.monitor_interval_sec}"
        )
    if detector.warmup_cycles < 0:
        raise TwinValidationError(
            f"invalid warmup_cycles: {detector.warmup_cycles}"
        )
    if detector.attack_confirm_cycles < 0:
        raise TwinValidationError(
            f"invalid attack_confirm_cycles: {detector.attack_confirm_cycles}"
        )


def normalize_scenario_id(scenario_id: str | int) -> str:
    """Normalize S1 / 1 / s1 → S1."""
    key = str(scenario_id).strip().upper()
    if key.isdigit():
        key = f"S{key}"
    return key


def validate_scenario_id(
    scenario_id: str | int,
    *,
    supported: Optional[Iterable[str]] = None,
) -> str:
    """Return normalized id or raise TwinValidationError if unsupported."""
    key = normalize_scenario_id(scenario_id)
    allowed = set(supported) if supported is not None else SUPPORTED_SCENARIO_IDS
    if key not in allowed:
        raise TwinValidationError(
            f"unsupported scenario reference {scenario_id!r}; "
            f"supported: {sorted(allowed)}"
        )
    return key


def validate_seed(seed: int) -> None:
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise TwinValidationError(f"invalid seed type: {type(seed)!r}")
    if seed < 0:
        raise TwinValidationError(f"invalid seed (must be >= 0): {seed}")


def validate_profile_version(version: str) -> None:
    if not isinstance(version, str) or not version.strip():
        raise TwinValidationError("profile version must be a non-empty string")


def validate_twin_profile(
    profile: TwinProfile,
    *,
    scenario_ids: Optional[Sequence[str]] = None,
) -> None:
    """
    Full TwinProfile validation.

    Does not mutate the profile. Safe to call before fingerprinting.
    """
    if not isinstance(profile, TwinProfile):
        raise TwinValidationError("profile must be a TwinProfile")
    validate_profile_version(profile.version)
    validate_seed(profile.random_seed)
    validate_topology(profile.topology)
    validate_traffic_config(profile.traffic)
    validate_detector_config(profile.detector)

    refs = scenario_ids
    if refs is None:
        meta_scenarios = profile.metadata.get("scenarios")
        if isinstance(meta_scenarios, list):
            refs = [str(x) for x in meta_scenarios]
    if refs:
        for sid in refs:
            validate_scenario_id(sid)
