"""TwinProfile factory for the default IntelliShield lab environment."""

from __future__ import annotations

from dataclasses import replace

from shared_contracts.models import (
    TwinDetectorConfig,
    TwinProfile,
    TwinTrafficConfig,
    TwinValidationPolicy,
)
from twin.fingerprint import fingerprint_profile
from twin.topology import build_default_topology
from twin.validate import TwinValidationError, validate_seed, validate_twin_profile


def build_default_twin_profile(
    *,
    profile_id: str = "intellishield_lab_default",
    version: str = "1.0.0",
    n_hosts: int = 5,
    random_seed: int = 42,
    normal_profile: str = "MEDIUM",
    r6_fusion_enabled: bool = True,
) -> TwinProfile:
    """
    Construct and validate the default security-oriented SDN twin profile.

    Values mirror traffic_profiles / PROJECT_STATE defaults that the lab
    can actually model today. Does not start Mininet.
    """
    validate_seed(random_seed)
    topology = build_default_topology(n_hosts=n_hosts)
    traffic = TwinTrafficConfig(
        normal_profile=normal_profile,
        protocol_mix=["icmp", "tcp"] if normal_profile == "MEDIUM" else ["icmp", "tcp", "udp"],
        ping_count=50 if normal_profile != "LIGHT" else 20,
        ping_interval=0.2 if normal_profile != "LIGHT" else 0.5,
        notes="Derived from traffic_profiles NORMAL_PROFILES defaults",
    )
    detector = TwinDetectorConfig(
        feature_schema="FEATURE_NAMES_v1",
        monitor_interval_sec=5,
        warmup_cycles=3,
        attack_confirm_cycles=2,
        r6_fusion_enabled=r6_fusion_enabled,
        model_artifact_uris={
            "isolation_forest": "logs/models/isolation_forest.pkl",
            "decision_tree": "logs/models/decision_tree.pkl",
            "scaler": "logs/models/scaler.pkl",
        },
        notes="Artifact paths expected; may be absent until ModelTrainer runs",
    )
    profile = TwinProfile(
        profile_id=profile_id,
        version=version,
        topology=topology,
        traffic=traffic,
        detector=detector,
        random_seed=random_seed,
        source_environment="mininet_lab",
        metadata={
            "kind": "security_oriented_sdn_digital_twin",
            "simulator_backend": "mininet",
            "orchestrator": "traffic_generator.TrafficScheduler",
            "scenarios": ["S1", "S2", "S3", "S4", "S5"],
            "not_a_claim": "Not perfect physical/network equivalence",
        },
    )
    validate_twin_profile(profile)
    return replace(profile, config_fingerprint=fingerprint_profile(profile))


def default_validation_policy(
    *,
    policy_id: str = "twin_default_gate_v1",
) -> TwinValidationPolicy:
    """
    Default TwinValidationPolicy for R3.3 candidate gates.

    Hard gates + required S1/S2 evidence. Optional baseline regression
    tolerances are unset by default (enable explicitly when baseline exists).
    """
    return TwinValidationPolicy(
        policy_id=policy_id,
        version="1.0",
        min_precision=0.70,
        min_recall=0.70,
        min_f1=0.70,
        max_fpr=0.20,
        max_detection_latency_sec=30.0,
        max_runtime_latency_sec=5.0,
        max_f1_regression=0.05,
        max_fpr_increase=0.05,
        require_scenario_ids=["S1", "S2"],
        notes=(
            "Hard safety/quality gates; missing required scenarios/metrics → "
            "INSUFFICIENT_EVIDENCE (never PASS). Baseline regression optional."
        ),
    )


def with_seed(profile: TwinProfile, seed: int) -> TwinProfile:
    """Return a copy with updated seed and recomputed fingerprint."""
    validate_seed(seed)
    updated = replace(profile, random_seed=seed, config_fingerprint="")
    validate_twin_profile(updated)
    return replace(updated, config_fingerprint=fingerprint_profile(updated))


def with_version(profile: TwinProfile, version: str) -> TwinProfile:
    """
    Return a new profile version (does not mutate the historical profile).

    Fingerprint changes with version because version is security-relevant
    configuration identity for twin experiments.
    """
    if not isinstance(version, str) or not version.strip():
        raise TwinValidationError("profile version must be a non-empty string")
    updated = replace(profile, version=version.strip(), config_fingerprint="")
    validate_twin_profile(updated)
    return replace(updated, config_fingerprint=fingerprint_profile(updated))
