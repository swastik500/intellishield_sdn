"""Baseline TwinScenario catalog derived from S1–S5 (expected-vs-observed ready)."""

from __future__ import annotations

from typing import Dict, List, Optional

from shared_contracts.enums import TwinLabelSource
from shared_contracts.models import TwinScenario


def baseline_scenario_catalog() -> Dict[str, TwinScenario]:
    """
    Map existing scenario identities to TwinScenario with a priori expectations.

    Ground truth events come from scenario control (ATTACK_START/STOP), not ML.
    Parameters remain mostly fixed today; R3.2 will make them first-class overrides.
    """
    scenarios: List[TwinScenario] = [
        TwinScenario(
            scenario_id="S1",
            name="SCENARIO_1_NORMAL_ONLY",
            description="Normal baseline — ICMP-only ring (LIVE uses LIGHT, not template MEDIUM)",
            attack_type=None,
            expected_attack=False,
            expected_attack_family="",
            intensity_profile="LIGHT",
            duration_sec=60,
            baseline_sec=60,
            attack_sec=0,
            recovery_sec=0,
            source_host="",
            target_host="",
            parameters={
                "template": "SCENARIO_1_NORMAL_ONLY",
                "registry_id": 1,
                "live_profile": "PROFILE_NORMAL_LIGHT",
                "template_profile_note": "template says MEDIUM; live function uses LIGHT",
            },
            ground_truth_events=["START", "PHASE", "END"],
            label_source=TwinLabelSource.SCENARIO_CONTROL,
        ),
        TwinScenario(
            scenario_id="S2",
            name="SCENARIO_2_SYN_FLOOD",
            description="SYN flood h1→h2 after baseline",
            attack_type="SYN_FLOOD",
            expected_attack=True,
            expected_attack_family="SYN_FLOOD",
            intensity_profile="SYN_FLOOD_HIGH",
            duration_sec=60,
            baseline_sec=20,
            attack_sec=30,
            recovery_sec=10,
            source_host="h1",
            target_host="h2",
            packet_rate=10000,
            protocol="TCP",
            parameters={
                "template": "SCENARIO_2_SYN_FLOOD",
                "registry_id": 2,
                "rand_source": True,
            },
            ground_truth_events=["START", "ATTACK_START", "ATTACK_STOP", "END"],
            label_source=TwinLabelSource.SCENARIO_CONTROL,
        ),
        TwinScenario(
            scenario_id="S3",
            name="SCENARIO_3_UDP_FLOOD",
            description="UDP flood h1→h2 after baseline",
            attack_type="UDP_FLOOD",
            expected_attack=True,
            expected_attack_family="UDP_FLOOD",
            intensity_profile="UDP_FLOOD",
            duration_sec=60,
            baseline_sec=20,
            attack_sec=30,
            recovery_sec=10,
            source_host="h1",
            target_host="h2",
            protocol="UDP",
            parameters={"template": "SCENARIO_3_UDP_FLOOD", "registry_id": 3},
            ground_truth_events=["START", "ATTACK_START", "ATTACK_STOP", "END"],
            label_source=TwinLabelSource.SCENARIO_CONTROL,
        ),
        TwinScenario(
            scenario_id="S4",
            name="SCENARIO_4_BURST",
            description="Short burst flood h1→h2",
            attack_type="BURST",
            expected_attack=True,
            expected_attack_family="BURST",
            intensity_profile="BURST",
            duration_sec=38,
            baseline_sec=15,
            attack_sec=8,
            recovery_sec=15,
            source_host="h1",
            target_host="h2",
            packet_rate=20000,
            protocol="TCP",
            parameters={"template": "SCENARIO_4_BURST", "registry_id": 4},
            ground_truth_events=["START", "ATTACK_START", "ATTACK_STOP", "END"],
            label_source=TwinLabelSource.SCENARIO_CONTROL,
        ),
        TwinScenario(
            scenario_id="S5",
            name="SCENARIO_5_MIXED_ATTACKS",
            description="SYN then UDP sequential floods",
            attack_type="SYN_THEN_UDP",
            expected_attack=True,
            expected_attack_family="MIXED",
            intensity_profile="SYN_FLOOD_LOW+UDP_FLOOD",
            duration_sec=65,
            baseline_sec=15,
            attack_sec=40,
            recovery_sec=5,
            source_host="h1",
            target_host="h2",
            protocol="TCP+UDP",
            parameters={
                "template": "SCENARIO_5_MIXED_SYN_UDP",
                "registry_id": 5,
                "phases": ["SYN_FLOOD", "UDP_FLOOD"],
            },
            ground_truth_events=[
                "START",
                "ATTACK1_START",
                "ATTACK1_STOP",
                "ATTACK2_START",
                "ATTACK2_STOP",
                "END",
            ],
            label_source=TwinLabelSource.SCENARIO_CONTROL,
        ),
    ]
    return {s.scenario_id: s for s in scenarios}


def get_baseline_scenario(
    scenario_id: str | int,
    *,
    require: bool = False,
) -> Optional[TwinScenario]:
    """
    Lookup by S1–S5 id (case-insensitive).

    If require=True, raises TwinValidationError for unknown ids.
    """
    from twin.validate import normalize_scenario_id, validate_scenario_id

    if require:
        key = validate_scenario_id(scenario_id)
    else:
        key = normalize_scenario_id(scenario_id)
    return baseline_scenario_catalog().get(key)
