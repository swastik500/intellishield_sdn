"""
Parameter controllability audit for S1–S5 (documentation + programmatic).

Behavior of attack_scenarios.py is NOT changed by R3.1 — this only records
what is currently callable vs hardcoded in the live functions.
"""

from __future__ import annotations

from typing import Any, Dict, List


# Accurate mapping of current attack_scenarios.py call signatures / constants.
SCENARIO_PARAMETER_AUDIT: Dict[str, Dict[str, Any]] = {
    "S1": {
        "purpose": "Normal baseline (ICMP-only ring)",
        "attack_or_normal": "normal",
        "ground_truth": ["START", "PHASE", "END"],
        "function": "scenario_1_normal_only",
        "controllable_today": ["duration"],
        "hardcoded_today": [
            "profile=PROFILE_NORMAL_LIGHT (ICMP only)",
            "host ring among first 4 hosts",
            "no attack",
        ],
        "notes": (
            "SCENARIO_TEMPLATES lists MEDIUM for S1, but live function uses LIGHT "
            "ICMP-only to avoid ML false positives from iperf."
        ),
    },
    "S2": {
        "purpose": "SYN flood detection evaluation",
        "attack_or_normal": "attack",
        "ground_truth": ["START", "ATTACK_START", "ATTACK_STOP", "END"],
        "function": "scenario_2_syn_flood",
        "controllable_today": ["baseline_sec", "attack_sec", "recovery_sec"],
        "hardcoded_today": [
            "attacker=h1",
            "target=h2",
            "PROFILE_SYN_FLOOD_HIGH",
            "rand_source=True",
            "normal PHASE_A profile LIGHT/MEDIUM per code path",
        ],
    },
    "S3": {
        "purpose": "UDP flood detection evaluation",
        "attack_or_normal": "attack",
        "ground_truth": ["START", "ATTACK_START", "ATTACK_STOP", "END"],
        "function": "scenario_3_udp_flood",
        "controllable_today": ["baseline_sec", "attack_sec", "recovery_sec"],
        "hardcoded_today": [
            "attacker=h1",
            "target=h2",
            "PROFILE_UDP_FLOOD",
        ],
    },
    "S4": {
        "purpose": "Burst flood sensitivity",
        "attack_or_normal": "attack",
        "ground_truth": ["START", "ATTACK_START", "ATTACK_STOP", "END"],
        "function": "scenario_4_burst_attack",
        "controllable_today": ["baseline_sec", "burst_sec", "recovery_sec"],
        "hardcoded_today": [
            "attacker=h1",
            "target=h2",
            "PROFILE_BURST",
        ],
    },
    "S5": {
        "purpose": "Mixed SYN then UDP sequential floods",
        "attack_or_normal": "attack",
        "ground_truth": [
            "START",
            "ATTACK1_START",
            "ATTACK1_STOP",
            "ATTACK2_START",
            "ATTACK2_STOP",
            "END",
        ],
        "function": "scenario_5_mixed_attacks",
        "controllable_today": [
            "baseline_sec",
            "attack1_sec",
            "gap_sec",
            "attack2_sec",
        ],
        "hardcoded_today": [
            "attacker=h1",
            "target=h2",
            "SYN then UDP profile pair",
            "phase order",
        ],
    },
}


def scenario_parameter_audit() -> Dict[str, Dict[str, Any]]:
    """Return a copy of the S1–S5 parameter audit table."""
    return {k: dict(v) for k, v in SCENARIO_PARAMETER_AUDIT.items()}


def controllable_parameters(scenario_id: str) -> List[str]:
    from twin.validate import validate_scenario_id

    key = validate_scenario_id(scenario_id)
    return list(SCENARIO_PARAMETER_AUDIT[key]["controllable_today"])
