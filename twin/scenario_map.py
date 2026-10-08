"""Map live scenario_logs names onto twin S1–S5 ids."""

from __future__ import annotations

from typing import Optional

_NAME_TO_SID = (
    ("SCENARIO_5", "S5"),
    ("MIXED", "S5"),
    ("SCENARIO_4", "S4"),
    ("BURST", "S4"),
    ("SCENARIO_3", "S3"),
    ("UDP_FLOOD", "S3"),
    ("SCENARIO_2", "S2"),
    ("SYN_FLOOD", "S2"),
    ("SCENARIO_1", "S1"),
    ("NORMAL_ONLY", "S1"),
    ("NORMAL", "S1"),
)


def scenario_name_to_id(name: str) -> Optional[str]:
    """Best-effort map from scenario_logs.scenario_name to S1–S5."""
    key = str(name or "").upper()
    if not key:
        return None
    if key in {"S1", "S2", "S3", "S4", "S5"}:
        return key
    for token, sid in _NAME_TO_SID:
        if token in key:
            return sid
    return None


def scenario_id_matches_name(scenario_id: str, name: str) -> bool:
    mapped = scenario_name_to_id(name)
    return mapped == str(scenario_id).strip().upper()
