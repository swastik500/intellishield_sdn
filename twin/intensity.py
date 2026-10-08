"""Documented intensity resolution for twin scenarios (numeric, bounded)."""

from __future__ import annotations

from typing import Any, Dict, Optional, Union

from twin.scenario_spec import (
    BURST_RATE_DEFAULT,
    MAX_SYN_RATE,
    MIN_SYN_RATE,
    SYN_RATE_HIGH,
    SYN_RATE_LOW,
    UDP_BW_HIGH,
    UDP_BW_LOW,
    UDP_BW_MED,
)
from twin.validate import TwinValidationError

IntensityInput = Union[int, float, str, None]


def resolve_syn_rate(intensity: IntensityInput, *, default: int = SYN_RATE_HIGH) -> int:
    """
    Map intensity to SYN pkt/s.

    Accepts int rate or documented labels LOW/HIGH (mapped to profiles).
    """
    if intensity is None:
        return default
    if isinstance(intensity, str):
        key = intensity.strip().upper()
        if key in ("LOW", "SYN_FLOOD_LOW"):
            return SYN_RATE_LOW
        if key in ("HIGH", "SYN_FLOOD_HIGH", "DEFAULT"):
            return SYN_RATE_HIGH
        if key.isdigit():
            return _clamp_syn_rate(int(key))
        raise TwinValidationError(f"invalid SYN intensity label: {intensity!r}")
    if isinstance(intensity, bool) or not isinstance(intensity, (int, float)):
        raise TwinValidationError(f"invalid SYN intensity type: {type(intensity)!r}")
    return _clamp_syn_rate(int(intensity))


def _clamp_syn_rate(rate: int) -> int:
    if rate < MIN_SYN_RATE or rate > MAX_SYN_RATE:
        raise TwinValidationError(
            f"invalid syn_rate {rate}; allowed [{MIN_SYN_RATE}, {MAX_SYN_RATE}]"
        )
    return rate


def resolve_udp_bandwidth(
    intensity: IntensityInput, *, default: str = UDP_BW_HIGH
) -> str:
    if intensity is None:
        return default
    if isinstance(intensity, (int, float)) and not isinstance(intensity, bool):
        # Treat numeric Mbps
        mbps = int(intensity)
        if mbps <= 0 or mbps > 50:
            raise TwinValidationError(f"invalid UDP bandwidth Mbps: {mbps}")
        return f"{mbps}M"
    if isinstance(intensity, str):
        key = intensity.strip().upper()
        if key in ("LOW",):
            return UDP_BW_LOW
        if key in ("MEDIUM", "MED"):
            return UDP_BW_MED
        if key in ("HIGH", "DEFAULT", "UDP_FLOOD"):
            return UDP_BW_HIGH
        if key.endswith("M") and key[:-1].isdigit():
            return key
        raise TwinValidationError(f"invalid UDP intensity: {intensity!r}")
    raise TwinValidationError(f"invalid UDP intensity type: {type(intensity)!r}")


def resolve_burst_rate(
    intensity: IntensityInput, *, default: int = BURST_RATE_DEFAULT
) -> int:
    if intensity is None:
        return default
    if isinstance(intensity, str):
        key = intensity.strip().upper()
        if key in ("LOW",):
            return 5000
        if key in ("HIGH", "DEFAULT", "BURST"):
            return BURST_RATE_DEFAULT
        if key.isdigit():
            return _clamp_syn_rate(int(key))  # same pkt/s bounds
        raise TwinValidationError(f"invalid burst intensity: {intensity!r}")
    if isinstance(intensity, bool) or not isinstance(intensity, (int, float)):
        raise TwinValidationError(f"invalid burst intensity type: {type(intensity)!r}")
    return _clamp_syn_rate(int(intensity))


def intensity_documentation() -> Dict[str, Any]:
    return {
        "syn_rate": {
            "LOW": SYN_RATE_LOW,
            "HIGH": SYN_RATE_HIGH,
            "bounds": [MIN_SYN_RATE, MAX_SYN_RATE],
        },
        "udp_bandwidth": {
            "LOW": UDP_BW_LOW,
            "MEDIUM": UDP_BW_MED,
            "HIGH": UDP_BW_HIGH,
        },
        "burst_rate": {"LOW": 5000, "HIGH": BURST_RATE_DEFAULT},
    }
