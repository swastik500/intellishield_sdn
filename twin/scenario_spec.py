"""Parameterized twin scenario plan (R3.2) — additive to S1–S5 defaults."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

GENERATOR_VERSION = "r3.2.0"

# Hard bounds — lab-safe, no uncontrolled flooding.
MAX_DURATION_SEC = 600
MIN_DURATION_SEC = 1
MAX_SYN_RATE = 20000
MIN_SYN_RATE = 100
MAX_BURST_COUNT = 5
MAX_VARIANTS_DEFAULT = 8
MAX_VARIANTS_HARD = 32

# Documented numeric intensity anchors (from traffic_profiles).
SYN_RATE_LOW = 1000
SYN_RATE_HIGH = 10000
UDP_BW_LOW = "1M"
UDP_BW_MED = "5M"
UDP_BW_HIGH = "10M"
BURST_RATE_DEFAULT = 20000


@dataclass(frozen=True)
class ScenarioPlan:
    """
    Resolved, validated twin scenario plan ready for dry-run / execution binding.

    Does not launch Mininet. Ground truth is scenario-control only.
    """

    scenario_id: str
    scenario_version: str
    scenario_family: str
    label: str
    seed: int
    source_host: str
    target_host: str
    source_ip: str
    target_ip: str
    expected_attack: bool
    expected_attack_family: str
    ground_truth_events: List[str]
    # Temporal
    duration_sec: int = 0
    baseline_sec: int = 0
    attack_sec: int = 0
    recovery_sec: int = 0
    attack1_sec: int = 0
    attack2_sec: int = 0
    gap_sec: int = 0
    burst_sec: int = 0
    burst_count: int = 1
    inter_burst_interval_sec: int = 0
    # Intensity (numeric / documented)
    syn_rate: Optional[int] = None
    udp_bandwidth: str = ""
    burst_rate: Optional[int] = None
    rand_source: bool = True
    # Bookkeeping
    parameters: Dict[str, Any] = field(default_factory=dict)
    run_kwargs: Dict[str, Any] = field(default_factory=dict)
    profile_id: str = ""
    profile_fingerprint: str = ""
    generator_version: str = GENERATOR_VERSION
    notes: str = ""

    def expected_timeline(self) -> List[Dict[str, Any]]:
        """Authoritative expected event schedule (independent of detectors)."""
        events: List[Dict[str, Any]] = []
        t = 0
        events.append({"t": t, "event": "START", "label": "NORMAL"})
        if self.scenario_id == "S1":
            events.append({"t": t, "event": "PHASE", "label": "NORMAL"})
            t = self.duration_sec
            events.append({"t": t, "event": "END", "label": "NORMAL"})
            return events

        t = self.baseline_sec
        if self.scenario_id == "S5":
            events.append(
                {
                    "t": t,
                    "event": "ATTACK1_START",
                    "label": "ATTACK",
                    "family": "SYN_FLOOD",
                    "source": self.source_host,
                    "target": self.target_host,
                }
            )
            t += self.attack1_sec
            events.append({"t": t, "event": "ATTACK1_STOP", "label": "NORMAL"})
            t += self.gap_sec
            events.append(
                {
                    "t": t,
                    "event": "ATTACK2_START",
                    "label": "ATTACK",
                    "family": "UDP_FLOOD",
                    "source": self.source_host,
                    "target": self.target_host,
                }
            )
            t += self.attack2_sec
            events.append({"t": t, "event": "ATTACK2_STOP", "label": "NORMAL"})
            events.append({"t": t, "event": "END", "label": "NORMAL"})
            return events

        # S2/S3/S4 (S4 may have multiple bursts)
        if self.scenario_id == "S4" and self.burst_count > 1:
            for i in range(self.burst_count):
                events.append(
                    {
                        "t": t,
                        "event": "ATTACK_START",
                        "label": "ATTACK",
                        "family": self.expected_attack_family,
                        "source": self.source_host,
                        "target": self.target_host,
                        "burst_index": i,
                    }
                )
                t += self.burst_sec
                events.append(
                    {
                        "t": t,
                        "event": "ATTACK_STOP",
                        "label": "NORMAL",
                        "burst_index": i,
                    }
                )
                if i < self.burst_count - 1:
                    t += self.inter_burst_interval_sec
            t += self.recovery_sec
            events.append({"t": t, "event": "END", "label": "NORMAL"})
            return events

        events.append(
            {
                "t": t,
                "event": "ATTACK_START",
                "label": "ATTACK",
                "family": self.expected_attack_family,
                "source": self.source_host,
                "target": self.target_host,
            }
        )
        attack_len = self.burst_sec if self.scenario_id == "S4" else self.attack_sec
        t += attack_len
        events.append({"t": t, "event": "ATTACK_STOP", "label": "NORMAL"})
        t += self.recovery_sec
        events.append({"t": t, "event": "END", "label": "NORMAL"})
        return events
