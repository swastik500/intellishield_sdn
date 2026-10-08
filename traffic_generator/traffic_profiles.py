"""
================================================================================
IntelliShield SDN — Phase 3: Traffic Generation & Attack Simulation Engine
================================================================================

File        : traffic_generator/traffic_profiles.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 3 — Traffic Generation & Attack Simulation

Description:
    Centralised traffic profile and attack configuration store.
    All tunable parameters for normal traffic and attack simulations
    are defined here as Python dataclasses and dicts.

    Importing modules consume these profiles so that experiment
    parameters are changed in ONE place only — not scattered across files.

IEEE Relevance:
    Predefined reproducible profiles are essential for IEEE-grade research.
    Identical profiles ensure that repeated experiments are comparable and
    results can be validated independently.

================================================================================
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any


# ─── Mininet Network Defaults ─────────────────────────────────────────────────

# IP subnet used by default Mininet topology
MININET_SUBNET   = "10.0.0."
MININET_IP_START = 1      # h1 = 10.0.0.1
MININET_IP_END   = 254    # Max hosts

# Controller address for standalone Mininet
CONTROLLER_HOST = "127.0.0.1"
CONTROLLER_PORT = 6653


# ─── Normal Traffic Defaults ──────────────────────────────────────────────────

DEFAULT_PING_COUNT    = 50        # Packets per ping burst
DEFAULT_PING_INTERVAL = 0.2       # Seconds between pings (5 pkt/s)
DEFAULT_IPERF_DURATION = 20       # Seconds of iperf session
DEFAULT_IPERF_BANDWIDTH = "1M"    # Bandwidth cap for iperf UDP
DEFAULT_TCP_CONNECTIONS = 3       # Parallel iperf TCP streams
DEFAULT_HTTP_PORT       = 8080    # Port for lightweight HTTP server
DEFAULT_UDP_PACKET_SIZE = 512     # Bytes per UDP packet


# ─── Attack Defaults ──────────────────────────────────────────────────────────

DEFAULT_ATTACK_DURATION  = 30     # Seconds an attack runs
DEFAULT_SYN_RATE         = 10000  # Packets/sec for SYN flood
DEFAULT_UDP_FLOOD_BW     = "10M"  # Bandwidth for UDP flood
DEFAULT_ICMP_FLOOD_RATE  = 5000   # Packets/sec for ICMP flood
DEFAULT_BURST_DURATION   = 10     # Seconds of burst
DEFAULT_BURST_RATE       = 20000  # Packets/sec during burst


# ─── Traffic Profile Dataclasses ─────────────────────────────────────────────

@dataclass
class NormalTrafficProfile:
    """
    Configuration profile for normal (benign) background traffic.

    Used by NormalTrafficGenerator to parameterise each traffic type.
    All fields have research-tuned defaults appropriate for a 5-host
    Mininet topology on a single Ubuntu VM.
    """
    name: str                          = "DEFAULT_NORMAL"
    description: str                   = "Standard mixed normal traffic"

    # ICMP settings
    ping_count:    int                 = DEFAULT_PING_COUNT
    ping_interval: float               = DEFAULT_PING_INTERVAL

    # TCP (iperf) settings
    iperf_duration:   int              = DEFAULT_IPERF_DURATION
    tcp_connections:  int              = DEFAULT_TCP_CONNECTIONS

    # UDP (iperf) settings
    udp_bandwidth:    str              = DEFAULT_IPERF_BANDWIDTH
    udp_packet_size:  int              = DEFAULT_UDP_PACKET_SIZE

    # HTTP settings
    http_port:        int              = DEFAULT_HTTP_PORT

    # Mixed: which protocols to combine
    mixed_protocols:  List[str]        = field(
        default_factory=lambda: ["icmp", "tcp", "udp"]
    )


@dataclass
class AttackProfile:
    """
    Configuration profile for a single DDoS attack type.

    AttackGenerator consumes this profile to parameterise hping3 / flooding
    commands. Each attack scenario references a specific AttackProfile.

    [HOOK] Phase 7 → PPO RL will modify 'packet_rate' and 'duration'
           dynamically based on reward signals.
    """
    name: str                          = "DEFAULT_ATTACK"
    attack_type: str                   = "SYN_FLOOD"
    description: str                   = "Default SYN flood profile"

    # Timing
    duration:     int                  = DEFAULT_ATTACK_DURATION

    # SYN flood
    syn_rate:     int                  = DEFAULT_SYN_RATE
    syn_flags:    str                  = "-S"            # TCP SYN flag

    # UDP flood
    udp_bandwidth: str                 = DEFAULT_UDP_FLOOD_BW
    udp_pkt_size:  int                 = 1400            # bytes near MTU

    # ICMP flood
    icmp_rate:     int                 = DEFAULT_ICMP_FLOOD_RATE

    # Burst
    burst_rate:    int                 = DEFAULT_BURST_RATE
    burst_duration: int                = DEFAULT_BURST_DURATION

    # hping3 extra flags (e.g. "--rand-source" for source spoofing)
    extra_flags:   str                 = ""


# ─── Predefined Named Profiles ────────────────────────────────────────────────

# Normal traffic profiles
PROFILE_NORMAL_LIGHT = NormalTrafficProfile(
    name        = "NORMAL_LIGHT",
    description = "Light background ICMP traffic only",
    ping_count  = 20,
    ping_interval = 0.5,
)

PROFILE_NORMAL_MEDIUM = NormalTrafficProfile(
    name             = "NORMAL_MEDIUM",
    description      = "Moderate mixed ICMP + TCP traffic",
    ping_count       = 50,
    ping_interval    = 0.2,
    iperf_duration   = 15,
    tcp_connections  = 2,
    mixed_protocols  = ["icmp", "tcp"],
)

PROFILE_NORMAL_HEAVY = NormalTrafficProfile(
    name             = "NORMAL_HEAVY",
    description      = "Heavy mixed traffic — all protocols",
    ping_count       = 100,
    ping_interval    = 0.1,
    iperf_duration   = 30,
    tcp_connections  = 4,
    udp_bandwidth    = "2M",
    mixed_protocols  = ["icmp", "tcp", "udp"],
)

# Attack profiles
PROFILE_SYN_FLOOD_LOW = AttackProfile(
    name        = "SYN_FLOOD_LOW",
    attack_type = "SYN_FLOOD",
    description = "Low-rate SYN flood — detectable but subtle",
    syn_rate    = 1000,
    duration    = 20,
)

PROFILE_SYN_FLOOD_HIGH = AttackProfile(
    name        = "SYN_FLOOD_HIGH",
    attack_type = "SYN_FLOOD",
    description = "High-rate SYN flood — obvious entropy collapse",
    syn_rate    = 10000,
    duration    = 30,
    extra_flags = "--rand-source",   # Randomise source IPs
)

PROFILE_UDP_FLOOD = AttackProfile(
    name          = "UDP_FLOOD",
    attack_type   = "UDP_FLOOD",
    description   = "UDP amplification-style flood",
    udp_bandwidth = "10M",
    udp_pkt_size  = 1400,
    duration      = 30,
)

PROFILE_ICMP_FLOOD = AttackProfile(
    name       = "ICMP_FLOOD",
    attack_type = "ICMP_FLOOD",
    description = "ICMP echo flood",
    icmp_rate   = 5000,
    duration    = 25,
)

PROFILE_BURST = AttackProfile(
    name           = "BURST_ATTACK",
    attack_type    = "BURST",
    description    = "Short burst flooding to test entropy sensitivity",
    burst_rate     = 20000,
    burst_duration = 8,
    duration       = 8,
)

# Named profile registry — for lookup by string key
ATTACK_PROFILES: Dict[str, AttackProfile] = {
    "SYN_FLOOD_LOW"  : PROFILE_SYN_FLOOD_LOW,
    "SYN_FLOOD_HIGH" : PROFILE_SYN_FLOOD_HIGH,
    "UDP_FLOOD"      : PROFILE_UDP_FLOOD,
    "ICMP_FLOOD"     : PROFILE_ICMP_FLOOD,
    "BURST"          : PROFILE_BURST,
}

NORMAL_PROFILES: Dict[str, NormalTrafficProfile] = {
    "LIGHT"  : PROFILE_NORMAL_LIGHT,
    "MEDIUM" : PROFILE_NORMAL_MEDIUM,
    "HEAVY"  : PROFILE_NORMAL_HEAVY,
}


# ─── Scenario Templates ───────────────────────────────────────────────────────

# Scenario definitions — each is a list of timed events.
# Format per event: {"t": seconds_offset, "action": str, "params": dict}
# Consumed by TrafficScheduler.

SCENARIO_TEMPLATES: Dict[str, List[Dict[str, Any]]] = {

    "SCENARIO_1_NORMAL_ONLY": [
        {"t":  0, "action": "start_normal",  "params": {"profile": "MEDIUM"}},
        {"t": 60, "action": "stop_all",      "params": {}},
    ],

    "SCENARIO_2_SYN_FLOOD": [
        {"t":  0,  "action": "start_normal",  "params": {"profile": "MEDIUM"}},
        {"t": 20,  "action": "start_attack",  "params": {"profile": "SYN_FLOOD_HIGH"}},
        {"t": 50,  "action": "stop_attack",   "params": {}},
        {"t": 60,  "action": "stop_all",      "params": {}},
    ],

    "SCENARIO_3_UDP_FLOOD": [
        {"t":  0,  "action": "start_normal",  "params": {"profile": "MEDIUM"}},
        {"t": 20,  "action": "start_attack",  "params": {"profile": "UDP_FLOOD"}},
        {"t": 50,  "action": "stop_attack",   "params": {}},
        {"t": 60,  "action": "stop_all",      "params": {}},
    ],

    "SCENARIO_4_BURST": [
        {"t":  0,  "action": "start_normal",  "params": {"profile": "LIGHT"}},
        {"t": 15,  "action": "start_attack",  "params": {"profile": "BURST"}},
        {"t": 25,  "action": "stop_attack",   "params": {}},
        {"t": 30,  "action": "stop_all",      "params": {}},
    ],

    "SCENARIO_5_MIXED_SYN_UDP": [
        {"t":  0,  "action": "start_normal",  "params": {"profile": "HEAVY"}},
        {"t": 15,  "action": "start_attack",  "params": {"profile": "SYN_FLOOD_LOW"}},
        {"t": 35,  "action": "stop_attack",   "params": {}},
        {"t": 40,  "action": "start_attack",  "params": {"profile": "UDP_FLOOD"}},
        {"t": 60,  "action": "stop_attack",   "params": {}},
        {"t": 65,  "action": "stop_all",      "params": {}},
    ],
}
