"""
================================================================================
IntelliShield SDN — Phase 3: Traffic Generation & Attack Simulation Engine
================================================================================

File        : traffic_generator/attack_scenarios.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 3 — Traffic Generation & Attack Simulation

Description:
    Predefined reproducible experiment scenarios for IEEE research evaluation.

    Each scenario is a self-contained function that:
        1. Starts normal background traffic
        2. Waits a defined baseline period
        3. Launches an attack
        4. Runs the attack for a defined duration
        5. Stops the attack
        6. Resumes normal monitoring
        7. Logs all events with timestamps

    Scenarios are designed to produce observable entropy changes:
        - Before attack  : entropy ≈ 0.7–1.0 (NORMAL)
        - During attack  : entropy ≈ 0.0–0.3 (ALERT)
        - After attack   : entropy recovers

    Providing 5 standard scenarios supports reproducible IEEE experiments.

IEEE Relevance:
    Reproducible scenario scripts are a requirement for IEEE prototype
    evaluation sections. Each scenario has a defined timeline that can
    be cited in the paper's experimental methodology.

================================================================================
"""

import time
import logging
import traceback
from typing import List, Optional

from traffic_generator.traffic_profiles import (
    NORMAL_PROFILES,
    ATTACK_PROFILES,
    PROFILE_NORMAL_LIGHT,
    PROFILE_NORMAL_MEDIUM,
    PROFILE_SYN_FLOOD_HIGH,
    PROFILE_UDP_FLOOD,
    PROFILE_ICMP_FLOOD,
    PROFILE_BURST,
    PROFILE_SYN_FLOOD_LOW,
)
from traffic_generator.normal_traffic import NormalTrafficGenerator
from traffic_generator.attack_generator import AttackGenerator
from traffic_generator.traffic_logger import (
    log_scenario_event,
    log_session_profile,
)

logger = logging.getLogger("intellishield.attack_scenarios")


# ─── Scenario Base Utilities ──────────────────────────────────────────────────

def _wait(seconds: int, label: str = "") -> None:
    """Sleep with progress logging every 5 seconds."""
    logger.info("[SCENARIO WAIT] %s — waiting %ds ...", label, seconds)
    elapsed = 0
    while elapsed < seconds:
        chunk = min(5, seconds - elapsed)
        time.sleep(chunk)
        elapsed += chunk
        if elapsed < seconds:
            logger.info("  ... %d/%d sec", elapsed, seconds)


def _default_hosts(net, n: int = 4) -> List[str]:
    """Return the first `n` host names from the Mininet topology."""
    try:
        hosts = [h.name for h in net.hosts[:n]]
        return hosts
    except Exception:
        return [f"h{i}" for i in range(1, n + 1)]


# ─── Scenario 1: Normal Traffic Only (Baseline) ───────────────────────────────

def scenario_1_normal_only(net, duration: int = 60) -> None:
    """
    Scenario 1 — Normal Traffic Baseline.

    Purpose:
        Establishes entropy baseline for research comparison.
        Run this FIRST to capture "ground truth" normal entropy values.

    Timeline:
        0s     : Start ICMP-only ring traffic (~5 pkt/s per flow)
        60s    : Stop all traffic

    Expected ML:
        status = NORMAL  (same ICMP baseline as S2–S5 PHASE_A)

    Args:
        net     : Mininet net object.
        duration: Total run time in seconds.
    """
    name  = "SCENARIO_1_NORMAL_ONLY"
    hosts = _default_hosts(net, 4)

    gen   = NormalTrafficGenerator(net)

    log_scenario_event(name, "START", f"Normal traffic only — {duration}s baseline")
    # ICMP-only baseline — matches S2–S5 PHASE_A (~5 pkt/s). MEDIUM profile's
    # iperf TCP pushes 100k+ pkt/s and is misclassified as ATTACK by the ML model.
    log_session_profile(name, vars(PROFILE_NORMAL_LIGHT))

    print("\n" + "─" * 56)
    print(f"  SCENARIO 1: Normal Traffic Baseline")
    print(f"  Hosts: {hosts}  |  Duration: {duration}s  |  Profile: LIGHT (ICMP only)")
    print("─" * 56)

    try:
        log_scenario_event(name, "PHASE", "Starting ICMP-only baseline traffic")
        for i in range(len(hosts)):
            src = hosts[i]
            dst = hosts[(i + 1) % len(hosts)]
            gen.generate_continuous_icmp(src, dst, PROFILE_NORMAL_LIGHT.ping_interval)
        time.sleep(duration)

    except KeyboardInterrupt:
        logger.info("[%s] Interrupted by user.", name)
    except Exception:
        logger.error("[%s] Error: %s", name, traceback.format_exc())
        log_scenario_event(name, "ERROR", traceback.format_exc(), status="ERROR")
    finally:
        gen.stop_all_traffic(hosts)
        log_scenario_event(name, "END", "Scenario 1 complete")
        logger.info("[%s] DONE.", name)


# ─── Scenario 2: SYN Flood Attack ─────────────────────────────────────────────

def scenario_2_syn_flood(net,
                          baseline_sec: int = 20,
                          attack_sec: int = 30,
                          recovery_sec: int = 10,
                          attacker: Optional[str] = None,
                          target: Optional[str] = None,
                          syn_rate: Optional[int] = None,
                          rand_source: bool = True) -> None:
    """
    Scenario 2 — SYN Flood DDoS Attack.

    Purpose:
        Primary DDoS detection evaluation scenario.
        Demonstrates entropy collapse during SYN flood.

    Timeline:
        0s              : Start normal background traffic
        baseline_sec    : Launch SYN flood h1 → h2
        baseline+attack : Stop SYN flood
        +recovery_sec   : Stop all traffic

    Expected behaviour:
        - Phase 1: entropy ≈ 1.0  (NORMAL)
        - Phase 2: entropy → 0.0  (ALERT — SRC/DST entropy collapse)
        - Phase 3: entropy recovers

    Args:
        net          : Mininet net object.
        baseline_sec : Seconds of normal traffic before attack.
        attack_sec   : Attack duration in seconds.
        recovery_sec : Seconds of recovery monitoring after attack.
    """
    name    = "SCENARIO_2_SYN_FLOOD"
    hosts   = _default_hosts(net, 4)
    attacker = attacker or hosts[0]    # default h1
    target   = target or hosts[1]      # default h2
    rate     = PROFILE_SYN_FLOOD_HIGH.syn_rate if syn_rate is None else int(syn_rate)

    gen     = NormalTrafficGenerator(net)
    atk     = AttackGenerator(net)

    log_scenario_event(name, "START",
                       f"SYN Flood: {attacker}→{target}  "
                       f"baseline={baseline_sec}s  attack={attack_sec}s")
    log_session_profile(name, vars(PROFILE_NORMAL_MEDIUM), vars(PROFILE_SYN_FLOOD_HIGH))

    print("\n" + "─" * 56)
    print(f"  SCENARIO 2: SYN Flood Attack")
    print(f"  Attacker: {attacker}  Target: {target}")
    print(f"  Baseline: {baseline_sec}s  Attack: {attack_sec}s  Recovery: {recovery_sec}s")
    print("─" * 56)

    try:
        # ── Phase A: Normal baseline traffic ─────────────────────────────────
        log_scenario_event(name, "PHASE_A", f"Normal baseline traffic — {baseline_sec}s")
        for i in range(len(hosts)):
            src = hosts[i]
            dst = hosts[(i + 1) % len(hosts)]
            gen.generate_continuous_icmp(src, dst)

        _wait(baseline_sec, "Normal baseline")

        # ── Phase B: Launch SYN flood ─────────────────────────────────────────
        log_scenario_event(name, "ATTACK_START",
                           f"SYN flood launched: {attacker} → {target}")
        atk.launch_syn_flood(
            attacker    = attacker,
            target      = target,
            rate        = rate,
            duration    = attack_sec,
            rand_source = rand_source,
        )

        _wait(attack_sec, "SYN flood running")

        # ── Phase C: Stop attack ──────────────────────────────────────────────
        log_scenario_event(name, "ATTACK_STOP", "SYN flood stopped")
        atk.stop_attack(attacker)

        _wait(recovery_sec, "Recovery monitoring")

    except KeyboardInterrupt:
        logger.info("[%s] Interrupted.", name)
    except Exception:
        logger.error("[%s] Error: %s", name, traceback.format_exc())
        log_scenario_event(name, "ERROR", traceback.format_exc(), status="ERROR")
    finally:
        atk.stop_all_attacks()
        gen.stop_all_traffic(hosts)
        log_scenario_event(name, "END", "Scenario 2 complete")
        logger.info("[%s] DONE.", name)


# ─── Scenario 3: UDP Flood ────────────────────────────────────────────────────

def scenario_3_udp_flood(net,
                          baseline_sec: int = 20,
                          attack_sec: int = 30,
                          recovery_sec: int = 10,
                          attacker: Optional[str] = None,
                          target: Optional[str] = None,
                          bandwidth: Optional[str] = None) -> None:
    """
    Scenario 3 — UDP Flood Attack.

    Demonstrates byte_entropy and packet_entropy collapse under high-volume
    UDP flooding. Unlike SYN flood, UDP flood primarily affects bandwidth
    metrics rather than TCP connection state.

    Timeline:
        0s              : Start normal traffic
        baseline_sec    : Launch UDP flood h1 → h2
        +attack_sec     : Stop attack
        +recovery_sec   : End

    Args:
        net          : Mininet net object.
        baseline_sec : Normal traffic baseline duration.
        attack_sec   : Attack duration.
        recovery_sec : Recovery monitoring window.
    """
    name     = "SCENARIO_3_UDP_FLOOD"
    hosts    = _default_hosts(net, 4)
    attacker = attacker or hosts[0]
    target   = target or hosts[1]
    bw       = PROFILE_UDP_FLOOD.udp_bandwidth if bandwidth is None else str(bandwidth)

    gen = NormalTrafficGenerator(net)
    atk = AttackGenerator(net)

    log_scenario_event(name, "START",
                       f"UDP Flood: {attacker}→{target}  attack={attack_sec}s")
    log_session_profile(name, vars(PROFILE_NORMAL_MEDIUM), vars(PROFILE_UDP_FLOOD))

    print("\n" + "─" * 56)
    print(f"  SCENARIO 3: UDP Flood Attack")
    print(f"  Attacker: {attacker}  Target: {target}")
    print("─" * 56)

    try:
        log_scenario_event(name, "PHASE_A", "Normal baseline")
        for i in range(len(hosts)):
            gen.generate_continuous_icmp(hosts[i], hosts[(i + 1) % len(hosts)])

        _wait(baseline_sec, "Normal baseline")

        log_scenario_event(name, "ATTACK_START", f"UDP flood: {attacker} → {target}")
        atk.launch_udp_flood(
            attacker  = attacker,
            target    = target,
            bandwidth = bw,
            pkt_size  = PROFILE_UDP_FLOOD.udp_pkt_size,
            duration  = attack_sec,
        )

        _wait(attack_sec, "UDP flood running")

        log_scenario_event(name, "ATTACK_STOP", "UDP flood stopped")
        atk.stop_attack(attacker)
        _wait(recovery_sec, "Recovery")

    except KeyboardInterrupt:
        logger.info("[%s] Interrupted.", name)
    except Exception:
        logger.error("[%s] Error: %s", name, traceback.format_exc())
        log_scenario_event(name, "ERROR", traceback.format_exc(), status="ERROR")
    finally:
        atk.stop_all_attacks()
        gen.stop_all_traffic(hosts)
        log_scenario_event(name, "END", "Scenario 3 complete")


# ─── Scenario 4: Burst Attack ─────────────────────────────────────────────────

def scenario_4_burst_attack(net,
                             baseline_sec: int = 15,
                             burst_sec: int = 8,
                             recovery_sec: int = 15,
                             attacker: Optional[str] = None,
                             target: Optional[str] = None,
                             burst_rate: Optional[int] = None,
                             burst_count: int = 1,
                             inter_burst_interval_sec: int = 0) -> None:
    """
    Scenario 4 — Burst Traffic Attack.

    Tests entropy detector sensitivity to short-duration traffic spikes.
    The burst lasts only 8 seconds — a narrow detection window.

    Research use:
        Measures minimum detectable attack duration (detection latency test).
        Results inform the optimal WINDOW_SIZE parameter for Phase 7 PPO RL.

    Timeline:
        0s              : Normal traffic
        baseline_sec    : Burst flood starts (ATTACK_START)
        +burst_sec      : Burst auto-stops (ATTACK_STOP)
        +recovery_sec   : Recovery observation
        End             : Scenario END

    Args:
        net          : Mininet net object.
        baseline_sec : Pre-attack baseline.
        burst_sec    : Burst attack duration.
        recovery_sec : Post-attack observation.
    """
    name     = "SCENARIO_4_BURST"
    hosts    = _default_hosts(net, 4)
    attacker = attacker or hosts[0]
    target   = target or hosts[1]
    rate     = PROFILE_BURST.burst_rate if burst_rate is None else int(burst_rate)
    count    = max(1, int(burst_count))
    gap      = max(0, int(inter_burst_interval_sec))

    gen = NormalTrafficGenerator(net)
    atk = AttackGenerator(net)

    log_scenario_event(name, "START",
                       f"Burst attack: {attacker}→{target}  burst={burst_sec}s")
    log_session_profile(name, vars(PROFILE_NORMAL_MEDIUM), vars(PROFILE_BURST))

    print("\n" + "─" * 56)
    print(f"  SCENARIO 4: Burst Attack (sensitivity test)")
    print(f"  Burst duration: {burst_sec}s  |  Monitor if entropy detector catches it!")
    print("─" * 56)

    try:
        log_scenario_event(name, "PHASE_A", "Normal baseline")
        for i in range(len(hosts)):
            gen.generate_continuous_icmp(hosts[i], hosts[(i + 1) % len(hosts)])
        _wait(baseline_sec, "Normal baseline")

        for i in range(count):
            log_scenario_event(name, "ATTACK_START", f"Burst attack — {burst_sec}s")
            atk.launch_burst_attack(
                attacker, target, burst_duration=burst_sec, rate=rate
            )
            log_scenario_event(name, "ATTACK_STOP", "Burst attack stopped")
            if i < count - 1 and gap > 0:
                _wait(gap, "Inter-burst interval")

        _wait(recovery_sec, "Recovery")

    except KeyboardInterrupt:
        logger.info("[%s] Interrupted.", name)
    except Exception:
        logger.error("[%s] Error: %s", name, traceback.format_exc())
        log_scenario_event(name, "ERROR", traceback.format_exc(), status="ERROR")
    finally:
        atk.stop_all_attacks()
        gen.stop_all_traffic(hosts)
        log_scenario_event(name, "END", "Scenario 4 complete")


# ─── Scenario 5: Mixed Multi-Attack ──────────────────────────────────────────

def scenario_5_mixed_attacks(net,
                               baseline_sec: int = 15,
                               attack1_sec: int = 20,
                               gap_sec: int = 10,
                               attack2_sec: int = 20,
                               attacker: Optional[str] = None,
                               target: Optional[str] = None,
                               syn_rate: Optional[int] = None,
                               bandwidth: Optional[str] = None) -> None:
    """
    Scenario 5 — Sequential Mixed Attacks (Advanced Evaluation).

    Runs SYN flood followed by UDP flood with a recovery gap.
    Tests whether the entropy detector correctly recovers between attacks
    and re-alerts on the second attack.

    Timeline:
        0s                : Normal traffic
        baseline_sec      : SYN flood h1 → h2
        +attack1_sec      : Stop SYN flood
        +gap_sec          : Recovery observation
        +0                : UDP flood h1 → h2
        +attack2_sec      : Stop UDP flood
        End

    Research use:
        Tests detector reset between attack events.
        Verifies no persistent false-positive state after attack stops.

    Args:
        net          : Mininet net object.
        baseline_sec : Pre-attack baseline period.
        attack1_sec  : First attack (SYN) duration.
        gap_sec      : Gap between attacks.
        attack2_sec  : Second attack (UDP) duration.
    """
    name     = "SCENARIO_5_MIXED_ATTACKS"
    hosts    = _default_hosts(net, 4)
    attacker = attacker or hosts[0]
    target   = target or hosts[1]

    gen = NormalTrafficGenerator(net)
    atk = AttackGenerator(net)

    log_scenario_event(name, "START",
                       f"Mixed attacks: SYN({attack1_sec}s) + UDP({attack2_sec}s)")

    print("\n" + "─" * 56)
    print(f"  SCENARIO 5: Sequential Mixed Attacks")
    print(f"  SYN flood: {attack1_sec}s  →  Gap: {gap_sec}s  →  UDP flood: {attack2_sec}s")
    print("─" * 56)

    try:
        # Baseline
        log_scenario_event(name, "PHASE_A", "Normal baseline")
        for i in range(len(hosts)):
            gen.generate_continuous_icmp(hosts[i], hosts[(i + 1) % len(hosts)])
        _wait(baseline_sec, "Normal baseline")

        # Attack 1: SYN flood (default rate matches AttackGenerator when syn_rate omitted)
        log_scenario_event(name, "ATTACK1_START", f"SYN flood: {attacker}→{target}")
        if syn_rate is None:
            atk.launch_syn_flood(attacker, target, duration=attack1_sec)
        else:
            atk.launch_syn_flood(
                attacker, target, rate=int(syn_rate), duration=attack1_sec
            )
        _wait(attack1_sec, "SYN flood")
        atk.stop_attack(attacker)
        log_scenario_event(name, "ATTACK1_STOP", "SYN flood stopped")

        # Recovery gap
        _wait(gap_sec, "Recovery gap")

        # Attack 2: UDP flood
        log_scenario_event(name, "ATTACK2_START", f"UDP flood: {attacker}→{target}")
        if bandwidth is None:
            atk.launch_udp_flood(attacker, target, duration=attack2_sec)
        else:
            atk.launch_udp_flood(
                attacker, target, bandwidth=str(bandwidth), duration=attack2_sec
            )
        _wait(attack2_sec, "UDP flood")
        atk.stop_attack(attacker)
        log_scenario_event(name, "ATTACK2_STOP", "UDP flood stopped")

    except KeyboardInterrupt:
        logger.info("[%s] Interrupted.", name)
    except Exception:
        logger.error("[%s] Error: %s", name, traceback.format_exc())
        log_scenario_event(name, "ERROR", traceback.format_exc(), status="ERROR")
    finally:
        atk.stop_all_attacks()
        gen.stop_all_traffic(hosts)
        log_scenario_event(name, "END", "Scenario 5 complete")


# ─── Scenario 6: Self-Supervised Zero-Day Attack (SSL Evaluation) ───────────

def scenario_6_zero_day_ssl(net,
                             baseline_sec: int = 20,
                             attack_sec: int = 30,
                             recovery_sec: int = 10,
                             attacker: Optional[str] = None,
                             target: Optional[str] = None) -> None:
    """
    Scenario 6 — Self-Supervised Zero-Day (SSL) Attack Evaluation.

    Purpose:
        Simulates an unseen, novel Zero-Day attack pattern (combining high-rate
        port sweep and irregular payload bursts) to evaluate the Self-Supervised
        Zero-Day (SSL) Autoencoder detector.

    Timeline:
        0s              : Normal ICMP background baseline
        baseline_sec    : Launch novel Zero-Day flood h1 → h2
        +attack_sec     : Stop Zero-Day attack
        +recovery_sec   : End & log
    """
    name     = "SCENARIO_6_ZERO_DAY_SSL"
    hosts    = _default_hosts(net, 4)
    attacker = attacker or hosts[0]
    target   = target or hosts[1]

    gen = NormalTrafficGenerator(net)
    atk = AttackGenerator(net)

    log_scenario_event(name, "START",
                       f"SSL Zero-Day attack: {attacker}→{target} attack={attack_sec}s")

    print("\n" + "─" * 56)
    print(f"  SCENARIO 6: Self-Supervised Zero-Day (SSL) Attack")
    print(f"  Attacker: {attacker}  Target: {target}")
    print(f"  Baseline: {baseline_sec}s  Attack: {attack_sec}s  Recovery: {recovery_sec}s")
    print("─" * 56)

    try:
        # Phase A: Normal baseline
        log_scenario_event(name, "PHASE_A", "Normal baseline")
        for i in range(len(hosts)):
            gen.generate_continuous_icmp(hosts[i], hosts[(i + 1) % len(hosts)])
        _wait(baseline_sec, "Normal baseline")

        # Phase B: Launch novel Zero-Day attack (combined burst + SYN/UDP flood)
        log_scenario_event(name, "ATTACK_START", f"Zero-day SSL attack: {attacker} → {target}")
        atk.launch_syn_flood(attacker, target, rate=1500, duration=attack_sec, rand_source=True)
        atk.launch_burst_attack(attacker, target, burst_duration=min(15, attack_sec), rate=3000)

        _wait(attack_sec, "Zero-day SSL attack running")

        # Phase C: Stop attack
        log_scenario_event(name, "ATTACK_STOP", "Zero-day SSL attack stopped")
        atk.stop_attack(attacker)
        _wait(recovery_sec, "Recovery monitoring")

    except KeyboardInterrupt:
        logger.info("[%s] Interrupted.", name)
    except Exception:
        logger.error("[%s] Error: %s", name, traceback.format_exc())
        log_scenario_event(name, "ERROR", traceback.format_exc(), status="ERROR")
    finally:
        atk.stop_all_attacks()
        gen.stop_all_traffic(hosts)
        log_scenario_event(name, "END", "Scenario 6 complete")


# ─── Scenario Registry ────────────────────────────────────────────────────────

SCENARIO_REGISTRY = {
    "1": ("Normal baseline",          scenario_1_normal_only),
    "2": ("SYN flood attack",         scenario_2_syn_flood),
    "3": ("UDP flood attack",         scenario_3_udp_flood),
    "4": ("Burst attack",             scenario_4_burst_attack),
    "5": ("Mixed sequential attacks", scenario_5_mixed_attacks),
    "6": ("Zero-Day (SSL) attack",    scenario_6_zero_day_ssl),
}


def run_scenario(net, scenario_id: str) -> None:
    """
    Look up and run a scenario by ID string.

    Args:
        net         : Mininet net object.
        scenario_id : "1" through "6".
    """
    if scenario_id not in SCENARIO_REGISTRY:
        logger.error("[run_scenario] Unknown scenario ID: '%s'. Valid: %s",
                     scenario_id, list(SCENARIO_REGISTRY.keys()))
        return

    name, func = SCENARIO_REGISTRY[scenario_id]
    logger.info("[run_scenario] Starting: %s — %s", scenario_id, name)
    func(net)

