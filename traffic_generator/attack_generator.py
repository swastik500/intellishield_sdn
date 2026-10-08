"""
================================================================================
IntelliShield SDN — Phase 3: Traffic Generation & Attack Simulation Engine
================================================================================

File        : traffic_generator/attack_generator.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 3 — Traffic Generation & Attack Simulation

Description:
    DDoS attack simulation engine using hping3, iperf UDP flood, and
    high-rate ping commands. Generates traffic patterns designed to
    trigger entropy collapse detection in Phase 2.

    Supported attack types:
        1. SYN Flood  — TCP SYN packet flood using hping3
        2. UDP Flood  — High-bandwidth UDP stream using iperf
        3. ICMP Flood — High-rate ping flood
        4. Burst      — Short-duration traffic spike

    SAFETY GUARDRAILS:
        - All target IPs are validated against Mininet 10.x.x.x subnet.
        - External IP targeting is explicitly rejected.
        - This is strictly a research/educational tool.

    Design:
        Each attack is launched as a background subprocess via Mininet
        host.cmd(). The returned PID is tracked so attacks can be
        stopped cleanly. Orphaned processes are prevented by explicit
        kill() on stop.

Future Integration Points:
    - [HOOK] Phase 5 → mitigation/flow_blocker.py reacts to attack events
    - [HOOK] Phase 7 → PPO RL reward uses attack detection latency

================================================================================
"""

import time
import logging
import traceback
from typing import Optional, Any

from traffic_generator.traffic_profiles import (
    AttackProfile,
    ATTACK_PROFILES,
    DEFAULT_ATTACK_DURATION,
)
from traffic_generator.traffic_logger import (
    init_traffic_logs,
    log_attack_event,
)

logger = logging.getLogger("intellishield.attack_generator")

# ─── Safety Configuration ─────────────────────────────────────────────────────

# Only allow targeting hosts in this subnet (Mininet default)
ALLOWED_SUBNETS = ["10.0.0.", "10.0.1.", "10.0.2.", "192.168.0."]


def _is_safe_target(ip: str) -> bool:
    """
    Validate that a target IP belongs to the Mininet simulation subnet.

    SAFETY GUARDRAIL: Prevents accidental targeting of real external IPs.

    Args:
        ip: Target IP address string.

    Returns:
        bool: True if IP is within allowed simulation subnets.
    """
    return any(ip.startswith(subnet) for subnet in ALLOWED_SUBNETS)


# ─── Attack Generator ─────────────────────────────────────────────────────────

class AttackGenerator:
    """
    IntelliShield SDN — DDoS Attack Simulation Engine.

    Launches configurable DDoS attacks from a Mininet host using hping3,
    iperf, and ping flood. All attacks run in background and can be
    stopped via stop_attack().

    Usage:
        gen = AttackGenerator(net)
        gen.launch_syn_flood(attacker="h1", target="h2", duration=30)
        # ... let entropy detector observe ...
        gen.stop_attack("h1")
    """

    def __init__(self, net=None):
        """
        Args:
            net: Mininet net object.
        """
        self.net = net
        # Maps host_name → list of active attack PIDs
        self._active_attacks: dict = {}
        init_traffic_logs()
        logger.info("[AttackGenerator] Initialised.")

    def set_net(self, net) -> None:
        """Set or update the Mininet net object."""
        self.net = net

    def _get_host(self, name: str) -> Optional[Any]:
        """Retrieve a Mininet host by name."""
        if self.net is None:
            logger.error("[_get_host] No Mininet net set.")
            return None
        try:
            return self.net.get(name)
        except Exception:
            logger.error("[_get_host] Host '%s' not found.", name)
            return None

    def _host_ip(self, name: str) -> str:
        """Return IP address of a host, or the name itself as fallback."""
        host = self._get_host(name)
        return host.IP() if host else name

    def _validate_target(self, attacker: str, target_ip: str) -> bool:
        """
        Safety check: validate attacker and target before launching.

        Args:
            attacker  : Attacker host name.
            target_ip : Target IP address.

        Returns:
            bool: True if safe to proceed.
        """
        if not _is_safe_target(target_ip):
            logger.error(
                "[SAFETY] BLOCKED: Target IP '%s' is outside allowed subnets. "
                "This tool only targets Mininet simulation hosts.",
                target_ip,
            )
            return False
        return True

    # ─── SYN Flood ────────────────────────────────────────────────────────────

    def launch_syn_flood(self,
                          attacker: str,
                          target: str,
                          rate: int = 10000,
                          duration: int = DEFAULT_ATTACK_DURATION,
                          rand_source: bool = False) -> str:
        """
        Launch a TCP SYN flood attack using hping3.

        Effect on entropy:
            - src_entropy  → COLLAPSE (all packets from one source)
            - dst_entropy  → COLLAPSE (all packets to one target)
            - packet_entropy → COLLAPSE (one flow dominates)

        Command: hping3 -S --flood --faster -p 80 <target_ip>

        Args:
            attacker    : Mininet host name launching the attack (e.g. "h1").
            target      : Mininet host name being targeted (e.g. "h2").
            rate        : Target packet rate (used for logging; hping3 --flood
                          runs as fast as possible).
            duration    : How long the attack runs (seconds).
            rand_source : If True, randomise source IPs (--rand-source).
                          Simulates a distributed SYN flood.

        Returns:
            str: Attack PID string.
        """
        try:
            attacker_host = self._get_host(attacker)
            target_ip     = self._host_ip(target)

            if attacker_host is None:
                return ""
            if not self._validate_target(attacker, target_ip):
                return ""

            rand_flag = "--rand-source" if rand_source else ""
            cmd = (
                f"hping3 -S --flood --faster {rand_flag} -p 80 {target_ip} "
                f"> /dev/null 2>&1 &"
            )

            attacker_host.cmd(cmd)
            pid = attacker_host.cmd("echo $!").strip()
            self._active_attacks.setdefault(attacker, []).append(pid)

            log_attack_event(
                attack_type = "SYN_FLOOD",
                source      = attacker,
                target      = target,
                attack_rate = rate,
                duration    = duration,
                status      = "LAUNCHED",
            )
            logger.info("[SYN_FLOOD] %s → %s  rate~%dpkt/s  dur=%ds  PID=%s",
                        attacker, target, rate, duration, pid)

            return pid

        except Exception:
            logger.error("[launch_syn_flood] %s", traceback.format_exc())
            log_attack_event("SYN_FLOOD", attacker, target, status="ERROR")
            return ""

    # ─── UDP Flood ────────────────────────────────────────────────────────────

    def launch_udp_flood(self,
                          attacker: str,
                          target: str,
                          bandwidth: str = "10M",
                          pkt_size: int = 1400,
                          duration: int = DEFAULT_ATTACK_DURATION) -> str:
        """
        Launch a UDP flood using hping3 UDP mode.

        Effect on entropy:
            - byte_entropy   → COLLAPSE (one flow dominates bytes)
            - packet_entropy → COLLAPSE (one flow dominates packets)

        Command: hping3 --udp --flood -p 53 --data <size> <target>

        Args:
            attacker  : Attacking host name.
            target    : Target host name.
            bandwidth : Target bandwidth string (used for logging).
            pkt_size  : UDP payload size in bytes.
            duration  : Attack duration in seconds.

        Returns:
            str: Attack PID string.
        """
        try:
            attacker_host = self._get_host(attacker)
            target_ip     = self._host_ip(target)

            if attacker_host is None:
                return ""
            if not self._validate_target(attacker, target_ip):
                return ""

            cmd = (
                f"hping3 --udp --flood -p 53 --data {pkt_size} {target_ip} "
                f"> /dev/null 2>&1 &"
            )

            attacker_host.cmd(cmd)
            pid = attacker_host.cmd("echo $!").strip()
            self._active_attacks.setdefault(attacker, []).append(pid)

            log_attack_event(
                attack_type = "UDP_FLOOD",
                source      = attacker,
                target      = target,
                attack_rate = 0,
                duration    = duration,
                status      = "LAUNCHED",
            )
            logger.info("[UDP_FLOOD] %s → %s  bw=%s  pkt=%dB  dur=%ds  PID=%s",
                        attacker, target, bandwidth, pkt_size, duration, pid)

            return pid

        except Exception:
            logger.error("[launch_udp_flood] %s", traceback.format_exc())
            log_attack_event("UDP_FLOOD", attacker, target, status="ERROR")
            return ""

    # ─── ICMP Flood ───────────────────────────────────────────────────────────

    def launch_icmp_flood(self,
                           attacker: str,
                           target: str,
                           rate: int = 5000,
                           duration: int = DEFAULT_ATTACK_DURATION) -> str:
        """
        Launch an ICMP echo (ping) flood.

        Uses hping3 ICMP mode for high-rate pings beyond what standard
        ping supports.

        Command: hping3 --icmp --flood --faster <target_ip>

        Args:
            attacker : Attacking host name.
            target   : Target host name.
            rate     : Approximate packet rate (for logging).
            duration : Attack duration in seconds.

        Returns:
            str: Attack PID string.
        """
        try:
            attacker_host = self._get_host(attacker)
            target_ip     = self._host_ip(target)

            if attacker_host is None:
                return ""
            if not self._validate_target(attacker, target_ip):
                return ""

            cmd = (
                f"hping3 --icmp --flood --faster {target_ip} "
                f"> /dev/null 2>&1 &"
            )

            attacker_host.cmd(cmd)
            pid = attacker_host.cmd("echo $!").strip()
            self._active_attacks.setdefault(attacker, []).append(pid)

            log_attack_event(
                attack_type = "ICMP_FLOOD",
                source      = attacker,
                target      = target,
                attack_rate = rate,
                duration    = duration,
                status      = "LAUNCHED",
            )
            logger.info("[ICMP_FLOOD] %s → %s  rate~%dpkt/s  dur=%ds  PID=%s",
                        attacker, target, rate, duration, pid)

            return pid

        except Exception:
            logger.error("[launch_icmp_flood] %s", traceback.format_exc())
            log_attack_event("ICMP_FLOOD", attacker, target, status="ERROR")
            return ""

    # ─── Burst Attack ─────────────────────────────────────────────────────────

    def launch_burst_attack(self,
                             attacker: str,
                             target: str,
                             burst_duration: int = 8,
                             rate: int = 20000) -> None:
        """
        Launch a short-duration burst flood then automatically stop.

        Useful for testing entropy detector sensitivity to transient spikes.
        The attack launches, runs for `burst_duration` seconds, then stops.

        Args:
            attacker       : Attacking host name.
            target         : Target host name.
            burst_duration : How long the burst lasts (seconds).
            rate           : Approximate packet rate (logging only).
        """
        try:
            target_ip = self._host_ip(target)
            if not self._validate_target(attacker, target_ip):
                return

            logger.info("[BURST] Starting %ds burst: %s → %s",
                        burst_duration, attacker, target)

            pid = self.launch_syn_flood(
                attacker = attacker,
                target   = target,
                rate     = rate,
                duration = burst_duration,
            )

            log_attack_event(
                attack_type = "BURST",
                source      = attacker,
                target      = target,
                attack_rate = rate,
                duration    = burst_duration,
                status      = "RUNNING",
            )

            time.sleep(burst_duration)
            self.stop_attack(attacker)

            log_attack_event("BURST", attacker, target,
                             attack_rate=rate, duration=burst_duration, status="STOPPED")
            logger.info("[BURST] Burst complete: %s → %s", attacker, target)

        except Exception:
            logger.error("[launch_burst_attack] %s", traceback.format_exc())

    # ─── Stop Attack ──────────────────────────────────────────────────────────

    def stop_attack(self, attacker: str = None) -> None:
        """
        Stop all active attacks from a specific host (or all hosts).

        Sends SIGKILL to all tracked hping3/iperf PIDs on the host.

        Args:
            attacker: Host name to stop. If None, stops all attacking hosts.
        """
        targets = [attacker] if attacker else list(self._active_attacks.keys())

        for host_name in targets:
            host = self._get_host(host_name)
            if host is None:
                continue

            # Kill all tracked PIDs
            for pid in self._active_attacks.get(host_name, []):
                host.cmd(f"kill -9 {pid} 2>/dev/null")

            # Also blanket-kill hping3 processes on this host
            host.cmd("pkill -9 -f hping3 2>/dev/null")

            log_attack_event(
                attack_type = "ALL",
                source      = host_name,
                target      = "N/A",
                status      = "STOPPED",
            )
            logger.info("[stop_attack] Attack stopped on host %s", host_name)

        # Clear tracked PIDs for stopped hosts
        for host_name in targets:
            self._active_attacks.pop(host_name, None)

    def stop_all_attacks(self) -> None:
        """Stop ALL active attacks on all hosts."""
        self.stop_attack(attacker=None)
        logger.info("[AttackGenerator] All attacks stopped.")
