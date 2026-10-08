"""
================================================================================
IntelliShield SDN — Phase 3: Traffic Generation & Attack Simulation Engine
================================================================================

File        : traffic_generator/traffic_scheduler.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 3 — Traffic Generation & Attack Simulation

Description:
    Main experiment orchestrator and standalone entry point for Phase 3.

    Two usage modes:
        1. STANDALONE — Creates its own Mininet topology with RemoteController,
           runs a selected scenario, and tears down cleanly. Run with:
               sudo python3 traffic_generator/traffic_scheduler.py --scenario 2

        2. LIBRARY — Imported by other scripts. Pass an existing Mininet net
           object to TrafficScheduler(net=net) and call run_scenario().

    The scheduler also implements a timed event system: given a scenario
    template (from traffic_profiles.SCENARIO_TEMPLATES), it executes events
    at precise time offsets using threading.Timer.

IEEE Relevance:
    Fully automated experiment execution is a requirement for IEEE prototype
    evaluation — it ensures that every run of "Scenario 2" is identical,
    making results reproducible and citable.

================================================================================
"""

import sys
import os
import time
import logging
import argparse
import traceback
import threading
import subprocess
from typing import Optional, List, Dict, Any

# ─── Logging Setup ────────────────────────────────────────────────────────────

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s  %(levelname)-7s  %(name)s — %(message)s",
    datefmt= "%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("intellishield.traffic_scheduler")


# ─── Mininet Imports (guarded) ────────────────────────────────────────────────

try:
    from mininet.net         import Mininet
    from mininet.node        import RemoteController, OVSSwitch
    from mininet.topo        import Topo
    from mininet.link        import TCLink
    from mininet.log         import setLogLevel
    from mininet.cli         import CLI
    _MININET_AVAILABLE = True
except ImportError:
    _MININET_AVAILABLE = False
    logger.warning("[TrafficScheduler] Mininet not importable — library mode only.")


# ─── Internal Imports ─────────────────────────────────────────────────────────

from traffic_generator.traffic_profiles import (
    SCENARIO_TEMPLATES,
    NORMAL_PROFILES,
    ATTACK_PROFILES,
    CONTROLLER_HOST,
    CONTROLLER_PORT,
)
from traffic_generator.normal_traffic   import NormalTrafficGenerator
from traffic_generator.attack_generator import AttackGenerator
from traffic_generator.attack_scenarios import (
    SCENARIO_REGISTRY,
    run_scenario,
)
from traffic_generator.traffic_logger   import (
    init_traffic_logs,
    log_scenario_event,
)


def _cleanup_stale_mininet() -> None:
    """
    Best-effort cleanup before creating a new Mininet topology.

    Prevents RTNETLINK 'File exists' when a previous Mininet / background
    lab topology left OVS bridges or veth pairs behind.
    """
    try:
        subprocess.run(
            ["pkill", "-f", "start_mininet_bg.py"],
            capture_output=True,
            timeout=5,
        )
    except Exception:
        pass
    try:
        # mn -c requires root when invoked from sudo traffic_scheduler
        subprocess.run(
            ["mn", "-c"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        logger.info("[start_mininet] Cleared stale Mininet/OVS state (mn -c).")
    except Exception as exc:
        logger.warning("[start_mininet] mn -c cleanup skipped/failed: %s", exc)
    time.sleep(1)


# ─── Custom Topology ──────────────────────────────────────────────────────────

if _MININET_AVAILABLE:

    class IntelliShieldTopo(Topo):
        """
        Default Mininet topology for IntelliShield experiments.

        Creates:
            1 switch (s1) connected to N hosts (h1...hN)
            All links use default bandwidth (no TCLink cap for flood tests)

        Default: 5 hosts — enough for diverse traffic entropy while staying
        lightweight on a single VM.
        """

        def build(self, n_hosts: int = 5, **opts):
            """
            Build a star topology: 1 switch, n_hosts hosts.

            Args:
                n_hosts: Number of hosts to create (default 5).
            """
            switch = self.addSwitch("s1")
            for i in range(1, n_hosts + 1):
                host = self.addHost(f"h{i}")
                self.addLink(host, switch)

else:
    IntelliShieldTopo = None  # type: ignore[misc, assignment]


# ─── Traffic Scheduler ────────────────────────────────────────────────────────

class TrafficScheduler:
    """
    IntelliShield SDN — Traffic and Attack Scheduler.

    Orchestrates timed experiment execution from scenario templates.
    Can run in standalone or library mode.

    Example (standalone):
        scheduler = TrafficScheduler()
        scheduler.start_mininet(n_hosts=5)
        scheduler.run_scenario("2")
        scheduler.stop_mininet()

    Example (library — existing net):
        scheduler = TrafficScheduler(net=existing_net)
        scheduler.run_scenario("3")
    """

    def __init__(self, net=None):
        """
        Args:
            net: Optional existing Mininet net object.
                 If None, call start_mininet() to create one.
        """
        self.net    = net
        self._gen   = None
        self._atk   = None
        self._timers: List[threading.Timer] = []

        init_traffic_logs()
        logger.info("[TrafficScheduler] Initialised.")

    # ─── Mininet Lifecycle ────────────────────────────────────────────────────

    def start_mininet(self,
                      n_hosts: int = 5,
                      controller_host: str = CONTROLLER_HOST,
                      controller_port: int = CONTROLLER_PORT) -> bool:
        """
        Start a Mininet instance with IntelliShieldTopo and RemoteController.

        IMPORTANT: The OsKen flow_monitor.py controller must be running
        BEFORE calling this method.

        Args:
            n_hosts         : Number of hosts in the topology.
            controller_host : OsKen controller IP (default 127.0.0.1).
            controller_port : OsKen controller port (default 6653).

        Returns:
            bool: True if Mininet started successfully.
        """
        if not _MININET_AVAILABLE:
            logger.error("[start_mininet] Mininet not available.")
            return False

        # Clear leftover topologies (background mn / failed runs) before create.
        _cleanup_stale_mininet()

        try:
            setLogLevel("warning")
            topo = IntelliShieldTopo(n_hosts=n_hosts)

            self.net = Mininet(
                topo       = topo,
                controller = RemoteController(
                    "c0",
                    ip   = controller_host,
                    port = controller_port,
                ),
                switch     = OVSSwitch,
                autoSetMacs= True,
            )

            self.net.start()
            time.sleep(2)   # Allow controller to install table-miss flows

            hosts = [h.name for h in self.net.hosts]
            logger.info("[start_mininet] Topology started: %d hosts %s", n_hosts, hosts)
            logger.info("[start_mininet] Controller: %s:%d", controller_host, controller_port)

            # Verify basic connectivity
            logger.info("[start_mininet] Testing connectivity (pingAll) ...")
            loss = self.net.pingAll(timeout="2")
            logger.info("[start_mininet] Ping loss: %.1f%%", loss)

            return True

        except Exception:
            logger.error("[start_mininet] Failed:\n%s", traceback.format_exc())
            return False

    def stop_mininet(self) -> None:
        """Stop the Mininet instance and clean up all processes."""
        if self.net is not None:
            try:
                # Stop all traffic first
                if self._gen:
                    self._gen.stop_all_traffic()
                if self._atk:
                    self._atk.stop_all_attacks()
                self.net.stop()
                logger.info("[stop_mininet] Mininet stopped cleanly.")
            except Exception:
                logger.error("[stop_mininet] %s", traceback.format_exc())

    # ─── Scenario Execution ───────────────────────────────────────────────────

    def run_scenario(self, scenario_id: str) -> None:
        """
        Execute a predefined experiment scenario by ID.

        Args:
            scenario_id: "1" through "5"
        """
        if self.net is None:
            logger.error("[run_scenario] No Mininet net. Call start_mininet() first.")
            return

        log_scenario_event(
            scenario_name = f"SCENARIO_{scenario_id}",
            event_type    = "SCHEDULER_DISPATCH",
            description   = f"Dispatching scenario {scenario_id}",
        )
        run_scenario(self.net, scenario_id)

    def run_all_scenarios(self, scenario_ids: List[str] = None,
                           gap_sec: int = 15) -> None:
        """
        Run multiple scenarios sequentially with a gap between them.

        Args:
            scenario_ids: List of scenario ID strings. Defaults to ["1","2","3"].
            gap_sec     : Seconds to wait between scenarios.
        """
        ids = scenario_ids or ["1", "2", "3"]
        logger.info("[run_all_scenarios] Running scenarios: %s  gap=%ds", ids, gap_sec)

        for sid in ids:
            logger.info("[run_all_scenarios] ─── Starting Scenario %s ───", sid)
            self.run_scenario(sid)
            if sid != ids[-1]:
                logger.info("[run_all_scenarios] Waiting %ds before next scenario...", gap_sec)
                time.sleep(gap_sec)

        logger.info("[run_all_scenarios] All scenarios complete.")

    # ─── Template-Based Scheduling ────────────────────────────────────────────

    def run_template(self, template_name: str) -> None:
        """
        Execute a scenario from the SCENARIO_TEMPLATES dict in traffic_profiles.

        Template events are dispatched at their defined time offsets using
        threading.Timer so the main thread doesn't block.

        Args:
            template_name: Key in SCENARIO_TEMPLATES dict.
        """
        template = SCENARIO_TEMPLATES.get(template_name)
        if template is None:
            logger.error("[run_template] Unknown template: '%s'", template_name)
            return

        if self.net is None:
            logger.error("[run_template] No Mininet net.")
            return

        self._gen = NormalTrafficGenerator(self.net)
        self._atk = AttackGenerator(self.net)
        hosts     = [h.name for h in self.net.hosts]

        logger.info("[run_template] Executing: %s  events=%d",
                    template_name, len(template))
        log_scenario_event(template_name, "TEMPLATE_START",
                           f"Template execution: {len(template)} events")

        self._timers = []
        max_t = 0

        for event in template:
            t      = event["t"]
            action = event["action"]
            params = event.get("params", {})
            max_t  = max(max_t, t)

            timer = threading.Timer(
                t,
                self._dispatch_event,
                args=(template_name, action, params, hosts),
            )
            timer.start()
            self._timers.append(timer)

        # Wait for all events to complete
        time.sleep(max_t + 5)
        self._cancel_timers()
        log_scenario_event(template_name, "TEMPLATE_END", "Template complete")

    def _dispatch_event(self, template_name: str, action: str,
                        params: dict, hosts: List[str]) -> None:
        """Dispatch a single template event action."""
        try:
            logger.info("[dispatch_event] t+now  action=%s  params=%s", action, params)

            if action == "start_normal":
                profile_key = params.get("profile", "MEDIUM")
                profile     = NORMAL_PROFILES.get(profile_key)
                self._gen.generate_continuous_icmp(hosts[0], hosts[1])
                if len(hosts) > 2:
                    self._gen.generate_continuous_icmp(hosts[2], hosts[0])
                log_scenario_event(template_name, "NORMAL_START",
                                   f"Normal traffic: profile={profile_key}")

            elif action == "start_attack":
                profile_key = params.get("profile", "SYN_FLOOD_HIGH")
                profile     = ATTACK_PROFILES.get(profile_key)
                if profile is None:
                    return
                attacker = hosts[0]
                target   = hosts[1]

                if profile.attack_type == "SYN_FLOOD":
                    self._atk.launch_syn_flood(attacker, target,
                                               rate=profile.syn_rate,
                                               duration=profile.duration)
                elif profile.attack_type == "UDP_FLOOD":
                    self._atk.launch_udp_flood(attacker, target,
                                               bandwidth=profile.udp_bandwidth)
                elif profile.attack_type == "ICMP_FLOOD":
                    self._atk.launch_icmp_flood(attacker, target,
                                                rate=profile.icmp_rate)
                elif profile.attack_type == "BURST":
                    self._atk.launch_burst_attack(attacker, target,
                                                  burst_duration=profile.burst_duration)

                log_scenario_event(template_name, "ATTACK_START",
                                   f"Attack: {profile.attack_type}")

            elif action == "stop_attack":
                self._atk.stop_all_attacks()
                log_scenario_event(template_name, "ATTACK_STOP", "Attack stopped")

            elif action == "stop_all":
                self._atk.stop_all_attacks()
                self._gen.stop_all_traffic(hosts)
                log_scenario_event(template_name, "STOP_ALL", "All traffic stopped")

        except Exception:
            logger.error("[_dispatch_event] Error: %s", traceback.format_exc())

    def _cancel_timers(self) -> None:
        for t in self._timers:
            t.cancel()
        self._timers.clear()


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="IntelliShield SDN — Traffic Scheduler (Phase 3)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scenarios:
  1 — Normal traffic baseline only (60s)
  2 — SYN flood attack (baseline 20s + attack 30s)
  3 — UDP flood attack (baseline 20s + attack 30s)
  4 — Burst attack (15s baseline + 8s burst)
  5 — Mixed SYN + UDP sequential attacks

Examples:
  sudo python3 -m traffic_generator.traffic_scheduler --scenario 2
  sudo python3 -m traffic_generator.traffic_scheduler --scenario 5 --hosts 5
  sudo python3 -m traffic_generator.traffic_scheduler --all
        """,
    )
    parser.add_argument(
        "--scenario", "-s", type=str, default="2",
        help="Scenario ID to run (1-5). Default: 2",
    )
    parser.add_argument(
        "--hosts", "-n", type=int, default=5,
        help="Number of Mininet hosts (default 5).",
    )
    parser.add_argument(
        "--controller-ip", type=str, default=CONTROLLER_HOST,
        help=f"OsKen controller IP (default {CONTROLLER_HOST}).",
    )
    parser.add_argument(
        "--controller-port", type=int, default=CONTROLLER_PORT,
        help=f"OsKen controller port (default {CONTROLLER_PORT}).",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Run all scenarios sequentially.",
    )
    parser.add_argument(
        "--cli", action="store_true",
        help="Drop into Mininet CLI after scenario completes.",
    )
    return parser.parse_args()


def main():
    args    = parse_args()
    sched   = TrafficScheduler()

    print("\n" + "=" * 60)
    print("  IntelliShield SDN — Traffic Scheduler v1.0")
    print("  Phase 3: Traffic Generation & Attack Simulation")
    print("=" * 60)

    if not sched.start_mininet(
        n_hosts         = args.hosts,
        controller_host = args.controller_ip,
        controller_port = args.controller_port,
    ):
        logger.error("Failed to start Mininet. Is the controller running?")
        sys.exit(1)

    try:
        if args.all:
            sched.run_all_scenarios(["1", "2", "3", "4", "5"], gap_sec=15)
        else:
            sched.run_scenario(args.scenario)

        if args.cli and _MININET_AVAILABLE:
            logger.info("Dropping into Mininet CLI...")
            CLI(sched.net)

    except KeyboardInterrupt:
        logger.info("\n[main] Interrupted by user.")
    except Exception:
        logger.error("[main] Fatal error:\n%s", traceback.format_exc())
    finally:
        sched.stop_mininet()
        print("\n[TrafficScheduler] Session complete. Check logs/")


if __name__ == "__main__":
    main()
