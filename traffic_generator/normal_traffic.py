"""
================================================================================
IntelliShield SDN — Phase 3: Traffic Generation & Attack Simulation Engine
================================================================================

File        : traffic_generator/normal_traffic.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 3 — Traffic Generation & Attack Simulation

Description:
    Generates realistic benign background traffic inside a Mininet environment.

    Supports 5 traffic types:
        1. ICMP   — ping-based round-trip traffic
        2. TCP    — iperf TCP throughput sessions
        3. UDP    — iperf UDP datagram streams
        4. HTTP   — lightweight Python HTTP server + wget requests
        5. Mixed  — parallel combination of the above

    Design:
        Each generator method accepts a Mininet `net` object and host names.
        Commands run in each host's network namespace via host.cmd().
        Background processes (iperf servers, HTTP servers) are tracked and
        can be stopped cleanly via stop_all_traffic().

    Integration:
        Called by TrafficScheduler (traffic_scheduler.py) during scenario
        execution. Can also be called directly from Mininet Python scripts.

IEEE Relevance:
    Realistic mixed-protocol background traffic is essential for baseline
    entropy measurement. Without baseline traffic, there is nothing to compare
    attack traffic against. These generators establish the "NORMAL" entropy
    baseline for Phase 2 detection and Phase 7 PPO reward computation.

Future Integration Points:
    - [HOOK] Phase 5 → HDBSCAN labels normal traffic clusters from this data
    - [HOOK] Phase 7 → PPO reward baseline uses normal entropy from this phase

================================================================================
"""

import time
import logging
import traceback
from typing import List, Optional, Any

from traffic_generator.traffic_profiles import (
    NormalTrafficProfile,
    NORMAL_PROFILES,
    DEFAULT_PING_COUNT,
    DEFAULT_PING_INTERVAL,
    DEFAULT_IPERF_DURATION,
    DEFAULT_HTTP_PORT,
)
from traffic_generator.traffic_logger import (
    init_traffic_logs,
    log_traffic_event,
)

logger = logging.getLogger("intellishield.normal_traffic")

# Track background server processes so we can terminate them
_server_pids: List[str] = []   # PIDs recorded as strings from host.cmd()


class NormalTrafficGenerator:
    """
    Generates controlled benign background traffic between Mininet hosts.

    Usage:
        from mininet.net import Mininet
        net = Mininet(...)
        net.start()

        gen = NormalTrafficGenerator(net)
        gen.generate_icmp_traffic(src="h1", dst="h2")
        gen.generate_tcp_traffic(server="h2", client="h1")
        gen.stop_all_traffic()
    """

    def __init__(self, net=None):
        """
        Args:
            net: Mininet net object. If None, must be set later via set_net().
        """
        self.net = net
        self._active_servers: dict = {}   # host_name → list of background PIDs
        init_traffic_logs()
        logger.info("[NormalTrafficGenerator] Initialised.")

    def set_net(self, net) -> None:
        """Set or update the Mininet net object after construction."""
        self.net = net

    def _get_host(self, name: str) -> Optional[Any]:
        """
        Retrieve a Mininet host object by name.

        Args:
            name: Host name string (e.g. "h1").

        Returns:
            Mininet host object, or None if not found.
        """
        if self.net is None:
            logger.error("[_get_host] No Mininet net object set.")
            return None
        try:
            return self.net.get(name)
        except Exception:
            logger.error("[_get_host] Host '%s' not found: %s", name, traceback.format_exc())
            return None

    def _host_ip(self, name: str) -> str:
        """Return the IP address of a Mininet host."""
        host = self._get_host(name)
        if host is None:
            return name   # Fallback: use name as IP
        return host.IP()

    # ─── ICMP Traffic ─────────────────────────────────────────────────────────

    def generate_icmp_traffic(self,
                               src: str,
                               dst: str,
                               count: int = DEFAULT_PING_COUNT,
                               interval: float = DEFAULT_PING_INTERVAL,
                               background: bool = False) -> str:
        """
        Generate ICMP ping traffic from src host to dst host.

        Args:
            src        : Source host name (e.g. "h1").
            dst        : Destination host name (e.g. "h2").
            count      : Number of ICMP echo requests to send.
            interval   : Seconds between packets.
            background : If True, run in background (non-blocking).

        Returns:
            str: Command output (if foreground) or empty string (background).

        Example:
            gen.generate_icmp_traffic("h1", "h2", count=100, interval=0.1)
        """
        try:
            src_host = self._get_host(src)
            dst_ip   = self._host_ip(dst)
            if src_host is None:
                return ""

            flag = "&" if background else ""
            cmd  = f"ping -c {count} -i {interval} {dst_ip} {flag}"

            log_traffic_event(
                traffic_type = "ICMP",
                source       = src,
                destination  = dst,
                protocol     = "ICMP",
                packet_rate  = round(1.0 / interval, 2),
                bandwidth    = "N/A",
                duration     = int(count * interval),
                status       = "STARTED",
            )
            logger.info("[ICMP] %s → %s  count=%d  interval=%ss",
                        src, dst, count, interval)

            output = src_host.cmd(cmd)

            log_traffic_event("ICMP", src, dst, "ICMP", status="STOPPED")
            return output

        except Exception:
            logger.error("[generate_icmp_traffic] %s", traceback.format_exc())
            log_traffic_event("ICMP", src, dst, "ICMP", status="ERROR")
            return ""

    def generate_continuous_icmp(self,
                                  src: str,
                                  dst: str,
                                  interval: float = DEFAULT_PING_INTERVAL) -> None:
        """
        Start a continuous background ping from src to dst.

        Runs indefinitely until stop_icmp() or stop_all_traffic() is called.

        Args:
            src     : Source host name.
            dst     : Destination host name.
            interval: Seconds between pings.
        """
        try:
            src_host = self._get_host(src)
            dst_ip   = self._host_ip(dst)
            if src_host is None:
                return

            cmd = f"ping -i {interval} {dst_ip} > /dev/null 2>&1 &"
            src_host.cmd(cmd)
            pid = src_host.cmd("echo $!").strip()

            self._active_servers.setdefault(src, []).append(pid)

            log_traffic_event(
                traffic_type = "ICMP_CONTINUOUS",
                source       = src,
                destination  = dst,
                protocol     = "ICMP",
                packet_rate  = round(1.0 / interval, 2),
                duration     = -1,
                status       = "RUNNING",
            )
            logger.info("[ICMP_CONTINUOUS] %s → %s  PID=%s", src, dst, pid)

        except Exception:
            logger.error("[generate_continuous_icmp] %s", traceback.format_exc())

    # ─── TCP Traffic ──────────────────────────────────────────────────────────

    def generate_tcp_traffic(self,
                              server: str,
                              client: str,
                              duration: int = DEFAULT_IPERF_DURATION,
                              parallel: int = 1) -> str:
        """
        Generate TCP throughput traffic using iperf client-server.

        Starts iperf server on `server`, runs iperf client from `client`.

        Args:
            server   : Host that runs the iperf server.
            client   : Host that runs the iperf client.
            duration : Test duration in seconds.
            parallel : Number of parallel TCP streams.

        Returns:
            str: iperf client output.
        """
        try:
            server_host = self._get_host(server)
            client_host = self._get_host(client)
            server_ip   = self._host_ip(server)

            if server_host is None or client_host is None:
                return ""

            # Start iperf server in background
            server_host.cmd("pkill -f 'iperf -s' 2>/dev/null; sleep 0.2")
            server_host.cmd("iperf -s -D")
            time.sleep(0.5)   # Give server time to bind

            log_traffic_event(
                traffic_type = "TCP",
                source       = client,
                destination  = server,
                protocol     = "TCP",
                bandwidth    = "max",
                duration     = duration,
                status       = "STARTED",
            )
            logger.info("[TCP] %s ← iperf server  |  %s → iperf client  dur=%ds",
                        server, client, duration)

            # Run iperf client (blocking)
            output = client_host.cmd(
                f"iperf -c {server_ip} -t {duration} -P {parallel}"
            )

            log_traffic_event("TCP", client, server, "TCP",
                               duration=duration, status="STOPPED")
            return output

        except Exception:
            logger.error("[generate_tcp_traffic] %s", traceback.format_exc())
            log_traffic_event("TCP", client, server, "TCP", status="ERROR")
            return ""

    # ─── UDP Traffic ──────────────────────────────────────────────────────────

    def generate_udp_traffic(self,
                              server: str,
                              client: str,
                              bandwidth: str = "1M",
                              duration: int = DEFAULT_IPERF_DURATION) -> str:
        """
        Generate UDP datagram traffic using iperf UDP mode.

        Args:
            server    : Host running the iperf UDP server.
            client    : Host sending UDP datagrams.
            bandwidth : Target bandwidth (e.g. "1M", "5M").
            duration  : Test duration in seconds.

        Returns:
            str: iperf client output.
        """
        try:
            server_host = self._get_host(server)
            client_host = self._get_host(client)
            server_ip   = self._host_ip(server)

            if server_host is None or client_host is None:
                return ""

            server_host.cmd("pkill -f 'iperf -s' 2>/dev/null; sleep 0.2")
            server_host.cmd("iperf -s -u -D")
            time.sleep(0.5)

            log_traffic_event(
                traffic_type = "UDP",
                source       = client,
                destination  = server,
                protocol     = "UDP",
                bandwidth    = bandwidth,
                duration     = duration,
                status       = "STARTED",
            )
            logger.info("[UDP] %s → %s  bw=%s  dur=%ds", client, server, bandwidth, duration)

            output = client_host.cmd(
                f"iperf -c {server_ip} -u -b {bandwidth} -t {duration}"
            )

            log_traffic_event("UDP", client, server, "UDP",
                               bandwidth=bandwidth, duration=duration, status="STOPPED")
            return output

        except Exception:
            logger.error("[generate_udp_traffic] %s", traceback.format_exc())
            log_traffic_event("UDP", client, server, "UDP", status="ERROR")
            return ""

    # ─── HTTP Traffic ─────────────────────────────────────────────────────────

    def generate_http_traffic(self,
                               server: str,
                               client: str,
                               port: int = DEFAULT_HTTP_PORT,
                               requests: int = 20) -> str:
        """
        Generate HTTP-like traffic using Python's SimpleHTTPServer + wget.

        Starts a lightweight Python HTTP server on `server`, then sends
        repeated wget requests from `client`. Simulates web browsing traffic.

        Args:
            server   : Host that serves HTTP content.
            client   : Host sending HTTP GET requests.
            port     : TCP port for HTTP server.
            requests : Number of GET requests to send.

        Returns:
            str: Combined wget output.
        """
        try:
            server_host = self._get_host(server)
            client_host = self._get_host(client)
            server_ip   = self._host_ip(server)

            if server_host is None or client_host is None:
                return ""

            # Start lightweight HTTP server in background
            server_host.cmd(
                f"cd /tmp && python3 -m http.server {port} "
                f"> /dev/null 2>&1 &"
            )
            pid = server_host.cmd("echo $!").strip()
            self._active_servers.setdefault(server, []).append(pid)
            time.sleep(0.5)

            log_traffic_event(
                traffic_type = "HTTP",
                source       = client,
                destination  = server,
                protocol     = "TCP/HTTP",
                duration     = requests,
                status       = "STARTED",
            )
            logger.info("[HTTP] %s serves on port %d  |  %s sends %d requests",
                        server, port, client, requests)

            outputs = []
            for i in range(requests):
                out = client_host.cmd(
                    f"wget -q -O /dev/null http://{server_ip}:{port}/ 2>&1"
                )
                outputs.append(out)
                time.sleep(0.3)

            # Stop HTTP server
            server_host.cmd(f"kill {pid} 2>/dev/null")

            log_traffic_event("HTTP", client, server, "TCP/HTTP",
                               duration=requests, status="STOPPED")
            return "\n".join(outputs)

        except Exception:
            logger.error("[generate_http_traffic] %s", traceback.format_exc())
            log_traffic_event("HTTP", client, server, "TCP/HTTP", status="ERROR")
            return ""

    # ─── Mixed Traffic ────────────────────────────────────────────────────────

    def generate_mixed_traffic(self,
                                hosts: List[str],
                                profile: NormalTrafficProfile = None,
                                duration: int = 30) -> None:
        """
        Generate a mix of ICMP, TCP, and UDP traffic across multiple hosts.

        Selects random host pairs and launches multiple traffic types
        simultaneously in the background. This creates diverse, realistic
        baseline traffic that produces high entropy values.

        Args:
            hosts   : List of host names to use (e.g. ["h1","h2","h3"]).
            profile : NormalTrafficProfile to use (defaults to MEDIUM).
            duration: How long to run mixed traffic in seconds.
        """
        if profile is None:
            from traffic_generator.traffic_profiles import PROFILE_NORMAL_MEDIUM
            profile = PROFILE_NORMAL_MEDIUM

        if len(hosts) < 2:
            logger.warning("[generate_mixed_traffic] Need at least 2 hosts.")
            return

        log_traffic_event(
            traffic_type = "MIXED",
            source       = "+".join(hosts),
            destination  = "all",
            protocol     = ",".join(profile.mixed_protocols),
            duration     = duration,
            status       = "STARTED",
        )
        logger.info("[MIXED] Starting mixed traffic: protocols=%s hosts=%s dur=%ds",
                    profile.mixed_protocols, hosts, duration)

        # ICMP: h1→h2, h2→h3, h3→h4, etc. (ring)
        if "icmp" in profile.mixed_protocols:
            for i in range(len(hosts)):
                src = hosts[i]
                dst = hosts[(i + 1) % len(hosts)]
                self.generate_continuous_icmp(src, dst, profile.ping_interval)

        # TCP: h1 → h2 iperf (background using &)
        if "tcp" in profile.mixed_protocols and len(hosts) >= 2:
            server_h = self._get_host(hosts[0])
            client_h = self._get_host(hosts[1])
            if server_h and client_h:
                server_h.cmd("pkill -f 'iperf -s' 2>/dev/null; sleep 0.1")
                server_h.cmd("iperf -s -D")
                time.sleep(0.3)
                client_h.cmd(
                    f"iperf -c {server_h.IP()} -t {duration} -P "
                    f"{profile.tcp_connections} > /dev/null 2>&1 &"
                )

        # UDP: h3 → h4 iperf UDP (background)
        if "udp" in profile.mixed_protocols and len(hosts) >= 4:
            udp_srv = self._get_host(hosts[2])
            udp_cli = self._get_host(hosts[3])
            if udp_srv and udp_cli:
                udp_srv.cmd("iperf -s -u -D")
                time.sleep(0.3)
                udp_cli.cmd(
                    f"iperf -c {udp_srv.IP()} -u -b {profile.udp_bandwidth} "
                    f"-t {duration} > /dev/null 2>&1 &"
                )

        logger.info("[MIXED] Mixed traffic running for %d seconds.", duration)
        time.sleep(duration)
        self.stop_all_traffic(hosts)

    # ─── Cleanup ──────────────────────────────────────────────────────────────

    def stop_all_traffic(self, hosts: List[str] = None) -> None:
        """
        Stop all background traffic generators and servers.

        Args:
            hosts: List of host names to clean up. If None, uses
                   all hosts tracked by this generator.
        """
        targets = hosts or list(self._active_servers.keys())

        for host_name in targets:
            host = self._get_host(host_name)
            if host is None:
                continue
            # Kill iperf, ping, wget, HTTP servers
            host.cmd("pkill -f iperf 2>/dev/null")
            host.cmd("pkill -f ping  2>/dev/null")
            host.cmd("pkill -f wget  2>/dev/null")
            host.cmd("pkill -f 'http.server' 2>/dev/null")
            logger.info("[stop_all_traffic] Cleaned up host %s", host_name)

        self._active_servers.clear()
        log_traffic_event("ALL", "all", "all", "ALL", status="STOPPED")
        logger.info("[NormalTrafficGenerator] All traffic stopped.")
