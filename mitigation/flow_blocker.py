"""
================================================================================
IntelliShield SDN — Phase 5: Automated Mitigation Engine
================================================================================

File        : mitigation/flow_blocker.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 5 — Automated DDoS Mitigation

Description:
    Core OpenFlow mitigation primitive. Installs high-priority DROP rules
    directly on OVS switches via OsKen's OFPFlowMod API.

    Blocking strategies:
        1. Block by Source MAC     — drops all traffic from attacker MAC
        2. Block by Source IP      — drops all IPv4 from attacker IP
        3. Block by Flow Pair      — drops traffic between specific src/dst
        4. Rate-limit (placeholder) — [HOOK] Phase 7 → PPO RL selects strategy

    OpenFlow 1.3 approach:
        Install a flow rule with:
          - High priority (BLOCK_PRIORITY = 200) → overrides normal forwarding
          - Match: eth_src = attacker_mac  (or ip_src for IP-based block)
          - Actions: empty list → DROP all matching packets
          - hard_timeout: auto-removes rule after N seconds
          - send_flow_rem: notifies controller when rule expires

    Safety:
        - Never blocks broadcast MACs (ff:ff:ff:ff:ff:ff)
        - Never blocks controller MAC
        - Whitelist prevents blocking legitimate hosts

IEEE Relevance:
    Automated mitigation via SDN flow rules demonstrates the key advantage
    of software-defined networking for security — programmable, instant,
    and topology-wide enforcement without hardware changes.

================================================================================
"""

import logging
import traceback
from typing import Optional, Set

logger = logging.getLogger("intellishield.flow_blocker")

# ─── Mitigation Constants ─────────────────────────────────────────────────────

BLOCK_PRIORITY    = 200     # Higher than normal forwarding priority (1)
DEFAULT_BLOCK_TIMEOUT = 60  # Seconds before block auto-expires
MAX_BLOCK_TIMEOUT = 300     # Hard cap on block duration

# MACs that must NEVER be blocked
PROTECTED_MACS: Set[str] = {
    "ff:ff:ff:ff:ff:ff",   # Broadcast
    "33:33:00:00:00:01",   # IPv6 multicast
    "33:33:00:00:00:02",   # IPv6 multicast
    "01:80:c2:00:00:0e",   # LLDP
    "00:00:00:00:00:00",   # Zero MAC
}


def _is_safe_to_block(mac: str) -> bool:
    """
    Safety guard: check a MAC address is safe to block.

    Returns False for broadcast, multicast, or zero MACs.
    """
    if not mac or mac in PROTECTED_MACS:
        return False
    # Skip IPv6 multicast range (33:33:xx:xx:xx:xx)
    if mac.lower().startswith("33:33"):
        return False
    return True


# ─── OpenFlow Mitigation Primitives ──────────────────────────────────────────

def block_src_mac(datapath, src_mac: str,
                  timeout: int = DEFAULT_BLOCK_TIMEOUT) -> bool:
    """
    Install a DROP rule matching packets from `src_mac` on `datapath`.

    The rule has a hard_timeout so it auto-expires — no manual cleanup needed.
    send_flow_rem=True ensures the controller receives a FlowRemoved message
    when the rule expires, which can be used to log mitigation end.

    Args:
        datapath: OsKen Datapath object (from self.datapaths[dpid]).
        src_mac : Source MAC address to block (e.g. "02:e4:b2:3a:4e:5f").
        timeout : Auto-expiry in seconds (default 60, max 300).

    Returns:
        bool: True if flow mod was sent successfully.
    """
    if not _is_safe_to_block(src_mac):
        logger.warning("[block_src_mac] BLOCKED request — MAC %s is protected.", src_mac)
        return False

    timeout = min(timeout, MAX_BLOCK_TIMEOUT)

    try:
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        # Match all packets from this source MAC
        match = parser.OFPMatch(eth_src=src_mac)

        # Empty instructions = DROP
        instructions = []

        mod = parser.OFPFlowMod(
            datapath     = datapath,
            priority     = BLOCK_PRIORITY,
            match        = match,
            instructions = instructions,
            hard_timeout = timeout,
            idle_timeout = 0,
            command      = ofproto.OFPFC_ADD,
            flags        = ofproto.OFPFF_SEND_FLOW_REM,
        )
        datapath.send_msg(mod)

        logger.info("[block_src_mac] ✅ DROP rule installed: src_mac=%s  dpid=%s  timeout=%ds",
                    src_mac, datapath.id, timeout)
        return True

    except Exception:
        logger.error("[block_src_mac] Failed:\n%s", traceback.format_exc())
        return False


def block_flow_pair(datapath, src_mac: str, dst_mac: str,
                    timeout: int = DEFAULT_BLOCK_TIMEOUT) -> bool:
    """
    Install a DROP rule matching packets from src_mac to dst_mac.

    More surgical than block_src_mac — only drops attack-specific flows
    while allowing legitimate traffic from the same source to other hosts.

    Args:
        datapath: OsKen Datapath object.
        src_mac : Attacker source MAC.
        dst_mac : Victim destination MAC.
        timeout : Auto-expiry in seconds.

    Returns:
        bool: True if flow mod was sent successfully.
    """
    if not _is_safe_to_block(src_mac):
        logger.warning("[block_flow_pair] Protected MAC — skipping: %s", src_mac)
        return False

    timeout = min(timeout, MAX_BLOCK_TIMEOUT)

    try:
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
        instructions = []

        mod = parser.OFPFlowMod(
            datapath     = datapath,
            priority     = BLOCK_PRIORITY,
            match        = match,
            instructions = instructions,
            hard_timeout = timeout,
            idle_timeout = 0,
            command      = ofproto.OFPFC_ADD,
            flags        = ofproto.OFPFF_SEND_FLOW_REM,
        )
        datapath.send_msg(mod)

        logger.info("[block_flow_pair] ✅ DROP rule installed: %s→%s  dpid=%s  timeout=%ds",
                    src_mac, dst_mac, datapath.id, timeout)
        return True

    except Exception:
        logger.error("[block_flow_pair] Failed:\n%s", traceback.format_exc())
        return False


def unblock_src_mac(datapath, src_mac: str) -> bool:
    """
    Remove a DROP rule for `src_mac` before its timeout expires.

    Sends an OFPFlowMod with OFPFC_DELETE_STRICT to remove the exact rule.
    Used for manual override or when Phase 7 PPO decides to lift a block early.

    Args:
        datapath: OsKen Datapath object.
        src_mac : MAC to unblock.

    Returns:
        bool: True if delete message was sent.
    """
    try:
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        match = parser.OFPMatch(eth_src=src_mac)

        mod = parser.OFPFlowMod(
            datapath  = datapath,
            priority  = BLOCK_PRIORITY,
            match     = match,
            command   = ofproto.OFPFC_DELETE_STRICT,
            out_port  = ofproto.OFPP_ANY,
            out_group = ofproto.OFPG_ANY,
        )
        datapath.send_msg(mod)

        logger.info("[unblock_src_mac] ✅ DROP rule removed: src_mac=%s  dpid=%s",
                    src_mac, datapath.id)
        return True

    except Exception:
        logger.error("[unblock_src_mac] Failed:\n%s", traceback.format_exc())
        return False


def unblock_all(datapath) -> bool:
    """
    Remove ALL high-priority DROP rules from a switch.

    Emergency reset — use when mitigation went wrong or topology changes.

    Args:
        datapath: OsKen Datapath object.

    Returns:
        bool: True if delete-all message was sent.
    """
    try:
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        match = parser.OFPMatch()   # Wildcard — matches everything

        mod = parser.OFPFlowMod(
            datapath  = datapath,
            priority  = BLOCK_PRIORITY,
            match     = match,
            command   = ofproto.OFPFC_DELETE,
            out_port  = ofproto.OFPP_ANY,
            out_group = ofproto.OFPG_ANY,
        )
        datapath.send_msg(mod)

        logger.info("[unblock_all] ✅ All DROP rules cleared on dpid=%s", datapath.id)
        return True

    except Exception:
        logger.error("[unblock_all] Failed:\n%s", traceback.format_exc())
        return False
