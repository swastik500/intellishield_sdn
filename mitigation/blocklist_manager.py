"""
================================================================================
IntelliShield SDN — Phase 5: Automated Mitigation Engine
================================================================================

File        : mitigation/blocklist_manager.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 5 — Automated DDoS Mitigation

Description:
    In-memory blocklist with expiry tracking, whitelist enforcement,
    and per-switch state management.

    Responsibilities:
        - Track which MACs are currently blocked (per switch)
        - Track block timestamps and expiry times
        - Prevent duplicate blocks (same MAC already blocked)
        - Enforce whitelist (legitimate hosts never blocked)
        - Support manual unblock requests
        - Provide current block status queries

    Thread safety:
        Uses a simple threading.Lock since OsKen greenlets run cooperatively
        and real thread contention is minimal. Lock is still applied for safety.

    Data structures:
        _blocks: {dpid → {mac → BlockRecord}}

Future Integration:
    - [HOOK] Phase 7 → PPO RL queries block_count and avg_duration per dpid
    - [HOOK] Phase 8 → Dashboard reads active_blocks() for live display

================================================================================
"""

import time
import logging
import threading
from datetime import datetime
from typing import Dict, Optional, List, Set
from dataclasses import dataclass, field

logger = logging.getLogger("intellishield.blocklist_manager")


@dataclass
class BlockRecord:
    """Represents one active or expired block entry."""
    mac           : str
    dpid          : int
    block_time    : float   = field(default_factory=time.time)
    timeout_sec   : int     = 60
    block_type    : str     = "SRC_MAC"      # SRC_MAC | FLOW_PAIR
    attack_hint   : str     = "UNKNOWN"
    confidence    : float   = 0.0
    dst_mac       : str     = ""             # Only for FLOW_PAIR blocks
    expired       : bool    = False

    @property
    def expires_at(self) -> float:
        return self.block_time + self.timeout_sec

    @property
    def remaining_sec(self) -> float:
        return max(0.0, self.expires_at - time.time())

    @property
    def is_active(self) -> bool:
        return not self.expired and time.time() < self.expires_at

    @property
    def block_time_str(self) -> str:
        return datetime.fromtimestamp(self.block_time).strftime("%Y-%m-%d %H:%M:%S")


class BlocklistManager:
    """
    Manages the per-switch blocklist of actively blocked source MACs.

    Usage:
        manager = BlocklistManager()
        manager.add_whitelist(["00:00:00:00:00:01"])   # controller MAC

        if manager.should_block(dpid=1, mac="02:e4:xx:xx:xx:xx"):
            # Block logic
            manager.record_block(dpid=1, mac="02:e4:xx:xx:xx:xx", timeout=60)

        if manager.is_blocked(dpid=1, mac="02:e4:xx:xx:xx:xx"):
            print("Still blocked")
    """

    def __init__(self):
        self._blocks: Dict[int, Dict[str, BlockRecord]] = {}
        self._whitelist: Set[str] = set()
        self._lock = threading.Lock()
        self._total_blocks = 0       # Lifetime counter for stats

        # Add default protected MACs to whitelist
        from mitigation.flow_blocker import PROTECTED_MACS
        self._whitelist.update(PROTECTED_MACS)

        logger.info("[BlocklistManager] Initialised.")

    # ─── Whitelist ────────────────────────────────────────────────────────────

    def add_whitelist(self, macs: List[str]) -> None:
        """Add MAC addresses that should never be blocked."""
        with self._lock:
            for mac in macs:
                self._whitelist.add(mac.lower())
        logger.info("[BlocklistManager] Whitelist updated: %s", macs)

    def is_whitelisted(self, mac: str) -> bool:
        """Return True if MAC is on the permanent whitelist."""
        return mac.lower() in self._whitelist

    # ─── Block Decision ───────────────────────────────────────────────────────

    def should_block(self, dpid: int, mac: str) -> bool:
        """
        Determine whether a MAC should be blocked right now.

        Returns False if:
          - MAC is whitelisted
          - MAC is already actively blocked (avoid duplicate FlowMods)

        Args:
            dpid: Switch datapath ID.
            mac : Source MAC to check.

        Returns:
            bool: True if we should install a new block rule.
        """
        if self.is_whitelisted(mac):
            logger.debug("[should_block] %s is whitelisted — skip.", mac)
            return False

        if self.is_blocked(dpid, mac):
            logger.debug("[should_block] %s already blocked on dpid=%d — skip.", mac, dpid)
            return False

        return True

    def is_blocked(self, dpid: int, mac: str) -> bool:
        """Return True if MAC is currently actively blocked on this switch."""
        with self._lock:
            record = self._blocks.get(dpid, {}).get(mac)
            if record is None:
                return False
            if not record.is_active:
                record.expired = True
                return False
            return True

    # ─── Block Recording ──────────────────────────────────────────────────────

    def record_block(self,
                     dpid       : int,
                     mac        : str,
                     timeout_sec: int   = 60,
                     block_type : str   = "SRC_MAC",
                     attack_hint: str   = "UNKNOWN",
                     confidence : float = 0.0,
                     dst_mac    : str   = "") -> BlockRecord:
        """
        Record a new block entry in the in-memory blocklist.

        Call AFTER installing the OpenFlow DROP rule.

        Args:
            dpid       : Switch datapath ID.
            mac        : Blocked source MAC.
            timeout_sec: Duration of block in seconds.
            block_type : "SRC_MAC" or "FLOW_PAIR".
            attack_hint: Attack type from Phase 4 Explainer.
            confidence : Detection confidence (0–100).
            dst_mac    : For FLOW_PAIR blocks — victim MAC.

        Returns:
            BlockRecord: The new block record.
        """
        record = BlockRecord(
            mac         = mac,
            dpid        = dpid,
            timeout_sec = timeout_sec,
            block_type  = block_type,
            attack_hint = attack_hint,
            confidence  = confidence,
            dst_mac     = dst_mac,
        )

        with self._lock:
            self._blocks.setdefault(dpid, {})[mac] = record
            self._total_blocks += 1

        logger.info("[record_block] Recorded: dpid=%d  mac=%s  type=%s  timeout=%ds  hint=%s",
                    dpid, mac, block_type, timeout_sec, attack_hint)
        return record

    def record_unblock(self, dpid: int, mac: str) -> bool:
        """
        Mark a block record as expired (manual unblock).

        Args:
            dpid: Switch datapath ID.
            mac : MAC to unblock.

        Returns:
            bool: True if record found and marked.
        """
        with self._lock:
            record = self._blocks.get(dpid, {}).get(mac)
            if record:
                record.expired = True
                logger.info("[record_unblock] Marked expired: dpid=%d  mac=%s", dpid, mac)
                return True
        return False

    # ─── Queries ──────────────────────────────────────────────────────────────

    def active_blocks(self, dpid: int = None) -> List[BlockRecord]:
        """
        Return all currently active block records.

        Args:
            dpid: If given, filter to this switch only.

        Returns:
            List of active BlockRecord objects.
        """
        result = []
        with self._lock:
            switches = [dpid] if dpid else list(self._blocks.keys())
            for sw in switches:
                for record in self._blocks.get(sw, {}).values():
                    if record.is_active:
                        result.append(record)
        return result

    def expired_blocks(self, dpid: int = None) -> List[BlockRecord]:
        """Return all expired (past) block records for history/logs."""
        result = []
        with self._lock:
            switches = [dpid] if dpid else list(self._blocks.keys())
            for sw in switches:
                for record in self._blocks.get(sw, {}).values():
                    if not record.is_active:
                        result.append(record)
        return result

    def get_stats(self) -> dict:
        """
        Return summary statistics for the current session.

        [HOOK] Phase 7 → PPO RL reads these for reward computation.
        [HOOK] Phase 8 → Dashboard displays these metrics live.
        """
        active   = self.active_blocks()
        expired  = self.expired_blocks()
        return {
            "total_blocks_ever"   : self._total_blocks,
            "currently_blocked"   : len(active),
            "expired_blocks"      : len(expired),
            "whitelisted_macs"    : len(self._whitelist),
            "active_switches"     : len(self._blocks),
            "active_block_macs"   : [r.mac for r in active],
        }

    def print_status(self) -> None:
        """Print current blocklist status to console."""
        active = self.active_blocks()
        border = "=" * 56
        print(f"\n{border}")
        print(f"  [BLOCKLIST STATUS]  Active blocks: {len(active)}")
        print(f"{border}")
        if not active:
            print("  No active blocks.")
        else:
            for r in active:
                print(f"  🚫 MAC: {r.mac:<20}  dpid={r.dpid}  "
                      f"remaining={r.remaining_sec:.0f}s  hint={r.attack_hint}")
        print(f"  Total blocks this session: {self._total_blocks}")
        print(f"{border}\n")
