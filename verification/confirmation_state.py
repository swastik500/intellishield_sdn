"""Bounded attack-confirmation streak state (mirrors flow_monitor semantics)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class AttackConfirmationState:
    """
    Per-switch consecutive ATTACK/SUSPICIOUS (or entropy ALERT) streak.

    Semantics match controller/flow_monitor.py:
      - ATTACK or SUSPICIOUS increments ML streak
      - NORMAL resets streak to 0
      - Entropy ALERT increments entropy streak; non-ALERT resets

    Bounded: at most ``max_tracked_switches`` keys; oldest-ish eviction via
    FIFO of insertion when over capacity (deterministic for tests).
    """

    confirm_threshold: int = 2
    max_tracked_switches: int = 64
    _streaks: Dict[int, int] = field(default_factory=dict)
    _order: list = field(default_factory=list)

    def reset(self, dpid: int | None = None) -> None:
        if dpid is None:
            self._streaks.clear()
            self._order.clear()
            return
        self._streaks.pop(dpid, None)
        if dpid in self._order:
            self._order.remove(dpid)

    def update(self, dpid: int, status: str) -> int:
        """
        Apply one-cycle status update; return streak after update.

        Status values: ATTACK / SUSPICIOUS increment; anything else resets.
        """
        status_u = str(status).upper()
        if status_u in ("ATTACK", "SUSPICIOUS"):
            self._ensure_slot(dpid)
            self._streaks[dpid] = self._streaks.get(dpid, 0) + 1
        else:
            self._streaks[dpid] = 0
            if dpid not in self._order:
                self._ensure_slot(dpid)
        return int(self._streaks.get(dpid, 0))

    def get(self, dpid: int) -> int:
        return int(self._streaks.get(dpid, 0))

    def is_confirmed(self, dpid: int) -> bool:
        return self.get(dpid) >= self.confirm_threshold

    def _ensure_slot(self, dpid: int) -> None:
        if dpid in self._streaks:
            return
        while len(self._order) >= self.max_tracked_switches:
            old = self._order.pop(0)
            self._streaks.pop(old, None)
        self._order.append(dpid)
        self._streaks[dpid] = 0
