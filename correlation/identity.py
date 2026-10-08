"""
R4.1 entity identity — only fields the repository actually provides.

Primary live identity in flow_stats is L2 MAC + switch dpid (+ in_port).
IPv4/ports are NOT in OpenFlow flow match today — optional fields accepted
when present elsewhere but never required / invented.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class EntityIdentity:
    """
    Smallest reusable identity for entity-scoped correlation.

    Matching is deterministic via ``key()`` string equality.
    Missing fields are omitted from the key (partial identity OK).
    """

    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None  # optional; not in current OF flow match
    dst_ip: Optional[str] = None
    switch_id: Optional[int] = None
    in_port: Optional[int] = None
    event_id: Optional[str] = None

    def key(self) -> Optional[str]:
        """Stable entity key, or None when no identity components exist."""
        return build_entity_key(
            src_mac=self.src_mac,
            dst_mac=self.dst_mac,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            switch_id=self.switch_id,
            in_port=self.in_port,
            event_id=self.event_id,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "switch_id": self.switch_id,
            "in_port": self.in_port,
            "event_id": self.event_id,
            "entity_key": self.key(),
        }


def build_entity_key(
    *,
    src_mac: Optional[str] = None,
    dst_mac: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    switch_id: Optional[int] = None,
    in_port: Optional[int] = None,
    event_id: Optional[str] = None,
) -> Optional[str]:
    """
    Deterministic entity key from available identity fields.

    Returns None when no identity is available (do not invent).
    """
    parts = []
    if switch_id is not None:
        parts.append(f"dpid:{int(switch_id)}")
    if in_port is not None:
        parts.append(f"in_port:{int(in_port)}")
    src = (src_mac or "").strip().lower()
    if src:
        parts.append(f"src:{src}")
    dst = (dst_mac or "").strip().lower()
    if dst:
        parts.append(f"dst:{dst}")
    sip = (src_ip or "").strip()
    if sip:
        parts.append(f"src_ip:{sip}")
    dip = (dst_ip or "").strip()
    if dip:
        parts.append(f"dst_ip:{dip}")
    eid = (event_id or "").strip()
    if eid:
        parts.append(f"event:{eid}")
    if not parts:
        return None
    return "|".join(parts)
