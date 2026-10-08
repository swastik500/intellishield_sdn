"""
R6.1 evidence records + entity key helpers.

Entity keys reuse R4 ``correlation.identity.build_entity_key`` semantics
(switch / MAC scope) so R6 does not invent a competing identity scheme.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional

from shared_contracts.enums import DetectorType
from shared_contracts.models import CorrelationResult, DetectorResult
from shared_contracts.timeutil import ensure_utc
from fusion.roles import EvidenceRole


def entity_key_from(
    *,
    switch_id: Optional[int] = None,
    src_mac: Optional[str] = None,
    dst_mac: Optional[str] = None,
    in_port: Optional[int] = None,
    event_id: Optional[str] = None,
    entity_key: Optional[str] = None,
) -> str:
    """
    Stable entity scope string for registry indexing.

    Empty string means unknown / global (caller did not supply identity).
    Prefer an explicit ``entity_key`` when already computed (e.g. R4).
    """
    if entity_key is not None and str(entity_key).strip():
        return str(entity_key).strip()
    try:
        from correlation.identity import build_entity_key
    except Exception:  # noqa: BLE001
        parts = []
        if switch_id is not None:
            parts.append(f"dpid:{int(switch_id)}")
        src = (src_mac or "").strip().lower()
        if src:
            parts.append(f"src:{src}")
        dst = (dst_mac or "").strip().lower()
        if dst:
            parts.append(f"dst:{dst}")
        return "|".join(parts) if parts else ""
    key = build_entity_key(
        switch_id=switch_id,
        src_mac=src_mac,
        dst_mac=dst_mac,
        in_port=in_port,
        event_id=event_id,
    )
    return key or ""


@dataclass(frozen=True)
class EvidenceRecord:
    """One bounded registry entry (DetectorResult and/or native CorrelationResult)."""

    evidence_id: str
    entity_key: str
    detector: DetectorType
    role: EvidenceRole
    observed_at: datetime
    received_at: datetime
    result: Optional[DetectorResult] = None
    correlation: Optional[CorrelationResult] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "observed_at", ensure_utc(self.observed_at))
        object.__setattr__(self, "received_at", ensure_utc(self.received_at))
        if self.result is None and self.correlation is None:
            raise ValueError("EvidenceRecord requires result and/or correlation")

    def to_dict(self) -> Dict[str, Any]:
        from shared_contracts.serialize import to_dict as contract_to_dict

        return {
            "evidence_id": self.evidence_id,
            "entity_key": self.entity_key,
            "detector": self.detector.value,
            "role": self.role.value,
            "observed_at": self.observed_at.isoformat(),
            "received_at": self.received_at.isoformat(),
            "result": contract_to_dict(self.result) if self.result is not None else None,
            "correlation": (
                contract_to_dict(self.correlation)
                if self.correlation is not None
                else None
            ),
            "meta": dict(self.meta),
        }
