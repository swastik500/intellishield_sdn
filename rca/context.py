"""
Smallest RCA input context — JSON-safe structured evidence only.

No controller, datapath, or live OpenFlow objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from shared_contracts.models import DetectionEvent, VerificationResult, CorrelationResult, FusedDecision


@dataclass(frozen=True)
class MitigationEvidence:
    """
    Optional mitigation facts supplied by caller (R5.2 does not query engines).

    RCA may explain eligibility/strategy only when these fields are present.
    RCA never selects or authorizes mitigation.
    """

    eligible: Optional[bool] = None
    strategy: Optional[str] = None
    result: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "eligible": self.eligible,
            "strategy": self.strategy,
            "result": self.result,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class RCAContext:
    """
    Inputs for RootCauseEngine.analyze.

    Prefer typed contracts; PredictionExplanation may be object or to_dict().
    """

    event_id: str
    detection: Optional[DetectionEvent] = None
    verification: Optional[VerificationResult] = None
    # PredictionExplanation or its to_dict() payload
    explanation: Optional[Any] = None
    attack_hint: Optional[str] = None
    # Optional entropy snapshot: {dim: value, ...} or {score, threshold, ...}
    entropy_evidence: Optional[Dict[str, Any]] = None
    mitigation: Optional[MitigationEvidence] = None
    # Only when real baseline exists; None → NOT_AVAILABLE
    baseline_evidence: Optional[Dict[str, Any]] = None
    # Optional explicit identities (used only if verification/detection lack them)
    source_mac: Optional[str] = None
    target_mac: Optional[str] = None
    report_id: Optional[str] = None
    # Optional R4 CorrelationResult (co-occurrence evidence; never causation)
    correlation: Optional[CorrelationResult] = None
    # Optional R6 FusedDecision (collaborative evidence; never causation / not ML-XAI)
    fused_decision: Optional[FusedDecision] = None
    extra_refs: tuple = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str) or not self.event_id.strip():
            raise ValueError("event_id must be a non-empty string")
