"""
SeverityPolicy — deterministic severity from currently available evidence (R8.2).

Future R4/R5/R6/R2 signals can be added to SeverityEvidence without changing
AlertEvent; unused fields default to None/False and are ignored today.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

from shared_contracts.enums import Severity, VerificationStatus
from shared_contracts.models import VerificationResult


# High-impact flood hints known in the current repository.
_CRITICAL_HINTS = frozenset(
    {
        "SYN_FLOOD",
        "UDP_FLOOD",
        "ICMP_FLOOD",
        "VOLUMETRIC_FLOOD",
    }
)


@dataclass(frozen=True)
class SeverityEvidence:
    """
    Evidence bag for severity assignment.

    Extensible: add optional fields later; AlertEvent stays unchanged.
    """

    verification_status: str
    mitigation_eligible: bool = False
    confidence: Optional[float] = None  # unit interval [0, 1] when known
    attack_hint: str = ""
    # Future hooks (ignored by DefaultSeverityPolicy until those reqs exist):
    correlation_elevated: Optional[bool] = None
    has_rca: Optional[bool] = None
    ssl_unknown: Optional[bool] = None

    @classmethod
    def from_verification(
        cls,
        result: VerificationResult,
        *,
        attack_hint: str = "",
    ) -> "SeverityEvidence":
        status = getattr(result.status, "value", result.status)
        return cls(
            verification_status=str(status),
            mitigation_eligible=bool(result.mitigation_eligible),
            confidence=result.confidence,
            attack_hint=str(attack_hint or ""),
        )


@runtime_checkable
class SeverityPolicy(Protocol):
    def assign(self, evidence: SeverityEvidence) -> Severity:
        ...


@dataclass(frozen=True)
class DefaultSeverityPolicy:
    """
    Exact rules (R8.2):

    1. VERIFIED + mitigation_eligible:
         CRITICAL if confidence >= critical_confidence
                    OR attack_hint in {SYN_FLOOD, UDP_FLOOD, ICMP_FLOOD, VOLUMETRIC_FLOOD}
         else HIGH
    2. VERIFIED + not eligible → MEDIUM
    3. PENDING → MEDIUM
    4. INELIGIBLE → LOW
    5. REJECTED → INFO
    6. anything else → INFO

    Confidence treated as unit [0,1]. Missing/invalid confidence → 0.0.
    Future evidence fields are ignored until policies are extended.
    """

    critical_confidence: float = 0.90
    # Reserved for future graduated HIGH floor (currently unused — eligible is HIGH).
    high_confidence: float = 0.75

    def assign(self, evidence: SeverityEvidence) -> Severity:
        status = str(evidence.verification_status or "").upper()
        conf = _safe_unit(evidence.confidence)
        hint = str(evidence.attack_hint or "").upper()

        if status == VerificationStatus.VERIFIED.value:
            if evidence.mitigation_eligible:
                if conf >= self.critical_confidence or hint in _CRITICAL_HINTS:
                    return Severity.CRITICAL
                return Severity.HIGH
            return Severity.MEDIUM

        if status == VerificationStatus.PENDING.value:
            return Severity.MEDIUM
        if status == VerificationStatus.INELIGIBLE.value:
            return Severity.LOW
        if status == VerificationStatus.REJECTED.value:
            return Severity.INFO
        return Severity.INFO


def _safe_unit(value: Optional[float]) -> float:
    try:
        if value is None:
            return 0.0
        conf = float(value)
    except (TypeError, ValueError):
        return 0.0
    if conf != conf:  # NaN
        return 0.0
    if conf < 0.0:
        return 0.0
    if conf > 1.0:
        # Defensive: percent-looking values → unit
        if conf <= 100.0:
            return conf / 100.0
        return 1.0
    return conf
