"""Explicit verification stage identities for R7."""

from __future__ import annotations

from enum import Enum


class VerificationStage(str, Enum):
    """
    Ordered verification stages derived from existing controller/mitigation gates.

    Future SSL / CORRELATION / FUSION stages must not be added here until
    those requirements are implemented.
    """

    WARMUP = "WARMUP"
    DETECTION_EVIDENCE = "DETECTION_EVIDENCE"
    ATTACK_CONFIRMATION = "ATTACK_CONFIRMATION"
    CONFIDENCE_GATE = "CONFIDENCE_GATE"
    ATTACKER_IDENTIFICATION = "ATTACKER_IDENTIFICATION"
    MITIGATION_ELIGIBILITY = "MITIGATION_ELIGIBILITY"


STAGE_ORDER = tuple(VerificationStage)
