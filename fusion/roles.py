"""
Evidence roles for R6 collaborative detection (R6-local; FOUNDATION enums unchanged).

PRIMARY_DETECTION  — may propose attack/anomaly judgments (ML, Entropy; future SSL)
SUPPORTING_EVIDENCE — co-occurrence / multi-signal support (R4 CorrelationResult)
CONTEXT_ONLY       — distribution/behaviour context (ADWIN, HDBSCAN); never solo ATTACK
"""

from __future__ import annotations

from enum import Enum


class EvidenceRole(str, Enum):
    PRIMARY_DETECTION = "PRIMARY_DETECTION"
    SUPPORTING_EVIDENCE = "SUPPORTING_EVIDENCE"
    CONTEXT_ONLY = "CONTEXT_ONLY"

    # Backward-compatible alias used in early R6.1 drafts
    SUPPORTING_CONTEXT = "SUPPORTING_EVIDENCE"


ROLE_RATIONALE = {
    EvidenceRole.PRIMARY_DETECTION.value: (
        "Online detectors that emit NORMAL/ATTACK-style security judgments "
        "on the live mitigation path (entropy, ML; future SSL)."
    ),
    EvidenceRole.SUPPORTING_EVIDENCE.value: (
        "R4 correlation co-occurrence support. Strengthens/weakens confidence "
        "but is not an independent attack detector under default R6 policy."
    ),
    EvidenceRole.CONTEXT_ONLY.value: (
        "ADWIN (distribution change) and HDBSCAN (behavioural outlier). "
        "Context/novelty only — not 'DDoS detected' by themselves."
    ),
}


def normalize_role(role: EvidenceRole | str | None) -> EvidenceRole | None:
    if role is None:
        return None
    if isinstance(role, EvidenceRole):
        # Resolve alias members that share values
        return EvidenceRole(role.value)
    key = str(role).strip().upper()
    if key in ("SUPPORTING", "SUPPORTING_CONTEXT", "SUPPORTING_EVIDENCE"):
        return EvidenceRole.SUPPORTING_EVIDENCE
    if key in ("CONTEXT", "CONTEXT_ONLY"):
        return EvidenceRole.CONTEXT_ONLY
    if key in ("PRIMARY", "PRIMARY_DETECTION", "PRIMARY_DETECTOR"):
        return EvidenceRole.PRIMARY_DETECTION
    return EvidenceRole(key)
