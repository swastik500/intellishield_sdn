"""Enums for IntelliShield shared contracts.

String values align with existing repository conventions where applicable
(e.g. ML status NORMAL/SUSPICIOUS/ATTACK, entropy ALERT/WARNING).
"""

from __future__ import annotations

from enum import Enum


class DetectorType(str, Enum):
    """Identity of a detector producing a DetectorResult."""

    ENTROPY = "ENTROPY"
    ML = "ML"
    SSL = "SSL"
    ADWIN = "ADWIN"
    HDBSCAN = "HDBSCAN"
    CORRELATION = "CORRELATION"
    OTHER = "OTHER"


class DetectorHealth(str, Enum):
    """Execution health of a detector invocation (not the traffic decision)."""

    SUCCESS = "SUCCESS"
    DEGRADED = "DEGRADED"
    ERROR = "ERROR"


class DetectionDecision(str, Enum):
    """
    Normalised decision vocabulary spanning detectors.

    Values match existing string statuses used in ML / entropy logs where
    those concepts already exist. Detectors that lack a traffic label
    (e.g. ADWIN) may use DRIFT / NONE instead.
    """

    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    ATTACK = "ATTACK"
    WARNING = "WARNING"
    ALERT = "ALERT"
    UNKNOWN = "UNKNOWN"
    DRIFT = "DRIFT"
    NOISE = "NOISE"
    NONE = "NONE"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VerificationStatus(str, Enum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    INELIGIBLE = "INELIGIBLE"


class AlertType(str, Enum):
    DETECTION = "DETECTION"
    MITIGATION = "MITIGATION"
    DRIFT = "DRIFT"
    SYSTEM = "SYSTEM"
    CORRELATION = "CORRELATION"
    UNKNOWN = "UNKNOWN"


class ModelStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    CHAMPION = "CHAMPION"
    RETIRED = "RETIRED"
    FAILED = "FAILED"
    VALIDATING = "VALIDATING"


class CandidateStatus(str, Enum):
    PENDING = "PENDING"
    TRAINING = "TRAINING"
    READY = "READY"
    VALIDATING = "VALIDATING"
    PROMOTED = "PROMOTED"
    REJECTED = "REJECTED"
    ROLLED_BACK = "ROLLED_BACK"


class ValidationStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class TwinRunPurpose(str, Enum):
    """Purpose of a twin experiment run (leakage / provenance separation)."""

    TRAINING = "TRAINING"
    VALIDATION = "VALIDATION"
    TEST = "TEST"
    FIDELITY = "FIDELITY"
    EXPLORATION = "EXPLORATION"


class TwinRunStatus(str, Enum):
    """Lifecycle status of a TwinRun / TwinExperimentPlan."""

    PLANNED = "PLANNED"
    VALIDATED = "VALIDATED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    # Backward-compatible aliases (R3.1)
    COMPLETED = "COMPLETED"  # treat as SUCCEEDED in new code
    ABORTED = "ABORTED"  # treat as CANCELLED in new code


class TwinLabelSource(str, Enum):
    """Allowed ground-truth provenance (never model predictions)."""

    SCENARIO_CONTROL = "SCENARIO_CONTROL"
    ATTACK_LOG = "ATTACK_LOG"
    MANUAL = "MANUAL"


class TwinOutcomeCode(str, Enum):
    """Structured validation outcome (maps onto ValidationStatus)."""

    PASS = "PASS"
    FAIL = "FAIL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    EXPERIMENT_FAILED = "EXPERIMENT_FAILED"


def parse_detection_decision(value: str | DetectionDecision | None) -> DetectionDecision:
    """Map legacy status strings to DetectionDecision; unknown → NONE."""
    if value is None or value == "":
        return DetectionDecision.NONE
    if isinstance(value, DetectionDecision):
        return value
    key = str(value).strip().upper()
    try:
        return DetectionDecision(key)
    except ValueError:
        return DetectionDecision.NONE
