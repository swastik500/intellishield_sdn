"""
IntelliShield shared typed contracts (FOUNDATION).

Dependency rules:
  - This package sits at the bottom of the import graph.
  - It must NOT import controller, ml_models, mitigation, dashboard,
    evaluation, traffic_generator, or rl_engine.
  - Stdlib only.

These contracts are infrastructure only. Existing detectors continue to
return plain dicts until later phases adopt these types incrementally.
"""

from shared_contracts.enums import (
    AlertType,
    CandidateStatus,
    DetectionDecision,
    DetectorHealth,
    DetectorType,
    ModelStatus,
    Severity,
    TwinLabelSource,
    TwinOutcomeCode,
    TwinRunPurpose,
    TwinRunStatus,
    ValidationStatus,
    VerificationStatus,
)
from shared_contracts.models import (
    SCHEMA_VERSION,
    AlertEvent,
    CorrelationResult,
    DetectionEvent,
    DetectorResult,
    FusedDecision,
    ModelCandidate,
    ModelVersion,
    RootCauseReport,
    TwinDetectorConfig,
    TwinHost,
    TwinLink,
    TwinObservation,
    TwinProfile,
    TwinRun,
    TwinScenario,
    TwinSwitch,
    TwinTopology,
    TwinTrafficConfig,
    TwinValidationPolicy,
    ValidationResult,
    VerificationResult,
    VerificationStageResult,
)
from shared_contracts.serialize import from_dict, from_json, to_dict, to_json
from shared_contracts.timeutil import format_ts, parse_ts, utc_now

__all__ = [
    "SCHEMA_VERSION",
    "AlertEvent",
    "AlertType",
    "CandidateStatus",
    "CorrelationResult",
    "DetectionDecision",
    "DetectionEvent",
    "DetectorHealth",
    "DetectorResult",
    "DetectorType",
    "FusedDecision",
    "ModelCandidate",
    "ModelStatus",
    "ModelVersion",
    "RootCauseReport",
    "Severity",
    "TwinDetectorConfig",
    "TwinHost",
    "TwinLabelSource",
    "TwinLink",
    "TwinObservation",
    "TwinOutcomeCode",
    "TwinProfile",
    "TwinRun",
    "TwinRunPurpose",
    "TwinRunStatus",
    "TwinScenario",
    "TwinSwitch",
    "TwinTopology",
    "TwinTrafficConfig",
    "TwinValidationPolicy",
    "ValidationResult",
    "ValidationStatus",
    "VerificationResult",
    "VerificationStageResult",
    "VerificationStatus",
    "format_ts",
    "from_dict",
    "from_json",
    "parse_ts",
    "to_dict",
    "to_json",
    "utc_now",
]

__version__ = "1.0.0"
