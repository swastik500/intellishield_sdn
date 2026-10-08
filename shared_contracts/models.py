"""Dataclass contracts for IntelliShield FOUNDATION.

All fields intended for serialization must be JSON-safe (no live model,
controller, or OpenFlow objects in evidence/metadata).
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from shared_contracts.enums import (
    AlertType,
    CandidateStatus,
    DetectionDecision,
    DetectorHealth,
    DetectorType,
    ModelStatus,
    Severity,
    TwinLabelSource,
    TwinRunPurpose,
    TwinRunStatus,
    ValidationStatus,
    VerificationStatus,
)
from shared_contracts.timeutil import ensure_utc, utc_now

SCHEMA_VERSION = "1.0"


def new_id() -> str:
    """Generate a new UUID4 string (overridable by supplying ids explicitly)."""
    return str(uuid.uuid4())


def _require_non_empty(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _finite_or_none(name: str, value: Optional[float]) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number or None")
    fval = float(value)
    if not math.isfinite(fval):
        raise ValueError(f"{name} must be finite (got {value!r})")
    return fval


def _check_unit_interval(name: str, value: Optional[float]) -> Optional[float]:
    fval = _finite_or_none(name, value)
    if fval is None:
        return None
    if fval < 0.0 or fval > 1.0:
        raise ValueError(f"{name} must be in [0, 1] (got {fval})")
    return fval


def _ensure_json_safe_mapping(name: str, data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{name} must be a dict")
    for key, val in data.items():
        if not isinstance(key, str):
            raise ValueError(f"{name} keys must be strings")
        if not _is_json_safe(val):
            raise ValueError(
                f"{name}[{key!r}] is not JSON-safe; "
                "use scalars, lists, or dicts of scalars only"
            )
    return data


def _is_json_safe(value: Any, depth: int = 0) -> bool:
    if depth > 4:
        return False
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_is_json_safe(v, depth + 1) for v in value)
    if isinstance(value, dict):
        return all(
            isinstance(k, str) and _is_json_safe(v, depth + 1)
            for k, v in value.items()
        )
    return False


@dataclass(frozen=True)
class DetectorResult:
    """Output of a single detector invocation."""

    detector: DetectorType
    timestamp: datetime
    health: DetectorHealth = DetectorHealth.SUCCESS
    decision: DetectionDecision = DetectionDecision.NONE
    confidence: Optional[float] = None  # normalized [0, 1] when set
    score: Optional[float] = None       # raw detector score (any finite)
    threshold: Optional[float] = None
    attack_hint: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "timestamp", ensure_utc(self.timestamp))
        object.__setattr__(
            self, "confidence", _check_unit_interval("confidence", self.confidence)
        )
        object.__setattr__(self, "score", _finite_or_none("score", self.score))
        object.__setattr__(
            self, "threshold", _finite_or_none("threshold", self.threshold)
        )
        object.__setattr__(
            self, "evidence", _ensure_json_safe_mapping("evidence", self.evidence)
        )
        if self.health is DetectorHealth.ERROR and not self.error_message:
            object.__setattr__(self, "error_message", "detector error")


@dataclass(frozen=True)
class DetectionEvent:
    """One detection cycle / security event collecting detector evidence."""

    event_id: str
    timestamp: datetime
    switch_id: Optional[int] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    detector_results: List[DetectorResult] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty("event_id", self.event_id)
        object.__setattr__(self, "timestamp", ensure_utc(self.timestamp))
        object.__setattr__(
            self, "context", _ensure_json_safe_mapping("context", self.context)
        )
        if not isinstance(self.detector_results, list):
            raise ValueError("detector_results must be a list")
        for item in self.detector_results:
            if not isinstance(item, DetectorResult):
                raise ValueError("detector_results must contain DetectorResult only")


@dataclass(frozen=True)
class CorrelationResult:
    """Future R4 correlation engine output (contract only)."""

    correlation_id: str
    timestamp: datetime
    event_id: Optional[str] = None
    score: Optional[float] = None
    severity: Severity = Severity.INFO
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    signal_ids: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty("correlation_id", self.correlation_id)
        object.__setattr__(self, "timestamp", ensure_utc(self.timestamp))
        object.__setattr__(self, "score", _finite_or_none("score", self.score))
        if self.window_start is not None:
            object.__setattr__(self, "window_start", ensure_utc(self.window_start))
        if self.window_end is not None:
            object.__setattr__(self, "window_end", ensure_utc(self.window_end))
        object.__setattr__(
            self, "evidence", _ensure_json_safe_mapping("evidence", self.evidence)
        )


@dataclass(frozen=True)
class FusedDecision:
    """Future R6 collaborative fusion output (contract only)."""

    fusion_id: str
    timestamp: datetime
    event_id: Optional[str] = None
    decision: DetectionDecision = DetectionDecision.NONE
    confidence: Optional[float] = None
    participating: List[str] = field(default_factory=list)
    disagreement: bool = False
    reason: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty("fusion_id", self.fusion_id)
        object.__setattr__(self, "timestamp", ensure_utc(self.timestamp))
        object.__setattr__(
            self, "confidence", _check_unit_interval("confidence", self.confidence)
        )
        object.__setattr__(
            self, "evidence", _ensure_json_safe_mapping("evidence", self.evidence)
        )


@dataclass(frozen=True)
class VerificationStageResult:
    """One ordered verification stage outcome."""

    stage_name: str
    passed: bool
    reason: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_non_empty("stage_name", self.stage_name)
        object.__setattr__(
            self, "details", _ensure_json_safe_mapping("details", self.details)
        )


@dataclass(frozen=True)
class VerificationResult:
    """Future R7 verification engine output (contract only)."""

    verification_id: str
    timestamp: datetime
    event_id: Optional[str] = None
    status: VerificationStatus = VerificationStatus.PENDING
    confidence: Optional[float] = None
    stages: List[VerificationStageResult] = field(default_factory=list)
    attacker_mac: Optional[str] = None
    victim_mac: Optional[str] = None
    mitigation_eligible: bool = False
    reason: str = ""
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty("verification_id", self.verification_id)
        object.__setattr__(self, "timestamp", ensure_utc(self.timestamp))
        object.__setattr__(
            self, "confidence", _check_unit_interval("confidence", self.confidence)
        )
        if not isinstance(self.stages, list):
            raise ValueError("stages must be a list")
        for stage in self.stages:
            if not isinstance(stage, VerificationStageResult):
                raise ValueError("stages must contain VerificationStageResult only")


@dataclass(frozen=True)
class RootCauseReport:
    """Future R5 RCA output (distinct from prediction explanation)."""

    report_id: str
    event_id: str
    timestamp: datetime
    summary: str = ""
    suspected_source: Optional[str] = None
    affected_target: Optional[str] = None
    contributing_signals: List[str] = field(default_factory=list)
    contributing_features: Dict[str, Any] = field(default_factory=dict)
    evidence_refs: List[str] = field(default_factory=list)
    confidence: Optional[float] = None
    explanation_summary: Optional[str] = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty("report_id", self.report_id)
        _require_non_empty("event_id", self.event_id)
        object.__setattr__(self, "timestamp", ensure_utc(self.timestamp))
        object.__setattr__(
            self, "confidence", _check_unit_interval("confidence", self.confidence)
        )
        object.__setattr__(
            self,
            "contributing_features",
            _ensure_json_safe_mapping("contributing_features", self.contributing_features),
        )


@dataclass(frozen=True)
class AlertEvent:
    """Future R8 unified alert representation."""

    alert_id: str
    timestamp: datetime
    severity: Severity
    alert_type: AlertType
    title: str
    message: str = ""
    event_id: Optional[str] = None
    source: str = ""
    rca_report_id: Optional[str] = None
    mitigation_ref: Optional[str] = None
    mitigation_status: Optional[str] = None
    dedup_key: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty("alert_id", self.alert_id)
        _require_non_empty("title", self.title)
        object.__setattr__(self, "timestamp", ensure_utc(self.timestamp))
        object.__setattr__(
            self, "evidence", _ensure_json_safe_mapping("evidence", self.evidence)
        )


@dataclass(frozen=True)
class ModelVersion:
    """Future R1/R9 model identity metadata (not a live model object)."""

    model_id: str
    version: str
    algorithm: str
    created_at: datetime
    artifact_uri: str = ""
    feature_schema: str = "FEATURE_NAMES_v1"
    metrics: Dict[str, Any] = field(default_factory=dict)
    status: ModelStatus = ModelStatus.CANDIDATE
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty("model_id", self.model_id)
        _require_non_empty("version", self.version)
        _require_non_empty("algorithm", self.algorithm)
        object.__setattr__(self, "created_at", ensure_utc(self.created_at))
        object.__setattr__(
            self, "metrics", _ensure_json_safe_mapping("metrics", self.metrics)
        )


@dataclass(frozen=True)
class ModelCandidate:
    """Challenger/candidate wrapper referencing a ModelVersion."""

    candidate_id: str
    model: ModelVersion
    status: CandidateStatus = CandidateStatus.PENDING
    created_at: datetime = field(default_factory=utc_now)
    parent_model_id: Optional[str] = None
    notes: str = ""
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty("candidate_id", self.candidate_id)
        if not isinstance(self.model, ModelVersion):
            raise ValueError("model must be a ModelVersion")
        object.__setattr__(self, "created_at", ensure_utc(self.created_at))


@dataclass(frozen=True)
class ValidationResult:
    """Digital Twin / lifecycle validation outcome (produced by R3 gate later)."""

    validation_id: str
    timestamp: datetime
    status: ValidationStatus
    model_id: str = ""
    candidate_id: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    artifact_uri: str = ""
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty("validation_id", self.validation_id)
        object.__setattr__(self, "timestamp", ensure_utc(self.timestamp))
        object.__setattr__(
            self, "metrics", _ensure_json_safe_mapping("metrics", self.metrics)
        )


# ─── R3 Digital Twin contracts (model plane; no auto-promotion) ───────────────


@dataclass(frozen=True)
class TwinHost:
    """Host identity in the lab twin topology (not a live Mininet object)."""

    host_id: str
    ip: str = ""
    mac: str = ""
    role: str = ""  # e.g. attacker, victim, client — optional metadata

    def __post_init__(self) -> None:
        _require_non_empty("host_id", self.host_id)


@dataclass(frozen=True)
class TwinSwitch:
    """Switch identity in the lab twin topology."""

    switch_id: str
    dpid: str = ""

    def __post_init__(self) -> None:
        _require_non_empty("switch_id", self.switch_id)


@dataclass(frozen=True)
class TwinLink:
    """Undirected link between two topology node ids."""

    src: str
    dst: str

    def __post_init__(self) -> None:
        _require_non_empty("src", self.src)
        _require_non_empty("dst", self.dst)


@dataclass(frozen=True)
class TwinTopology:
    """Software topology model mirroring IntelliShieldTopo defaults."""

    topology_id: str
    hosts: List[TwinHost] = field(default_factory=list)
    switches: List[TwinSwitch] = field(default_factory=list)
    links: List[TwinLink] = field(default_factory=list)
    controller_host: str = "127.0.0.1"
    controller_port: int = 6653
    subnet_prefix: str = "10.0.0."
    host_count: int = 0
    switch_count: int = 0
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty("topology_id", self.topology_id)
        if self.host_count <= 0 and self.hosts:
            object.__setattr__(self, "host_count", len(self.hosts))
        if self.switch_count <= 0 and self.switches:
            object.__setattr__(self, "switch_count", len(self.switches))


@dataclass(frozen=True)
class TwinTrafficConfig:
    """Controllable traffic parameters supported by existing generators."""

    normal_profile: str = "MEDIUM"
    protocol_mix: List[str] = field(default_factory=lambda: ["icmp", "tcp", "udp"])
    ping_count: int = 50
    ping_interval: float = 0.2
    iperf_duration: int = 20
    tcp_connections: int = 3
    udp_bandwidth: str = "1M"
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "ping_interval",
            _finite_or_none("ping_interval", self.ping_interval) or 0.0,
        )


@dataclass(frozen=True)
class TwinDetectorConfig:
    """Detector stack configuration mirrored for twin experiments (read-only model)."""

    feature_schema: str = "FEATURE_NAMES_v1"
    monitor_interval_sec: int = 5
    warmup_cycles: int = 3
    attack_confirm_cycles: int = 2
    r6_fusion_enabled: bool = True
    model_artifact_uris: Dict[str, str] = field(default_factory=dict)
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "model_artifact_uris",
            _ensure_json_safe_mapping("model_artifact_uris", self.model_artifact_uris),
        )


@dataclass(frozen=True)
class TwinProfile:
    """
    Reproducible software representation of the protected SDN lab environment.

    This is a security-oriented SDN digital twin profile — not a claim of
    perfect physical-network equivalence.
    """

    profile_id: str
    version: str
    topology: TwinTopology
    traffic: TwinTrafficConfig = field(default_factory=TwinTrafficConfig)
    detector: TwinDetectorConfig = field(default_factory=TwinDetectorConfig)
    random_seed: int = 0
    created_at: datetime = field(default_factory=utc_now)
    source_environment: str = "mininet_lab"
    metadata: Dict[str, Any] = field(default_factory=dict)
    config_fingerprint: str = ""
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty("profile_id", self.profile_id)
        _require_non_empty("version", self.version)
        if not isinstance(self.topology, TwinTopology):
            raise ValueError("topology must be a TwinTopology")
        object.__setattr__(self, "created_at", ensure_utc(self.created_at))
        object.__setattr__(
            self, "metadata", _ensure_json_safe_mapping("metadata", self.metadata)
        )


@dataclass(frozen=True)
class TwinScenario:
    """
    Parameterizable scenario definition with scenario-control ground truth.

    Expected properties are defined a priori; they must not be inferred from
    detector predictions.
    """

    scenario_id: str
    name: str
    description: str = ""
    attack_type: Optional[str] = None
    expected_attack: bool = False
    expected_attack_family: str = ""
    intensity_profile: str = ""
    duration_sec: int = 0
    baseline_sec: int = 0
    attack_sec: int = 0
    recovery_sec: int = 0
    source_host: str = ""
    target_host: str = ""
    packet_rate: Optional[int] = None
    protocol: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    ground_truth_events: List[str] = field(
        default_factory=lambda: ["START", "ATTACK_START", "ATTACK_STOP", "END"]
    )
    label_source: TwinLabelSource = TwinLabelSource.SCENARIO_CONTROL
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty("scenario_id", self.scenario_id)
        _require_non_empty("name", self.name)
        object.__setattr__(
            self, "parameters", _ensure_json_safe_mapping("parameters", self.parameters)
        )
        if self.expected_attack and not self.expected_attack_family:
            raise ValueError(
                "expected_attack_family required when expected_attack is True"
            )


@dataclass(frozen=True)
class TwinObservation:
    """
    Captured twin/lab observation references (paths + summaries).

    Populated by twin.snapshot.capture_snapshot from completed experiment logs.
    Capture is observational (read-only); it does not sync OpenFlow live.
    """

    observation_id: str
    timestamp: datetime
    profile_id: str = ""
    run_id: str = ""
    artifact_refs: Dict[str, str] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty("observation_id", self.observation_id)
        object.__setattr__(self, "timestamp", ensure_utc(self.timestamp))
        object.__setattr__(
            self,
            "artifact_refs",
            _ensure_json_safe_mapping("artifact_refs", self.artifact_refs),
        )
        object.__setattr__(
            self, "summary", _ensure_json_safe_mapping("summary", self.summary)
        )


@dataclass(frozen=True)
class TwinValidationPolicy:
    """
    Pass/fail thresholds for candidate validation (R3.3 TwinValidationEngine).

    Only metrics supported by evaluation/ieee_metrics should be referenced.

    Acceptance semantics:
      1. Hard gates: min_precision/recall/f1, max_fpr/fnr, max latencies
      2. Required scenarios/metrics must be present (else INSUFFICIENT_EVIDENCE)
      3. Baseline comparison (optional): allow bounded absolute regression
         (candidate may be worse by at most max_*_regression; need not improve all)
    """

    policy_id: str
    version: str = "1.0"
    min_precision: Optional[float] = None
    min_recall: Optional[float] = None
    min_f1: Optional[float] = None
    max_fpr: Optional[float] = None
    max_fnr: Optional[float] = None
    max_detection_latency_sec: Optional[float] = None
    max_runtime_latency_sec: Optional[float] = None
    max_false_mitigations: Optional[int] = None
    # Absolute regression tolerance vs baseline (e.g. 0.05 = 5 points)
    max_f1_regression: Optional[float] = None
    max_precision_regression: Optional[float] = None
    max_fpr_increase: Optional[float] = None
    require_scenario_ids: List[str] = field(default_factory=list)
    require_metric_keys: List[str] = field(
        default_factory=lambda: [
            "precision",
            "recall",
            "f1_score",
            "false_positive_rate",
        ]
    )
    notes: str = ""
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty("policy_id", self.policy_id)
        for name in (
            "min_precision",
            "min_recall",
            "min_f1",
            "max_fpr",
            "max_fnr",
            "max_f1_regression",
            "max_precision_regression",
            "max_fpr_increase",
        ):
            object.__setattr__(
                self, name, _check_unit_interval(name, getattr(self, name))
            )
        object.__setattr__(
            self,
            "max_detection_latency_sec",
            _finite_or_none(
                "max_detection_latency_sec", self.max_detection_latency_sec
            ),
        )
        object.__setattr__(
            self,
            "max_runtime_latency_sec",
            _finite_or_none(
                "max_runtime_latency_sec", self.max_runtime_latency_sec
            ),
        )


@dataclass(frozen=True)
class TwinRun:
    """
    Traceable twin experiment record.

    Does not execute Mininet; orchestration belongs to later R3 phases.
    Never auto-promotes production models.
    """

    run_id: str
    profile_id: str
    profile_version: str
    scenario_id: str
    purpose: TwinRunPurpose = TwinRunPurpose.EXPLORATION
    status: TwinRunStatus = TwinRunStatus.PLANNED
    parameters: Dict[str, Any] = field(default_factory=dict)
    random_seed: int = 0
    config_fingerprint: str = ""
    git_commit: str = ""
    model_id: str = ""
    candidate_id: Optional[str] = None
    created_at: datetime = field(default_factory=utc_now)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    artifact_refs: Dict[str, str] = field(default_factory=dict)
    notes: str = ""
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_non_empty("run_id", self.run_id)
        _require_non_empty("profile_id", self.profile_id)
        _require_non_empty("profile_version", self.profile_version)
        _require_non_empty("scenario_id", self.scenario_id)
        object.__setattr__(self, "created_at", ensure_utc(self.created_at))
        if self.started_at is not None:
            object.__setattr__(self, "started_at", ensure_utc(self.started_at))
        if self.finished_at is not None:
            object.__setattr__(self, "finished_at", ensure_utc(self.finished_at))
        object.__setattr__(
            self, "parameters", _ensure_json_safe_mapping("parameters", self.parameters)
        )
        object.__setattr__(
            self,
            "artifact_refs",
            _ensure_json_safe_mapping("artifact_refs", self.artifact_refs),
        )
