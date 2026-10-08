"""
R5.1 structured prediction explanation models.

Distinct from FOUNDATION RootCauseReport (RCA — R5.2).
JSON-safe only; no live model objects; no pickle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from shared_contracts.models import new_id
from shared_contracts.timeutil import ensure_utc, format_ts, utc_now

SCHEMA_VERSION = "1.0"


class EvidenceKind(str, Enum):
    """How a statement or attribute should be interpreted."""

    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class ExplanationMethod(str, Enum):
    DECISION_TREE_PATH = "DECISION_TREE_PATH"
    FEATURE_DEVIATION = "FEATURE_DEVIATION"
    COMPOSITE = "COMPOSITE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    FEATURE_MISMATCH = "FEATURE_MISMATCH"
    UNSUPPORTED_MODEL = "UNSUPPORTED_MODEL"


class ExplanationStatus(str, Enum):
    """Availability of the explanation itself (not the ML label)."""

    OK = "OK"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


class AttributionScope(str, Enum):
    """Distinguish global model stats from local path evidence."""

    GLOBAL_IMPORTANCE = "GLOBAL_IMPORTANCE"
    LOCAL_PATH = "LOCAL_PATH"
    HEURISTIC_DEVIATION = "HEURISTIC_DEVIATION"


@dataclass(frozen=True)
class DecisionPathStep:
    """One Decision Tree split along the taken path (local decision-path evidence)."""

    node_id: int
    feature: str
    threshold: float
    operator: str  # "<=" or ">"
    feature_value: float
    direction: str  # "left" / "right"
    threshold_distance: Optional[float] = None
    evidence_kind: str = EvidenceKind.OBSERVED.value
    scope: str = AttributionScope.LOCAL_PATH.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": int(self.node_id),
            "feature": str(self.feature),
            "threshold": float(self.threshold),
            "operator": str(self.operator),
            "feature_value": float(self.feature_value),
            "direction": str(self.direction),
            "threshold_distance": (
                None
                if self.threshold_distance is None
                else float(self.threshold_distance)
            ),
            "evidence_kind": str(self.evidence_kind),
            "scope": str(self.scope),
        }


@dataclass(frozen=True)
class FeatureAttribution:
    """
    One feature attribute.

    scope=GLOBAL_IMPORTANCE → model.feature_importances_ (NOT per-sample causality)
    scope=LOCAL_PATH → feature appeared on this sample's decision path
    scope=HEURISTIC_DEVIATION → vs NORMAL_RANGES (INFERRED)
    """

    feature: str
    value: Optional[float] = None
    importance: Optional[float] = None
    deviation: Optional[str] = None
    note: str = ""
    evidence_kind: str = EvidenceKind.OBSERVED.value
    scope: str = AttributionScope.GLOBAL_IMPORTANCE.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature": str(self.feature),
            "value": None if self.value is None else float(self.value),
            "importance": None if self.importance is None else float(self.importance),
            "deviation": self.deviation,
            "note": str(self.note),
            "evidence_kind": str(self.evidence_kind),
            "scope": str(self.scope),
        }


@dataclass(frozen=True)
class PredictionExplanation:
    """
    Why the detector/model produced this prediction (XAI).

    Not a root-cause report. Does not authorize mitigation.
    """

    explanation_id: str
    timestamp: datetime
    event_id: Optional[str] = None
    model_id: Optional[str] = None
    status: str = ExplanationStatus.UNAVAILABLE.value
    method: str = ExplanationMethod.INSUFFICIENT_EVIDENCE.value
    prediction_status: str = "UNKNOWN"
    confidence_percent: Optional[float] = None
    model_name: str = "none"
    model_available: bool = False
    decision_path: List[DecisionPathStep] = field(default_factory=list)
    leaf_decision: Optional[str] = None
    leaf_node_id: Optional[int] = None
    # GLOBAL model importances (not local causality)
    global_feature_importances: List[FeatureAttribution] = field(default_factory=list)
    # Features that appeared on THIS sample's path (local evidence)
    local_path_features: List[FeatureAttribution] = field(default_factory=list)
    anomalous_features: List[FeatureAttribution] = field(default_factory=list)
    attack_type_hint: str = "NOT_AVAILABLE"
    summary: str = ""
    narrative: str = ""
    evidence_refs: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    observed_facts: List[str] = field(default_factory=list)
    inferred_statements: List[str] = field(default_factory=list)
    iso_score: Optional[float] = None
    dt_label: Optional[int] = None
    dt_confidence: Optional[float] = None
    feature_names: List[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "timestamp", ensure_utc(self.timestamp))

    @property
    def feature_importances(self) -> List[FeatureAttribution]:
        """Alias kept for earlier R5.1 callers — means GLOBAL importances."""
        return self.global_feature_importances

    def content_fingerprint(self) -> Dict[str, Any]:
        """Deterministic content excluding explanation_id / timestamp."""
        d = self.to_dict()
        d.pop("explanation_id", None)
        d.pop("timestamp", None)
        return d

    def to_dict(self) -> Dict[str, Any]:
        """JSON-safe dict (no live models)."""
        return {
            "_type": "PredictionExplanation",
            "explanation_id": self.explanation_id,
            "timestamp": format_ts(self.timestamp),
            "event_id": self.event_id,
            "model_id": self.model_id,
            "status": self.status,
            "method": self.method,
            "prediction_status": self.prediction_status,
            "confidence_percent": self.confidence_percent,
            "model_name": self.model_name,
            "model_available": bool(self.model_available),
            "decision_path": [s.to_dict() for s in self.decision_path],
            "leaf_decision": self.leaf_decision,
            "leaf_node_id": self.leaf_node_id,
            "global_feature_importances": [
                f.to_dict() for f in self.global_feature_importances
            ],
            "local_path_features": [f.to_dict() for f in self.local_path_features],
            "anomalous_features": [f.to_dict() for f in self.anomalous_features],
            "attack_type_hint": self.attack_type_hint,
            "summary": self.summary,
            "narrative": self.narrative,
            "evidence_refs": list(self.evidence_refs),
            "missing_evidence": list(self.missing_evidence),
            "observed_facts": list(self.observed_facts),
            "inferred_statements": list(self.inferred_statements),
            "iso_score": self.iso_score,
            "dt_label": self.dt_label,
            "dt_confidence": self.dt_confidence,
            "feature_names": list(self.feature_names),
            "schema_version": self.schema_version,
        }


def new_explanation_id() -> str:
    return new_id()


def empty_insufficient(
    *,
    reason: str,
    event_id: Optional[str] = None,
    prediction_status: str = "UNKNOWN",
    method: str = ExplanationMethod.INSUFFICIENT_EVIDENCE.value,
    status: str = ExplanationStatus.UNAVAILABLE.value,
    model_id: Optional[str] = None,
) -> PredictionExplanation:
    summary = f"Explanation {status}: {reason}."
    return PredictionExplanation(
        explanation_id=new_explanation_id(),
        timestamp=utc_now(),
        event_id=event_id,
        model_id=model_id,
        status=status,
        method=method,
        prediction_status=prediction_status,
        summary=summary,
        narrative=f"INSUFFICIENT_EVIDENCE: {reason}",
        missing_evidence=[reason],
        observed_facts=[],
        inferred_statements=[],
        feature_names=list(),
    )
