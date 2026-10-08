"""Explicit serialization helpers for shared contracts.

No pickle. No dynamic class import from serialized payloads.
"""

from __future__ import annotations

import json
from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Type, TypeVar, Union, get_args, get_origin

from shared_contracts import models as _models
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
from shared_contracts.timeutil import format_ts, parse_ts

T = TypeVar("T")

_ENUM_BY_NAME: Dict[str, Type[Enum]] = {
    "DetectorType": DetectorType,
    "DetectorHealth": DetectorHealth,
    "DetectionDecision": DetectionDecision,
    "Severity": Severity,
    "VerificationStatus": VerificationStatus,
    "AlertType": AlertType,
    "ModelStatus": ModelStatus,
    "CandidateStatus": CandidateStatus,
    "ValidationStatus": ValidationStatus,
    "TwinRunPurpose": TwinRunPurpose,
    "TwinRunStatus": TwinRunStatus,
    "TwinLabelSource": TwinLabelSource,
    "TwinOutcomeCode": TwinOutcomeCode,
}

_MODEL_BY_NAME: Dict[str, Type[Any]] = {
    "DetectorResult": _models.DetectorResult,
    "DetectionEvent": _models.DetectionEvent,
    "CorrelationResult": _models.CorrelationResult,
    "FusedDecision": _models.FusedDecision,
    "VerificationStageResult": _models.VerificationStageResult,
    "VerificationResult": _models.VerificationResult,
    "RootCauseReport": _models.RootCauseReport,
    "AlertEvent": _models.AlertEvent,
    "ModelVersion": _models.ModelVersion,
    "ModelCandidate": _models.ModelCandidate,
    "ValidationResult": _models.ValidationResult,
    "TwinHost": _models.TwinHost,
    "TwinSwitch": _models.TwinSwitch,
    "TwinLink": _models.TwinLink,
    "TwinTopology": _models.TwinTopology,
    "TwinTrafficConfig": _models.TwinTrafficConfig,
    "TwinDetectorConfig": _models.TwinDetectorConfig,
    "TwinProfile": _models.TwinProfile,
    "TwinScenario": _models.TwinScenario,
    "TwinObservation": _models.TwinObservation,
    "TwinValidationPolicy": _models.TwinValidationPolicy,
    "TwinRun": _models.TwinRun,
}


def to_dict(obj: Any) -> Any:
    """Convert a contract object (or nested structure) to JSON-compatible data."""
    if obj is None:
        return None
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return format_ts(obj)
    if is_dataclass(obj) and not isinstance(obj, type):
        out: Dict[str, Any] = {"_type": type(obj).__name__}
        for f in fields(obj):
            out[f.name] = to_dict(getattr(obj, f.name))
        return out
    if isinstance(obj, list):
        return [to_dict(v) for v in obj]
    if isinstance(obj, dict):
        return {str(k): to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (str, int, bool)):
        return obj
    if isinstance(obj, float):
        return float(obj)
    raise TypeError(f"Cannot serialize type {type(obj)!r}")


def to_json(obj: Any, *, indent: Optional[int] = None) -> str:
    """Serialize a contract object to a JSON string (sorted keys)."""
    return json.dumps(to_dict(obj), indent=indent, sort_keys=True)


def from_dict(data: Any, cls: Optional[Type[T]] = None) -> T:
    """
    Reconstruct a contract object from a dictionary.

    If *cls* is omitted, uses the ``_type`` discriminator written by ``to_dict``.
    """
    if cls is None:
        if not isinstance(data, dict) or "_type" not in data:
            raise ValueError("from_dict requires cls or a '_type' field")
        type_name = data["_type"]
        if type_name not in _MODEL_BY_NAME:
            raise ValueError(f"Unknown contract type {type_name!r}")
        cls = _MODEL_BY_NAME[type_name]  # type: ignore[assignment]
    return _coerce(cls, data)  # type: ignore[return-value]


def from_json(text: str, cls: Optional[Type[T]] = None) -> T:
    """Deserialize JSON text into a contract object."""
    return from_dict(json.loads(text), cls=cls)


def _strip_optional(annotation: Any) -> Any:
    origin = get_origin(annotation)
    if origin is Union:
        args = [a for a in get_args(annotation) if a is not type(None)]
        if len(args) == 1:
            return args[0]
    if isinstance(annotation, str) and annotation.startswith("Optional["):
        return annotation[len("Optional[") : -1]
    return annotation


def _coerce(annotation: Any, data: Any) -> Any:
    if data is None:
        return None

    annotation = _strip_optional(annotation)

    if isinstance(annotation, str):
        return _coerce_string_annotation(annotation, data)

    origin = get_origin(annotation)
    if origin is list or origin is List:
        args = get_args(annotation)
        inner = args[0] if args else Any
        if not isinstance(data, list):
            raise TypeError(f"Expected list, got {type(data)!r}")
        return [_coerce(inner, item) for item in data]

    if origin is dict or origin is Dict:
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict, got {type(data)!r}")
        return {str(k): v for k, v in data.items()}

    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return annotation(data)

    if annotation is datetime:
        parsed = parse_ts(data)
        if parsed is None:
            raise ValueError(f"Invalid timestamp: {data!r}")
        return parsed

    if is_dataclass(annotation):
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict for {annotation.__name__}")
        kwargs: Dict[str, Any] = {}
        for f in fields(annotation):
            if f.name not in data:
                continue
            kwargs[f.name] = _coerce(f.type, data[f.name])
        return annotation(**kwargs)

    if annotation is float:
        return float(data)
    if annotation is int:
        return int(data)
    if annotation is str:
        return str(data)
    if annotation is bool:
        return bool(data)
    if annotation is Any:
        return data

    return data


def _coerce_string_annotation(annotation: str, data: Any) -> Any:
    annotation = annotation.strip()
    if annotation.startswith("Optional["):
        return _coerce_string_annotation(annotation[len("Optional[") : -1], data)

    if annotation.startswith("List["):
        inner = annotation[len("List[") : -1]
        if not isinstance(data, list):
            raise TypeError("Expected list")
        return [_coerce_string_annotation(inner, item) for item in data]

    if annotation.startswith("Dict["):
        if not isinstance(data, dict):
            raise TypeError("Expected dict")
        return {str(k): v for k, v in data.items()}

    if annotation == "datetime":
        return _coerce(datetime, data)

    if annotation in ("str", "int", "float", "bool", "Any"):
        mapping = {"str": str, "int": int, "float": float, "bool": bool, "Any": Any}
        return _coerce(mapping[annotation], data)

    if annotation in _ENUM_BY_NAME:
        return _ENUM_BY_NAME[annotation](data)

    if annotation in _MODEL_BY_NAME:
        return _coerce(_MODEL_BY_NAME[annotation], data)

    raise TypeError(f"Unsupported annotation string {annotation!r}")
