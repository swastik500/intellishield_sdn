"""Command input / target / event validation (no security-engine decisions)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .actions import ActionSpec, TargetType

_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TARGET_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$")
_REASON_MAX = 500
_REASON_MIN = 8


@dataclass
class ValidationResult:
    valid: bool
    reason: Optional[str] = None
    details: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "details": self.details or {},
        }


def validate_reason(reason: Optional[str]) -> ValidationResult:
    if reason is None or not isinstance(reason, str):
        return ValidationResult(False, "reason_required")
    text = reason.strip()
    if len(text) < _REASON_MIN:
        return ValidationResult(False, "reason_too_short")
    if len(text) > _REASON_MAX:
        return ValidationResult(False, "reason_too_long")
    low = text.lower()
    for banned in ("password=", "secret=", "token=", "api_key=", "authorization:"):
        if banned in low:
            return ValidationResult(False, "reason_contains_sensitive_pattern")
    return ValidationResult(True)


def validate_target(
    *,
    target_type: Optional[str],
    target_id: Optional[str],
    spec: ActionSpec,
) -> ValidationResult:
    if spec.target_type == TargetType.NONE:
        return ValidationResult(True, details={"target_type": TargetType.NONE.value})

    if not target_type or not isinstance(target_type, str):
        return ValidationResult(False, "target_type_required")
    tt = target_type.strip().upper()
    try:
        parsed = TargetType(tt)
    except ValueError:
        return ValidationResult(False, "target_type_invalid")

    if parsed != spec.target_type:
        return ValidationResult(
            False,
            "target_type_mismatch",
            {"expected": spec.target_type.value, "got": parsed.value},
        )

    if not target_id or not isinstance(target_id, str):
        return ValidationResult(False, "target_id_required")
    tid = target_id.strip()
    if not _TARGET_ID_RE.match(tid):
        return ValidationResult(False, "target_id_invalid")

    return ValidationResult(True, details={"type": parsed.value, "id": tid})


def validate_event_id(event_id: Optional[str], *, required: bool) -> ValidationResult:
    if not event_id:
        if required:
            return ValidationResult(False, "event_id_required")
        return ValidationResult(True, details={"event_id": None})
    if not isinstance(event_id, str):
        return ValidationResult(False, "event_id_invalid")
    eid = event_id.strip()
    if not _EVENT_ID_RE.match(eid):
        return ValidationResult(False, "event_id_invalid")
    return ValidationResult(True, details={"event_id": eid})


def validate_idempotency_key(key: Optional[str]) -> ValidationResult:
    if key is None or key == "":
        return ValidationResult(True)
    if not isinstance(key, str) or len(key) > 128:
        return ValidationResult(False, "idempotency_key_invalid")
    if not re.match(r"^[A-Za-z0-9._:-]+$", key):
        return ValidationResult(False, "idempotency_key_invalid")
    return ValidationResult(True)
