"""
Best-effort verification trace persistence (R7.3).

Writes append-only JSONL records. I/O failures never propagate to callers.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from shared_contracts.models import SCHEMA_VERSION, VerificationResult
from shared_contracts.timeutil import format_ts

logger = logging.getLogger("intellishield.verification.trace")

DEFAULT_TRACE_FILENAME = "verification_trace.jsonl"
# Soft bound per JSON line (bytes). Oversized stage details are trimmed.
MAX_RECORD_BYTES = 24_576
MAX_DETAIL_STRING = 512
MAX_STAGES = 32


def default_trace_path(logs_dir: str) -> str:
    return os.path.join(logs_dir, DEFAULT_TRACE_FILENAME)


def _trim_value(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_DETAIL_STRING:
        return value[: MAX_DETAIL_STRING - 3] + "..."
    if isinstance(value, dict):
        return {str(k): _trim_value(v) for k, v in list(value.items())[:40]}
    if isinstance(value, list):
        return [_trim_value(v) for v in value[:40]]
    return value


def verification_result_to_trace_record(
    result: VerificationResult,
    *,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a bounded JSON-serializable trace record."""
    status = getattr(result.status, "value", result.status)
    stages_out: List[Dict[str, Any]] = []
    for stage in list(result.stages or [])[:MAX_STAGES]:
        stages_out.append(
            {
                "stage_name": stage.stage_name,
                "passed": bool(stage.passed),
                "reason": str(stage.reason or "")[:MAX_DETAIL_STRING],
                "details": _trim_value(dict(stage.details or {})),
            }
        )

    record: Dict[str, Any] = {
        "schema_version": getattr(result, "schema_version", SCHEMA_VERSION)
        or SCHEMA_VERSION,
        "verification_id": result.verification_id,
        "event_id": result.event_id,
        "timestamp": format_ts(result.timestamp),
        "status": status,
        "mitigation_eligible": bool(result.mitigation_eligible),
        "stages": stages_out,
        "reason": str(result.reason or "")[:MAX_DETAIL_STRING],
    }
    if result.attacker_mac:
        record["attacker_mac"] = result.attacker_mac
    if result.victim_mac:
        record["victim_mac"] = result.victim_mac
    if result.confidence is not None:
        record["confidence"] = float(result.confidence)
    if extra:
        for key, value in extra.items():
            if key not in record:
                record[key] = _trim_value(value)
    return record


def append_verification_trace(
    result: VerificationResult,
    path: str,
    *,
    extra: Optional[Dict[str, Any]] = None,
    max_record_bytes: int = MAX_RECORD_BYTES,
) -> bool:
    """
    Append one verification trace line.

    Returns True on success, False on any failure (never raises).

    Growth: unbounded append-only JSONL (same pattern as other IntelliShield
    CSV/JSONL logs). Operators archive via existing practice
    (``mv logs/*.jsonl logs/archive/``). No rotation platform is added here.
    """
    try:
        record = verification_result_to_trace_record(result, extra=extra)
        line = json.dumps(record, separators=(",", ":"), sort_keys=True)
        encoded = line.encode("utf-8")
        if len(encoded) > max_record_bytes:
            # Drop stage details first, then stages entirely if still too large.
            for stage in record.get("stages", []):
                if isinstance(stage, dict):
                    stage["details"] = {"truncated": True}
            line = json.dumps(record, separators=(",", ":"), sort_keys=True)
            encoded = line.encode("utf-8")
            if len(encoded) > max_record_bytes:
                record["stages"] = [{"stage_name": "TRUNCATED", "passed": False,
                                     "reason": "record_too_large"}]
                record["reason"] = (record.get("reason") or "")[:200]
                line = json.dumps(record, separators=(",", ":"), sort_keys=True)

        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.write("\n")
        return True
    except Exception as exc:  # noqa: BLE001 — best-effort boundary
        logger.warning(
            "[verification_trace] append failed (%s): %s",
            type(exc).__name__,
            exc,
        )
        return False
