"""
Best-effort R6 fusion trace persistence (R6.3).

Append-only JSONL. I/O failures never propagate to callers.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

from shared_contracts.models import SCHEMA_VERSION, FusedDecision
from shared_contracts.timeutil import format_ts

logger = logging.getLogger("intellishield.fusion.trace")

DEFAULT_FUSION_TRACE_FILENAME = "fused_decisions.jsonl"
MAX_RECORD_BYTES = 24_576
MAX_STRING = 512


def default_fusion_trace_path(logs_dir: str) -> str:
    return os.path.join(logs_dir, DEFAULT_FUSION_TRACE_FILENAME)


def _trim(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_STRING:
        return value[: MAX_STRING - 3] + "..."
    if isinstance(value, dict):
        return {str(k): _trim(v) for k, v in list(value.items())[:48]}
    if isinstance(value, list):
        return [_trim(v) for v in value[:48]]
    return value


def fused_decision_to_trace_record(
    fused: FusedDecision,
    *,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    ev = dict(fused.evidence or {})
    scores = ev.get("scores") if isinstance(ev.get("scores"), dict) else {}
    votes = ev.get("primary_votes") if isinstance(ev.get("primary_votes"), list) else []
    compact_votes = []
    for v in votes[:8]:
        if not isinstance(v, dict):
            continue
        compact_votes.append(
            {
                "detector": v.get("detector"),
                "decision": v.get("decision"),
                "confidence": v.get("confidence"),
                "health": v.get("health"),
                "camp": v.get("camp"),
            }
        )
    record: Dict[str, Any] = {
        "schema_version": getattr(fused, "schema_version", SCHEMA_VERSION) or SCHEMA_VERSION,
        "fusion_id": fused.fusion_id,
        "event_id": fused.event_id,
        "timestamp": format_ts(fused.timestamp),
        "decision": getattr(fused.decision, "value", fused.decision),
        "confidence": fused.confidence,
        "participating": list(fused.participating or []),
        "disagreement": bool(fused.disagreement),
        "reason": str(fused.reason or "")[:MAX_STRING],
        "missing_detectors": list(ev.get("missing_detectors") or []),
        "degraded_detectors": list(ev.get("degraded_detectors") or []),
        "unavailable_detectors": list(ev.get("unavailable_detectors") or []),
        "stale_detectors": list(ev.get("stale_detectors") or []),
        "entity_key": ev.get("entity_key"),
        "scores": _trim(scores),
        "primary_votes": compact_votes,
        "correlation": _trim(ev.get("correlation") or {}),
        "context_uncertainty": _trim(ev.get("context_uncertainty") or {}),
        "decision_rule": ev.get("decision_rule"),
        "mitigation_authorized": False,
    }
    if extra:
        for k, v in extra.items():
            if k not in record:
                record[k] = _trim(v)
    return record


def append_fusion_trace(
    fused: FusedDecision,
    path: str,
    *,
    extra: Optional[Dict[str, Any]] = None,
) -> bool:
    """Append one JSONL record. Returns False on failure (never raises)."""
    try:
        record = fused_decision_to_trace_record(fused, extra=extra)
        line = json.dumps(record, default=str, separators=(",", ":"))
        if len(line.encode("utf-8")) > MAX_RECORD_BYTES:
            record["scores"] = {}
            record["correlation"] = {"truncated": True}
            record["context_uncertainty"] = {"truncated": True}
            line = json.dumps(record, default=str, separators=(",", ":"))
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return True
    except Exception:  # noqa: BLE001
        logger.debug("[append_fusion_trace] failed", exc_info=True)
        return False
