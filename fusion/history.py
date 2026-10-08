"""
R6.4 FusedDecision JSONL history reader (dashboard / API).

Reads logs/fused_decisions.jsonl written by fusion.trace.append_fusion_trace.
Bounded scan; malformed lines skipped; never raises to callers.
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from typing import Any, Dict, List, Optional

from shared_contracts.models import SCHEMA_VERSION
from shared_contracts.timeutil import parse_ts
from fusion.trace import DEFAULT_FUSION_TRACE_FILENAME

logger = logging.getLogger("intellishield.fusion.history")

MAX_SCAN_LINES = 5000
DEFAULT_TAIL_BYTES = 512_000


def default_fused_decisions_jsonl_path(logs_dir: str) -> str:
    return os.path.join(logs_dir, DEFAULT_FUSION_TRACE_FILENAME)


def _tail_lines(path: str, *, max_lines: int, max_bytes: int = DEFAULT_TAIL_BYTES) -> List[str]:
    if max_lines < 1:
        return []
    try:
        if not os.path.isfile(path):
            return []
        size = os.path.getsize(path)
        if size == 0:
            return []
        with open(path, "rb") as fh:
            read_size = min(size, max(max_bytes, max_lines * 256))
            fh.seek(max(0, size - read_size))
            raw = fh.read().decode("utf-8", errors="replace")
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        return lines[-max_lines:]
    except Exception:  # noqa: BLE001
        logger.debug("[_tail_lines] failed for %s", path, exc_info=True)
        return []


def _parse_fusion_line(line: str) -> Optional[Dict[str, Any]]:
    try:
        obj = json.loads(line)
        if not isinstance(obj, dict):
            return None
        if not obj.get("fusion_id"):
            return None
        return obj
    except Exception:  # noqa: BLE001
        return None


def read_fused_decision_history(
    path: str,
    *,
    limit: int = 50,
    event_id: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    scan_lines: int = MAX_SCAN_LINES,
) -> List[Dict[str, Any]]:
    """Newest-first bounded fusion history. Malformed lines skipped."""
    if limit < 0:
        return []
    limit = min(int(limit), 500)
    since_dt = parse_ts(since) if since else None
    until_dt = parse_ts(until) if until else None
    lines = _tail_lines(path, max_lines=min(scan_lines, MAX_SCAN_LINES))
    parsed: List[Dict[str, Any]] = []
    for line in lines:
        rec = _parse_fusion_line(line)
        if rec is None:
            continue
        if event_id is not None and str(rec.get("event_id") or "") != str(event_id):
            continue
        ts = parse_ts(rec.get("timestamp"))
        if since_dt is not None and (ts is None or ts < since_dt):
            continue
        if until_dt is not None and (ts is None or ts > until_dt):
            continue
        parsed.append(rec)
    parsed.reverse()
    return parsed[:limit]


def get_fused_decision(
    path: str,
    fusion_id: str,
    *,
    scan_lines: int = MAX_SCAN_LINES,
) -> Optional[Dict[str, Any]]:
    if not fusion_id or not str(fusion_id).strip():
        return None
    fid = str(fusion_id).strip()
    found = None
    for line in _tail_lines(path, max_lines=min(scan_lines, MAX_SCAN_LINES)):
        rec = _parse_fusion_line(line)
        if rec is None:
            continue
        if str(rec.get("fusion_id") or "") == fid:
            found = rec
    return found


def fused_decision_history_stats(
    path: str, *, scan_lines: int = 1000
) -> Dict[str, Any]:
    exists = os.path.isfile(path)
    empty = (not exists) or (exists and os.path.getsize(path) == 0)
    rows = read_fused_decision_history(
        path, limit=min(scan_lines, 500), scan_lines=scan_lines
    )
    by_decision = Counter()
    disagreements = 0
    for r in rows:
        by_decision[str(r.get("decision") or "UNKNOWN")] += 1
        if r.get("disagreement"):
            disagreements += 1
    return {
        "total": len(rows),
        "exists": exists,
        "empty": empty,
        "by_decision": dict(by_decision),
        "disagreement_count": disagreements,
        "path": path,
        "source": DEFAULT_FUSION_TRACE_FILENAME,
    }


def fused_decision_record_for_api(record: Dict[str, Any]) -> Dict[str, Any]:
    """Dashboard-friendly FusedDecision flatten (context ≠ attack detected)."""
    scores = record.get("scores") if isinstance(record.get("scores"), dict) else {}
    corr = record.get("correlation") if isinstance(record.get("correlation"), dict) else {}
    ctx = (
        record.get("context_uncertainty")
        if isinstance(record.get("context_uncertainty"), dict)
        else {}
    )
    # Prefer primary_votes from nested evidence if present in raw contracts;
    # trace records store flat fields.
    votes = record.get("primary_votes")
    if not isinstance(votes, list):
        votes = []

    context_signals = list(ctx.get("signals") or [])
    context_note = (
        "ADWIN/HDBSCAN shown as context indicators only — not attack detected."
        if context_signals
        else None
    )

    return {
        "fusion_id": record.get("fusion_id", ""),
        "timestamp": record.get("timestamp", ""),
        "event_id": record.get("event_id") or "UNAVAILABLE",
        "entity_key": record.get("entity_key") or "UNAVAILABLE",
        "decision": record.get("decision") or "UNAVAILABLE",
        "confidence": record.get("confidence"),
        "participating": list(record.get("participating") or []),
        "disagreement": bool(record.get("disagreement")),
        "agreement": not bool(record.get("disagreement")),
        "missing_detectors": list(record.get("missing_detectors") or []),
        "degraded_detectors": list(record.get("degraded_detectors") or []),
        "unavailable_detectors": list(record.get("unavailable_detectors") or []),
        "stale_detectors": list(record.get("stale_detectors") or []),
        "scores": {
            "A": scores.get("A"),
            "N": scores.get("N"),
            "S": scores.get("S"),
            "G": scores.get("G"),
            "C": scores.get("C"),
            "R": scores.get("R"),
            "U": scores.get("U"),
        },
        "r4_support": {
            "present": bool(corr.get("present")),
            "boost_applied": corr.get("boost_applied"),
            "correlation_id": corr.get("correlation_id"),
            "score": corr.get("score"),
        },
        "context_indicators": context_signals,
        "context_note": context_note
        or "No ADWIN/HDBSCAN context on this record.",
        "decision_rule": record.get("decision_rule"),
        "reason": record.get("reason") or "",
        "verification_id": record.get("verification_id"),
        "dpid": record.get("dpid"),
        "schema_version": record.get("schema_version", SCHEMA_VERSION),
        "mitigation_authorized": False,
        "note": "Collaborative fusion evidence — R7 still gates mitigation.",
        "primary_votes": votes[:8] if votes else [],
    }
