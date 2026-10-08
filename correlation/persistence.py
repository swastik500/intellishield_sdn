"""
R4.3/R4.4 CorrelationResult JSONL persistence + bounded history reader.

Target: logs/correlation_results.jsonl
Uses shared_contracts.serialize.to_dict. Failures never crash the controller.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections import Counter
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from shared_contracts.models import CorrelationResult, SCHEMA_VERSION
from shared_contracts.serialize import to_dict
from shared_contracts.timeutil import parse_ts

logger = logging.getLogger("intellishield.correlation.persistence")

DEFAULT_CORR_FILENAME = "correlation_results.jsonl"
MAX_SCAN_LINES = 5000
DEFAULT_TAIL_BYTES = 512_000


def default_correlation_jsonl_path(logs_dir: str) -> str:
    return os.path.join(logs_dir, DEFAULT_CORR_FILENAME)


@runtime_checkable
class CorrelationStore(Protocol):
    name: str

    def append(self, result: CorrelationResult) -> bool:
        ...


class NullCorrelationStore:
    name = "null"

    def append(self, result: CorrelationResult) -> bool:
        return True


class MemoryCorrelationStore:
    name = "memory"

    def __init__(self, *, max_retained: int = 256) -> None:
        self._max = max(1, int(max_retained))
        self.records: list = []

    def append(self, result: CorrelationResult) -> bool:
        self.records.append(result)
        if len(self.records) > self._max:
            del self.records[: len(self.records) - self._max]
        return True


class JsonlCorrelationStore:
    """Append-only JSONL for CorrelationResult."""

    name = "jsonl"

    def __init__(self, path: str) -> None:
        self.path = str(path)
        self._lock = threading.Lock()

    def append(self, result: CorrelationResult) -> bool:
        try:
            parent = os.path.dirname(self.path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            record = to_dict(result)
            if "schema_version" not in record:
                record["schema_version"] = SCHEMA_VERSION
            line = json.dumps(record, separators=(",", ":"), sort_keys=True)
            with self._lock:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line)
                    fh.write("\n")
            return True
        except Exception:  # noqa: BLE001
            logger.warning(
                "[JsonlCorrelationStore] append failed (isolated)", exc_info=True
            )
            return False


def safe_append_correlation(
    store: Optional[CorrelationStore],
    result: Optional[CorrelationResult],
) -> bool:
    """Never raises."""
    if store is None or result is None:
        return False
    try:
        return bool(store.append(result))
    except Exception:  # noqa: BLE001
        logger.warning("[safe_append_correlation] store raised (isolated)", exc_info=True)
        return False


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


def _parse_corr_line(line: str) -> Optional[Dict[str, Any]]:
    try:
        obj = json.loads(line)
        if not isinstance(obj, dict):
            return None
        if not obj.get("correlation_id"):
            return None
        return obj
    except Exception:  # noqa: BLE001
        return None


def read_correlation_history(
    path: str,
    *,
    limit: int = 50,
    event_id: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    scan_lines: int = MAX_SCAN_LINES,
) -> List[Dict[str, Any]]:
    """Newest-first bounded CorrelationResult history. Malformed lines skipped."""
    if limit < 0:
        return []
    limit = min(int(limit), 500)
    since_dt = parse_ts(since) if since else None
    until_dt = parse_ts(until) if until else None
    lines = _tail_lines(path, max_lines=min(scan_lines, MAX_SCAN_LINES))
    parsed: List[Dict[str, Any]] = []
    for line in lines:
        rec = _parse_corr_line(line)
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


def get_correlation_result(
    path: str,
    correlation_id: str,
    *,
    scan_lines: int = MAX_SCAN_LINES,
) -> Optional[Dict[str, Any]]:
    if not correlation_id or not str(correlation_id).strip():
        return None
    cid = str(correlation_id).strip()
    found = None
    for line in _tail_lines(path, max_lines=min(scan_lines, MAX_SCAN_LINES)):
        rec = _parse_corr_line(line)
        if rec is None:
            continue
        if str(rec.get("correlation_id") or "") == cid:
            found = rec
    return found


def correlation_history_stats(path: str, *, scan_lines: int = 1000) -> Dict[str, Any]:
    exists = os.path.isfile(path)
    empty = (not exists) or (exists and os.path.getsize(path) == 0)
    rows = read_correlation_history(
        path, limit=min(scan_lines, 500), scan_lines=scan_lines
    )
    statuses = Counter()
    for r in rows:
        ev = r.get("evidence") if isinstance(r.get("evidence"), dict) else {}
        statuses[str(ev.get("status") or "UNKNOWN")] += 1
    return {
        "total": len(rows),
        "exists": exists,
        "empty": empty,
        "by_status": dict(statuses),
        "path": path,
        "source": "correlation_results.jsonl",
    }


def correlation_record_for_api(record: Dict[str, Any]) -> Dict[str, Any]:
    """Dashboard-friendly CorrelationResult flatten (R4.1 category names only)."""
    evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
    cats = evidence.get("participating_categories") or []
    if not isinstance(cats, list):
        cats = []
    focal = evidence.get("focal_entity_key")
    return {
        "correlation_id": record.get("correlation_id", ""),
        "timestamp": record.get("timestamp", ""),
        "event_id": record.get("event_id") or "UNAVAILABLE",
        "score": record.get("score"),
        "severity": record.get("severity") or "INFO",
        "window_start": record.get("window_start"),
        "window_end": record.get("window_end"),
        "signal_ids": list(record.get("signal_ids") or []),
        "signal_count": len(record.get("signal_ids") or []),
        "participating_categories": [str(c) for c in cats],
        "entity_key": focal or "UNAVAILABLE",
        "status": evidence.get("status") or "UNAVAILABLE",
        "summary": evidence.get("summary")
        or evidence.get("reason")
        or "UNAVAILABLE",
        "evidence_completeness": evidence.get("evidence_completeness"),
        "diversity_count": evidence.get("diversity_count"),
        "advisory_only": bool(evidence.get("advisory_only", True)),
        "mitigation_authorized": bool(evidence.get("mitigation_authorized", False)),
        "switch_id": evidence.get("switch_id"),
        "schema_version": record.get("schema_version", SCHEMA_VERSION),
        "note": evidence.get("note")
        or "Correlation expresses co-occurrence — not causation.",
    }
