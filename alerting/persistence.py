"""
Alert persistence — JSONL store + bounded history reader (R8.4).

Target path: logs/alerts.jsonl
Failures are non-fatal. Existing CSV schemas are never modified.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections import Counter
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from shared_contracts.models import AlertEvent, SCHEMA_VERSION
from shared_contracts.serialize import from_dict, to_dict

logger = logging.getLogger("intellishield.alerting.persistence")

DEFAULT_ALERTS_FILENAME = "alerts.jsonl"
# Soft bound when scanning for stats / filtered history from disk.
MAX_SCAN_LINES = 5000
DEFAULT_TAIL_BYTES = 512_000


@runtime_checkable
class AlertStore(Protocol):
    """Best-effort alert persistence. Implementations must never raise fatal."""

    name: str

    def append(self, alert: AlertEvent) -> bool:
        """Persist one alert. Return True on success, False on failure."""
        ...


class NullAlertStore:
    """No-op store."""

    name = "null"

    def append(self, alert: AlertEvent) -> bool:
        return True


class MemoryAlertStore:
    """Bounded in-memory store for tests / development."""

    name = "memory"

    def __init__(self, *, max_retained: int = 512) -> None:
        if max_retained < 1:
            raise ValueError("max_retained must be >= 1")
        self._max = int(max_retained)
        self.records: list = []

    def append(self, alert: AlertEvent) -> bool:
        self.records.append(alert)
        if len(self.records) > self._max:
            del self.records[: len(self.records) - self._max]
        return True


def default_alerts_jsonl_path(logs_dir: str) -> str:
    return os.path.join(logs_dir, DEFAULT_ALERTS_FILENAME)


class JsonlAlertStore:
    """
    Append-only JSONL persistence for AlertEvent.

    Each line is ``to_dict(AlertEvent)`` (schema_version included).
    A process-local lock serializes appends (OsKen is cooperative; lock
    still protects accidental concurrent writers in the same process).
    """

    name = "jsonl"

    def __init__(self, path: str) -> None:
        self.path = str(path)
        self._lock = threading.Lock()

    def append(self, alert: AlertEvent) -> bool:
        try:
            parent = os.path.dirname(self.path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            record = to_dict(alert)
            if "schema_version" not in record:
                record["schema_version"] = SCHEMA_VERSION
            line = json.dumps(record, separators=(",", ":"), sort_keys=True)
            with self._lock:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line)
                    fh.write("\n")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "[JsonlAlertStore] append failed (%s): %s",
                type(exc).__name__,
                exc,
            )
            return False


def _parse_alert_line(line: str) -> Optional[Dict[str, Any]]:
    text = (line or "").strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or "alert_id" not in data:
        return None
    payload = dict(data)
    payload["_type"] = "AlertEvent"
    try:
        obj = from_dict(payload, AlertEvent)
        return to_dict(obj)
    except Exception:  # noqa: BLE001
        # Malformed relative to contract but still JSON with alert_id —
        # expose as raw record for audit (dashboard may show partial).
        raw = dict(data)
        raw.setdefault("schema_version", SCHEMA_VERSION)
        return raw


def _tail_lines(path: str, *, max_lines: int, max_bytes: int = DEFAULT_TAIL_BYTES) -> List[str]:
    """Return up to max_lines from the end of the file without full-file load."""
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
            chunk = fh.read().decode("utf-8", errors="replace")
        lines = chunk.splitlines()
        # If we started mid-line, drop the first partial line.
        if size > read_size and lines:
            lines = lines[1:]
        return lines[-max_lines:]
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "[alert_history] tail read failed (%s): %s",
            type(exc).__name__,
            exc,
        )
        return []


def _match_filters(
    record: Dict[str, Any],
    *,
    severity: Optional[str],
    alert_type: Optional[str],
    since: Optional[str],
    until: Optional[str],
) -> bool:
    if severity:
        sev = str(record.get("severity") or "")
        if sev.upper() != severity.upper():
            return False
    if alert_type:
        at = str(record.get("alert_type") or "")
        if at.upper() != alert_type.upper():
            return False
    ts = str(record.get("timestamp") or "")
    if since and ts and ts < since:
        return False
    if until and ts and ts > until:
        return False
    return True


def read_alert_history(
    path: str,
    *,
    limit: int = 50,
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    scan_lines: int = MAX_SCAN_LINES,
) -> List[Dict[str, Any]]:
    """
    Return newest-first alert records (dicts), skipping malformed lines.

    Uses a bounded tail read — does not load an arbitrarily large file.
    """
    limit = max(0, min(int(limit), 500))
    if limit == 0:
        return []
    need_filter = bool(severity or alert_type or since or until)
    fetch_n = scan_lines if need_filter else limit
    fetch_n = min(max(fetch_n, limit), MAX_SCAN_LINES)
    lines = _tail_lines(path, max_lines=fetch_n)
    parsed: List[Dict[str, Any]] = []
    for line in lines:
        rec = _parse_alert_line(line)
        if rec is None:
            continue
        if not _match_filters(
            rec,
            severity=severity,
            alert_type=alert_type,
            since=since,
            until=until,
        ):
            continue
        parsed.append(rec)
    # Newest last in file → reverse for newest-first API
    parsed.reverse()
    return parsed[:limit]


def alert_history_stats(
    path: str,
    *,
    scan_lines: int = MAX_SCAN_LINES,
) -> Dict[str, Any]:
    """Bounded scan stats over recent JSONL lines."""
    lines = _tail_lines(path, max_lines=min(scan_lines, MAX_SCAN_LINES))
    by_severity: Counter = Counter()
    by_type: Counter = Counter()
    total = 0
    malformed = 0
    with_rca = 0
    for line in lines:
        if not (line or "").strip():
            continue
        rec = _parse_alert_line(line)
        if rec is None:
            malformed += 1
            continue
        total += 1
        by_severity[str(rec.get("severity") or "UNKNOWN")] += 1
        by_type[str(rec.get("alert_type") or "UNKNOWN")] += 1
        if rec.get("rca_report_id"):
            with_rca += 1
    exists = os.path.isfile(path)
    empty = (not exists) or (exists and os.path.getsize(path) == 0)
    return {
        "path": path,
        "scanned_lines": len(lines),
        "total": total,
        "malformed_skipped": malformed,
        "by_severity": dict(by_severity),
        "by_alert_type": dict(by_type),
        "with_rca_reference": with_rca,
        "schema_version": SCHEMA_VERSION,
        "exists": exists,
        "empty": empty,
    }


def alert_record_for_api(record: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten AlertEvent dict into dashboard-friendly fields."""
    evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
    return {
        "alert_id": record.get("alert_id", ""),
        "timestamp": record.get("timestamp", ""),
        "severity": record.get("severity", ""),
        "alert_type": record.get("alert_type", ""),
        "title": record.get("title", ""),
        "message": record.get("message", ""),
        "source": record.get("source", ""),
        "event_id": record.get("event_id"),
        "verification_id": evidence.get("verification_id"),
        "attacker_mac": evidence.get("attacker_mac") or "",
        "victim_mac": evidence.get("victim_mac") or "",
        "attack_hint": evidence.get("attack_hint") or "",
        "mitigation_status": record.get("mitigation_status"),
        "mitigation_ref": record.get("mitigation_ref"),
        "rca_report_id": record.get("rca_report_id"),
        "rca_status": "linked" if record.get("rca_report_id") else "absent",
        "correlation_id": evidence.get("correlation_id") or None,
        "correlation_score": evidence.get("correlation_score"),
        "correlation_summary": evidence.get("correlation_summary") or "",
        "correlation_status": (
            "linked" if evidence.get("correlation_id") or evidence.get("correlation_linked") else "absent"
        ),
        "fusion_id": evidence.get("fusion_id") or None,
        "fused_decision": evidence.get("fused_decision") or None,
        "fused_confidence": evidence.get("fused_confidence"),
        "fusion_disagreement": evidence.get("fusion_disagreement"),
        "fusion_status": (
            "linked" if evidence.get("fusion_id") or evidence.get("fusion_linked") else "absent"
        ),
        "dedup_key": record.get("dedup_key"),
        "schema_version": record.get("schema_version", SCHEMA_VERSION),
    }
