"""
RCA JSONL persistence + bounded history reader (R5.3 / R5.4).

Target: logs/root_cause_reports.jsonl
Uses shared_contracts.serialize.to_dict. Failures are non-fatal.
Does not modify CSV schemas. Avoids loading unlimited history.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from shared_contracts.models import RootCauseReport, SCHEMA_VERSION
from shared_contracts.serialize import from_dict, to_dict

logger = logging.getLogger("intellishield.rca.persistence")

DEFAULT_RCA_FILENAME = "root_cause_reports.jsonl"
MAX_SCAN_LINES = 5000
DEFAULT_TAIL_BYTES = 512_000


def default_rca_jsonl_path(logs_dir: str) -> str:
    return os.path.join(logs_dir, DEFAULT_RCA_FILENAME)


@runtime_checkable
class RCAStore(Protocol):
    name: str

    def append(self, report: RootCauseReport) -> bool:
        ...


class NullRCAStore:
    name = "null"

    def append(self, report: RootCauseReport) -> bool:
        return True


class MemoryRCAStore:
    name = "memory"

    def __init__(self, *, max_retained: int = 256) -> None:
        self._max = max(1, int(max_retained))
        self.records: list = []

    def append(self, report: RootCauseReport) -> bool:
        self.records.append(report)
        if len(self.records) > self._max:
            del self.records[: len(self.records) - self._max]
        return True


class JsonlRCAStore:
    """Append-only JSONL for RootCauseReport."""

    name = "jsonl"

    def __init__(self, path: str) -> None:
        self.path = str(path)
        self._lock = threading.Lock()

    def append(self, report: RootCauseReport) -> bool:
        try:
            parent = os.path.dirname(self.path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            record = to_dict(report)
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
                "[JsonlRCAStore] append failed (%s): %s",
                type(exc).__name__,
                exc,
            )
            return False


def safe_append_rca(
    store: Optional[RCAStore],
    report: Optional[RootCauseReport],
) -> bool:
    """Never raises."""
    if store is None or report is None:
        return False
    try:
        return bool(store.append(report))
    except Exception:  # noqa: BLE001
        logger.warning("[safe_append_rca] store raised (isolated)", exc_info=True)
        return False


def _tail_lines(path: str, *, max_lines: int, max_bytes: int = DEFAULT_TAIL_BYTES) -> List[str]:
    """Return up to max_lines from end of file without full-file load."""
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
        if size > read_size and lines:
            lines = lines[1:]
        return lines[-max_lines:]
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "[rca_history] tail read failed (%s): %s",
            type(exc).__name__,
            exc,
        )
        return []


def _parse_rca_line(line: str) -> Optional[Dict[str, Any]]:
    text = (line or "").strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or "report_id" not in data:
        return None
    payload = dict(data)
    payload["_type"] = "RootCauseReport"
    try:
        obj = from_dict(payload, RootCauseReport)
        return to_dict(obj)
    except Exception:  # noqa: BLE001
        raw = dict(data)
        raw.setdefault("schema_version", SCHEMA_VERSION)
        return raw


def read_rca_history(
    path: str,
    *,
    limit: int = 50,
    event_id: Optional[str] = None,
    scan_lines: int = MAX_SCAN_LINES,
) -> List[Dict[str, Any]]:
    """
    Newest-first RootCauseReport records; skips malformed lines.

    Bounded tail read — does not load an arbitrarily large file.
    """
    limit = max(0, min(int(limit), 500))
    if limit == 0:
        return []
    need_filter = bool(event_id)
    fetch_n = scan_lines if need_filter else limit
    fetch_n = min(max(fetch_n, limit), MAX_SCAN_LINES)
    lines = _tail_lines(path, max_lines=fetch_n)
    parsed: List[Dict[str, Any]] = []
    for line in lines:
        rec = _parse_rca_line(line)
        if rec is None:
            continue
        if event_id and str(rec.get("event_id") or "") != str(event_id):
            continue
        parsed.append(rec)
    parsed.reverse()
    return parsed[:limit]


def get_rca_report(
    path: str,
    report_id: str,
    *,
    scan_lines: int = MAX_SCAN_LINES,
) -> Optional[Dict[str, Any]]:
    """Lookup one report by report_id within a bounded recent window."""
    if not report_id or not str(report_id).strip():
        return None
    rid = str(report_id).strip()
    lines = _tail_lines(path, max_lines=min(scan_lines, MAX_SCAN_LINES))
    # Prefer newest match if duplicates somehow exist
    found = None
    for line in lines:
        rec = _parse_rca_line(line)
        if rec is None:
            continue
        if str(rec.get("report_id") or "") == rid:
            found = rec
    return found


def get_rca_by_event(
    path: str,
    event_id: str,
    *,
    scan_lines: int = MAX_SCAN_LINES,
) -> Optional[Dict[str, Any]]:
    """Newest report for an event_id within bounded window."""
    rows = read_rca_history(path, limit=1, event_id=event_id, scan_lines=scan_lines)
    return rows[0] if rows else None


def rca_record_for_api(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flatten RootCauseReport into dashboard-friendly fields.

    Evidence items retain OBSERVED / INFERRED / UNKNOWN / NOT_AVAILABLE kinds.
    XAI path evidence is summarized concisely (no raw tree dump).
    Never invents values — missing fields become UNAVAILABLE.
    """
    features = record.get("contributing_features")
    if not isinstance(features, dict):
        features = {}

    items_raw = features.get("evidence_items")
    evidence_items: List[Dict[str, Any]] = []
    if isinstance(items_raw, list):
        for item in items_raw:
            if not isinstance(item, dict):
                continue
            evidence_items.append(
                {
                    "key": item.get("key", ""),
                    "statement": item.get("statement", ""),
                    "kind": item.get("kind") or "UNKNOWN",
                    "value": item.get("value"),
                    "source": item.get("source") or "",
                }
            )

    missing = features.get("missing_evidence")
    if not isinstance(missing, list):
        missing = []

    baseline = features.get("baseline_evidence", "NOT_AVAILABLE")
    if baseline is None:
        baseline = "NOT_AVAILABLE"

    xai_block = features.get("xai")
    decision_evidence: List[str] = []
    prediction_label = "UNAVAILABLE"
    if isinstance(xai_block, dict):
        local = xai_block.get("local_path_features") or []
        if isinstance(local, list):
            for name in local[:8]:
                decision_evidence.append(str(name))
        steps = xai_block.get("decision_path_steps")
        if steps is not None:
            decision_evidence.append(f"path_steps={steps}")

    # Pull concise XAI lines from evidence_items when present
    for item in evidence_items:
        key = str(item.get("key") or "")
        if key in ("xai_leaf", "xai_method", "xai_local_path_features"):
            if key == "xai_leaf" and item.get("value") is not None:
                prediction_label = str(item["value"])
            if key == "xai_local_path_features" and isinstance(item.get("value"), list):
                decision_evidence = [str(v) for v in item["value"][:8]]

    expl_summary = record.get("explanation_summary")
    if not expl_summary:
        expl_summary = "UNAVAILABLE"

    conf = record.get("confidence")
    policy = features.get("rca_confidence_policy")
    if not isinstance(policy, dict):
        policy = {}

    return {
        "report_id": record.get("report_id", ""),
        "event_id": record.get("event_id", ""),
        "timestamp": record.get("timestamp", ""),
        "summary": record.get("summary") or "UNAVAILABLE",
        "suspected_source": record.get("suspected_source") or "UNAVAILABLE",
        "affected_target": record.get("affected_target") or "UNAVAILABLE",
        "attack_hint": features.get("attack_hint") or "UNAVAILABLE",
        "verification_status": features.get("verification_status") or "UNAVAILABLE",
        "mitigation_eligible": features.get("mitigation_eligible"),
        "mitigation_strategy": features.get("mitigation_strategy") or "UNAVAILABLE",
        "rca_confidence": conf if conf is not None else None,
        "rca_confidence_semantics": policy.get("semantics")
        or "evidence completeness (not ML confidence)",
        "prediction": prediction_label,
        "decision_evidence": decision_evidence,
        "explanation_summary": expl_summary,
        "contributing_signals": list(record.get("contributing_signals") or []),
        "evidence_items": evidence_items,
        "missing_evidence": [str(m) for m in missing],
        "baseline_evidence": baseline
        if baseline == "NOT_AVAILABLE" or isinstance(baseline, dict)
        else "NOT_AVAILABLE",
        "evidence_refs": list(record.get("evidence_refs") or []),
        "correlation": (
            features.get("correlation")
            if isinstance(features.get("correlation"), dict)
            else "NOT_AVAILABLE"
        ),
        "correlation_id": (
            (features.get("correlation") or {}).get("correlation_id")
            if isinstance(features.get("correlation"), dict)
            else None
        ),
        "fusion": (
            features.get("fusion")
            if isinstance(features.get("fusion"), dict)
            else "NOT_AVAILABLE"
        ),
        "fusion_id": (
            (features.get("fusion") or {}).get("fusion_id")
            if isinstance(features.get("fusion"), dict)
            else None
        ),
        "schema_version": record.get("schema_version", SCHEMA_VERSION),
    }
