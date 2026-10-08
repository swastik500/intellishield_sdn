"""
R4.1 SignalEvent + CorrelationWindow — input contracts / buffer.

FOUNDATION CorrelationResult remains the *output* DTO (R4.2+).
These types describe telemetry entering the correlator — not attack verdicts.
No correlation score is computed here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence

from shared_contracts.models import new_id
from shared_contracts.timeutil import ensure_utc, format_ts
from correlation.categories import SignalCategory
from correlation.clock import RealTimeProvider, TimeProvider
from correlation.identity import EntityIdentity, build_entity_key

SCHEMA_VERSION = "1.0"

_AVAIL = frozenset({"AVAILABLE", "NOT_AVAILABLE", "STALE", "DEGRADED"})


def new_signal_id() -> str:
    return new_id()


def new_window_id() -> str:
    return new_id()


@dataclass(frozen=True)
class SignalEvent:
    """
    One telemetry / security signal observation for correlation.

    ``timestamp`` = event time (for alignment).
    ``value`` must be JSON-safe scalar/structure or None (NOT_AVAILABLE).
    ``normalized_score`` optional [0,1] when already transformed; R4.2 may fill.
    Missing layers → omit SignalEvent or availability=NOT_AVAILABLE;
    do not invent zeros as negative evidence (R4.2 policy).
    """

    signal_id: str
    timestamp: datetime
    category: SignalCategory
    source: str
    name: str
    value: Optional[Any] = None
    unit: str = ""
    entity_key: Optional[str] = None
    event_id: Optional[str] = None
    switch_id: Optional[int] = None
    normalized_score: Optional[float] = None
    availability: str = "AVAILABLE"
    evidence: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.signal_id, str) or not self.signal_id.strip():
            raise ValueError("signal_id must be non-empty")
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("source must be non-empty")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("name must be non-empty")
        if not isinstance(self.category, SignalCategory):
            object.__setattr__(
                self, "category", SignalCategory(str(self.category))
            )
        object.__setattr__(self, "timestamp", ensure_utc(self.timestamp))
        object.__setattr__(self, "evidence", _json_safe_dict(self.evidence))
        if self.value is not None and not _is_json_safe(self.value):
            raise ValueError("value must be JSON-safe")
        avail = str(self.availability).upper()
        if avail not in _AVAIL:
            raise ValueError(f"availability must be one of {sorted(_AVAIL)}")
        object.__setattr__(self, "availability", avail)
        if self.normalized_score is not None:
            ns = float(self.normalized_score)
            if not (ns == ns) or ns < 0.0 or ns > 1.0:
                raise ValueError("normalized_score must be in [0, 1] or None")
            object.__setattr__(self, "normalized_score", ns)

    @property
    def signal_key(self) -> str:
        return f"{self.source}.{self.name}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "_type": "SignalEvent",
            "signal_id": self.signal_id,
            "timestamp": format_ts(self.timestamp),
            "category": self.category.value,
            "source": self.source,
            "name": self.name,
            "signal_key": self.signal_key,
            "value": self.value,
            "unit": self.unit,
            "entity_key": self.entity_key,
            "event_id": self.event_id,
            "switch_id": self.switch_id,
            "normalized_score": self.normalized_score,
            "availability": self.availability,
            "evidence": dict(self.evidence),
            "schema_version": self.schema_version,
        }


class CorrelationWindow:
    """
    Bounded, time-aligned signal buffer (R4.1).

    Responsibilities:
    - accept signals
    - time-align / retrieve by time, entity, category
    - expire stale signals (event-time window + optional monotonic TTL)
    - enforce maximum size

    Does NOT compute a correlation score (R4.2).
    """

    def __init__(
        self,
        *,
        window_id: Optional[str] = None,
        duration_sec: float = 30.0,
        max_signals: int = 256,
        clock: Optional[TimeProvider] = None,
        entity_key: Optional[str] = None,
        insert_ttl_sec: Optional[float] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        event_id: Optional[str] = None,
    ) -> None:
        if max_signals < 1:
            raise ValueError("max_signals must be >= 1")
        self.window_id = window_id or new_window_id()
        self.entity_key = entity_key
        self.event_id = event_id
        self.max_signals = int(max_signals)
        self.clock: TimeProvider = clock or RealTimeProvider()
        self.insert_ttl_sec = (
            float(insert_ttl_sec) if insert_ttl_sec is not None else None
        )
        self._fixed_start = ensure_utc(start) if start is not None else None
        self._fixed_end = ensure_utc(end) if end is not None else None
        if (
            self._fixed_start is not None
            and self._fixed_end is not None
            and self._fixed_end < self._fixed_start
        ):
            raise ValueError("window end must be >= start")
        if self._fixed_start is not None and self._fixed_end is not None:
            self._duration_sec = max(
                0.0, (self._fixed_end - self._fixed_start).total_seconds()
            )
        else:
            if duration_sec <= 0:
                raise ValueError("duration_sec must be > 0")
            self._duration_sec = float(duration_sec)
        self._by_id: Dict[str, SignalEvent] = {}
        self._inserted_mono: Dict[str, float] = {}

    @property
    def duration_sec(self) -> float:
        return self._duration_sec

    @property
    def start(self) -> Optional[datetime]:
        if self._fixed_start is not None:
            return self._fixed_start
        if not self._by_id:
            return None
        latest = max(s.timestamp for s in self._by_id.values())
        return latest - timedelta(seconds=self._duration_sec)

    @property
    def end(self) -> Optional[datetime]:
        if self._fixed_end is not None:
            return self._fixed_end
        if not self._by_id:
            return None
        return max(s.timestamp for s in self._by_id.values())

    @property
    def signal_ids(self) -> List[str]:
        return [s.signal_id for s in self.get()]

    def contains_timestamp(self, ts: datetime) -> bool:
        t = ensure_utc(ts)
        if self._fixed_start is not None and self._fixed_end is not None:
            return self._fixed_start <= t <= self._fixed_end
        if not self._by_id:
            return True
        latest = max(s.timestamp for s in self._by_id.values())
        return (latest - timedelta(seconds=self._duration_sec)) <= t <= latest

    def with_signals(self, signals: Sequence[SignalEvent]) -> "CorrelationWindow":
        """Fixed-bound helper: new window containing in-range matching signals."""
        if self._fixed_start is None or self._fixed_end is None:
            raise ValueError("with_signals requires fixed start/end bounds")
        w = CorrelationWindow(
            window_id=self.window_id,
            max_signals=self.max_signals,
            clock=self.clock,
            entity_key=self.entity_key,
            event_id=self.event_id,
            start=self._fixed_start,
            end=self._fixed_end,
        )
        for s in signals:
            w.accept(s)
        return w

    def accept(self, signal: SignalEvent) -> bool:
        """Insert or replace a signal. Returns False if rejected by filters."""
        if not isinstance(signal, SignalEvent):
            raise TypeError("signal must be SignalEvent")
        if (
            self.entity_key is not None
            and signal.entity_key is not None
            and signal.entity_key != self.entity_key
        ):
            return False
        if self._fixed_start is not None and self._fixed_end is not None:
            if not (self._fixed_start <= signal.timestamp <= self._fixed_end):
                return False
        self._by_id[signal.signal_id] = signal
        self._inserted_mono[signal.signal_id] = self.clock.monotonic()
        self.expire(reference_ts=signal.timestamp)
        self._enforce_bound()
        return True

    def expire(self, reference_ts: Optional[datetime] = None) -> int:
        """Drop stale signals (event-time window + optional monotonic insert TTL)."""
        removed = 0
        now_mono = self.clock.monotonic()
        ref = ensure_utc(reference_ts) if reference_ts is not None else self.end
        drop_ids: List[str] = []
        for sid, sig in self._by_id.items():
            if self._fixed_start is not None and self._fixed_end is not None:
                if not (self._fixed_start <= sig.timestamp <= self._fixed_end):
                    drop_ids.append(sid)
                    continue
            elif ref is not None:
                oldest = ref - timedelta(seconds=self._duration_sec)
                if sig.timestamp < oldest:
                    drop_ids.append(sid)
                    continue
            if self.insert_ttl_sec is not None:
                inserted = self._inserted_mono.get(sid, now_mono)
                if (now_mono - inserted) > self.insert_ttl_sec:
                    drop_ids.append(sid)
        for sid in drop_ids:
            self._by_id.pop(sid, None)
            self._inserted_mono.pop(sid, None)
            removed += 1
        return removed

    def _enforce_bound(self) -> None:
        while len(self._by_id) > self.max_signals:
            oldest_id = min(
                self._by_id.keys(),
                key=lambda i: (
                    self._by_id[i].timestamp,
                    self._inserted_mono.get(i, 0.0),
                ),
            )
            self._by_id.pop(oldest_id, None)
            self._inserted_mono.pop(oldest_id, None)

    def get(
        self,
        *,
        entity_key: Optional[str] = None,
        category: Optional[SignalCategory] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        source: Optional[str] = None,
    ) -> List[SignalEvent]:
        """Retrieve signals filtered and ordered by event timestamp ascending."""
        since_u = ensure_utc(since) if since is not None else None
        until_u = ensure_utc(until) if until is not None else None
        out: List[SignalEvent] = []
        for sig in self._by_id.values():
            if entity_key is not None and sig.entity_key != entity_key:
                continue
            if category is not None and sig.category != category:
                continue
            if source is not None and sig.source != source:
                continue
            if since_u is not None and sig.timestamp < since_u:
                continue
            if until_u is not None and sig.timestamp > until_u:
                continue
            out.append(sig)
        out.sort(key=lambda s: (s.timestamp, s.signal_id))
        return out

    def size(self) -> int:
        return len(self._by_id)

    def clear(self) -> None:
        self._by_id.clear()
        self._inserted_mono.clear()

    def categories_present(self) -> List[SignalCategory]:
        return sorted({s.category for s in self._by_id.values()}, key=lambda c: c.value)

    def to_dict(self) -> Dict[str, Any]:
        start = self.start
        end = self.end
        return {
            "_type": "CorrelationWindow",
            "window_id": self.window_id,
            "start": format_ts(start) if start else None,
            "end": format_ts(end) if end else None,
            "duration_sec": self.duration_sec,
            "entity_key": self.entity_key,
            "event_id": self.event_id,
            "max_signals": self.max_signals,
            "size": self.size(),
            "signal_ids": self.signal_ids,
            "schema_version": SCHEMA_VERSION,
        }


def _is_json_safe(value: Any, depth: int = 0) -> bool:
    if depth > 4:
        return False
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return value == value and value not in (float("inf"), float("-inf"))
    if isinstance(value, list):
        return all(_is_json_safe(v, depth + 1) for v in value)
    if isinstance(value, dict):
        return all(
            isinstance(k, str) and _is_json_safe(v, depth + 1)
            for k, v in value.items()
        )
    return False


def _json_safe_dict(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("evidence must be a dict")
    out = {}
    for k, v in data.items():
        if not isinstance(k, str):
            raise ValueError("evidence keys must be strings")
        if not _is_json_safe(v):
            raise ValueError(f"evidence[{k!r}] is not JSON-safe")
        out[k] = v
    return out


__all__ = [
    "SignalEvent",
    "CorrelationWindow",
    "EntityIdentity",
    "build_entity_key",
    "new_signal_id",
    "new_window_id",
]
