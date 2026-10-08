"""Timestamp helpers for shared contracts.

Policy:
  - Internal datetime fields are timezone-aware UTC.
  - JSON/dict serialization uses ISO-8601 with trailing 'Z' for UTC.
  - Existing CSV log formats (\"YYYY-MM-DD HH:MM:SS\") are NOT changed by
    this package; conversion helpers are available for adopters.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Union

# Legacy CSV timestamp format used across IntelliShield logs.
LEGACY_TS_FMT = "%Y-%m-%d %H:%M:%S"


def utc_now() -> datetime:
    """Return current UTC time as an aware datetime."""
    return datetime.now(timezone.utc)


def ensure_utc(ts: datetime) -> datetime:
    """Return *ts* as timezone-aware UTC."""
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def format_ts(ts: datetime) -> str:
    """Serialize datetime to ISO-8601 UTC (…Z)."""
    ts = ensure_utc(ts)
    # timespec=seconds keeps payloads small and deterministic
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: Union[str, datetime, None]) -> Optional[datetime]:
    """
    Parse a timestamp into aware UTC datetime.

    Accepts:
      - datetime (naive treated as UTC)
      - ISO-8601 with Z or offset
      - Legacy IntelliShield CSV format YYYY-MM-DD HH:MM:SS (assumed UTC)
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return ensure_utc(value)

    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        return ensure_utc(dt)
    except ValueError:
        pass
    try:
        dt = datetime.strptime(text, LEGACY_TS_FMT)
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def format_legacy_ts(ts: datetime) -> str:
    """Format as legacy CSV timestamp (UTC wall clock, no TZ suffix)."""
    return ensure_utc(ts).strftime(LEGACY_TS_FMT)
