"""Event freshness evaluation — server time authoritative; fail-closed for high risk."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .actions import ActionSpec, RiskLevel


class FreshnessStatus:
    FRESH = "FRESH"
    STALE = "STALE"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"


@dataclass
class FreshnessResult:
    status: str
    max_age_seconds: Optional[int] = None
    age_seconds: Optional[float] = None
    detail: Optional[str] = None

    @property
    def blocks_high_risk(self) -> bool:
        """High/critical actions must not proceed when not configured or stale."""
        return self.status in {
            FreshnessStatus.NOT_CONFIGURED,
            FreshnessStatus.STALE,
            FreshnessStatus.INVALID_TIMESTAMP,
        }

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "max_age_seconds": self.max_age_seconds,
            "age_seconds": self.age_seconds,
            "detail": self.detail,
        }


def _parse_iso(ts: str) -> Optional[datetime]:
    try:
        s = ts.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def freshness_policy_configured() -> bool:
    """True when INTELLISHIELD_COMMAND_FRESHNESS_MAX_AGE_SECONDS is set to a positive int."""
    raw = os.environ.get("INTELLISHIELD_COMMAND_FRESHNESS_MAX_AGE_SECONDS", "").strip()
    if not raw:
        return False
    try:
        return int(raw) > 0
    except ValueError:
        return False


def max_age_seconds() -> Optional[int]:
    if not freshness_policy_configured():
        return None
    return int(os.environ["INTELLISHIELD_COMMAND_FRESHNESS_MAX_AGE_SECONDS"].strip())


def evaluate_freshness(
    spec: ActionSpec,
    *,
    event_timestamp: Optional[str],
    now: Optional[datetime] = None,
) -> FreshnessResult:
    """
    Server-side freshness.

    For HIGH/CRITICAL actions: if policy not configured → NOT_CONFIGURED (fail-closed).
    For LOW/MEDIUM without event timestamp → NOT_APPLICABLE.
    """
    n = now or datetime.now(timezone.utc)
    high = spec.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}

    if not freshness_policy_configured():
        if high:
            return FreshnessResult(
                FreshnessStatus.NOT_CONFIGURED,
                detail="Freshness policy not configured; high-risk commands blocked",
            )
        return FreshnessResult(
            FreshnessStatus.NOT_APPLICABLE,
            detail="Freshness policy not configured; low/medium dry-run allowed",
        )

    max_age = max_age_seconds()
    if event_timestamp is None:
        if high:
            return FreshnessResult(
                FreshnessStatus.NOT_CONFIGURED,
                max_age_seconds=max_age,
                detail="event timestamp required for high-risk freshness",
            )
        return FreshnessResult(FreshnessStatus.NOT_APPLICABLE, max_age_seconds=max_age)

    ts = _parse_iso(event_timestamp)
    if ts is None:
        return FreshnessResult(
            FreshnessStatus.INVALID_TIMESTAMP,
            max_age_seconds=max_age,
            detail="unparseable event timestamp",
        )

    age = (n - ts).total_seconds()
    if age < 0:
        # Future timestamp — treat as invalid (do not trust)
        return FreshnessResult(
            FreshnessStatus.INVALID_TIMESTAMP,
            max_age_seconds=max_age,
            age_seconds=age,
            detail="event timestamp in the future",
        )
    if age > float(max_age or 0):
        return FreshnessResult(
            FreshnessStatus.STALE,
            max_age_seconds=max_age,
            age_seconds=age,
            detail="event older than freshness window",
        )
    return FreshnessResult(
        FreshnessStatus.FRESH,
        max_age_seconds=max_age,
        age_seconds=age,
    )
