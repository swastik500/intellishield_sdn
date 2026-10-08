"""Lab-only target safety helpers for twin orchestration (no attack launch)."""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence

# Mirrors AttackGenerator.ALLOWED_SUBNETS — twin must not target external nets.
ALLOWED_TWIN_SUBNETS: List[str] = [
    "10.0.0.",
    "10.0.1.",
    "10.0.2.",
    "192.168.0.",
]


def is_safe_twin_target(
    ip: str,
    *,
    allowed_subnets: Optional[Sequence[str]] = None,
) -> bool:
    """Return True iff *ip* is inside an allowed lab subnet prefix."""
    if not isinstance(ip, str) or not ip.strip():
        return False
    prefixes: Iterable[str] = allowed_subnets or ALLOWED_TWIN_SUBNETS
    return any(ip.startswith(p) for p in prefixes)


def assert_safe_twin_target(ip: str) -> None:
    """Raise ValueError if target is outside the twin/lab allow-list."""
    if not is_safe_twin_target(ip):
        raise ValueError(
            f"Twin target {ip!r} is outside allowed lab subnets "
            f"{ALLOWED_TWIN_SUBNETS}; external attacks are forbidden"
        )
