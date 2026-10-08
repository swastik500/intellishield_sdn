"""
P0.1-preserving confidence normalization at R6 adapter boundaries.

Canonical fusion confidence: [0.0, 1.0].
Legacy ML/entropy often use 0–100 percent — convert only here.
"""

from __future__ import annotations

import math
from typing import Any, Optional


def to_unit_confidence(value: Any) -> Optional[float]:
    """
    Normalize confidence-like scalars to [0, 1].

    Rules:
    - None / non-numeric → None
    - NaN / Inf → None
    - value > 1.0 → treat as percent (÷100), clamp
    - otherwise clamp to [0, 1]
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(v):
        return None
    if v > 1.0:
        v = v / 100.0
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return float(v)


def finite_or_none(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(v):
        return None
    return float(v)
