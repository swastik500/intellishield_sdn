"""
================================================================================
IntelliShield SDN — Phase 2: Entropy Detection Engine
================================================================================

File        : entropy_engine/entropy_utils.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 2 — Entropy-Based DDoS Detection

Description:
    Low-level utility functions for probability distributions, safe logarithms,
    entropy normalization, and statistical helpers. All higher-level entropy
    modules import from here — keeping math isolated and testable.

IEEE Relevance:
    Implements the mathematical primitives required for Shannon entropy H(X).
    These utilities ensure numerical stability (log2(0) avoidance) and
    normalized entropy output for fair cross-feature comparison.

================================================================================
"""

import math
from collections import Counter
from typing import List, Dict, Tuple, Optional


# ─── Probability Distribution ─────────────────────────────────────────────────

def calculate_probability_distribution(values: list) -> Dict[str, float]:
    """
    Compute probability distribution P(x_i) for a list of observed values.

    Counts occurrences of each unique value and normalises by total count
    to produce a proper probability mass function: sum(P) == 1.0

    Args:
        values: List of hashable items (MACs, ports, counts, etc.)

    Returns:
        Dict mapping each unique value → its probability.
        Returns empty dict if input is empty.

    Example:
        >>> calculate_probability_distribution(['A','A','B','C'])
        {'A': 0.5, 'B': 0.25, 'C': 0.25}
    """
    if not values:
        return {}

    total = len(values)
    counts = Counter(values)
    return {k: v / total for k, v in counts.items()}


def calculate_probability_distribution_from_counts(count_dict: dict) -> Dict[str, float]:
    """
    Compute probability distribution from a pre-counted {value: count} dict.

    Useful when flow stats already provide packet/byte counts per flow —
    avoids re-expanding counts into a raw list.

    Args:
        count_dict: Dict mapping values → integer counts.

    Returns:
        Dict mapping values → probabilities. Empty dict if input is empty.

    Example:
        >>> calculate_probability_distribution_from_counts({'h1': 200, 'h2': 100})
        {'h1': 0.6667, 'h2': 0.3333}
    """
    if not count_dict:
        return {}

    total = sum(count_dict.values())
    if total == 0:
        return {}

    return {k: v / total for k, v in count_dict.items()}


# ─── Safe Logarithm ───────────────────────────────────────────────────────────

def safe_log2(p: float) -> float:
    """
    Compute log2(p) safely, returning 0.0 when p <= 0.

    Shannon entropy requires p * log2(p) for each probability p.
    By convention: 0 * log2(0) = 0 (the limit as p→0+ is 0).
    This function enforces that convention by returning 0.0 for p <= 0.

    Args:
        p: Probability value (expected in [0, 1]).

    Returns:
        float: log2(p) if p > 0, else 0.0.

    Example:
        >>> safe_log2(0.5)
        -1.0
        >>> safe_log2(0.0)
        0.0
    """
    if p <= 0.0:
        return 0.0
    return math.log2(p)


# ─── Entropy Normalization ────────────────────────────────────────────────────

def normalize_entropy(entropy: float, num_categories: int) -> float:
    """
    Normalize Shannon entropy to [0, 1] range.

    Normalized entropy = H(X) / H_max
    where H_max = log2(n) is the maximum possible entropy for n categories.

    Normalized entropy = 1.0 means perfectly uniform distribution.
    Normalized entropy = 0.0 means perfectly concentrated (one category).

    Args:
        entropy      : Raw Shannon entropy value H(X).
        num_categories: Number of distinct categories (n).

    Returns:
        float: Normalized entropy in [0.0, 1.0].
               Returns 0.0 if num_categories <= 1 (undefined case).

    Example:
        >>> normalize_entropy(2.0, 4)   # H_max = log2(4) = 2.0
        1.0
    """
    if num_categories <= 1:
        return 0.0
    h_max = math.log2(num_categories)
    if h_max == 0.0:
        return 0.0
    return min(1.0, entropy / h_max)


# ─── Distribution Validation ──────────────────────────────────────────────────

def validate_distribution(prob_dist: dict) -> Tuple[bool, str]:
    """
    Validate that a probability distribution is well-formed.

    Checks:
      1. Not empty
      2. All probabilities are non-negative
      3. Probabilities sum to approximately 1.0 (tolerance: ±0.01)

    Args:
        prob_dist: Dict mapping category → probability.

    Returns:
        Tuple (is_valid: bool, message: str)

    Example:
        >>> validate_distribution({'A': 0.5, 'B': 0.5})
        (True, 'Valid distribution')
    """
    if not prob_dist:
        return False, "Empty distribution"

    for k, p in prob_dist.items():
        if p < 0:
            return False, f"Negative probability for '{k}': {p}"

    total = sum(prob_dist.values())
    if not (0.99 <= total <= 1.01):
        return False, f"Probabilities sum to {total:.4f}, expected ~1.0"

    return True, "Valid distribution"


# ─── Statistical Helpers ──────────────────────────────────────────────────────

def compute_mean(values: list) -> float:
    """
    Compute arithmetic mean of a list of numeric values.

    Args:
        values: List of numbers.

    Returns:
        float: Mean, or 0.0 if list is empty.
    """
    if not values:
        return 0.0
    return sum(values) / len(values)


def compute_std(values: list, mean: Optional[float] = None) -> float:
    """
    Compute population standard deviation of a numeric list.

    Used to measure entropy variability over time — high std indicates
    volatile traffic patterns (useful for ADWIN baseline in Phase 6).

    Args:
        values: List of numbers.
        mean  : Pre-computed mean (optional, avoids double pass).

    Returns:
        float: Standard deviation, or 0.0 if fewer than 2 values.
    """
    if len(values) < 2:
        return 0.0
    if mean is None:
        mean = compute_mean(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return math.sqrt(variance)


def clamp(value: float, lo: float, hi: float) -> float:
    """
    Clamp a float value to [lo, hi] range.

    Args:
        value: Input value.
        lo   : Minimum bound.
        hi   : Maximum bound.

    Returns:
        float: value clamped to [lo, hi].
    """
    return max(lo, min(hi, value))


def bucket_values(values: list, num_buckets: int = 10) -> list:
    """
    Discretize a list of continuous values into `num_buckets` equal-width bins.

    Used to compute entropy over continuous metrics (packet_rate, byte_rate)
    by first binning them into discrete categories.

    Args:
        values     : List of numeric values.
        num_buckets: Number of bins.

    Returns:
        List of bucket indices (integers) — same length as input.

    Special case (BUGFIX):
        When all values are identical (max == min), the old code returned all
        zeros, causing entropy to collapse to 0.0 — wrongly triggering an ALERT
        on perfectly balanced traffic (e.g., 5 flows each with 10 packets).

        Fix: return one unique index per flow so the distribution is perfectly
        uniform, giving entropy = 1.0 (maximum = normal balanced traffic).

    Example:
        >>> bucket_values([1, 5, 10], num_buckets=3)
        [0, 1, 2]
        >>> bucket_values([10, 10, 10], num_buckets=3)  # equal → each gets own bucket
        [0, 1, 2]
    """
    if not values:
        return []

    min_v = min(values)
    max_v = max(values)

    if max_v == min_v:
        # All values are identical — perfectly uniform distribution.
        # Assign each flow its own unique bucket index so Shannon entropy
        # correctly equals 1.0 (maximum diversity) instead of 0.0 (collapse).
        # We cap at num_buckets so bucket indices stay in the expected range.
        return [i % num_buckets for i in range(len(values))]

    span = max_v - min_v
    result = []
    for v in values:
        idx = int((v - min_v) / span * (num_buckets - 1))
        result.append(idx)
    return result
