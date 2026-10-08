"""
================================================================================
IntelliShield SDN — Phase 2: Entropy Detection Engine
================================================================================

File        : entropy_engine/entropy_calculator.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 2 — Entropy-Based DDoS Detection

Description:
    Core Shannon entropy calculation module. Computes 5 entropy dimensions
    from a batch of flow feature dictionaries:

        1. Source MAC Entropy     — diversity of traffic origins
        2. Destination MAC Entropy — concentration toward victim(s)
        3. Packet Distribution Entropy — evenness of packet load
        4. Byte Distribution Entropy  — evenness of byte load
        5. Flow Distribution Entropy  — overall flow diversity

    Each function is independent, testable, and returns both a raw and
    normalized entropy value.

Mathematical Foundation:
    Shannon Entropy:  H(X) = -Σ p(x_i) * log2(p(x_i))
    Normalized:       H_norm = H(X) / log2(n)   where n = |categories|

IEEE Relevance:
    Multi-dimensional entropy analysis is the core novelty of IntelliShield.
    Using 5 simultaneous entropy metrics improves detection accuracy over
    single-metric approaches documented in prior SDN security literature.

Future Integration Points:
    - [HOOK] Phase 6 → ADWIN drift detector monitors entropy time series
    - [HOOK] Phase 7 → PPO RL adjusts per-dimension thresholds dynamically

================================================================================
"""

import math
from typing import List, Dict, Optional

from entropy_engine.entropy_utils import (
    calculate_probability_distribution,
    calculate_probability_distribution_from_counts,
    safe_log2,
    normalize_entropy,
    validate_distribution,
    bucket_values,
)


# ─── Core Shannon Entropy ─────────────────────────────────────────────────────

def calculate_shannon_entropy(prob_dist: dict) -> float:
    """
    Compute Shannon entropy H(X) from a probability distribution.

    Formula: H(X) = -Σ p(x_i) * log2(p(x_i))

    Properties:
      - H(X) = 0  : All probability concentrated in one event (pure attack)
      - H(X) = log2(n) : Perfectly uniform distribution (normal traffic)

    Args:
        prob_dist: Dict mapping category → probability (must sum to ~1.0).

    Returns:
        float: Shannon entropy in bits. Returns 0.0 for empty input.

    Example:
        >>> calculate_shannon_entropy({'A': 0.5, 'B': 0.5})
        1.0
        >>> calculate_shannon_entropy({'A': 1.0})
        0.0
    """
    if not prob_dist:
        return 0.0

    is_valid, msg = validate_distribution(prob_dist)
    if not is_valid:
        # Degenerate distribution — return 0 entropy (concentrated)
        return 0.0

    entropy = 0.0
    for p in prob_dist.values():
        if p > 0:
            entropy -= p * safe_log2(p)

    return round(entropy, 6)


# ─── Per-Dimension Entropy Calculators ───────────────────────────────────────

def calculate_src_entropy(flow_features: List[dict],
                           normalized: bool = False) -> Dict[str, float]:
    """
    Calculate Shannon entropy of source MAC address distribution.

    High src_entropy → traffic comes from many diverse sources (NORMAL).
    Low  src_entropy → traffic dominated by few sources (POSSIBLE ATTACK).

    In a SYN flood from a single attacker, src_entropy approaches 0.

    Args:
        flow_features: List of flow feature dicts from Phase 1 monitor.
        normalized   : If True, normalize to [0, 1] range.

    Returns:
        Dict with keys:
            'entropy'   : Raw Shannon entropy (bits)
            'normalized': Normalized entropy [0,1] (if requested)
            'n_sources' : Number of unique source MACs seen
            'dominant'  : MAC with highest traffic share (or 'unknown')

    Example:
        >>> feats = [{'src_mac': 'aa:bb', ...}, {'src_mac': 'cc:dd', ...}]
        >>> calculate_src_entropy(feats)
        {'entropy': 1.0, 'normalized': 1.0, 'n_sources': 2, 'dominant': ...}
    """
    src_macs = [
        f.get("src_mac", "unknown")
        for f in flow_features
        if f.get("src_mac") not in (None, "", "unknown")
    ]

    if not src_macs:
        return {"entropy": 0.0, "normalized": 0.0, "n_sources": 0, "dominant": "none"}

    prob_dist = calculate_probability_distribution(src_macs)
    entropy   = calculate_shannon_entropy(prob_dist)
    n_sources = len(prob_dist)
    dominant  = max(prob_dist, key=prob_dist.get) if prob_dist else "unknown"
    norm      = normalize_entropy(entropy, n_sources) if normalized else entropy

    return {
        "entropy"    : round(entropy, 6),
        "normalized" : round(norm, 6),
        "n_sources"  : n_sources,
        "dominant"   : dominant,
    }


def calculate_dst_entropy(flow_features: List[dict],
                           normalized: bool = False) -> Dict[str, float]:
    """
    Calculate Shannon entropy of destination MAC address distribution.

    High dst_entropy → packets distributed across many destinations (NORMAL).
    Low  dst_entropy → packets concentrated on one target (VICTIM FOCUSED).

    In a volumetric DDoS attack, most packets target a single host.
    dst_entropy will collapse toward 0 in that scenario.

    Args:
        flow_features: List of flow feature dicts.
        normalized   : If True, normalize to [0, 1].

    Returns:
        Dict with 'entropy', 'normalized', 'n_destinations', 'dominant'.
    """
    dst_macs = [
        f.get("dst_mac", "unknown")
        for f in flow_features
        if f.get("dst_mac") not in (None, "", "unknown")
           and f.get("dst_mac") != "ff:ff:ff:ff:ff:ff"  # skip broadcasts
    ]

    if not dst_macs:
        return {"entropy": 0.0, "normalized": 0.0, "n_destinations": 0, "dominant": "none"}

    prob_dist     = calculate_probability_distribution(dst_macs)
    entropy       = calculate_shannon_entropy(prob_dist)
    n_destinations = len(prob_dist)
    dominant      = max(prob_dist, key=prob_dist.get) if prob_dist else "unknown"
    norm          = normalize_entropy(entropy, n_destinations) if normalized else entropy

    return {
        "entropy"        : round(entropy, 6),
        "normalized"     : round(norm, 6),
        "n_destinations" : n_destinations,
        "dominant"       : dominant,
    }


def calculate_packet_entropy(flow_features: List[dict],
                              num_buckets: int = 10,
                              normalized: bool = False) -> Dict[str, float]:
    """
    Calculate Shannon entropy of packet count distribution across flows.

    Measures how evenly packet load is distributed.

    High packet_entropy → flows carry similar packet volumes (NORMAL).
    Low  packet_entropy → one flow carries almost all packets (FLOOD).

    Packet counts are discretized into `num_buckets` bins before entropy
    computation (continuous values → discrete entropy problem).

    Args:
        flow_features: List of flow feature dicts.
        num_buckets  : Number of bins for discretization (default 10).
        normalized   : If True, normalize to [0, 1].

    Returns:
        Dict with 'entropy', 'normalized', 'n_flows', 'max_packets'.
    """
    packet_counts = [
        f.get("packet_count", 0)
        for f in flow_features
        if f.get("packet_count") is not None
    ]

    if not packet_counts or sum(packet_counts) == 0:
        return {"entropy": 0.0, "normalized": 0.0, "n_flows": 0, "max_packets": 0}

    bucketed   = bucket_values(packet_counts, num_buckets=num_buckets)
    prob_dist  = calculate_probability_distribution(bucketed)
    entropy    = calculate_shannon_entropy(prob_dist)
    n_buckets  = len(prob_dist)
    norm       = normalize_entropy(entropy, n_buckets) if normalized else entropy

    return {
        "entropy"     : round(entropy, 6),
        "normalized"  : round(norm, 6),
        "n_flows"     : len(packet_counts),
        "max_packets" : max(packet_counts),
    }


def calculate_byte_entropy(flow_features: List[dict],
                            num_buckets: int = 10,
                            normalized: bool = False) -> Dict[str, float]:
    """
    Calculate Shannon entropy of byte count distribution across flows.

    Measures how evenly bandwidth is distributed across flows.

    High byte_entropy → bandwidth spread across many flows (NORMAL).
    Low  byte_entropy → bandwidth dominated by single flow (VOLUMETRIC ATTACK).

    Args:
        flow_features: List of flow feature dicts.
        num_buckets  : Number of bins for discretization (default 10).
        normalized   : If True, normalize to [0, 1].

    Returns:
        Dict with 'entropy', 'normalized', 'n_flows', 'total_bytes'.
    """
    byte_counts = [
        f.get("byte_count", 0)
        for f in flow_features
        if f.get("byte_count") is not None
    ]

    if not byte_counts or sum(byte_counts) == 0:
        return {"entropy": 0.0, "normalized": 0.0, "n_flows": 0, "total_bytes": 0}

    bucketed   = bucket_values(byte_counts, num_buckets=num_buckets)
    prob_dist  = calculate_probability_distribution(bucketed)
    entropy    = calculate_shannon_entropy(prob_dist)
    n_buckets  = len(prob_dist)
    norm       = normalize_entropy(entropy, n_buckets) if normalized else entropy

    return {
        "entropy"    : round(entropy, 6),
        "normalized" : round(norm, 6),
        "n_flows"    : len(byte_counts),
        "total_bytes": sum(byte_counts),
    }


def calculate_flow_entropy(flow_features: List[dict],
                            normalized: bool = False) -> Dict[str, float]:
    """
    Calculate Shannon entropy of per-source-MAC flow volume distribution.

    Measures overall flow diversity — how many flows originate from each source.

    High flow_entropy → flows balanced across many sources (NORMAL).
    Low  flow_entropy → one source generates disproportionate flow volume.

    This complements src_entropy: a single attacker may use many spoofed IPs
    but still generate an uneven flow distribution detectable here.

    Args:
        flow_features: List of flow feature dicts.
        normalized   : If True, normalize to [0, 1].

    Returns:
        Dict with 'entropy', 'normalized', 'n_active_flows', 'total_flows'.
    """
    # Count flows originating from each source MAC
    from collections import Counter
    src_flow_counts: Counter = Counter()

    for f in flow_features:
        src = f.get("src_mac", "unknown")
        if src not in (None, "", "unknown"):
            src_flow_counts[src] += 1

    if not src_flow_counts:
        return {"entropy": 0.0, "normalized": 0.0, "n_active_flows": 0, "total_flows": 0}

    prob_dist = calculate_probability_distribution_from_counts(dict(src_flow_counts))
    entropy   = calculate_shannon_entropy(prob_dist)
    n_sources = len(src_flow_counts)
    norm      = normalize_entropy(entropy, n_sources) if normalized else entropy

    return {
        "entropy"       : round(entropy, 6),
        "normalized"    : round(norm, 6),
        "n_active_flows": n_sources,
        "total_flows"   : sum(src_flow_counts.values()),
    }


# ─── Combined Entropy Snapshot ───────────────────────────────────────────────

def calculate_all_entropy(flow_features: List[dict],
                           normalized: bool = True) -> Dict[str, object]:
    """
    Compute all 5 entropy dimensions in a single call.

    This is the primary API for entropy_detector.py. Returns a compact
    dict that maps directly to the entropy_metrics schema logged to CSV.

    Args:
        flow_features: List of flow feature dicts from Phase 1.
        normalized   : If True, all entropy values normalized to [0, 1].

    Returns:
        Dict with per-dimension entropy results and summary metadata.

    Schema:
        {
            "n_flows"     : int,   total flows in window
            "src"         : dict,  src entropy result
            "dst"         : dict,  dst entropy result
            "packet"      : dict,  packet entropy result
            "byte"        : dict,  byte entropy result
            "flow"        : dict,  flow entropy result
        }
    """
    if not flow_features:
        empty = {"entropy": 0.0, "normalized": 0.0}
        return {
            "n_flows" : 0,
            "src"     : empty,
            "dst"     : empty,
            "packet"  : empty,
            "byte"    : empty,
            "flow"    : empty,
        }

    return {
        "n_flows" : len(flow_features),
        "src"     : calculate_src_entropy(flow_features, normalized=normalized),
        "dst"     : calculate_dst_entropy(flow_features, normalized=normalized),
        "packet"  : calculate_packet_entropy(flow_features, normalized=normalized),
        "byte"    : calculate_byte_entropy(flow_features, normalized=normalized),
        "flow"    : calculate_flow_entropy(flow_features, normalized=normalized),
    }
