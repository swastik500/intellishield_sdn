"""
================================================================================
IntelliShield SDN — Phase 2: Entropy Detection Engine
================================================================================

File        : entropy_engine/entropy_detector.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 2 — Entropy-Based DDoS Detection

Description:
    Main entropy analysis and anomaly detection engine. This module:

      1. Maintains a sliding window of recent flow feature dicts
      2. Computes 5-dimensional entropy on each window cycle
      3. Computes an overall composite entropy score
      4. Compares against configurable per-dimension thresholds
      5. Generates structured detection alerts with confidence scores
      6. Maintains entropy history for baseline computation
      7. Logs all results via entropy_logger

    This is the highest-level module in the entropy_engine package.
    It is called from controller/flow_monitor.py (Phase 1 hook) and
    will later feed the ADWIN detector (Phase 6) and PPO RL (Phase 7).

Detection Philosophy:
    DDoS traffic produces ENTROPY COLLAPSE — traffic concentrates on a
    small number of sources/destinations, making distributions non-uniform.
    Shannon entropy drops from ~3–4 bits (normal) to ~0–1 bit (attack).

    Multi-dimensional detection: flagging only when MULTIPLE dimensions
    show simultaneous collapse reduces false positives significantly.

Future Integration Points:
    - [HOOK] Phase 5 → mitigation/flow_blocker.py acts on ALERT status
    - [HOOK] Phase 6 → monitoring/adwin_detector.py watches entropy time series
    - [HOOK] Phase 6 → ml_models/hdbscan_profiler.py clusters entropy vectors
    - [HOOK] Phase 7 → rl_engine/ppo_threshold.py adjusts thresholds dynamically

IEEE Relevance:
    Multi-dimensional entropy analysis with sliding windows and adaptive
    baseline tracking represents the core novelty of IntelliShield's
    detection layer. This approach improves upon single-metric SDN IDS
    systems described in existing SDN security literature.

================================================================================
"""

import logging
import traceback
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from entropy_engine.entropy_calculator import calculate_all_entropy
from entropy_engine.entropy_utils import clamp, compute_mean, compute_std
from entropy_engine.entropy_logger import (
    init_log_files,
    log_entropy_metrics,
    log_alert,
    update_baseline,
    print_entropy_report,
    print_alert_banner,
)

# ─── Detection Configuration ──────────────────────────────────────────────────

# Sliding window: number of flow feature dicts to retain per analysis cycle.
# Larger window = more stable entropy, but slower to detect sudden attacks.
# [HOOK] Phase 7 → PPO RL dynamically tunes WINDOW_SIZE
WINDOW_SIZE = 100

# History depth: how many past entropy scores to retain for baseline tracking.
# Used by update_baseline() to compute rolling mean/std.
# [HOOK] Phase 6 → ADWIN uses this history to detect concept drift
HISTORY_SIZE = 50

# ── Per-Dimension Entropy Thresholds ─────────────────────────────────────────
# All values are in the [0, 1] normalized range.
# A single dimension falling below its threshold raises a "dim_alert".
# Multiple dimensions failing simultaneously triggers an ALERT.
#
# Research notes:
#   - Normal internet traffic: normalized entropy ≈ 0.7–1.0
#   - SYN flood (single source): src_entropy collapses to ~0.0
#   - Amplification attacks: dst_entropy collapses to ~0.0
#   - Default thresholds tuned for Mininet experiments (small topology)
#   [HOOK] Phase 7 → PPO RL replaces these with learned adaptive thresholds

SRC_ENTROPY_THRESHOLD    = 0.3   # Collapse → likely single-source flood
DST_ENTROPY_THRESHOLD    = 0.3   # Collapse → victim concentration
PACKET_ENTROPY_THRESHOLD = 0.2   # Collapse → single flow dominates packets
BYTE_ENTROPY_THRESHOLD   = 0.2   # Collapse → single flow dominates bytes
FLOW_ENTROPY_THRESHOLD   = 0.3   # Collapse → unbalanced flow distribution

# Composite entropy score threshold.
# Score = weighted mean of all normalized entropy values.
# Alert fires when score drops below this AND at least 1 dimension is flagged.
COMPOSITE_SCORE_THRESHOLD = 0.4

# Minimum number of flows required for reliable entropy calculation.
# With fewer flows than this, entropy is unreliable → skip analysis.
MIN_FLOWS_FOR_ANALYSIS = 3

# Dimension weights for composite score (must sum to 1.0)
# src and dst MACs are weighted highest — they most directly indicate DDoS.
DIM_WEIGHTS = {
    "src"    : 0.30,
    "dst"    : 0.30,
    "packet" : 0.15,
    "byte"   : 0.15,
    "flow"   : 0.10,
}

# Alert type labels (maps dimension key → human-readable alert type)
ALERT_LABELS = {
    "src"    : "SRC_MAC_ENTROPY_COLLAPSE",
    "dst"    : "DST_MAC_ENTROPY_COLLAPSE",
    "packet" : "PACKET_DISTRIBUTION_COLLAPSE",
    "byte"   : "BYTE_DISTRIBUTION_COLLAPSE",
    "flow"   : "FLOW_DISTRIBUTION_COLLAPSE",
}

# Threshold map for per-dimension comparison
DIM_THRESHOLDS = {
    "src"    : SRC_ENTROPY_THRESHOLD,
    "dst"    : DST_ENTROPY_THRESHOLD,
    "packet" : PACKET_ENTROPY_THRESHOLD,
    "byte"   : BYTE_ENTROPY_THRESHOLD,
    "flow"   : FLOW_ENTROPY_THRESHOLD,
}

# ─── Module Logger ────────────────────────────────────────────────────────────

logger = logging.getLogger("intellishield.entropy_detector")


# ─── Main Detector Class ──────────────────────────────────────────────────────

class EntropyDetector:
    """
    IntelliShield SDN — Entropy-Based DDoS Anomaly Detector.

    Maintains per-switch sliding windows of flow features and performs
    5-dimensional entropy analysis on each monitoring cycle.

    Usage:
        detector = EntropyDetector()
        detector.add_flows(switch_id=1, flow_features=[...])
        result = detector.analyze(switch_id=1)

    The detector is stateful — it accumulates flow windows across multiple
    calls, so analysis improves as the window fills up over time.
    """

    def __init__(self,
                 window_size: int = WINDOW_SIZE,
                 history_size: int = HISTORY_SIZE):
        """
        Initialise the detector.

        Args:
            window_size  : Max flow features retained per switch window.
            history_size : Max entropy scores retained in history per switch.
        """
        self.window_size   = window_size
        self.history_size  = history_size

        # Per-switch sliding windows: dpid → deque of flow feature dicts
        # deque with maxlen automatically discards oldest entries
        self._windows: Dict[int, deque] = {}

        # Per-switch entropy history for baseline computation
        # dpid → {"src": deque([...]), "dst": deque([...]), ...}
        self._history: Dict[int, Dict[str, deque]] = {}

        # Total alert count per switch (for research stats)
        self._alert_counts: Dict[int, int] = {}

        # Initialise log files
        init_log_files()

        logger.info("[EntropyDetector] Initialised.")
        logger.info("  Window size  : %d flows", self.window_size)
        logger.info("  History size : %d samples", self.history_size)
        logger.info("  Thresholds   : src=%.2f  dst=%.2f  pkt=%.2f  byte=%.2f  flow=%.2f",
                    SRC_ENTROPY_THRESHOLD, DST_ENTROPY_THRESHOLD,
                    PACKET_ENTROPY_THRESHOLD, BYTE_ENTROPY_THRESHOLD,
                    FLOW_ENTROPY_THRESHOLD)

    # ─── Window Management ────────────────────────────────────────────────────

    def _get_window(self, switch_id: int) -> deque:
        """Return (or create) the sliding window deque for a switch."""
        if switch_id not in self._windows:
            self._windows[switch_id] = deque(maxlen=self.window_size)
        return self._windows[switch_id]

    def _get_history(self, switch_id: int) -> Dict[str, deque]:
        """Return (or create) the entropy history dict for a switch."""
        if switch_id not in self._history:
            self._history[switch_id] = {
                dim: deque(maxlen=self.history_size)
                for dim in ["src", "dst", "packet", "byte", "flow", "score"]
            }
        return self._history[switch_id]

    def add_flows(self, switch_id: int, flow_features: List[dict]) -> int:
        """
        Add a batch of flow feature dicts to the switch's sliding window.

        Call this once per monitoring cycle (every 5 seconds) with the
        flow features collected by the Phase 1 flow monitor.

        Args:
            switch_id    : Integer datapath ID.
            flow_features: List of flow feature dicts from Phase 1.

        Returns:
            int: Current window size after adding flows.
        """
        if not flow_features:
            return len(self._get_window(switch_id))

        window = self._get_window(switch_id)
        for f in flow_features:
            window.append(f)

        return len(window)

    def clear_window(self, switch_id: int) -> None:
        """
        Clear the sliding window for a switch.

        Useful after topology changes or Mininet restarts.

        Args:
            switch_id: Integer datapath ID.
        """
        if switch_id in self._windows:
            self._windows[switch_id].clear()
            logger.info("[EntropyDetector] Window cleared for switch %d", switch_id)

    # ─── Entropy Score Computation ────────────────────────────────────────────

    def _compute_composite_score(self, entropy_result: dict) -> float:
        """
        Compute a single weighted composite entropy score from all dimensions.

        Formula: score = Σ (weight_i * normalized_entropy_i)

        Score of 1.0 = maximum entropy, perfectly normal traffic.
        Score of 0.0 = complete entropy collapse, pure attack.

        Args:
            entropy_result: Output of calculate_all_entropy(..., normalized=True).

        Returns:
            float: Composite score in [0.0, 1.0].
        """
        score = 0.0
        for dim, weight in DIM_WEIGHTS.items():
            dim_data = entropy_result.get(dim, {})
            norm_val = dim_data.get("normalized", 0.0)
            score   += weight * norm_val
        return round(clamp(score, 0.0, 1.0), 6)

    def _compute_confidence(self, current_value: float,
                             threshold: float) -> float:
        """
        Estimate detection confidence as percentage below threshold.

        Formula: confidence = ((threshold - current) / threshold) * 100

        A higher gap from threshold → higher confidence the anomaly is real.

        Args:
            current_value: Current normalized entropy value.
            threshold    : Detection threshold for this dimension.

        Returns:
            float: Confidence in [0.0, 100.0].
        """
        if threshold <= 0:
            return 0.0
        raw = ((threshold - current_value) / threshold) * 100.0
        return round(clamp(raw, 0.0, 100.0), 2)

    # ─── Anomaly Detection ────────────────────────────────────────────────────

    def _check_dimension_alerts(self,
                                  switch_id: int,
                                  entropy_result: dict,
                                  composite_score: float,
                                  timestamp: str) -> List[dict]:
        """
        Check each entropy dimension against its threshold and collect alerts.

        A dimension alert fires when normalized_entropy < threshold.
        All fired alerts are logged to detection_alerts.csv and printed.

        Args:
            switch_id      : Switch datapath ID.
            entropy_result : Output of calculate_all_entropy().
            composite_score: Pre-computed composite entropy score.
            timestamp      : Current timestamp string.

        Returns:
            List of alert dicts (empty if no thresholds breached).
        """
        alerts = []

        for dim, threshold in DIM_THRESHOLDS.items():
            dim_data    = entropy_result.get(dim, {})
            norm_val    = dim_data.get("normalized", 0.0)
            raw_val     = dim_data.get("entropy", 0.0)

            if norm_val < threshold:
                confidence = self._compute_confidence(norm_val, threshold)
                alert = {
                    "timestamp"    : timestamp,
                    "switch_id"    : switch_id,
                    "alert_type"   : ALERT_LABELS.get(dim, "ENTROPY_COLLAPSE"),
                    "dimension"    : dim,
                    "entropy_value": round(norm_val, 6),
                    "threshold"    : threshold,
                    "entropy_score": composite_score,
                    "confidence"   : confidence,
                    "status"       : "ALERT",
                }
                alerts.append(alert)
                log_alert(alert)
                print_alert_banner(alert)

        return alerts

    def _determine_status(self, alerts: list, composite_score: float) -> Tuple[str, float]:
        """
        Determine overall detection status and aggregate confidence.

        Rules:
          - No dimension alerts      → NORMAL
          - 1 dimension alert        → WARNING
          - 2+ dimension alerts      → ALERT
          - composite_score < threshold regardless → ALERT

        Args:
            alerts         : List of dimension alert dicts.
            composite_score: Composite entropy score.

        Returns:
            Tuple (status: str, confidence: float)
        """
        if not alerts:
            if composite_score < COMPOSITE_SCORE_THRESHOLD:
                # Composite collapse even without single-dim trigger
                max_conf = self._compute_confidence(
                    composite_score, COMPOSITE_SCORE_THRESHOLD
                )
                return "ALERT", max_conf
            return "NORMAL", 0.0

        confidences = [a["confidence"] for a in alerts]
        max_conf    = max(confidences)
        avg_conf    = sum(confidences) / len(confidences)

        if len(alerts) >= 2:
            return "ALERT",   round(max_conf, 2)
        else:
            return "WARNING", round(avg_conf, 2)

    # ─── Main Analysis Entry Point ────────────────────────────────────────────

    def analyze(self, switch_id: int) -> Optional[dict]:
        """
        Run a full entropy analysis cycle on the current window for a switch.

        This is the primary method called by the OsKen controller every 5s.

        Steps:
          1. Retrieve current sliding window
          2. Check window has enough flows
          3. Compute 5-dimensional entropy
          4. Compute composite score
          5. Check thresholds → generate alerts
          6. Determine overall status + confidence
          7. Build metrics dict
          8. Log to CSV and print to console
          9. Update entropy history and baseline JSON
          10. Return metrics dict

        Args:
            switch_id: Integer datapath ID of the switch to analyze.

        Returns:
            dict: Entropy metrics dict (logged to CSV), or None on failure.

        Schema:
            {
                "timestamp"      : str,
                "switch_id"      : int,
                "n_flows"        : int,
                "src_entropy"    : float,   normalized
                "dst_entropy"    : float,
                "packet_entropy" : float,
                "byte_entropy"   : float,
                "flow_entropy"   : float,
                "entropy_score"  : float,   composite
                "status"         : str,     NORMAL / WARNING / ALERT
                "confidence"     : float,   0–100
            }
        """
        try:
            window    = self._get_window(switch_id)
            n_flows   = len(window)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # ── Guard: insufficient data ──────────────────────────────────────
            if n_flows < MIN_FLOWS_FOR_ANALYSIS:
                logger.debug(
                    "[analyze] Switch %d: only %d flows in window "
                    "(min=%d) — skipping entropy analysis.",
                    switch_id, n_flows, MIN_FLOWS_FOR_ANALYSIS
                )
                return None

            # ── Compute 5-dimensional entropy ─────────────────────────────────
            entropy_result  = calculate_all_entropy(list(window), normalized=True)
            composite_score = self._compute_composite_score(entropy_result)

            # ── Check dimension thresholds → collect alerts ───────────────────
            alerts = self._check_dimension_alerts(
                switch_id, entropy_result, composite_score, timestamp
            )

            # ── Determine overall status ──────────────────────────────────────
            status, confidence = self._determine_status(alerts, composite_score)

            # ── Build metrics dict ────────────────────────────────────────────
            metrics = {
                "timestamp"      : timestamp,
                "switch_id"      : switch_id,
                "n_flows"        : n_flows,
                "src_entropy"    : entropy_result["src"].get("normalized", 0.0),
                "dst_entropy"    : entropy_result["dst"].get("normalized", 0.0),
                "packet_entropy" : entropy_result["packet"].get("normalized", 0.0),
                "byte_entropy"   : entropy_result["byte"].get("normalized", 0.0),
                "flow_entropy"   : entropy_result["flow"].get("normalized", 0.0),
                "entropy_score"  : composite_score,
                "status"         : status,
                "confidence"     : confidence,
            }

            # ── Log and print ─────────────────────────────────────────────────
            log_entropy_metrics(metrics)
            print_entropy_report(metrics)

            # Track alert count for research stats
            if status in ("ALERT", "WARNING"):
                self._alert_counts[switch_id] = \
                    self._alert_counts.get(switch_id, 0) + 1

            # ── Update entropy history ────────────────────────────────────────
            history = self._get_history(switch_id)
            history["src"].append(metrics["src_entropy"])
            history["dst"].append(metrics["dst_entropy"])
            history["packet"].append(metrics["packet_entropy"])
            history["byte"].append(metrics["byte_entropy"])
            history["flow"].append(metrics["flow_entropy"])
            history["score"].append(composite_score)

            # ── Update baseline JSON (every cycle) ───────────────────────────
            # [HOOK] Phase 6 → ADWIN reads these baselines for drift detection
            # [HOOK] Phase 7 → PPO RL initialises from these statistics
            history_snapshot = {
                dim: list(history[dim]) for dim in history
            }
            update_baseline(switch_id, history_snapshot)

            return metrics

        except Exception:
            logger.error(
                "[analyze] Error during entropy analysis for switch %d:\n%s",
                switch_id, traceback.format_exc()
            )
            return None

    # ─── Research Stats ───────────────────────────────────────────────────────

    def get_stats(self, switch_id: int) -> dict:
        """
        Return research statistics for a switch's detection session.

        Useful for summary reports at the end of an experiment.

        Args:
            switch_id: Integer datapath ID.

        Returns:
            Dict with session statistics.
        """
        history = self._get_history(switch_id)
        scores  = list(history.get("score", []))

        return {
            "switch_id"      : switch_id,
            "window_size"    : self.window_size,
            "current_flows"  : len(self._get_window(switch_id)),
            "history_samples": len(scores),
            "alert_count"    : self._alert_counts.get(switch_id, 0),
            "mean_score"     : round(compute_mean(scores), 6) if scores else 0.0,
            "min_score"      : round(min(scores), 6) if scores else 0.0,
            "max_score"      : round(max(scores), 6) if scores else 0.0,
            "std_score"      : round(compute_std(scores), 6) if scores else 0.0,
        }

    def print_session_summary(self, switch_id: int) -> None:
        """
        Print end-of-session research statistics to console.

        Args:
            switch_id: Integer datapath ID.
        """
        stats = self.get_stats(switch_id)
        print("\n" + "=" * 56)
        print(f"  [SESSION SUMMARY]  Switch {switch_id}")
        print("=" * 56)
        print(f"  Analysis cycles  : {stats['history_samples']}")
        print(f"  Total alerts     : {stats['alert_count']}")
        print(f"  Mean entropy score: {stats['mean_score']:.4f}")
        print(f"  Min entropy score : {stats['min_score']:.4f}")
        print(f"  Max entropy score : {stats['max_score']:.4f}")
        print(f"  Std entropy score : {stats['std_score']:.4f}")
        print("=" * 56 + "\n")


# ─── Convenience: Standalone Batch Analysis ───────────────────────────────────

def analyze_flow_batch(switch_id: int,
                        flow_features: List[dict],
                        detector: Optional["EntropyDetector"] = None
                        ) -> Optional[dict]:
    """
    One-shot convenience function: add flows and immediately analyze.

    Creates a temporary EntropyDetector if none provided.
    Useful for testing, evaluation scripts, and offline analysis.

    Args:
        switch_id    : Switch datapath ID.
        flow_features: List of flow feature dicts.
        detector     : Optional existing EntropyDetector instance.

    Returns:
        Entropy metrics dict, or None if analysis failed.
    """
    if detector is None:
        detector = EntropyDetector()

    detector.add_flows(switch_id, flow_features)
    return detector.analyze(switch_id)
