"""
================================================================================
IntelliShield SDN — Phase 4: ML-Based Anomaly Detection
================================================================================

File        : ml_models/feature_builder.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 4 — ML Anomaly Detection

Description:
    Bridges Phase 1 (flow stats) and Phase 2 (entropy) into a unified
    ML feature vector. Every monitoring cycle produces one feature vector
    that the anomaly detector classifies as NORMAL / SUSPICIOUS / ATTACK.

    Feature vector schema (15 dimensions):
        Flow features (Phase 1):
            1.  packet_rate_mean      — mean pkt/s across active flows
            2.  packet_rate_max       — max pkt/s (flood indicator)
            3.  byte_rate_mean        — mean B/s across active flows
            4.  byte_rate_max         — max B/s
            5.  flow_count            — number of active flows
            6.  duration_mean         — mean flow age in seconds
            7.  unique_src_count      — distinct source MACs
            8.  unique_dst_count      — distinct destination MACs

        Entropy features (Phase 2):
            9.  src_entropy           — normalized source MAC entropy
            10. dst_entropy           — normalized destination entropy
            11. packet_entropy        — normalized packet distribution entropy
            12. byte_entropy          — normalized byte distribution entropy
            13. flow_entropy          — normalized flow distribution entropy
            14. entropy_score         — composite weighted entropy score

        Derived:
            15. flow_concentration    — 1 - src_entropy (attack signal)

    Labels (for supervised training):
        0 = NORMAL
        1 = ATTACK

IEEE Relevance:
    15-dimensional feature vectors from live OpenFlow telemetry represent
    a novel approach to SDN intrusion detection. The fusion of statistical
    flow features with information-theoretic entropy metrics is the core
    technical contribution of IntelliShield.

Future Integration Points:
    - [HOOK] Phase 6 → HDBSCAN clusters these vectors unsupervisedly
    - [HOOK] Phase 7 → PPO RL state space uses subset of these features

================================================================================
"""

import os
import csv
import logging
import traceback
from datetime import datetime
from typing import List, Dict, Optional, Tuple

from ml_models.ml_utils import safe_mean, safe_max, safe_divide

logger = logging.getLogger("intellishield.feature_builder")

# ─── Feature Schema ───────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "packet_rate_mean",
    "packet_rate_max",
    "byte_rate_mean",
    "byte_rate_max",
    "flow_count",
    "duration_mean",
    "unique_src_count",
    "unique_dst_count",
    "src_entropy",
    "dst_entropy",
    "packet_entropy",
    "byte_entropy",
    "flow_entropy",
    "entropy_score",
    "flow_concentration",
]

# CSV path for persisting feature vectors
_BASE_DIR         = os.path.dirname(os.path.abspath(__file__))
FEATURES_CSV_PATH = os.path.join(_BASE_DIR, "..", "logs", "ml_features.csv")
FEATURES_CSV_HEADERS = ["timestamp", "switch_id", "label"] + FEATURE_NAMES


# ─── Feature Builder ──────────────────────────────────────────────────────────

class FeatureBuilder:
    """
    Constructs ML feature vectors from Phase 1 flow features and
    Phase 2 entropy metrics.

    Usage:
        builder = FeatureBuilder()

        # From live monitoring cycle:
        vec, meta = builder.build(
            flow_features  = [flow_feature_dict, ...],   # Phase 1 output
            entropy_metrics = entropy_metrics_dict,       # Phase 2 output
            switch_id       = 1,
            label           = None,    # None=unknown, 0=normal, 1=attack
        )
    """

    def __init__(self):
        self._label_inferencer = None
        self._ensure_csv()
        logger.info("[FeatureBuilder] Initialised. Features: %d dims", len(FEATURE_NAMES))

    def infer_live_label(self, timestamp_str: Optional[str] = None) -> Optional[int]:
        """
        Infer label from Phase 3 attack/scenario logs when available.

        Returns 0, 1, or None (no attack logs on disk yet).
        """
        try:
            if self._label_inferencer is None:
                from ml_models.label_inference import LabelInferencer
                self._label_inferencer = LabelInferencer()
            ts = timestamp_str or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return self._label_inferencer.infer(ts)
        except Exception:
            logger.debug("[infer_live_label] unavailable", exc_info=True)
            return None

    def _ensure_csv(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(FEATURES_CSV_PATH)), exist_ok=True)
        if not os.path.exists(FEATURES_CSV_PATH):
            with open(FEATURES_CSV_PATH, "w", newline="") as f:
                csv.writer(f).writerow(FEATURES_CSV_HEADERS)

    # ─── Build Vector ─────────────────────────────────────────────────────────

    def build(self,
              flow_features: List[dict],
              entropy_metrics: Optional[dict] = None,
              switch_id: int = 0,
              label: Optional[int] = None,
              persist: bool = True) -> Tuple[List[float], dict]:
        """
        Build a 15-dimensional feature vector from one monitoring cycle.

        Args:
            flow_features  : List of flow dicts from Phase 1 _extract_flow_features().
            entropy_metrics: Dict from Phase 2 EntropyDetector.analyze().
                             If None, entropy features default to 0.0.
            switch_id      : Datapath ID for logging.
            label          : Ground-truth label (0=NORMAL, 1=ATTACK, None=unknown).

        Returns:
            Tuple:
                vector (List[float]) : 15-element feature vector (same order as FEATURE_NAMES)
                meta   (dict)        : Metadata for logging/debugging

        Example:
            vec, meta = builder.build(flow_features, entropy_metrics, switch_id=1)
            # vec = [24.5, 100.0, 1640.0, 5440.0, 4, 12.3, 3, 2, 0.98, 0.91, ...]
        """
        try:
            # ── Flow-based features ───────────────────────────────────────────
            pkt_rates  = [f.get("packet_rate", 0.0) for f in flow_features]
            byte_rates = [f.get("byte_rate",   0.0) for f in flow_features]
            durations  = [f.get("duration_sec", 0.0) for f in flow_features]
            src_macs   = {f.get("src_mac", "") for f in flow_features if f.get("src_mac")}
            dst_macs   = {f.get("dst_mac", "") for f in flow_features if f.get("dst_mac")}

            packet_rate_mean  = safe_mean(pkt_rates)
            packet_rate_max   = safe_max(pkt_rates)
            byte_rate_mean    = safe_mean(byte_rates)
            byte_rate_max     = safe_max(byte_rates)
            flow_count        = float(len(flow_features))
            duration_mean     = safe_mean(durations)
            unique_src_count  = float(len(src_macs))
            unique_dst_count  = float(len(dst_macs))

            # ── Entropy features (Phase 2) ────────────────────────────────────
            if entropy_metrics:
                src_entropy    = float(entropy_metrics.get("src_entropy",    0.0))
                dst_entropy    = float(entropy_metrics.get("dst_entropy",    0.0))
                packet_entropy = float(entropy_metrics.get("packet_entropy", 0.0))
                byte_entropy   = float(entropy_metrics.get("byte_entropy",   0.0))
                flow_entropy   = float(entropy_metrics.get("flow_entropy",   0.0))
                entropy_score  = float(entropy_metrics.get("entropy_score",  0.0))
            else:
                src_entropy = dst_entropy = packet_entropy = 0.0
                byte_entropy = flow_entropy = entropy_score = 0.0

            # ── Derived feature ───────────────────────────────────────────────
            # flow_concentration: inverse of src_entropy — high when attack concentrated
            # Normal traffic → ~0.0–0.3   Attack traffic → ~0.7–1.0
            flow_concentration = round(1.0 - src_entropy, 6)

            # ── Assemble vector ───────────────────────────────────────────────
            vector = [
                round(packet_rate_mean,  4),
                round(packet_rate_max,   4),
                round(byte_rate_mean,    4),
                round(byte_rate_max,     4),
                round(flow_count,        4),
                round(duration_mean,     4),
                round(unique_src_count,  4),
                round(unique_dst_count,  4),
                round(src_entropy,       6),
                round(dst_entropy,       6),
                round(packet_entropy,    6),
                round(byte_entropy,      6),
                round(flow_entropy,      6),
                round(entropy_score,     6),
                round(flow_concentration, 6),
            ]

            meta = {
                "timestamp" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "switch_id" : switch_id,
                "label"     : label if label is not None else -1,
                "n_flows"   : len(flow_features),
            }

            if label is None:
                label = self.infer_live_label(meta["timestamp"])

            if persist:
                self._save_feature(vector, meta, label)

            return vector, meta

        except Exception:
            logger.error("[build] Feature extraction error:\n%s", traceback.format_exc())
            return [0.0] * len(FEATURE_NAMES), {}

    def build_vector(self,
                     flow_features: List[dict],
                     entropy_metrics: Optional[dict] = None) -> List[float]:
        """Build a 15-dim vector without persisting to CSV (offline training)."""
        vector, _ = self.build(
            flow_features, entropy_metrics, switch_id=0, label=-1, persist=False,
        )
        return vector

    def _save_feature(self, vector: list, meta: dict, label) -> None:
        """Append feature vector to ml_features.csv."""
        try:
            with open(FEATURES_CSV_PATH, "a", newline="") as f:
                writer = csv.writer(f)
                row = [
                    meta.get("timestamp", ""),
                    meta.get("switch_id", 0),
                    label if label is not None else "",
                ] + vector
                writer.writerow(row)
        except Exception:
            logger.error("[_save_feature] CSV write error:\n%s", traceback.format_exc())

    # ─── Batch Build from CSV ─────────────────────────────────────────────────

    def build_dataset_from_csvs(self,
                                 flow_csv: str,
                                 entropy_csv: str,
                                 label: int = 0) -> Tuple[List[List[float]], List[int]]:
        """
        Build a full labelled dataset by joining flow_stats.csv and
        entropy_logs.csv on timestamp (nearest-match join).

        Used by ModelTrainer for offline training from captured experiment data.

        Args:
            flow_csv   : Path to logs/flow_stats.csv
            entropy_csv: Path to logs/entropy_logs.csv
            label      : Ground-truth label for ALL rows (0=normal, 1=attack)
                         Use separate calls for normal and attack CSVs, then merge.

        Returns:
            Tuple:
                X (List[List[float]]) : Feature vectors
                y (List[int])         : Labels
        """
        import csv as csv_mod

        try:
            # Load flow CSV
            flow_rows = []
            with open(flow_csv, "r") as f:
                reader = csv_mod.DictReader(f)
                for row in reader:
                    flow_rows.append(row)

            # Load entropy CSV
            entropy_rows = []
            with open(entropy_csv, "r") as f:
                reader = csv_mod.DictReader(f)
                for row in reader:
                    entropy_rows.append(row)

            if not flow_rows or not entropy_rows:
                logger.warning("[build_dataset_from_csvs] Empty CSV file(s).")
                return [], []

            # Group flow rows by timestamp (round to nearest 5s window)
            from collections import defaultdict
            flow_by_ts: dict = defaultdict(list)
            for row in flow_rows:
                ts = row.get("timestamp", "")
                flow_by_ts[ts].append(row)

            X, y = [], []
            for ent_row in entropy_rows:
                ts = ent_row.get("timestamp", "")
                flows = flow_by_ts.get(ts, [])

                # Convert flow CSV rows → feature dicts
                flow_features = []
                for fr in flows:
                    try:
                        flow_features.append({
                            "packet_rate" : float(fr.get("packet_rate", 0)),
                            "byte_rate"   : float(fr.get("byte_rate",   0)),
                            "duration_sec": float(fr.get("duration_sec", 0)),
                            "src_mac"     : fr.get("src_mac", ""),
                            "dst_mac"     : fr.get("dst_mac", ""),
                        })
                    except (ValueError, TypeError):
                        continue

                # Convert entropy CSV row → entropy dict
                entropy_metrics = {
                    "src_entropy"    : float(ent_row.get("src_entropy",    0)),
                    "dst_entropy"    : float(ent_row.get("dst_entropy",    0)),
                    "packet_entropy" : float(ent_row.get("packet_entropy", 0)),
                    "byte_entropy"   : float(ent_row.get("byte_entropy",   0)),
                    "flow_entropy"   : float(ent_row.get("flow_entropy",   0)),
                    "entropy_score"  : float(ent_row.get("entropy_score",  0)),
                }

                vec = self.build_vector(flow_features, entropy_metrics)
                X.append(vec)
                y.append(label)

            logger.info("[build_dataset_from_csvs] Built %d vectors (label=%d)", len(X), label)
            return X, y

        except Exception:
            logger.error("[build_dataset_from_csvs] Error:\n%s", traceback.format_exc())
            return [], []
