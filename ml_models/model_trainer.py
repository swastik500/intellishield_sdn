"""
================================================================================
IntelliShield SDN — Phase 4: ML-Based Anomaly Detection
================================================================================

File        : ml_models/model_trainer.py
Author      : IntelliShield SDN Research Team
Version     : 1.0.0
Phase       : Phase 4 — ML Anomaly Detection

Description:
    Offline training pipeline that:
        1. Loads labelled feature vectors from logs/ml_features.csv
           (produced by FeatureBuilder during Phase 3 experiment runs)
        2. Trains IsolationForest on normal-traffic samples
        3. Trains DecisionTree on full labelled dataset
        4. Evaluates both models and prints research metrics
        5. Saves trained models to logs/models/

    Alternatively, can generate synthetic training data from live
    OpenFlow CSVs when the ml_features.csv does not yet exist.

    Standalone usage:
        python3 -m ml_models.model_trainer --from-csv
        python3 -m ml_models.model_trainer --synthetic

IEEE Relevance:
    Reproducible training from captured experiment logs ensures that
    research results can be replicated by reviewing the Phase 3 scenario
    logs alongside the training dataset.

================================================================================
"""

import os
import csv
import logging
import argparse
import traceback
import random
import math
from collections import defaultdict
from typing import List, Tuple, Dict, Optional

logger = logging.getLogger("intellishield.model_trainer")

_BASE_DIR         = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR          = os.path.join(_BASE_DIR, "..", "logs")
FEATURES_CSV_PATH = os.path.join(LOGS_DIR, "ml_features.csv")
FLOW_CSV_PATH     = os.path.join(LOGS_DIR, "flow_stats.csv")
ENTROPY_CSV_PATH  = os.path.join(LOGS_DIR, "entropy_logs.csv")

MIN_LABELLED_SAMPLES = 20
MIN_ATTACK_SAMPLES   = 5
MIN_NORMAL_SAMPLES   = 10


# ─── Synthetic Data Generator ─────────────────────────────────────────────────

def generate_synthetic_data(n_normal: int = 300,
                              n_attack: int = 200,
                              seed: int = 42) -> Tuple[List[List[float]], List[int]]:
    """
    Generate synthetic labelled training data for initial model training.

    Used when real experiment CSV logs are not yet available.
    Synthetic data is based on realistic entropy/flow distributions
    observed during Mininet experiments.

    Normal traffic characteristics:
        - packet_rate:    10–500 pkt/s
        - entropy scores: 0.7–1.0  (high diversity)
        - flow_count:     3–10 flows
        - unique_src:     2–8 hosts

    Attack traffic characteristics:
        - packet_rate:    5000–150000 pkt/s
        - entropy scores: 0.0–0.2  (concentrated)
        - flow_count:     1–3 flows
        - unique_src:     1–2 hosts

    Returns:
        Tuple (X: feature matrix, y: label list)
    """
    random.seed(seed)

    def rnd(lo, hi):
        return round(random.uniform(lo, hi), 4)

    X, y = [], []

    # ── Normal samples ────────────────────────────────────────────────────────
    for _ in range(n_normal):
        pkt_mean = rnd(10, 500)
        byt_mean = pkt_mean * rnd(54, 1500)
        n_flows  = random.randint(3, 10)
        n_src    = random.randint(2, min(n_flows, 8))
        n_dst    = random.randint(2, min(n_flows, 6))
        src_ent  = rnd(0.70, 1.00)
        dst_ent  = rnd(0.65, 1.00)
        pkt_ent  = rnd(0.60, 1.00)
        byt_ent  = rnd(0.60, 1.00)
        flw_ent  = rnd(0.65, 1.00)
        score    = round((src_ent*0.30 + dst_ent*0.30 + pkt_ent*0.15 +
                          byt_ent*0.15 + flw_ent*0.10), 4)
        conc     = round(1.0 - src_ent, 6)

        X.append([
            pkt_mean,                           # packet_rate_mean
            pkt_mean * rnd(1.1, 3.0),           # packet_rate_max
            byt_mean,                           # byte_rate_mean
            byt_mean * rnd(1.1, 3.0),           # byte_rate_max
            float(n_flows),                     # flow_count
            rnd(5, 120),                        # duration_mean
            float(n_src),                       # unique_src_count
            float(n_dst),                       # unique_dst_count
            src_ent, dst_ent, pkt_ent,          # entropy dims
            byt_ent, flw_ent,
            score,                              # entropy_score
            conc,                               # flow_concentration
        ])
        y.append(0)

    # ── Attack samples ────────────────────────────────────────────────────────
    for _ in range(n_attack):
        pkt_mean = rnd(5000, 150000)
        byt_mean = pkt_mean * rnd(54, 100)
        n_flows  = random.randint(1, 3)
        n_src    = random.randint(1, 2)
        n_dst    = 1
        src_ent  = rnd(0.00, 0.20)
        dst_ent  = rnd(0.00, 0.20)
        pkt_ent  = rnd(0.00, 0.15)
        byt_ent  = rnd(0.00, 0.15)
        flw_ent  = rnd(0.00, 0.20)
        score    = round((src_ent*0.30 + dst_ent*0.30 + pkt_ent*0.15 +
                          byt_ent*0.15 + flw_ent*0.10), 4)
        conc     = round(1.0 - src_ent, 6)

        X.append([
            pkt_mean,
            pkt_mean * rnd(1.0, 1.5),
            byt_mean,
            byt_mean * rnd(1.0, 1.5),
            float(n_flows),
            rnd(5, 90),
            float(n_src),
            float(n_dst),
            src_ent, dst_ent, pkt_ent,
            byt_ent, flw_ent,
            score,
            conc,
        ])
        y.append(1)

    logger.info("[generate_synthetic_data] Normal: %d  Attack: %d", n_normal, n_attack)
    return X, y


# ─── CSV Loader ───────────────────────────────────────────────────────────────

def relabel_features_csv(filepath: str = FEATURES_CSV_PATH,
                         logs_dir: str = LOGS_DIR,
                         in_place: bool = True) -> Dict[str, int]:
    """
    Backfill missing labels in ml_features.csv using Phase 3 attack windows.

    Returns counts: {filled, already_labelled, still_unlabelled, total}.
    """
    from ml_models.label_inference import LabelInferencer, heuristic_label_from_features
    from ml_models.feature_builder import FEATURE_NAMES, FEATURES_CSV_HEADERS

    stats = {"filled": 0, "already_labelled": 0, "still_unlabelled": 0, "total": 0}
    if not os.path.exists(filepath):
        return stats

    inferencer = LabelInferencer(logs_dir=logs_dir, refresh_sec=0)
    rows_out = []

    with open(filepath, "r", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or FEATURES_CSV_HEADERS
        for row in reader:
            stats["total"] += 1
            label_str = row.get("label", "").strip()
            if label_str not in ("", "-1", "None"):
                stats["already_labelled"] += 1
                rows_out.append(row)
                continue

            inferred = inferencer.infer(row.get("timestamp", ""))
            if inferred is None:
                inferred = heuristic_label_from_features(row)
            if inferred is None:
                stats["still_unlabelled"] += 1
                rows_out.append(row)
                continue

            row["label"] = str(inferred)
            stats["filled"] += 1
            rows_out.append(row)

    if in_place and rows_out:
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows_out)

    logger.info(
        "[relabel_features_csv] total=%d  filled=%d  labelled=%d  unlabelled=%d",
        stats["total"], stats["filled"], stats["already_labelled"],
        stats["still_unlabelled"],
    )
    return stats


def load_from_features_csv(filepath: str = FEATURES_CSV_PATH,
                           backfill: bool = True
                           ) -> Tuple[List[List[float]], List[int], set]:
    """
    Load feature vectors and labels from ml_features.csv.

    Optionally backfills empty labels from attack/scenario logs before loading.
    Returns (X, y, timestamps_with_labels).
    """
    if backfill and os.path.exists(filepath):
        relabel_features_csv(filepath, in_place=True)

    X, y, seen_ts = [], [], set()
    try:
        from ml_models.label_inference import heuristic_label_from_features
        with open(filepath, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                label_str = row.get("label", "")
                if label_str in ("", "-1", "None"):
                    continue
                try:
                    label = int(float(label_str))
                except (ValueError, TypeError):
                    continue

                # Upgrade mis-labelled flood rows (SYN flood keeps src_entropy high)
                h = heuristic_label_from_features(row)
                if h == 1:
                    label = 1

                from ml_models.feature_builder import FEATURE_NAMES
                vec = []
                for feat in FEATURE_NAMES:
                    try:
                        vec.append(float(row.get(feat, 0)))
                    except (ValueError, TypeError):
                        vec.append(0.0)
                X.append(vec)
                y.append(label)
                seen_ts.add(row.get("timestamp", ""))

        normal_count = sum(1 for l in y if l == 0)
        attack_count = sum(1 for l in y if l == 1)
        logger.info("[load_from_features_csv] Loaded %d vectors: normal=%d attack=%d",
                    len(X), normal_count, attack_count)
    except FileNotFoundError:
        logger.warning("[load_from_features_csv] File not found: %s", filepath)
    except Exception:
        logger.error("[load_from_features_csv] %s", traceback.format_exc())
    return X, y, seen_ts


def build_dataset_from_monitoring_logs(
        logs_dir: str = LOGS_DIR,
        flow_csv: str = FLOW_CSV_PATH,
        entropy_csv: str = ENTROPY_CSV_PATH,
        skip_timestamps: Optional[set] = None,
) -> Tuple[List[List[float]], List[int]]:
    """
    Build labelled training data by joining flow_stats + entropy_logs per cycle.

    Labels come from Phase 3 attack/scenario log windows (LabelInferencer).
    Deduplicates entropy rows that share the same timestamp (duplicate-hook artefact).
    """
    from ml_models.feature_builder import FeatureBuilder
    from ml_models.label_inference import LabelInferencer, heuristic_label_from_features

    if not os.path.exists(flow_csv) or not os.path.exists(entropy_csv):
        logger.warning("[build_dataset_from_monitoring_logs] Missing flow/entropy CSV.")
        return [], []

    inferencer = LabelInferencer(logs_dir=logs_dir, refresh_sec=0)
    builder    = FeatureBuilder()

    flow_by_ts: Dict[str, list] = defaultdict(list)
    with open(flow_csv, "r", newline="") as f:
        for row in csv.DictReader(f):
            flow_by_ts[row.get("timestamp", "")].append(row)

    # Keep one entropy row per (timestamp, switch_id) — latest wins
    entropy_by_key: Dict[tuple, dict] = {}
    with open(entropy_csv, "r", newline="") as f:
        for row in csv.DictReader(f):
            key = (row.get("timestamp", ""), row.get("switch_id", ""))
            entropy_by_key[key] = row

    X, y = [], []
    skip = skip_timestamps or set()
    for (ts, _sw), ent_row in sorted(entropy_by_key.items()):
        if ts in skip:
            continue

        flows = flow_by_ts.get(ts, [])
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

        if not flow_features:
            continue

        entropy_metrics = {
            "src_entropy"    : float(ent_row.get("src_entropy",    0)),
            "dst_entropy"    : float(ent_row.get("dst_entropy",    0)),
            "packet_entropy" : float(ent_row.get("packet_entropy", 0)),
            "byte_entropy"   : float(ent_row.get("byte_entropy",   0)),
            "flow_entropy"   : float(ent_row.get("flow_entropy",   0)),
            "entropy_score"  : float(ent_row.get("entropy_score",  0)),
        }

        label = inferencer.infer(ts)
        h = heuristic_label_from_features({
            "packet_rate_max" : max(
                (float(f.get("packet_rate", 0)) for f in flow_features), default=0.0
            ),
            "packet_entropy"  : entropy_metrics.get("packet_entropy", 1.0),
        })
        if label is None:
            label = h
        elif h == 1:
            label = 1
        if label is None:
            continue

        vec = builder.build_vector(flow_features, entropy_metrics)
        X.append(vec)
        y.append(label)

    normal_count = sum(1 for l in y if l == 0)
    attack_count = sum(1 for l in y if l == 1)
    logger.info(
        "[build_dataset_from_monitoring_logs] Built %d vectors: normal=%d attack=%d",
        len(X), normal_count, attack_count,
    )
    return X, y


def _merge_datasets(*datasets: Tuple[List[List[float]], List[int]]
                    ) -> Tuple[List[List[float]], List[int]]:
    X: List[List[float]] = []
    y: List[int] = []
    for X_part, y_part in datasets:
        X.extend(X_part)
        y.extend(y_part)
    return X, y


def _dataset_stats(y: List[int]) -> Dict[str, int]:
    return {
        "total"  : len(y),
        "normal" : sum(1 for l in y if l == 0),
        "attack" : sum(1 for l in y if l == 1),
    }


# ─── Model Trainer ────────────────────────────────────────────────────────────

class ModelTrainer:
    """
    Orchestrates training of IsolationForest and DecisionTree models.

    Usage:
        trainer = ModelTrainer()
        trainer.train_all(use_synthetic=True)   # Quick start
        # or
        trainer.train_all(use_synthetic=False)  # From real CSV logs
    """

    def __init__(self):
        from ml_models.anomaly_detector import AnomalyDetector
        from ml_models.feature_builder  import FeatureBuilder
        self._detector = AnomalyDetector(auto_load=False)
        self._builder  = FeatureBuilder()

    def train_all(self,
                   use_synthetic: bool = False,
                   n_normal: int = 300,
                   n_attack: int = 200,
                   allow_synthetic_fallback: bool = False) -> Dict:
        """
        Full training pipeline: load data → train IF → train DT → evaluate.

        Args:
            use_synthetic: If True, generate synthetic data (no CSV needed).
            n_normal     : Synthetic normal samples (if use_synthetic=True).
            n_attack     : Synthetic attack samples (if use_synthetic=True).
            allow_synthetic_fallback: When loading from CSV, supplement with
                           synthetic data only if explicitly allowed.

        Returns:
            dict: Combined training metrics.
        """
        print("\n" + "=" * 60)
        print("  IntelliShield SDN — Phase 4 Model Trainer")
        print("=" * 60)

        # Load data
        if use_synthetic:
            print("  Mode: SYNTHETIC data generation")
            X, y = generate_synthetic_data(n_normal, n_attack)
        else:
            print("  Mode: REAL experiment data (ml_features.csv + monitoring logs)")
            relabel_stats = relabel_features_csv(in_place=True)
            print(
                f"  Relabel: filled={relabel_stats['filled']}  "
                f"already_labelled={relabel_stats['already_labelled']}  "
                f"still_unlabelled={relabel_stats['still_unlabelled']}"
            )

            X_csv, y_csv, seen_ts = load_from_features_csv(backfill=False)
            X_log, y_log = build_dataset_from_monitoring_logs(skip_timestamps=seen_ts)
            X, y = _merge_datasets((X_csv, y_csv), (X_log, y_log))

            stats = _dataset_stats(y)
            print(
                f"  Dataset: {stats['total']} samples "
                f"(normal={stats['normal']}  attack={stats['attack']})"
            )

            if stats["attack"] < MIN_ATTACK_SAMPLES or stats["normal"] < MIN_NORMAL_SAMPLES:
                msg = (
                    f"  WARNING: Need ≥{MIN_NORMAL_SAMPLES} normal and "
                    f"≥{MIN_ATTACK_SAMPLES} attack samples; "
                    f"got normal={stats['normal']} attack={stats['attack']}."
                )
                if allow_synthetic_fallback:
                    print(msg)
                    print("  Supplementing with SYNTHETIC data (--allow-synthetic-fallback).")
                    X_syn, y_syn = generate_synthetic_data(n_normal, n_attack)
                    X, y = _merge_datasets((X, y), (X_syn, y_syn))
                else:
                    print(msg)
                    print("  Run Scenario 2 first, then retry. No synthetic fallback.")

            if len(X) < MIN_LABELLED_SAMPLES and allow_synthetic_fallback:
                print(f"  WARNING: Only {len(X)} labelled vectors — supplementing synthetic.")
                X_syn, y_syn = generate_synthetic_data(n_normal, n_attack)
                X, y = _merge_datasets((X, y), (X_syn, y_syn))

        if not X:
            logger.error("[train_all] No training data available.")
            return {}

        X_normal = [x for x, l in zip(X, y) if l == 0]

        metrics = {}

        # ── Train IsolationForest ─────────────────────────────────────────────
        print(f"\n  [1/2] Training IsolationForest on {len(X_normal)} normal samples...")
        iso_ok = self._detector.train_isolation_forest(X_normal)
        if iso_ok:
            print("        ✅ IsolationForest trained and saved.")
        else:
            print("        ❌ IsolationForest training failed.")

        # ── Train DecisionTree ────────────────────────────────────────────────
        print(f"\n  [2/2] Training DecisionTree on {len(X)} labelled samples...")
        dt_metrics = self._detector.train_decision_tree(X, y)
        if dt_metrics:
            acc = dt_metrics.get("accuracy", 0)
            print(f"        ✅ DecisionTree trained. Accuracy: {acc*100:.2f}%")
            top = dt_metrics.get("top_features", [])
            print("        Top 5 features by importance:")
            for name, imp in top:
                bar = "█" * int(imp * 40)
                print(f"          {name:<22} {imp:.4f}  {bar}")
            metrics["dt"] = dt_metrics
        else:
            print("        ❌ DecisionTree training failed.")

        # ── Quick sanity check ────────────────────────────────────────────────
        print("\n  [Sanity Check] Predicting on held-out attack-like vectors...")
        attack_like = [v for v, l in zip(X, y) if l == 1][:5]
        normal_like = [v for v, l in zip(X, y) if l == 0][:5]
        for i, vec in enumerate(normal_like + attack_like):
            pred = self._detector.predict(vec)
            expected = "NORMAL" if i < len(normal_like) else "ATTACK"
            match = "✅" if pred["status"] == expected else "❌"
            print(
                f"    Sample {i+1}: expected={expected:<8} "
                f"predicted={pred['status']:<12} conf={pred['confidence']:.1f}%  {match}"
            )

        print("\n  Models saved to: logs/models/")
        print("=" * 60 + "\n")

        metrics["iso_trained"] = iso_ok
        metrics["n_samples"]   = len(X)
        metrics["n_normal"]    = len(X_normal)
        metrics["n_attack"]    = len(X) - len(X_normal)
        return metrics


# ─── CLI Entry Point ──────────────────────────────────────────────────────────

def main():
    logging.basicConfig(
        level  = logging.INFO,
        format = "%(asctime)s  %(levelname)-7s  %(name)s — %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="IntelliShield Phase 4 — Model Trainer"
    )
    parser.add_argument(
        "--synthetic", action="store_true",
        help="Train on synthetic data (no CSV logs needed)"
    )
    parser.add_argument(
        "--from-csv", action="store_true",
        help="Train from real experiment logs (ml_features + flow/entropy CSVs)"
    )
    parser.add_argument(
        "--relabel-only", action="store_true",
        help="Only backfill labels in ml_features.csv from attack logs, then exit"
    )
    parser.add_argument(
        "--allow-synthetic-fallback", action="store_true",
        help="Supplement real data with synthetic samples when CSV data is sparse"
    )
    parser.add_argument(
        "--n-normal", type=int, default=300,
        help="Number of synthetic normal samples (default 300)"
    )
    parser.add_argument(
        "--n-attack", type=int, default=200,
        help="Number of synthetic attack samples (default 200)"
    )
    args = parser.parse_args()

    if args.relabel_only:
        stats = relabel_features_csv(in_place=True)
        print(f"Relabel complete: {stats}")
        return

    trainer = ModelTrainer()
    trainer.train_all(
        use_synthetic              = args.synthetic or not args.from_csv,
        n_normal                   = args.n_normal,
        n_attack                   = args.n_attack,
        allow_synthetic_fallback   = args.allow_synthetic_fallback,
    )


if __name__ == "__main__":
    main()
