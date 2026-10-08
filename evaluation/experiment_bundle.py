"""
Reproducible experiment artifact bundle for IntelliShield SDN.

Collects logs, models, metrics, configuration, and metadata into a
timestamped directory with experiment_manifest.json for IEEE-style
reproducibility.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Optional

from evaluation.experiment_windows import (
    TS_FMT,
    load_experiment_windows,
)

BUNDLE_VERSION = "1.0.0"

# Relative paths under logs/ included in every bundle (present files only)
ARTIFACT_PATHS = [
    # Ground truth + traffic
    "scenario_logs.csv",
    "attack_logs.csv",
    "traffic_logs.csv",
    "traffic_profiles.json",
    # Controller telemetry
    "flow_stats.csv",
    "port_stats.csv",
    "controller_stats.csv",
    # Entropy
    "entropy_logs.csv",
    "detection_alerts.csv",
    "entropy_baselines.json",
    # ML
    "ml_features.csv",
    "ml_predictions.csv",
    "ml_alerts.csv",
    "ml_summary.json",
    # Mitigation
    "mitigation_actions.csv",
    "mitigation_summary.json",
    # Analytics + RL
    "drift_alerts.csv",
    "cluster_labels.csv",
    "cluster_summary.json",
    "rl_decisions.csv",
    "rl_training.csv",
    # Metrics + weights
    "metrics_report.json",
    "metrics_report.csv",
    "paper_tables.md",
    "ppo_weights.pkl",
    # Models
    "models/isolation_forest.pkl",
    "models/decision_tree.pkl",
    "models/scaler.pkl",
]


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sha256_file(path: str) -> Optional[str]:
    if not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def get_git_version(root: Optional[str] = None) -> Dict:
    """Return git commit, branch, and dirty-state for reproducibility."""
    root = root or _project_root()
    result = {"commit": "unknown", "branch": "unknown", "dirty": None}
    try:
        result["commit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, stderr=subprocess.DEVNULL,
        ).decode().strip()
        result["branch"] = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root,
            stderr=subprocess.DEVNULL,
        ).decode().strip()
        result["dirty"] = subprocess.call(
            ["git", "diff", "--quiet"], cwd=root, stderr=subprocess.DEVNULL,
        ) != 0
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        pass
    return result


def collect_dataset_checksums(logs_dir: str) -> Dict[str, str]:
    """SHA-256 checksums for key datasets (present files only)."""
    checksums = {}
    for rel in ARTIFACT_PATHS:
        path = os.path.join(logs_dir, rel)
        digest = sha256_file(path)
        if digest:
            checksums[rel] = digest
    return checksums


def collect_model_versions(logs_dir: str) -> List[Dict]:
    """Metadata for each model artifact on disk."""
    models = []
    model_paths = [
        "models/isolation_forest.pkl",
        "models/decision_tree.pkl",
        "models/scaler.pkl",
        "ppo_weights.pkl",
    ]
    for rel in model_paths:
        path = os.path.join(logs_dir, rel)
        if not os.path.isfile(path):
            continue
        stat = os.stat(path)
        entry = {
            "path"       : rel,
            "sha256"     : sha256_file(path),
            "size_bytes" : stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime).strftime(TS_FMT),
        }
        try:
            import sklearn  # noqa: F401 — optional
            entry["sklearn_version"] = sklearn.__version__
        except ImportError:
            pass
        models.append(entry)
    return models


def collect_scenario_metadata(logs_dir: str) -> List[Dict]:
    """Attack windows and scenario names from ground-truth logs."""
    windows = []
    for w in load_experiment_windows(logs_dir):
        windows.append({
            "scenario"    : w.scenario,
            "attack_start": w.attack_start.strftime(TS_FMT),
            "attack_stop" : w.attack_stop.strftime(TS_FMT),
            "duration_sec": w.duration_sec,
            "source"      : w.source,
        })
    return windows


def collect_config_snapshot() -> Dict:
    """Snapshot of key runtime constants (no secrets)."""
    snapshot = {
        "bundle_version"       : BUNDLE_VERSION,
        "monitor_interval_sec" : 5,
        "metrics_grace_sec"    : 60.0,
    }
    try:
        from mitigation.mitigation_engine import (
            MIN_CONFIDENCE_TO_BLOCK,
            FLOW_PAIR_ATTACK_HINTS,
            SRC_MAC_ATTACK_HINTS,
            ATTACK_RATE_THRESHOLD,
        )
        snapshot["mitigation"] = {
            "min_confidence_to_block": MIN_CONFIDENCE_TO_BLOCK,
            "flow_pair_hints"        : sorted(FLOW_PAIR_ATTACK_HINTS),
            "src_mac_hints"          : sorted(SRC_MAC_ATTACK_HINTS),
            "attack_rate_threshold"  : ATTACK_RATE_THRESHOLD,
        }
    except ImportError:
        pass
    try:
        from traffic_generator.attack_scenarios import SCENARIO_REGISTRY
        snapshot["scenarios"] = {
            sid: name for sid, (name, _) in SCENARIO_REGISTRY.items()
        }
    except ImportError:
        pass
    return snapshot


def _try_generate_entropy_plot(logs_dir: str, plots_dir: str) -> Optional[str]:
    """Generate entropy timeline PNG when matplotlib and data are available."""
    entropy_csv = os.path.join(logs_dir, "entropy_logs.csv")
    if not os.path.isfile(entropy_csv):
        return None
    try:
        import csv
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return None

    timestamps, scores = [], []
    with open(entropy_csv, newline="") as f:
        for row in csv.DictReader(f):
            try:
                scores.append(float(row.get("entropy_score", 0)))
                timestamps.append(row.get("timestamp", ""))
            except (TypeError, ValueError):
                continue
    if len(scores) < 2:
        return None

    os.makedirs(plots_dir, exist_ok=True)
    out_path = os.path.join(plots_dir, "entropy_timeline.png")
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(range(len(scores)), scores, color="#2563eb", linewidth=1.5)
    ax.set_xlabel("Sample index")
    ax.set_ylabel("Entropy score")
    ax.set_title("IntelliShield — Entropy Timeline")
    ax.set_ylim(0, 1.05)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, dpi=120)
    plt.close(fig)
    return out_path


def _write_directory_tree(bundle_dir: str, tree_path: str) -> None:
    """Write a text directory tree of the bundle."""
    lines = []
    bundle_dir = os.path.abspath(bundle_dir)
    for root, dirs, files in os.walk(bundle_dir):
        dirs.sort()
        rel_root = os.path.relpath(root, bundle_dir) or "."
        depth = 0 if rel_root == "." else rel_root.count(os.sep) + 1
        if rel_root != ".":
            lines.append(f"{'  ' * depth}{os.path.basename(root)}/")
        for name in sorted(files):
            if name == "directory_tree.txt":
                continue
            lines.append(f"{'  ' * (depth + 1)}{name}")
    with open(tree_path, "w") as f:
        f.write("\n".join(lines) + "\n")


def build_manifest(logs_dir: str,
                   bundle_id: str,
                   bundle_dir: str,
                   artifacts: List[str],
                   plots: List[str],
                   metrics_report: Optional[Dict] = None) -> Dict:
    """Assemble experiment_manifest.json contents."""
    root = _project_root()
    return {
        "bundle_version"   : BUNDLE_VERSION,
        "experiment_id"    : bundle_id,
        "created_at"       : datetime.now().strftime(TS_FMT),
        "project"          : "IntelliShield SDN",
        "git"              : get_git_version(root),
        "python_version"   : sys.version.split()[0],
        "logs_source_dir"  : os.path.abspath(logs_dir),
        "bundle_dir"       : os.path.abspath(bundle_dir),
        "artifacts"        : artifacts,
        "plots"            : plots,
        "dataset_checksums": collect_dataset_checksums(logs_dir),
        "model_versions"   : collect_model_versions(logs_dir),
        "scenario_windows" : collect_scenario_metadata(logs_dir),
        "configuration"    : collect_config_snapshot(),
        "metrics_summary"  : (metrics_report or {}).get("summary"),
    }


def create_bundle(logs_dir: str,
                  bundle_id: Optional[str] = None,
                  output_root: Optional[str] = None,
                  metrics_report: Optional[Dict] = None,
                  generate_plots: bool = True) -> Dict:
    """
    Create a reproducible experiment bundle under logs/experiments/<id>/.

    Returns dict with bundle_dir, manifest path, and artifact list.
    """
    logs_dir = os.path.abspath(logs_dir)
    bundle_id = bundle_id or datetime.now().strftime("%Y%m%d_%H%M%S")
    output_root = output_root or os.path.join(logs_dir, "experiments")
    bundle_dir = os.path.join(output_root, bundle_id)
    artifacts_dir = os.path.join(bundle_dir, "artifacts")
    plots_dir = os.path.join(bundle_dir, "plots")

    os.makedirs(artifacts_dir, exist_ok=True)
    os.makedirs(plots_dir, exist_ok=True)

    copied = []
    for rel in ARTIFACT_PATHS:
        src = os.path.join(logs_dir, rel)
        if not os.path.isfile(src):
            continue
        dest = os.path.join(artifacts_dir, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(src, dest)
        copied.append(rel)

    # Ensure metrics_report.json is in the bundle
    metrics_path = os.path.join(logs_dir, "metrics_report.json")
    if metrics_report and not os.path.isfile(metrics_path):
        os.makedirs(os.path.dirname(metrics_path), exist_ok=True)
        with open(metrics_path, "w") as f:
            json.dump(metrics_report, f, indent=2)
        dest = os.path.join(artifacts_dir, "metrics_report.json")
        shutil.copy2(metrics_path, dest)
        if "metrics_report.json" not in copied:
            copied.append("metrics_report.json")
    elif os.path.isfile(metrics_path) and "metrics_report.json" not in copied:
        shutil.copy2(metrics_path, os.path.join(artifacts_dir, "metrics_report.json"))
        copied.append("metrics_report.json")

    plots = []
    if generate_plots:
        plot_path = _try_generate_entropy_plot(logs_dir, plots_dir)
        if plot_path:
            plots.append(os.path.relpath(plot_path, bundle_dir))

    if metrics_report is None and os.path.isfile(metrics_path):
        with open(metrics_path) as f:
            metrics_report = json.load(f)

    manifest = build_manifest(
        logs_dir, bundle_id, bundle_dir, copied, plots, metrics_report,
    )
    manifest_path = os.path.join(bundle_dir, "experiment_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    tree_path = os.path.join(bundle_dir, "directory_tree.txt")
    _write_directory_tree(bundle_dir, tree_path)

    return {
        "bundle_id"     : bundle_id,
        "bundle_dir"    : bundle_dir,
        "manifest_path" : manifest_path,
        "artifacts"     : copied,
        "plots"         : plots,
        "tree_path"     : tree_path,
    }
