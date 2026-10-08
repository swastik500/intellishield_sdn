"""
================================================================================
IntelliShield SDN — Phase 7: RL Logger
================================================================================

File        : rl_engine/rl_logger.py
Phase       : Phase 7 — PPO Reinforcement Learning

Description:
    Logs every RL decision (state, action, reward, updated thresholds) and
    every PPO weight-update (actor/critic loss) to separate CSV files.

CSV files produced:
    logs/rl_decisions.csv   — one row per monitoring cycle
    logs/rl_training.csv    — one row per PPO weight update
================================================================================
"""

import csv
import logging
import os
from datetime import datetime

logger = logging.getLogger("intellishield.rl_logger")

# CSV schemas
_DECISION_HEADERS = [
    "timestamp", "switch_id", "cycle",
    "pkt_rate_mean", "byte_rate_mean", "entropy_score", "flow_count",
    "ml_label", "ml_confidence",
    "action_pkt", "action_byte", "action_conf",
    "pkt_threshold", "byte_threshold", "conf_threshold",
    "reward",
]

_TRAINING_HEADERS = [
    "timestamp", "update_number",
    "actor_loss", "critic_loss",
    "buffer_size",
]


def _ensure_csv(path: str, headers: list) -> None:
    """Create CSV with header row if it does not exist."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", newline="") as f:
            csv.writer(f).writerow(headers)


class RLLogger:
    """
    CSV logger for Phase 7 RL decisions and training metrics.

    Usage:
        rl_log = RLLogger(logs_dir="/path/to/logs")
        rl_log.log_decision(...)
        rl_log.log_training(...)
    """

    def __init__(self, logs_dir: str = "logs") -> None:
        self._dec_path  = os.path.join(logs_dir, "rl_decisions.csv")
        self._train_path = os.path.join(logs_dir, "rl_training.csv")
        _ensure_csv(self._dec_path,   _DECISION_HEADERS)
        _ensure_csv(self._train_path, _TRAINING_HEADERS)
        self._cycle = 0
        logger.info("[RLLogger] Log files initialised.")
        logger.info("  RL Decisions : %s", self._dec_path)
        logger.info("  RL Training  : %s", self._train_path)

    def log_decision(self, *,
                     switch_id:    int,
                     pkt_rate:     float,
                     byte_rate:    float,
                     entropy:      float,
                     flow_count:   int,
                     ml_label:     str,
                     ml_conf:      float,
                     action:       "np.ndarray",
                     thresholds:   dict,
                     reward:       float) -> None:
        """Write one cycle's RL decision to CSV."""
        self._cycle += 1
        row = [
            datetime.now().isoformat(timespec="seconds"),
            switch_id,
            self._cycle,
            round(pkt_rate,  2),
            round(byte_rate, 2),
            round(entropy,   4),
            flow_count,
            ml_label,
            round(ml_conf, 4),
            round(float(action[0]), 4),
            round(float(action[1]), 4),
            round(float(action[2]), 4),
            round(thresholds["pkt_threshold"],  1),
            round(thresholds["byte_threshold"], 1),
            round(thresholds["conf_threshold"], 4),
            round(reward, 4),
        ]
        try:
            with open(self._dec_path, "a", newline="") as f:
                csv.writer(f).writerow(row)
        except Exception as e:
            logger.error("[RLLogger] Could not write decision: %s", e)

    def log_training(self, *,
                     update_number: int,
                     actor_loss:    float,
                     critic_loss:   float,
                     buffer_size:   int) -> None:
        """Write one PPO weight-update record to CSV."""
        row = [
            datetime.now().isoformat(timespec="seconds"),
            update_number,
            round(actor_loss,  6),
            round(critic_loss, 6),
            buffer_size,
        ]
        try:
            with open(self._train_path, "a", newline="") as f:
                csv.writer(f).writerow(row)
        except Exception as e:
            logger.error("[RLLogger] Could not write training record: %s", e)
