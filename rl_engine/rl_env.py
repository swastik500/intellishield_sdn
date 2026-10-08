"""
================================================================================
IntelliShield SDN — Phase 7: SDN RL Environment
================================================================================

File        : rl_engine/rl_env.py
Phase       : Phase 7 — PPO Reinforcement Learning

Description:
    Converts raw SDN metrics into a normalised 10-dimensional state vector
    consumed by the PPO agent.  Acts as the "observation encoder" for the RL
    environment — no simulation, no gym dependency, just a pure state builder.

State vector layout (all values normalised to [0, 1]):
    [0]  packet_rate_mean   / 200,000
    [1]  byte_rate_mean     / 10,000,000
    [2]  entropy_score      (already 0–1)
    [3]  flow_count         / 20
    [4]  ml_confidence      (0–100 from ML → /100, or 0–1 passthrough)
    [5]  pkt_threshold      / 5,000
    [6]  byte_threshold     / 5,000,000
    [7]  conf_threshold     (already 0–1)
    [8]  recent_attack_count / 10
    [9]  recent_fp_count    / 10
================================================================================
"""

import logging
import numpy as np

logger = logging.getLogger("intellishield.rl_env")

# Normalisation constants
_PKT_NORM   = 200_000
_BYTE_NORM  = 10_000_000
_FLOW_NORM  = 20
_THRESH_PKT = 5_000
_THRESH_BYT = 5_000_000
_WIN_NORM   = 10

STATE_DIM   = 10


def _normalize_ml_confidence(value: float) -> float:
    """
    Map ML confidence to [0, 1] for the observation vector.

    AnomalyDetector.predict() returns confidence on a 0–100 scale.
    Legacy callers (e.g. verify_phase7) may pass an already-normalised 0–1 value.
    Values strictly greater than 1.0 are treated as percentages.
    """
    v = float(value)
    if v > 1.0:
        return v / 100.0
    return v


class SDNEnvironment:
    """
    Lightweight RL environment wrapper for the SDN flow monitor.

    No gym/OpenAI dependency.  Provides:
        build_state()  — encode current network metrics as observation
    """

    def __init__(self) -> None:
        logger.info("[SDNEnv] Initialised.  State dim: %d", STATE_DIM)

    def build_state(self,
                    packet_rate_mean:  float,
                    byte_rate_mean:    float,
                    entropy_score:     float,
                    flow_count:        int,
                    ml_confidence:     float,  # 0–100 (production) or 0–1 (legacy)
                    pkt_threshold:     float,
                    byte_threshold:    float,
                    conf_threshold:    float,
                    recent_attack_cnt: int,
                    recent_fp_cnt:     int) -> np.ndarray:
        """
        Build a normalised state vector from current network observations.

        All values are clipped to [0, 1] after normalisation so the network
        never receives out-of-range inputs.

        Returns:
            np.ndarray of shape (STATE_DIM,), dtype float32
        """
        ml_norm = _normalize_ml_confidence(ml_confidence)
        raw = [
            packet_rate_mean  / _PKT_NORM,
            byte_rate_mean    / _BYTE_NORM,
            entropy_score,
            flow_count        / _FLOW_NORM,
            ml_norm,
            pkt_threshold     / _THRESH_PKT,
            byte_threshold    / _THRESH_BYT,
            conf_threshold,
            recent_attack_cnt / _WIN_NORM,
            recent_fp_cnt     / _WIN_NORM,
        ]
        state = np.clip(raw, 0.0, 1.0).astype(np.float32)
        return state
