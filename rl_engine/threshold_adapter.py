"""
================================================================================
IntelliShield SDN — Phase 7: Threshold Adapter
================================================================================

File        : rl_engine/threshold_adapter.py
Phase       : Phase 7 — PPO Reinforcement Learning

Description:
    Owns the three adaptive thresholds that PPO controls.
    Maps raw RL actions ([-1, 1]) to bounded threshold deltas,
    and tracks recent attack / false-positive counts for the state vector.

    Confidence-gate bounds come from shared_contracts.ops_profile so lab
    demos can freeze the gate while production keeps adaptive-but-capped RL.
================================================================================
"""

import logging
import numpy as np
from collections import deque

from shared_contracts.ops_profile import get_ops_policy

logger = logging.getLogger("intellishield.threshold_adapter")

# ── Default starting thresholds (pkt/byte static; conf from ops policy) ───────
DEFAULT_PKT_THRESHOLD  = 500        # packets/sec
DEFAULT_BYTE_THRESHOLD = 500_000    # bytes/sec

# Back-compat aliases for verify_phase7 / older imports (resolved at import time
# from the active ops profile — production bounds unless env overrides).
_policy0 = get_ops_policy()
DEFAULT_CONF_THRESHOLD = float(_policy0.default_rl_conf_threshold)
MIN_CONF = float(_policy0.min_rl_conf_threshold)
MAX_CONF = float(_policy0.max_rl_conf_threshold)

# ── Bounds (pkt/byte) ─────────────────────────────────────────────────────────
# Floor raised so untrained PPO cannot collapse thresholds dangerously low
MIN_PKT  =   250;  MAX_PKT  =  5_000
MIN_BYTE = 300_000; MAX_BYTE = 5_000_000

# ── Action scaling (how much a unit action changes each threshold) ────────────────
# Smaller scale = more gradual changes = policy has time to learn from penalties
PKT_SCALE  = 100          # ±100 pkt/s per unit action  (was 200)
BYTE_SCALE = 100_000      # ±100K B/s per unit action   (was 200K)
CONF_SCALE = 0.03         # ±0.03 confidence per unit action (was 0.05)


class ThresholdAdapter:
    """
    Manages the three adaptive thresholds controlled by PPO.

    Public attributes (read by flow_monitor.py):
        pkt_threshold  : current packet-rate warning threshold (pkt/s)
        byte_threshold : current byte-rate warning threshold   (B/s)
        conf_threshold : minimum ML confidence to trigger mitigation
    """

    def __init__(self) -> None:
        policy = get_ops_policy()
        self._ops_policy = policy
        self._freeze_conf = bool(policy.freeze_rl_confidence_gate)
        self._min_conf = float(policy.min_rl_conf_threshold)
        self._max_conf = float(policy.max_rl_conf_threshold)

        self.pkt_threshold  = float(DEFAULT_PKT_THRESHOLD)
        self.byte_threshold = float(DEFAULT_BYTE_THRESHOLD)
        self.conf_threshold = float(policy.default_rl_conf_threshold)

        # Rolling windows for state features (last 10 cycles)
        self._attack_window : deque = deque(maxlen=10)
        self._fp_window     : deque = deque(maxlen=10)

        logger.info(
            "[ThresholdAdapter] Initialised.  pkt=%d  byte=%d  conf=%.2f  "
            "profile=%s freeze_conf=%s conf_bounds=[%.2f,%.2f]",
            self.pkt_threshold,
            self.byte_threshold,
            self.conf_threshold,
            policy.profile.value,
            self._freeze_conf,
            self._min_conf,
            self._max_conf,
        )

    # ── Apply RL action ───────────────────────────────────────────────────────

    def apply_action(self, action: np.ndarray) -> dict:
        """
        Apply a 3-dimensional RL action to adjust thresholds.

        Args:
            action : np.ndarray of shape (3,), values in [-1, 1]
                     action[0] → Δpacket_rate_threshold
                     action[1] → Δbyte_rate_threshold
                     action[2] → Δconf_threshold (ignored when lab freeze)

        Returns:
            dict with updated threshold values.
        """
        a = np.clip(action, -1.0, 1.0)

        self.pkt_threshold  = float(np.clip(
            self.pkt_threshold  + a[0] * PKT_SCALE,
            MIN_PKT, MAX_PKT,
        ))
        self.byte_threshold = float(np.clip(
            self.byte_threshold + a[1] * BYTE_SCALE,
            MIN_BYTE, MAX_BYTE,
        ))
        if self._freeze_conf:
            self.conf_threshold = float(self._ops_policy.default_rl_conf_threshold)
        else:
            self.conf_threshold = float(np.clip(
                self.conf_threshold + a[2] * CONF_SCALE,
                self._min_conf, self._max_conf,
            ))

        return self.thresholds()

    def thresholds(self) -> dict:
        return {
            "pkt_threshold" : self.pkt_threshold,
            "byte_threshold": self.byte_threshold,
            "conf_threshold": self.conf_threshold,
        }

    # ── Reward computation ────────────────────────────────────────────────────

    def compute_reward(self,
                       ml_label:     str,
                       ml_confidence: float,
                       packet_rate:  float,
                       entropy_score: float,
                       entropy_status: str = "NORMAL",
                       max_pkt_rate: float = 0.0,
                       packet_entropy: float = 1.0) -> float:
        """
        Compute the RL reward for the current cycle.

        Reward signal (Fix D — entropy/ML agreement):
            +10  True positive  (attack indicators + high rate or low entropy)
            +8   Entropy caught attack ML missed (entropy ALERT, high max_pkt)
            +1   Quiet NORMAL cycle
            +0.5 IF-only SUSPICIOUS on quiet traffic (not a full false positive)
            −5   False positive (ATTACK label when traffic is clearly normal)
            −3   ML false negative during entropy ALERT with flood rate
        """
        reward = 0.0
        flood_like = (
            max_pkt_rate > self.pkt_threshold * 2
            or packet_rate > self.pkt_threshold * 2
            or entropy_score < 0.35
            or packet_entropy < 0.30
        )
        quiet = (
            packet_rate < self.pkt_threshold * 0.5
            and max_pkt_rate < self.pkt_threshold
            and entropy_score > 0.65
        )

        ent_alert = str(entropy_status).upper() in ("ALERT", "WARNING")

        if ml_label == "ATTACK":
            if flood_like:
                reward += 10.0
                self._attack_window.append(1)
                self._fp_window.append(0)
            elif quiet:
                reward -= 5.0
                self._attack_window.append(0)
                self._fp_window.append(1)
            else:
                reward += 2.0
                self._attack_window.append(1)
                self._fp_window.append(0)
        elif ml_label == "SUSPICIOUS":
            if quiet:
                reward += 0.5   # IF noise on baseline — mild, not −5
                self._attack_window.append(0)
                self._fp_window.append(0)
            elif flood_like:
                reward += 8.0
                self._attack_window.append(1)
                self._fp_window.append(0)
            else:
                reward += 0.0
                self._attack_window.append(0)
                self._fp_window.append(0)
        else:
            # ML NORMAL
            if ent_alert and flood_like:
                reward -= 3.0
            elif quiet:
                reward += 1.0
            self._attack_window.append(0)
            self._fp_window.append(0)

        if ent_alert and ml_label == "NORMAL" and flood_like:
            reward += 8.0

        # Threshold health penalties
        if self.pkt_threshold < 150:
            reward -= 2.0
        elif self.pkt_threshold > 3_000:
            reward -= 1.0

        if self.conf_threshold > 0.90 and ent_alert and ml_label == "NORMAL":
            reward -= 2.0   # stop RL raising conf during missed attacks

        return reward

    # ── State features ────────────────────────────────────────────────────────

    @property
    def recent_attack_count(self) -> int:
        return sum(self._attack_window)

    @property
    def recent_fp_count(self) -> int:
        return sum(self._fp_window)

    def normalized_thresholds(self) -> tuple:
        """Return thresholds normalised to [0, 1] for the state vector."""
        return (
            self.pkt_threshold  / MAX_PKT,
            self.byte_threshold / MAX_BYTE,
            self.conf_threshold,              # already 0–1
        )
