#!/usr/bin/env python3
"""
P0.1 — RL observation normalization tests.

Verifies ml_confidence from AnomalyDetector (0–100) is encoded as [0, 1]
in the PPO state vector without breaking legacy 0–1 callers.
"""

import os
import sys

import numpy as np

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from rl_engine.rl_env import SDNEnvironment, STATE_DIM, _normalize_ml_confidence
from rl_engine.ppo_agent import PPOAgent


def _build_state_legacy_raw(env, ml_confidence, **kwargs):
    """Reproduce pre-P0.1 behaviour (ml_confidence passed through unscaled)."""
    defaults = dict(
        packet_rate_mean=1000.0,
        byte_rate_mean=100_000.0,
        entropy_score=0.9,
        flow_count=4,
        pkt_threshold=500.0,
        byte_threshold=500_000.0,
        conf_threshold=0.80,
        recent_attack_cnt=0,
        recent_fp_cnt=0,
    )
    defaults.update(kwargs)
    defaults["ml_confidence"] = ml_confidence
    # Inline old encoder: no _normalize_ml_confidence
    raw = [
        defaults["packet_rate_mean"] / 200_000,
        defaults["byte_rate_mean"] / 10_000_000,
        defaults["entropy_score"],
        defaults["flow_count"] / 20,
        defaults["ml_confidence"],
        defaults["pkt_threshold"] / 5_000,
        defaults["byte_threshold"] / 5_000_000,
        defaults["conf_threshold"],
        defaults["recent_attack_cnt"] / 10,
        defaults["recent_fp_cnt"] / 10,
    ]
    return np.clip(raw, 0.0, 1.0).astype(np.float32)


def test_normalize_helper():
    assert _normalize_ml_confidence(85.2) == 0.852
    assert _normalize_ml_confidence(0.85) == 0.85
    assert _normalize_ml_confidence(100.0) == 1.0
    assert _normalize_ml_confidence(0.0) == 0.0


def test_production_confidence_not_saturated_before_fix():
    """85.2% confidence used to clip observation dim [4] to 1.0."""
    env = SDNEnvironment()
    before = _build_state_legacy_raw(env, 85.2)
    assert before[4] == 1.0, f"expected pre-fix saturation, got {before[4]}"


def test_production_confidence_normalized_after_fix():
    env = SDNEnvironment()
    after = env.build_state(
        packet_rate_mean=1000,
        byte_rate_mean=100_000,
        entropy_score=0.9,
        flow_count=4,
        ml_confidence=85.2,
        pkt_threshold=500,
        byte_threshold=500_000,
        conf_threshold=0.80,
        recent_attack_cnt=0,
        recent_fp_cnt=0,
    )
    assert after.shape == (STATE_DIM,)
    assert after.dtype == np.float32
    assert 0.85 <= after[4] <= 0.86, f"dim[4]={after[4]}"
    assert after[4] < 1.0


def test_legacy_fractional_confidence_unchanged():
    env = SDNEnvironment()
    state = env.build_state(
        packet_rate_mean=5,
        byte_rate_mean=400,
        entropy_score=0.98,
        flow_count=2,
        ml_confidence=0.82,
        pkt_threshold=500,
        byte_threshold=500_000,
        conf_threshold=0.80,
        recent_attack_cnt=0,
        recent_fp_cnt=0,
    )
    assert abs(state[4] - 0.82) < 1e-6


def test_all_dims_in_unit_interval():
    env = SDNEnvironment()
    state = env.build_state(
        packet_rate_mean=120_000,
        byte_rate_mean=6_000_000,
        entropy_score=0.0,
        flow_count=20,
        ml_confidence=87.0,
        pkt_threshold=500,
        byte_threshold=500_000,
        conf_threshold=0.80,
        recent_attack_cnt=10,
        recent_fp_cnt=10,
    )
    assert np.all((state >= 0.0) & (state <= 1.0))


def test_ppo_accepts_normalized_state():
    agent = PPOAgent(save_path=os.path.join(_ROOT, "logs", "_test_ppo_p01.pkl"),
                     update_every=20)
    env = SDNEnvironment()
    state = env.build_state(
        packet_rate_mean=50_000,
        byte_rate_mean=2_000_000,
        entropy_score=0.15,
        flow_count=3,
        ml_confidence=92.5,
        pkt_threshold=600,
        byte_threshold=600_000,
        conf_threshold=0.78,
        recent_attack_cnt=2,
        recent_fp_cnt=1,
    )
    action, log_prob, value = agent.step(state)
    assert action.shape == (3,)
    assert np.isfinite(log_prob)
    assert np.isfinite(value)
    # Clean up test weights if created
    try:
        os.remove(agent.save_path)
    except OSError:
        pass


if __name__ == "__main__":
    tests = [
        test_normalize_helper,
        test_production_confidence_not_saturated_before_fix,
        test_production_confidence_normalized_after_fix,
        test_legacy_fractional_confidence_unchanged,
        test_all_dims_in_unit_interval,
        test_ppo_accepts_normalized_state,
    ]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {fn.__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
