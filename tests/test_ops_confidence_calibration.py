"""Ops profile + confidence-gate / fusion calibration regression tests."""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timezone
from unittest import mock

import numpy as np

from fusion.adapters import adapt_entropy_metrics, adapt_ml_prediction
from fusion.engine import CollaborativeFusionEngine
from mitigation.mitigation_engine import (
    MAX_RL_CONFIDENCE_GATE_PERCENT,
    MIN_CONFIDENCE_TO_BLOCK,
    MitigationEngine,
)
from shared_contracts.enums import DetectionDecision
from shared_contracts.ops_profile import OpsProfile, get_ops_policy, resolve_ops_profile


def _ts(sec: int = 0) -> datetime:
    return datetime(2026, 7, 28, 12, 0, sec, tzinfo=timezone.utc)


class TestOpsProfile(unittest.TestCase):
    def test_default_production(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("INTELLISHIELD_OPS_PROFILE", None)
            self.assertEqual(resolve_ops_profile(), OpsProfile.PRODUCTION)

    def test_lab_aliases(self):
        for raw in ("lab", "demo", "DEV"):
            self.assertEqual(resolve_ops_profile(raw), OpsProfile.LAB)

    def test_lab_freezes_conf(self):
        with mock.patch.dict(os.environ, {"INTELLISHIELD_OPS_PROFILE": "lab"}):
            p = get_ops_policy()
            self.assertTrue(p.freeze_rl_confidence_gate)
            self.assertEqual(p.min_rl_conf_threshold, p.max_rl_conf_threshold)


class TestThresholdAdapterBounds(unittest.TestCase):
    def test_production_caps_conf(self):
        with mock.patch.dict(os.environ, {"INTELLISHIELD_OPS_PROFILE": "production"}):
            from rl_engine.threshold_adapter import ThresholdAdapter

            ad = ThresholdAdapter()
            self.assertAlmostEqual(ad.conf_threshold, 0.60, places=2)
            for _ in range(40):
                ad.apply_action(np.array([0.0, 0.0, 1.0]))
            self.assertLessEqual(ad.conf_threshold, 0.75 + 1e-9)

    def test_lab_freezes_conf_under_actions(self):
        with mock.patch.dict(os.environ, {"INTELLISHIELD_OPS_PROFILE": "lab"}):
            from rl_engine.threshold_adapter import ThresholdAdapter

            ad = ThresholdAdapter()
            for _ in range(20):
                ad.apply_action(np.array([0.0, 0.0, 1.0]))
            self.assertAlmostEqual(ad.conf_threshold, 0.60, places=5)


class TestMitigationGateClamp(unittest.TestCase):
    def test_rl_gate_clamped(self):
        eng = MitigationEngine(auto_mitigate=False)

        class _A:
            conf_threshold = 0.92

        eng.set_threshold_adapter(_A())
        with mock.patch.dict(os.environ, {"INTELLISHIELD_OPS_PROFILE": "production"}):
            self.assertLessEqual(
                eng._min_confidence_to_block({"source": "ml"}),
                MAX_RL_CONFIDENCE_GATE_PERCENT,
            )

    def test_lab_uses_static_floor(self):
        eng = MitigationEngine(auto_mitigate=False)

        class _A:
            conf_threshold = 0.92

        eng.set_threshold_adapter(_A())
        with mock.patch.dict(os.environ, {"INTELLISHIELD_OPS_PROFILE": "lab"}):
            self.assertAlmostEqual(
                eng._min_confidence_to_block({"source": "r6_fusion"}),
                MIN_CONFIDENCE_TO_BLOCK,
            )


class TestFusionConfidenceCalibration(unittest.TestCase):
    def test_agree_attack_calibrated_above_raw_s(self):
        eng = CollaborativeFusionEngine()
        fd = eng.fuse(
            detector_results=[
                adapt_ml_prediction({"status": "ATTACK", "confidence": 90.0}, timestamp=_ts(0)),
                adapt_entropy_metrics(
                    {"status": "ALERT", "confidence": 85.0, "entropy_score": 0.2},
                    timestamp=_ts(0),
                ),
            ],
            timestamp=_ts(1),
        )
        self.assertEqual(fd.decision, DetectionDecision.ATTACK)
        S = float(fd.evidence["scores"]["S"])
        self.assertGreaterEqual(fd.confidence or 0.0, S)
        # Should clear static 60% gate after calibration
        self.assertGreaterEqual(fd.confidence or 0.0, 0.70)


if __name__ == "__main__":
    unittest.main()
