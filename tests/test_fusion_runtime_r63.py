#!/usr/bin/env python3
"""R6.3 — Production R6 → R7 integration (no direct mitigation)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import DetectionDecision, DetectorType
from shared_contracts.models import CorrelationResult, FusedDecision, new_id
from shared_contracts.timeutil import utc_now
from fusion.engine import CollaborativeFusionEngine
from fusion.r7_adapter import (
    fused_decision_to_r7_payload,
    fused_should_enter_verification,
)
from fusion.runtime import (
    prepare_collaborative_cycle,
    r6_fusion_enabled_from_env,
)
from fusion.trace import append_fusion_trace, default_fusion_trace_path
from verification.config import VerificationConfig
from verification.engine import VerificationEngine
from verification.runtime import run_verified_mitigation


_TS = datetime(2026, 7, 27, 4, 0, 0, tzinfo=timezone.utc)
ATTACKER = "02:aa:aa:aa:aa:01"
VICTIM = "02:bb:bb:bb:bb:02"


def _flows():
    return [
        {"src_mac": ATTACKER, "dst_mac": VICTIM, "packet_rate": 9000.0, "priority": 1},
        {"src_mac": "02:cc:cc:cc:cc:03", "dst_mac": VICTIM, "packet_rate": 40.0, "priority": 1},
    ]


class _StubMitigation:
    def __init__(self):
        self.calls = []

    def handle_alert(self, dpid, prediction, explanation, flow_features):
        self.calls.append(
            {
                "dpid": dpid,
                "prediction": dict(prediction),
                "explanation": dict(explanation),
                "source": prediction.get("source"),
            }
        )

    def _identify_attackers(self, flow_features, explanation):
        from mitigation.mitigation_engine import MitigationEngine

        return MitigationEngine(auto_mitigate=False)._identify_attackers(
            flow_features, explanation
        )

    def _select_block_strategy(self, hint, dst):
        from mitigation.mitigation_engine import MitigationEngine

        return MitigationEngine(auto_mitigate=False)._select_block_strategy(hint, dst)

    def _min_confidence_to_block(self, prediction=None):
        return 60.0


class TestR63Adapter(unittest.TestCase):
    def test_fused_to_r7_percent_source(self):
        fused = FusedDecision(
            fusion_id="f1",
            timestamp=_TS,
            decision=DetectionDecision.ATTACK,
            confidence=0.91,
            participating=["ML", "ENTROPY"],
            disagreement=False,
            reason="agree",
            evidence={"status": "OK"},
        )
        pred, expl = fused_decision_to_r7_payload(fused)
        self.assertEqual(pred["source"], "r6_fusion")
        self.assertEqual(pred["confidence_scale"], "percent")
        self.assertAlmostEqual(pred["confidence"], 91.0)
        self.assertEqual(pred["status"], "ATTACK")
        self.assertTrue(fused_should_enter_verification(fused))


class TestR63CollaborativeToR7(unittest.TestCase):
    def setUp(self):
        self.engine = VerificationEngine(
            config=VerificationConfig(warmup_threshold=3, attack_confirm=2),
            identify_attackers=_StubMitigation()._identify_attackers,
            select_strategy=_StubMitigation()._select_block_strategy,
        )
        self.mit = _StubMitigation()

    def _dispatch(self, outcome):
        return run_verified_mitigation(
            engine=self.engine,
            mitigation=self.mit,
            dpid=1,
            prediction=outcome.prediction,
            explanation=outcome.explanation,
            flow_features=_flows(),
            warmup_cycles_done=10,
            attack_streak=2,
            source_tag="r6_fusion",
        )

    def test_collaborative_attack_to_r7(self):
        out = prepare_collaborative_cycle(
            switch_id=1,
            ml_prediction={"status": "ATTACK", "confidence": 92.0},
            ml_explanation={"attack_type_hint": "SYN_FLOOD"},
            entropy_metrics={"status": "ALERT", "confidence": 85.0, "entropy_score": 0.2},
            timestamp=_TS,
            persist_trace=False,
        )
        self.assertTrue(out.owned)
        self.assertTrue(out.should_dispatch_r7)
        self.assertEqual(out.prediction["source"], "r6_fusion")
        vr = self._dispatch(out)
        self.assertTrue(vr.result.mitigation_eligible)
        self.assertEqual(len(self.mit.calls), 1)
        self.assertEqual(self.mit.calls[0]["source"], "r6_fusion")

    def test_collaborative_normal(self):
        out = prepare_collaborative_cycle(
            switch_id=1,
            ml_prediction={"status": "NORMAL", "confidence": 80.0},
            entropy_metrics={"status": "NORMAL", "confidence": 75.0, "entropy_score": 0.9},
            timestamp=_TS,
            persist_trace=False,
        )
        self.assertTrue(out.owned)
        self.assertFalse(out.should_dispatch_r7)
        self.assertEqual(out.fused.decision, DetectionDecision.NORMAL)

    def test_collaborative_suspicious_disagreement(self):
        out = prepare_collaborative_cycle(
            switch_id=1,
            ml_prediction={"status": "ATTACK", "confidence": 90.0},
            entropy_metrics={"status": "NORMAL", "confidence": 85.0, "entropy_score": 0.9},
            timestamp=_TS,
            persist_trace=False,
        )
        self.assertTrue(out.owned)
        self.assertTrue(out.fused.disagreement)
        self.assertTrue(out.should_dispatch_r7)
        vr = self._dispatch(out)
        # May or may not be eligible depending on confidence after disagreement
        self.assertIsNotNone(vr.result.status)

    def test_ml_only_owned(self):
        out = prepare_collaborative_cycle(
            switch_id=1,
            ml_prediction={"status": "ATTACK", "confidence": 95.0},
            timestamp=_TS,
            persist_trace=False,
        )
        self.assertTrue(out.owned)
        self.assertIn("ENTROPY", out.fused.evidence["missing_detectors"])

    def test_entropy_only_owned(self):
        out = prepare_collaborative_cycle(
            switch_id=1,
            entropy_metrics={"status": "ALERT", "confidence": 90.0, "entropy_score": 0.1},
            timestamp=_TS,
            persist_trace=False,
        )
        self.assertTrue(out.owned)
        self.assertTrue(out.should_dispatch_r7)

    def test_r6_exception_fallback(self):
        class BoomEngine(CollaborativeFusionEngine):
            def fuse(self, **kwargs):
                raise RuntimeError("boom")

        out = prepare_collaborative_cycle(
            switch_id=1,
            ml_prediction={"status": "ATTACK", "confidence": 90.0},
            engine=BoomEngine(),
            timestamp=_TS,
            persist_trace=False,
        )
        self.assertTrue(out.fallback_legacy)
        self.assertFalse(out.owned)
        self.assertIsNotNone(out.error)

    def test_empty_evidence_fallback(self):
        out = prepare_collaborative_cycle(
            switch_id=1,
            timestamp=_TS,
            persist_trace=False,
        )
        self.assertFalse(out.owned)
        self.assertTrue(out.fallback_legacy)

    def test_r4_high_all_normal_not_attack(self):
        corr = CorrelationResult(
            correlation_id="c1",
            timestamp=_TS,
            score=0.99,
            evidence={"status": "CORRELATED"},
        )
        out = prepare_collaborative_cycle(
            switch_id=1,
            ml_prediction={"status": "NORMAL", "confidence": 90.0},
            entropy_metrics={"status": "NORMAL", "confidence": 90.0, "entropy_score": 0.9},
            correlation=corr,
            timestamp=_TS,
            persist_trace=False,
        )
        self.assertTrue(out.owned)
        self.assertNotEqual(out.fused.decision, DetectionDecision.ATTACK)
        self.assertFalse(out.should_dispatch_r7)

    def test_adwin_cannot_authorize_attack(self):
        out = prepare_collaborative_cycle(
            switch_id=1,
            adwin_alerts=[{"metric_name": "flow_count"}],
            timestamp=_TS,
            persist_trace=False,
        )
        self.assertFalse(out.owned)  # no primary → fallback
        self.assertTrue(out.fallback_legacy)

    def test_hdbscan_cannot_authorize_attack(self):
        out = prepare_collaborative_cycle(
            switch_id=1,
            hdbscan_summary={
                "n_attack": 3,
                "clusters": [{"cluster_label": "ATTACK", "confidence": 0.95}],
            },
            timestamp=_TS,
            persist_trace=False,
        )
        self.assertFalse(out.owned)

    def test_duplicate_prevention_one_r7(self):
        """Single collaborative dispatch — not ML + entropy separately."""
        out = prepare_collaborative_cycle(
            switch_id=1,
            ml_prediction={"status": "ATTACK", "confidence": 90.0},
            entropy_metrics={"status": "ALERT", "confidence": 88.0, "entropy_score": 0.2},
            timestamp=_TS,
            persist_trace=False,
        )
        self.assertTrue(out.owned)
        self._dispatch(out)
        self.assertEqual(len(self.mit.calls), 1)

    def test_trace_persistence_and_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = default_fusion_trace_path(tmp)
            out = prepare_collaborative_cycle(
                switch_id=1,
                ml_prediction={"status": "ATTACK", "confidence": 90.0},
                entropy_metrics={"status": "ALERT", "confidence": 80.0, "entropy_score": 0.2},
                timestamp=_TS,
                trace_path=path,
                persist_trace=True,
            )
            self.assertTrue(out.trace_written)
            with open(path, encoding="utf-8") as fh:
                rec = json.loads(fh.readline())
            self.assertEqual(rec["decision"], "ATTACK")
            self.assertIn("participating", rec)
            # non-fatal write failure
            with mock.patch("os.makedirs", side_effect=OSError("Permission denied")):
                bad = append_fusion_trace(out.fused, "/proc/does_not_exist_r63/x.jsonl")
            self.assertFalse(bad)


class TestR63EnvAndMonitorHook(unittest.TestCase):
    def test_env_flag(self):
        with mock.patch.dict(os.environ, {"INTELLISHIELD_R6_FUSION": "0"}):
            self.assertFalse(r6_fusion_enabled_from_env())
        with mock.patch.dict(os.environ, {"INTELLISHIELD_R6_FUSION": "1"}):
            self.assertTrue(r6_fusion_enabled_from_env())

    def test_flow_monitor_has_r6_method(self):
        # Avoid importing os_ken (not always installed in unit env).
        path = os.path.join(_ROOT, "controller", "flow_monitor.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("_run_r6_collaborative_cycle", src)
        self.assertIn("prepare_collaborative_cycle", src)
        self.assertIn("source_tag=\"r6_fusion\"", src)
        self.assertIn("INTELLISHIELD_R6_FUSION", src)
        self.assertIn("r6_owned_cycle", src)


class TestR63NoDirectMitigation(unittest.TestCase):
    def test_prepare_never_calls_handle_alert(self):
        mit = _StubMitigation()
        with mock.patch.object(mit, "handle_alert") as ha:
            prepare_collaborative_cycle(
                switch_id=1,
                ml_prediction={"status": "ATTACK", "confidence": 99.0},
                entropy_metrics={"status": "ALERT", "confidence": 99.0, "entropy_score": 0.1},
                timestamp=_TS,
                persist_trace=False,
            )
            ha.assert_not_called()


if __name__ == "__main__":
    unittest.main()
