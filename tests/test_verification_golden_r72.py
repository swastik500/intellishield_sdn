#!/usr/bin/env python3
"""
R7.2 — Golden compatibility: legacy decision vs VerificationEngine.

No OpenFlow installs. Production controller is not switched.
"""

from __future__ import annotations

import os
import sys
import unittest
from typing import Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import DetectionDecision, DetectorType, VerificationStatus
from verification.adapters import (
    build_detection_event,
    build_verification_input,
    confidence_to_percent,
    normalize_prediction_confidence,
    prediction_to_detector_result,
)
from verification.config import VerificationConfig
from verification.engine import VerificationEngine
from verification.legacy_decision import (
    evaluate_legacy_decision,
    extract_recommended_strategy,
    verification_matches_legacy,
)

ATTACKER = "02:aa:aa:aa:aa:01"
VICTIM = "02:bb:bb:bb:bb:02"
BYSTANDER = "02:cc:cc:cc:cc:03"


def _flow(src, dst, rate, priority=1):
    return {
        "src_mac": src,
        "dst_mac": dst,
        "packet_rate": rate,
        "priority": priority,
    }


def _attack_flows():
    return [
        _flow(ATTACKER, VICTIM, 9000.0),
        _flow(BYSTANDER, VICTIM, 50.0),
    ]


def _victim_reply_flows():
    return [
        _flow(ATTACKER, VICTIM, 14223.0),
        _flow(VICTIM, ATTACKER, 14220.0),
        _flow(BYSTANDER, ATTACKER, 5.0),
    ]


def _pred(status="ATTACK", confidence=95.0, source="ml", **extra):
    out = {"status": status, "confidence": confidence, "source": source}
    out.update(extra)
    return out


def _expl(hint="SYN_FLOOD"):
    return {"attack_type_hint": hint}


def _run_pair(
    *,
    warmup_cycles_done: int,
    attack_streak: int,
    prediction: dict,
    explanation: dict,
    flow_features: list,
    config: Optional[VerificationConfig] = None,
):
    cfg = config or VerificationConfig()
    legacy = evaluate_legacy_decision(
        warmup_cycles_done=warmup_cycles_done,
        attack_streak=attack_streak,
        prediction=prediction,
        explanation=explanation,
        flow_features=flow_features,
        config=cfg,
        datapath_available=True,
    )
    vin = build_verification_input(
        dpid=1,
        prediction=prediction,
        explanation=explanation,
        flow_features=flow_features,
        warmup_cycles_done=warmup_cycles_done,
        attack_streak=attack_streak,
    )
    result = VerificationEngine(config=cfg).verify(vin)
    ok, detail = verification_matches_legacy(legacy, result)
    return legacy, result, ok, detail


class TestAdapterConfidence(unittest.TestCase):
    def test_percent_passthrough(self):
        self.assertEqual(confidence_to_percent(85.0), 85.0)
        self.assertEqual(confidence_to_percent(0.85, scale="percent"), 0.85)

    def test_unit_scale_explicit(self):
        self.assertAlmostEqual(confidence_to_percent(0.85, scale="unit"), 85.0)

    def test_normalize_uses_metadata_not_magnitude(self):
        # 0.85 without unit metadata stays 0.85% (legacy percent semantics)
        out = normalize_prediction_confidence({"confidence": 0.85})
        self.assertAlmostEqual(out["confidence"], 0.85)
        out_u = normalize_prediction_confidence(
            {"confidence": 0.85, "confidence_scale": "unit"}
        )
        self.assertAlmostEqual(out_u["confidence"], 85.0)

    def test_non_finite_fail_closed(self):
        self.assertEqual(confidence_to_percent(float("nan")), 0.0)
        self.assertEqual(confidence_to_percent("bad"), 0.0)

    def test_detection_event_mapping(self):
        ev = build_detection_event(
            dpid=1,
            prediction=_pred("ATTACK", 90.0),
            explanation=_expl("SYN_FLOOD"),
            src_mac=ATTACKER,
            dst_mac=VICTIM,
        )
        self.assertEqual(ev.switch_id, 1)
        self.assertEqual(ev.detector_results[0].decision, DetectionDecision.ATTACK)
        self.assertEqual(ev.detector_results[0].detector, DetectorType.ML)
        self.assertAlmostEqual(ev.detector_results[0].confidence, 0.9)

    def test_entropy_detector_type(self):
        dr = prediction_to_detector_result(_pred(source="entropy"))
        self.assertEqual(dr.detector, DetectorType.ENTROPY)


class TestGoldenCompatibility(unittest.TestCase):
    """Mandatory golden cases: LEGACY vs VerificationEngine."""

    def _assert_match(self, legacy, result, ok, detail):
        self.assertTrue(ok, f"{detail} | legacy={legacy} | engine={result.status} "
                            f"eligible={result.mitigation_eligible} reason={result.reason}")

    def test_warmup(self):
        legacy, result, ok, detail = _run_pair(
            warmup_cycles_done=2,
            attack_streak=5,
            prediction=_pred(),
            explanation=_expl(),
            flow_features=_attack_flows(),
        )
        self._assert_match(legacy, result, ok, detail)
        self.assertEqual(result.status, VerificationStatus.INELIGIBLE)
        self.assertEqual(legacy.reason, "warmup_active")

    def test_normal(self):
        legacy, result, ok, detail = _run_pair(
            warmup_cycles_done=10,
            attack_streak=0,
            prediction=_pred("NORMAL", 10.0),
            explanation=_expl("UNKNOWN"),
            flow_features=_attack_flows(),
        )
        self._assert_match(legacy, result, ok, detail)
        self.assertEqual(result.status, VerificationStatus.REJECTED)

    def test_attack_first_occurrence(self):
        # First ATTACK after increment → streak=1 < confirm=2
        legacy, result, ok, detail = _run_pair(
            warmup_cycles_done=10,
            attack_streak=1,
            prediction=_pred(),
            explanation=_expl(),
            flow_features=_attack_flows(),
        )
        self._assert_match(legacy, result, ok, detail)
        self.assertTrue(legacy.pending_confirmation)
        self.assertEqual(result.status, VerificationStatus.PENDING)

    def test_attack_below_streak(self):
        legacy, result, ok, detail = _run_pair(
            warmup_cycles_done=10,
            attack_streak=1,
            prediction=_pred(),
            explanation=_expl(),
            flow_features=_attack_flows(),
        )
        self._assert_match(legacy, result, ok, detail)
        self.assertEqual(result.status, VerificationStatus.PENDING)

    def test_attack_reaching_streak(self):
        legacy, result, ok, detail = _run_pair(
            warmup_cycles_done=10,
            attack_streak=2,
            prediction=_pred(),
            explanation=_expl("SYN_FLOOD"),
            flow_features=_attack_flows(),
        )
        self._assert_match(legacy, result, ok, detail)
        self.assertTrue(legacy.would_block)
        self.assertEqual(result.status, VerificationStatus.VERIFIED)
        self.assertEqual(extract_recommended_strategy(result), "FLOW_PAIR")

    def test_confidence_below_threshold(self):
        legacy, result, ok, detail = _run_pair(
            warmup_cycles_done=10,
            attack_streak=2,
            prediction=_pred(confidence=59.9),
            explanation=_expl(),
            flow_features=_attack_flows(),
        )
        self._assert_match(legacy, result, ok, detail)
        self.assertFalse(legacy.would_block)
        self.assertEqual(result.status, VerificationStatus.INELIGIBLE)

    def test_confidence_at_threshold(self):
        # handle_alert: confidence < min → block; at 60.0 blocks
        legacy, result, ok, detail = _run_pair(
            warmup_cycles_done=10,
            attack_streak=2,
            prediction=_pred(confidence=60.0),
            explanation=_expl(),
            flow_features=_attack_flows(),
        )
        self._assert_match(legacy, result, ok, detail)
        self.assertTrue(legacy.would_block)
        self.assertEqual(result.status, VerificationStatus.VERIFIED)

    def test_confidence_above_threshold(self):
        legacy, result, ok, detail = _run_pair(
            warmup_cycles_done=10,
            attack_streak=2,
            prediction=_pred(confidence=85.0),
            explanation=_expl(),
            flow_features=_attack_flows(),
        )
        self._assert_match(legacy, result, ok, detail)
        self.assertTrue(result.mitigation_eligible)

    def test_missing_attacker(self):
        flows = [_flow(ATTACKER, VICTIM, 200.0)]  # below rate threshold
        legacy, result, ok, detail = _run_pair(
            warmup_cycles_done=10,
            attack_streak=2,
            prediction=_pred(),
            explanation=_expl(),
            flow_features=flows,
        )
        self._assert_match(legacy, result, ok, detail)
        self.assertEqual(legacy.reason, "attacker_not_identified")
        self.assertEqual(result.status, VerificationStatus.INELIGIBLE)

    def test_valid_attacker(self):
        legacy, result, ok, detail = _run_pair(
            warmup_cycles_done=10,
            attack_streak=2,
            prediction=_pred(),
            explanation=_expl(),
            flow_features=_attack_flows(),
        )
        self._assert_match(legacy, result, ok, detail)
        self.assertEqual(result.attacker_mac, ATTACKER)
        self.assertEqual(result.victim_mac, VICTIM)

    def test_syn_attack_flow_pair(self):
        legacy, result, ok, detail = _run_pair(
            warmup_cycles_done=10,
            attack_streak=2,
            prediction=_pred(),
            explanation=_expl("SYN_FLOOD"),
            flow_features=_attack_flows(),
        )
        self._assert_match(legacy, result, ok, detail)
        self.assertEqual(legacy.recommended_strategy, "FLOW_PAIR")
        self.assertEqual(extract_recommended_strategy(result), "FLOW_PAIR")

    def test_volumetric_attack_src_mac(self):
        legacy, result, ok, detail = _run_pair(
            warmup_cycles_done=10,
            attack_streak=2,
            prediction=_pred(confidence=92.0),
            explanation=_expl("VOLUMETRIC_FLOOD"),
            flow_features=_attack_flows(),
        )
        self._assert_match(legacy, result, ok, detail)
        self.assertEqual(legacy.recommended_strategy, "SRC_MAC")
        self.assertEqual(extract_recommended_strategy(result), "SRC_MAC")

    def test_unknown_attack_type_fallback(self):
        for hint in ("UNKNOWN", "UNKNOWN_ANOMALY"):
            legacy, result, ok, detail = _run_pair(
                warmup_cycles_done=10,
                attack_streak=2,
                prediction=_pred(),
                explanation=_expl(hint),
                flow_features=_attack_flows(),
            )
            self._assert_match(legacy, result, ok, detail)
            self.assertEqual(legacy.recommended_strategy, "FLOW_PAIR")
            self.assertEqual(extract_recommended_strategy(result), "FLOW_PAIR")

    def test_victim_reply_p04(self):
        legacy, result, ok, detail = _run_pair(
            warmup_cycles_done=10,
            attack_streak=2,
            prediction=_pred(),
            explanation=_expl("BURST"),
            flow_features=_victim_reply_flows(),
        )
        self._assert_match(legacy, result, ok, detail)
        self.assertTrue(legacy.would_block)
        self.assertEqual(result.attacker_mac, ATTACKER)
        self.assertEqual(result.victim_mac, VICTIM)
        self.assertEqual(extract_recommended_strategy(result), "FLOW_PAIR")

    def test_malformed_degraded_input(self):
        cases = [
            ({}, {}, []),
            (_pred(confidence=float("nan")), _expl(), _attack_flows()),
            (_pred(confidence="nope"), _expl(), _attack_flows()),
            (_pred(), _expl(), None),
            (_pred(status=None), _expl(), _attack_flows()),
        ]
        for prediction, explanation, flows in cases:
            with self.subTest(prediction=prediction, flows=flows):
                # None flows → treat as empty list at adapter
                ff = flows if flows is not None else []
                pred = prediction if prediction is not None else {}
                legacy, result, ok, detail = _run_pair(
                    warmup_cycles_done=10,
                    attack_streak=2,
                    prediction=pred,
                    explanation=explanation or {},
                    flow_features=ff,
                )
                self._assert_match(legacy, result, ok, detail)
                self.assertFalse(result.mitigation_eligible)
                self.assertNotEqual(result.status, VerificationStatus.VERIFIED)

    def test_unit_scale_adapter_enables_parity_when_declared(self):
        """Explicit confidence_scale=unit is normalized before both paths."""
        pred = _pred(confidence=0.95, confidence_scale="unit")
        legacy, result, ok, detail = _run_pair(
            warmup_cycles_done=10,
            attack_streak=2,
            prediction=pred,
            explanation=_expl(),
            flow_features=_attack_flows(),
        )
        self._assert_match(legacy, result, ok, detail)
        self.assertTrue(result.mitigation_eligible)

    def test_no_openflow_side_effects(self):
        """Verification path must not touch MitigationEngine block APIs."""
        from unittest import mock
        import mitigation.mitigation_engine as me

        with mock.patch.object(me, "block_flow_pair") as fp, \
             mock.patch.object(me, "block_src_mac") as sm:
            _run_pair(
                warmup_cycles_done=10,
                attack_streak=2,
                prediction=_pred(),
                explanation=_expl("SYN_FLOOD"),
                flow_features=_attack_flows(),
            )
            self.assertFalse(fp.called)
            self.assertFalse(sm.called)

    def test_r73_wires_verification_into_flow_monitor(self):
        """R7.3 wires VerificationEngine; R7.2 golden path stays OpenFlow-free."""
        path = os.path.join(_ROOT, "controller", "flow_monitor.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("VerificationEngine", src)
        self.assertIn("run_verified_mitigation", src)
        self.assertIn("_dispatch_verified_mitigation", src)


if __name__ == "__main__":
    unittest.main()
