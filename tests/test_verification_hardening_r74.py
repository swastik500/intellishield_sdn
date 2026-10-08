#!/usr/bin/env python3
"""
R7.4 — Hardening / failure / state / fail-safe tests.

Safety invariant: verification internal failure ≠ mitigation authorization.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import VerificationStatus
from verification.config import VerificationConfig
from verification.confirmation_state import AttackConfirmationState
from verification.engine import VerificationEngine, VerificationInput
from verification.runtime import run_verified_mitigation
from verification.trace import append_verification_trace

ATTACKER = "02:aa:aa:aa:aa:01"
VICTIM = "02:bb:bb:bb:bb:02"


def _flows(rate=9000.0):
    return [
        {"src_mac": ATTACKER, "dst_mac": VICTIM, "packet_rate": rate, "priority": 1},
        {"src_mac": "02:cc:cc:cc:cc:03", "dst_mac": VICTIM, "packet_rate": 40.0, "priority": 1},
    ]


class _Mit:
    def __init__(self):
        self.calls = 0

    def handle_alert(self, **_kwargs):
        self.calls += 1


class TestFailureModes(unittest.TestCase):
    def setUp(self):
        self.engine = VerificationEngine(config=VerificationConfig())

    def test_invalid_detector_evidence(self):
        inp = VerificationInput(
            dpid=1,
            prediction={"status": "TOTALLY_INVALID", "confidence": 99.0},
            explanation={},
            flow_features=_flows(),
            warmup_cycles_done=10,
            attack_streak=5,
        )
        result = self.engine.verify(inp)
        self.assertEqual(result.status, VerificationStatus.REJECTED)
        self.assertFalse(result.mitigation_eligible)

    def test_missing_confidence(self):
        inp = VerificationInput(
            dpid=1,
            prediction={"status": "ATTACK"},  # no confidence key
            explanation={"attack_type_hint": "SYN_FLOOD"},
            flow_features=_flows(),
            warmup_cycles_done=10,
            attack_streak=2,
        )
        result = self.engine.verify(inp)
        self.assertFalse(result.mitigation_eligible)
        self.assertNotEqual(result.status, VerificationStatus.VERIFIED)

    def test_malformed_attacker_data(self):
        bad_flows = [
            {"src_mac": None, "dst_mac": VICTIM, "packet_rate": "fast"},
            {"src_mac": ATTACKER, "dst_mac": "", "packet_rate": 99999},
            {"not_a_flow": True},
        ]
        inp = VerificationInput(
            dpid=1,
            prediction={"status": "ATTACK", "confidence": 95.0},
            explanation={"attack_type_hint": "SYN_FLOOD"},
            flow_features=bad_flows,
            warmup_cycles_done=10,
            attack_streak=2,
        )
        result = self.engine.verify(inp)
        self.assertFalse(result.mitigation_eligible)
        self.assertIn(
            result.status,
            (VerificationStatus.INELIGIBLE, VerificationStatus.PENDING),
        )

    def test_empty_flow_evidence(self):
        inp = VerificationInput(
            dpid=1,
            prediction={"status": "ATTACK", "confidence": 95.0},
            explanation={"attack_type_hint": "SYN_FLOOD"},
            flow_features=[],
            warmup_cycles_done=10,
            attack_streak=2,
        )
        result = self.engine.verify(inp)
        self.assertEqual(result.status, VerificationStatus.INELIGIBLE)
        self.assertEqual(result.reason, "attacker_not_identified")

    def test_unexpected_attack_type(self):
        inp = VerificationInput(
            dpid=1,
            prediction={"status": "ATTACK", "confidence": 95.0},
            explanation={"attack_type_hint": "QUANTUM_FLOOD_X"},
            flow_features=_flows(),
            warmup_cycles_done=10,
            attack_streak=2,
        )
        result = self.engine.verify(inp)
        # Unknown hints fall through to existing FLOW_PAIR default when eligible
        self.assertEqual(result.status, VerificationStatus.VERIFIED)
        strat = None
        for stage in result.stages:
            if stage.details.get("recommended_strategy"):
                strat = stage.details["recommended_strategy"]
        self.assertEqual(strat, "FLOW_PAIR")

    def test_trace_write_failure_does_not_authorize(self):
        mit = _Mit()
        with tempfile.NamedTemporaryFile() as blocker:
            bad = os.path.join(blocker.name, "verification_trace.jsonl")
            outcome = run_verified_mitigation(
                engine=self.engine,
                mitigation=mit,
                dpid=1,
                prediction={"status": "NORMAL", "confidence": 10.0},
                explanation={},
                flow_features=[],
                warmup_cycles_done=10,
                attack_streak=0,
                trace_path=bad,
            )
        self.assertFalse(outcome.trace_written)
        self.assertFalse(outcome.handle_alert_called)
        self.assertEqual(mit.calls, 0)

    def test_stage_exception_not_authorization(self):
        def boom(_f, _e):
            raise RuntimeError("stage boom")

        engine = VerificationEngine(
            config=VerificationConfig(),
            identify_attackers=boom,
        )
        mit = _Mit()
        outcome = run_verified_mitigation(
            engine=engine,
            mitigation=mit,
            dpid=1,
            prediction={"status": "ATTACK", "confidence": 99.0},
            explanation={"attack_type_hint": "SYN_FLOOD"},
            flow_features=_flows(),
            warmup_cycles_done=10,
            attack_streak=2,
        )
        self.assertEqual(outcome.result.status, VerificationStatus.INELIGIBLE)
        self.assertFalse(outcome.result.mitigation_eligible)
        self.assertFalse(outcome.handle_alert_called)
        self.assertEqual(mit.calls, 0)

    def test_verify_raise_not_authorization(self):
        engine = VerificationEngine(config=VerificationConfig())
        mit = _Mit()
        with mock.patch.object(engine, "verify", side_effect=ValueError("explode")):
            outcome = run_verified_mitigation(
                engine=engine,
                mitigation=mit,
                dpid=1,
                prediction={"status": "ATTACK", "confidence": 99.0},
                explanation={"attack_type_hint": "SYN_FLOOD"},
                flow_features=_flows(),
                warmup_cycles_done=10,
                attack_streak=2,
            )
        self.assertFalse(outcome.result.mitigation_eligible)
        self.assertEqual(mit.calls, 0)


class TestConfirmationState(unittest.TestCase):
    def test_state_reset(self):
        st = AttackConfirmationState(confirm_threshold=2, max_tracked_switches=8)
        st.update(1, "ATTACK")
        st.update(1, "ATTACK")
        self.assertTrue(st.is_confirmed(1))
        st.reset(1)
        self.assertEqual(st.get(1), 0)
        self.assertFalse(st.is_confirmed(1))

    def test_repeated_attack_events(self):
        st = AttackConfirmationState(confirm_threshold=2)
        self.assertEqual(st.update(7, "ATTACK"), 1)
        self.assertEqual(st.update(7, "ATTACK"), 2)
        self.assertEqual(st.update(7, "ATTACK"), 3)
        self.assertEqual(st.update(7, "NORMAL"), 0)
        self.assertEqual(st.update(7, "SUSPICIOUS"), 1)

    def test_bounded_cardinality(self):
        st = AttackConfirmationState(max_tracked_switches=4)
        for dpid in range(20):
            st.update(dpid, "ATTACK")
        self.assertLessEqual(len(st._streaks), 4)  # noqa: SLF001


class TestConcurrencyAssumptions(unittest.TestCase):
    def test_engine_verify_is_reentrant_stateless(self):
        """Two sequential verifies must not leak eligibility across calls."""
        engine = VerificationEngine(config=VerificationConfig())
        bad = VerificationInput(
            dpid=1,
            prediction={"status": "NORMAL", "confidence": 10.0},
            explanation={},
            flow_features=[],
            warmup_cycles_done=10,
            attack_streak=0,
        )
        good = VerificationInput(
            dpid=1,
            prediction={"status": "ATTACK", "confidence": 95.0},
            explanation={"attack_type_hint": "SYN_FLOOD"},
            flow_features=_flows(),
            warmup_cycles_done=10,
            attack_streak=2,
        )
        r1 = engine.verify(bad)
        r2 = engine.verify(good)
        r3 = engine.verify(bad)
        self.assertFalse(r1.mitigation_eligible)
        self.assertTrue(r2.mitigation_eligible)
        self.assertFalse(r3.mitigation_eligible)

    def test_production_streak_owned_by_monitor_not_engine(self):
        """VerificationEngine does not hold streak dictionaries."""
        engine = VerificationEngine(config=VerificationConfig())
        self.assertFalse(hasattr(engine, "_attack_streak"))
        self.assertFalse(hasattr(engine, "_streaks"))


class TestTraceResourceBounds(unittest.TestCase):
    def test_oversized_record_still_appends(self):
        engine = VerificationEngine(config=VerificationConfig())
        inp = VerificationInput(
            dpid=1,
            prediction={"status": "ATTACK", "confidence": 95.0},
            explanation={"attack_type_hint": "SYN_FLOOD", "summary": "X" * 50000},
            flow_features=_flows(),
            warmup_cycles_done=10,
            attack_streak=2,
        )
        result = engine.verify(inp)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "verification_trace.jsonl")
            # Force tiny bound to exercise truncation path
            ok = append_verification_trace(result, path, max_record_bytes=800)
            self.assertTrue(ok)
            size = os.path.getsize(path)
            self.assertLess(size, 2000)


if __name__ == "__main__":
    unittest.main()
