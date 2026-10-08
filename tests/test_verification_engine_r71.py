#!/usr/bin/env python3
"""R7.1 — VerificationEngine core unit tests (no controller integration)."""

from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import VerificationStatus
from verification import (
    AttackConfirmationState,
    STAGE_ORDER,
    VerificationConfig,
    VerificationEngine,
    VerificationInput,
    VerificationStage,
    is_warmup_active,
)


def _pred(status="ATTACK", confidence=90.0, source="ml"):
    return {"status": status, "confidence": confidence, "source": source}


def _expl(hint="SYN_FLOOD"):
    return {"attack_type_hint": hint}


def _flood_flows(src="aa:aa:aa:aa:aa:01", dst="aa:aa:aa:aa:aa:02", rate=5000.0):
    return [
        {"src_mac": src, "dst_mac": dst, "packet_rate": rate, "priority": 1},
        {
            "src_mac": "aa:aa:aa:aa:aa:03",
            "dst_mac": "aa:aa:aa:aa:aa:04",
            "packet_rate": 10.0,
            "priority": 1,
        },
    ]


def _engine_with_stub_identify(pairs=None, strategy="FLOW_PAIR"):
    pairs = pairs if pairs is not None else [("aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02")]

    def identify(flows, expl):
        return list(pairs)

    def select(hint, dst):
        return strategy

    return VerificationEngine(
        identify_attackers=identify,
        select_strategy=select,
    )


class TestWarmup(unittest.TestCase):
    def test_is_warmup_active_matches_flow_monitor(self):
        self.assertTrue(is_warmup_active(1, 3))
        self.assertTrue(is_warmup_active(3, 3))
        self.assertFalse(is_warmup_active(4, 3))

    def test_warmup_prevents_eligibility(self):
        eng = _engine_with_stub_identify()
        result = eng.verify(
            VerificationInput(
                dpid=1,
                prediction=_pred(),
                explanation=_expl(),
                flow_features=_flood_flows(),
                warmup_cycles_done=2,
                attack_streak=5,
            )
        )
        self.assertEqual(result.status, VerificationStatus.INELIGIBLE)
        self.assertFalse(result.mitigation_eligible)
        self.assertEqual(result.stages[0].stage_name, VerificationStage.WARMUP.value)
        self.assertEqual(len(result.stages), 1)


class TestDetectionEvidence(unittest.TestCase):
    def test_normal_rejected(self):
        eng = _engine_with_stub_identify()
        result = eng.verify(
            VerificationInput(
                dpid=1,
                prediction=_pred("NORMAL", 10.0),
                explanation=_expl(),
                flow_features=_flood_flows(),
                warmup_cycles_done=5,
                attack_streak=0,
            )
        )
        self.assertEqual(result.status, VerificationStatus.REJECTED)
        self.assertEqual(result.reason, "no_detection_evidence")


class TestAttackConfirmation(unittest.TestCase):
    def test_confirmation_below_required_count(self):
        eng = _engine_with_stub_identify()
        result = eng.verify(
            VerificationInput(
                dpid=1,
                prediction=_pred("ATTACK", 95.0),
                explanation=_expl(),
                flow_features=_flood_flows(),
                warmup_cycles_done=5,
                attack_streak=1,
            )
        )
        self.assertEqual(result.status, VerificationStatus.PENDING)
        self.assertFalse(result.mitigation_eligible)

    def test_confirmation_reaches_required_count(self):
        eng = _engine_with_stub_identify()
        result = eng.verify(
            VerificationInput(
                dpid=1,
                prediction=_pred("ATTACK", 95.0),
                explanation=_expl(),
                flow_features=_flood_flows(),
                warmup_cycles_done=5,
                attack_streak=2,
            )
        )
        self.assertEqual(result.status, VerificationStatus.VERIFIED)
        self.assertTrue(result.mitigation_eligible)

    def test_suspicious_insufficient_for_auto_mitigate(self):
        eng = _engine_with_stub_identify()
        result = eng.verify(
            VerificationInput(
                dpid=1,
                prediction=_pred("SUSPICIOUS", 90.0),
                explanation=_expl(),
                flow_features=_flood_flows(),
                warmup_cycles_done=5,
                attack_streak=1,
            )
        )
        self.assertEqual(result.status, VerificationStatus.INELIGIBLE)
        self.assertEqual(result.reason, "status_not_auto_mitigated")


class TestConfidenceGate(unittest.TestCase):
    def test_confidence_below_threshold(self):
        eng = _engine_with_stub_identify()
        result = eng.verify(
            VerificationInput(
                dpid=1,
                prediction=_pred("ATTACK", 59.9),
                explanation=_expl(),
                flow_features=_flood_flows(),
                warmup_cycles_done=5,
                attack_streak=2,
            )
        )
        self.assertEqual(result.status, VerificationStatus.INELIGIBLE)
        self.assertEqual(result.reason, "confidence_below_threshold")

    def test_confidence_exactly_at_threshold(self):
        eng = _engine_with_stub_identify()
        result = eng.verify(
            VerificationInput(
                dpid=1,
                prediction=_pred("ATTACK", 60.0),
                explanation=_expl(),
                flow_features=_flood_flows(),
                warmup_cycles_done=5,
                attack_streak=2,
            )
        )
        self.assertEqual(result.status, VerificationStatus.VERIFIED)

    def test_confidence_above_threshold(self):
        eng = _engine_with_stub_identify()
        result = eng.verify(
            VerificationInput(
                dpid=1,
                prediction=_pred("ATTACK", 60.1),
                explanation=_expl(),
                flow_features=_flood_flows(),
                warmup_cycles_done=5,
                attack_streak=2,
            )
        )
        self.assertEqual(result.status, VerificationStatus.VERIFIED)

    def test_invalid_nan_confidence_fail_closed(self):
        eng = _engine_with_stub_identify()
        result = eng.verify(
            VerificationInput(
                dpid=1,
                prediction=_pred("ATTACK", float("nan")),
                explanation=_expl(),
                flow_features=_flood_flows(),
                warmup_cycles_done=5,
                attack_streak=2,
            )
        )
        self.assertEqual(result.status, VerificationStatus.INELIGIBLE)
        self.assertEqual(result.reason, "confidence_below_threshold")


class TestAttackerStages(unittest.TestCase):
    def test_attacker_missing(self):
        eng = _engine_with_stub_identify(pairs=[])
        result = eng.verify(
            VerificationInput(
                dpid=1,
                prediction=_pred("ATTACK", 95.0),
                explanation=_expl(),
                flow_features=_flood_flows(),
                warmup_cycles_done=5,
                attack_streak=2,
            )
        )
        self.assertEqual(result.status, VerificationStatus.INELIGIBLE)
        self.assertEqual(result.reason, "attacker_not_identified")

    def test_attacker_and_victim_identified(self):
        eng = _engine_with_stub_identify(
            pairs=[("aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02")]
        )
        result = eng.verify(
            VerificationInput(
                dpid=1,
                prediction=_pred("ATTACK", 92.0),
                explanation=_expl(),
                flow_features=_flood_flows(),
                warmup_cycles_done=5,
                attack_streak=2,
                event_id="evt-1",
            )
        )
        self.assertEqual(result.status, VerificationStatus.VERIFIED)
        self.assertEqual(result.attacker_mac, "aa:aa:aa:aa:aa:01")
        self.assertEqual(result.victim_mac, "aa:aa:aa:aa:aa:02")
        self.assertAlmostEqual(result.confidence, 0.92, places=5)

    def test_real_identify_p04_bidirectional(self):
        """Uses real MitigationEngine identify (P0.4 victim-reply semantics)."""
        eng = VerificationEngine()
        flows = [
            {
                "src_mac": "aa:aa:aa:aa:aa:01",
                "dst_mac": "aa:aa:aa:aa:aa:02",
                "packet_rate": 8000.0,
                "priority": 1,
            },
            {
                "src_mac": "aa:aa:aa:aa:aa:02",
                "dst_mac": "aa:aa:aa:aa:aa:01",
                "packet_rate": 8000.0,
                "priority": 1,
            },
        ]
        result = eng.verify(
            VerificationInput(
                dpid=1,
                prediction=_pred("ATTACK", 95.0),
                explanation=_expl("BURST"),
                flow_features=flows,
                warmup_cycles_done=5,
                attack_streak=2,
            )
        )
        self.assertEqual(result.status, VerificationStatus.VERIFIED)
        self.assertEqual(result.attacker_mac, "aa:aa:aa:aa:aa:01")


class TestStagesAndFailSafe(unittest.TestCase):
    def test_ordered_stages_on_verified(self):
        eng = _engine_with_stub_identify()
        result = eng.verify(
            VerificationInput(
                dpid=1,
                prediction=_pred("ATTACK", 95.0),
                explanation=_expl(),
                flow_features=_flood_flows(),
                warmup_cycles_done=5,
                attack_streak=2,
            )
        )
        names = [s.stage_name for s in result.stages]
        self.assertEqual(names, [s.value for s in STAGE_ORDER])

    def test_short_circuit_stage_list(self):
        eng = _engine_with_stub_identify()
        result = eng.verify(
            VerificationInput(
                dpid=1,
                prediction=_pred("NORMAL"),
                explanation=_expl(),
                flow_features=_flood_flows(),
                warmup_cycles_done=5,
                attack_streak=0,
            )
        )
        self.assertEqual(len(result.stages), 2)
        self.assertEqual(
            result.stages[-1].stage_name,
            VerificationStage.DETECTION_EVIDENCE.value,
        )

    def test_exception_fail_closed(self):
        eng = _engine_with_stub_identify()
        with mock.patch.object(
            eng, "_verify_inner", side_effect=RuntimeError("boom")
        ):
            result = eng.verify(
                VerificationInput(
                    dpid=1,
                    prediction=_pred(),
                    explanation=_expl(),
                    flow_features=_flood_flows(),
                    warmup_cycles_done=5,
                    attack_streak=2,
                )
            )
        self.assertEqual(result.status, VerificationStatus.INELIGIBLE)
        self.assertFalse(result.mitigation_eligible)
        self.assertEqual(result.reason, "verification_error_fail_closed")

    def test_no_mitigation_side_effects(self):
        execute = mock.Mock()
        identify = mock.Mock(return_value=[("a", "b")])
        select = mock.Mock(return_value="FLOW_PAIR")
        eng = VerificationEngine(
            identify_attackers=identify,
            select_strategy=select,
        )
        # Ensure lazy MitigationEngine is never constructed for this path
        with mock.patch(
            "mitigation.mitigation_engine.MitigationEngine"
        ) as ctor:
            result = eng.verify(
                VerificationInput(
                    dpid=1,
                    prediction=_pred("ATTACK", 95.0),
                    explanation=_expl(),
                    flow_features=_flood_flows(),
                    warmup_cycles_done=5,
                    attack_streak=2,
                )
            )
            ctor.assert_not_called()
        execute.assert_not_called()
        self.assertTrue(result.mitigation_eligible)
        identify.assert_called_once()
        select.assert_called_once()


class TestConfirmationState(unittest.TestCase):
    def test_state_reset_and_increment(self):
        st = AttackConfirmationState(confirm_threshold=2)
        self.assertEqual(st.update(1, "ATTACK"), 1)
        self.assertFalse(st.is_confirmed(1))
        self.assertEqual(st.update(1, "ATTACK"), 2)
        self.assertTrue(st.is_confirmed(1))
        self.assertEqual(st.update(1, "NORMAL"), 0)
        st.reset(1)
        self.assertEqual(st.get(1), 0)

    def test_bounded_state(self):
        st = AttackConfirmationState(max_tracked_switches=2)
        st.update(1, "ATTACK")
        st.update(2, "ATTACK")
        st.update(3, "ATTACK")  # evicts 1
        self.assertEqual(st.get(1), 0)
        self.assertEqual(st.get(3), 1)


class TestConfig(unittest.TestCase):
    def test_invalid_config(self):
        with self.assertRaises(ValueError):
            VerificationConfig(attack_confirm=0)


if __name__ == "__main__":
    unittest.main()
