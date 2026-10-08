#!/usr/bin/env python3
"""
R7.3 — Runtime integration: detector → adapter → verify → mitigate eligibility.

OpenFlow actuation is mocked. Trace I/O is exercised on a temp path.
"""

from __future__ import annotations

import json
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
from verification.engine import VerificationEngine
from verification.runtime import run_verified_mitigation
from verification.trace import append_verification_trace, default_trace_path

ATTACKER = "02:aa:aa:aa:aa:01"
VICTIM = "02:bb:bb:bb:bb:02"


def _flow(src, dst, rate):
    return {
        "src_mac": src,
        "dst_mac": dst,
        "packet_rate": rate,
        "priority": 1,
    }


def _attack_flows():
    return [
        _flow(ATTACKER, VICTIM, 9000.0),
        _flow("02:cc:cc:cc:cc:03", VICTIM, 50.0),
    ]


class _StubMitigation:
    def __init__(self):
        self.calls = []

    def handle_alert(self, dpid, prediction, explanation, flow_features):
        self.calls.append(
            {
                "dpid": dpid,
                "prediction": prediction,
                "explanation": explanation,
                "flow_features": flow_features,
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


class TestVerificationTrace(unittest.TestCase):
    def test_append_trace_fields(self):
        engine = VerificationEngine(config=VerificationConfig())
        from verification.adapters import build_verification_input

        vin = build_verification_input(
            dpid=1,
            prediction={"status": "ATTACK", "confidence": 95.0, "source": "ml"},
            explanation={"attack_type_hint": "SYN_FLOOD"},
            flow_features=_attack_flows(),
            warmup_cycles_done=10,
            attack_streak=2,
        )
        result = engine.verify(vin)
        with tempfile.TemporaryDirectory() as tmp:
            path = default_trace_path(tmp)
            ok = append_verification_trace(result, path, extra={"dpid": 1})
            self.assertTrue(ok)
            with open(path, encoding="utf-8") as fh:
                line = fh.readline()
            rec = json.loads(line)
            for key in (
                "schema_version",
                "verification_id",
                "event_id",
                "timestamp",
                "status",
                "mitigation_eligible",
                "stages",
                "reason",
            ):
                self.assertIn(key, rec)
            self.assertTrue(isinstance(rec["stages"], list))
            self.assertTrue(len(rec["stages"]) >= 1)
            self.assertEqual(rec["attacker_mac"], ATTACKER)
            self.assertEqual(rec["victim_mac"], VICTIM)

    def test_trace_io_error_nonfatal(self):
        engine = VerificationEngine(config=VerificationConfig())
        from verification.adapters import build_verification_input

        vin = build_verification_input(
            dpid=1,
            prediction={"status": "NORMAL", "confidence": 10.0},
            explanation={},
            flow_features=[],
            warmup_cycles_done=10,
            attack_streak=0,
        )
        result = engine.verify(vin)
        # Directory that cannot be created as a file parent... use a file as dir
        with tempfile.NamedTemporaryFile() as blocker:
            bad_path = os.path.join(blocker.name, "verification_trace.jsonl")
            ok = append_verification_trace(result, bad_path)
            self.assertFalse(ok)


class TestRuntimeIntegration(unittest.TestCase):
    def test_eligible_calls_handle_alert(self):
        mitigation = _StubMitigation()
        engine = VerificationEngine(
            config=VerificationConfig(),
            identify_attackers=mitigation._identify_attackers,
            select_strategy=mitigation._select_block_strategy,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = default_trace_path(tmp)
            outcome = run_verified_mitigation(
                engine=engine,
                mitigation=mitigation,
                dpid=1,
                prediction={
                    "status": "ATTACK",
                    "confidence": 95.0,
                    "source": "ml",
                },
                explanation={"attack_type_hint": "SYN_FLOOD"},
                flow_features=_attack_flows(),
                warmup_cycles_done=10,
                attack_streak=2,
                min_confidence_percent=60.0,
                trace_path=path,
                source_tag="ml",
            )
        self.assertEqual(outcome.result.status, VerificationStatus.VERIFIED)
        self.assertTrue(outcome.result.mitigation_eligible)
        self.assertTrue(outcome.handle_alert_called)
        self.assertEqual(len(mitigation.calls), 1)
        self.assertTrue(outcome.trace_written)

    def test_pending_does_not_call_handle_alert(self):
        mitigation = _StubMitigation()
        engine = VerificationEngine(config=VerificationConfig())
        outcome = run_verified_mitigation(
            engine=engine,
            mitigation=mitigation,
            dpid=1,
            prediction={"status": "ATTACK", "confidence": 95.0},
            explanation={"attack_type_hint": "SYN_FLOOD"},
            flow_features=_attack_flows(),
            warmup_cycles_done=10,
            attack_streak=1,
            trace_path=None,
        )
        self.assertEqual(outcome.result.status, VerificationStatus.PENDING)
        self.assertFalse(outcome.handle_alert_called)
        self.assertEqual(mitigation.calls, [])

    def test_low_confidence_no_handle_alert(self):
        mitigation = _StubMitigation()
        engine = VerificationEngine(config=VerificationConfig())
        outcome = run_verified_mitigation(
            engine=engine,
            mitigation=mitigation,
            dpid=1,
            prediction={"status": "ATTACK", "confidence": 40.0},
            explanation={"attack_type_hint": "SYN_FLOOD"},
            flow_features=_attack_flows(),
            warmup_cycles_done=10,
            attack_streak=2,
        )
        self.assertFalse(outcome.result.mitigation_eligible)
        self.assertFalse(outcome.handle_alert_called)

    def test_entropy_path_eligible(self):
        mitigation = _StubMitigation()
        engine = VerificationEngine(
            config=VerificationConfig(),
            identify_attackers=mitigation._identify_attackers,
            select_strategy=mitigation._select_block_strategy,
        )
        outcome = run_verified_mitigation(
            engine=engine,
            mitigation=mitigation,
            dpid=1,
            prediction={
                "status": "ATTACK",
                "confidence": 90.0,
                "source": "entropy",
            },
            explanation={"attack_type_hint": "VOLUMETRIC_FLOOD"},
            flow_features=_attack_flows(),
            warmup_cycles_done=10,
            attack_streak=2,
            source_tag="entropy",
        )
        self.assertTrue(outcome.result.mitigation_eligible)
        self.assertTrue(outcome.handle_alert_called)
        self.assertEqual(len(mitigation.calls), 1)
        self.assertEqual(mitigation.calls[0]["prediction"]["source"], "entropy")

    def test_verification_exception_no_unsafe_block(self):
        mitigation = _StubMitigation()
        engine = VerificationEngine(config=VerificationConfig())
        with mock.patch.object(
            engine, "verify", side_effect=RuntimeError("boom")
        ):
            outcome = run_verified_mitigation(
                engine=engine,
                mitigation=mitigation,
                dpid=1,
                prediction={"status": "ATTACK", "confidence": 99.0},
                explanation={"attack_type_hint": "SYN_FLOOD"},
                flow_features=_attack_flows(),
                warmup_cycles_done=10,
                attack_streak=2,
            )
        self.assertEqual(outcome.result.status, VerificationStatus.INELIGIBLE)
        self.assertFalse(outcome.result.mitigation_eligible)
        self.assertFalse(outcome.handle_alert_called)
        self.assertEqual(mitigation.calls, [])

    def test_engine_internal_fail_closed_no_block(self):
        """Identify raising inside verify → INELIGIBLE, no handle_alert."""

        def boom_identify(_flows, _expl):
            raise RuntimeError("identify failed")

        mitigation = _StubMitigation()
        engine = VerificationEngine(
            config=VerificationConfig(),
            identify_attackers=boom_identify,
            select_strategy=lambda h, d: "FLOW_PAIR",
        )
        outcome = run_verified_mitigation(
            engine=engine,
            mitigation=mitigation,
            dpid=1,
            prediction={"status": "ATTACK", "confidence": 95.0},
            explanation={"attack_type_hint": "SYN_FLOOD"},
            flow_features=_attack_flows(),
            warmup_cycles_done=10,
            attack_streak=2,
        )
        self.assertEqual(outcome.result.status, VerificationStatus.INELIGIBLE)
        self.assertFalse(outcome.handle_alert_called)
        self.assertEqual(mitigation.calls, [])

    def test_no_openflow_from_runtime_helper(self):
        import mitigation.mitigation_engine as me

        mitigation = _StubMitigation()
        engine = VerificationEngine(
            config=VerificationConfig(),
            identify_attackers=mitigation._identify_attackers,
            select_strategy=mitigation._select_block_strategy,
        )
        with mock.patch.object(me, "block_flow_pair") as fp, \
             mock.patch.object(me, "block_src_mac") as sm:
            run_verified_mitigation(
                engine=engine,
                mitigation=mitigation,
                dpid=1,
                prediction={"status": "ATTACK", "confidence": 95.0},
                explanation={"attack_type_hint": "SYN_FLOOD"},
                flow_features=_attack_flows(),
                warmup_cycles_done=10,
                attack_streak=2,
            )
            self.assertFalse(fp.called)
            self.assertFalse(sm.called)
            self.assertEqual(len(mitigation.calls), 1)


class TestFlowMonitorHookSurface(unittest.TestCase):
    def test_dispatch_helper_exists(self):
        import ast

        path = os.path.join(_ROOT, "controller", "flow_monitor.py")
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
        }
        self.assertIn("_dispatch_verified_mitigation", names)
        self.assertIn("_try_entropy_mitigation", names)


if __name__ == "__main__":
    unittest.main()
