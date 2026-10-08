#!/usr/bin/env python3
"""
R8.3 — Runtime integration: VerificationResult fan-out to Alert + Mitigation.

OpenFlow mocked. Legacy CSV schemas untouched.
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import VerificationStatus
from shared_contracts.models import new_id
from alerting import (
    AlertDisposition,
    AlertManager,
    AlertingConfig,
    FakeTimeProvider,
    MemoryAlertStore,
    MemoryNotificationAdapter,
)
from alerting.runtime import (
    build_runtime_alert_context,
    safe_emit_verification_alert,
)
from verification.config import VerificationConfig
from verification.engine import VerificationEngine
from verification.runtime import run_verified_mitigation

ATTACKER = "02:aa:aa:aa:aa:01"
VICTIM = "02:bb:bb:bb:bb:02"


def _flows(rate=9000.0):
    return [
        {"src_mac": ATTACKER, "dst_mac": VICTIM, "packet_rate": rate, "priority": 1},
        {"src_mac": "02:cc:cc:cc:cc:03", "dst_mac": VICTIM, "packet_rate": 40.0, "priority": 1},
    ]


def _pred(status="ATTACK", confidence=95.0, source="ml"):
    return {"status": status, "confidence": confidence, "source": source}


def _expl(hint="SYN_FLOOD"):
    return {"attack_type_hint": hint}


class _Mit:
    def __init__(self, boom=False):
        self.calls = 0
        self.boom = boom

    def handle_alert(self, **_kwargs):
        if self.boom:
            raise RuntimeError("mitigation boom")
        self.calls += 1

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


def _engine(mit):
    return VerificationEngine(
        config=VerificationConfig(),
        identify_attackers=mit._identify_attackers,
        select_strategy=mit._select_block_strategy,
    )


class TestRuntimeFanOut(unittest.TestCase):
    def test_verified_attack_creates_alert_and_mitigates(self):
        mit = _Mit()
        mem = MemoryNotificationAdapter()
        store = MemoryAlertStore()
        clock = FakeTimeProvider()
        am = AlertManager(
            config=AlertingConfig(alert_on_pending=False),
            adapters=[mem],
            store=store,
            clock=clock,
        )
        eid = new_id()

        def on_verified(result):
            ctx = build_runtime_alert_context(
                dpid=1,
                prediction=_pred(),
                explanation=_expl(),
                detector_path="ml",
                event_id=result.event_id,
            )
            safe_emit_verification_alert(am, result, ctx)

        outcome = run_verified_mitigation(
            engine=_engine(mit),
            mitigation=mit,
            dpid=1,
            prediction=_pred(),
            explanation=_expl(),
            flow_features=_flows(),
            warmup_cycles_done=10,
            attack_streak=2,
            event_id=eid,
            on_verified=on_verified,
        )
        self.assertTrue(outcome.result.mitigation_eligible)
        self.assertTrue(outcome.handle_alert_called)
        self.assertEqual(mit.calls, 1)
        self.assertEqual(len(mem.sent), 1)
        self.assertEqual(mem.sent[0].event_id, eid)
        self.assertEqual(len(store.records), 1)

    def test_normal_no_security_alert(self):
        mit = _Mit()
        mem = MemoryNotificationAdapter()
        am = AlertManager(adapters=[mem], clock=FakeTimeProvider())

        def on_verified(result):
            safe_emit_verification_alert(
                am,
                result,
                build_runtime_alert_context(
                    dpid=1,
                    prediction=_pred("NORMAL", 10.0),
                    explanation=_expl("UNKNOWN"),
                    detector_path="ml",
                    event_id=result.event_id,
                ),
            )

        outcome = run_verified_mitigation(
            engine=_engine(mit),
            mitigation=mit,
            dpid=1,
            prediction=_pred("NORMAL", 10.0),
            explanation=_expl("UNKNOWN"),
            flow_features=_flows(),
            warmup_cycles_done=10,
            attack_streak=0,
            on_verified=on_verified,
        )
        self.assertFalse(outcome.handle_alert_called)
        self.assertEqual(mem.sent, [])
        self.assertEqual(mit.calls, 0)

    def test_pending_no_alert_by_default(self):
        mit = _Mit()
        mem = MemoryNotificationAdapter()
        am = AlertManager(
            config=AlertingConfig(alert_on_pending=False),
            adapters=[mem],
            clock=FakeTimeProvider(),
        )

        def on_verified(result):
            safe_emit_verification_alert(
                am,
                result,
                build_runtime_alert_context(
                    dpid=1,
                    prediction=_pred(),
                    explanation=_expl(),
                    detector_path="ml",
                    event_id=result.event_id,
                ),
            )

        outcome = run_verified_mitigation(
            engine=_engine(mit),
            mitigation=mit,
            dpid=1,
            prediction=_pred(),
            explanation=_expl(),
            flow_features=_flows(),
            warmup_cycles_done=10,
            attack_streak=1,
            on_verified=on_verified,
        )
        self.assertEqual(outcome.result.status, VerificationStatus.PENDING)
        self.assertEqual(mem.sent, [])
        self.assertFalse(outcome.handle_alert_called)

    def test_ineligible_low_confidence_no_alert(self):
        mit = _Mit()
        mem = MemoryNotificationAdapter()
        am = AlertManager(adapters=[mem], clock=FakeTimeProvider())

        def on_verified(result):
            safe_emit_verification_alert(
                am,
                result,
                build_runtime_alert_context(
                    dpid=1,
                    prediction=_pred(confidence=40.0),
                    explanation=_expl(),
                    detector_path="ml",
                    event_id=result.event_id,
                ),
            )

        outcome = run_verified_mitigation(
            engine=_engine(mit),
            mitigation=mit,
            dpid=1,
            prediction=_pred(confidence=40.0),
            explanation=_expl(),
            flow_features=_flows(),
            warmup_cycles_done=10,
            attack_streak=2,
            on_verified=on_verified,
        )
        self.assertEqual(outcome.result.status, VerificationStatus.INELIGIBLE)
        self.assertEqual(mem.sent, [])
        self.assertFalse(outcome.handle_alert_called)

    def test_duplicate_verified_suppressed(self):
        mit = _Mit()
        mem = MemoryNotificationAdapter()
        am = AlertManager(adapters=[mem], clock=FakeTimeProvider())

        def on_verified(result):
            safe_emit_verification_alert(
                am,
                result,
                build_runtime_alert_context(
                    dpid=1,
                    prediction=_pred(),
                    explanation=_expl(),
                    detector_path="ml",
                    event_id=result.event_id,
                ),
            )

        for _ in range(3):
            run_verified_mitigation(
                engine=_engine(mit),
                mitigation=mit,
                dpid=1,
                prediction=_pred(),
                explanation=_expl(),
                flow_features=_flows(),
                warmup_cycles_done=10,
                attack_streak=2,
                on_verified=on_verified,
            )
        self.assertEqual(len(mem.sent), 1)
        self.assertEqual(am.metrics.snapshot()["alerts_deduplicated"], 2)
        self.assertEqual(mit.calls, 3)  # mitigation still each cycle

    def test_rate_limited_suppression(self):
        mit = _Mit()
        mem = MemoryNotificationAdapter()
        am = AlertManager(
            config=AlertingConfig(
                dedup_enabled=False,
                rate_limit_per_window=1,
                rate_limit_window_sec=60.0,
            ),
            adapters=[mem],
            clock=FakeTimeProvider(),
        )

        def on_verified(result):
            safe_emit_verification_alert(
                am,
                result,
                build_runtime_alert_context(
                    dpid=1,
                    prediction=_pred(),
                    explanation=_expl(),
                    detector_path="ml",
                    event_id=result.event_id,
                ),
            )

        run_verified_mitigation(
            engine=_engine(mit), mitigation=mit, dpid=1,
            prediction=_pred(), explanation=_expl(), flow_features=_flows(),
            warmup_cycles_done=10, attack_streak=2, on_verified=on_verified,
        )
        run_verified_mitigation(
            engine=_engine(mit), mitigation=mit, dpid=1,
            prediction=_pred(), explanation=_expl(), flow_features=_flows(),
            warmup_cycles_done=10, attack_streak=2, on_verified=on_verified,
        )
        self.assertEqual(len(mem.sent), 1)
        self.assertEqual(am.metrics.snapshot()["alerts_rate_limited"], 1)
        self.assertEqual(mit.calls, 2)

    def test_adapter_failure_mitigation_unaffected(self):
        class Boom:
            name = "boom"
            enabled = True

            def send(self, alert):
                raise RuntimeError("adapter down")

        mit = _Mit()
        am = AlertManager(adapters=[Boom()], clock=FakeTimeProvider())

        def on_verified(result):
            safe_emit_verification_alert(
                am, result,
                build_runtime_alert_context(
                    dpid=1, prediction=_pred(), explanation=_expl(),
                    detector_path="ml", event_id=result.event_id,
                ),
            )

        outcome = run_verified_mitigation(
            engine=_engine(mit), mitigation=mit, dpid=1,
            prediction=_pred(), explanation=_expl(), flow_features=_flows(),
            warmup_cycles_done=10, attack_streak=2, on_verified=on_verified,
        )
        self.assertTrue(outcome.handle_alert_called)
        self.assertEqual(mit.calls, 1)
        self.assertEqual(am.metrics.snapshot()["adapter_failures"], 1)

    def test_alert_manager_failure_mitigation_unaffected(self):
        mit = _Mit()

        def on_verified(_result):
            raise RuntimeError("alert manager exploded")

        outcome = run_verified_mitigation(
            engine=_engine(mit), mitigation=mit, dpid=1,
            prediction=_pred(), explanation=_expl(), flow_features=_flows(),
            warmup_cycles_done=10, attack_streak=2, on_verified=on_verified,
        )
        self.assertTrue(outcome.handle_alert_called)
        self.assertEqual(mit.calls, 1)

    def test_mitigation_failure_alert_still_recorded(self):
        mit = _Mit(boom=True)
        mem = MemoryNotificationAdapter()
        store = MemoryAlertStore()
        am = AlertManager(
            adapters=[mem], store=store, clock=FakeTimeProvider()
        )

        def on_verified(result):
            safe_emit_verification_alert(
                am, result,
                build_runtime_alert_context(
                    dpid=1, prediction=_pred(), explanation=_expl(),
                    detector_path="ml", event_id=result.event_id,
                ),
            )

        outcome = run_verified_mitigation(
            engine=_engine(mit), mitigation=mit, dpid=1,
            prediction=_pred(), explanation=_expl(), flow_features=_flows(),
            warmup_cycles_done=10, attack_streak=2, on_verified=on_verified,
        )
        self.assertTrue(outcome.result.mitigation_eligible)
        self.assertFalse(outcome.handle_alert_called)
        self.assertEqual(len(mem.sent), 1)
        self.assertEqual(len(store.records), 1)

    def test_event_ids_linked(self):
        mit = _Mit()
        mem = MemoryNotificationAdapter()
        am = AlertManager(adapters=[mem], clock=FakeTimeProvider())
        eid = "evt-link-001"

        def on_verified(result):
            self.assertEqual(result.event_id, eid)
            safe_emit_verification_alert(
                am, result,
                build_runtime_alert_context(
                    dpid=1, prediction=_pred(), explanation=_expl(),
                    detector_path="ml", event_id=result.event_id,
                ),
            )

        run_verified_mitigation(
            engine=_engine(mit), mitigation=mit, dpid=1,
            prediction=_pred(), explanation=_expl(), flow_features=_flows(),
            warmup_cycles_done=10, attack_streak=2, event_id=eid,
            on_verified=on_verified,
        )
        self.assertEqual(mem.sent[0].event_id, eid)

    def test_ml_entropy_share_dedup_source(self):
        """Same attack via ml then entropy detector_path → one alert."""
        mit = _Mit()
        mem = MemoryNotificationAdapter()
        am = AlertManager(adapters=[mem], clock=FakeTimeProvider())

        def make_on(path):
            def on_verified(result):
                safe_emit_verification_alert(
                    am, result,
                    build_runtime_alert_context(
                        dpid=1, prediction=_pred(), explanation=_expl(),
                        detector_path=path, event_id=result.event_id,
                    ),
                )
            return on_verified

        run_verified_mitigation(
            engine=_engine(mit), mitigation=mit, dpid=1,
            prediction=_pred(), explanation=_expl(), flow_features=_flows(),
            warmup_cycles_done=10, attack_streak=2, on_verified=make_on("ml"),
        )
        run_verified_mitigation(
            engine=_engine(mit), mitigation=mit, dpid=1,
            prediction=_pred(source="entropy"), explanation=_expl(),
            flow_features=_flows(), warmup_cycles_done=10, attack_streak=2,
            on_verified=make_on("entropy"),
        )
        self.assertEqual(len(mem.sent), 1)

    def test_legacy_csv_paths_unchanged(self):
        from entropy_engine.entropy_logger import ALERTS_CSV_PATH
        from ml_models.ml_logger import ML_ALERT_CSV_PATH

        self.assertTrue(ALERTS_CSV_PATH.endswith("detection_alerts.csv"))
        self.assertTrue(ML_ALERT_CSV_PATH.endswith("ml_alerts.csv"))

    def test_flow_monitor_wires_alerting(self):
        path = os.path.join(_ROOT, "controller", "flow_monitor.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("AlertManager", src)
        self.assertIn("on_verified", src)
        self.assertIn("safe_emit_verification_alert", src)

    def test_no_openflow_from_integration(self):
        import mitigation.mitigation_engine as me

        mit = _Mit()
        am = AlertManager(
            adapters=[MemoryNotificationAdapter()], clock=FakeTimeProvider()
        )

        def on_verified(result):
            safe_emit_verification_alert(
                am, result,
                build_runtime_alert_context(
                    dpid=1, prediction=_pred(), explanation=_expl(),
                    detector_path="ml", event_id=result.event_id,
                ),
            )

        with mock.patch.object(me, "block_flow_pair") as fp, mock.patch.object(
            me, "block_src_mac"
        ) as sm:
            run_verified_mitigation(
                engine=_engine(mit), mitigation=mit, dpid=1,
                prediction=_pred(), explanation=_expl(), flow_features=_flows(),
                warmup_cycles_done=10, attack_streak=2, on_verified=on_verified,
            )
            self.assertFalse(fp.called)
            self.assertFalse(sm.called)
            self.assertEqual(mit.calls, 1)


if __name__ == "__main__":
    unittest.main()
