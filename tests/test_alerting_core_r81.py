#!/usr/bin/env python3
"""R8.1 — AlertManager core unit tests (checklist coverage; not controller-wired)."""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import AlertType, Severity, VerificationStatus
from shared_contracts.models import (
    AlertEvent,
    VerificationResult,
    VerificationStageResult,
    new_id,
)
from shared_contracts.serialize import from_dict, to_dict
from alerting import (
    AlertDisposition,
    AlertFactory,
    AlertFactoryContext,
    AlertManager,
    AlertingConfig,
    LoggingNotificationAdapter,
    MemoryAlertStore,
    MemoryNotificationAdapter,
)
from alerting.factory import build_dedup_key
from alerting.severity import DefaultSeverityPolicy, SeverityEvidence


def _verified_result(**kwargs):
    base = dict(
        verification_id=new_id(),
        timestamp=datetime.now(timezone.utc),
        event_id=new_id(),
        status=VerificationStatus.VERIFIED,
        confidence=0.95,
        stages=[
            VerificationStageResult(
                stage_name="MITIGATION_ELIGIBILITY",
                passed=True,
                reason="ok",
                details={
                    "attack_hint": "SYN_FLOOD",
                    "recommended_strategy": "FLOW_PAIR",
                },
            )
        ],
        attacker_mac="02:aa:aa:aa:aa:01",
        victim_mac="02:bb:bb:bb:bb:02",
        mitigation_eligible=True,
        reason="verified_mitigation_eligible",
    )
    base.update(kwargs)
    return VerificationResult(**base)


class TestAlertFactoryChecklist(unittest.TestCase):
    """STEP 8 items 1–7, 15, 19."""

    def test_01_alert_event_from_verification(self):
        alert = AlertFactory().from_verification(_verified_result())
        self.assertIsInstance(alert, AlertEvent)

    def test_02_ids_generated(self):
        alert = AlertFactory().from_verification(_verified_result())
        assert alert is not None
        self.assertTrue(alert.alert_id)
        self.assertTrue(len(alert.alert_id) >= 8)

    def test_03_supplied_ids_preserved(self):
        aid = "alert-fixed-001"
        eid = "event-fixed-001"
        alert = AlertFactory().from_verification(
            _verified_result(event_id="will-override"),
            AlertFactoryContext(alert_id=aid, event_id=eid),
        )
        assert alert is not None
        self.assertEqual(alert.alert_id, aid)
        self.assertEqual(alert.event_id, eid)

    def test_04_timestamp_valid(self):
        alert = AlertFactory().from_verification(_verified_result())
        assert alert is not None
        self.assertIsInstance(alert.timestamp, datetime)
        self.assertIsNotNone(alert.timestamp.tzinfo)

    def test_05_severity_accepted(self):
        alert = AlertFactory().from_verification(_verified_result())
        assert alert is not None
        self.assertIsInstance(alert.severity, Severity)

    def test_06_no_rca_required(self):
        alert = AlertFactory().from_verification(_verified_result())
        assert alert is not None
        self.assertIsNone(alert.rca_report_id)

    def test_07_optional_rca_accepted(self):
        alert = AlertFactory().from_verification(
            _verified_result(),
            AlertFactoryContext(rca_report_id="rca-xyz"),
        )
        assert alert is not None
        self.assertEqual(alert.rca_report_id, "rca-xyz")

    def test_15_alert_event_serializable(self):
        alert = AlertFactory().from_verification(_verified_result())
        assert alert is not None
        raw = to_dict(alert)
        restored = from_dict(raw, AlertEvent)
        self.assertEqual(restored.alert_id, alert.alert_id)
        self.assertEqual(restored.severity, alert.severity)

    def test_19_invalid_input_handled_safely(self):
        mgr = AlertManager(adapters=[MemoryNotificationAdapter()])
        outcome = mgr.process_verification(None)  # type: ignore[arg-type]
        self.assertEqual(outcome.disposition, AlertDisposition.SKIPPED)
        outcome2 = mgr.process_alert(None)  # type: ignore[arg-type]
        self.assertEqual(outcome2.disposition, AlertDisposition.SKIPPED)

    def test_dedup_key_stable(self):
        self.assertEqual(
            build_dedup_key(
                alert_type=AlertType.MITIGATION,
                source="ml",
                attacker_mac="aa",
                victim_mac="bb",
                attack_hint="SYN_FLOOD",
            ),
            "MITIGATION|ml|aa|bb|SYN_FLOOD",
        )

    def test_secret_keys_stripped(self):
        alert = AlertFactory().from_verification(
            _verified_result(),
            AlertFactoryContext(extra_evidence={"token": "SECRET", "ok": 1}),
        )
        assert alert is not None
        self.assertNotIn("token", alert.evidence)
        self.assertEqual(alert.evidence.get("ok"), 1)


class TestAlertManagerChecklist(unittest.TestCase):
    """STEP 8 items 8–14, 16–18, 20."""

    def test_08_manager_accepts_alert(self):
        alert = AlertFactory().from_verification(_verified_result())
        assert alert is not None
        outcome = AlertManager().process_alert(alert)
        self.assertEqual(outcome.disposition, AlertDisposition.NEW)

    def test_09_one_adapter_receives(self):
        mem = MemoryNotificationAdapter()
        AlertManager(adapters=[mem]).process_verification(_verified_result())
        self.assertEqual(len(mem.sent), 1)

    def test_10_multiple_adapters_receive(self):
        a = MemoryNotificationAdapter()
        b = MemoryNotificationAdapter()
        AlertManager(adapters=[a, b]).process_verification(_verified_result())
        self.assertEqual(len(a.sent), 1)
        self.assertEqual(len(b.sent), 1)

    def test_11_disabled_adapter_skipped(self):
        disabled = MemoryNotificationAdapter(enabled=False)
        enabled = MemoryNotificationAdapter(enabled=True)
        outcome = AlertManager(adapters=[disabled, enabled]).process_verification(
            _verified_result()
        )
        self.assertEqual(len(disabled.sent), 0)
        self.assertEqual(len(enabled.sent), 1)
        self.assertEqual(outcome.adapters_skipped, 1)
        self.assertEqual(outcome.adapters_ok, 1)

    def test_12_13_failing_adapter_isolated_healthy_still_called(self):
        class Boom:
            name = "boom"
            enabled = True

            def send(self, alert):
                raise RuntimeError("down")

        healthy = MemoryNotificationAdapter()
        outcome = AlertManager(adapters=[Boom(), healthy]).process_verification(
            _verified_result()
        )
        self.assertEqual(outcome.adapters_failed, 1)
        self.assertEqual(outcome.adapters_ok, 1)
        self.assertEqual(len(healthy.sent), 1)

    def test_14_counters_accurate(self):
        store = MemoryAlertStore()
        mem = MemoryNotificationAdapter()
        mgr = AlertManager(adapters=[mem], store=store)
        mgr.process_verification(_verified_result())
        snap = mgr.metrics.snapshot()
        self.assertEqual(snap["alerts_received"], 1)
        self.assertEqual(snap["alerts_created"], 1)
        self.assertEqual(snap["alerts_dispatched"], 1)
        self.assertEqual(snap["alerts_persisted"], 1)
        self.assertEqual(len(store.records), 1)

    def test_16_no_external_network(self):
        with mock.patch("socket.socket") as sock:
            AlertManager(adapters=[MemoryNotificationAdapter()]).process_verification(
                _verified_result()
            )
            self.assertFalse(sock.called)

    def test_17_no_controller_dependency(self):
        import alerting.manager as m
        import alerting.factory as f

        self.assertNotIn("controller", m.__file__)
        src = open(m.__file__, encoding="utf-8").read()
        self.assertNotIn("flow_monitor", src)
        self.assertNotIn("osken", open(f.__file__, encoding="utf-8").read())

    def test_18_no_mitigation_side_effects(self):
        import mitigation.mitigation_engine as me

        with mock.patch.object(me, "block_flow_pair") as fp, mock.patch.object(
            me, "block_src_mac"
        ) as sm:
            AlertManager(adapters=[MemoryNotificationAdapter()]).process_verification(
                _verified_result()
            )
            self.assertFalse(fp.called)
            self.assertFalse(sm.called)

    def test_20_deterministic_memory_adapter(self):
        mem = MemoryNotificationAdapter()
        AlertManager(adapters=[mem, LoggingNotificationAdapter()]).process_verification(
            _verified_result()
        )
        self.assertEqual(len(mem.sent), 1)
        self.assertEqual(mem.sent[0].severity, Severity.CRITICAL)

    def test_r83_wires_alerting_into_flow_monitor(self):
        """R8.3 wires AlertManager; R8.1 core remains OpenFlow-free."""
        path = os.path.join(_ROOT, "controller", "flow_monitor.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("AlertManager", src)
        self.assertIn("safe_emit_verification_alert", src)

    def test_disabled_manager(self):
        mem = MemoryNotificationAdapter()
        outcome = AlertManager(
            config=AlertingConfig(enabled=False), adapters=[mem]
        ).process_verification(_verified_result())
        self.assertEqual(outcome.disposition, AlertDisposition.DISABLED)
        self.assertEqual(mem.sent, [])

    def test_severity_map_deterministic(self):
        policy = DefaultSeverityPolicy()
        ev = SeverityEvidence(
            "VERIFIED", True, 0.5, attack_hint="BURST"
        )
        self.assertEqual(policy.assign(ev), Severity.HIGH)


if __name__ == "__main__":
    unittest.main()
