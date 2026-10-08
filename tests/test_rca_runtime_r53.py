#!/usr/bin/env python3
"""
R5.3 — Runtime XAI/RCA integration tests.

OpenFlow mocked. Proves fail-isolation vs alert + mitigation.
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
from shared_contracts.models import new_id
from shared_contracts.serialize import to_dict
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
from ml_models.feature_builder import FEATURE_NAMES
from rca import (
    JsonlRCAStore,
    MemoryRCAStore,
    RCAConfig,
    safe_enrich_verified_event,
    status_allows_xai_rca,
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
    summary = {n: 0.5 for n in FEATURE_NAMES}
    summary["packet_rate_max"] = 3200.0
    summary["src_entropy"] = 0.1
    return {"attack_type_hint": hint, "vector_summary": summary}


def _vector():
    return [float(_expl()["vector_summary"][n]) for n in FEATURE_NAMES]


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


def _alert_mgr(clock=None):
    return AlertManager(
        config=AlertingConfig(alert_on_pending=False, rate_limit_enabled=False),
        adapters=[MemoryNotificationAdapter()],
        store=MemoryAlertStore(),
        clock=clock or FakeTimeProvider(),
    )


class TestR53RuntimeIntegration(unittest.TestCase):
    def test_policy_verified_only_by_default(self):
        cfg = RCAConfig()
        self.assertTrue(status_allows_xai_rca(VerificationStatus.VERIFIED, cfg))
        self.assertFalse(status_allows_xai_rca(VerificationStatus.PENDING, cfg))
        self.assertFalse(status_allows_xai_rca(VerificationStatus.INELIGIBLE, cfg))
        self.assertFalse(status_allows_xai_rca(VerificationStatus.REJECTED, cfg))

    def test_verified_ml_attack_explanation_and_rca(self):
        mit = _Mit()
        am = _alert_mgr()
        store = MemoryRCAStore()
        eid = new_id()

        def on_verified(result):
            enrich = safe_enrich_verified_event(
                result=result,
                prediction=_pred(),
                explanation=_expl(),
                feature_vector=_vector(),
                store=store,
            )
            self.assertTrue(enrich.ran)
            self.assertIsNotNone(enrich.explanation)
            self.assertIsNotNone(enrich.rca_report_id)
            self.assertEqual(enrich.report.event_id, result.event_id or result.verification_id)
            ctx = build_runtime_alert_context(
                dpid=1,
                prediction=_pred(),
                explanation=_expl(),
                detector_path="ml",
                event_id=result.event_id,
                rca_report_id=enrich.rca_report_id,
                extra_evidence=enrich.extra_evidence,
            )
            out = safe_emit_verification_alert(am, result, ctx)
            self.assertEqual(out.disposition, AlertDisposition.NEW)
            self.assertEqual(out.alert.rca_report_id, enrich.rca_report_id)
            self.assertEqual(out.alert.event_id, result.event_id)
            self.assertTrue(out.alert.evidence.get("rca_linked"))

        outcome = run_verified_mitigation(
            engine=_engine(mit),
            mitigation=mit,
            dpid=1,
            prediction=_pred(),
            explanation=_expl(),
            flow_features=_flows(),
            warmup_cycles_done=5,
            attack_streak=2,
            event_id=eid,
            on_verified=on_verified,
        )
        self.assertTrue(outcome.handle_alert_called)
        self.assertEqual(mit.calls, 1)
        self.assertEqual(len(store.records), 1)
        self.assertEqual(store.records[0].event_id, eid)

    def test_missing_xai_degraded_rca(self):
        # Force XAI error via exploding engine
        class BoomXAI:
            def explain_from_detector(self, *a, **k):
                raise RuntimeError("xai boom")

            def explain(self, *a, **k):
                raise RuntimeError("xai boom")

        mit = _Mit()
        result_holder = {}

        def on_verified(result):
            enrich = safe_enrich_verified_event(
                result=result,
                prediction=_pred(),
                explanation=_expl(),
                feature_vector=_vector(),
                store=MemoryRCAStore(),
                xai_engine=BoomXAI(),
            )
            result_holder["enrich"] = enrich

        outcome = run_verified_mitigation(
            engine=_engine(mit),
            mitigation=mit,
            dpid=1,
            prediction=_pred(),
            explanation=_expl(),
            flow_features=_flows(),
            warmup_cycles_done=5,
            attack_streak=2,
            on_verified=on_verified,
        )
        self.assertTrue(outcome.handle_alert_called)
        enrich = result_holder["enrich"]
        self.assertEqual(enrich.xai_status, "ERROR")
        self.assertIsNotNone(enrich.rca_report_id)
        missing = enrich.report.contributing_features["missing_evidence"]
        self.assertTrue(any(str(m).startswith("xai:") for m in missing))

    def test_xai_exception_isolated_alert_and_mitigation(self):
        mit = _Mit()
        am = _alert_mgr()
        mem = am._adapters[0]

        class BoomXAI:
            def explain(self, *a, **k):
                raise RuntimeError("xai")

            def explain_from_detector(self, *a, **k):
                raise RuntimeError("xai")

        def on_verified(result):
            enrich = safe_enrich_verified_event(
                result=result,
                prediction=_pred(),
                explanation=_expl(),
                xai_engine=BoomXAI(),
                store=MemoryRCAStore(),
            )
            ctx = build_runtime_alert_context(
                dpid=1,
                prediction=_pred(),
                explanation=_expl(),
                detector_path="ml",
                event_id=result.event_id,
                rca_report_id=enrich.rca_report_id,
                extra_evidence=enrich.extra_evidence,
            )
            out = safe_emit_verification_alert(am, result, ctx)
            self.assertEqual(out.disposition, AlertDisposition.NEW)

        outcome = run_verified_mitigation(
            engine=_engine(mit),
            mitigation=mit,
            dpid=1,
            prediction=_pred(),
            explanation=_expl(),
            flow_features=_flows(),
            warmup_cycles_done=5,
            attack_streak=2,
            on_verified=on_verified,
        )
        self.assertEqual(mit.calls, 1)
        self.assertEqual(len(mem.sent), 1)

    def test_rca_exception_isolated(self):
        mit = _Mit()
        am = _alert_mgr()

        class BoomRCA:
            def analyze(self, ctx):
                raise RuntimeError("rca boom")

        def on_verified(result):
            enrich = safe_enrich_verified_event(
                result=result,
                prediction=_pred(),
                explanation=_expl(),
                feature_vector=_vector(),
                rca_engine=BoomRCA(),
                store=MemoryRCAStore(),
            )
            self.assertEqual(enrich.rca_status, "ERROR")
            self.assertIsNone(enrich.rca_report_id)
            ctx = build_runtime_alert_context(
                dpid=1,
                prediction=_pred(),
                explanation=_expl(),
                detector_path="ml",
                event_id=result.event_id,
                rca_report_id=None,
                extra_evidence=enrich.extra_evidence,
            )
            out = safe_emit_verification_alert(am, result, ctx)
            self.assertEqual(out.disposition, AlertDisposition.NEW)
            self.assertIsNone(out.alert.rca_report_id)

        outcome = run_verified_mitigation(
            engine=_engine(mit),
            mitigation=mit,
            dpid=1,
            prediction=_pred(),
            explanation=_expl(),
            flow_features=_flows(),
            warmup_cycles_done=5,
            attack_streak=2,
            on_verified=on_verified,
        )
        self.assertEqual(mit.calls, 1)

    def test_persistence_exception_isolated(self):
        mit = _Mit()
        am = _alert_mgr()

        class BoomStore:
            name = "boom"

            def append(self, report):
                raise RuntimeError("disk full")

        def on_verified(result):
            enrich = safe_enrich_verified_event(
                result=result,
                prediction=_pred(),
                explanation=_expl(),
                feature_vector=_vector(),
                store=BoomStore(),
            )
            self.assertIsNotNone(enrich.rca_report_id)
            self.assertFalse(enrich.persisted)
            ctx = build_runtime_alert_context(
                dpid=1,
                prediction=_pred(),
                explanation=_expl(),
                detector_path="ml",
                event_id=result.event_id,
                rca_report_id=enrich.rca_report_id,
                extra_evidence=enrich.extra_evidence,
            )
            self.assertEqual(
                safe_emit_verification_alert(am, result, ctx).disposition,
                AlertDisposition.NEW,
            )

        outcome = run_verified_mitigation(
            engine=_engine(mit),
            mitigation=mit,
            dpid=1,
            prediction=_pred(),
            explanation=_expl(),
            flow_features=_flows(),
            warmup_cycles_done=5,
            attack_streak=2,
            on_verified=on_verified,
        )
        self.assertEqual(mit.calls, 1)

    def test_normal_pending_skips_xai_rca(self):
        mit = _Mit()
        called = {"n": 0}

        def on_verified(result):
            called["n"] += 1
            enrich = safe_enrich_verified_event(
                result=result,
                prediction=_pred(),
                explanation=_expl(),
                store=MemoryRCAStore(),
            )
            self.assertFalse(enrich.ran)
            self.assertEqual(enrich.xai_status, "SKIPPED")
            self.assertEqual(enrich.rca_status, "SKIPPED")

        outcome = run_verified_mitigation(
            engine=_engine(mit),
            mitigation=mit,
            dpid=1,
            prediction=_pred(),
            explanation=_expl(),
            flow_features=_flows(),
            warmup_cycles_done=5,
            attack_streak=1,  # PENDING
            on_verified=on_verified,
        )
        self.assertFalse(outcome.handle_alert_called)
        self.assertEqual(called["n"], 1)
        self.assertEqual(mit.calls, 0)

    def test_duplicate_alert_does_not_reuse_prior_rca_id(self):
        mit = _Mit()
        clock = FakeTimeProvider()
        am = _alert_mgr(clock)
        store = MemoryRCAStore()
        ids = []

        def on_verified(result):
            enrich = safe_enrich_verified_event(
                result=result,
                prediction=_pred(),
                explanation=_expl(),
                feature_vector=_vector(),
                store=store,
            )
            ids.append(enrich.rca_report_id)
            ctx = build_runtime_alert_context(
                dpid=1,
                prediction=_pred(),
                explanation=_expl(),
                detector_path="ml",
                event_id=result.event_id,
                rca_report_id=enrich.rca_report_id,
                extra_evidence=enrich.extra_evidence,
            )
            return safe_emit_verification_alert(am, result, ctx)

        outs = []
        for _ in range(2):
            def hook(result, outs=outs):
                outs.append(on_verified(result))

            run_verified_mitigation(
                engine=_engine(mit),
                mitigation=mit,
                dpid=1,
                prediction=_pred(),
                explanation=_expl(),
                flow_features=_flows(),
                warmup_cycles_done=5,
                attack_streak=2,
                event_id=new_id(),
                on_verified=hook,
            )

        self.assertEqual(outs[0].disposition, AlertDisposition.NEW)
        self.assertEqual(outs[1].disposition, AlertDisposition.DUPLICATE)
        self.assertNotEqual(ids[0], ids[1])
        # Duplicate alert object may carry its own fresh rca id, but must not
        # equal the *first persisted* alert's id incorrectly swapped.
        self.assertEqual(outs[0].alert.rca_report_id, ids[0])
        if outs[1].alert is not None:
            self.assertEqual(outs[1].alert.rca_report_id, ids[1])
            self.assertNotEqual(outs[1].alert.rca_report_id, ids[0])

    def test_jsonl_persistence_and_r8_compatible(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "root_cause_reports.jsonl")
            store = JsonlRCAStore(path)
            mit = _Mit()
            am = _alert_mgr()

            def on_verified(result):
                enrich = safe_enrich_verified_event(
                    result=result,
                    prediction=_pred(),
                    explanation=_expl(),
                    feature_vector=_vector(),
                    store=store,
                )
                ctx = build_runtime_alert_context(
                    dpid=1,
                    prediction=_pred(),
                    explanation=_expl(),
                    detector_path="ml",
                    event_id=result.event_id,
                    rca_report_id=enrich.rca_report_id,
                    extra_evidence=enrich.extra_evidence,
                )
                out = safe_emit_verification_alert(am, result, ctx)
                self.assertTrue(out.persisted)
                # Alert evidence remains JSON-safe / small
                encoded = json.dumps(to_dict(out.alert))
                self.assertIn("rca_report_id", encoded)
                self.assertNotIn("evidence_items", encoded)

            run_verified_mitigation(
                engine=_engine(mit),
                mitigation=mit,
                dpid=1,
                prediction=_pred(),
                explanation=_expl(),
                flow_features=_flows(),
                warmup_cycles_done=5,
                attack_streak=2,
                on_verified=on_verified,
            )
            with open(path, encoding="utf-8") as fh:
                line = fh.readline()
            rec = json.loads(line)
            self.assertEqual(rec["_type"], "RootCauseReport")

    def test_r7_trace_still_written(self):
        mit = _Mit()
        with tempfile.TemporaryDirectory() as tmp:
            trace = os.path.join(tmp, "verification_trace.jsonl")
            outcome = run_verified_mitigation(
                engine=_engine(mit),
                mitigation=mit,
                dpid=1,
                prediction=_pred(),
                explanation=_expl(),
                flow_features=_flows(),
                warmup_cycles_done=5,
                attack_streak=2,
                trace_path=trace,
                on_verified=lambda r: None,
            )
            self.assertTrue(outcome.trace_written)
            self.assertTrue(os.path.isfile(trace))


if __name__ == "__main__":
    unittest.main()
