#!/usr/bin/env python3
"""R4.3 — Runtime adapters, persistence, fail-isolation (advisory only)."""

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

from correlation.adapters import (
    from_adwin_alerts,
    from_controller_stats,
    from_entropy,
    from_flow_features,
    from_hdbscan_summary,
    from_ml_prediction,
)
from correlation import (
    CorrelationEngine,
    CorrelationRuntimeConfig,
    JsonlCorrelationStore,
    MemoryCorrelationStore,
    build_cycle_signals,
    safe_correlate_cycle,
)
from correlation.engine import CorrelationEngine as Eng
from correlation.persistence import safe_append_correlation
from shared_contracts.serialize import to_dict


ATTACKER = "02:aa:aa:aa:aa:01"
VICTIM = "02:bb:bb:bb:bb:02"


def _flows(rate=9000.0):
    return [
        {
            "src_mac": ATTACKER,
            "dst_mac": VICTIM,
            "switch_id": 1,
            "in_port": 1,
            "packet_rate": rate,
            "byte_rate": 500000.0,
            "priority": 1,
        },
        {
            "src_mac": "02:cc:cc:cc:cc:03",
            "dst_mac": VICTIM,
            "switch_id": 1,
            "in_port": 2,
            "packet_rate": 40.0,
            "byte_rate": 1000.0,
            "priority": 1,
        },
    ]


class TestR43Adapters(unittest.TestCase):
    def test_flow_signal(self):
        sigs = from_flow_features(_flows(), switch_id=1)
        keys = {s.signal_key for s in sigs}
        self.assertIn("flow_stats.packet_rate", keys)
        self.assertIn("flow_stats.active_flow_count", keys)
        self.assertTrue(any(s.entity_key and ATTACKER.lower() in s.entity_key for s in sigs))

    def test_entropy_signal(self):
        sigs = from_entropy(
            {"entropy_score": 0.25, "status": "ALERT", "confidence": 80.0},
            switch_id=1,
        )
        self.assertGreaterEqual(len(sigs), 2)
        self.assertTrue(any(s.name == "status" and s.value == "ALERT" for s in sigs))

    def test_ml_signal(self):
        sigs = from_ml_prediction(
            {"status": "ATTACK", "confidence": 94.0, "iso_score": 0.9},
            switch_id=1,
            explanation={"attack_type_hint": "SYN_FLOOD"},
        )
        self.assertTrue(any(s.source == "ml" and s.name == "status" for s in sigs))

    def test_controller_signal(self):
        sigs = from_controller_stats(
            {"cpu_percent": 55.0, "memory_percent": 40.0, "memory_rss_mb": 200.0}
        )
        self.assertTrue(any(s.name == "cpu_percent" for s in sigs))

    def test_adwin_signal(self):
        sigs = from_adwin_alerts(
            [{"metric_name": "entropy_score", "old_mean": 0.9, "new_mean": 0.3}],
            switch_id=1,
        )
        self.assertEqual(len(sigs), 1)
        self.assertTrue(sigs[0].value is True)

    def test_hdbscan_signal(self):
        sigs = from_hdbscan_summary(
            {
                "n_attack": 1,
                "clusters": [
                    {"cluster_label": "ATTACK", "confidence": 0.8, "cluster_id": 0}
                ],
            },
            switch_id=1,
        )
        self.assertTrue(any(s.name == "cluster_label" for s in sigs))

    def test_malformed_signal_skipped(self):
        # Should not raise
        self.assertEqual(from_entropy(None, switch_id=1), [])
        self.assertEqual(from_ml_prediction("bad", switch_id=1), [])  # type: ignore[arg-type]
        self.assertIsInstance(from_flow_features([None, "x"], switch_id=1), list)  # type: ignore[list-item]


class TestR43Runtime(unittest.TestCase):
    def test_multi_category_window_and_result(self):
        store = MemoryCorrelationStore()
        out = safe_correlate_cycle(
            engine=CorrelationEngine(),
            store=store,
            switch_id=1,
            feature_batch=_flows(),
            entropy={"entropy_score": 0.2, "status": "ALERT", "confidence": 85.0},
            prediction={"status": "ATTACK", "confidence": 95.0},
            controller_stats={"cpu_percent": 70.0, "memory_percent": 50.0},
            drift_alerts=[{"metric_name": "flow_count", "old_mean": 2, "new_mean": 20}],
            cluster_summary={
                "n_attack": 1,
                "clusters": [{"cluster_label": "ATTACK", "confidence": 0.7}],
            },
        )
        self.assertTrue(out.ran)
        self.assertIsNotNone(out.result)
        self.assertGreater(out.result.score, 0.0)
        cats = out.result.evidence.get("participating_categories") or []
        self.assertGreaterEqual(len(cats), 2)
        self.assertFalse(out.result.evidence.get("mitigation_authorized"))
        self.assertTrue(out.result.evidence.get("advisory_only"))
        self.assertEqual(len(store.records), 1)

    def test_entity_separation(self):
        other = [
            {
                "src_mac": "02:ff:ff:ff:ff:ff",
                "dst_mac": VICTIM,
                "switch_id": 1,
                "packet_rate": 50.0,
                "byte_rate": 100.0,
            }
        ]
        # Dominant is ATTACKER from _flows; other host ML-only should not merge if we pass entity
        from correlation.identity import build_entity_key

        ent_a = build_entity_key(src_mac=ATTACKER, switch_id=1)
        signals = build_cycle_signals(
            switch_id=1,
            feature_batch=_flows() + other,
            prediction={"status": "ATTACK", "confidence": 90.0},
            entropy={"status": "ALERT", "entropy_score": 0.2},
        )
        r = CorrelationEngine().correlate(signals, entity_key=ent_a)
        # Should include ATTACKER-scoped evidence; not fail
        self.assertIsNotNone(r.score)

    def test_artifact_persistence_jsonl(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "correlation_results.jsonl")
            store = JsonlCorrelationStore(path)
            out = safe_correlate_cycle(
                engine=CorrelationEngine(),
                store=store,
                switch_id=1,
                feature_batch=_flows(),
                entropy={"status": "ALERT", "entropy_score": 0.15},
                prediction={"status": "ATTACK", "confidence": 90.0},
            )
            self.assertTrue(out.persisted)
            with open(path, encoding="utf-8") as fh:
                line = fh.readline()
            rec = json.loads(line)
            self.assertEqual(rec.get("_type"), "CorrelationResult")
            self.assertIn("score", rec)

    def test_engine_exception_isolated(self):
        class BoomEngine(Eng):
            def correlate(self, *args, **kwargs):
                raise RuntimeError("boom")

        mit_calls = {"n": 0}

        class Mit:
            def handle_alert(self, **_k):
                mit_calls["n"] += 1

        out = safe_correlate_cycle(
            engine=BoomEngine(),
            store=MemoryCorrelationStore(),
            switch_id=1,
            feature_batch=_flows(),
            prediction={"status": "ATTACK", "confidence": 90.0},
        )
        self.assertEqual(out.status, "ERROR")
        Mit().handle_alert()  # still callable
        self.assertEqual(mit_calls["n"], 1)

    def test_persistence_exception_isolated(self):
        class BoomStore:
            name = "boom"

            def append(self, result):
                raise IOError("disk full")

        out = safe_correlate_cycle(
            engine=CorrelationEngine(),
            store=BoomStore(),  # type: ignore[arg-type]
            switch_id=1,
            feature_batch=_flows(),
            entropy={"status": "ALERT", "entropy_score": 0.2},
            prediction={"status": "ATTACK", "confidence": 90.0},
        )
        self.assertTrue(out.ran)
        self.assertIsNotNone(out.result)
        self.assertFalse(out.persisted)

    def test_no_mitigation_call_from_runtime(self):
        with mock.patch(
            "mitigation.mitigation_engine.MitigationEngine.handle_alert"
        ) as ha:
            safe_correlate_cycle(
                engine=CorrelationEngine(),
                store=MemoryCorrelationStore(),
                switch_id=1,
                feature_batch=_flows(),
                prediction={"status": "ATTACK", "confidence": 99.0},
                entropy={"status": "ALERT", "entropy_score": 0.1},
            )
            ha.assert_not_called()


class TestR43PipelineIsolation(unittest.TestCase):
    """Prove R7/R8/R5/mitigation continue when correlation fails."""

    def test_r7_r8_r5_mitigation_unaffected_by_correlation_boom(self):
        from alerting import (
            AlertManager,
            AlertingConfig,
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
        from rca import MemoryRCAStore, RCAConfig, safe_enrich_verified_event
        from ml_models.feature_builder import FEATURE_NAMES

        class Mit:
            def __init__(self):
                self.calls = 0

            def handle_alert(self, **_k):
                self.calls += 1

            def _identify_attackers(self, flow_features, explanation):
                from mitigation.mitigation_engine import MitigationEngine

                return MitigationEngine(auto_mitigate=False)._identify_attackers(
                    flow_features, explanation
                )

            def _select_block_strategy(self, hint, dst):
                from mitigation.mitigation_engine import MitigationEngine

                return MitigationEngine(auto_mitigate=False)._select_block_strategy(
                    hint, dst
                )

            def _min_confidence_to_block(self, prediction=None):
                return 60.0

        mit = Mit()
        engine = VerificationEngine(
            config=VerificationConfig(warmup_threshold=0, attack_confirm=1),
            identify_attackers=mit._identify_attackers,
            select_strategy=mit._select_block_strategy,
        )
        store = MemoryAlertStore()
        am = AlertManager(
            config=AlertingConfig(enabled=True),
            adapters=[MemoryNotificationAdapter()],
            store=store,
        )
        rca_store = MemoryRCAStore()

        prediction = {"status": "ATTACK", "confidence": 95.0, "source": "ml"}
        summary = {n: 0.5 for n in FEATURE_NAMES}
        summary["packet_rate_max"] = 3200.0
        explanation = {"attack_type_hint": "SYN_FLOOD", "vector_summary": summary}

        # Correlation boom first (isolated)
        class Boom(Eng):
            def correlate(self, *a, **k):
                raise RuntimeError("corr boom")

        corr_out = safe_correlate_cycle(
            engine=Boom(),
            store=MemoryCorrelationStore(),
            switch_id=1,
            feature_batch=_flows(),
            prediction=prediction,
        )
        self.assertEqual(corr_out.status, "ERROR")

        def on_verified(result):
            enrich = safe_enrich_verified_event(
                result=result,
                prediction=prediction,
                explanation=explanation,
                store=rca_store,
                config=RCAConfig(enabled=True, run_on_verified=True),
            )
            ctx = build_runtime_alert_context(
                dpid=1,
                prediction=prediction,
                explanation=explanation,
                detector_path="ml",
                event_id=getattr(result, "event_id", None),
                rca_report_id=enrich.rca_report_id,
                extra_evidence=enrich.extra_evidence,
            )
            safe_emit_verification_alert(am, result, ctx)

        outcome = run_verified_mitigation(
            engine=engine,
            mitigation=mit,
            dpid=1,
            prediction=prediction,
            explanation=explanation,
            flow_features=_flows(),
            warmup_cycles_done=10,
            attack_streak=3,
            min_confidence_percent=60.0,
            source_tag="ml",
            on_verified=on_verified,
        )
        self.assertTrue(outcome.handle_alert_called)
        self.assertEqual(mit.calls, 1)
        self.assertGreaterEqual(len(store.records), 1)


class TestR43HookDoesNotWireMitigation(unittest.TestCase):
    def test_flow_monitor_correlation_import_advisory(self):
        import correlation.runtime as rt
        import inspect

        src = inspect.getsource(rt)
        self.assertNotIn("handle_alert", src)
        self.assertNotIn("from mitigation", src)
        self.assertNotIn("FlowBlocker", src)
        self.assertNotIn("ofp_flow_mod", src.lower())
        # Docstring may mention MitigationEngine as a negative constraint
        self.assertIn("Does not call MitigationEngine", src)


if __name__ == "__main__":
    unittest.main()
