#!/usr/bin/env python3
"""R5.5 — Failure injection + resource bounds for XAI/RCA."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import VerificationStatus
from shared_contracts.models import VerificationResult, new_id
from ml_models.feature_builder import FEATURE_NAMES
from xai import ExplanationMethod, XAIEngine
from rca import (
    MemoryRCAStore,
    RCAContext,
    RootCauseEngine,
    safe_enrich_verified_event,
)
from rca.persistence import read_rca_history
from verification.config import VerificationConfig
from verification.engine import VerificationEngine
from verification.runtime import run_verified_mitigation
from alerting import (
    AlertDisposition,
    AlertManager,
    AlertingConfig,
    FakeTimeProvider,
    MemoryAlertStore,
    MemoryNotificationAdapter,
)
from alerting.runtime import build_runtime_alert_context, safe_emit_verification_alert


def _vec(**kw):
    base = {n: 1.0 for n in FEATURE_NAMES}
    base.update(kw)
    return [float(base[n]) for n in FEATURE_NAMES]


def _ver(status=VerificationStatus.VERIFIED, eligible=True):
    return VerificationResult(
        verification_id=new_id(),
        timestamp=datetime.now(timezone.utc),
        event_id=new_id(),
        status=status,
        confidence=0.9,
        stages=[],
        attacker_mac="02:aa:aa:aa:aa:01",
        victim_mac="02:bb:bb:bb:bb:02",
        mitigation_eligible=eligible,
        reason="test",
    )


class _Mit:
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

        return MitigationEngine(auto_mitigate=False)._select_block_strategy(hint, dst)

    def _min_confidence_to_block(self, prediction=None):
        return 60.0


class TestR5HardeningR55(unittest.TestCase):
    def test_model_unavailable_unsupported_mismatch_nan(self):
        eng = XAIEngine()
        out = eng.explain(_vec(packet_rate_max=3000), {"status": "ATTACK", "confidence": 90})
        self.assertFalse(out.model_available)

        rf = RandomForestClassifier(n_estimators=2, random_state=0)
        rf.fit(np.zeros((8, len(FEATURE_NAMES))), [0, 1] * 4)
        out2 = eng.explain(
            _vec(),
            {"status": "ATTACK", "confidence": 90},
            decision_tree=rf,
            scaler=StandardScaler().fit(np.zeros((4, len(FEATURE_NAMES)))),
        )
        self.assertEqual(out2.method, ExplanationMethod.UNSUPPORTED_MODEL.value)

        out3 = eng.explain(
            [1.0, 2.0],
            {"status": "ATTACK", "confidence": 90},
            decision_tree=DecisionTreeClassifier(),
            scaler=StandardScaler(),
        )
        self.assertEqual(out3.method, ExplanationMethod.FEATURE_MISMATCH.value)

        bad = _vec()
        bad[0] = float("nan")
        out4 = eng.explain(bad, {"status": "ATTACK", "confidence": 90})
        self.assertTrue(any("nonfinite" in m for m in out4.missing_evidence))

    def test_xai_rca_persist_failures_isolated_from_mitigation(self):
        mit = _Mit()
        am = AlertManager(
            config=AlertingConfig(rate_limit_enabled=False),
            adapters=[MemoryNotificationAdapter()],
            store=MemoryAlertStore(),
            clock=FakeTimeProvider(),
        )

        class BoomXAI:
            def explain(self, *a, **k):
                raise RuntimeError("xai")

            def explain_from_detector(self, *a, **k):
                raise RuntimeError("xai")

        class BoomStore:
            name = "boom"

            def append(self, report):
                raise RuntimeError("disk")

        def on_verified(result):
            enrich = safe_enrich_verified_event(
                result=result,
                prediction={"status": "ATTACK", "confidence": 95},
                explanation={"attack_type_hint": "SYN_FLOOD"},
                feature_vector=_vec(packet_rate_max=3000),
                xai_engine=BoomXAI(),
                store=BoomStore(),
            )
            ctx = build_runtime_alert_context(
                dpid=1,
                prediction={"status": "ATTACK", "confidence": 95},
                explanation={"attack_type_hint": "SYN_FLOOD"},
                detector_path="ml",
                event_id=result.event_id,
                rca_report_id=enrich.rca_report_id,
                extra_evidence=enrich.extra_evidence,
            )
            out = safe_emit_verification_alert(am, result, ctx)
            self.assertEqual(out.disposition, AlertDisposition.NEW)

        engine = VerificationEngine(
            config=VerificationConfig(),
            identify_attackers=mit._identify_attackers,
            select_strategy=mit._select_block_strategy,
        )
        outcome = run_verified_mitigation(
            engine=engine,
            mitigation=mit,
            dpid=1,
            prediction={"status": "ATTACK", "confidence": 95, "source": "ml"},
            explanation={"attack_type_hint": "SYN_FLOOD"},
            flow_features=[
                {
                    "src_mac": "02:aa:aa:aa:aa:01",
                    "dst_mac": "02:bb:bb:bb:bb:02",
                    "packet_rate": 9000,
                    "priority": 1,
                }
            ],
            warmup_cycles_done=5,
            attack_streak=2,
            on_verified=on_verified,
        )
        self.assertTrue(outcome.handle_alert_called)
        self.assertEqual(mit.calls, 1)

    def test_rca_exception_and_malformed_history_dashboard_empty(self):
        class BoomRCA:
            def analyze(self, ctx):
                raise RuntimeError("rca")

        enrich = safe_enrich_verified_event(
            result=_ver(),
            prediction={"status": "ATTACK", "confidence": 90},
            explanation={"attack_type_hint": "SYN_FLOOD"},
            rca_engine=BoomRCA(),
            store=MemoryRCAStore(),
        )
        self.assertEqual(enrich.rca_status, "ERROR")
        self.assertIsNone(enrich.rca_report_id)

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "root_cause_reports.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("bad\n{}\n")
            self.assertEqual(read_rca_history(path, limit=10), [])

        dash = os.path.join(_ROOT, "dashboard")
        if dash not in sys.path:
            sys.path.insert(0, dash)
        from fastapi.testclient import TestClient
        import api as api_mod
        from pathlib import Path

        orig = api_mod.RCA_REPORTS_JSONL
        api_mod.RCA_REPORTS_JSONL = Path(tempfile.mkdtemp()) / "missing.jsonl"
        try:
            client = TestClient(api_mod.app)
            res = client.get("/api/root-cause-reports?limit=5")
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json()["reports"], [])
            missing = client.get("/api/root-cause-reports/nope")
            self.assertEqual(missing.status_code, 404)
        finally:
            api_mod.RCA_REPORTS_JSONL = orig

    def test_alert_manager_failure_and_mitigation_failure_isolated(self):
        mit = _Mit()

        class BoomMgr:
            def process_verification(self, *a, **k):
                raise RuntimeError("alert boom")

        def on_verified(result):
            safe_emit_verification_alert(BoomMgr(), result, None)

        engine = VerificationEngine(
            config=VerificationConfig(),
            identify_attackers=mit._identify_attackers,
            select_strategy=mit._select_block_strategy,
        )
        outcome = run_verified_mitigation(
            engine=engine,
            mitigation=mit,
            dpid=1,
            prediction={"status": "ATTACK", "confidence": 95, "source": "ml"},
            explanation={"attack_type_hint": "SYN_FLOOD"},
            flow_features=[
                {
                    "src_mac": "02:aa:aa:aa:aa:01",
                    "dst_mac": "02:bb:bb:bb:bb:02",
                    "packet_rate": 9000,
                    "priority": 1,
                }
            ],
            warmup_cycles_done=5,
            attack_streak=2,
            on_verified=on_verified,
        )
        self.assertEqual(mit.calls, 1)

        # Mitigation boom still after alert
        class BoomMit(_Mit):
            def handle_alert(self, **k):
                raise RuntimeError("mit boom")

        boom_mit = BoomMit()
        am = AlertManager(
            config=AlertingConfig(rate_limit_enabled=False),
            adapters=[MemoryNotificationAdapter()],
            store=MemoryAlertStore(),
            clock=FakeTimeProvider(),
        )
        alerts = []

        def on_verified2(result):
            alerts.append(
                safe_emit_verification_alert(
                    am,
                    result,
                    build_runtime_alert_context(
                        dpid=1,
                        prediction={"status": "ATTACK", "confidence": 95},
                        explanation={"attack_type_hint": "SYN_FLOOD"},
                        detector_path="ml",
                        event_id=result.event_id,
                    ),
                )
            )

        engine2 = VerificationEngine(
            config=VerificationConfig(),
            identify_attackers=boom_mit._identify_attackers,
            select_strategy=boom_mit._select_block_strategy,
        )
        run_verified_mitigation(
            engine=engine2,
            mitigation=boom_mit,
            dpid=1,
            prediction={"status": "ATTACK", "confidence": 95, "source": "ml"},
            explanation={"attack_type_hint": "SYN_FLOOD"},
            flow_features=[
                {
                    "src_mac": "02:aa:aa:aa:aa:01",
                    "dst_mac": "02:bb:bb:bb:bb:02",
                    "packet_rate": 9000,
                    "priority": 1,
                }
            ],
            warmup_cycles_done=5,
            attack_streak=2,
            on_verified=on_verified2,
        )
        self.assertEqual(alerts[0].disposition, AlertDisposition.NEW)

    def test_bounded_history_state(self):
        store = MemoryRCAStore(max_retained=8)
        eng = RootCauseEngine()
        for i in range(20):
            report = eng.analyze(
                RCAContext(event_id=f"e{i}", verification=_ver())
            )
            store.append(report)
        self.assertLessEqual(len(store.records), 8)


if __name__ == "__main__":
    unittest.main()
