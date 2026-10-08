#!/usr/bin/env python3
"""R6.4 — FusedDecision evidence → R5/R8/Dashboard integration."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import DetectionDecision, VerificationStatus
from shared_contracts.models import (
    FusedDecision,
    VerificationResult,
    VerificationStageResult,
    new_id,
)
from shared_contracts.timeutil import utc_now
from fusion.history import (
    fused_decision_history_stats,
    fused_decision_record_for_api,
    get_fused_decision,
    read_fused_decision_history,
)
from fusion.trace import append_fusion_trace
from rca.context import RCAContext
from rca.engine import RootCauseEngine
from rca.evidence import EvidenceKind
from rca.fusion_evidence import fusion_alert_refs, fusion_evidence_items
from rca.runtime import safe_enrich_verified_event
from alerting.runtime import build_runtime_alert_context
from alerting.factory import AlertFactory
from alerting.config import AlertingConfig
from alerting.persistence import alert_record_for_api


_TS = datetime(2026, 7, 27, 5, 0, 0, tzinfo=timezone.utc)


def _fused(*, disagreement: bool = False, decision=DetectionDecision.ATTACK) -> FusedDecision:
    return FusedDecision(
        fusion_id="fuse-r64-1",
        timestamp=_TS,
        event_id="evt-r64",
        decision=decision,
        confidence=0.82,
        participating=["ML", "ENTROPY"],
        disagreement=disagreement,
        reason="S=0.820 A=0.900 N=0.080 G=1.000 C=0.000 rule=S_ge_attack_threshold",
        evidence={
            "status": "OK",
            "entity_key": "dpid:1|src:02:aa:aa:aa:aa:01",
            "scores": {"A": 0.9, "N": 0.08, "S": 0.82, "G": 1.0, "C": 0.0, "R": 0.1, "U": 0.0},
            "primary_votes": [
                {
                    "detector": "ML",
                    "decision": "ATTACK",
                    "confidence": 0.9,
                    "health": "SUCCESS",
                    "effective_weight": 1.0,
                    "camp": "ATTACK",
                },
                {
                    "detector": "ENTROPY",
                    "decision": "ALERT",
                    "confidence": 0.85,
                    "health": "SUCCESS",
                    "effective_weight": 0.95,
                    "camp": "ATTACK",
                },
            ],
            "missing_detectors": [],
            "degraded_detectors": [],
            "unavailable_detectors": [],
            "stale_detectors": [],
            "correlation": {
                "present": True,
                "boost_applied": True,
                "correlation_id": "corr-1",
                "score": 0.7,
            },
            "context_uncertainty": {"signals": ["ADWIN_DRIFT"], "U": 0.2},
            "context": [
                {
                    "detector": "ADWIN",
                    "role": "CONTEXT_ONLY",
                    "decision": "DRIFT",
                }
            ],
            "decision_rule": "S_ge_attack_threshold",
        },
    )


def _verified() -> VerificationResult:
    return VerificationResult(
        verification_id=new_id(),
        timestamp=utc_now(),
        event_id="evt-r64",
        status=VerificationStatus.VERIFIED,
        confidence=0.9,
        stages=[VerificationStageResult(stage_name="warmup", passed=True)],
        attacker_mac="02:aa:aa:aa:aa:01",
        victim_mac="02:bb:bb:bb:bb:02",
        mitigation_eligible=True,
        reason="ok",
    )


class TestR64FusionEvidence(unittest.TestCase):
    def test_r5_with_fused_decision(self):
        fused = _fused()
        items, signals, features = fusion_evidence_items(fused)
        kinds = {i.key: i.kind for i in items}
        self.assertEqual(kinds["fusion_decision"], EvidenceKind.OBSERVED.value)
        self.assertEqual(kinds["fusion_decision_rule"], EvidenceKind.INFERRED.value)
        self.assertIn("fusion", signals)
        self.assertEqual(features["fusion_id"], "fuse-r64-1")
        # Context must not say attack detected
        ctx_item = next(i for i in items if i.key == "fusion_context")
        self.assertIn("not labelled as attack", ctx_item.statement.lower())

        eng = RootCauseEngine()
        report = eng.analyze(
            RCAContext(event_id="evt-r64", verification=_verified(), fused_decision=fused)
        )
        self.assertIn("fusion", report.contributing_signals)
        self.assertIsInstance(report.contributing_features.get("fusion"), dict)
        self.assertEqual(report.contributing_features["fusion"]["fusion_id"], "fuse-r64-1")

    def test_r5_without_fused_decision(self):
        eng = RootCauseEngine()
        report = eng.analyze(RCAContext(event_id="evt-r64", verification=_verified()))
        self.assertIn("fusion:NOT_AVAILABLE", report.contributing_features["missing_evidence"])
        fus = report.contributing_features.get("fusion")
        self.assertEqual(fus, "NOT_AVAILABLE")

    def test_rca_disagreement_explanation(self):
        fused = _fused(disagreement=True, decision=DetectionDecision.SUSPICIOUS)
        items, _, _ = fusion_evidence_items(fused)
        agree = next(i for i in items if i.key == "fusion_agreement")
        self.assertIn("disagreed", agree.statement.lower())
        self.assertTrue(agree.value.get("disagreement"))


class TestR64AlertLinkage(unittest.TestCase):
    def test_r8_with_r6_evidence(self):
        fused = _fused()
        refs = fusion_alert_refs(fused)
        self.assertTrue(refs["fusion_linked"])
        self.assertEqual(refs["fusion_id"], "fuse-r64-1")
        ctx = build_runtime_alert_context(
            dpid=1,
            prediction={"status": "ATTACK", "confidence": 82.0, "source": "r6_fusion", "fusion_id": fused.fusion_id},
            explanation={"attack_type_hint": "SYN_FLOOD", "r6_confidence_unit": 0.82},
            detector_path="r6_fusion",
            fusion_id=fused.fusion_id,
            extra_evidence=refs,
        )
        self.assertEqual(ctx.fusion_id, "fuse-r64-1")
        self.assertTrue(ctx.extra_evidence.get("fusion_linked"))
        alert = AlertFactory(AlertingConfig()).from_verification(_verified(), ctx)
        flat = alert_record_for_api(
            {
                "alert_id": alert.alert_id,
                "timestamp": alert.timestamp.isoformat(),
                "severity": alert.severity.value,
                "alert_type": alert.alert_type.value,
                "title": alert.title,
                "message": alert.message,
                "source": alert.source,
                "event_id": alert.event_id,
                "rca_report_id": alert.rca_report_id,
                "evidence": alert.evidence,
                "schema_version": alert.schema_version,
            }
        )
        self.assertEqual(flat["fusion_status"], "linked")
        self.assertEqual(flat["fusion_id"], "fuse-r64-1")

    def test_r8_without_r6_evidence(self):
        ctx = build_runtime_alert_context(
            dpid=1,
            prediction={"status": "ATTACK", "confidence": 90.0, "source": "ml"},
            explanation={"attack_type_hint": "SYN_FLOOD"},
            detector_path="ml",
        )
        self.assertIsNone(ctx.fusion_id)
        self.assertFalse(ctx.extra_evidence.get("fusion_linked"))


class TestR64EnrichRuntime(unittest.TestCase):
    def test_safe_enrich_with_and_without_fusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = safe_enrich_verified_event(
                result=_verified(),
                prediction={"status": "ATTACK", "confidence": 90.0, "source": "r6_fusion"},
                explanation={"attack_type_hint": "SYN_FLOOD"},
                fused_decision=_fused(),
                store=None,
            )
            self.assertTrue(out.extra_evidence.get("fusion_linked"))
            self.assertEqual(out.extra_evidence.get("fusion_id"), "fuse-r64-1")

            out2 = safe_enrich_verified_event(
                result=_verified(),
                prediction={"status": "ATTACK", "confidence": 90.0, "source": "ml"},
                explanation={"attack_type_hint": "SYN_FLOOD"},
                fused_decision=None,
                store=None,
            )
            self.assertFalse(out2.extra_evidence.get("fusion_linked"))


class TestR64HistoryAndDashboard(unittest.TestCase):
    def test_history_empty_populated_lookup_stats_malformed_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fused_decisions.jsonl")
            self.assertEqual(read_fused_decision_history(path, limit=10), [])
            stats = fused_decision_history_stats(path)
            self.assertTrue(stats["empty"])

            fused = _fused()
            self.assertTrue(append_fusion_trace(fused, path, extra={"dpid": 1}))
            # malformed line
            with open(path, "a", encoding="utf-8") as fh:
                fh.write("{not-json\n")
                fh.write(json.dumps({"no_fusion_id": True}) + "\n")
            # second valid
            f2 = FusedDecision(
                fusion_id="fuse-r64-2",
                timestamp=_TS,
                decision=DetectionDecision.NORMAL,
                confidence=0.7,
                participating=["ML"],
                disagreement=False,
                reason="normal",
                evidence={"status": "OK", "scores": {}, "decision_rule": "all_primary_normal"},
            )
            append_fusion_trace(f2, path)

            rows = read_fused_decision_history(path, limit=10)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["fusion_id"], "fuse-r64-2")  # newest first
            one = get_fused_decision(path, "fuse-r64-1")
            self.assertIsNotNone(one)
            api = fused_decision_record_for_api(one)
            self.assertEqual(api["decision"], "ATTACK")
            self.assertIn("context", (api.get("context_note") or "").lower())
            self.assertFalse(api["mitigation_authorized"])

            # bounded
            many = read_fused_decision_history(path, limit=1)
            self.assertEqual(len(many), 1)

            st = fused_decision_history_stats(path)
            self.assertEqual(st["total"], 2)
            self.assertIn("ATTACK", st["by_decision"])

    def test_dashboard_routes(self):
        from fastapi.testclient import TestClient

        dash = os.path.join(_ROOT, "dashboard")
        if dash not in sys.path:
            sys.path.insert(0, dash)
        from dashboard import api as dash_api

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fused_decisions.jsonl"
            old = dash_api.FUSED_DECISIONS_JSONL
            dash_api.FUSED_DECISIONS_JSONL = path
            try:
                client = TestClient(dash_api.app)
                empty = client.get("/api/fused-decisions?limit=5")
                self.assertEqual(empty.status_code, 200)
                self.assertEqual(empty.json()["total"], 0)

                append_fusion_trace(_fused(), str(path), extra={"dpid": 1})
                pop = client.get("/api/fused-decisions?limit=5")
                self.assertEqual(pop.status_code, 200)
                body = pop.json()
                self.assertEqual(body["total"], 1)
                self.assertEqual(body["results"][0]["fusion_id"], "fuse-r64-1")

                one = client.get("/api/fused-decisions/fuse-r64-1")
                self.assertEqual(one.status_code, 200)
                self.assertEqual(one.json()["decision"], "ATTACK")

                miss = client.get("/api/fused-decisions/nope")
                self.assertEqual(miss.status_code, 404)

                stats = client.get("/api/fused-decisions/stats")
                self.assertEqual(stats.status_code, 200)
                self.assertEqual(stats.json()["total"], 1)

                # Existing routes unchanged
                self.assertEqual(client.get("/api/correlation-results?limit=1").status_code, 200)
                self.assertEqual(client.get("/api/security-alerts?limit=1").status_code, 200)
                self.assertEqual(client.get("/api/root-cause-reports?limit=1").status_code, 200)
                self.assertEqual(client.get("/api/status").status_code, 200)
            finally:
                dash_api.FUSED_DECISIONS_JSONL = old


if __name__ == "__main__":
    unittest.main()
