#!/usr/bin/env python3
"""R4.4 — Correlation evidence for RCA / R8 / dashboard."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import Severity, VerificationStatus
from shared_contracts.models import CorrelationResult, VerificationResult, new_id
from shared_contracts.serialize import to_dict
from correlation.persistence import (
    JsonlCorrelationStore,
    correlation_record_for_api,
    get_correlation_result,
    read_correlation_history,
)
from rca.context import RCAContext
from rca.engine import RootCauseEngine
from rca.correlation_evidence import correlation_alert_refs
from alerting import AlertManager, AlertingConfig, MemoryAlertStore, MemoryNotificationAdapter
from alerting.runtime import build_runtime_alert_context, safe_emit_verification_alert
from alerting.persistence import alert_record_for_api


def _ts():
    return datetime(2026, 7, 26, 12, 0, 0, tzinfo=timezone.utc)


def _corr(**kwargs):
    base = dict(
        correlation_id="corr-test-1",
        timestamp=_ts(),
        event_id="evt-1",
        score=0.72,
        severity=Severity.HIGH,
        window_start=_ts(),
        window_end=_ts(),
        signal_ids=["s1", "s2", "s3"],
        evidence={
            "status": "CORRELATED",
            "summary": "CORRELATED: categories [DATA_PLANE,DETECTION]",
            "participating_categories": ["DATA_PLANE", "DETECTION"],
            "focal_entity_key": "src:02:aa:aa:aa:aa:01",
            "advisory_only": True,
            "mitigation_authorized": False,
        },
    )
    base.update(kwargs)
    return CorrelationResult(**base)


def _vr():
    return VerificationResult(
        verification_id=new_id(),
        event_id="evt-1",
        timestamp=_ts(),
        status=VerificationStatus.VERIFIED,
        mitigation_eligible=True,
        attacker_mac="02:aa:aa:aa:aa:01",
        victim_mac="02:bb:bb:bb:bb:02",
        reason="ok",
    )


class TestR44RCACorrelation(unittest.TestCase):
    def test_rca_with_correlation_observed_inferred(self):
        report = RootCauseEngine().analyze(
            RCAContext(event_id="evt-1", verification=_vr(), correlation=_corr())
        )
        items = (report.contributing_features or {}).get("evidence_items") or []
        kinds = {i["key"]: i["kind"] for i in items if isinstance(i, dict)}
        self.assertEqual(kinds.get("correlation_cooccurrence"), "OBSERVED")
        self.assertEqual(kinds.get("correlation_score"), "OBSERVED")
        self.assertEqual(kinds.get("correlation_pattern_support"), "INFERRED")
        blob = " ".join(i.get("statement", "") for i in items if isinstance(i, dict))
        self.assertIn("temporally correlated", blob.lower())
        self.assertNotIn("caused the attack", blob.lower())
        self.assertNotIn("Application Layer", blob)
        corr_feat = (report.contributing_features or {}).get("correlation")
        self.assertIsInstance(corr_feat, dict)
        self.assertEqual(corr_feat.get("correlation_id"), "corr-test-1")
        self.assertIn("correlation", report.contributing_signals)

    def test_rca_without_correlation(self):
        report = RootCauseEngine().analyze(
            RCAContext(event_id="evt-1", verification=_vr(), correlation=None)
        )
        items = (report.contributing_features or {}).get("evidence_items") or []
        corr_item = next((i for i in items if i.get("key") == "correlation"), None)
        self.assertIsNotNone(corr_item)
        self.assertEqual(corr_item["kind"], "NOT_AVAILABLE")
        self.assertEqual(
            (report.contributing_features or {}).get("correlation"), "NOT_AVAILABLE"
        )


class TestR44AlertLinkage(unittest.TestCase):
    def test_alert_correlation_refs(self):
        refs = correlation_alert_refs(_corr())
        self.assertTrue(refs["correlation_linked"])
        self.assertEqual(refs["correlation_id"], "corr-test-1")
        self.assertEqual(refs["correlation_score"], 0.72)
        self.assertIn("correlation_summary", refs)

        am = AlertManager(
            config=AlertingConfig(enabled=True, rate_limit_enabled=False),
            adapters=[MemoryNotificationAdapter()],
            store=MemoryAlertStore(),
        )
        ctx = build_runtime_alert_context(
            dpid=1,
            prediction={"status": "ATTACK"},
            explanation={"attack_type_hint": "SYN_FLOOD"},
            detector_path="ml",
            event_id="evt-1",
            correlation_id="corr-test-1",
            extra_evidence=refs,
        )
        res = safe_emit_verification_alert(am, _vr(), ctx)
        self.assertIsNotNone(res)
        alert = res.alert
        self.assertEqual(alert.evidence.get("correlation_id"), "corr-test-1")
        flat = alert_record_for_api(to_dict(alert))
        self.assertEqual(flat["correlation_status"], "linked")


class TestR44HistoryAndDashboard(unittest.TestCase):
    def test_history_empty_malformed_lookup_bounded(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "correlation_results.jsonl")
            self.assertEqual(read_correlation_history(path, limit=10), [])

            store = JsonlCorrelationStore(path)
            store.append(_corr(correlation_id="c-a"))
            store.append(_corr(correlation_id="c-b", score=0.4))
            with open(path, "a", encoding="utf-8") as fh:
                fh.write("{not-json\n")
                fh.write(json.dumps({"no_id": True}) + "\n")

            rows = read_correlation_history(path, limit=10)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["correlation_id"], "c-b")  # newest first

            found = get_correlation_result(path, "c-a")
            self.assertIsNotNone(found)
            self.assertEqual(found["correlation_id"], "c-a")
            self.assertIsNone(get_correlation_result(path, "missing"))

            api = correlation_record_for_api(found)
            self.assertIn("DATA_PLANE", api["participating_categories"])
            self.assertNotIn("Application", str(api))
            self.assertTrue(api["advisory_only"])

            bounded = read_correlation_history(path, limit=1)
            self.assertEqual(len(bounded), 1)

    def test_dashboard_routes_empty_and_populated(self):
        from pathlib import Path
        from fastapi.testclient import TestClient

        dash = os.path.join(_ROOT, "dashboard")
        if dash not in sys.path:
            sys.path.insert(0, dash)
        import api as api_mod

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "correlation_results.jsonl"
            old = api_mod.CORR_RESULTS_JSONL
            old_rca = api_mod.RCA_REPORTS_JSONL
            old_sec = api_mod.SECURITY_ALERTS_JSONL
            api_mod.CORR_RESULTS_JSONL = path
            api_mod.RCA_REPORTS_JSONL = Path(td) / "root_cause_reports.jsonl"
            api_mod.SECURITY_ALERTS_JSONL = Path(td) / "alerts.jsonl"
            try:
                client = TestClient(api_mod.app)
                empty = client.get("/api/correlation-results?limit=5")
                self.assertEqual(empty.status_code, 200)
                self.assertEqual(empty.json()["total"], 0)

                JsonlCorrelationStore(str(path)).append(_corr(correlation_id="dash-1"))
                pop = client.get("/api/correlation-results?limit=5")
                self.assertEqual(pop.status_code, 200)
                body = pop.json()
                self.assertEqual(body["total"], 1)
                self.assertEqual(body["results"][0]["correlation_id"], "dash-1")

                one = client.get("/api/correlation-results/dash-1")
                self.assertEqual(one.status_code, 200)
                self.assertEqual(one.json()["score"], 0.72)

                miss = client.get("/api/correlation-results/nope")
                self.assertEqual(miss.status_code, 404)

                stats = client.get("/api/correlation-results/stats")
                self.assertEqual(stats.status_code, 200)
                self.assertGreaterEqual(stats.json()["total"], 1)

                self.assertEqual(client.get("/api/security-alerts?limit=1").status_code, 200)
                self.assertEqual(client.get("/api/root-cause-reports?limit=1").status_code, 200)
                self.assertEqual(client.get("/api/status").status_code, 200)
            finally:
                api_mod.CORR_RESULTS_JSONL = old
                api_mod.RCA_REPORTS_JSONL = old_rca
                api_mod.SECURITY_ALERTS_JSONL = old_sec


if __name__ == "__main__":
    unittest.main()
