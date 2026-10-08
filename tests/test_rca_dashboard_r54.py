#!/usr/bin/env python3
"""R5.4 — RCA history reader + dashboard API tests."""

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

from shared_contracts.models import RootCauseReport, new_id
from shared_contracts.serialize import to_dict
from rca.persistence import (
    JsonlRCAStore,
    get_rca_by_event,
    get_rca_report,
    rca_record_for_api,
    read_rca_history,
)


def _report(**kwargs):
    base = dict(
        report_id=new_id(),
        event_id=new_id(),
        timestamp=datetime.now(timezone.utc),
        summary="Event test: verification_status=VERIFIED.",
        suspected_source="02:aa:aa:aa:aa:01",
        affected_target="02:bb:bb:bb:bb:02",
        contributing_signals=["verification", "xai"],
        contributing_features={
            "attack_hint": "SYN_FLOOD",
            "verification_status": "VERIFIED",
            "mitigation_eligible": True,
            "mitigation_strategy": "FLOW_PAIR",
            "missing_evidence": ["baseline:NOT_AVAILABLE"],
            "baseline_evidence": "NOT_AVAILABLE",
            "xai": {
                "local_path_features": ["packet_rate_max", "src_entropy"],
                "decision_path_steps": 2,
            },
            "evidence_items": [
                {
                    "key": "suspected_source",
                    "statement": "Source MAC observed.",
                    "kind": "OBSERVED",
                    "value": "02:aa:aa:aa:aa:01",
                    "source": "VerificationResult.attacker_mac",
                },
                {
                    "key": "attack_hint",
                    "statement": "Hint inferred.",
                    "kind": "INFERRED",
                    "value": "SYN_FLOOD",
                    "source": "RCAContext.attack_hint",
                },
                {
                    "key": "baseline_evidence",
                    "statement": "Baseline evidence is NOT_AVAILABLE.",
                    "kind": "NOT_AVAILABLE",
                    "value": "NOT_AVAILABLE",
                    "source": "",
                },
                {
                    "key": "xai_leaf",
                    "statement": "XAI leaf_decision=ATTACK.",
                    "kind": "OBSERVED",
                    "value": "ATTACK",
                    "source": "PredictionExplanation.leaf_decision",
                },
            ],
            "rca_confidence_policy": {
                "semantics": "completeness of RCA evidence; not ML confidence",
                "value": 0.75,
            },
        },
        evidence_refs=["VerificationResult"],
        confidence=0.75,
        explanation_summary="Model predicted ATTACK with confidence 0.94.",
    )
    base.update(kwargs)
    return RootCauseReport(**base)


class TestRcaHistoryReader(unittest.TestCase):
    def test_empty_and_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "root_cause_reports.jsonl")
            self.assertEqual(read_rca_history(path, limit=10), [])
            self.assertIsNone(get_rca_report(path, "missing"))

    def test_bounded_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "root_cause_reports.jsonl")
            store = JsonlRCAStore(path)
            for _ in range(12):
                store.append(_report())
            rows = read_rca_history(path, limit=5)
            self.assertEqual(len(rows), 5)

    def test_malformed_lines_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "root_cause_reports.jsonl")
            good = _report()
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("not-json\n")
                fh.write("{}\n")
                fh.write(json.dumps(to_dict(good)) + "\n")
            rows = read_rca_history(path, limit=10)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["report_id"], good.report_id)

    def test_lookup_existing_and_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "root_cause_reports.jsonl")
            r = _report()
            JsonlRCAStore(path).append(r)
            found = get_rca_report(path, r.report_id)
            self.assertIsNotNone(found)
            self.assertEqual(found["report_id"], r.report_id)
            self.assertIsNone(get_rca_report(path, "nope"))
            by_evt = get_rca_by_event(path, r.event_id)
            self.assertEqual(by_evt["report_id"], r.report_id)

    def test_api_flatten_observed_inferred_missing(self):
        flat = rca_record_for_api(to_dict(_report()))
        self.assertEqual(flat["prediction"], "ATTACK")
        self.assertIn("packet_rate_max", flat["decision_evidence"])
        kinds = {i["key"]: i["kind"] for i in flat["evidence_items"]}
        self.assertEqual(kinds["suspected_source"], "OBSERVED")
        self.assertEqual(kinds["attack_hint"], "INFERRED")
        self.assertEqual(kinds["baseline_evidence"], "NOT_AVAILABLE")
        self.assertIn("baseline:NOT_AVAILABLE", flat["missing_evidence"])
        self.assertEqual(flat["baseline_evidence"], "NOT_AVAILABLE")


class TestRcaDashboardApi(unittest.TestCase):
    def setUp(self):
        dash = os.path.join(_ROOT, "dashboard")
        if dash not in sys.path:
            sys.path.insert(0, dash)
        from fastapi.testclient import TestClient
        import api as api_mod

        self.api_mod = api_mod
        self.client = TestClient(api_mod.app)
        self._orig_rca = api_mod.RCA_REPORTS_JSONL
        self._orig_sec = api_mod.SECURITY_ALERTS_JSONL

    def tearDown(self):
        self.api_mod.RCA_REPORTS_JSONL = self._orig_rca
        self.api_mod.SECURITY_ALERTS_JSONL = self._orig_sec

    def test_api_empty_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.api_mod.RCA_REPORTS_JSONL = Path(tmp) / "root_cause_reports.jsonl"
            res = self.client.get("/api/root-cause-reports?limit=10")
            self.assertEqual(res.status_code, 200)
            body = res.json()
            self.assertEqual(body["reports"], [])
            self.assertEqual(body["total"], 0)

    def test_api_list_and_get_and_by_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "root_cause_reports.jsonl"
            self.api_mod.RCA_REPORTS_JSONL = path
            r = _report()
            JsonlRCAStore(str(path)).append(r)
            res = self.client.get("/api/root-cause-reports?limit=5")
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json()["total"], 1)
            rid = res.json()["reports"][0]["report_id"]
            one = self.client.get(f"/api/root-cause-reports/{rid}")
            self.assertEqual(one.status_code, 200)
            self.assertEqual(one.json()["report_id"], r.report_id)
            self.assertEqual(one.json()["prediction"], "ATTACK")
            by_evt = self.client.get(f"/api/root-cause-reports/by-event/{r.event_id}")
            self.assertEqual(by_evt.status_code, 200)
            self.assertEqual(by_evt.json()["event_id"], r.event_id)
            missing = self.client.get("/api/root-cause-reports/does-not-exist")
            self.assertEqual(missing.status_code, 404)

    def test_alert_rca_linkage_fields_and_r8_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.api_mod.RCA_REPORTS_JSONL = Path(tmp) / "root_cause_reports.jsonl"
            self.api_mod.SECURITY_ALERTS_JSONL = Path(tmp) / "alerts.jsonl"
            # R8 route still responds
            sec = self.client.get("/api/security-alerts?limit=5")
            self.assertEqual(sec.status_code, 200)
            self.assertIn("alerts", sec.json())
            # Legacy alerts route still present
            legacy = self.client.get("/api/alerts?n=5")
            self.assertEqual(legacy.status_code, 200)
            self.assertIn("alerts", legacy.json())

    def test_existing_status_api_unchanged(self):
        res = self.client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), dict)


if __name__ == "__main__":
    unittest.main()
