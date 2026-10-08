#!/usr/bin/env python3
"""R8.4 — alerts.jsonl persistence + dashboard API tests."""

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

from shared_contracts.enums import AlertType, Severity
from shared_contracts.models import AlertEvent, new_id
from shared_contracts.serialize import from_dict, to_dict
from alerting.persistence import (
    JsonlAlertStore,
    alert_history_stats,
    alert_record_for_api,
    default_alerts_jsonl_path,
    read_alert_history,
)


def _alert(**kwargs):
    base = dict(
        alert_id=new_id(),
        timestamp=datetime.now(timezone.utc),
        severity=Severity.CRITICAL,
        alert_type=AlertType.MITIGATION,
        title="Mitigation-eligible attack (SYN_FLOOD)",
        message="verified",
        event_id=new_id(),
        source="verification",
        rca_report_id=None,
        mitigation_status=None,
        evidence={
            "attacker_mac": "02:aa:aa:aa:aa:01",
            "verification_id": new_id(),
            "attack_hint": "SYN_FLOOD",
        },
    )
    base.update(kwargs)
    return AlertEvent(**base)


class TestJsonlPersistence(unittest.TestCase):
    def test_append_and_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = default_alerts_jsonl_path(tmp)
            store = JsonlAlertStore(path)
            a = _alert()
            self.assertTrue(store.append(a))
            rows = read_alert_history(path, limit=10)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["alert_id"], a.alert_id)
            self.assertEqual(rows[0]["schema_version"], a.schema_version)
            restored = from_dict(rows[0], AlertEvent)
            self.assertEqual(restored.alert_id, a.alert_id)
            self.assertIsNone(restored.rca_report_id)

    def test_write_failure_nonfatal(self):
        with tempfile.NamedTemporaryFile() as blocker:
            bad = os.path.join(blocker.name, "alerts.jsonl")
            store = JsonlAlertStore(bad)
            self.assertFalse(store.append(_alert()))

    def test_missing_directory_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "nested", "alerts.jsonl")
            self.assertTrue(JsonlAlertStore(path).append(_alert()))
            self.assertTrue(os.path.isfile(path))

    def test_malformed_history_line_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = default_alerts_jsonl_path(tmp)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("not-json\n")
                fh.write("{}\n")
                fh.write(json.dumps(to_dict(_alert())) + "\n")
            rows = read_alert_history(path, limit=10)
            self.assertEqual(len(rows), 1)

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = default_alerts_jsonl_path(tmp)
            open(path, "w").close()
            self.assertEqual(read_alert_history(path, limit=5), [])
            stats = alert_history_stats(path)
            self.assertTrue(stats["empty"])
            self.assertEqual(stats["total"], 0)

    def test_bounded_history_and_filters(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = default_alerts_jsonl_path(tmp)
            store = JsonlAlertStore(path)
            store.append(_alert(severity=Severity.LOW, alert_type=AlertType.SYSTEM))
            store.append(
                _alert(severity=Severity.CRITICAL, alert_type=AlertType.MITIGATION)
            )
            all_rows = read_alert_history(path, limit=1)
            self.assertEqual(len(all_rows), 1)
            self.assertEqual(all_rows[0]["severity"], "CRITICAL")
            crit = read_alert_history(path, limit=10, severity="CRITICAL")
            self.assertEqual(len(crit), 1)
            mit = read_alert_history(path, limit=10, alert_type="MITIGATION")
            self.assertEqual(len(mit), 1)

    def test_stats(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = default_alerts_jsonl_path(tmp)
            store = JsonlAlertStore(path)
            store.append(_alert())
            store.append(_alert(severity=Severity.HIGH))
            stats = alert_history_stats(path)
            self.assertEqual(stats["total"], 2)
            self.assertIn("CRITICAL", stats["by_severity"])

    def test_rca_absent_and_future_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = default_alerts_jsonl_path(tmp)
            store = JsonlAlertStore(path)
            store.append(_alert(rca_report_id=None))
            store.append(_alert(rca_report_id="rca-future-1"))
            rows = read_alert_history(path, limit=10)
            api0 = alert_record_for_api(rows[0])  # newest first
            api1 = alert_record_for_api(rows[1])
            # newest has rca
            self.assertEqual(api0["rca_status"], "linked")
            self.assertEqual(api0["rca_report_id"], "rca-future-1")
            self.assertEqual(api1["rca_status"], "absent")
            self.assertIsNone(api1["rca_report_id"])


class TestDashboardSecurityAlertsAPI(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient

        dash_dir = os.path.join(_ROOT, "dashboard")
        if dash_dir not in sys.path:
            sys.path.insert(0, dash_dir)
        import api as api_mod  # dashboard/api.py when dashboard is on path

        self.api_mod = api_mod
        self._orig = api_mod.SECURITY_ALERTS_JSONL
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "alerts.jsonl"
        api_mod.SECURITY_ALERTS_JSONL = self.path
        self.client = TestClient(api_mod.app)

    def tearDown(self):
        self.api_mod.SECURITY_ALERTS_JSONL = self._orig
        self.tmp.cleanup()

    def test_api_empty_state(self):
        res = self.client.get("/api/security-alerts")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["alerts"], [])
        self.assertEqual(body["total"], 0)

    def test_api_populated_and_filters(self):
        store = JsonlAlertStore(str(self.path))
        store.append(_alert(severity=Severity.CRITICAL))
        store.append(_alert(severity=Severity.LOW, alert_type=AlertType.SYSTEM))
        res = self.client.get("/api/security-alerts?limit=10&severity=CRITICAL")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["alerts"][0]["severity"], "CRITICAL")
        self.assertEqual(body["alerts"][0]["rca_status"], "absent")

    def test_api_invalid_filters(self):
        res = self.client.get("/api/security-alerts?limit=9999")
        self.assertEqual(res.status_code, 400)
        res2 = self.client.get("/api/security-alerts?severity=")
        self.assertEqual(res2.status_code, 400)

    def test_api_stats(self):
        JsonlAlertStore(str(self.path)).append(_alert())
        res = self.client.get("/api/security-alerts/stats")
        self.assertEqual(res.status_code, 200)
        self.assertGreaterEqual(res.json()["total"], 1)

    def test_legacy_alerts_route_unchanged(self):
        res = self.client.get("/api/alerts?n=5")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIn("alerts", body)
        self.assertIn("total", body)
        # Legacy shape uses status/confidence keys, not rca_status
        if body["alerts"]:
            self.assertIn("confidence", body["alerts"][0])
            self.assertNotIn("rca_status", body["alerts"][0])


if __name__ == "__main__":
    unittest.main()
