"""
Phase 3 — Security Event Investigation UX tests (read-only).
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOC = ROOT / "dashboard" / "static" / "soc"


class SocUiPhase3StaticTests(unittest.TestCase):
    def test_investigation_modules_exist(self):
        self.assertTrue((SOC / "js" / "pages" / "investigation.js").is_file())
        self.assertTrue((SOC / "js" / "api" / "investigation.js").is_file())

    def test_shell_has_events_nav_and_phase3(self):
        html = (SOC / "index.html").read_text(encoding="utf-8")
        self.assertIn("#events", html)
        self.assertRegex(html, r"Phase (?:[3-9]|1[012]) Observer")

    def test_app_supports_investigation_hash(self):
        app = (SOC / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("investigation/", app)
        self.assertIn("parseHash", app)
        self.assertIn("renderInvestigation", app)
        self.assertNotIn('method: "POST"', app)

    def test_explicit_event_id_join_only(self):
        inv = (SOC / "js" / "api" / "investigation.js").read_text(encoding="utf-8")
        self.assertIn("sameEventId", inv)
        self.assertIn("event_id=", inv)
        self.assertNotIn("timestamp difference", inv.lower())
        pages = (SOC / "js" / "pages" / "investigation.js").read_text(encoding="utf-8")
        self.assertIn("buildInvestigationTimeline", pages)
        self.assertIn("View Investigation", (SOC / "js" / "components" / "ui.js").read_text())

    def test_no_fake_xai_weights_or_writes(self):
        banned = [
            re.compile(r"Math\.random\s*\("),
            re.compile(r"method:\s*['\"]POST['\"]"),
            re.compile(r"/api/control/(archive|controller|scenario|scenarios|metrics|bundle|train)"),
        ]
        for path in [
            SOC / "js" / "pages" / "investigation.js",
            SOC / "js" / "api" / "investigation.js",
            SOC / "js" / "app.js",
        ]:
            text = path.read_text(encoding="utf-8")
            for pat in banned:
                self.assertIsNone(pat.search(text), f"{pat.pattern} in {path.name}")
        pages = (SOC / "js" / "pages" / "investigation.js").read_text(encoding="utf-8")
        self.assertIn("contribution weights not exposed", pages)
        self.assertIn("READ ONLY", pages)
        self.assertNotIn("Force Verify", pages)
        self.assertNotIn("Approve", pages)

    def test_timeline_builder_exported_for_logic_checks(self):
        # Ensure missing-stage behavior is coded (empty when no records)
        pages = (SOC / "js" / "pages" / "investigation.js").read_text(encoding="utf-8")
        self.assertIn("Empty timeline", pages)
        self.assertIn("Time unavailable", pages)
        self.assertIn("ADVISORY", pages)


class SocUiPhase3ApiJoinTests(unittest.TestCase):
    """Backend GET-by-event surfaces used by investigation."""

    @classmethod
    def setUpClass(cls):
        try:
            from fastapi.testclient import TestClient
        except Exception as exc:  # pragma: no cover
            raise unittest.SkipTest(str(exc)) from exc
        dash = str(ROOT / "dashboard")
        if dash not in sys.path:
            sys.path.insert(0, dash)
        import dashboard.api as api_mod

        cls.api_mod = api_mod
        cls.TestClient = TestClient

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.logs = Path(self._tmp.name)
        self.patches = [
            mock.patch.object(self.api_mod, "_LOGS", self.logs),
            mock.patch.object(self.api_mod, "VERIFICATION_TRACE_JSONL", self.logs / "verification_trace.jsonl"),
            mock.patch.object(self.api_mod, "CORR_RESULTS_JSONL", self.logs / "correlation_results.jsonl"),
            mock.patch.object(self.api_mod, "FUSED_DECISIONS_JSONL", self.logs / "fused_decisions.jsonl"),
            mock.patch.object(self.api_mod, "RCA_REPORTS_JSONL", self.logs / "root_cause_reports.jsonl"),
            mock.patch.object(self.api_mod, "SECURITY_ALERTS_JSONL", self.logs / "alerts.jsonl"),
            mock.patch.object(self.api_mod, "FLOW_CSV", self.logs / "flow_stats.csv"),
            mock.patch.object(self.api_mod, "ENTROPY_CSV", self.logs / "entropy_logs.csv"),
            mock.patch.object(self.api_mod, "ALERTS_CSV", self.logs / "detection_alerts.csv"),
            mock.patch.object(self.api_mod, "MITIGATION_CSV", self.logs / "mitigation_actions.csv"),
            mock.patch.object(self.api_mod, "RL_CSV", self.logs / "rl_decisions.csv"),
            mock.patch.object(self.api_mod, "DRIFT_CSV", self.logs / "drift_alerts.csv"),
            mock.patch.object(self.api_mod, "ML_PRED_CSV", self.logs / "ml_predictions.csv"),
            mock.patch.object(self.api_mod, "PORT_STATS_CSV", self.logs / "port_stats.csv"),
            mock.patch.object(self.api_mod, "MIT_SUMMARY", self.logs / "mitigation_summary.json"),
            mock.patch.object(self.api_mod, "CLUSTER_SUMMARY", self.logs / "cluster_summary.json"),
            mock.patch.object(self.api_mod, "PPO_WEIGHTS", self.logs / "ppo_weights.pkl"),
        ]
        for p in self.patches:
            p.start()
        self.client = self.TestClient(self.api_mod.app)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self._tmp.cleanup()

    def _write_jsonl(self, name: str, rows: list):
        path = self.logs / name
        with open(path, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row) + "\n")

    def test_verification_filter_by_event_id(self):
        self._write_jsonl(
            "verification_trace.jsonl",
            [
                {
                    "verification_id": "v1",
                    "event_id": "evt-A",
                    "status": "VERIFIED",
                    "timestamp": "2026-01-01T00:00:01Z",
                    "stages": [{"stage_name": "WARMUP", "passed": True, "reason": "ok"}],
                },
                {
                    "verification_id": "v2",
                    "event_id": "evt-B",
                    "status": "INELIGIBLE",
                    "timestamp": "2026-01-01T00:00:02Z",
                    "stages": [],
                },
            ],
        )
        res = self.client.get("/api/verification-traces?event_id=evt-A")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["traces"][0]["event_id"], "evt-A")

    def test_rca_by_event_empty_and_unknown(self):
        # empty file / missing → 404 or empty depending on implementation
        res = self.client.get("/api/root-cause-reports/by-event/missing-event")
        self.assertIn(res.status_code, (404, 200))

    def test_shell_serves_investigation_assets(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertRegex(res.text, r"Phase (?:[3-9]|1[012]) Observer")
        self.assertIn("#events", res.text)
        js = self.client.get("/soc/js/pages/investigation.js")
        self.assertEqual(js.status_code, 200)
        self.assertIn("renderInvestigation", js.text)
        api = self.client.get("/soc/js/api/investigation.js")
        self.assertEqual(api.status_code, 200)
        self.assertIn("fetchInvestigationBundle", api.text)

    def test_partial_event_endpoints_independent(self):
        """R7 present, R4 empty — both GETs succeed independently."""
        self._write_jsonl(
            "verification_trace.jsonl",
            [
                {
                    "verification_id": "v1",
                    "event_id": "evt-partial",
                    "status": "VERIFIED",
                    "timestamp": "2026-01-01T00:00:01Z",
                    "stages": [],
                }
            ],
        )
        v = self.client.get("/api/verification-traces?event_id=evt-partial")
        c = self.client.get("/api/correlation-results?event_id=evt-partial&limit=5")
        self.assertEqual(v.status_code, 200)
        self.assertEqual(c.status_code, 200)
        self.assertEqual(v.json()["total"], 1)
        self.assertEqual(c.json()["total"], 0)


if __name__ == "__main__":
    unittest.main()
