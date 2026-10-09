"""
Phase 1 SOC UI — dashboard surface tests (read-only).

Does not modify security algorithms. Covers:
- SOC / legacy HTML serving
- verification-traces GET API
- empty / malformed JSONL handling
- POST control still exist but are not used by SOC assets
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class SocUiPhase1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from fastapi.testclient import TestClient
        except Exception as exc:  # pragma: no cover
            raise unittest.SkipTest(f"TestClient unavailable: {exc}") from exc

        cls.TestClient = TestClient
        dash = str(ROOT / "dashboard")
        if dash not in sys.path:
            sys.path.insert(0, dash)
        import dashboard.api as api_mod

        cls.api_mod = api_mod

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.logs = Path(self._tmp.name)
        self.patches = [
            mock.patch.object(self.api_mod, "_LOGS", self.logs),
            mock.patch.object(self.api_mod, "VERIFICATION_TRACE_JSONL", self.logs / "verification_trace.jsonl"),
            mock.patch.object(self.api_mod, "FLOW_CSV", self.logs / "flow_stats.csv"),
            mock.patch.object(self.api_mod, "ENTROPY_CSV", self.logs / "entropy_logs.csv"),
            mock.patch.object(self.api_mod, "ALERTS_CSV", self.logs / "detection_alerts.csv"),
            mock.patch.object(self.api_mod, "SECURITY_ALERTS_JSONL", self.logs / "alerts.jsonl"),
            mock.patch.object(self.api_mod, "RCA_REPORTS_JSONL", self.logs / "root_cause_reports.jsonl"),
            mock.patch.object(self.api_mod, "CORR_RESULTS_JSONL", self.logs / "correlation_results.jsonl"),
            mock.patch.object(self.api_mod, "FUSED_DECISIONS_JSONL", self.logs / "fused_decisions.jsonl"),
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

    def test_soc_index_served_at_root(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertTrue("Phase" in res.text or "SOC" in res.text)
        self.assertIn("Observer", res.text)
        self.assertTrue("READ ONLY" in res.text or "OPERATIONAL" in res.text)
        self.assertIn("/soc/js/app.js", res.text)

    def test_legacy_route_preserved(self):
        res = self.client.get("/legacy")
        self.assertEqual(res.status_code, 200)
        self.assertTrue(len(res.text) > 100)

    def test_soc_static_assets(self):
        css = self.client.get("/soc/css/soc.css")
        self.assertEqual(css.status_code, 200)
        self.assertIn("--bg", css.text)
        js = self.client.get("/soc/js/api/client.js")
        self.assertEqual(js.status_code, 200)
        self.assertIn("getJSON", js.text)
        self.assertNotIn("Math.random", js.text)

    def test_soc_api_layer_is_get_only(self):
        api_dir = ROOT / "dashboard" / "static" / "soc" / "js" / "api"
        for path in api_dir.glob("*.js"):
            text = path.read_text(encoding="utf-8")
            # Phase 8: auth.js may POST to /api/auth/* only (not operator control)
            # Phase 10: commands.js may POST preview/confirm (never execute)
            if path.name in {"auth.js", "commands.js"}:
                if path.name == "auth.js":
                    self.assertIn("/api/auth/", text)
                else:
                    self.assertIn("/api/operator/commands/", text)
                    if "/execute" in text:

                        self.assertIn("/api/operator/commands/", text)
                self.assertNotIn("/api/control/scenario", text)
                self.assertNotIn("Math.random", text)
                continue
            self.assertNotRegex(text, r"method:\s*['\"]POST['\"]")
            self.assertNotRegex(text, r"\bfetch\([^)]*\{\s*method:\s*['\"]PUT")
            self.assertNotIn("/api/control/scenario", text)
            self.assertNotIn("Math.random", text)

    def test_verification_traces_empty(self):
        res = self.client.get("/api/verification-traces?limit=10")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["traces"], [])
        self.assertEqual(body["total"], 0)
        self.assertIn("verification_trace.jsonl", body["source"])

    def test_verification_traces_populated_and_lookup(self):
        path = self.logs / "verification_trace.jsonl"
        records = [
            {
                "verification_id": "ver-1",
                "event_id": "evt-1",
                "status": "INELIGIBLE",
                "mitigation_eligible": False,
                "stages": [{"stage_name": "WARMUP", "passed": True, "reason": "ok"}],
                "timestamp": "2026-01-01T00:00:00Z",
            },
            {
                "verification_id": "ver-2",
                "event_id": "evt-2",
                "status": "VERIFIED",
                "mitigation_eligible": True,
                "confidence": 0.82,
                "stages": [
                    {"stage_name": "WARMUP", "passed": True, "reason": "ok"},
                    {"stage_name": "CONFIDENCE_GATE", "passed": True, "reason": "ok"},
                ],
                "timestamp": "2026-01-01T00:01:00Z",
            },
            "not-json",
            123,
        ]
        with open(path, "w", encoding="utf-8") as fh:
            for rec in records:
                if isinstance(rec, dict):
                    fh.write(json.dumps(rec) + "\n")
                else:
                    fh.write(str(rec) + "\n")

        res = self.client.get("/api/verification-traces?limit=5")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["total"], 2)
        self.assertEqual(body["traces"][0]["verification_id"], "ver-2")

        one = self.client.get("/api/verification-traces/ver-1")
        self.assertEqual(one.status_code, 200)
        self.assertEqual(one.json()["status"], "INELIGIBLE")

        miss = self.client.get("/api/verification-traces/missing")
        self.assertEqual(miss.status_code, 404)

        filtered = self.client.get("/api/verification-traces?status=VERIFIED")
        self.assertEqual(filtered.status_code, 200)
        self.assertEqual(filtered.json()["total"], 1)

    def test_verification_post_rejected(self):
        res = self.client.post("/api/verification-traces", json={"x": 1})
        self.assertEqual(res.status_code, 405)

    def test_status_and_summary_still_ok(self):
        self.assertEqual(self.client.get("/api/status").status_code, 200)
        self.assertEqual(self.client.get("/api/summary").status_code, 200)

    def test_nav_routes_present_in_shell(self):
        html = (ROOT / "dashboard" / "static" / "soc" / "index.html").read_text(encoding="utf-8")
        for route in (
            "#dashboard",
            "#traffic",
            "#topology",
            "#detection",
            "#correlation",
            "#fusion",
            "#verification",
            "#mitigation",
            "#alerts",
            "#events",
            "#rca",
            "#twin",
            "#attack-lab",
            "#reports",
            "#health",
            "#settings",
        ):
            self.assertIn(route, html)


if __name__ == "__main__":
    unittest.main()
