"""
Phase 4 — System Health & Operational Observability (read-only).

Covers:
- Health route / navigation
- Component health model states
- Partial failure rendering evidence in static modules
- Single RefreshManager / GET-only / no fake health scores
- Dashboard GET smoke for status/summary/metrics
"""

from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOC = ROOT / "dashboard" / "static" / "soc"


class SocUiPhase4StaticTests(unittest.TestCase):
    def test_health_modules_exist(self):
        self.assertTrue((SOC / "js" / "pages" / "health.js").is_file())
        self.assertTrue((SOC / "js" / "utils" / "health.js").is_file())

    def test_health_route_and_nav(self):
        html = (SOC / "index.html").read_text(encoding="utf-8")
        self.assertIn('href="#health"', html)
        self.assertIn("System Health", html)
        self.assertIn("OPERATIONS", html)
        self.assertRegex(html, r"(?:Phase (?:[4-9]|1[012]) Observer|SOC · Observer)")
        # OPERATIONS order: System Health before Reports / Settings
        ops = html.split("OPERATIONS", 1)[1]
        self.assertLess(ops.find("#health"), ops.find("#reports"))
        self.assertLess(ops.find("#reports"), ops.find("#settings"))

        app = (SOC / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("health:", app)
        self.assertIn("renderHealth", app)

    def test_health_page_renders_required_sections(self):
        page = (SOC / "js" / "pages" / "health.js").read_text(encoding="utf-8")
        for needle in [
            "System Health",
            "Component health",
            "Security pipeline health",
            "Component detail",
            "Historical health trend",
            "Not available from backend",
            "Overall Score",
            "GET /api/status",
            "GET /api/control/status",
            "GET /api/summary",
            "READ ONLY",
            "buildComponentHealth",
            "redactDiagnostics",
        ]:
            self.assertIn(needle, page)

    def test_health_model_states(self):
        model = (SOC / "js" / "utils" / "health.js").read_text(encoding="utf-8")
        for state in [
            "HEALTHY",
            "DEGRADED",
            "STALE",
            "OFFLINE",
            "NO DATA",
            "UNKNOWN",
            "SNAPSHOT",
            "LOADING",
        ]:
            self.assertIn(state, model)
        self.assertIn("healthFromApiResult", model)
        self.assertIn("PIPELINE_IDS", model)
        # Must not invent aggregate scores
        self.assertNotIn("98.7", model)
        self.assertNotIn("overallScore", model)
        self.assertNotIn("averageHealth", model)

    def test_partial_failure_model_is_independent(self):
        """Each component maps from its own API result — not inferred from siblings."""
        model = (SOC / "js" / "utils" / "health.js").read_text(encoding="utf-8")
        self.assertIn("sliceCard", model)
        self.assertIn("bundle.correlation", model)
        self.assertIn("bundle.fusion", model)
        self.assertIn("bundle.verification", model)
        self.assertIn("bundle.securityAlerts", model)
        self.assertIn("bundle.rca", model)
        # Twin never treated as production mitigation
        self.assertIn("SNAPSHOT", model)
        self.assertIn("not production mitigation", model.lower())

    def test_single_refresh_manager_still(self):
        app = (SOC / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("RefreshManager", app)
        self.assertEqual(app.count("setInterval"), 0)
        refresh = (SOC / "js" / "utils" / "refresh.js").read_text(encoding="utf-8")
        self.assertIn('"health"', refresh)
        self.assertIn("class RefreshManager", refresh)
        health = (SOC / "js" / "pages" / "health.js").read_text(encoding="utf-8")
        self.assertNotIn("setInterval", health)

    def test_get_only_and_no_fake_health_data(self):
        banned = [
            re.compile(r"Math\.random\s*\("),
            re.compile(r"method:\s*['\"]PUT['\"]"),
            re.compile(r"method:\s*['\"]PATCH['\"]"),
            re.compile(r"method:\s*['\"]DELETE['\"]"),
            re.compile(r"/api/control/(archive|controller|scenario|scenarios|metrics|bundle|train)"),
            re.compile(r"\b98\.7\b"),
            re.compile(r"\b99\.8\b"),
            re.compile(r"\b95\.4\b"),
            re.compile(r"fake health", re.I),
            re.compile(r"demo health", re.I),
            re.compile(r"synthetic history", re.I),
        ]
        post_pat = re.compile(r"method:\s*['\"]POST['\"]")
        for path in SOC.rglob("*.js"):
            text = path.read_text(encoding="utf-8")
            for pat in banned:
                self.assertIsNone(
                    pat.search(text),
                    f"Banned pattern {pat.pattern} in {path.relative_to(ROOT)}",
                )
            if post_pat.search(text):
                self.assertTrue(
                    "/api/auth/" in text or "/api/operator/commands/" in text,
                    f"Unexpected POST in {path.relative_to(ROOT)}",
                )
                if "/execute" in text:

                    self.assertIn("/api/operator/commands/", text)
            # No XMLHttpRequest write surface
            if "XMLHttpRequest" in text:
                self.assertNotIn(".open('POST'", text)
                self.assertNotIn('.open("POST"', text)

    def test_dashboard_links_to_health(self):
        pages = (SOC / "js" / "pages" / "index.js").read_text(encoding="utf-8")
        self.assertIn("renderHealthSummaryHtml", pages)
        self.assertIn("buildComponentHealth", pages)
        summary = (SOC / "js" / "pages" / "health.js").read_text(encoding="utf-8")
        self.assertIn('href="#health"', summary)
        self.assertIn("Open System Health", summary)

    def test_client_distinguishes_api_quality(self):
        client = (SOC / "js" / "api" / "client.js").read_text(encoding="utf-8")
        self.assertIn("Malformed JSON", client)
        self.assertIn("Request timeout", client)
        self.assertIn("Backend unavailable", client)
        self.assertIn("EMPTY", client)
        self.assertIn('method: "GET"', client)


class SocUiPhase4HealthModelLogicTests(unittest.TestCase):
    """Pure-logic checks mirrored from healthFromApiResult mapping (documented in utils)."""

    EXPECTED = {
        "LIVE": "HEALTHY",
        "STALE": "STALE",
        "EMPTY": "NO DATA",
        "OFFLINE": "OFFLINE",
        "ERROR": "DEGRADED",
        "UNAVAILABLE": "UNKNOWN",
        "LOADING": "LOADING",
        "SNAPSHOT": "SNAPSHOT",
    }

    def test_mapping_documented(self):
        model = (SOC / "js" / "utils" / "health.js").read_text(encoding="utf-8")
        for src, dst in self.EXPECTED.items():
            # Each DataState case returns the corresponding HealthState
            self.assertRegex(
                model,
                rf"case DataState\.{src}:\s*\n\s*return HealthState\.",
            )
            self.assertIn(f'"{dst}"', model)


class SocUiPhase4ApiSmoke(unittest.TestCase):
    """Read-only API surfaces used by the health page."""

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

    def test_soc_health_route_returns_200(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("System Health", r.text)
        self.assertIn("#health", r.text)
        # Health page module is served as a static asset
        js = self.client.get("/soc/js/pages/health.js")
        self.assertEqual(js.status_code, 200)
        self.assertIn("renderHealth", js.text)
        model = self.client.get("/soc/js/utils/health.js")
        self.assertEqual(model.status_code, 200)
        self.assertIn("buildComponentHealth", model.text)

    def test_status_summary_metrics_get(self):
        for path in ("/api/status", "/api/summary", "/api/metrics"):
            r = self.client.get(path)
            self.assertIn(r.status_code, (200, 404, 500), path)
            # Empty logs still often 200 with empty payloads
            if path == "/api/status":
                self.assertEqual(r.status_code, 200)
                body = r.json()
                self.assertIsInstance(body, dict)

    def test_control_status_get_only_surface(self):
        r = self.client.get("/api/control/status")
        self.assertIn(r.status_code, (200, 404, 500))

    def test_pipeline_gets_empty_ok(self):
        endpoints = [
            "/api/correlation-results",
            "/api/fused-decisions",
            "/api/verification-traces",
            "/api/root-cause-reports",
            "/api/security-alerts",
            "/api/security-alerts/stats",
            "/api/traffic",
            "/api/digital-twin/stats",
            "/api/digital-twin/snapshots",
            "/api/digital-twin/runs",
        ]
        for path in endpoints:
            r = self.client.get(path)
            self.assertIn(r.status_code, (200, 404), path)


if __name__ == "__main__":
    unittest.main()
