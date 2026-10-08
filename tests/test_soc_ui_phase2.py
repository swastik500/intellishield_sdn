"""
Phase 2 SOC observability — read-only UI checks.

Covers:
- Phase 1 baseline still intact
- Chart.js loaded in shell
- Refresh manager / charts modules present
- No Math.random / write APIs in SOC frontend
- No /api/control write usage from SOC JS
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOC = ROOT / "dashboard" / "static" / "soc"


class SocUiPhase2Tests(unittest.TestCase):
    def test_phase1_assets_still_present(self):
        self.assertTrue((SOC / "index.html").is_file())
        self.assertTrue((ROOT / "dashboard" / "static" / "legacy" / "index.html").is_file())
        self.assertTrue((ROOT / "tests" / "test_soc_ui_phase1.py").is_file())

    def test_chartjs_loaded_and_phase2_label(self):
        html = (SOC / "index.html").read_text(encoding="utf-8")
        self.assertIn("chart.js@4.4.0", html)
        self.assertIn("SOC · Observer", html)
        self.assertNotRegex(html, r"Phase\s+\d+\s+Observer")

    def test_refresh_and_charts_modules_exist(self):
        self.assertTrue((SOC / "js" / "utils" / "refresh.js").is_file())
        self.assertTrue((SOC / "js" / "utils" / "charts.js").is_file())
        refresh = (SOC / "js" / "utils" / "refresh.js").read_text(encoding="utf-8")
        self.assertIn("class RefreshManager", refresh)
        self.assertIn("intervalMs", refresh)
        self.assertRegex(refresh, r"Math\.max\(5000")
        charts = (SOC / "js" / "utils" / "charts.js").read_text(encoding="utf-8")
        self.assertIn("upsertChart", charts)
        self.assertIn("destroyChart", charts)
        self.assertIn("destroyAllCharts", charts)

    def test_app_uses_single_refresh_manager(self):
        app = (SOC / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("RefreshManager", app)
        self.assertEqual(app.count("setInterval"), 0)  # no ad-hoc timers in app
        self.assertIn("refresh.start()", app)
        self.assertNotIn("/api/control/scenario", app)
        self.assertNotIn("method: \"POST\"", app)
        self.assertNotIn("method: 'POST'", app)

    def test_no_fake_metrics_or_writes_in_soc_js(self):
        banned = [
            re.compile(r"Math\.random\s*\("),
            re.compile(r"method:\s*['\"]PUT['\"]"),
            re.compile(r"method:\s*['\"]PATCH['\"]"),
            re.compile(r"method:\s*['\"]DELETE['\"]"),
            re.compile(r"/api/control/(archive|controller|scenario|scenarios|metrics|bundle|train)"),
        ]
        post_pat = re.compile(r"method:\s*['\"]POST['\"]")
        for path in SOC.rglob("*.js"):
            text = path.read_text(encoding="utf-8")
            for pat in banned:
                self.assertIsNone(
                    pat.search(text),
                    f"Banned pattern {pat.pattern} in {path.relative_to(ROOT)}",
                )
            # Phase 8 auth infrastructure may POST to /api/auth/*
            if post_pat.search(text):
                self.assertTrue(
                    "/api/auth/" in text or "/api/operator/commands/" in text,
                    f"Unexpected POST in {path.relative_to(ROOT)}",
                )
                if "/execute" in text:

                    self.assertIn("/api/operator/commands/", text)
                self.assertNotIn("/api/mitigation/", text)

    def test_pages_use_real_endpoints_and_na_threshold(self):
        pages = (SOC / "js" / "pages" / "index.js").read_text(encoding="utf-8")
        self.assertIn("/api/traffic", (SOC / "js" / "api" / "index.js").read_text(encoding="utf-8"))
        self.assertIn("Threshold: N/A", pages)
        self.assertIn("Topology data unavailable", pages)
        self.assertIn("Overall Score: N/A", pages)
        self.assertIn("soft", pages)
        self.assertIn("upsertChart", pages)

    def test_client_exports_stale_window(self):
        client = (SOC / "js" / "api" / "client.js").read_text(encoding="utf-8")
        self.assertIn("STALE_AFTER_MS", client)
        self.assertIn("AbortSignal", client)

    def test_get_only_fetch_in_client(self):
        client = (SOC / "js" / "api" / "client.js").read_text(encoding="utf-8")
        self.assertIn('method: "GET"', client)
        self.assertNotIn('method: "POST"', client)


class SocUiPhase2DashboardApiSmoke(unittest.TestCase):
    """Ensure Phase 2 did not break dashboard GET surfaces."""

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

        cls.client = TestClient(api_mod.app)

    def test_root_still_soc(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("Observer", res.text)
        self.assertIn("chart.js", res.text)

    def test_key_gets(self):
        for path in (
            "/api/status",
            "/api/summary",
            "/api/traffic?n=10",
            "/api/entropy?n=10",
            "/api/alerts?n=5",
            "/api/verification-traces?limit=5",
            "/api/security-alerts?limit=5",
            "/api/correlation-results?limit=5",
            "/api/fused-decisions?limit=5",
        ):
            res = self.client.get(path)
            self.assertEqual(res.status_code, 200, path)

    def test_verification_still_get_only(self):
        self.assertEqual(self.client.post("/api/verification-traces").status_code, 405)


if __name__ == "__main__":
    unittest.main()
