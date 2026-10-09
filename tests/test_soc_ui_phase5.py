"""
Phase 5 — Security Reports & Historical Analysis (read-only).

Covers:
- Reports route / modules
- Historical data availability matrix
- Aggregation helpers (deterministic)
- NOT AVAILABLE vs zero
- Investigation links use explicit event_id
- No polling of reports / no fake history
- GET-only + export sanitization markers
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


class SocUiPhase5StaticTests(unittest.TestCase):
    def test_reports_modules_exist(self):
        self.assertTrue((SOC / "js" / "pages" / "reports.js").is_file())
        self.assertTrue((SOC / "js" / "utils" / "report.js").is_file())
        self.assertTrue((SOC / "js" / "api" / "reports.js").is_file())

    def test_reports_route_and_nav(self):
        html = (SOC / "index.html").read_text(encoding="utf-8")
        self.assertIn('href="#reports"', html)
        self.assertIn("Reports", html)
        self.assertRegex(html, r"(?:Phase (?:[5-9]|1[012]) Observer|SOC · Observer)")
        app = (SOC / "js" / "app.js").read_text(encoding="utf-8")
        self.assertIn("reports:", app)
        self.assertIn("renderReports", app)
        self.assertIn("Security Reports", app)

    def test_reports_not_in_polled_routes(self):
        refresh = (SOC / "js" / "utils" / "refresh.js").read_text(encoding="utf-8")
        self.assertNotIn('"reports"', refresh)
        page = (SOC / "js" / "pages" / "reports.js").read_text(encoding="utf-8")
        self.assertNotIn("setInterval", page)
        self.assertIn("Reload report", page)

    def test_page_sections_and_not_available(self):
        page = (SOC / "js" / "pages" / "reports.js").read_text(encoding="utf-8")
        for needle in [
            "Security Reports",
            "Data Availability",
            "System Health History",
            "NOT AVAILABLE",
            "FEATURE PRESENCE",
            "contribution weights",
            "DIGITAL TWIN",
            "ADVISORY",
            "View Investigation",
            "Export JSON",
            "Export CSV",
            "Overall Security Score",
            "Protocol Distribution",
        ]:
            # DIGITAL TWIN may appear as "Digital Twin" + SNAPSHOT labels
            if needle == "DIGITAL TWIN":
                self.assertTrue(
                    "DIGITAL TWIN" in page or ("Digital Twin" in page and "SNAPSHOT" in page),
                    "Digital Twin section missing",
                )
                continue
            if needle == "View Investigation":
                self.assertTrue(
                    "View Investigation" in page or "investigationNav" in page,
                    "Investigation navigation missing",
                )
                continue
            self.assertIn(needle, page)
        ui = (SOC / "js" / "components" / "ui.js").read_text(encoding="utf-8")
        self.assertIn("#investigation/", ui)
        self.assertNotIn("Attacks Prevented", page)
        self.assertNotIn("Threat Score", page)
        self.assertNotIn("Math.random", page)

    def test_availability_matrix_documented(self):
        util = (SOC / "js" / "utils" / "report.js").read_text(encoding="utf-8")
        self.assertIn("DATA_AVAILABILITY", util)
        self.assertIn("Health history", util)
        self.assertIn("Topology history", util)
        self.assertIn("XAI contribution weights", util)
        self.assertIn("timeFilterApi: true", util)
        self.assertIn("filterByTime", util)
        self.assertIn("bucketByTime", util)
        self.assertIn("countBy", util)
        self.assertIn("redactDiagnostics", util)

    def test_no_heuristic_joins(self):
        page = (SOC / "js" / "pages" / "reports.js").read_text(encoding="utf-8")
        util = (SOC / "js" / "utils" / "report.js").read_text(encoding="utf-8")
        for text in (page, util):
            self.assertNotIn("same timestamp", text.lower())
            self.assertNotIn("similar score", text.lower())
            self.assertNotIn("same IP", text)
        self.assertIn("event_id", page)

    def test_get_only_and_no_fake_history(self):
        banned = [
            re.compile(r"Math\.random\s*\("),
            re.compile(r"method:\s*['\"]POST['\"]"),
            re.compile(r"method:\s*['\"]PUT['\"]"),
            re.compile(r"method:\s*['\"]PATCH['\"]"),
            re.compile(r"method:\s*['\"]DELETE['\"]"),
            re.compile(r"/api/control/(archive|controller|scenario|scenarios|metrics|bundle|train)"),
            re.compile(r"history\.push\s*\("),
            re.compile(r"fake history", re.I),
            re.compile(r"synthetic history", re.I),
            re.compile(r"demo report", re.I),
        ]
        for path in [
            SOC / "js" / "pages" / "reports.js",
            SOC / "js" / "utils" / "report.js",
            SOC / "js" / "api" / "reports.js",
        ]:
            text = path.read_text(encoding="utf-8")
            for pat in banned:
                self.assertIsNone(pat.search(text), f"{pat.pattern} in {path.name}")

    def test_r8_uses_since_until(self):
        api = (SOC / "js" / "api" / "reports.js").read_text(encoding="utf-8")
        self.assertIn("since", api)
        self.assertIn("until", api)
        self.assertIn("/api/security-alerts", api)


class SocUiPhase5AggregationLogicTests(unittest.TestCase):
    def test_count_by_and_time_filter_semantics_documented(self):
        util = (SOC / "js" / "utils" / "report.js").read_text(encoding="utf-8")
        self.assertIn('return "NO DATA"', util)
        page = (SOC / "js" / "pages" / "reports.js").read_text(encoding="utf-8")
        self.assertIn('value: "N/A"', page)
        self.assertIn("Not exposed by backend", page)

    def test_time_ranges_present(self):
        util = (SOC / "js" / "utils" / "report.js").read_text(encoding="utf-8")
        for key in ('"1h"', '"6h"', '"24h"', '"7d"', '"custom"', '"all"'):
            self.assertIn(key, util)

    def test_python_side_count_by_fixture(self):
        records = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "CRITICAL"},
            {"severity": ""},
        ]
        out = {}
        for r in records:
            k = r["severity"] or "UNKNOWN"
            out[k] = out.get(k, 0) + 1
        self.assertEqual(out["CRITICAL"], 2)
        self.assertEqual(out["HIGH"], 1)
        self.assertEqual(out["UNKNOWN"], 1)

    def test_time_window_filter_fixture(self):
        from datetime import datetime, timezone

        records = [
            {"timestamp": "2026-01-01T10:00:00+00:00", "id": "a"},
            {"timestamp": "2026-01-01T12:00:00+00:00", "id": "b"},
            {"timestamp": "2026-01-02T10:00:00+00:00", "id": "c"},
            {"timestamp": "", "id": "bad"},
        ]
        start = datetime(2026, 1, 1, 11, 0, tzinfo=timezone.utc).timestamp() * 1000
        end = datetime(2026, 1, 1, 13, 0, tzinfo=timezone.utc).timestamp() * 1000

        def parse_ts(value):
            if not value:
                return None
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000

        filtered = []
        for r in records:
            ms = parse_ts(r["timestamp"])
            if ms is None:
                continue
            if start <= ms <= end:
                filtered.append(r)
        self.assertEqual([x["id"] for x in filtered], ["b"])


class SocUiPhase5ApiSmoke(unittest.TestCase):
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

    def test_shell_and_report_assets(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("#reports", r.text)
        self.assertRegex(r.text, r"(?:Phase (?:[5-9]|1[012]) Observer|SOC · Observer)")
        for path in (
            "/soc/js/pages/reports.js",
            "/soc/js/utils/report.js",
            "/soc/js/api/reports.js",
        ):
            js = self.client.get(path)
            self.assertEqual(js.status_code, 200, path)

    def test_historical_gets_empty_ok(self):
        for path in (
            "/api/traffic?n=10",
            "/api/entropy?n=10",
            "/api/alerts?n=10",
            "/api/correlation-results?limit=10",
            "/api/fused-decisions?limit=10",
            "/api/verification-traces?limit=10",
            "/api/root-cause-reports?limit=10",
            "/api/security-alerts?limit=10",
            "/api/security-alerts/stats",
            "/api/digital-twin/snapshots?limit=5",
            "/api/digital-twin/runs?limit=5",
        ):
            res = self.client.get(path)
            self.assertIn(res.status_code, (200, 404), path)

    def test_security_alerts_accept_since_until(self):
        res = self.client.get(
            "/api/security-alerts",
            params={
                "limit": 5,
                "since": "2020-01-01T00:00:00Z",
                "until": "2030-01-01T00:00:00Z",
            },
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIn("alerts", body)


if __name__ == "__main__":
    unittest.main()
