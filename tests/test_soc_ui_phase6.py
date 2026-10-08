"""
Phase 6 — SOC Data Quality, Provenance & Backend Contract Hardening.
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


class SocUiPhase6StaticTests(unittest.TestCase):
    def test_provenance_module_exists(self):
        self.assertTrue((SOC / "js" / "utils" / "provenance.js").is_file())
        text = (SOC / "js" / "utils" / "provenance.js").read_text(encoding="utf-8")
        for state in [
            "LIVE",
            "HISTORICAL",
            "SNAPSHOT",
            "STALE",
            "OFFLINE",
            "NO_DATA",
            "PARTIAL",
            "NOT_AVAILABLE",
            "UNKNOWN",
        ]:
            self.assertIn(state, text)
        for needle in [
            "JOINABLE",
            "NOT_JOINABLE",
            "SERVER FILTERED",
            "CLIENT FILTERED",
            "BOUNDED",
            "buildProvenance",
            "isValidEventId",
            "validateListResponse",
            "normalizeRecord",
            "QUALITY_SUMMARY",
        ]:
            self.assertIn(needle, text)

    def test_ui_provenance_components(self):
        ui = (SOC / "js" / "components" / "ui.js").read_text(encoding="utf-8")
        self.assertIn("provenanceBanner", ui)
        self.assertIn("investigationNav", ui)
        self.assertIn("dataQualitySummary", ui)
        self.assertIn("DATA ERROR", ui)
        self.assertIn("Unable to interpret response", ui)

    def test_reports_use_provenance(self):
        page = (SOC / "js" / "pages" / "reports.js").read_text(encoding="utf-8")
        self.assertIn("provenanceBanner", page)
        self.assertIn("SERVER FILTERED", page)
        self.assertIn("CLIENT FILTERED", page)
        self.assertIn("Showing", page)
        self.assertIn("retrieved", page)
        self.assertIn("FEATURE PRESENCE", page)
        self.assertIn("FEATURE IMPORTANCE", page)
        self.assertNotIn("████", page)
        self.assertIn("dataQualitySummary", page)
        self.assertIn("provenanceBySection", page)

    def test_investigation_link_requires_event_id(self):
        inv = (SOC / "js" / "pages" / "investigation.js").read_text(encoding="utf-8")
        self.assertIn("isValidEventId", inv)
        self.assertIn("Investigation unavailable", inv)
        self.assertIn("Linkability", inv)
        self.assertIn("provenanceBanner", inv)
        self.assertIn("Legacy records do not reliably contain event_id", inv)
        # No synthetic ID creation
        self.assertNotIn("crypto.subtle", inv)
        self.assertNotIn("btoa(", inv)

    def test_health_current_not_historical(self):
        health = (SOC / "js" / "pages" / "health.js").read_text(encoding="utf-8")
        self.assertIn("CURRENT", health)
        self.assertIn("NOT AVAILABLE", health)
        self.assertIn("polling is not treated as history", health)

    def test_phase6_shell_label(self):
        html = (SOC / "index.html").read_text(encoding="utf-8")
        self.assertRegex(html, r"Phase (?:[6-9]|1[012]) Observer")

    def test_get_only_audit(self):
        banned = [
            re.compile(r"Math\.random\s*\("),
            re.compile(r"method:\s*['\"]POST['\"]"),
            re.compile(r"method:\s*['\"]PUT['\"]"),
            re.compile(r"method:\s*['\"]PATCH['\"]"),
            re.compile(r"method:\s*['\"]DELETE['\"]"),
            re.compile(r"/api/control/(archive|controller|scenario|scenarios|metrics|bundle|train)"),
        ]
        for path in [
            SOC / "js" / "utils" / "provenance.js",
            SOC / "js" / "pages" / "reports.js",
            SOC / "js" / "pages" / "investigation.js",
            SOC / "js" / "components" / "ui.js",
        ]:
            text = path.read_text(encoding="utf-8")
            for pat in banned:
                self.assertIsNone(pat.search(text), f"{pat.pattern} in {path.name}")

    def test_no_fake_importance_bars(self):
        for path in SOC.rglob("*.js"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("feature importance 82%", text.lower())
            self.assertIsNone(re.search(r"Math\.random\s*\(", text))


class SocUiPhase6LogicTests(unittest.TestCase):
    def test_event_id_validation_semantics(self):
        """Mirror isValidEventId rules."""
        def valid(v):
            if v is None:
                return False
            s = str(v).strip()
            if not s:
                return False
            if s.upper() in {"N/A", "NA", "UNAVAILABLE", "NULL", "UNDEFINED"}:
                return False
            if s in {"-", "—"}:
                return False
            return True

        self.assertTrue(valid("evt-123"))
        self.assertFalse(valid(None))
        self.assertFalse(valid(""))
        self.assertFalse(valid("N/A"))
        self.assertFalse(valid("UNAVAILABLE"))
        self.assertFalse(valid("null"))
        self.assertFalse(valid("-"))

    def test_retrieved_vs_displayed_not_confused(self):
        retrieved, displayed = 200, 31
        note = f"Showing {displayed} of {retrieved} retrieved"
        self.assertIn("31 of 200", note)
        self.assertNotEqual(retrieved, displayed)

    def test_filter_modes_documented(self):
        util = (SOC / "js" / "utils" / "provenance.js").read_text(encoding="utf-8")
        self.assertIn('SERVER: "SERVER FILTERED"', util)
        self.assertIn('CLIENT: "CLIENT FILTERED"', util)


class SocUiPhase6ApiSmoke(unittest.TestCase):
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

    def test_assets_served(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertRegex(r.text, r"Phase (?:[6-9]|1[012]) Observer")
        js = self.client.get("/soc/js/utils/provenance.js")
        self.assertEqual(js.status_code, 200)
        self.assertIn("buildProvenance", js.text)

    def test_twin_still_snapshot_labeled_in_reports(self):
        js = self.client.get("/soc/js/pages/reports.js")
        self.assertEqual(js.status_code, 200)
        self.assertIn("SNAPSHOT", js.text)
        self.assertIn("OBSERVATIONAL", js.text)


if __name__ == "__main__":
    unittest.main()
