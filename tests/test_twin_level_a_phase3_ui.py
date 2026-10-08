"""Phase 3 UI / API smoke — twin read-only surfaces (no browser)."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


class TestTwinUiReadOnlyPhase3(unittest.TestCase):
    def test_soc_twin_page_has_readonly_banner_and_no_exec_controls(self):
        src = (_ROOT / "dashboard/static/soc/js/pages/index.js").read_text(encoding="utf-8")
        self.assertIn("renderTwin", src)
        self.assertIn("READ ONLY", src)
        self.assertIn("fetchTwinReplays", src)
        self.assertIn("fetchTwinSimulations", src)
        self.assertIn("Snapshots + Fidelity", src)
        for banned in (
            "Start Twin Attack",
            "Launch Mininet",
            "Promote Model",
            "/api/digital-twin/exec",
        ):
            self.assertNotIn(banned, src)

    def test_legacy_dashboard_fetches_replays_and_fidelity(self):
        src = (_ROOT / "dashboard/static/index.html").read_text(encoding="utf-8")
        self.assertIn("loadTwinSnapshotDetail", src)
        self.assertIn("/api/digital-twin/replays", src)
        self.assertIn("twin-fidelity-summary", src)
        self.assertIn("_twinFidLabel", src)
        self.assertNotIn("Start Twin Attack", src)

    def test_api_clients_export_replay_simulation(self):
        src = (_ROOT / "dashboard/static/soc/js/api/index.js").read_text(encoding="utf-8")
        self.assertIn("export function fetchTwinReplays", src)
        self.assertIn("export function fetchTwinSimulations", src)
        self.assertIn("export function fetchTwinSnapshot", src)

    def test_snapshot_detail_includes_fidelity_via_api(self):
        try:
            from fastapi.testclient import TestClient
        except Exception:
            self.skipTest("TestClient unavailable")
        dash_dir = str(_ROOT / "dashboard")
        if dash_dir not in sys.path:
            sys.path.insert(0, dash_dir)
        import api as api_mod

        from twin.pipeline import ingest_experiment

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = _ROOT / "tests" / "fixtures" / "twin_s2_slim"
            out = ingest_experiment(
                fixture, scenario_id="S2", seed=42, root=root, persist=True, validate=False
            )
            api_mod.TWIN_LOGS_DIR = root / "logs"
            client = TestClient(api_mod.app)
            listing = client.get("/api/digital-twin/snapshots?limit=5")
            self.assertEqual(listing.status_code, 200)
            body = listing.json()
            self.assertEqual(body["control"], "READ_ONLY")
            self.assertGreaterEqual(body["count"], 1)
            row = body["snapshots"][0]
            self.assertIn("fidelity", row)
            self.assertIsNotNone(row["fidelity"])
            self.assertIn("overall", row["fidelity"])

            detail = client.get(
                f"/api/digital-twin/snapshots/{out['snapshot_id']}"
            )
            self.assertEqual(detail.status_code, 200)
            d = detail.json()
            self.assertIn("fidelity_report", d)
            self.assertEqual(
                d["fidelity_report"]["schema"], "intellishield.twin.fidelity_report.v1"
            )
            self.assertEqual(client.post("/api/digital-twin/snapshots").status_code, 405)
            self.assertEqual(client.post("/api/digital-twin/replays").status_code, 405)
            self.assertEqual(client.post("/api/digital-twin/simulations").status_code, 405)


if __name__ == "__main__":
    unittest.main()
