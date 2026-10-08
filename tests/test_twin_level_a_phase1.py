"""Level A Phase 1 — fidelity hardening, snapshot package, ingest contract, history APIs."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from twin.fidelity import (
    FIDELITY_DIMENSIONS,
    TRAFFIC_NA_HINT,
    VALID_FIDELITY_STATUSES,
    build_fidelity_report,
    compact_fidelity_summary,
    observed_from_snapshot,
    overall_verdict,
)
from twin.history import get_twin_snapshot, read_twin_snapshots
from twin.pipeline import LIVE_MININET_NOT_RUN_MSG, ingest_experiment
from twin.planner import plan_scenario
from twin.snapshot import capture_snapshot


def _write_csv(path: Path, header: str, rows: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(header + "\n" + "\n".join(rows) + "\n", encoding="utf-8")


def _mini_logs(root: Path, *, with_flow_attack: bool = False, with_syn_traffic: bool = False) -> Path:
    logs = root / "experiment"
    logs.mkdir(parents=True)
    _write_csv(
        logs / "scenario_logs.csv",
        "timestamp,scenario_name,event_type,description,status",
        [
            "2026-07-28 10:00:00,SCENARIO_2_SYN_FLOOD,START,begin,OK",
            "2026-07-28 10:00:20,SCENARIO_2_SYN_FLOOD,ATTACK_START,syn,OK",
            "2026-07-28 10:00:50,SCENARIO_2_SYN_FLOOD,ATTACK_STOP,done,OK",
            "2026-07-28 10:01:00,SCENARIO_2_SYN_FLOOD,END,end,OK",
        ],
    )
    if with_flow_attack:
        _write_csv(
            logs / "flow_stats.csv",
            "timestamp,packet_rate,byte_rate",
            [
                "2026-07-28 10:00:10,100.0,1000",
                "2026-07-28 10:00:30,10000.0,800000",
                "2026-07-28 10:00:40,9800.0,790000",
            ],
        )
    if with_syn_traffic:
        _write_csv(
            logs / "traffic_logs.csv",
            "timestamp,traffic_type,source_host,destination_host,protocol,packet_rate,bandwidth,duration,status",
            [
                "2026-07-28 10:00:25,SYN_FLOOD,h1,h2,TCP,10000.0,N/A,30,RUNNING",
                "2026-07-28 10:00:35,SYN_FLOOD,h1,h2,TCP,9900.0,N/A,30,RUNNING",
            ],
        )
    else:
        _write_csv(
            logs / "traffic_logs.csv",
            "timestamp,traffic_type,source_host,destination_host,protocol,packet_rate,bandwidth,duration,status",
            [
                "2026-07-28 10:00:05,ICMP_CONTINUOUS,h1,h2,ICMP,2.0,N/A,-1,RUNNING",
            ],
        )
    _write_csv(
        logs / "ml_predictions.csv",
        "timestamp,label,confidence",
        ["2026-07-28 10:00:30,ATTACK,0.9"],
    )
    return logs


class TestFidelityDimensionsPhase1(unittest.TestCase):
    def test_all_dimensions_valid_statuses_and_reason(self):
        report = build_fidelity_report(plan=plan_scenario("S2", seed=3), seed=3, mode="offline")
        self.assertEqual({d["dimension"] for d in report["dimensions"]}, set(FIDELITY_DIMENSIONS))
        self.assertEqual(len(report["dimensions"]), 5)
        for dim in report["dimensions"]:
            self.assertIn(dim["status"], VALID_FIDELITY_STATUSES)
            self.assertTrue(str(dim["notes"]).strip())
            self.assertEqual(dim["reason"], dim["notes"])
        self.assertIn(report["overall"], {"PASS", "FAIL", "NOT_AVAILABLE", "PASS_WITH_GAPS"})
        self.assertIn("LIVE_MININET_NOT_RUN", report["notes"])

    def test_traffic_na_has_explicit_hint(self):
        report = build_fidelity_report(plan=plan_scenario("S2", seed=1), seed=1)
        by_dim = {d["dimension"]: d for d in report["dimensions"]}
        self.assertEqual(by_dim["TRAFFIC_FIDELITY"]["status"], "NOT_AVAILABLE")
        self.assertIn("flow_stats.csv", by_dim["TRAFFIC_FIDELITY"]["notes"])
        self.assertEqual(by_dim["TRAFFIC_FIDELITY"]["notes"], TRAFFIC_NA_HINT)

    def test_overall_verdict_helpers(self):
        self.assertEqual(overall_verdict({"PASS": 5, "FAIL": 0, "NOT_AVAILABLE": 0}), "PASS")
        self.assertEqual(overall_verdict({"PASS": 4, "FAIL": 0, "NOT_AVAILABLE": 1}), "PASS_WITH_GAPS")
        self.assertEqual(overall_verdict({"PASS": 0, "FAIL": 1, "NOT_AVAILABLE": 4}), "FAIL")
        self.assertEqual(overall_verdict({"PASS": 0, "FAIL": 0, "NOT_AVAILABLE": 5}), "NOT_AVAILABLE")

    def test_observed_from_snapshot_prefers_flow_then_traffic(self):
        snap = {
            "baseline_vs_attack": {
                "attack_mean_pkt_s": 10000.0,
                "attack_like_traffic_mean_pkt_s": 500.0,
            },
            "windows": [{"duration_sec": 30}],
        }
        obs = observed_from_snapshot(snap)
        self.assertEqual(obs["syn_rate"], 10000.0)
        self.assertEqual(obs["attack_duration_sec"], 30.0)

        snap2 = {
            "baseline_vs_attack": {
                "attack_mean_pkt_s": None,
                "attack_like_traffic_mean_pkt_s": 9900.0,
            }
        }
        self.assertEqual(observed_from_snapshot(snap2)["syn_rate"], 9900.0)


class TestSnapshotTrafficAndPackagePhase1(unittest.TestCase):
    def test_traffic_logs_counted_and_icmp_not_used_as_attack_rate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = _mini_logs(root, with_syn_traffic=False)
            snap = capture_snapshot(logs, root=root, persist=True)
            self.assertGreaterEqual(snap["csv_counts"].get("traffic_logs.csv", 0), 1)
            bva = snap["baseline_vs_attack"]
            self.assertIsNone(bva.get("attack_like_traffic_mean_pkt_s"))
            self.assertEqual(bva.get("n_attack_like_traffic_rows"), 0)

    def test_syn_traffic_logs_fill_attack_like_rate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = _mini_logs(root, with_syn_traffic=True)
            snap = capture_snapshot(logs, root=root, persist=False)
            self.assertAlmostEqual(
                snap["baseline_vs_attack"]["attack_like_traffic_mean_pkt_s"], 9950.0, delta=1.0
            )


class TestIngestContractAndHistoryPhase1(unittest.TestCase):
    def test_ingest_stable_summary_and_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = _mini_logs(root, with_flow_attack=True)
            out = ingest_experiment(
                logs, scenario_id="S2", seed=42, root=root, persist=True, validate=False
            )
            self.assertEqual(out["schema"], "intellishield.twin.ingest.v1")
            self.assertTrue(out["snapshot_id"])
            self.assertIn("sequence_ok", out)
            self.assertIn("temporal_error_sec", out)
            self.assertIn("fidelity_summary", out)
            self.assertIn("overall", out)
            self.assertFalse(out["mutates_mitigation"])
            self.assertFalse(out["launches_mininet"])
            self.assertIn("LIVE_MININET_NOT_RUN", out["live_mininet_note"])
            self.assertEqual(out["live_mininet_note"], LIVE_MININET_NOT_RUN_MSG)
            self.assertTrue(out["package"]["twin_snapshot.json"])
            self.assertTrue(out["package"]["twin_observation.json"])
            self.assertTrue(out["package"]["fidelity_report.json"])
            # flow attack rates should make traffic fidelity available
            by_dim = {d["dimension"]: d for d in out["fidelity"]["dimensions"]}
            self.assertIn(by_dim["TRAFFIC_FIDELITY"]["status"], {"PASS", "FAIL"})

            rows = read_twin_snapshots(str(root / "logs"))
            self.assertGreaterEqual(len(rows), 1)
            self.assertIsNotNone(rows[0].get("fidelity"))
            self.assertIn("overall", rows[0]["fidelity"])
            self.assertTrue(rows[0]["package"]["fidelity_report.json"])

            detail = get_twin_snapshot(str(root / "logs"), out["snapshot_id"])
            self.assertIsNotNone(detail)
            assert detail is not None
            self.assertIsNotNone(detail.get("fidelity_report"))
            self.assertEqual(
                detail["fidelity_report"]["schema"], "intellishield.twin.fidelity_report.v1"
            )
            self.assertEqual(
                compact_fidelity_summary(detail["fidelity_report"])["overall"],
                detail["fidelity"]["overall"],
            )

    def test_missing_logs_dir_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(Exception):
                ingest_experiment(
                    Path(tmp) / "nope",
                    root=tmp,
                    persist=False,
                    validate=False,
                )

    def test_history_without_fidelity_file_still_lists_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = _mini_logs(root)
            snap = capture_snapshot(logs, root=root, persist=True)
            # intentionally no fidelity_report.json
            rows = read_twin_snapshots(str(root / "logs"))
            self.assertEqual(rows[0]["snapshot_id"], snap["snapshot_id"])
            self.assertIsNone(rows[0]["fidelity"])
            self.assertFalse(rows[0]["package"]["fidelity_report.json"])
            detail = get_twin_snapshot(str(root / "logs"), snap["snapshot_id"])
            self.assertIsNone(detail["fidelity_report"])


if __name__ == "__main__":
    unittest.main()
