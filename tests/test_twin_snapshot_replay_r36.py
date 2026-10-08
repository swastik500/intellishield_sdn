"""R3.6 — Observational snapshot, replay, what-if, log evidence, safety."""

from __future__ import annotations

import ast
import csv
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from shared_contracts.enums import ValidationStatus
from shared_contracts.models import ModelCandidate, ModelVersion
from shared_contracts.timeutil import utc_now
from twin.bounds import MAX_SNAPSHOT_CSV_ROWS
from twin.evidence_from_logs import evidence_metrics_from_logs
from twin.experiment_runner import TwinExperimentRunner
from twin.history import (
    read_twin_replays,
    read_twin_simulations,
    read_twin_snapshots,
    twin_history_stats,
)
from twin.pipeline import ingest_experiment
from twin.replay import replay_scenario
from twin.snapshot import FORBIDDEN_IMPORTS, capture_snapshot
from twin.validate import TwinValidationError
from twin.whatif import simulate_whatif


def _write_csv(path: Path, headers: list, rows: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(headers)
        w.writerows(rows)


def _mini_experiment(root: Path) -> Path:
    logs = root / "exp"
    logs.mkdir()
    fmt = "%Y-%m-%d %H:%M:%S"
    base = datetime(2026, 7, 28, 22, 42, 16)
    scen_rows = [
        [(base - timedelta(seconds=70)).strftime(fmt), "SCENARIO_1_NORMAL_ONLY", "START", "s1", "OK"],
        [(base - timedelta(seconds=10)).strftime(fmt), "SCENARIO_1_NORMAL_ONLY", "END", "s1end", "OK"],
        [(base + timedelta(seconds=0)).strftime(fmt), "SCENARIO_2_SYN_FLOOD", "START", "start", "OK"],
        [(base + timedelta(seconds=0)).strftime(fmt), "SCENARIO_2_SYN_FLOOD", "PHASE_A", "baseline", "OK"],
        [(base + timedelta(seconds=20)).strftime(fmt), "SCENARIO_2_SYN_FLOOD", "ATTACK_START", "syn", "OK"],
        [(base + timedelta(seconds=50)).strftime(fmt), "SCENARIO_2_SYN_FLOOD", "ATTACK_STOP", "stop", "OK"],
        [(base + timedelta(seconds=60)).strftime(fmt), "SCENARIO_2_SYN_FLOOD", "END", "end", "OK"],
    ]
    _write_csv(
        logs / "scenario_logs.csv",
        ["timestamp", "scenario_name", "event_type", "description", "status"],
        scen_rows,
    )
    flow = []
    for i in range(0, 61, 5):
        ts = (base + timedelta(seconds=i)).strftime(fmt)
        rate = 50 if i < 20 else 800
        flow.append([ts, "1", "00:00:00:00:00:01", "00:00:00:00:00:02", 1, 1, 100, 1000, rate, 8000, 5])
    _write_csv(
        logs / "flow_stats.csv",
        [
            "timestamp", "switch_id", "src_mac", "dst_mac", "in_port", "priority",
            "packet_count", "byte_count", "packet_rate", "byte_rate", "duration_sec",
        ],
        flow,
    )
    ml = []
    for i in range(0, 61, 5):
        ts = (base + timedelta(seconds=i)).strftime(fmt)
        status = "NORMAL" if i < 20 else "ATTACK"
        ml.append([ts, "1", status, 90, 0.1, 1, 0.9, "SYN_FLOOD", 0.2, 0.2, 0.3, 10, 4])
    _write_csv(
        logs / "ml_predictions.csv",
        [
            "timestamp", "switch_id", "status", "confidence", "iso_score",
            "dt_label", "dt_confidence", "attack_type_hint", "src_entropy",
            "dst_entropy", "entropy_score", "packet_rate_mean", "flow_count",
        ],
        ml,
    )
    _write_csv(
        logs / "mitigation_actions.csv",
        [
            "timestamp", "action", "dpid", "src_mac", "dst_mac", "block_type",
            "attack_hint", "confidence", "timeout_sec", "status", "reason",
        ],
        [
            [
                (base + timedelta(seconds=28)).strftime(fmt),
                "BLOCK", 1, "00:00:00:00:00:01", "00:00:00:00:00:02",
                "FLOW_PAIR", "SYN_FLOOD", 100.0, 120, "SUCCESS", "",
            ]
        ],
    )
    report = {
        "summary": {"classification": {}},
        "runs": [
            {
                "scenario": "SCENARIO_1_NORMAL_ONLY",
                "detection_latency_s": 0.0,
                "mitigation_latency_s": None,
                "false_positive_blocks": 0,
                "classification": {
                    "precision": 0.95,
                    "recall": 0.90,
                    "f1_score": 0.92,
                    "false_positive_rate": 0.04,
                    "false_negative_rate": 0.10,
                    "accuracy": 0.93,
                    "tp": 0,
                    "fp": 1,
                    "tn": 20,
                    "fn": 0,
                    "samples": 21,
                },
            },
            {
                "scenario": "SCENARIO_2_SYN_FLOOD",
                "detection_latency_s": 4.0,
                "mitigation_latency_s": 8.0,
                "false_positive_blocks": 0,
                "classification": {
                    "precision": 0.91,
                    "recall": 0.88,
                    "f1_score": 0.89,
                    "false_positive_rate": 0.05,
                    "false_negative_rate": 0.12,
                    "accuracy": 0.9,
                    "tp": 10,
                    "fp": 1,
                    "tn": 8,
                    "fn": 1,
                    "samples": 20,
                },
            }
        ],
    }
    (logs / "metrics_report.json").write_text(json.dumps(report), encoding="utf-8")
    (logs / "fused_decisions.jsonl").write_text(
        json.dumps({"decision": "ATTACK"}) + "\n", encoding="utf-8"
    )
    return logs


def _candidate(root: Path) -> ModelCandidate:
    art = root / "cand.pkl"
    art.write_bytes(b"twin-r36")
    return ModelCandidate(
        candidate_id="r36-cand",
        model=ModelVersion(
            model_id="ml-if-dt",
            version="r36",
            algorithm="IsolationForest+DecisionTree",
            created_at=utc_now(),
            artifact_uri=str(art),
        ),
    )


class TestSnapshotIngestionR36(unittest.TestCase):
    def test_missing_logs_dir(self):
        with self.assertRaises(TwinValidationError):
            capture_snapshot("/no/such/twin-exp-dir", persist=False)

    def test_empty_dir_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "empty"
            src.mkdir()
            snap = capture_snapshot(src, root=tmp, persist=True)
            self.assertEqual(snap["control"], "READ_ONLY")
            self.assertFalse(snap["mutates_mitigation"])
            self.assertFalse(snap["launches_mininet"])
            self.assertEqual(snap["windows"], [])
            self.assertTrue((Path(tmp) / "logs" / "twin" / "snapshots" / snap["snapshot_id"] / "twin_observation.json").is_file())

    def test_malformed_csv_tolerated(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "bad"
            src.mkdir()
            (src / "flow_stats.csv").write_text("not,a,valid\n{{{", encoding="utf-8")
            snap = capture_snapshot(src, root=tmp, persist=False)
            self.assertIsInstance(snap["csv_counts"]["flow_stats.csv"], int)

    def test_ingest_mini_experiment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = _mini_experiment(root)
            snap = capture_snapshot(logs, root=root, persist=True)
            self.assertGreaterEqual(snap["csv_counts"]["scenario_logs.csv"], 5)
            self.assertTrue(any(w.get("scenario_id") == "S2" for w in snap["windows"]))
            bva = snap["baseline_vs_attack"]
            self.assertIsNotNone(bva.get("attack_mean_pkt_s"))
            self.assertGreater(bva["attack_mean_pkt_s"], bva.get("baseline_mean_pkt_s") or 0)


class TestReplayR36(unittest.TestCase):
    def test_replay_matches_s2_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = _mini_experiment(root)
            snap = capture_snapshot(logs, root=root, persist=True)
            replay = replay_scenario(snap, "S2", seed=42, persist=True, root=root)
            self.assertIn("ATTACK_START", replay["matched_events"])
            self.assertIn("ATTACK_STOP", replay["matched_events"])
            self.assertTrue(replay["sequence_ok"])
            self.assertFalse(replay["mutates_mitigation"])
            self.assertAlmostEqual(replay["observed_attack_duration_sec"], 30.0)

    def test_replay_unknown_scenario(self):
        with self.assertRaises(TwinValidationError):
            replay_scenario({"scenario_events": []}, "S99", persist=False)


class TestWhatIfR36(unittest.TestCase):
    def test_duration_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = _mini_experiment(root)
            snap = capture_snapshot(logs, root=root, persist=False)
            sim = simulate_whatif(
                snap, "S2", overrides={"attack_sec": 25}, seed=42, persist=True, root=root
            )
            self.assertEqual(sim["duration_delta_sec"], -5)
            self.assertIn("attack_sec", sim["parameter_delta"])
            self.assertFalse(sim["launches_mininet"])


class TestEvidenceAndGateR36(unittest.TestCase):
    def test_metrics_from_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            logs = _mini_experiment(Path(tmp))
            packed = evidence_metrics_from_logs(logs, "S2")
            self.assertEqual(packed["metrics"]["f1_score"], 0.89)
            self.assertEqual(packed["metrics"]["evidence_origin"], "metrics_report.json")
            self.assertEqual(packed["metrics"]["false_mitigations"], 0)

    def test_ingest_logs_does_not_touch_production(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = _mini_experiment(root)
            prod = root / "logs" / "models"
            prod.mkdir(parents=True)
            marker = prod / "isolation_forest.pkl"
            marker.write_bytes(b"prod")
            before = marker.stat().st_mtime_ns
            runner = TwinExperimentRunner(mode="offline", root=root)
            result = runner.ingest_experiment_logs(
                logs, candidate=_candidate(root), scenario_ids=["S1", "S2"], seed=42
            )
            self.assertEqual(result.status, ValidationStatus.PASS)
            self.assertEqual(marker.stat().st_mtime_ns, before)
            self.assertEqual(result.metrics.get("evidence_source"), ["experiment_logs"])

    def test_pipeline_ingest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = _mini_experiment(root)
            out = ingest_experiment(
                logs, scenario_id="S2", seed=42, root=root, persist=True, validate=False
            )
            self.assertEqual(out["control"], "READ_ONLY")
            self.assertFalse(out["mutates_mitigation"])
            self.assertIn("snapshot_ms", out["performance"])
            self.assertTrue(out["replay"]["sequence_ok"])
            stats = twin_history_stats(str(root / "logs"))
            self.assertGreaterEqual(stats["snapshots"], 1)
            self.assertGreaterEqual(stats["replays"], 1)
            self.assertGreaterEqual(stats["simulations"], 1)
            self.assertEqual(stats["control"], "READ_ONLY")


class TestSafetyBoundaryR36(unittest.TestCase):
    def test_source_forbids_mitigation_imports(self):
        for rel in (
            "twin/snapshot.py",
            "twin/replay.py",
            "twin/whatif.py",
            "twin/pipeline.py",
            "twin/evidence_from_logs.py",
        ):
            tree = ast.parse(Path(_ROOT, rel).read_text(encoding="utf-8"))
            mods = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods.extend(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    mods.append(node.module)
            joined = " ".join(mods)
            self.assertNotIn("mitigation", joined, rel)
            self.assertNotIn("flow_monitor", joined, rel)
            self.assertNotIn("traffic_scheduler", joined, rel)
        self.assertIn("mitigation.mitigation_engine", FORBIDDEN_IMPORTS)

    def test_no_mitigation_callable(self):
        import twin.snapshot as snap

        self.assertFalse(hasattr(snap, "handle_alert"))
        self.assertFalse(hasattr(snap, "install_drop_flow"))

    def test_live_mininet_still_fail_closed_without_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = TwinExperimentRunner(mode="live_mininet", root=root)
            result = runner.validate_candidate(_candidate(root))
            self.assertEqual(result.status, ValidationStatus.ERROR)
            self.assertIn("LIVE_MININET_NOT_RUN", result.reason)


class TestBoundsAndApiR36(unittest.TestCase):
    def test_csv_bound_constant(self):
        self.assertGreaterEqual(MAX_SNAPSHOT_CSV_ROWS, 100)

    def test_history_skips_malformed_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "logs"
            bad = logs / "twin" / "snapshots" / "x"
            bad.mkdir(parents=True)
            (bad / "twin_snapshot.json").write_text("{nope", encoding="utf-8")
            self.assertEqual(read_twin_snapshots(str(logs)), [])
            self.assertEqual(read_twin_replays(str(logs)), [])
            self.assertEqual(read_twin_simulations(str(logs)), [])

    def test_api_snapshots_readonly(self):
        try:
            from fastapi.testclient import TestClient
        except Exception:
            self.skipTest("TestClient unavailable")
        dash_dir = os.path.join(_ROOT, "dashboard")
        if dash_dir not in sys.path:
            sys.path.insert(0, dash_dir)
        import api as api_mod

        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "logs"
            logs.mkdir()
            api_mod.TWIN_LOGS_DIR = logs
            client = TestClient(api_mod.app)
            r = client.get("/api/digital-twin/snapshots")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["control"], "READ_ONLY")
            self.assertEqual(r.json()["count"], 0)
            self.assertEqual(client.post("/api/digital-twin/snapshots").status_code, 405)
            self.assertEqual(client.post("/api/digital-twin/replays").status_code, 405)
            self.assertIn(
                client.post("/api/digital-twin/exec", json={"cmd": "rm"}).status_code,
                (404, 405, 422),
            )


class TestReproducibilityR36(unittest.TestCase):
    def test_same_seed_same_whatif_id(self):
        snap = {"snapshot_id": "fixed", "windows": [], "baseline_vs_attack": {}}
        a = simulate_whatif(snap, "S2", overrides={"attack_sec": 25}, seed=7, persist=False)
        b = simulate_whatif(snap, "S2", overrides={"attack_sec": 25}, seed=7, persist=False)
        self.assertEqual(a["simulation_id"], b["simulation_id"])


class TestLiveVmOptionalR36(unittest.TestCase):
    def test_ingest_existing_lab_logs_if_present(self):
        live = Path(_ROOT) / "logs" / "live_vm_20260728T170330Z" / "logs" / "live_runs" / "slim_20260728T170330Z"
        if not (live / "scenario_logs.csv").is_file():
            self.skipTest("live_vm slim logs not present")
        with tempfile.TemporaryDirectory() as tmp:
            out = ingest_experiment(
                live, scenario_id="S2", seed=42, root=tmp, persist=True, validate=False
            )
            self.assertGreaterEqual(len(out["snapshot"]["windows"]), 1)
            self.assertIn("ATTACK_START", out["replay"]["observed_events"] or out["replay"]["matched_events"])


if __name__ == "__main__":
    unittest.main()
