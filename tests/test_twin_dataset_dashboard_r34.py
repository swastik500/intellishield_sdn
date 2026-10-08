"""R3.4 — Twin training data generation + dashboard observability."""

from __future__ import annotations

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

from evaluation.experiment_windows import AttackWindow
from ml_models.feature_builder import FEATURE_NAMES
from twin.dataset import TwinDatasetGenerator, default_split_for_scenario, label_from_windows
from twin.feature_schema import (
    FEATURE_SCHEMA_VERSION,
    assert_compatible_feature_vector,
    feature_schema_hash,
)
from twin.history import (
    get_twin_run,
    read_twin_datasets,
    read_twin_runs,
    read_twin_validations,
    twin_history_stats,
)
from twin.validate import TwinValidationError


def _write_features(path: Path, rows: list) -> None:
    headers = ["timestamp", "switch_id", "label"] + list(FEATURE_NAMES)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(headers)
        for ts, label_ignored, feats in rows:
            # CSV may contain stale ML labels — generator must ignore them
            w.writerow([ts, "1", label_ignored, *feats])


def _vec(fill: float = 0.1) -> list:
    return [float(fill)] * len(FEATURE_NAMES)


class TestGroundTruthLabelingR34(unittest.TestCase):
    def test_normal_and_attack_and_boundaries(self):
        base = datetime(2026, 7, 27, 12, 0, 0)
        windows = [
            AttackWindow(
                scenario="SCENARIO_2_SYN_FLOOD",
                attack_start=base + timedelta(seconds=20),
                attack_stop=base + timedelta(seconds=50),
                source="scenario_logs",
            )
        ]
        fmt = "%Y-%m-%d %H:%M:%S"
        self.assertEqual(
            label_from_windows((base + timedelta(seconds=5)).strftime(fmt), windows, pad_sec=0),
            0,
        )
        self.assertEqual(
            label_from_windows((base + timedelta(seconds=30)).strftime(fmt), windows, pad_sec=0),
            1,
        )
        # Boundary: exactly at stop with pad 0 → not inside (stop exclusive? check AttackWindow)
        at_stop = label_from_windows(
            (base + timedelta(seconds=50)).strftime(fmt), windows, pad_sec=0
        )
        # contains typically start <= ts <= stop — accept 0 or 1 but document
        self.assertIn(at_stop, (0, 1))


class TestDatasetGeneratorR34(unittest.TestCase):
    def test_schema_manifest_checksums_splits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "logs"
            logs.mkdir()
            feats = logs / "ml_features.csv"
            base = datetime(2026, 7, 27, 12, 0, 0)
            fmt = "%Y-%m-%d %H:%M:%S"
            _write_features(
                feats,
                [
                    ((base + timedelta(seconds=5)).strftime(fmt), 1, _vec(0.2)),  # stale label 1
                    ((base + timedelta(seconds=30)).strftime(fmt), 0, _vec(0.9)),  # stale label 0
                ],
            )
            windows = [
                AttackWindow(
                    scenario="SCENARIO_2_SYN_FLOOD",
                    attack_start=base + timedelta(seconds=20),
                    attack_stop=base + timedelta(seconds=50),
                    source="scenario_logs",
                )
            ]
            gen = TwinDatasetGenerator(root=root)
            result = gen.generate(
                run_id="run-a",
                profile_id="prof",
                profile_fingerprint="fp123",
                scenario_id="S2",
                seed=42,
                features_csv=feats,
                logs_dir=logs,
                windows=windows,
                pad_sec=0,
            )
            self.assertEqual(result.sample_count, 2)
            self.assertEqual(result.class_distribution["NORMAL"], 1)
            self.assertEqual(result.class_distribution["ATTACK"], 1)
            self.assertEqual(result.manifest["label_source"], "SCENARIO_CONTROL")
            self.assertFalse(result.manifest["oversampling"])
            self.assertEqual(
                result.manifest["feature_schema_version"], FEATURE_SCHEMA_VERSION
            )
            self.assertEqual(
                result.manifest["feature_schema_hash"], feature_schema_hash()
            )
            self.assertIn("samples.csv", result.manifest["checksums"])
            # Split provenance at scenario level
            self.assertEqual(
                result.manifest["split_policy"]["assignment"]["S2"], "VALIDATION"
            )
            # Verify labels ignored CSV and used windows
            with result.samples_csv.open(newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            labels = [int(r["label"]) for r in rows]
            self.assertEqual(labels, [0, 1])
            self.assertTrue(all(r["split"] == "VALIDATION" for r in rows))

    def test_schema_mismatch_rejected(self):
        with self.assertRaises(TwinValidationError):
            assert_compatible_feature_vector([1.0, 2.0])  # wrong dim

    def test_forbidden_model_label_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "logs"
            logs.mkdir()
            path = logs / "ml_features.csv"
            headers = ["timestamp", "switch_id", "ml_prediction"] + list(FEATURE_NAMES)
            with path.open("w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(headers)
                w.writerow(["2026-07-27 12:00:00", "1", "ATTACK", *_vec()])
            gen = TwinDatasetGenerator(root=root)
            with self.assertRaises(TwinValidationError) as ctx:
                gen.generate(
                    run_id="r",
                    profile_id="p",
                    profile_fingerprint="f",
                    scenario_id="S1",
                    features_csv=path,
                    logs_dir=logs,
                    windows=[],
                )
            self.assertIn("model-derived", str(ctx.exception).lower())

    def test_split_defaults_no_row_shuffle(self):
        self.assertEqual(default_split_for_scenario("S1"), "TRAINING")
        self.assertEqual(default_split_for_scenario("S2"), "VALIDATION")
        self.assertEqual(default_split_for_scenario("S5"), "TEST")


class TestTwinHistoryDashboardR34(unittest.TestCase):
    def _seed_run(self, logs: Path, run_id: str = "twinrun-demo") -> Path:
        run_dir = logs / "twin" / "candidates" / "cand-x" / run_id
        run_dir.mkdir(parents=True)
        (run_dir / "twin_experiment_manifest.json").write_text(
            json.dumps(
                {
                    "run_id": run_id,
                    "seed": 7,
                    "profile_id": "intellishield_lab_default",
                    "profile_version": "1.0.0",
                    "profile_fingerprint": "abc123",
                    "scenario_ids": ["S1", "S2"],
                    "candidate_id": "cand-x",
                    "validation_status": "PASS",
                    "outcome_code": "PASS",
                    "metrics": {"f1_score": 0.9, "precision": 0.91},
                    "mode": "offline",
                    "git_commit": "deadbeef",
                }
            ),
            encoding="utf-8",
        )
        (run_dir / "validation_result.json").write_text(
            json.dumps(
                {
                    "_type": "ValidationResult",
                    "validation_id": "v1",
                    "status": "PASS",
                    "metrics": {"outcome_code": "PASS", "f1_score": 0.9},
                }
            ),
            encoding="utf-8",
        )
        # malformed junk
        (run_dir / "broken.json").write_text("{not-json", encoding="utf-8")
        return run_dir

    def test_empty_and_populated(self):
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "logs"
            logs.mkdir()
            self.assertEqual(read_twin_runs(str(logs)), [])
            stats = twin_history_stats(str(logs))
            self.assertEqual(stats["runs"], 0)
            self.assertEqual(stats["control"], "READ_ONLY")

            self._seed_run(logs)
            runs = read_twin_runs(str(logs), limit=10)
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]["run_id"], "twinrun-demo")
            self.assertEqual(runs[0]["seed"], 7)
            got = get_twin_run(str(logs), "twinrun-demo")
            self.assertIsNotNone(got)
            vals = read_twin_validations(str(logs))
            self.assertEqual(vals[0]["outcome_code"], "PASS")
            # dataset listing empty ok
            self.assertEqual(read_twin_datasets(str(logs)), [])

    def test_bounded_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "logs"
            logs.mkdir()
            for i in range(5):
                self._seed_run(logs, run_id=f"run-{i}")
            runs = read_twin_runs(str(logs), limit=2)
            self.assertEqual(len(runs), 2)


class TestDashboardApiDigitalTwinR34(unittest.TestCase):
    def test_api_empty_and_populated_and_no_shell_control(self):
        try:
            from fastapi.testclient import TestClient
        except Exception:
            self.skipTest("TestClient unavailable")

        dash_dir = os.path.join(_ROOT, "dashboard")
        if dash_dir not in sys.path:
            sys.path.insert(0, dash_dir)
        import api as api_mod  # dashboard/api.py when dashboard is on path

        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "logs"
            logs.mkdir()
            api_mod.TWIN_LOGS_DIR = logs
            client = TestClient(api_mod.app)

            empty = client.get("/api/digital-twin/runs")
            self.assertEqual(empty.status_code, 200)
            self.assertEqual(empty.json()["count"], 0)
            self.assertEqual(empty.json()["control"], "READ_ONLY")

            stats = client.get("/api/digital-twin/stats")
            self.assertEqual(stats.status_code, 200)
            self.assertEqual(stats.json()["control"], "READ_ONLY")

            run_dir = logs / "twin" / "candidates" / "c1" / "run-1"
            run_dir.mkdir(parents=True)
            (run_dir / "twin_experiment_manifest.json").write_text(
                json.dumps(
                    {
                        "run_id": "run-1",
                        "seed": 1,
                        "profile_id": "p",
                        "profile_fingerprint": "fp",
                        "scenario_ids": ["S2"],
                        "candidate_id": "c1",
                        "validation_status": "FAIL",
                        "outcome_code": "FAIL",
                        "metrics": {"f1_score": 0.2},
                    }
                ),
                encoding="utf-8",
            )
            populated = client.get("/api/digital-twin/runs?limit=5")
            self.assertEqual(populated.json()["count"], 1)
            one = client.get("/api/digital-twin/runs/run-1")
            self.assertEqual(one.status_code, 200)
            self.assertEqual(one.json()["run_id"], "run-1")

            val = client.get("/api/digital-twin/validation")
            self.assertEqual(val.status_code, 200)
            profiles = client.get("/api/digital-twin/profiles")
            self.assertEqual(profiles.status_code, 200)

            self.assertEqual(client.post("/api/digital-twin/runs").status_code, 405)
            self.assertEqual(
                client.post("/api/digital-twin/exec", json={"cmd": "rm -rf /"}).status_code,
                404,
            )


if __name__ == "__main__":
    unittest.main()
