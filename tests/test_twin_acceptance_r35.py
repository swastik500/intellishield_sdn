"""R3.5 — Digital Twin fidelity, safety, acceptance tests (offline)."""

from __future__ import annotations

import csv
import json
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta
from pathlib import Path

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from evaluation.experiment_windows import AttackWindow
from ml_models.feature_builder import FEATURE_NAMES
from shared_contracts import (
    ModelCandidate,
    ModelVersion,
    TwinOutcomeCode,
    TwinTopology,
    TwinHost,
    TwinSwitch,
    TwinLink,
    TwinProfile,
    ValidationStatus,
    utc_now,
)
from twin.bounds import (
    MAX_SCENARIO_MATRIX_ROWS,
    assert_history_limit,
    assert_matrix_rows,
    assert_variant_count,
)
from twin.dataset import TwinDatasetGenerator, label_from_windows
from twin.diversity import (
    build_scenario_diversity_matrix,
    write_scenario_diversity_matrix,
)
from twin.fidelity import FIDELITY_DIMENSIONS, build_fidelity_report, write_fidelity_report
from twin.fingerprint import fingerprint_profile
from twin.history import read_twin_runs
from twin.isolation import assert_candidate_isolated, production_model_paths
from twin.leakage import assert_no_leakage, detect_dataset_leakage
from twin.manifest import build_manifest
from twin.offline import (
    good_offline_metrics,
    high_fpr_metrics,
    high_latency_metrics,
    low_recall_metrics,
    poor_f1_metrics,
)
from twin.perf import benchmark_r3_software
from twin.planner import plan_scenario
from twin.profile import build_default_twin_profile
from twin.research import emit_research_artifacts
from twin.run_guard import acquire_twin_run_slot, reset_twin_run_slots_for_tests
from twin.safety import assert_safe_twin_target, is_safe_twin_target
from twin.validate import TwinValidationError, validate_twin_profile
from twin.experiment_runner import TwinExperimentRunner


def _candidate(tmp: Path, cid: str = "cand-r35") -> ModelCandidate:
    art = tmp / f"{cid}.pkl"
    art.write_bytes(b"candidate-bytes")
    return ModelCandidate(
        candidate_id=cid,
        model=ModelVersion(
            model_id="ml-if-dt",
            version="r35",
            algorithm="IsolationForest+DecisionTree",
            created_at=utc_now(),
            artifact_uri=str(art),
        ),
    )


def _vec(v: float = 0.1) -> list:
    return [float(v)] * len(FEATURE_NAMES)


class TestReproducibilityR35(unittest.TestCase):
    def test_same_profile_scenario_seed_equivalent(self):
        p1 = build_default_twin_profile(random_seed=42)
        p2 = build_default_twin_profile(random_seed=42)
        self.assertEqual(fingerprint_profile(p1), fingerprint_profile(p2))
        a = plan_scenario("S2", profile=p1, seed=42)
        b = plan_scenario("S2", profile=p2, seed=42)
        self.assertEqual(a.profile_fingerprint, b.profile_fingerprint)
        self.assertEqual(build_manifest(a), build_manifest(b))
        self.assertEqual(a.seed, b.seed)

    def test_security_param_changes_manifest(self):
        a = plan_scenario("S2", seed=42, overrides={"intensity": 1000})
        b = plan_scenario("S2", seed=42, overrides={"intensity": 10000})
        self.assertNotEqual(a.syn_rate, b.syn_rate)
        ma, mb = build_manifest(a), build_manifest(b)
        # Manifest may nest rate under parameters; compare plan fields + digests
        self.assertNotEqual(ma, mb)


class TestGroundTruthIntegrityR35(unittest.TestCase):
    def test_detector_output_cannot_alter_labels(self):
        base = datetime(2026, 7, 27, 16, 0, 0)
        windows = [
            AttackWindow(
                scenario="SCENARIO_2_SYN_FLOOD",
                attack_start=base + timedelta(seconds=10),
                attack_stop=base + timedelta(seconds=40),
                source="scenario_logs",
            )
        ]
        fmt = "%Y-%m-%d %H:%M:%S"
        normal_ts = (base + timedelta(seconds=5)).strftime(fmt)
        attack_ts = (base + timedelta(seconds=20)).strftime(fmt)
        # Even if CSV had ML label=1 for normal, generator uses windows only
        self.assertEqual(label_from_windows(normal_ts, windows, pad_sec=0), 0)
        self.assertEqual(label_from_windows(attack_ts, windows, pad_sec=0), 1)

    def test_scenario_identity_in_plan(self):
        plan = plan_scenario("S2", seed=7)
        self.assertEqual(plan.scenario_id, "S2")
        self.assertTrue(plan.expected_attack)
        self.assertTrue(plan.source_host)
        self.assertTrue(plan.target_host)
        timeline = [e["event"] for e in plan.expected_timeline()]
        self.assertIn("ATTACK_START", timeline)
        self.assertIn("ATTACK_STOP", timeline)


class TestCandidateSafetyR35(unittest.TestCase):
    def setUp(self):
        reset_twin_run_slots_for_tests()

    def test_cannot_overwrite_production(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prod = root / "logs" / "models" / "isolation_forest.pkl"
            prod.parent.mkdir(parents=True)
            prod.write_bytes(b"prod")
            cand = ModelCandidate(
                candidate_id="bad",
                model=ModelVersion(
                    model_id="m",
                    version="1",
                    algorithm="IF",
                    created_at=utc_now(),
                    artifact_uri=str(prod),
                ),
            )
            with self.assertRaises(TwinValidationError):
                assert_candidate_isolated(cand, root=root)

    def test_fail_cannot_promote(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prod_dir = root / "logs" / "models"
            prod_dir.mkdir(parents=True)
            for name in ("isolation_forest.pkl", "decision_tree.pkl", "scaler.pkl"):
                (prod_dir / name).write_bytes(b"prod")
            before = {p: p.read_bytes() for p in production_model_paths(root=root)}
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            result = runner.validate_candidate(
                cand,
                metrics_by_scenario={"S1": poor_f1_metrics(), "S2": poor_f1_metrics()},
            )
            self.assertEqual(result.status, ValidationStatus.FAIL)
            for p, data in before.items():
                self.assertEqual(p.read_bytes(), data)
            # No promotion artifact under logs/models
            self.assertFalse((prod_dir / f"{cand.candidate_id}.pkl").exists())

    def test_experiment_fail_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            result = runner.validate_candidate(
                cand, experiment_ok=False, experiment_error="boom"
            )
            self.assertEqual(result.status, ValidationStatus.ERROR)
            self.assertNotEqual(result.status, ValidationStatus.PASS)

    def test_missing_metrics_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            result = runner.validate_candidate(
                cand, metrics_by_scenario={"S1": {}, "S2": {}}
            )
            self.assertEqual(result.status, ValidationStatus.SKIPPED)
            self.assertNotEqual(result.status, ValidationStatus.PASS)

    def test_missing_scenarios_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            plan = runner.build_plan(candidate=cand, scenario_ids=["S1"], seed=1)
            result = runner.run_offline(
                plan, metrics_by_scenario={"S1": good_offline_metrics()}
            )
            self.assertEqual(result.status, ValidationStatus.SKIPPED)


class TestValidationGateMatrixR35(unittest.TestCase):
    def setUp(self):
        reset_twin_run_slots_for_tests()

    def _run(self, root: Path, metrics):
        cand = _candidate(root)
        return TwinExperimentRunner(mode="offline", root=root).validate_candidate(
            cand, metrics_by_scenario={"S1": metrics, "S2": metrics}
        )

    def test_a_better_candidate_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._run(Path(tmp), good_offline_metrics())
            self.assertEqual(r.status, ValidationStatus.PASS)

    def test_b_worse_candidate_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._run(Path(tmp), poor_f1_metrics())
            self.assertEqual(r.status, ValidationStatus.FAIL)

    def test_c_high_fpr_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._run(Path(tmp), high_fpr_metrics())
            self.assertEqual(r.status, ValidationStatus.FAIL)

    def test_d_low_recall_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._run(Path(tmp), low_recall_metrics())
            self.assertEqual(r.status, ValidationStatus.FAIL)

    def test_e_excessive_latency_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._run(Path(tmp), high_latency_metrics())
            self.assertEqual(r.status, ValidationStatus.FAIL)

    def test_f_missing_metrics_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = self._run(Path(tmp), {"precision": 0.9})
            self.assertEqual(r.status, ValidationStatus.SKIPPED)
            self.assertEqual(
                r.metrics["outcome_code"], TwinOutcomeCode.INSUFFICIENT_EVIDENCE.value
            )

    def test_g_failed_experiment_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            r = TwinExperimentRunner(mode="offline", root=root).validate_candidate(
                cand, experiment_ok=False, experiment_error="crash"
            )
            self.assertEqual(r.status, ValidationStatus.ERROR)


class TestLeakageR35(unittest.TestCase):
    def test_detect_run_across_splits(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "samples.csv"
            with path.open("w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(
                    fh,
                    fieldnames=[
                        "timestamp",
                        "switch_id",
                        "label",
                        "split",
                        "scenario_id",
                        "run_id",
                    ],
                )
                w.writeheader()
                w.writerow(
                    {
                        "timestamp": "t1",
                        "switch_id": "1",
                        "label": "0",
                        "split": "TRAINING",
                        "scenario_id": "S1",
                        "run_id": "same-run",
                    }
                )
                w.writerow(
                    {
                        "timestamp": "t2",
                        "switch_id": "1",
                        "label": "1",
                        "split": "TEST",
                        "scenario_id": "S2",
                        "run_id": "same-run",
                    }
                )
            report = detect_dataset_leakage(path)
            self.assertFalse(report.ok)
            self.assertTrue(any(f.code == "run_across_splits" for f in report.findings))
            with self.assertRaises(TwinValidationError):
                assert_no_leakage(path)

    def test_clean_splits_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "samples.csv"
            with path.open("w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(
                    fh,
                    fieldnames=[
                        "timestamp",
                        "switch_id",
                        "label",
                        "split",
                        "scenario_id",
                        "run_id",
                    ],
                )
                w.writeheader()
                w.writerow(
                    {
                        "timestamp": "t1",
                        "switch_id": "1",
                        "label": "0",
                        "split": "TRAINING",
                        "scenario_id": "S1",
                        "run_id": "r1",
                    }
                )
                w.writerow(
                    {
                        "timestamp": "t2",
                        "switch_id": "1",
                        "label": "1",
                        "split": "TEST",
                        "scenario_id": "S4",
                        "run_id": "r2",
                    }
                )
            report = assert_no_leakage(path)
            self.assertTrue(report.ok)
            self.assertTrue(report.limitations)


class TestFidelityR35(unittest.TestCase):
    def test_dimensions_and_report(self):
        plan = plan_scenario("S2", seed=42)
        report = build_fidelity_report(
            plan=plan,
            profile_fingerprint=plan.profile_fingerprint,
            seed=42,
            mode="offline",
        )
        dims = {d["dimension"] for d in report["dimensions"]}
        self.assertEqual(dims, set(FIDELITY_DIMENSIONS))
        self.assertFalse(report["live_mininet"])
        statuses = {d["status"] for d in report["dimensions"]}
        self.assertTrue(statuses & {"PASS", "NOT_AVAILABLE"})
        self.assertNotIn("FAIL", statuses)  # offline default should not FAIL topology/config
        with tempfile.TemporaryDirectory() as tmp:
            path = write_fidelity_report(report, path=Path(tmp) / "twin_fidelity_report.json")
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["schema"], "intellishield.twin.fidelity_report.v1")

    def test_live_traffic_error_when_observed(self):
        plan = plan_scenario("S2", seed=1, overrides={"intensity": 1000})
        report = build_fidelity_report(
            plan=plan,
            seed=1,
            observed={"syn_rate": 1000.0, "attack_duration_sec": float(plan.attack_sec)},
            live_pipeline_seen=True,
            mode="offline",
        )
        by_dim = {d["dimension"]: d for d in report["dimensions"]}
        self.assertEqual(by_dim["TRAFFIC_FIDELITY"]["status"], "PASS")
        self.assertEqual(by_dim["TEMPORAL_FIDELITY"]["status"], "PASS")
        self.assertEqual(by_dim["SECURITY_RESPONSE_FIDELITY"]["status"], "PASS")


class TestDiversityAndResearchR35(unittest.TestCase):
    def test_scenario_matrix_bounded(self):
        rows = build_scenario_diversity_matrix(seed=100, max_rows=9)
        self.assertGreaterEqual(len(rows), 5)
        self.assertLessEqual(len(rows), MAX_SCENARIO_MATRIX_ROWS)
        scenarios = {r["scenario_id"] for r in rows}
        self.assertTrue({"S1", "S2"} <= scenarios)
        with self.assertRaises(TwinValidationError):
            build_scenario_diversity_matrix(max_rows=MAX_SCENARIO_MATRIX_ROWS + 1)

    def test_research_artifacts_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index = emit_research_artifacts(root=root)
            self.assertFalse(index["live_mininet"])
            for key, path in index["artifacts"].items():
                self.assertTrue(Path(path).is_file(), msg=key)
            matrix = write_scenario_diversity_matrix(root=root, max_rows=9)
            self.assertTrue(matrix.is_file())


class TestTrainingDataProvenanceR35(unittest.TestCase):
    def test_manifest_provenance_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "logs"
            logs.mkdir()
            feats = logs / "ml_features.csv"
            base = datetime(2026, 7, 27, 17, 0, 0)
            fmt = "%Y-%m-%d %H:%M:%S"
            with feats.open("w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["timestamp", "switch_id", "label"] + list(FEATURE_NAMES))
                w.writerow([(base + timedelta(seconds=5)).strftime(fmt), "1", "1", *_vec()])
                w.writerow([(base + timedelta(seconds=25)).strftime(fmt), "1", "0", *_vec(0.9)])
            windows = [
                AttackWindow(
                    scenario="SCENARIO_2_SYN_FLOOD",
                    attack_start=base + timedelta(seconds=20),
                    attack_stop=base + timedelta(seconds=50),
                )
            ]
            profile = build_default_twin_profile(random_seed=42)
            ds = TwinDatasetGenerator(root=root).generate(
                run_id="prov-run",
                profile_id=profile.profile_id,
                profile_fingerprint=profile.config_fingerprint,
                scenario_id="S2",
                seed=42,
                features_csv=feats,
                logs_dir=logs,
                windows=windows,
                pad_sec=0,
            )
            m = ds.manifest
            self.assertEqual(m["label_source"], "SCENARIO_CONTROL")
            self.assertEqual(m["seeds"], [42])
            self.assertEqual(m["run_ids"], ["prov-run"])
            self.assertTrue(m["profile_fingerprint"])
            self.assertTrue(m["feature_schema_hash"])
            self.assertTrue(m["checksums"]["samples.csv"])
            self.assertIn("split_policy", m)
            # Detector-poisoned CSV label ignored: first row NORMAL
            with ds.samples_csv.open(newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(rows[0]["label"], "0")
            self.assertEqual(rows[1]["label"], "1")


class TestPerfBoundsR35(unittest.TestCase):
    def test_software_benchmark(self):
        bench = benchmark_r3_software(iterations=5)
        self.assertIn("profile_load_ms", bench)
        self.assertIn("fingerprint_ms", bench)
        self.assertIn("scenario_planning_ms", bench)
        self.assertIn("validation_calculation_ms", bench)
        self.assertEqual(bench["excludes"], "Mininet experiment wall-clock")

    def test_bounds_enforced(self):
        assert_matrix_rows(1)
        with self.assertRaises(TwinValidationError):
            assert_matrix_rows(0)
        with self.assertRaises(TwinValidationError):
            assert_variant_count(9999)
        self.assertEqual(assert_history_limit(500), 100)

    def test_concurrent_run_limit(self):
        reset_twin_run_slots_for_tests()
        entered = threading.Event()
        release = threading.Event()
        errors = []

        def hold():
            try:
                with acquire_twin_run_slot():
                    entered.set()
                    release.wait(timeout=5)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        t = threading.Thread(target=hold)
        t.start()
        self.assertTrue(entered.wait(timeout=2))
        with self.assertRaises(TwinValidationError):
            with acquire_twin_run_slot():
                pass
        release.set()
        t.join(timeout=2)
        self.assertFalse(errors)
        reset_twin_run_slots_for_tests()


class TestFailureInjectionR35(unittest.TestCase):
    def setUp(self):
        reset_twin_run_slots_for_tests()

    def test_invalid_profile(self):
        topo = TwinTopology(
            topology_id="bad",
            hosts=[TwinHost(host_id="h1", ip="10.0.0.1")],
            switches=[TwinSwitch(switch_id="s1", dpid="1")],
            links=[TwinLink(src="h1", dst="unknown-switch")],
        )
        with self.assertRaises(TwinValidationError):
            validate_twin_profile(
                TwinProfile(
                    profile_id="x",
                    version="1",
                    topology=topo,
                    created_at=utc_now(),
                )
            )

    def test_unknown_host_and_external_target(self):
        with self.assertRaises(TwinValidationError):
            plan_scenario("S2", overrides={"source_host": "h99"})
        self.assertFalse(is_safe_twin_target("8.8.8.8"))
        with self.assertRaises(ValueError):
            assert_safe_twin_target("1.2.3.4")

    def test_bad_seed(self):
        with self.assertRaises(TwinValidationError):
            plan_scenario("S2", seed=-1)

    def test_invalid_scenario(self):
        with self.assertRaises(TwinValidationError):
            plan_scenario("S99")

    def test_missing_candidate_artifact_when_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = ModelCandidate(
                candidate_id="missing",
                model=ModelVersion(
                    model_id="m",
                    version="1",
                    algorithm="IF",
                    created_at=utc_now(),
                    artifact_uri=str(root / "nope.pkl"),
                ),
            )
            with self.assertRaises(TwinValidationError):
                assert_candidate_isolated(
                    cand, root=root, allow_missing_artifact=False
                )

    def test_dashboard_malformed_artifact_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad = root / "twin" / "candidates" / "c1" / "run1"
            bad.mkdir(parents=True)
            (bad / "experiment_plan.json").write_text("{not-json", encoding="utf-8")
            runs = read_twin_runs(str(root), limit=10)
            self.assertEqual(runs, [])


class TestCapabilityInventoryR35(unittest.TestCase):
    def test_more_than_mininet(self):
        from twin.inventory import SIMULATION_INVENTORY, inventory_summary

        self.assertIn("TwinProfile", " ".join(SIMULATION_INVENTORY["r31_delivered"]))
        self.assertTrue(inventory_summary().get("r35_complete") or "r35_delivered" in SIMULATION_INVENTORY)
        self.assertTrue(SIMULATION_INVENTORY["auto_promotion_forbidden"])
        self.assertNotIn("R3.5", SIMULATION_INVENTORY.get("deferred", {}))


if __name__ == "__main__":
    unittest.main()
