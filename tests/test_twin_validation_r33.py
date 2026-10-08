"""R3.3 — Twin experiment runner + candidate validation engine tests."""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from shared_contracts import (
    ModelCandidate,
    ModelVersion,
    TwinOutcomeCode,
    TwinRunStatus,
    ValidationStatus,
    utc_now,
)
from twin import (
    TwinExperimentRunner,
    TwinValidationError,
    TwinValidationEngine,
    default_validation_policy,
    good_offline_metrics,
    high_fpr_metrics,
    high_latency_metrics,
    poor_f1_metrics,
    run_python_module,
    validate_candidate,
)
from twin.isolation import assert_candidate_isolated, is_production_model_path
from twin.offline import synthetic_evidence_for_plan
from twin.subprocess_safe import ALLOWED_PYTHON_MODULES


def _candidate(tmp: Path, cid: str = "cand-1") -> ModelCandidate:
    art = tmp / "candidate_model.pkl"
    art.write_bytes(b"fake-candidate-artifact")
    return ModelCandidate(
        candidate_id=cid,
        model=ModelVersion(
            model_id="ml-if-dt",
            version="cand-1.0",
            algorithm="IsolationForest+DecisionTree",
            created_at=utc_now(),
            artifact_uri=str(art),
        ),
    )


def _baseline() -> ModelVersion:
    return ModelVersion(
        model_id="ml-if-dt",
        version="baseline-1.0",
        algorithm="IsolationForest+DecisionTree",
        created_at=utc_now(),
        artifact_uri="logs/models/isolation_forest.pkl",
    )


class TestExperimentPlanR33(unittest.TestCase):
    def test_valid_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            plan = runner.build_plan(
                candidate=cand, scenario_ids=["S1", "S2"], seed=42
            )
            self.assertEqual(plan.status, TwinRunStatus.VALIDATED)
            self.assertEqual(plan.seed, 42)
            self.assertEqual(plan.scenario_ids, ["S1", "S2"])
            self.assertEqual(plan.profile_fingerprint, plan.profile.config_fingerprint)
            self.assertTrue(plan.expected_ground_truth)

    def test_invalid_plan_empty_scenarios(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            with self.assertRaises(TwinValidationError):
                runner.build_plan(candidate=cand, scenario_ids=[], seed=1)


class TestIsolationR33(unittest.TestCase):
    def test_candidate_isolation_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            path = assert_candidate_isolated(cand, root=root)
            self.assertTrue(path.is_file())
            self.assertFalse(is_production_model_path(path, root=root))

    def test_production_path_rejected_as_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "logs" / "models").mkdir(parents=True)
            prod = root / "logs" / "models" / "isolation_forest.pkl"
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

    def test_run_does_not_modify_production(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prod_dir = root / "logs" / "models"
            prod_dir.mkdir(parents=True)
            prod = prod_dir / "isolation_forest.pkl"
            prod.write_bytes(b"production-bytes")
            before = prod.read_bytes()
            mtime = prod.stat().st_mtime_ns
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            metrics = {
                "S1": good_offline_metrics(),
                "S2": good_offline_metrics(),
            }
            runner.validate_candidate(
                cand, scenario_ids=["S1", "S2"], metrics_by_scenario=metrics, seed=9
            )
            self.assertEqual(prod.read_bytes(), before)
            self.assertEqual(prod.stat().st_mtime_ns, mtime)


class TestValidationEngineR33(unittest.TestCase):
    def test_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            result = runner.validate_candidate(
                cand,
                scenario_ids=["S1", "S2"],
                seed=3,
                metrics_by_scenario={
                    "S1": good_offline_metrics(),
                    "S2": good_offline_metrics(),
                },
            )
            self.assertEqual(result.status, ValidationStatus.PASS)
            self.assertEqual(result.metrics["outcome_code"], TwinOutcomeCode.PASS.value)
            self.assertEqual(result.candidate_id, cand.candidate_id)

    def test_fail_f1(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            result = runner.validate_candidate(
                cand,
                metrics_by_scenario={
                    "S1": poor_f1_metrics(),
                    "S2": poor_f1_metrics(),
                },
            )
            self.assertEqual(result.status, ValidationStatus.FAIL)
            self.assertIn("f1", result.reason.lower())

    def test_fail_fpr(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            result = runner.validate_candidate(
                cand,
                metrics_by_scenario={
                    "S1": high_fpr_metrics(),
                    "S2": high_fpr_metrics(),
                },
            )
            self.assertEqual(result.status, ValidationStatus.FAIL)
            self.assertIn("false_positive", result.reason.lower())

    def test_fail_latency(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            result = runner.validate_candidate(
                cand,
                metrics_by_scenario={
                    "S1": high_latency_metrics(),
                    "S2": high_latency_metrics(),
                },
            )
            self.assertEqual(result.status, ValidationStatus.FAIL)
            self.assertIn("detection_latency", result.reason.lower())

    def test_multiple_criteria(self):
        policy = default_validation_policy()
        engine = TwinValidationEngine(policy=policy)
        with tempfile.TemporaryDirectory() as tmp:
            cand = _candidate(Path(tmp))
            # Build evidence manually with two failures
            from twin.experiment_plan import ExperimentEvidence

            bad = poor_f1_metrics()
            bad["false_positive_rate"] = 0.5
            evidence = [
                ExperimentEvidence(
                    scenario_id="S1",
                    metrics=bad,
                    seed=1,
                    profile_fingerprint="abc",
                    source="offline_synthetic",
                ),
                ExperimentEvidence(
                    scenario_id="S2",
                    metrics=bad,
                    seed=1,
                    profile_fingerprint="abc",
                    source="offline_synthetic",
                ),
            ]
            result = engine.evaluate(candidate=cand, evidence=evidence)
            self.assertEqual(result.status, ValidationStatus.FAIL)
            self.assertGreaterEqual(len(result.metrics["findings"]), 2)

    def test_missing_metric_insufficient(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            result = runner.validate_candidate(
                cand,
                metrics_by_scenario={
                    "S1": {"precision": 0.9},  # incomplete
                    "S2": {"precision": 0.9},
                },
            )
            self.assertEqual(result.status, ValidationStatus.SKIPPED)
            self.assertEqual(
                result.metrics["outcome_code"],
                TwinOutcomeCode.INSUFFICIENT_EVIDENCE.value,
            )

    def test_missing_scenario_insufficient(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            # Only S1 provided but policy requires S1+S2
            plan = runner.build_plan(
                candidate=cand, scenario_ids=["S1"], seed=1
            )
            result = runner.run_offline(
                plan,
                metrics_by_scenario={"S1": good_offline_metrics()},
            )
            self.assertEqual(result.status, ValidationStatus.SKIPPED)
            self.assertIn("INSUFFICIENT_EVIDENCE", result.reason)

    def test_missing_artifact_insufficient(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            result = runner.validate_candidate(
                cand,
                metrics_by_scenario={
                    "S1": good_offline_metrics(),
                    "S2": good_offline_metrics(),
                },
                missing_artifacts=["scenario_logs.csv"],
            )
            self.assertEqual(result.status, ValidationStatus.SKIPPED)
            self.assertIn("scenario_logs", result.reason)

    def test_experiment_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            result = runner.validate_candidate(
                cand,
                metrics_by_scenario={},
                experiment_ok=False,
                experiment_error="mininet crashed",
            )
            self.assertEqual(result.status, ValidationStatus.ERROR)
            self.assertEqual(
                result.metrics["outcome_code"],
                TwinOutcomeCode.EXPERIMENT_FAILED.value,
            )
            # Experiment failure ≠ automatic candidate FAIL code
            self.assertNotEqual(result.metrics["outcome_code"], TwinOutcomeCode.FAIL.value)

    def test_baseline_regression_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            baseline = good_offline_metrics()
            cand_metrics = dict(baseline)
            cand_metrics["f1_score"] = 0.60  # drop > 0.05 from 0.89
            result = runner.validate_candidate(
                cand,
                metrics_by_scenario={"S1": cand_metrics, "S2": cand_metrics},
                baseline_metrics=baseline,
            )
            self.assertEqual(result.status, ValidationStatus.FAIL)
            self.assertIn("regression", result.reason.lower())

    def test_bundle_fingerprint_seed_linkage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="offline", root=root)
            result = runner.validate_candidate(
                cand,
                seed=77,
                metrics_by_scenario={
                    "S1": good_offline_metrics(),
                    "S2": good_offline_metrics(),
                },
            )
            art = Path(result.artifact_uri)
            manifest = (art / "twin_experiment_manifest.json").read_text(encoding="utf-8")
            self.assertIn('"seed": 77', manifest)
            self.assertIn("profile_fingerprint", manifest)
            self.assertIn(cand.candidate_id, manifest)
            plan_json = (art / "experiment_plan.json").read_text(encoding="utf-8")
            self.assertIn("config_fingerprint", plan_json)

    def test_determinism(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root, "cand-det")
            runner = TwinExperimentRunner(mode="offline", root=root)
            metrics = {"S1": good_offline_metrics(), "S2": good_offline_metrics()}
            a = runner.validate_candidate(cand, seed=5, metrics_by_scenario=metrics)
            b = runner.validate_candidate(cand, seed=5, metrics_by_scenario=metrics)
            self.assertEqual(a.status, b.status)
            self.assertEqual(a.metrics["f1_score"], b.metrics["f1_score"])
            self.assertEqual(a.metrics["outcome_code"], b.metrics["outcome_code"])


class TestSubprocessSafeR33(unittest.TestCase):
    def test_disallowed_module(self):
        with self.assertRaises(ValueError):
            run_python_module("os.system", ["rm", "-rf", "/"])

    def test_allow_list_fixed(self):
        self.assertIn("scripts.compute_metrics", ALLOWED_PYTHON_MODULES)
        self.assertNotIn("builtins", ALLOWED_PYTHON_MODULES)


class TestLiveMininetGateR33(unittest.TestCase):
    def test_live_mode_not_claimed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            runner = TwinExperimentRunner(mode="live_mininet", root=root)
            result = runner.validate_candidate(cand)
            self.assertEqual(result.status, ValidationStatus.ERROR)
            self.assertIn("LIVE_MININET_NOT_RUN", result.reason)


class TestModuleAPIValidateCandidateR33(unittest.TestCase):
    def test_module_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cand = _candidate(root)
            result = validate_candidate(
                cand,
                root=root,
                metrics_by_scenario={
                    "S1": good_offline_metrics(),
                    "S2": good_offline_metrics(),
                },
            )
            self.assertEqual(result.status, ValidationStatus.PASS)


if __name__ == "__main__":
    unittest.main()
