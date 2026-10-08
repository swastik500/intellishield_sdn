"""R3.2 — Parameterized twin scenario + traffic engine tests."""

from __future__ import annotations

import inspect
import json
import tempfile
import unittest
from pathlib import Path

from twin import (
    GENERATOR_VERSION,
    TwinValidationError,
    build_manifest,
    default_plan,
    dry_run_scenario,
    generate_variants,
    plan_scenario,
    write_manifest,
)
from twin.scenario_spec import MAX_VARIANTS_HARD


class TestDefaultCompatibilityR32(unittest.TestCase):
    def test_s1_default(self):
        p = default_plan("S1")
        self.assertFalse(p.expected_attack)
        self.assertEqual(p.duration_sec, 60)
        self.assertEqual(p.run_kwargs, {"duration": 60})
        self.assertIn("START", p.ground_truth_events)

    def test_s2_default(self):
        p = default_plan("S2")
        self.assertTrue(p.expected_attack)
        self.assertEqual(p.expected_attack_family, "SYN_FLOOD")
        self.assertEqual(p.baseline_sec, 20)
        self.assertEqual(p.attack_sec, 30)
        self.assertEqual(p.recovery_sec, 10)
        self.assertEqual(p.source_host, "h1")
        self.assertEqual(p.target_host, "h2")
        self.assertEqual(p.syn_rate, 10000)
        self.assertEqual(p.run_kwargs["attacker"], "h1")
        self.assertEqual(p.run_kwargs["syn_rate"], 10000)

    def test_s3_default(self):
        p = default_plan("S3")
        self.assertEqual(p.expected_attack_family, "UDP_FLOOD")
        self.assertEqual(p.udp_bandwidth, "10M")
        self.assertEqual(p.run_kwargs["bandwidth"], "10M")

    def test_s4_attack_stop_preserved(self):
        p = default_plan("S4")
        self.assertEqual(p.burst_sec, 8)
        self.assertEqual(p.burst_count, 1)
        self.assertIn("ATTACK_START", p.ground_truth_events)
        self.assertIn("ATTACK_STOP", p.ground_truth_events)
        timeline = p.expected_timeline()
        types = [e["event"] for e in timeline]
        self.assertEqual(types.count("ATTACK_START"), 1)
        self.assertEqual(types.count("ATTACK_STOP"), 1)
        # ATTACK_STOP before END
        self.assertLess(types.index("ATTACK_STOP"), types.index("END"))

    def test_s5_default(self):
        p = default_plan("S5")
        self.assertEqual(p.attack1_sec, 20)
        self.assertEqual(p.gap_sec, 10)
        self.assertEqual(p.attack2_sec, 20)
        self.assertNotIn("syn_rate", p.run_kwargs)  # legacy default path
        self.assertIn("ATTACK1_START", p.ground_truth_events)


class TestParameterOverridesR32(unittest.TestCase):
    def test_overrides(self):
        p = plan_scenario(
            "S2",
            overrides={
                "baseline_sec": 15,
                "attack_sec": 25,
                "intensity": 1000,
                "source_host": "h3",
                "target_host": "h4",
            },
            seed=7,
        )
        self.assertEqual(p.baseline_sec, 15)
        self.assertEqual(p.attack_sec, 25)
        self.assertEqual(p.syn_rate, 1000)
        self.assertEqual(p.source_host, "h3")
        self.assertEqual(p.target_host, "h4")
        self.assertEqual(p.seed, 7)
        self.assertEqual(p.duration_sec, 15 + 25 + 10)

    def test_invalid_duration(self):
        with self.assertRaises(TwinValidationError):
            plan_scenario("S1", overrides={"duration_sec": 0})
        with self.assertRaises(TwinValidationError):
            plan_scenario("S2", overrides={"attack_sec": 9999})

    def test_invalid_intensity(self):
        with self.assertRaises(TwinValidationError):
            plan_scenario("S2", overrides={"intensity": 50})  # below MIN
        with self.assertRaises(TwinValidationError):
            plan_scenario("S2", overrides={"intensity": "ULTRA"})


class TestSafetyR32(unittest.TestCase):
    def test_unknown_target(self):
        with self.assertRaises(TwinValidationError) as ctx:
            plan_scenario("S2", overrides={"target_host": "h99"})
        self.assertIn("unknown", str(ctx.exception).lower())

    def test_external_ip_rejected(self):
        with self.assertRaises(TwinValidationError) as ctx:
            plan_scenario("S2", overrides={"target": "8.8.8.8"})
        msg = str(ctx.exception).lower()
        self.assertTrue("external" in msg or "not an ip" in msg or "host id" in msg)

    def test_external_attacker_rejected(self):
        with self.assertRaises(TwinValidationError):
            plan_scenario("S3", overrides={"attacker": "1.2.3.4"})

    def test_same_source_target_rejected(self):
        with self.assertRaises(TwinValidationError):
            plan_scenario("S2", overrides={"source_host": "h2", "target_host": "h2"})


class TestSeedAndVariantsR32(unittest.TestCase):
    def test_seed_determinism(self):
        a = generate_variants("S2", seed=10, count=3)
        b = generate_variants("S2", seed=10, count=3)
        self.assertEqual(
            [p.parameters for p in a],
            [p.parameters for p in b],
        )

    def test_different_seeds_differ(self):
        a = generate_variants("S2", seed=10, count=3)
        b = generate_variants("S2", seed=11, count=3)
        self.assertNotEqual(
            [p.parameters for p in a],
            [p.parameters for p in b],
        )

    def test_variant_bounds(self):
        with self.assertRaises(TwinValidationError):
            generate_variants("S2", seed=1, count=MAX_VARIANTS_HARD + 1)
        plans = generate_variants("S4", seed=5, count=4)
        self.assertEqual(len(plans), 4)
        for p in plans:
            self.assertEqual(p.scenario_id, "S4")
            self.assertIn("ATTACK_STOP", p.ground_truth_events)


class TestManifestAndDryRunR32(unittest.TestCase):
    def test_ground_truth_independent(self):
        p = default_plan("S2")
        m = build_manifest(p)
        gt = m["expected_ground_truth"]
        self.assertEqual(gt["label_source"], "SCENARIO_CONTROL")
        self.assertTrue(gt["expected_attack"])
        self.assertTrue(any(e["event"] == "ATTACK_START" for e in gt["timeline"]))
        self.assertNotIn("ml_prediction", m)
        self.assertEqual(m["generator_version"], GENERATOR_VERSION)

    def test_manifest_write_json_safe(self):
        p = default_plan("S3", seed=99)
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(p, Path(tmp) / "manifest.json")
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["scenario_id"], "S3")
            self.assertEqual(data["seed"], 99)
            self.assertEqual(data["profile_fingerprint"], p.profile_fingerprint)

    def test_dry_run_no_mininet(self):
        report = dry_run_scenario(
            "S2",
            overrides={"intensity": "LOW", "attack_sec": 20},
            seed=3,
        )
        self.assertTrue(report["dry_run"])
        self.assertFalse(report["launches_mininet"])
        self.assertFalse(report["launches_traffic"])
        self.assertEqual(report["parameters"]["syn_rate"], 1000)
        self.assertEqual(report["target"]["target_host"], "h2")
        self.assertIn("timeline", report["expected_outputs"])


class TestNoProductionSideEffectsR32(unittest.TestCase):
    def test_import_does_not_touch_flow_monitor(self):
        import twin
        import twin.planner as planner
        import twin.dry_run as dry_run

        self.assertFalse(hasattr(twin, "flow_monitor"))
        # Twin modules must not import TrafficScheduler / Mininet
        for mod in (twin, planner, dry_run):
            src = inspect.getsource(mod)
            self.assertNotIn("from traffic_generator.traffic_scheduler", src)
            self.assertNotIn("import mininet", src)
        self.assertIn("TrafficScheduler unchanged", twin.default_plan("S1").notes)


class TestScenarioFunctionSignaturesR32(unittest.TestCase):
    def test_additive_kwargs_exist_with_defaults(self):
        from traffic_generator.attack_scenarios import (
            scenario_2_syn_flood,
            scenario_4_burst_attack,
            scenario_5_mixed_attacks,
        )

        sig2 = inspect.signature(scenario_2_syn_flood)
        self.assertEqual(sig2.parameters["baseline_sec"].default, 20)
        self.assertEqual(sig2.parameters["attacker"].default, None)
        sig4 = inspect.signature(scenario_4_burst_attack)
        self.assertEqual(sig4.parameters["burst_count"].default, 1)
        self.assertEqual(sig4.parameters["burst_sec"].default, 8)
        sig5 = inspect.signature(scenario_5_mixed_attacks)
        self.assertEqual(sig5.parameters["attack1_sec"].default, 20)


if __name__ == "__main__":
    unittest.main()
