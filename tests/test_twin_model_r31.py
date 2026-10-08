"""R3.1 — Twin model + simulation audit tests (no Mininet dependency)."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace

from shared_contracts import (
    TwinHost,
    TwinLink,
    TwinProfile,
    TwinRun,
    TwinRunPurpose,
    TwinScenario,
    TwinSwitch,
    TwinTopology,
    TwinTrafficConfig,
    TwinValidationPolicy,
    from_dict,
    to_dict,
    to_json,
)
from twin import (
    SIMULATION_INVENTORY,
    TwinValidationError,
    baseline_scenario_catalog,
    build_default_topology,
    build_default_twin_profile,
    default_validation_policy,
    export_topology_dict,
    fingerprint_profile,
    get_baseline_scenario,
    inventory_summary,
    scenario_parameter_audit,
    validate_scenario_id,
    validate_topology,
    validate_twin_profile,
    with_seed,
    with_version,
)
from twin.safety import assert_safe_twin_target, is_safe_twin_target


class TestTwinTopologyR31(unittest.TestCase):
    def test_default_star_topology(self):
        topo = build_default_topology()
        self.assertEqual(topo.host_count, 5)
        self.assertEqual(topo.switch_count, 1)
        self.assertEqual(len(topo.links), 5)
        self.assertEqual(topo.hosts[0].ip, "10.0.0.1")
        self.assertEqual(topo.hosts[0].role, "attacker")
        self.assertEqual(topo.hosts[1].role, "victim")
        self.assertEqual(topo.controller_port, 6653)
        validate_topology(topo)

    def test_export_topology_dict_has_type(self):
        d = export_topology_dict()
        self.assertEqual(d["_type"], "TwinTopology")
        self.assertEqual(d["topology_id"], "intellishield_star_v1")

    def test_duplicate_host_id_rejected(self):
        topo = build_default_topology()
        bad = TwinTopology(
            topology_id="bad",
            hosts=[TwinHost("h1"), TwinHost("h1")],
            switches=[TwinSwitch("s1")],
            links=[TwinLink("h1", "s1")],
        )
        with self.assertRaises(TwinValidationError):
            validate_topology(bad)

    def test_duplicate_switch_id_rejected(self):
        bad = TwinTopology(
            topology_id="bad",
            hosts=[TwinHost("h1"), TwinHost("h2")],
            switches=[TwinSwitch("s1"), TwinSwitch("s1")],
            links=[TwinLink("h1", "s1"), TwinLink("h2", "s1")],
        )
        with self.assertRaises(TwinValidationError):
            validate_topology(bad)

    def test_invalid_link_unknown_endpoint(self):
        topo = build_default_topology()
        bad = TwinTopology(
            topology_id=topo.topology_id,
            hosts=list(topo.hosts),
            switches=list(topo.switches),
            links=[TwinLink("h1", "s99")],
            controller_host=topo.controller_host,
            controller_port=topo.controller_port,
        )
        with self.assertRaises(TwinValidationError) as ctx:
            validate_topology(bad)
        self.assertIn("unknown endpoint", str(ctx.exception))

    def test_self_link_rejected(self):
        bad = TwinTopology(
            topology_id="bad",
            hosts=[TwinHost("h1")],
            switches=[TwinSwitch("s1")],
            links=[TwinLink("h1", "h1")],
        )
        with self.assertRaises(TwinValidationError):
            validate_topology(bad)


class TestTwinProfileR31(unittest.TestCase):
    def test_profile_construction_and_validation(self):
        profile = build_default_twin_profile()
        validate_twin_profile(profile)
        self.assertEqual(profile.version, "1.0.0")
        self.assertEqual(profile.random_seed, 42)

    def test_default_profile_fingerprint_stable(self):
        a = build_default_twin_profile()
        b = build_default_twin_profile()
        self.assertEqual(a.config_fingerprint, b.config_fingerprint)
        self.assertEqual(len(a.config_fingerprint), 64)
        self.assertEqual(a.config_fingerprint, fingerprint_profile(a))

    def test_fingerprint_ignores_created_at(self):
        a = build_default_twin_profile()
        # Recompute on a copy with different created_at via replace after build
        # fingerprint_profile drops created_at — same config → same hash
        mutated = replace(a, created_at=a.created_at.replace(year=1999))
        self.assertEqual(fingerprint_profile(a), fingerprint_profile(mutated))

    def test_seed_changes_fingerprint(self):
        a = build_default_twin_profile(random_seed=1)
        b = with_seed(a, 2)
        self.assertNotEqual(a.config_fingerprint, b.config_fingerprint)
        self.assertEqual(b.random_seed, 2)

    def test_version_changes_fingerprint_no_silent_mutate(self):
        a = build_default_twin_profile(version="1.0.0")
        b = with_version(a, "1.1.0")
        self.assertEqual(a.version, "1.0.0")
        self.assertEqual(b.version, "1.1.0")
        self.assertNotEqual(a.config_fingerprint, b.config_fingerprint)

    def test_negative_seed_rejected(self):
        with self.assertRaises(TwinValidationError):
            build_default_twin_profile(random_seed=-1)

    def test_negative_duration_rejected(self):
        profile = build_default_twin_profile()
        bad_traffic = TwinTrafficConfig(iperf_duration=-5)
        bad = replace(profile, traffic=bad_traffic, config_fingerprint="")
        with self.assertRaises(TwinValidationError):
            validate_twin_profile(bad)

    def test_round_trip_serialize(self):
        profile = build_default_twin_profile()
        restored = from_dict(to_dict(profile), TwinProfile)
        self.assertEqual(restored.profile_id, profile.profile_id)
        self.assertEqual(restored.topology.host_count, 5)
        self.assertEqual(restored.config_fingerprint, profile.config_fingerprint)

    def test_json_safety(self):
        profile = build_default_twin_profile()
        text = to_json(profile)
        data = json.loads(text)
        self.assertEqual(data["_type"], "TwinProfile")
        # round-trip via JSON
        restored = from_dict(data, TwinProfile)
        self.assertEqual(restored.config_fingerprint, profile.config_fingerprint)

    def test_metadata_declares_not_physical_equivalence(self):
        profile = build_default_twin_profile()
        self.assertIn("not_a_claim", profile.metadata)
        self.assertEqual(profile.source_environment, "mininet_lab")

    def test_no_mininet_import_for_model(self):
        import sys

        # twin model modules must not require mininet
        for mod in list(sys.modules):
            if mod == "mininet" or mod.startswith("mininet."):
                self.fail(f"mininet loaded during twin model tests: {mod}")


class TestTwinScenarioCatalogR31(unittest.TestCase):
    def test_five_baseline_scenarios(self):
        cat = baseline_scenario_catalog()
        self.assertEqual(set(cat.keys()), {"S1", "S2", "S3", "S4", "S5"})

    def test_s1_no_attack_expected(self):
        s1 = get_baseline_scenario("S1")
        self.assertIsNotNone(s1)
        assert s1 is not None
        self.assertFalse(s1.expected_attack)
        self.assertEqual(s1.attack_type, None)
        self.assertEqual(s1.intensity_profile, "LIGHT")
        self.assertNotIn("ATTACK_START", s1.ground_truth_events)

    def test_s2_expected_attack_family(self):
        s2 = get_baseline_scenario(2)
        self.assertIsNotNone(s2)
        assert s2 is not None
        self.assertTrue(s2.expected_attack)
        self.assertEqual(s2.expected_attack_family, "SYN_FLOOD")
        self.assertEqual(s2.source_host, "h1")
        self.assertEqual(s2.target_host, "h2")

    def test_expected_attack_requires_family(self):
        with self.assertRaises(ValueError):
            TwinScenario(
                scenario_id="bad",
                name="BAD",
                expected_attack=True,
                expected_attack_family="",
            )

    def test_scenario_round_trip(self):
        s = get_baseline_scenario("S5")
        assert s is not None
        restored = from_dict(to_dict(s), TwinScenario)
        self.assertEqual(restored.expected_attack_family, "MIXED")
        self.assertIn("ATTACK1_START", restored.ground_truth_events)

    def test_unknown_scenario_rejected(self):
        with self.assertRaises(TwinValidationError):
            validate_scenario_id("S99")
        with self.assertRaises(TwinValidationError):
            get_baseline_scenario("S99", require=True)

    def test_parameter_audit_covers_s1_s5(self):
        audit = scenario_parameter_audit()
        self.assertEqual(set(audit.keys()), {"S1", "S2", "S3", "S4", "S5"})
        self.assertIn("duration", audit["S1"]["controllable_today"])
        self.assertTrue(audit["S2"]["hardcoded_today"])


class TestTwinRunAndPolicyR31(unittest.TestCase):
    def test_planned_run_record(self):
        profile = build_default_twin_profile()
        run = TwinRun(
            run_id="run-test-1",
            profile_id=profile.profile_id,
            profile_version=profile.version,
            scenario_id="S2",
            purpose=TwinRunPurpose.VALIDATION,
            random_seed=profile.random_seed,
            config_fingerprint=profile.config_fingerprint,
        )
        self.assertEqual(run.status.value, "PLANNED")
        restored = from_dict(to_dict(run), TwinRun)
        self.assertEqual(restored.purpose, TwinRunPurpose.VALIDATION)

    def test_validation_policy_shape(self):
        policy = default_validation_policy()
        self.assertIsInstance(policy, TwinValidationPolicy)
        self.assertIn("S1", policy.require_scenario_ids)
        self.assertLessEqual(policy.max_fpr or 1.0, 1.0)


class TestTwinSafetyAndInventoryR31(unittest.TestCase):
    def test_lab_targets_allowed(self):
        self.assertTrue(is_safe_twin_target("10.0.0.2"))
        assert_safe_twin_target("10.0.0.2")

    def test_external_targets_blocked(self):
        self.assertFalse(is_safe_twin_target("8.8.8.8"))
        with self.assertRaises(ValueError):
            assert_safe_twin_target("1.2.3.4")

    def test_inventory_explicit_non_claim(self):
        self.assertIn("NOT the Digital Twin", SIMULATION_INVENTORY["explicit_non_claim"])
        self.assertTrue(SIMULATION_INVENTORY["auto_promotion_forbidden"])
        summary = inventory_summary()
        self.assertGreaterEqual(summary["reuse_count"], 8)
        self.assertEqual(summary["deferred_phases"], [])
        self.assertTrue(summary.get("r32_complete"))
        self.assertTrue(summary.get("r34_complete"))
        self.assertTrue(summary.get("r35_complete"))
        self.assertIn("r35_delivered", SIMULATION_INVENTORY)

    def test_no_production_side_effects_on_import(self):
        # Importing twin must not touch flow_monitor or create log files as a side effect
        import twin  # noqa: F401

        self.assertFalse(hasattr(twin, "flow_monitor"))


if __name__ == "__main__":
    unittest.main()
