"""Level A acceptance — demo CLI / runner against slim fixture (+ optional live logs)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from twin.demo_level_a import (
    EXIT_LOGS_MISSING,
    EXIT_PASS,
    EXIT_REPLAY_OR_FIDELITY_FAIL,
    parse_whatif_overrides,
    run_level_a_demo,
)

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE = _ROOT / "tests" / "fixtures" / "twin_s2_slim"
_LIVE_SLIM = (
    _ROOT
    / "logs"
    / "live_vm_20260728T170330Z"
    / "logs"
    / "live_runs"
    / "slim_20260728T170330Z"
)
_DEMO_SCRIPT = _ROOT / "scripts" / "r3_level_a_demo.py"


class TestWhatifParse(unittest.TestCase):
    def test_parse_overrides(self):
        self.assertEqual(
            parse_whatif_overrides(["attack_sec=25", "intensity=high"]),
            {"attack_sec": 25, "intensity": "high"},
        )


class TestLevelADemoFixture(unittest.TestCase):
    def test_fixture_exists(self):
        self.assertTrue((_FIXTURE / "scenario_logs.csv").is_file())

    def test_demo_pass_on_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_level_a_demo(
                _FIXTURE,
                scenario_id="S2",
                seed=42,
                whatif={"attack_sec": 25},
                root=tmp,
                persist=True,
            )
            self.assertEqual(result.exit_code, EXIT_PASS, result.message)
            self.assertTrue(result.checks.get("sequence_ok"))
            self.assertTrue(result.checks.get("overall_not_fail"))
            self.assertTrue(result.checks.get("mutates_mitigation_false"))
            self.assertTrue(result.checks.get("launches_mininet_false"))
            self.assertTrue(result.ingest)
            assert result.ingest is not None
            self.assertTrue(result.ingest["package"]["fidelity_report.json"])

    def test_missing_logs_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_level_a_demo(Path(tmp) / "missing", root=tmp, persist=False)
            self.assertEqual(result.exit_code, EXIT_LOGS_MISSING)

    def test_incomplete_logs_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty_exp"
            empty.mkdir()
            result = run_level_a_demo(empty, root=tmp, persist=False)
            self.assertEqual(result.exit_code, EXIT_LOGS_MISSING)

    def test_cli_subprocess_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_out = Path(tmp) / "demo_result.json"
            env = os.environ.copy()
            env["PYTHONPATH"] = str(_ROOT)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(_DEMO_SCRIPT),
                    "--logs-dir",
                    str(_FIXTURE),
                    "--scenario",
                    "S2",
                    "--whatif",
                    "attack_sec=25",
                    "--root",
                    tmp,
                    "--json-out",
                    str(json_out),
                    "--quiet",
                ],
                cwd=str(_ROOT),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, EXIT_PASS, proc.stdout + proc.stderr)
            payload = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(payload["exit_code"], EXIT_PASS)
            self.assertTrue(payload.get("snapshot_id"))


@unittest.skipUnless(_LIVE_SLIM.is_dir(), "live slim log bundle not present")
class TestLevelADemoLiveSlimOptional(unittest.TestCase):
    def test_demo_pass_on_live_slim(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_level_a_demo(
                _LIVE_SLIM,
                scenario_id="S2",
                seed=42,
                whatif={"attack_sec": 25},
                root=tmp,
                persist=True,
            )
            self.assertEqual(result.exit_code, EXIT_PASS, result.message)
            self.assertNotEqual(result.checks.get("overall"), "FAIL")


if __name__ == "__main__":
    unittest.main()
