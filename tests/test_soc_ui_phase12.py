"""
Phase 12 — Controlled low-risk operational command (dry-run adapter).

Exactly one allowlisted action: COMMAND_DRY_RUN.
No mitigation / controller / OpenFlow /api/control/* integration.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import threading
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SOC = ROOT / "dashboard" / "static" / "soc"
CMD_PKG = ROOT / "dashboard" / "commands"
DOC = SOC / "CONTROLLED_OPERATION_ARCHITECTURE.md"


def _principal(roles):
    from dashboard.auth.principal import Principal

    return Principal(
        id="user:p12",
        username="p12",
        authentication_method="password",
        authenticated_at="2020-01-01T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
        roles=list(roles),
        session_id="s12",
    )


class SocUiPhase12DocTests(unittest.TestCase):
    def test_doc_exists(self):
        self.assertTrue(DOC.is_file())
        text = DOC.read_text(encoding="utf-8").lower()
        for n in [
            "command_dry_run",
            "allowlist",
            "execution",
            "confirmation",
            "idempotency",
            "phase 13",
            "/api/control",
            "mitigation",
        ]:
            self.assertIn(n, text, n)

    def test_only_one_allowlisted_action(self):
        from dashboard.commands.actions import PHASE12_ALLOWLIST, Action, ACTION_REGISTRY

        self.assertEqual(PHASE12_ALLOWLIST, frozenset({Action.COMMAND_DRY_RUN}))
        enabled = [a for a, s in ACTION_REGISTRY.items() if s.execution_enabled]
        self.assertEqual(enabled, [Action.COMMAND_DRY_RUN])


class SocUiPhase12UnitTests(unittest.TestCase):
    def setUp(self):
        from dashboard.commands.executor import reset_execution_counter
        from dashboard.commands.store import (
            AUDIT_STORE,
            COMMAND_STORE,
            reset_persistence_for_tests,
        )

        reset_execution_counter()
        self._tmp = tempfile.TemporaryDirectory()
        reset_persistence_for_tests(str(Path(self._tmp.name) / "p12.db"))
        COMMAND_STORE.clear()
        AUDIT_STORE.clear()

    def tearDown(self):
        self._tmp.cleanup()

    def test_full_flow_execute_dry_run(self):
        from dashboard.commands.service import (
            confirm_command,
            execute_command,
            preview_command,
        )

        p = _principal(["ANALYST"])
        prev = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-p12-1",
            event_id="evt-p12-1",
            reason="Phase 12 controlled dry-run flow",
        )
        self.assertEqual(prev["status"], "AWAITING_CONFIRMATION")
        conf = confirm_command(
            p,
            command_id=prev["command_id"],
            confirmation_token=prev["confirmation_token"],
        )
        self.assertEqual(conf["status"], "READY_FOR_EXECUTION")
        self.assertTrue(conf["execution_enabled"])
        done = execute_command(p, command_id=prev["command_id"])
        self.assertEqual(done["status"], "EXECUTED")
        self.assertTrue(done["executed"])
        self.assertEqual(done["execution"]["result_summary"], "controlled_dry_run_completed")
        self.assertFalse(done["execution"]["mutates_network"])

    def test_execute_before_confirm_rejected(self):
        from dashboard.commands.service import execute_command, preview_command

        p = _principal(["ANALYST"])
        prev = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-early",
            event_id="evt-early",
            reason="Phase 12 execute before confirm",
        )
        out = execute_command(p, command_id=prev["command_id"])
        self.assertEqual(out.get("failure_reason"), "invalid_state_for_execution")

    def test_execute_idempotent(self):
        from dashboard.commands.service import (
            confirm_command,
            execute_command,
            preview_command,
        )

        p = _principal(["ANALYST"])
        prev = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-idem-ex",
            event_id="evt-idem-ex",
            reason="Phase 12 execute idempotency",
        )
        confirm_command(
            p,
            command_id=prev["command_id"],
            confirmation_token=prev["confirmation_token"],
        )
        a = execute_command(p, command_id=prev["command_id"])
        b = execute_command(p, command_id=prev["command_id"])
        self.assertEqual(a["status"], "EXECUTED")
        self.assertEqual(b["status"], "EXECUTED")
        self.assertTrue(b.get("duplicate"))
        self.assertEqual(a["execution_id"], b["execution_id"])

    def test_concurrent_execute_once(self):
        from dashboard.commands.service import (
            confirm_command,
            execute_command,
            preview_command,
        )

        p = _principal(["ANALYST"])
        prev = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-conc-ex",
            event_id="evt-conc-ex",
            reason="Phase 12 concurrent execute",
        )
        confirm_command(
            p,
            command_id=prev["command_id"],
            confirmation_token=prev["confirmation_token"],
        )
        cid = prev["command_id"]
        results = []

        def _run():
            results.append(execute_command(p, command_id=cid))

        threads = [threading.Thread(target=_run) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        winners = [
            r
            for r in results
            if r.get("status") == "EXECUTED" and not r.get("duplicate")
        ]
        dups = [r for r in results if r.get("duplicate")]
        self.assertEqual(len(results), 2)
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(dups), 1)

    def test_block_target_still_disabled(self):
        from dashboard.commands.executor import CONTROLLED_EXECUTOR, ExecutionDisabledError
        from dashboard.commands.models import Command, CommandStatus, Target, utcnow

        cmd = Command(
            command_id="cmd_block",
            action="BLOCK_TARGET",
            target=Target("ATTACKER", "10.0.0.1"),
            event_id=None,
            principal_id="u",
            principal_username="u",
            reason="should not execute",
            created_at=utcnow(),
            expires_at=utcnow() + timedelta(minutes=5),
            status=CommandStatus.READY_FOR_EXECUTION,
            execution_enabled=False,
        )
        with self.assertRaises(ExecutionDisabledError):
            CONTROLLED_EXECUTOR.execute(cmd)

    def test_unknown_action_handler_rejected(self):
        from dashboard.commands.actions import is_execution_allowlisted

        self.assertFalse(is_execution_allowlisted("EXECUTE_MITIGATION"))
        self.assertFalse(is_execution_allowlisted("TOTALLY_FAKE"))
        self.assertTrue(is_execution_allowlisted("COMMAND_DRY_RUN"))

    def test_expired_rejects_execute(self):
        from dashboard.commands.models import utcnow
        from dashboard.commands.service import (
            confirm_command,
            execute_command,
            preview_command,
        )
        from dashboard.commands.store import COMMAND_STORE

        p = _principal(["ANALYST"])
        prev = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-exp-ex",
            event_id="evt-exp-ex",
            reason="Phase 12 expire before execute",
        )
        confirm_command(
            p,
            command_id=prev["command_id"],
            confirmation_token=prev["confirmation_token"],
        )
        cmd = COMMAND_STORE.get(prev["command_id"])
        cmd.expires_at = utcnow() - timedelta(seconds=2)
        COMMAND_STORE.put(cmd)
        out = execute_command(p, command_id=prev["command_id"])
        self.assertEqual(out["status"], "EXPIRED")

    def test_no_shell_eval_in_executor(self):
        text = (CMD_PKG / "executor.py").read_text(encoding="utf-8")
        self.assertNotIn("eval(", text)
        self.assertNotIn("exec(", text)
        self.assertNotIn("subprocess", text)
        self.assertNotIn("__import__", text)

    def test_no_control_or_mitigation_wiring(self):
        for path in CMD_PKG.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("from mitigation", text)
            self.assertNotIn("import mitigation", text)
            self.assertNotRegex(text, r"install_flow|ofp_event", re.I)
            self.assertNotRegex(text, r'["\']/api/control/', text)

    def test_execution_survives_restart(self):
        from dashboard.commands.persistence import reset_initialized_cache
        from dashboard.commands.service import (
            confirm_command,
            execute_command,
            get_command,
            preview_command,
        )

        p = _principal(["ANALYST"])
        prev = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-restart",
            event_id="evt-restart",
            reason="Phase 12 restart after execute",
        )
        confirm_command(
            p,
            command_id=prev["command_id"],
            confirmation_token=prev["confirmation_token"],
        )
        done = execute_command(p, command_id=prev["command_id"])
        self.assertEqual(done["status"], "EXECUTED")
        db = os.environ["INTELLISHIELD_COMMAND_DB_PATH"]
        reset_initialized_cache()
        os.environ["INTELLISHIELD_COMMAND_DB_PATH"] = db
        again = get_command(prev["command_id"])
        self.assertEqual(again["status"], "EXECUTED")
        self.assertEqual(again["execution_id"], done["execution_id"])


class SocUiPhase12FrontendTests(unittest.TestCase):
    def test_ui_has_execute_but_no_mitigation(self):
        api = (SOC / "js" / "api" / "commands.js").read_text(encoding="utf-8")
        page = (SOC / "js" / "pages" / "commands.js").read_text(encoding="utf-8")
        self.assertIn("/execute", api)
        self.assertIn("executeCommand", api)
        self.assertIn("data-cmd-execute", page)
        self.assertNotRegex(api, r'fetch\([\'"`]/api/control/')
        self.assertNotIn("localStorage", api)
        self.assertNotIn("localStorage", page)


if __name__ == "__main__":
    unittest.main()
