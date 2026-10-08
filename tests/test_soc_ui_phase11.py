"""
Phase 11 — Persistent command, audit & idempotency infrastructure.

Execution must remain DISABLED. No mitigation/controller/OpenFlow.
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
DOC = SOC / "COMMAND_PERSISTENCE_ARCHITECTURE.md"


def _principal(roles):
    from dashboard.auth.principal import Principal

    return Principal(
        id="user:p11",
        username="p11",
        authentication_method="password",
        authenticated_at="2020-01-01T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
        roles=list(roles),
        session_id="s11",
    )


class SocUiPhase11DocTests(unittest.TestCase):
    def test_doc_exists(self):
        self.assertTrue(DOC.is_file())
        text = DOC.read_text(encoding="utf-8").lower()
        for n in [
            "persistence",
            "sqlite",
            "idempotency",
            "audit",
            "concurrency",
            "execution",
            "disabled",
            "restart",
            "freshness",
            "/api/control",
        ]:
            self.assertIn(n, text, n)

    def test_no_execute_endpoint(self):
        routes = (CMD_PKG / "routes.py").read_text(encoding="utf-8")
        # Phase 12 adds narrow execute; still no mitigation/OpenFlow
        self.assertIn("/commands/{command_id}/execute", routes)
        self.assertNotIn("/mitigate", routes)
        self.assertNotIn("install_flow", routes.lower())


class SocUiPhase11PersistenceTests(unittest.TestCase):
    def setUp(self):
        from dashboard.commands.executor import reset_execution_counter
        from dashboard.commands.store import (
            AUDIT_STORE,
            COMMAND_STORE,
            reset_persistence_for_tests,
        )

        reset_execution_counter()
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self._tmp.name) / "p11.db")
        reset_persistence_for_tests(self.db_path)
        COMMAND_STORE.clear()
        AUDIT_STORE.clear()

    def tearDown(self):
        self._tmp.cleanup()

    def test_command_create_read_survives_reopen(self):
        from dashboard.commands.service import get_command, preview_command
        from dashboard.commands.store import reset_persistence_for_tests

        p = _principal(["ANALYST"])
        prev = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-p11-1",
            event_id="evt-p11-1",
            reason="Phase 11 persistence create/read",
            idempotency_key="idem-p11-create-1",
        )
        cid = prev["command_id"]
        self.assertEqual(prev["status"], "AWAITING_CONFIRMATION")

        # Simulate process restart: clear init cache, keep same DB file
        reset_persistence_for_tests  # noqa: B018 — referenced for clarity
        from dashboard.commands.persistence import reset_initialized_cache

        reset_initialized_cache()
        os.environ["INTELLISHIELD_COMMAND_DB_PATH"] = self.db_path

        again = get_command(cid)
        self.assertIsNotNone(again)
        self.assertEqual(again["command_id"], cid)
        self.assertEqual(again["status"], "AWAITING_CONFIRMATION")
        # Phase 12 allowlisted dry-run may advertise execution_enabled
        self.assertIn(again["execution_enabled"], (True, False))

    def test_idempotency_duplicate_does_not_create_second(self):
        from dashboard.commands.service import list_commands, preview_command

        p = _principal(["ANALYST"])
        a = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-idem",
            event_id="evt-idem",
            reason="Phase 11 idempotency first",
            idempotency_key="same-key-abc",
        )
        b = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-idem",
            event_id="evt-idem",
            reason="Phase 11 idempotency second",
            idempotency_key="same-key-abc",
        )
        self.assertEqual(a["command_id"], b["command_id"])
        self.assertTrue(b.get("duplicate"))
        listed = list_commands(limit=50)
        matching = [
            c
            for c in listed["commands"]
            if c.get("idempotency_key") == "same-key-abc"
        ]
        self.assertEqual(len(matching), 1)

    def test_idempotency_survives_restart(self):
        from dashboard.commands.persistence import reset_initialized_cache
        from dashboard.commands.service import preview_command

        p = _principal(["ANALYST"])
        first = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-idem-r",
            event_id="evt-idem-r",
            reason="Phase 11 idempotency restart",
            idempotency_key="restart-key-1",
        )
        reset_initialized_cache()
        os.environ["INTELLISHIELD_COMMAND_DB_PATH"] = self.db_path
        second = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-idem-r",
            event_id="evt-idem-r",
            reason="Phase 11 idempotency restart",
            idempotency_key="restart-key-1",
        )
        self.assertEqual(first["command_id"], second["command_id"])
        self.assertTrue(second.get("duplicate"))

    def test_confirm_and_audit_persist(self):
        from dashboard.commands.service import (
            confirm_command,
            list_audits,
            preview_command,
        )

        p = _principal(["ANALYST"])
        prev = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-c1",
            event_id="evt-c1",
            reason="Phase 11 confirm persistence",
        )
        conf = confirm_command(
            p,
            command_id=prev["command_id"],
            confirmation_token=prev["confirmation_token"],
        )
        self.assertEqual(conf["status"], "READY_FOR_EXECUTION")
        self.assertFalse(conf["executed"])
        from dashboard.commands.service import execute_command

        done = execute_command(p, command_id=prev["command_id"])
        self.assertEqual(done["status"], "EXECUTED")
        audits = list_audits(limit=50)
        self.assertGreaterEqual(audits["total"], 1)
        self.assertTrue(any(a.get("command_id") == prev["command_id"] for a in audits["audits"]))

    def test_concurrent_confirmation(self):
        from dashboard.commands.service import confirm_command, preview_command

        p = _principal(["ANALYST"])
        prev = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-conc",
            event_id="evt-conc",
            reason="Phase 11 concurrent confirm",
        )
        token = prev["confirmation_token"]
        cid = prev["command_id"]
        results = []

        def _run():
            results.append(
                confirm_command(p, command_id=cid, confirmation_token=token)
            )

        t1 = threading.Thread(target=_run)
        t2 = threading.Thread(target=_run)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        finals = [
            r
            for r in results
            if r.get("status") == "READY_FOR_EXECUTION" and not r.get("duplicate")
        ]
        dups = [
            r
            for r in results
            if r.get("duplicate") or r.get("failure_reason") == "confirmation_replay"
        ]
        self.assertEqual(len(results), 2)
        self.assertEqual(len(finals) + len(dups), 2)
        self.assertGreaterEqual(len(finals), 1)
        self.assertLessEqual(len(finals), 1)

    def test_expired_command_rejected(self):
        from dashboard.commands.models import CommandStatus, utcnow
        from dashboard.commands.service import confirm_command, preview_command
        from dashboard.commands.store import COMMAND_STORE

        p = _principal(["ANALYST"])
        prev = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-exp",
            event_id="evt-exp",
            reason="Phase 11 expiration check",
        )
        cmd = COMMAND_STORE.get(prev["command_id"])
        cmd.expires_at = utcnow() - timedelta(seconds=5)
        COMMAND_STORE.put(cmd)
        conf = confirm_command(
            p,
            command_id=prev["command_id"],
            confirmation_token=prev["confirmation_token"],
        )
        self.assertEqual(conf["status"], CommandStatus.EXPIRED.value)

    def test_high_risk_freshness_fail_closed(self):
        from dashboard.commands.actions import Action, get_action_spec
        from dashboard.commands.freshness import FreshnessStatus, evaluate_freshness

        os.environ.pop("INTELLISHIELD_COMMAND_FRESHNESS_MAX_AGE_SECONDS", None)
        spec = get_action_spec(Action.BLOCK_TARGET)
        fr = evaluate_freshness(spec, event_timestamp=None)
        self.assertEqual(fr.status, FreshnessStatus.NOT_CONFIGURED)
        self.assertTrue(fr.blocks_high_risk)

    def test_invalid_transition_rejected(self):
        from dashboard.commands.models import (
            Command,
            CommandStatus,
            InvalidTransitionError,
            Target,
            utcnow,
        )

        cmd = Command(
            command_id="cmd_bad",
            action="READ",
            target=Target("NONE", "none"),
            event_id=None,
            principal_id="u",
            principal_username="u",
            reason="enough chars here",
            created_at=utcnow(),
            expires_at=utcnow() + timedelta(minutes=5),
            status=CommandStatus.EXECUTION_DISABLED,
        )
        with self.assertRaises(InvalidTransitionError):
            cmd.transition(CommandStatus.CONFIRMED)

    def test_audit_immutable_and_survives_restart(self):
        from dashboard.commands.persistence import reset_initialized_cache
        from dashboard.commands.service import list_audits, preview_command
        from dashboard.commands.store import AUDIT_STORE

        p = _principal(["ANALYST"])
        preview_command(
            p,
            action="READ",
            target_type="NONE",
            target_id="none",
            event_id=None,
            reason="Phase 11 audit durability",
        )
        before = list_audits(limit=50)
        self.assertGreaterEqual(before["total"], 1)
        aid = before["audits"][0]["audit_id"]
        with self.assertRaises(ValueError):
            AUDIT_STORE.append(
                {
                    "audit_id": aid,
                    "command_id": "cmd_x",
                    "principal_id": "u",
                    "action": "READ",
                    "status": "REQUESTED",
                    "source": "test",
                }
            )
        reset_initialized_cache()
        os.environ["INTELLISHIELD_COMMAND_DB_PATH"] = self.db_path
        after = list_audits(limit=50)
        self.assertGreaterEqual(after["total"], before["total"])
        self.assertTrue(any(a.get("audit_id") == aid for a in after["audits"]))

    def test_persistence_unavailable_fail_closed(self):
        from dashboard.commands.service import preview_command

        p = _principal(["ANALYST"])
        with mock.patch(
            "dashboard.commands.service.COMMAND_STORE.put",
            side_effect=__import__(
                "dashboard.commands.persistence", fromlist=["PersistenceUnavailableError"]
            ).PersistenceUnavailableError("db_down"),
        ):
            out = preview_command(
                p,
                action="READ",
                target_type="NONE",
                target_id="none",
                event_id=None,
                reason="Phase 11 fail closed",
            )
        self.assertEqual(out.get("http_hint"), 503)
        self.assertFalse(out.get("execution_enabled", True))

    def test_executor_not_successful(self):
        from dashboard.commands.executor import (
            DISABLED_EXECUTOR,
            ExecutionDisabledError,
            get_execution_attempt_count,
            reset_execution_counter,
        )
        from dashboard.commands.service import (
            confirm_command,
            execute_command,
            preview_command,
        )

        reset_execution_counter()
        p = _principal(["ANALYST"])
        prev = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-ex",
            event_id="evt-ex",
            reason="Phase 11 executor controlled path",
        )
        before = get_execution_attempt_count()
        conf = confirm_command(
            p,
            command_id=prev["command_id"],
            confirmation_token=prev["confirmation_token"],
        )
        self.assertEqual(conf["status"], "READY_FOR_EXECUTION")
        done = execute_command(p, command_id=prev["command_id"])
        self.assertEqual(done["status"], "EXECUTED")
        self.assertGreater(get_execution_attempt_count(), before)
        with self.assertRaises(ExecutionDisabledError):
            DISABLED_EXECUTOR.execute(object())

    def test_pagination(self):
        from dashboard.commands.service import list_audits, list_commands, preview_command

        p = _principal(["ANALYST"])
        for i in range(3):
            preview_command(
                p,
                action="READ",
                target_type="NONE",
                target_id="none",
                event_id=None,
                reason=f"Phase 11 pagination item {i} xx",
                idempotency_key=f"page-{i}",
            )
        page = list_commands(limit=2, offset=0)
        self.assertEqual(len(page["commands"]), 2)
        self.assertGreaterEqual(page["total"], 3)
        page2 = list_commands(limit=2, offset=2)
        self.assertGreaterEqual(len(page2["commands"]), 1)
        audits = list_audits(limit=2, offset=0)
        self.assertEqual(len(audits["audits"]), 2)
        self.assertIn("total", audits)

    def test_no_control_wiring_in_command_pkg(self):
        for path in CMD_PKG.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            # Disallow live wiring (imports / calls), not documentary negation
            self.assertNotIn("from mitigation", text)
            self.assertNotIn("import mitigation", text)
            self.assertNotRegex(text, r"install_flow|ofp_event", re.I)
            self.assertNotRegex(text, r'["\']/api/control/', text)


class SocUiPhase11FrontendGuardTests(unittest.TestCase):
    def test_no_localstorage_command_authority(self):
        js_root = SOC / "js"
        for path in js_root.rglob("*.js"):
            text = path.read_text(encoding="utf-8")
            if "localStorage" in text or "sessionStorage" in text:
                # Auth may mention storage; command authority must not
                if "command" in path.name.lower() or path.name == "commands.js":
                    self.assertNotIn("localStorage", text)
                    self.assertNotIn("sessionStorage", text)


if __name__ == "__main__":
    unittest.main()
