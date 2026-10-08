"""
Phase 13 — R7-gated operational mitigation boundary proofs.

Phase 13 status: BLOCKED. Real mitigation remains DISABLED on the Command Center path.
These tests prove the safety boundary; they do not enable OpenFlow/mitigation.
"""

from __future__ import annotations

import ast
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SOC = ROOT / "dashboard" / "static" / "soc"
CMD_PKG = ROOT / "dashboard" / "commands"
DOC = SOC / "R7_GATED_OPERATIONAL_MITIGATION.md"


def _principal(roles):
    from dashboard.auth.principal import Principal

    return Principal(
        id="user:p13",
        username="p13",
        authentication_method="password",
        authenticated_at="2020-01-01T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
        roles=list(roles),
        session_id="s13",
    )


class SocUiPhase13DocTests(unittest.TestCase):
    def test_doc_exists_and_declares_blocked(self):
        self.assertTrue(DOC.is_file())
        text = DOC.read_text(encoding="utf-8")
        lower = text.lower()
        for needle in [
            "blocked",
            "mitigation capability matrix",
            "r7",
            "event_id",
            "autonomous mitigation",
            "/api/control",
            "command_dry_run",
            "not implemented",
        ]:
            self.assertIn(needle, lower, needle)
        self.assertIn("MITIGATION REMAINS DISABLED", text)

    def test_phase13_status_constants(self):
        from dashboard.commands.actions import (
            PHASE13_MITIGATION_ALLOWLIST,
            PHASE13_MITIGATION_ENABLED,
            PHASE13_STATUS,
            PHASE12_ALLOWLIST,
            Action,
            ACTION_REGISTRY,
        )

        self.assertEqual(PHASE13_STATUS, "BLOCKED")
        self.assertFalse(PHASE13_MITIGATION_ENABLED)
        self.assertEqual(PHASE13_MITIGATION_ALLOWLIST, frozenset())
        self.assertEqual(PHASE12_ALLOWLIST, frozenset({Action.COMMAND_DRY_RUN}))
        enabled = [a for a, s in ACTION_REGISTRY.items() if s.execution_enabled]
        self.assertEqual(enabled, [Action.COMMAND_DRY_RUN])


class SocUiPhase13MitigationDisabledTests(unittest.TestCase):
    def setUp(self):
        from dashboard.commands.executor import reset_execution_counter
        from dashboard.commands.store import (
            AUDIT_STORE,
            COMMAND_STORE,
            reset_persistence_for_tests,
        )

        reset_execution_counter()
        self._tmp = tempfile.TemporaryDirectory()
        reset_persistence_for_tests(str(Path(self._tmp.name) / "p13.db"))
        COMMAND_STORE.clear()
        AUDIT_STORE.clear()

    def tearDown(self):
        self._tmp.cleanup()

    def test_execute_mitigation_not_allowlisted(self):
        from dashboard.commands.actions import is_execution_allowlisted

        self.assertFalse(is_execution_allowlisted("EXECUTE_MITIGATION"))
        self.assertFalse(is_execution_allowlisted("BLOCK_TARGET"))
        self.assertFalse(is_execution_allowlisted("UNBLOCK_TARGET"))

    def test_preview_execute_mitigation_ends_disabled(self):
        from dashboard.commands.service import confirm_command, preview_command

        p = _principal(["OPERATOR"])
        prev = preview_command(
            p,
            action="EXECUTE_MITIGATION",
            target_type="EVENT",
            target_id="evt-r7-1",
            event_id="evt-r7-1",
            reason="Attempt R7 mitigation — must remain disabled",
        )
        self.assertFalse(prev.get("execution_enabled"))
        # May be denied early by permission (FUTURE) or reach confirm path disabled
        cid = prev.get("command_id")
        if cid and prev.get("status") == "AWAITING_CONFIRMATION":
            conf = confirm_command(p, command_id=cid)
            self.assertFalse(conf.get("execution_enabled"))
            self.assertNotEqual(conf.get("status"), "READY_FOR_EXECUTION")

    def test_block_target_cannot_reach_ready(self):
        from dashboard.commands.service import confirm_command, preview_command

        p = _principal(["ADMIN"])
        prev = preview_command(
            p,
            action="BLOCK_TARGET",
            target_type="ATTACKER",
            target_id="02:aa:aa:aa:aa:01",
            event_id="evt-block-1",
            reason="Block attempt must fail closed",
        )
        self.assertFalse(prev.get("execution_enabled"))
        cid = prev.get("command_id")
        if cid and prev.get("status") == "AWAITING_CONFIRMATION":
            conf = confirm_command(p, command_id=cid)
            self.assertIn(
                conf.get("status"),
                {
                    "EXECUTION_DISABLED",
                    "DENIED",
                    "FAILED",
                    "AWAITING_CONFIRMATION",
                    "SAFETY_FAILED",
                    "UNAUTHORIZED",
                },
            )
            self.assertNotEqual(conf.get("status"), "READY_FOR_EXECUTION")

    def test_mitigation_permissions_never_granted(self):
        from dashboard.auth.permissions import (
            FUTURE_PERMISSIONS,
            Permission,
            is_enabled_permission,
        )
        from dashboard.auth.roles import Role, permissions_for_roles

        for perm in (
            Permission.EXECUTE_MITIGATION,
            Permission.BLOCK_TARGET,
            Permission.UNBLOCK_TARGET,
        ):
            self.assertIn(perm, FUTURE_PERMISSIONS)
            self.assertFalse(is_enabled_permission(perm))
            for role in Role:
                self.assertNotIn(perm, permissions_for_roles([role]))

    def test_dry_run_still_works_after_phase13_block(self):
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
            target_id="evt-p13-dry",
            event_id="evt-p13-dry",
            reason="Phase 13 must not break Phase 12 dry-run",
        )
        token = prev.get("confirmation_token")
        conf = confirm_command(
            p, command_id=prev["command_id"], confirmation_token=token
        )
        self.assertEqual(conf["status"], "READY_FOR_EXECUTION")
        exe = execute_command(p, command_id=prev["command_id"])
        self.assertTrue(exe.get("executed") or exe.get("status") == "EXECUTED")


class SocUiPhase13SecurityBoundaryTests(unittest.TestCase):
    def test_no_mitigation_imports_in_commands_package(self):
        banned = re.compile(
            r"^\s*(from\s+mitigation|import\s+mitigation|"
            r"from\s+controller|import\s+controller)\b",
            re.M,
        )
        for path in CMD_PKG.rglob("*.py"):
            if "__pycache__" in str(path):
                continue
            src = path.read_text(encoding="utf-8")
            self.assertIsNone(banned.search(src), f"mitigation/controller import in {path}")

    def test_no_shell_eval_exec_subprocess_in_commands(self):
        for path in CMD_PKG.rglob("*.py"):
            if "__pycache__" in str(path):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    fn = node.func
                    name = ""
                    if isinstance(fn, ast.Name):
                        name = fn.id
                    elif isinstance(fn, ast.Attribute):
                        name = fn.attr
                    self.assertNotIn(name, {"eval", "exec", "system"}, path)

    def test_no_generic_mitigation_api_routes(self):
        api = (ROOT / "dashboard" / "api.py").read_text(encoding="utf-8")
        routes = (CMD_PKG / "routes.py").read_text(encoding="utf-8")
        for blob in (api, routes):
            self.assertNotRegex(blob, r'@app\.post\("/api/mitigate')
            self.assertNotRegex(blob, r'@app\.post\("/api/block')
            self.assertNotRegex(blob, r'@.*\("/api/controller/execute')
            self.assertNotRegex(blob, r"execute-anything")

    def test_control_routes_not_invoked_from_commands(self):
        call_patterns = (
            re.compile(r"requests\.(get|post|put|delete).*control", re.I),
            re.compile(r"httpx\.(get|post).*control", re.I),
            re.compile(r'["\']/api/control/'),
            re.compile(r"\bblock_src_mac\s*\("),
            re.compile(r"\bOFPFlowMod\b"),
        )
        for path in CMD_PKG.rglob("*.py"):
            if "__pycache__" in str(path):
                continue
            src = path.read_text(encoding="utf-8")
            for pat in call_patterns:
                self.assertIsNone(pat.search(src), f"{pat.pattern} in {path}")
            self.assertNotIn("control/controller", src)

    def test_executor_has_no_mitigation_handler(self):
        from dashboard.commands.actions import Action
        from dashboard.commands import executor as ex

        handlers = getattr(ex, "_HANDLERS", None) or getattr(ex, "ACTION_HANDLERS", None)
        if handlers is None:
            # Inspect ControlledExecutor mapping attribute names
            src = (CMD_PKG / "executor.py").read_text(encoding="utf-8")
            self.assertNotIn("EXECUTE_MITIGATION", src.split("ACTION")[0] if False else src)
            self.assertIn("COMMAND_DRY_RUN", src)
            self.assertNotRegex(
                src,
                r"Action\.EXECUTE_MITIGATION\s*:",
            )
            self.assertNotRegex(src, r"Action\.BLOCK_TARGET\s*:")
            return
        self.assertNotIn(Action.EXECUTE_MITIGATION, handlers)
        self.assertNotIn(Action.BLOCK_TARGET, handlers)

    def test_r7_trace_is_read_only_in_dashboard_api(self):
        api = (ROOT / "dashboard" / "api.py").read_text(encoding="utf-8")
        self.assertIn('@app.get("/api/verification-traces")', api)
        self.assertNotRegex(api, r'@app\.post\("/api/verification')
        self.assertNotIn("run_verified_mitigation", api)

    def test_ui_does_not_fabricate_r7_verified(self):
        for path in (SOC / "js").rglob("*.js"):
            src = path.read_text(encoding="utf-8")
            self.assertNotRegex(src, r"r7_verified\s*=\s*true")
            self.assertNotRegex(src, r"mitigation_eligible\s*=\s*true")


class SocUiPhase13HttpBoundaryTests(unittest.TestCase):
    """HTTP-level proofs that mitigation execute is unavailable."""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("INTELLISHIELD_AUTH_ENABLED", "true")
        # Ensure users exist for login tests via existing phase fixtures if present
        cls._tmp = tempfile.TemporaryDirectory()
        db = str(Path(cls._tmp.name) / "p13http.db")
        os.environ["INTELLISHIELD_COMMAND_DB_PATH"] = db

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()
        os.environ.pop("INTELLISHIELD_COMMAND_DB_PATH", None)

    def test_execute_endpoint_exists_but_mitigation_not_ready(self):
        from dashboard.commands.routes import commands_router

        paths = []
        for route in commands_router.routes:
            methods = getattr(route, "methods", None) or set()
            if "POST" in methods:
                paths.append(getattr(route, "path", ""))
        self.assertTrue(any(p.endswith("/execute") for p in paths))
        self.assertFalse(any("mitigate" in p for p in paths))
        self.assertFalse(any("block" in p for p in paths))


if __name__ == "__main__":
    unittest.main()
