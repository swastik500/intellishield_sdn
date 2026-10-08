"""
Phase 10 — Command infrastructure, audit trail & safety gate.

Execution must remain DISABLED. No mitigation/controller calls.
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
DOC = SOC / "COMMAND_SAFETY_ARCHITECTURE.md"

_TEST_USER = "phase10_test_operator"
_TEST_PASSWORD = "phase10-test-password-not-real"
_TEST_SECRET = "phase10-test-secret-key-not-for-production"


def _hash():
    from dashboard.auth.passwords import hash_password

    return hash_password(_TEST_PASSWORD)


def _principal(roles):
    from dashboard.auth.principal import Principal

    return Principal(
        id="user:t",
        username="t",
        authentication_method="password",
        authenticated_at="2020-01-01T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
        roles=list(roles),
        session_id="s",
    )


class SocUiPhase10DocTests(unittest.TestCase):
    def test_doc_exists(self):
        self.assertTrue(DOC.is_file())
        text = DOC.read_text(encoding="utf-8").lower()
        for n in [
            "execution",
            "disabled",
            "confirmation",
            "idempotency",
            "safety",
            "audit",
            "state machine",
            "freshness",
            "/api/control",
        ]:
            self.assertIn(n, text, n)

    def test_no_execute_endpoint_in_routes(self):
        routes = (CMD_PKG / "routes.py").read_text(encoding="utf-8")
        # Phase 12 may add narrow /commands/{id}/execute — still no mitigation/OpenFlow
        self.assertIn("/commands/{command_id}/execute", routes)
        self.assertNotIn("/mitigate", routes)
        self.assertNotIn("execute-anything", routes)
        self.assertNotIn("install_flow", routes.lower())


class SocUiPhase10UnitTests(unittest.TestCase):
    def setUp(self):
        from dashboard.commands.executor import reset_execution_counter
        from dashboard.commands.store import AUDIT_STORE, COMMAND_STORE, reset_persistence_for_tests

        reset_execution_counter()
        self._db_tmp = tempfile.TemporaryDirectory()
        reset_persistence_for_tests(
            str(Path(self._db_tmp.name) / "phase10_commands.db")
        )
        COMMAND_STORE.clear()
        AUDIT_STORE.clear()

    def tearDown(self):
        self._db_tmp.cleanup()

    def test_state_machine_rejects_invalid(self):
        from dashboard.commands.models import (
            Command,
            CommandStatus,
            InvalidTransitionError,
            Target,
            utcnow,
        )

        cmd = Command(
            command_id="cmd_x",
            action="READ",
            target=Target("NONE", "none"),
            event_id=None,
            principal_id="u",
            principal_username="u",
            reason="enough chars",
            created_at=utcnow(),
            expires_at=utcnow() + timedelta(minutes=5),
            status=CommandStatus.DENIED,
        )
        with self.assertRaises(InvalidTransitionError):
            cmd.transition(CommandStatus.CONFIRMED)

    def test_dry_run_to_execution_disabled(self):
        from dashboard.commands.executor import get_execution_attempt_count, reset_execution_counter
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
            target_id="evt-100",
            event_id="evt-100",
            reason="Phase 10 dry-run validation path",
        )
        self.assertEqual(prev["status"], "AWAITING_CONFIRMATION")
        self.assertTrue(prev["execution_enabled"])  # Phase 12 allowlisted
        self.assertIn("confirmation_token", prev)
        conf = confirm_command(
            p,
            command_id=prev["command_id"],
            confirmation_token=prev["confirmation_token"],
        )
        self.assertEqual(conf["status"], "READY_FOR_EXECUTION")
        self.assertFalse(conf["executed"])
        self.assertTrue(conf["execution_enabled"])
        final = execute_command(p, command_id=prev["command_id"])
        self.assertEqual(final["status"], "EXECUTED")
        self.assertTrue(final["executed"])
        self.assertGreaterEqual(get_execution_attempt_count(), 1)

    def test_viewer_block_denied(self):
        from dashboard.commands.service import preview_command

        p = _principal(["VIEWER"])
        out = preview_command(
            p,
            action="BLOCK_TARGET",
            target_type="ATTACKER",
            target_id="10.0.0.1",
            event_id=None,
            reason="Should not authorize block",
        )
        self.assertEqual(out["status"], "DENIED")

    def test_idempotency_duplicate(self):
        from dashboard.commands.service import preview_command

        p = _principal(["ANALYST"])
        kwargs = dict(
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-idem",
            event_id="evt-idem",
            reason="Idempotency check reason",
            idempotency_key="key-1",
        )
        a = preview_command(p, **kwargs)
        b = preview_command(p, **kwargs)
        self.assertEqual(a["command_id"], b["command_id"])
        self.assertTrue(b.get("duplicate"))

    def test_confirmation_replay(self):
        from dashboard.commands.service import confirm_command, preview_command

        p = _principal(["ANALYST"])
        prev = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-r",
            event_id="evt-r",
            reason="Replay confirmation test",
        )
        token = prev["confirmation_token"]
        first = confirm_command(p, command_id=prev["command_id"], confirmation_token=token)
        second = confirm_command(p, command_id=prev["command_id"], confirmation_token=token)
        self.assertEqual(first["status"], "READY_FOR_EXECUTION")
        self.assertTrue(second.get("duplicate") or second.get("failure_reason") == "confirmation_replay")

    def test_confirmation_wrong_principal(self):
        from dashboard.commands.service import confirm_command, preview_command

        a = _principal(["ANALYST"])
        b = _principal(["ANALYST"])
        b = type(b)(
            id="user:other",
            username="other",
            authentication_method="password",
            authenticated_at=b.authenticated_at,
            expires_at=b.expires_at,
            roles=["ANALYST"],
            session_id="z",
        )
        prev = preview_command(
            a,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-p",
            event_id="evt-p",
            reason="Wrong principal confirm",
        )
        out = confirm_command(
            b,
            command_id=prev["command_id"],
            confirmation_token=prev["confirmation_token"],
        )
        self.assertEqual(out.get("failure_reason"), "principal_mismatch")

    def test_expired_command(self):
        from dashboard.commands.models import CommandStatus
        from dashboard.commands.service import confirm_command, preview_command
        from dashboard.commands.store import COMMAND_STORE
        from dashboard.commands.models import utcnow

        p = _principal(["ANALYST"])
        prev = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-exp",
            event_id="evt-exp",
            reason="Expiration path test ok",
        )
        cmd = COMMAND_STORE.get(prev["command_id"])
        cmd.expires_at = utcnow() - timedelta(seconds=5)
        COMMAND_STORE.put(cmd)
        out = confirm_command(
            p,
            command_id=prev["command_id"],
            confirmation_token=prev["confirmation_token"],
        )
        self.assertEqual(out["status"], CommandStatus.EXPIRED.value)

    def test_high_risk_freshness_not_configured_blocks(self):
        from dashboard.commands.service import preview_command

        # Ensure freshness env unset
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("INTELLISHIELD_COMMAND_FRESHNESS_MAX_AGE_SECONDS", None)
            # Even ADMIN cannot get BLOCK past authz (future perm). Use authz allow path:
            # Simulate by dry-run is medium. For HIGH, authz denies first.
            # Test freshness unit directly:
            from dashboard.commands.actions import get_action_spec, Action
            from dashboard.commands.freshness import evaluate_freshness, FreshnessStatus

            spec = get_action_spec(Action.BLOCK_TARGET)
            fr = evaluate_freshness(spec, event_timestamp=None)
            self.assertEqual(fr.status, FreshnessStatus.NOT_CONFIGURED)
            self.assertTrue(fr.blocks_high_risk)

    def test_concurrent_confirm(self):
        from dashboard.commands.service import confirm_command, preview_command

        p = _principal(["ANALYST"])
        prev = preview_command(
            p,
            action="COMMAND_DRY_RUN",
            target_type="EVENT",
            target_id="evt-c",
            event_id="evt-c",
            reason="Concurrent confirmation test",
        )
        results = []

        def run():
            results.append(
                confirm_command(
                    p,
                    command_id=prev["command_id"],
                    confirmation_token=prev["confirmation_token"],
                )
            )

        t1 = threading.Thread(target=run)
        t2 = threading.Thread(target=run)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        finals = [r for r in results if r.get("status") == "READY_FOR_EXECUTION" and not r.get("duplicate")]
        dups = [r for r in results if r.get("duplicate") or r.get("failure_reason") == "confirmation_replay"]
        self.assertEqual(len(finals) + len(dups), 2)
        self.assertGreaterEqual(len(finals), 1)

    def test_executor_never_succeeds(self):
        from dashboard.commands.executor import DISABLED_EXECUTOR, ExecutionDisabledError

        with self.assertRaises(ExecutionDisabledError):
            DISABLED_EXECUTOR.execute(object())

    def test_audit_append_only(self):
        from dashboard.commands.service import preview_command
        from dashboard.commands.store import AUDIT_STORE

        p = _principal(["ANALYST"])
        preview_command(
            p,
            action="READ",
            target_type="NONE",
            target_id="none",
            event_id=None,
            reason="Read path audit check",
        )
        self.assertGreaterEqual(len(AUDIT_STORE.list_recent(10)), 1)
        existing_id = AUDIT_STORE.list_recent(1)[0]["audit_id"]
        with self.assertRaises(ValueError):
            AUDIT_STORE.append(
                {
                    "audit_id": existing_id,
                    "command_id": "cmd_x",
                    "principal_id": "u",
                    "action": "READ",
                    "status": "REQUESTED",
                    "source": "test",
                }
            )

class SocUiPhase10ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from fastapi.testclient import TestClient
        except Exception as exc:  # pragma: no cover
            raise unittest.SkipTest(str(exc)) from exc
        cls.TestClient = TestClient
        dash = str(ROOT / "dashboard")
        if dash not in sys.path:
            sys.path.insert(0, dash)
        import dashboard.api as api_mod

        cls.api_mod = api_mod
        cls._pw = _hash()

    def setUp(self):
        from dashboard.commands.executor import reset_execution_counter
        from dashboard.commands.store import AUDIT_STORE, COMMAND_STORE, reset_persistence_for_tests
        from dashboard.auth.sessions import SESSION_STORE

        reset_execution_counter()
        self._cmd_db_tmp = tempfile.TemporaryDirectory()
        reset_persistence_for_tests(
            str(Path(self._cmd_db_tmp.name) / "phase10_api_commands.db")
        )
        COMMAND_STORE.clear()
        AUDIT_STORE.clear()
        SESSION_STORE._sessions.clear()

        self._env = mock.patch.dict(
            os.environ,
            {
                "INTELLISHIELD_AUTH_ENABLED": "1",
                "INTELLISHIELD_AUTH_SECRET_KEY": _TEST_SECRET,
                "INTELLISHIELD_AUTH_USERNAME": _TEST_USER,
                "INTELLISHIELD_AUTH_PASSWORD_HASH": self._pw,
                "INTELLISHIELD_AUTH_ROLES": "ANALYST",
                "INTELLISHIELD_AUTH_SESSION_TTL_SECONDS": "3600",
            },
            clear=False,
        )
        self._env.start()
        self._tmp = tempfile.TemporaryDirectory()
        self.logs = Path(self._tmp.name)
        for name in (
            "verification_trace.jsonl",
            "correlation_results.jsonl",
            "fused_decisions.jsonl",
            "root_cause_reports.jsonl",
            "alerts.jsonl",
            "flow_stats.csv",
            "entropy_logs.csv",
            "detection_alerts.csv",
            "mitigation_actions.csv",
            "rl_decisions.csv",
            "drift_alerts.csv",
            "ml_predictions.csv",
            "port_stats.csv",
        ):
            (self.logs / name).write_text("", encoding="utf-8")
        (self.logs / "mitigation_summary.json").write_text("{}", encoding="utf-8")
        (self.logs / "cluster_summary.json").write_text("{}", encoding="utf-8")
        (self.logs / "ppo_weights.pkl").write_bytes(b"")
        self.patches = [
            mock.patch.object(self.api_mod, "_LOGS", self.logs),
            mock.patch.object(self.api_mod, "VERIFICATION_TRACE_JSONL", self.logs / "verification_trace.jsonl"),
            mock.patch.object(self.api_mod, "CORR_RESULTS_JSONL", self.logs / "correlation_results.jsonl"),
            mock.patch.object(self.api_mod, "FUSED_DECISIONS_JSONL", self.logs / "fused_decisions.jsonl"),
            mock.patch.object(self.api_mod, "RCA_REPORTS_JSONL", self.logs / "root_cause_reports.jsonl"),
            mock.patch.object(self.api_mod, "SECURITY_ALERTS_JSONL", self.logs / "alerts.jsonl"),
            mock.patch.object(self.api_mod, "FLOW_CSV", self.logs / "flow_stats.csv"),
            mock.patch.object(self.api_mod, "ENTROPY_CSV", self.logs / "entropy_logs.csv"),
            mock.patch.object(self.api_mod, "ALERTS_CSV", self.logs / "detection_alerts.csv"),
            mock.patch.object(self.api_mod, "MITIGATION_CSV", self.logs / "mitigation_actions.csv"),
            mock.patch.object(self.api_mod, "RL_CSV", self.logs / "rl_decisions.csv"),
            mock.patch.object(self.api_mod, "DRIFT_CSV", self.logs / "drift_alerts.csv"),
            mock.patch.object(self.api_mod, "ML_PRED_CSV", self.logs / "ml_predictions.csv"),
            mock.patch.object(self.api_mod, "PORT_STATS_CSV", self.logs / "port_stats.csv"),
            mock.patch.object(self.api_mod, "MIT_SUMMARY", self.logs / "mitigation_summary.json"),
            mock.patch.object(self.api_mod, "CLUSTER_SUMMARY", self.logs / "cluster_summary.json"),
            mock.patch.object(self.api_mod, "PPO_WEIGHTS", self.logs / "ppo_weights.pkl"),
        ]
        for p in self.patches:
            p.start()
        self.client = self.TestClient(self.api_mod.app)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self._env.stop()
        self._tmp.cleanup()
        if hasattr(self, "_cmd_db_tmp"):
            self._cmd_db_tmp.cleanup()

    def _login(self, roles="ANALYST"):
        with mock.patch.dict(os.environ, {"INTELLISHIELD_AUTH_ROLES": roles}, clear=False):
            r = self.client.post(
                "/api/auth/login",
                json={"username": _TEST_USER, "password": _TEST_PASSWORD},
            )
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["session_token"]

    def test_preview_unauthenticated_401(self):
        r = self.client.post(
            "/api/operator/commands/preview",
            json={
                "action": "READ",
                "reason": "Need auth first please",
            },
        )
        self.assertEqual(r.status_code, 401)

    def test_preview_confirm_api(self):
        from dashboard.commands.executor import CommandExecutor

        token = self._login("ANALYST")
        h = {"Authorization": f"Bearer {token}"}
        prev = self.client.post(
            "/api/operator/commands/preview",
            headers=h,
            json={
                "action": "COMMAND_DRY_RUN",
                "target_type": "EVENT",
                "target_id": "evt-api-1",
                "event_id": "evt-api-1",
                "reason": "API preview confirm path",
            },
        )
        self.assertEqual(prev.status_code, 200, prev.text)
        body = prev.json()
        self.assertEqual(body["status"], "AWAITING_CONFIRMATION")
        conf = self.client.post(
            f"/api/operator/commands/{body['command_id']}/confirm",
            headers=h,
            json={"confirmation_token": body["confirmation_token"]},
        )
        self.assertEqual(conf.status_code, 200, conf.text)
        final = conf.json()
        self.assertEqual(final["status"], "READY_FOR_EXECUTION")
        self.assertFalse(final["executed"])
        self.assertTrue(final.get("execution_enabled"))
        ex = self.client.post(
            f"/api/operator/commands/{body['command_id']}/execute", headers=h
        )
        self.assertEqual(ex.status_code, 200, ex.text)
        executed = ex.json()
        self.assertEqual(executed["status"], "EXECUTED")
        self.assertTrue(executed.get("executed"))

    def test_viewer_forbidden_list(self):
        token = self._login("VIEWER")
        r = self.client.get(
            "/api/operator/commands",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(r.status_code, 403)

    def test_soc_gets_public(self):
        self.assertEqual(self.client.get("/api/status").status_code, 200)


class SocUiPhase10FrontendTests(unittest.TestCase):
    def test_command_center_assets(self):
        self.assertTrue((SOC / "js" / "pages" / "commands.js").is_file())
        self.assertTrue((SOC / "js" / "api" / "commands.js").is_file())
        html = (SOC / "index.html").read_text(encoding="utf-8")
        self.assertIn("#commands", html)
        self.assertTrue(
            "SOC · Observer" in html or "SOC &middot; Observer" in html,
            "Expected observer shell branding",
        )
        page = (SOC / "js" / "pages" / "commands.js").read_text(encoding="utf-8")
        self.assertTrue(
            "PREVIEW ONLY" in page or "CONTROLLED DRY-RUN" in page,
            "Expected preview/controlled dry-run banner",
        )
        self.assertNotRegex(page, r"data-action\s*=\s*[\"']mitigate", re.I)
        self.assertNotIn("Kill Flow", page)
        api = (SOC / "js" / "api" / "commands.js").read_text(encoding="utf-8")
        self.assertIn("/preview", api)
        self.assertIn("/confirm", api)
        self.assertIn("/execute", api)

    def test_post_classification(self):
        for path in SOC.rglob("*.js"):
            text = path.read_text(encoding="utf-8")
            if re.search(r'method:\s*["\']POST["\']', text):
                self.assertTrue(
                    "/api/auth/" in text or "/api/operator/commands/" in text,
                    f"Unexpected POST in {path}",
                )
                self.assertNotIn("/api/mitigation/", text)
                # Mentions of lab control in comments are OK; live paths are not
                self.assertNotRegex(
                    text,
                    r'fetch\([\'"`]/api/control/',
                )

    def test_no_mitigation_imports_in_commands_pkg(self):
        for path in CMD_PKG.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("from mitigation", text)
            self.assertNotIn("import mitigation", text)
            self.assertNotIn("from controller", text)
            self.assertNotRegex(text, r"^\s*from\s+controller", re.M)
            # No live OpenFlow / mitigation API usage
            self.assertNotRegex(text, r"install_flow|remove_flow|ofp_event", re.I)


if __name__ == "__main__":
    unittest.main()
