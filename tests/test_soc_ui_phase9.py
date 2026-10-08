"""
Phase 9 — Backend RBAC & Authorization Enforcement.

Verifies:
- Central role/permission mapping
- Fail-closed authorize()
- require_permission → 401 vs 403
- Future operational permissions remain DENY
- Client-forged roles/permissions cannot elevate
- SOC observational GETs remain public
- No operator control APIs
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SOC = ROOT / "dashboard" / "static" / "soc"
AUTH_PKG = ROOT / "dashboard" / "auth"
RBAC_DOC = SOC / "RBAC_AUTHORIZATION_ARCHITECTURE.md"

_TEST_USER = "phase9_test_operator"
_TEST_PASSWORD = "phase9-test-password-not-real"
_TEST_SECRET = "phase9-test-secret-key-not-for-production"


def _hash_for_tests():
    from dashboard.auth.passwords import hash_password

    return hash_password(_TEST_PASSWORD)


def _principal(roles, *, pid="user:t", username="t"):
    from dashboard.auth.principal import Principal

    return Principal(
        id=pid,
        username=username,
        authentication_method="password",
        authenticated_at="2020-01-01T00:00:00Z",
        expires_at="2099-01-01T00:00:00Z",
        roles=list(roles),
        session_id="sess-test",
    )


class SocUiPhase9DocTests(unittest.TestCase):
    def test_rbac_document(self):
        self.assertTrue(RBAC_DOC.is_file())
        text = RBAC_DOC.read_text(encoding="utf-8").lower()
        for needle in [
            "viewer",
            "analyst",
            "operator",
            "admin",
            "fail-closed",
            "401",
            "403",
            "execute_mitigation",
            "not enabled",
            "require_permission",
            "non-goals",
            "/api/control",
        ]:
            self.assertIn(needle, text, needle)

    def test_no_rbac_bypass_flags(self):
        banned = [
            "skip_authorization",
            "disable_rbac",
            "bypass_rbac",
            "allow_all",
            "DISABLE_AUTH",
            "BYPASS_AUTH",
            "AUTO_LOGIN",
        ]
        for path in AUTH_PKG.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            low = text.lower()
            for b in banned:
                self.assertNotIn(b.lower(), low, f"{b} in {path.name}")
            # No hardcoded superuser elevation API
            self.assertNotIn("is_admin = True", text)


class SocUiPhase9UnitTests(unittest.TestCase):
    def test_viewer_permissions(self):
        from dashboard.auth.authorization import authorize
        from dashboard.auth.permissions import Permission

        p = _principal(["VIEWER"])
        self.assertTrue(authorize(p, Permission.READ_DASHBOARD).allow)
        self.assertTrue(authorize(p, Permission.READ_REPORTS).allow)
        self.assertFalse(authorize(p, Permission.INVESTIGATE_EVENTS).allow)
        self.assertFalse(authorize(p, Permission.EXECUTE_MITIGATION).allow)

    def test_analyst_permissions(self):
        from dashboard.auth.authorization import authorize
        from dashboard.auth.permissions import Permission

        p = _principal(["ANALYST"])
        self.assertTrue(authorize(p, Permission.READ_REPORTS).allow)
        self.assertTrue(authorize(p, Permission.INVESTIGATE_EVENTS).allow)
        self.assertTrue(authorize(p, Permission.GENERATE_REPORTS).allow)
        self.assertFalse(authorize(p, Permission.EXECUTE_MITIGATION).allow)

    def test_operator_future_mitigation_denied(self):
        from dashboard.auth.authorization import AuthzReason, authorize
        from dashboard.auth.permissions import Permission

        p = _principal(["OPERATOR"])
        self.assertTrue(authorize(p, Permission.INVESTIGATE_EVENTS).allow)
        d = authorize(p, Permission.EXECUTE_MITIGATION)
        self.assertFalse(d.allow)
        self.assertEqual(d.reason, AuthzReason.POLICY_DENIED)
        self.assertFalse(authorize(p, Permission.BLOCK_TARGET).allow)
        self.assertFalse(authorize(p, Permission.UNBLOCK_TARGET).allow)

    def test_admin_not_superuser(self):
        from dashboard.auth.authorization import authorize
        from dashboard.auth.permissions import Permission

        p = _principal(["ADMIN"])
        self.assertTrue(authorize(p, Permission.READ_DASHBOARD).allow)
        self.assertTrue(authorize(p, Permission.INVESTIGATE_EVENTS).allow)
        self.assertFalse(authorize(p, Permission.MANAGE_RBAC).allow)
        self.assertFalse(authorize(p, Permission.MANAGE_CONFIGURATION).allow)
        self.assertFalse(authorize(p, Permission.EXECUTE_MITIGATION).allow)

    def test_unknown_role_fail_closed(self):
        from dashboard.auth.authorization import AuthzReason, authorize
        from dashboard.auth.permissions import Permission

        p = _principal(["UNKNOWN"])
        d = authorize(p, Permission.READ_DASHBOARD)
        self.assertFalse(d.allow)
        self.assertEqual(d.reason, AuthzReason.UNKNOWN_ROLE)

        # Mixed known + unknown → DENY
        p2 = _principal(["VIEWER", "UNKNOWN"])
        self.assertFalse(authorize(p2, Permission.READ_DASHBOARD).allow)

    def test_unknown_permission_deny(self):
        from dashboard.auth.authorization import AuthzReason, authorize

        p = _principal(["ADMIN"])
        d = authorize(p, "NOT_A_REAL_PERMISSION")
        self.assertFalse(d.allow)
        self.assertEqual(d.reason, AuthzReason.UNKNOWN_PERMISSION)

    def test_unauthenticated_deny(self):
        from dashboard.auth.authorization import AuthzReason, authorize
        from dashboard.auth.permissions import Permission

        d = authorize(None, Permission.READ_DASHBOARD)
        self.assertFalse(d.allow)
        self.assertEqual(d.reason, AuthzReason.UNAUTHENTICATED)

    def test_empty_roles_deny(self):
        from dashboard.auth.authorization import authorize
        from dashboard.auth.permissions import Permission

        self.assertFalse(authorize(_principal([]), Permission.READ_DASHBOARD).allow)

    def test_multi_role_union(self):
        from dashboard.auth.authorization import authorize
        from dashboard.auth.permissions import Permission

        # VIEWER alone cannot investigate; VIEWER+ANALYST can
        self.assertFalse(authorize(_principal(["VIEWER"]), Permission.INVESTIGATE_EVENTS).allow)
        self.assertTrue(
            authorize(_principal(["VIEWER", "ANALYST"]), Permission.INVESTIGATE_EVENTS).allow
        )

    def test_observer_maps_to_viewer(self):
        from dashboard.auth.authorization import authorize
        from dashboard.auth.permissions import Permission

        p = _principal(["observer"])
        self.assertTrue(authorize(p, Permission.READ_TRAFFIC).allow)
        self.assertFalse(authorize(p, Permission.INVESTIGATE_EVENTS).allow)

    def test_resource_context(self):
        from dashboard.auth.authorization import AuthzReason, authorize
        from dashboard.auth.permissions import Permission

        p = _principal(["ANALYST"])
        ok = authorize(
            p,
            Permission.INVESTIGATE_EVENTS,
            resource_type="event",
            resource_id="evt-1",
        )
        self.assertTrue(ok.allow)
        bad = authorize(
            p,
            Permission.INVESTIGATE_EVENTS,
            resource_type="  ",
            resource_id="evt-1",
        )
        self.assertFalse(bad.allow)
        self.assertEqual(bad.reason, AuthzReason.INVALID_CONTEXT)

    def test_invalid_auth_roles_config_defaults_viewer(self):
        from dashboard.auth.config import load_auth_config

        with mock.patch.dict(
            os.environ,
            {"INTELLISHIELD_AUTH_ROLES": "SUPERUSER,GOD"},
            clear=False,
        ):
            cfg = load_auth_config()
            self.assertEqual(cfg.roles, ["VIEWER"])


class SocUiPhase9ApiTests(unittest.TestCase):
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
        cls._pw_hash = _hash_for_tests()

    def setUp(self):
        from dashboard.auth.sessions import SESSION_STORE

        SESSION_STORE._sessions.clear()
        self._env = {
            "INTELLISHIELD_AUTH_ENABLED": "1",
            "INTELLISHIELD_AUTH_SECRET_KEY": _TEST_SECRET,
            "INTELLISHIELD_AUTH_USERNAME": _TEST_USER,
            "INTELLISHIELD_AUTH_PASSWORD_HASH": self._pw_hash,
            "INTELLISHIELD_AUTH_SESSION_TTL_SECONDS": "3600",
            "INTELLISHIELD_AUTH_ROLES": "VIEWER",
            "INTELLISHIELD_AUTH_LOGIN_MAX_ATTEMPTS": "50",
        }
        self._env_patch = mock.patch.dict(os.environ, self._env, clear=False)
        self._env_patch.start()

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
        self._env_patch.stop()
        self._tmp.cleanup()
        from dashboard.auth.sessions import SESSION_STORE

        SESSION_STORE._sessions.clear()

    def _login_as(self, roles: str):
        with mock.patch.dict(os.environ, {"INTELLISHIELD_AUTH_ROLES": roles}, clear=False):
            r = self.client.post(
                "/api/auth/login",
                json={"username": _TEST_USER, "password": _TEST_PASSWORD},
            )
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["session_token"]

    def test_unauthenticated_authorized_probe_401(self):
        r = self.client.get("/api/auth/authorized/dashboard")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"]["code"], "AUTHENTICATION_REQUIRED")

    def test_viewer_dashboard_allow_investigate_deny(self):
        token = self._login_as("VIEWER")
        h = {"Authorization": f"Bearer {token}"}
        ok = self.client.get("/api/auth/authorized/dashboard", headers=h)
        self.assertEqual(ok.status_code, 200)
        deny = self.client.get("/api/auth/authorized/investigate", headers=h)
        self.assertEqual(deny.status_code, 403)
        self.assertEqual(deny.json()["error"]["code"], "FORBIDDEN")

    def test_analyst_investigate_allow(self):
        token = self._login_as("ANALYST")
        h = {"Authorization": f"Bearer {token}"}
        self.assertEqual(
            self.client.get("/api/auth/authorized/investigate", headers=h).status_code,
            200,
        )

    def test_operator_execute_mitigation_check_403(self):
        token = self._login_as("OPERATOR")
        h = {"Authorization": f"Bearer {token}"}
        r = self.client.get(
            "/api/auth/authorization/check",
            params={"permission": "EXECUTE_MITIGATION"},
            headers=h,
        )
        self.assertEqual(r.status_code, 403)

    def test_admin_manage_rbac_403(self):
        token = self._login_as("ADMIN")
        h = {"Authorization": f"Bearer {token}"}
        r = self.client.get(
            "/api/auth/authorization/check",
            params={"permission": "MANAGE_RBAC"},
            headers=h,
        )
        self.assertEqual(r.status_code, 403)

    def test_forged_role_in_login_body_ignored(self):
        token = self._login_as("VIEWER")
        # Re-login attempting elevation
        r = self.client.post(
            "/api/auth/login",
            json={
                "username": _TEST_USER,
                "password": _TEST_PASSWORD,
                "role": "ADMIN",
                "roles": ["ADMIN"],
                "permissions": ["EXECUTE_MITIGATION"],
            },
        )
        self.assertEqual(r.status_code, 200)
        roles = r.json()["principal"]["roles"]
        self.assertEqual(roles, ["VIEWER"])
        self.assertNotIn("EXECUTE_MITIGATION", r.json().get("permissions") or [])

    def test_forged_x_role_header_no_elevation(self):
        token = self._login_as("VIEWER")
        r = self.client.get(
            "/api/auth/authorized/investigate",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Role": "ADMIN",
                "X-Permissions": "INVESTIGATE_EVENTS",
            },
        )
        self.assertEqual(r.status_code, 403)

    def test_forged_role_query_no_elevation(self):
        token = self._login_as("VIEWER")
        r = self.client.get(
            "/api/auth/authorized/investigate?role=ADMIN&permission=INVESTIGATE_EVENTS",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(r.status_code, 403)

    def test_authorization_summary_401_then_200(self):
        self.assertEqual(self.client.get("/api/auth/authorization").status_code, 401)
        token = self._login_as("ANALYST")
        r = self.client.get(
            "/api/auth/authorization",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["authorization_implemented"])
        self.assertIn("INVESTIGATE_EVENTS", body["permissions"])
        self.assertFalse(body["operator_controls_enabled"])

    def test_soc_gets_still_public(self):
        for path in ("/api/status", "/api/summary", "/api/traffic?n=5"):
            self.assertEqual(self.client.get(path).status_code, 200, path)

    def test_me_includes_permissions(self):
        token = self._login_as("VIEWER")
        me = self.client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        ).json()
        self.assertTrue(me["authorization_implemented"])
        self.assertIn("READ_DASHBOARD", me["permissions"])
        self.assertNotIn("EXECUTE_MITIGATION", me["permissions"])

    def test_unknown_permission_check_403(self):
        token = self._login_as("ADMIN")
        r = self.client.get(
            "/api/auth/authorization/check",
            params={"permission": "TOTALLY_FAKE"},
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(r.status_code, 403)

    def test_cross_user_payload_cannot_impersonate(self):
        token = self._login_as("VIEWER")
        r = self.client.get(
            "/api/auth/authorization",
            headers={"Authorization": f"Bearer {token}"},
            params={"user_id": "admin", "username": "admin"},
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["principal"]["username"], _TEST_USER)
        self.assertNotEqual(r.json()["principal"]["id"], "admin")


class SocUiPhase9FrontendTests(unittest.TestCase):
    def test_phase9_shell_and_readiness(self):
        html = (SOC / "index.html").read_text(encoding="utf-8")
        self.assertIn("SOC · Observer", html)
        self.assertNotRegex(html, r"Phase\s+\d+\s+Observer")
        ready = (SOC / "js" / "utils" / "operator_readiness.js").read_text(encoding="utf-8")
        self.assertIn("RBAC", ready)
        self.assertIn("Mitigation", ready)
        self.assertIn("NOT ENABLED", ready)
        identity = (SOC / "js" / "utils" / "identity.js").read_text(encoding="utf-8")
        self.assertIn("RBAC ENABLED", identity)
        self.assertIn("NOT ENABLED", identity)

    def test_no_control_apis_in_soc(self):
        for path in SOC.rglob("*.js"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("/api/mitigation/block", text)
            if "/execute" in text:
                self.assertIn("/api/operator/commands/", text)
            if re.search(r'method:\s*["\']POST["\']', text):
                self.assertTrue(
                    "/api/auth/" in text or "/api/operator/commands/" in text,
                    f"Unexpected POST in {path}",
                )


class SocUiPhase9ProtectedPackages(unittest.TestCase):
    def test_no_protected_package_authz(self):
        for pkg in (
            "controller",
            "entropy_engine",
            "ml_models",
            "correlation",
            "fusion",
            "verification",
            "mitigation",
            "rca",
            "xai",
            "alerting",
            "twin",
        ):
            p = ROOT / pkg
            if not p.is_dir():
                continue
            for f in p.rglob("*require_permission*"):
                self.fail(f"Unexpected authz file in {pkg}: {f}")


if __name__ == "__main__":
    unittest.main()
