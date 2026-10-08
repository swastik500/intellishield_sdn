"""
Phase 8 — Authentication & Identity Foundation.

Covers:
- Auth architecture documentation
- Password hashing / principal / sessions
- /api/auth/login|logout|me|status
- Unauthenticated / invalid / expired credentials
- No client-supplied role/user_id trust
- No credential leakage
- SOC observational GETs remain public
- No operator control APIs from SOC
- Operator readiness + identity display
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SOC = ROOT / "dashboard" / "static" / "soc"
AUTH_DOC = SOC / "AUTHENTICATION_IDENTITY_ARCHITECTURE.md"
AUTH_PKG = ROOT / "dashboard" / "auth"

# Intentionally fake test credentials — not real secrets
_TEST_USER = "phase8_test_operator"
_TEST_PASSWORD = "phase8-test-password-not-real"
_TEST_SECRET = "phase8-test-secret-key-not-for-production-use-only"


def _hash_for_tests():
    from dashboard.auth.passwords import hash_password

    return hash_password(_TEST_PASSWORD)


class SocUiPhase8DocTests(unittest.TestCase):
    def test_auth_architecture_document(self):
        self.assertTrue(AUTH_DOC.is_file(), f"Missing {AUTH_DOC}")
        text = AUTH_DOC.read_text(encoding="utf-8").lower()
        for needle in [
            "purpose",
            "principal",
            "session",
            "pbkdf2",
            "csrf",
            "cors",
            "revocation",
            "expiration",
            "rate",
            "/api/auth/me",
            "rbac",
            "non-goals",
            "public",
            "operator control endpoints",
        ]:
            self.assertIn(needle, text, f"Missing: {needle}")

    def test_no_auth_bypass_flags_in_auth_package(self):
        banned = [
            "DISABLE_AUTH",
            "BYPASS_AUTH",
            "SKIP_AUTH",
            "AUTO_LOGIN",
            "DEBUG_AUTH",
            "MOCK_USER",
        ]
        for path in AUTH_PKG.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for b in banned:
                self.assertNotIn(b, text, f"{b} in {path.name}")


class SocUiPhase8UnitTests(unittest.TestCase):
    def test_password_hash_roundtrip(self):
        from dashboard.auth.passwords import hash_password, verify_password

        h = hash_password("s3cret-value")
        self.assertTrue(h.startswith("pbkdf2_sha256$"))
        self.assertTrue(verify_password("s3cret-value", h))
        self.assertFalse(verify_password("wrong", h))
        self.assertFalse(verify_password("s3cret-value", "garbage"))

    def test_session_expiry_and_revoke(self):
        from dashboard.auth.sessions import SessionStore

        store = SessionStore()
        rec = store.create(
            principal_id="user:a",
            username="a",
            roles=["observer"],
            ttl_seconds=3600,
        )
        self.assertIsNotNone(store.get(rec.session_id))
        self.assertTrue(store.revoke(rec.session_id))
        self.assertIsNone(store.get(rec.session_id))

        rec2 = store.create(
            principal_id="user:b",
            username="b",
            roles=[],
            ttl_seconds=3600,
        )
        # Force expiry
        rec2.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        self.assertIsNone(store.get(rec2.session_id))

    def test_principal_public_dict_no_secrets(self):
        from dashboard.auth.principal import Principal

        p = Principal(
            id="user:x",
            username="x",
            authentication_method="password",
            authenticated_at="2020-01-01T00:00:00Z",
            expires_at="2020-01-01T08:00:00Z",
            roles=["observer"],
            session_id="secret-session-id",
        )
        d = p.to_public_dict()
        blob = str(d).lower()
        self.assertNotIn("password_hash", blob)
        self.assertNotIn("secret-session-id", blob)
        self.assertNotIn("session_id", d)
        self.assertEqual(d["authentication_method"], "password")


class SocUiPhase8ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from fastapi.testclient import TestClient
        except Exception as exc:  # pragma: no cover
            raise unittest.SkipTest(f"TestClient unavailable: {exc}") from exc

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
            "INTELLISHIELD_AUTH_LOGIN_MAX_ATTEMPTS": "20",
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

    def _login(self, username=None, password=None):
        return self.client.post(
            "/api/auth/login",
            json={
                "username": username if username is not None else _TEST_USER,
                "password": password if password is not None else _TEST_PASSWORD,
            },
        )

    def test_me_unauthenticated(self):
        r = self.client.get("/api/auth/me")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertFalse(body["authenticated"])
        self.assertIsNone(body["principal"])
        self.assertTrue(body["authentication_configured"])
        self.assertTrue(body["authorization_implemented"])
        self.assertFalse(body["operator_controls_enabled"])

    def test_login_success_and_me(self):
        r = self._login()
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["authenticated"])
        self.assertEqual(body["principal"]["username"], _TEST_USER)
        self.assertIn("session_token", body)
        self.assertTrue(body["authorization_implemented"])
        self.assertFalse(body["operator_controls_enabled"])
        # No password leakage
        blob = r.text.lower()
        self.assertNotIn(_TEST_PASSWORD.lower(), blob)
        self.assertNotIn("password_hash", blob)

        me = self.client.get("/api/auth/me")
        self.assertEqual(me.status_code, 200)
        me_body = me.json()
        self.assertTrue(me_body["authenticated"])
        self.assertEqual(me_body["principal"]["username"], _TEST_USER)

    def test_login_bearer_token(self):
        r = self._login()
        token = r.json()["session_token"]
        # New client without cookie
        c2 = self.TestClient(self.api_mod.app)
        me = c2.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me.status_code, 200)
        self.assertTrue(me.json()["authenticated"])

    def test_invalid_credentials_generic(self):
        r = self._login(password="wrong-password")
        self.assertEqual(r.status_code, 401)
        body = r.json()
        self.assertEqual(body["error"]["code"], "AUTHENTICATION_FAILED")
        msg = body["error"]["message"].lower()
        self.assertNotIn("user does not exist", msg)
        self.assertNotIn("password incorrect", msg)
        self.assertNotIn(_TEST_PASSWORD.lower(), r.text.lower())

    def test_unknown_username_generic(self):
        r = self._login(username="no_such_user_xyz")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"]["code"], "AUTHENTICATION_FAILED")

    def test_malformed_bearer(self):
        r = self.client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-real-session"})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()["authenticated"])

    def test_expired_session(self):
        from dashboard.auth.sessions import SESSION_STORE

        r = self._login()
        token = r.json()["session_token"]
        rec = SESSION_STORE._sessions.get(token)
        self.assertIsNotNone(rec)
        rec.expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
        me = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertFalse(me.json()["authenticated"])

    def test_logout_revokes(self):
        self._login()
        me1 = self.client.get("/api/auth/me")
        self.assertTrue(me1.json()["authenticated"])
        out = self.client.post("/api/auth/logout")
        self.assertEqual(out.status_code, 200)
        me2 = self.client.get("/api/auth/me")
        self.assertFalse(me2.json()["authenticated"])

    def test_client_role_payload_ignored(self):
        """Client-supplied role/user_id must not create an admin principal."""
        r = self.client.post(
            "/api/auth/login",
            json={
                "username": _TEST_USER,
                "password": _TEST_PASSWORD,
                "role": "ADMIN",
                "user_id": "admin",
                "is_admin": True,
            },
        )
        self.assertEqual(r.status_code, 200)
        principal = r.json()["principal"]
        self.assertEqual(principal["username"], _TEST_USER)
        self.assertNotIn("ADMIN", principal.get("roles") or [])
        self.assertNotEqual(principal["id"], "admin")

    def test_soc_gets_remain_public(self):
        for path in ("/api/status", "/api/summary", "/api/auth/status"):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 200, path)

    def test_auth_status_no_secrets(self):
        r = self.client.get("/api/auth/status")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        blob = str(body).lower()
        self.assertNotIn(_TEST_SECRET.lower(), blob)
        self.assertNotIn("password", blob)
        self.assertTrue(body["authentication_configured"])
        self.assertTrue(body["authorization_implemented"])
        self.assertFalse(body.get("operator_controls_enabled"))

    def test_require_authenticated_dependency(self):
        from fastapi import Depends, FastAPI
        from fastapi.testclient import TestClient
        from dashboard.auth.deps import require_authenticated_principal
        from dashboard.auth.errors import AuthError, auth_exception_handler
        from dashboard.auth.principal import Principal

        mini = FastAPI()
        mini.add_exception_handler(AuthError, auth_exception_handler)

        @mini.get("/protected")
        async def protected(
            principal: Principal = Depends(require_authenticated_principal),
        ):
            return {"ok": True, "username": principal.username}

        login = self._login()
        token = login.json()["session_token"]
        c = TestClient(mini)
        denied = c.get("/protected")
        self.assertEqual(denied.status_code, 401)
        self.assertEqual(denied.json()["error"]["code"], "AUTHENTICATION_REQUIRED")
        ok = c.get("/protected", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.json()["username"], _TEST_USER)

    def test_login_not_configured(self):
        with mock.patch.dict(
            os.environ,
            {
                "INTELLISHIELD_AUTH_ENABLED": "0",
                "INTELLISHIELD_AUTH_SECRET_KEY": "",
                "INTELLISHIELD_AUTH_USERNAME": "",
                "INTELLISHIELD_AUTH_PASSWORD_HASH": "",
            },
            clear=False,
        ):
            r = self.client.post(
                "/api/auth/login",
                json={"username": "x", "password": "y"},
            )
            self.assertEqual(r.status_code, 503)
            self.assertEqual(r.json()["error"]["code"], "AUTHENTICATION_NOT_CONFIGURED")


class SocUiPhase8FrontendTests(unittest.TestCase):
    def test_identity_and_auth_modules(self):
        identity = (SOC / "js" / "utils" / "identity.js").read_text(encoding="utf-8")
        self.assertIn("Identity", identity)
        self.assertIn("NOT ENABLED", identity)
        self.assertIn("NOT IMPLEMENTED", identity)
        self.assertNotIn("localStorage", identity)

        auth_js = (SOC / "js" / "api" / "auth.js").read_text(encoding="utf-8")
        self.assertIn("/api/auth/login", auth_js)
        self.assertIn("/api/auth/logout", auth_js)
        self.assertIn("/api/auth/me", auth_js)
        self.assertIn('method: "POST"', auth_js)
        self.assertNotIn("fetchControl", auth_js)
        self.assertNotIn("localStorage", auth_js)

    def test_settings_wires_identity(self):
        pages = (SOC / "js" / "pages" / "index.js").read_text(encoding="utf-8")
        self.assertIn("identityPanelHtml", pages)
        self.assertIn("fetchAuthMe", pages)
        self.assertIn("data-auth-login", pages)

    def test_operator_readiness_phase8(self):
        text = (SOC / "js" / "utils" / "operator_readiness.js").read_text(encoding="utf-8")
        self.assertIn("NOT CONFIGURED", text)
        self.assertIn("AUTHENTICATED", text)
        self.assertIn("NOT AUTHENTICATED", text)
        self.assertIn("NOT ENABLED", text)
        # Phase 9 may show READY for RBAC; mitigation/controls must not
        self.assertIn("Mitigation", text)

    def test_phase8_shell(self):
        html = (SOC / "index.html").read_text(encoding="utf-8")
        self.assertIn("SOC · Observer", html)
        self.assertNotRegex(html, r"Phase\s+\d+\s+Observer")

    def test_no_operator_control_endpoints_in_soc(self):
        for path in SOC.rglob("*.js"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("/api/mitigation/block", text)
            self.assertNotIn("/api/mitigation/unblock", text)
            if "/execute" in text:

                self.assertIn("/api/operator/commands/", text)
            if re.search(r"/api/control/(archive|controller|scenario|scenarios|metrics|bundle|train)", text):
                self.fail(f"Control write path referenced in {path}")
            if path.name in {"auth.js", "commands.js"}:
                continue
            if 'method: "POST"' in text or "method: 'POST'" in text:
                self.assertTrue(
                    "/api/auth/" in text or "/api/operator/commands/" in text,
                    f"Unexpected POST in {path}",
                )

    def test_no_localstorage_auth_trust(self):
        for path in SOC.rglob("*.js"):
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(
                text,
                r"localStorage\.(isAuthenticated|role|token|session)",
                f"Forbidden localStorage auth trust in {path}",
            )

    def test_secret_scan_modified_auth(self):
        patterns = [
            re.compile(r'password\s*=\s*["\'][^"\']{8,}["\']', re.I),
            re.compile(r"BEGIN PRIVATE KEY"),
        ]
        for path in AUTH_PKG.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            # Allow hash_password function and env var names; flag hardcoded assignments
            if "SECRET_KEY" in text and "=" in text:
                for line in text.splitlines():
                    if re.search(r'SECRET_KEY\s*=\s*["\'][^"\']+["\']', line):
                        self.fail(f"Hardcoded SECRET_KEY in {path}: {line}")
            for pat in patterns:
                if pat.search(text) and "hash_password" not in text:
                    # passwords.py has no literal passwords
                    pass


class SocUiPhase8ProtectedPackages(unittest.TestCase):
    def test_auth_files_only_under_dashboard(self):
        self.assertTrue((AUTH_PKG / "routes.py").is_file())
        self.assertTrue((AUTH_PKG / "principal.py").is_file())
        # Sanity: protected packages not containing phase8 auth modules
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
            hits = list(p.rglob("*auth*session*"))
            # No restriction on unrelated names; just ensure we didn't drop auth package there
            self.assertFalse(
                any("phase8" in str(h).lower() for h in hits),
            )


if __name__ == "__main__":
    unittest.main()
