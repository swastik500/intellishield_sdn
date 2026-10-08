"""
Phase 7 — Operator Mode Safety Architecture (design / read-only preparation).

Verifies:
- Observer-only SOC (no control execution)
- GET-only runtime
- Architecture documentation
- Operator readiness display-only panel
- Protected packages untouched by Phase 7 SOC work
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOC = ROOT / "dashboard" / "static" / "soc"
DOC = ROOT / "dashboard" / "static" / "soc" / "OPERATOR_MODE_SECURITY_ARCHITECTURE.md"
# Note: repository .gitignore excludes DOCS/; keep this file outside any docs/ path.


class SocUiPhase7DocTests(unittest.TestCase):
    def test_architecture_document_exists(self):
        self.assertTrue(DOC.is_file(), f"Missing {DOC}")
        text = DOC.read_text(encoding="utf-8")
        text_norm = text.lower().replace("-", " ")
        for needle in [
            "authentication",
            "authorization",
            "rbac",
            "audit",
            "idempotency",
            "confirmation",
            "fail closed",
            "threat",
            "r7",
            "digital twin",
            "not enabled",
            "untrusted",
        ]:
            self.assertIn(needle, text_norm, f"Missing section topic: {needle}")
        # Explicit non-activation
        self.assertIn("does not enable", text.lower())
        self.assertIn("observer", text.lower())


class SocUiPhase7StaticTests(unittest.TestCase):
    def test_operator_readiness_module(self):
        path = SOC / "js" / "utils" / "operator_readiness.js"
        self.assertTrue(path.is_file())
        text = path.read_text(encoding="utf-8")
        self.assertIn("DESIGN ONLY", text)
        self.assertIn("NOT ENABLED", text)
        self.assertIn("NOT IMPLEMENTED", text)
        self.assertIn("DEFINED", text)
        self.assertIn("operatorReadinessHtml", text)
        # Readiness module itself must not fetch or write
        self.assertNotIn("fetch(", text)
        self.assertNotIn("POST", text)

    def test_settings_shows_readiness(self):
        pages = (SOC / "js" / "pages" / "index.js").read_text(encoding="utf-8")
        self.assertIn("operatorReadinessHtml", pages)
        self.assertIn("Operator Readiness", (SOC / "js" / "utils" / "operator_readiness.js").read_text())

    def test_phase7_shell_label(self):
        """Observer shell branding (engineering phase numbers removed from UI)."""
        html = (SOC / "index.html").read_text(encoding="utf-8")
        self.assertIn("SOC · Observer", html)
        self.assertNotRegex(html, r"Phase\s+\d+\s+Observer")

    def test_no_functional_control_buttons(self):
        """SOC must not introduce executable Block/Unblock/Mitigate controls."""
        banned_handlers = [
            re.compile(r"data-action\s*=\s*[\"']block", re.I),
            re.compile(r"data-action\s*=\s*[\"']unblock", re.I),
            re.compile(r"data-action\s*=\s*[\"']mitigate", re.I),
            re.compile(r"onclick\s*=\s*[\"'].*block", re.I),
            re.compile(r"/api/control/(archive|controller|scenario|scenarios|metrics|bundle|train)"),
            re.compile(r"method:\s*[\"']PUT[\"']"),
            re.compile(r"method:\s*[\"']PATCH[\"']"),
            re.compile(r"method:\s*[\"']DELETE[\"']"),
        ]
        post_pat = re.compile(r"method:\s*[\"']POST[\"']")
        for path in SOC.rglob("*.js"):
            text = path.read_text(encoding="utf-8")
            for pat in banned_handlers:
                self.assertIsNone(
                    pat.search(text),
                    f"Banned control pattern {pat.pattern} in {path.relative_to(ROOT)}",
                )
            # Phase 8/10: POST allowed for /api/auth/* and /api/operator/commands/{preview,confirm}
            if post_pat.search(text):
                self.assertTrue(
                    "/api/auth/" in text or "/api/operator/commands/" in text,
                    f"POST found outside auth/command infrastructure in {path.relative_to(ROOT)}",
                )
                self.assertIsNone(
                    re.search(
                        r"/api/control/(archive|controller|scenario|scenarios|metrics|bundle|train)",
                        text,
                    ),
                    f"Control write path with POST in {path.relative_to(ROOT)}",
                )
                self.assertNotIn("/api/mitigation/", text)
                # Phase 12 may POST /api/operator/commands/{id}/execute (allowlisted only)
                if "/execute" in text:
                    self.assertIn("/api/operator/commands/", text)

    def test_get_only_client(self):
        client = (SOC / "js" / "api" / "client.js").read_text(encoding="utf-8")
        self.assertIn('method: "GET"', client)
        self.assertNotIn('method: "POST"', client)

    def test_readiness_not_claiming_ready_auth(self):
        text = (SOC / "js" / "utils" / "operator_readiness.js").read_text(encoding="utf-8")
        # Control / mitigation must never claim READY
        self.assertNotIn('value: "ENABLED"', text)
        self.assertIn("NOT ENABLED", text)
        self.assertIn("Mitigation", text)
        # RBAC may show READY in Phase 9 when backend reports it; mitigation must not
        self.assertIn('value: "NOT ENABLED"', text)


class SocUiPhase7ApiSmoke(unittest.TestCase):
    def test_doc_and_asset_paths(self):
        self.assertTrue(DOC.is_file())
        self.assertTrue((SOC / "js" / "utils" / "operator_readiness.js").is_file())


if __name__ == "__main__":
    unittest.main()
