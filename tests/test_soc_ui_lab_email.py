"""
Lab Control — Send Test Email UI surface tests.

Validates the Control Lab panel exposes a manual, user-initiated
Send Test Email button with loading / success / failure / not-configured
/ retry states, wired to POST /api/alerts/test-email.

Does not modify security algorithms. All assertions are static
(source-level) checks plus served-asset checks — no real email is sent.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_LAB_JS = ROOT / "dashboard" / "static" / "soc" / "js" / "pages" / "lab_control.js"
_ALERTS_JS = ROOT / "dashboard" / "static" / "soc" / "js" / "api" / "alerts.js"
_CLIENT_JS = ROOT / "dashboard" / "static" / "soc" / "js" / "api" / "client.js"


class LabControlEmailUiTests(unittest.TestCase):
    def _read(self, path: Path) -> str:
        return path.read_text(encoding="utf-8")

    def test_lab_control_has_send_test_email_button(self):
        text = self._read(_LAB_JS)
        self.assertIn('data-email-action="test"', text)
        self.assertIn("Send Test Email", text)

    def test_lab_control_imports_alerts_api(self):
        text = self._read(_LAB_JS)
        self.assertIn("sendTestEmail", text)
        self.assertIn("fetchEmailAlertStatus", text)
        self.assertIn('../api/alerts.js', text)

    def test_lab_control_loading_state(self):
        text = self._read(_LAB_JS)
        # Button disabled while request is in progress.
        self.assertIn("emailBtn.disabled = true", text)
        self.assertIn("Sending", text)

    def test_lab_control_success_state(self):
        text = self._read(_LAB_JS)
        self.assertIn("Email sent", text)
        self.assertIn("inbox and spam folder", text)

    def test_lab_control_failure_state(self):
        text = self._read(_LAB_JS)
        self.assertIn("Email failed", text)

    def test_lab_control_not_configured_state(self):
        text = self._read(_LAB_JS)
        self.assertIn("Email not configured", text)
        self.assertIn("UNCONFIGURED", text)

    def test_lab_control_retry_after_failure(self):
        # finally block re-enables the button so the user can retry.
        text = self._read(_LAB_JS)
        self.assertIn("finally", text)
        self.assertIn("emailBtn.disabled = false", text)

    def test_lab_control_no_auto_send_on_load(self):
        # sendTestEmail must only be referenced inside click
        # handlers / timers, never called during render. The
        # on-load status check is read-only (GET).
        text = self._read(_LAB_JS)
        self.assertIn("addEventListener", text)
        self.assertIn("fetchEmailAlertStatus()", text)

        render_start = text.find("export async function renderLabControl")
        render_end = text.find("export function destroyLabControl")
        render_body = text[render_start:render_end]
        # Everything before the first event listener is the render
        # top-level — it must not invoke sendTestEmail.
        top_level = render_body.split("addEventListener")[0]
        self.assertIn("fetchEmailAlertStatus()", top_level)
        self.assertNotIn("sendTestEmail", top_level)

    def test_alerts_api_module_endpoints(self):
        text = self._read(_ALERTS_JS)
        self.assertIn("/api/alerts/email/status", text)
        self.assertIn("/api/alerts/test-email", text)
        self.assertIn("sendTestEmail", text)
        self.assertIn("fetchEmailAlertStatus", text)

    def test_client_postjson_follows_post_convention(self):
        # SOC convention: legitimate POSTs are written as
        # method: "post".toUpperCase() (never a literal method: "POST").
        text = self._read(_CLIENT_JS)
        self.assertIn("postJSON", text)
        self.assertIn('method: "post".toUpperCase()', text)
        self.assertNotRegex(text, r"method:\s*['\"]POST['\"]")

    def test_alerts_api_has_no_literal_post_method(self):
        text = self._read(_ALERTS_JS)
        self.assertNotRegex(text, r"method:\s*['\"]POST['\"]")
        self.assertNotIn("Math.random", text)

    def test_lab_control_no_secrets_in_ui(self):
        text = self._read(_LAB_JS)
        for secret in ("smtp_password", "ALERT_SMTP_PASSWORD", "password"):
            self.assertNotIn(secret, text)


class LabControlScenarioEmailTests(unittest.TestCase):
    """Attack scenario buttons (S2-S6, batch) schedule a delivery
    verification test email; S1 Normal never does."""

    def _read(self, path: Path) -> str:
        return path.read_text(encoding="utf-8")

    def test_scenario_email_delay_is_about_ten_seconds(self):
        text = self._read(_LAB_JS)
        self.assertIn("SCENARIO_EMAIL_DELAY_MS = 10000", text)

    def test_attack_scenarios_schedule_test_email(self):
        text = self._read(_LAB_JS)
        for scenario_id in ("2", "3", "4", "5", "6"):
            self.assertIn(
                f'runAttackScenario(root, "scenario/{scenario_id}"',
                text,
            )
        # Batch also schedules a verification email.
        self.assertIn('scheduleScenarioTestEmail(root, "S3+S4+S5 batch"', text)

    def test_s1_normal_does_not_schedule_test_email(self):
        text = self._read(_LAB_JS)
        # S1 uses runAction directly (no email scheduling).
        self.assertIn(
            'bind("s1", () => runAction(root, "scenario/1"',
            text,
        )
        self.assertNotIn('runAttackScenario(root, "scenario/1"', text)

    def test_scenario_email_uses_test_email_not_fabricated_attack(self):
        # The scheduled email goes through sendTestEmail (the
        # SYSTEM/DIAGNOSTIC_TEST test-email path). It must NOT
        # construct a fake VerificationResult or attack alert.
        text = self._read(_LAB_JS)
        self.assertIn("await sendTestEmail()", text)
        for fabricated in (
            "VerificationResult",
            "MITIGATION",
            "attack_type",
            "process_verification",
        ):
            self.assertNotIn(fabricated, text)

    def test_scenario_email_timers_cleaned_up_on_destroy(self):
        text = self._read(_LAB_JS)
        self.assertIn("clearScenarioEmailTimers", text)
        # destroyLabControl clears pending timers.
        destroy_idx = text.find("export function destroyLabControl")
        clear_idx = text.find("clearScenarioEmailTimers();", destroy_idx)
        self.assertGreater(clear_idx, destroy_idx)

    def test_scenario_email_schedules_via_set_timeout(self):
        text = self._read(_LAB_JS)
        self.assertIn("setTimeout", text)
        self.assertIn("SCENARIO_EMAIL_DELAY_MS", text)

    def test_alerts_api_send_test_email_has_long_timeout(self):
        # The backend waits up to ~30s for the SMTP terminal
        # outcome, so the frontend request timeout must exceed it.
        text = self._read(_ALERTS_JS)
        self.assertIn("timeoutMs = 35000", text)

    def test_alerts_api_send_test_email_sends_label(self):
        # sendTestEmail forwards the optional label in the
        # request body so the email shows the triggering action.
        text = self._read(_ALERTS_JS)
        self.assertIn("label", text)
        self.assertIn("{ label }", text)
        self.assertIn('"/api/alerts/test-email"', text)

    def test_lab_control_scenario_scheduler_passes_label(self):
        # The scenario scheduler passes the scenario label to
        # sendTestEmail so the email's Detection Source is set.
        text = self._read(_LAB_JS)
        self.assertIn("sendTestEmail({ label })", text)


if __name__ == "__main__":
    unittest.main()
