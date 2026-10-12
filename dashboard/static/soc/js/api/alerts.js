/**
 * Email alert API — read status + send a diagnostic test email.
 *
 * POST /api/alerts/test-email is a manual, user-initiated delivery
 * test. It is never called automatically on page load.
 */

import { getJSON, postJSON } from "./client.js";

export async function fetchEmailAlertStatus(signal) {
  return getJSON("/api/alerts/email/status", signal ? { signal } : {});
}

/**
 * Send a diagnostic test email.
 *
 * The backend waits for the actual SMTP terminal outcome
 * (adapter SMTP timeout is 15s, backend wait up to 30s), so
 * the request timeout must be longer than that.
 *
 * @param {{ label?: string, timeoutMs?: number, signal?: AbortSignal }} [opts]
 *   label — optional Control Lab action (e.g. "S2 SYN Flood")
 *   shown in the email's Detection Source field.
 * @returns {Promise<object>} { ok, status, message, recipient, ... }
 */
export async function sendTestEmail(opts = {}) {
  const { label = null, timeoutMs = 35000, signal } = opts;
  const body = label != null ? { label } : null;
  const fetchOpts = { timeoutMs };
  if (signal) fetchOpts.signal = signal;
  return postJSON("/api/alerts/test-email", body, fetchOpts);
}
