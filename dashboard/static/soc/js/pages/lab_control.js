/**
 * Lab Control — functional parity with legacy Master Control panel.
 * Wires real POST /api/control/* endpoints. Not OpenFlow mitigation.
 */

import * as controlApi from "../api/control.js";
import { sendTestEmail, fetchEmailAlertStatus } from "../api/alerts.js";
import { pageHeader, sectionHeader, statusBadge } from "../components/ui.js";
import { escapeHtml, na, shortTs } from "../utils/format.js";

let _jobTimer = null;
let _activeJobId = null;

// Attack-scenario → delivery-verification email scheduling.
// A test email (clearly labelled, never a fabricated attack
// alert) is sent a few seconds after an attack scenario is
// launched, so operators can confirm SMTP delivery end-to-end.
const SCENARIO_EMAIL_DELAY_MS = 10000;
let _scenarioEmailTimers = [];

function clearScenarioEmailTimers() {
  for (const t of _scenarioEmailTimers) {
    clearTimeout(t);
  }
  _scenarioEmailTimers = [];
}

function stopJobPoll() {
  if (_jobTimer) {
    clearInterval(_jobTimer);
    _jobTimer = null;
  }
}

function setLog(root, msg) {
  const el = root.querySelector("[data-lab-log]");
  if (el) el.textContent = msg;
}

function setBusy(root, busy) {
  root.querySelectorAll("[data-lab-action]").forEach((btn) => {
    btn.disabled = !!busy;
  });
}

async function refreshStatus(root) {
  const slot = root.querySelector("[data-lab-status]");
  if (!slot) return;
  try {
    const res = await controlApi.fetchControlStatus();
    const d = res && res.state ? res.data || {} : res || {};
    const running = !!(d.controller_running);
    slot.innerHTML = `
      <div class="metric-grid">
        <article class="metric-card">
          <header><span class="metric-title">Controller</span>${statusBadge(
            running ? "LIVE" : "OFFLINE"
          )}</header>
          <div class="metric-value">${running ? "RUNNING" : "STOPPED"}</div>
          <div class="metric-sub">scenario_busy=${escapeHtml(
            String(!!d.scenario_running)
          )} · jobs=${escapeHtml(String((d.running_jobs || []).length))}</div>
        </article>
        <article class="metric-card">
          <header><span class="metric-title">Active job</span></header>
          <div class="metric-value" style="font-size:1rem">${escapeHtml(
            na(_activeJobId || "—")
          )}</div>
        </article>
      </div>
      <pre class="json-block" style="max-height:160px;overflow:auto">${escapeHtml(
        JSON.stringify(d, null, 2).slice(0, 2500)
      )}</pre>`;
  } catch (e) {
    slot.innerHTML = `<div class="state-panel state-error">Control status failed: ${escapeHtml(
      e.message || String(e)
    )}</div>`;
  }
}

async function pollJob(root, jobId) {
  stopJobPoll();
  _activeJobId = jobId;
  const tick = async () => {
    try {
      const res = await controlApi.fetchControlJob(jobId);
      const job = res && res.state ? res.data : res;
      if (!job) return;
      if (res && res.state === "ERROR") {
        setLog(root, `Job poll error: ${res.error || "ERROR"}`);
        stopJobPoll();
        setBusy(root, false);
        return;
      }
      const tail = (job.log_tail || []).join("\n");
      setLog(root, `[${job.status || "?"}] ${job.name || jobId}\n${tail}`);
      if (job.status && job.status !== "running") {
        stopJobPoll();
        setBusy(root, false);
        refreshStatus(root);
      }
    } catch (e) {
      setLog(root, `Job poll error: ${e.message || e}`);
      stopJobPoll();
      setBusy(root, false);
    }
  };
  await tick();
  _jobTimer = setInterval(tick, 2000);
}

async function runAction(root, label, fn) {
  setBusy(root, true);
  setLog(root, `Running ${label}…`);
  try {
    const data = await fn();
    if (data.job && data.job.id) {
      setLog(root, `Job started: ${data.job.id} (${data.job.name || label})`);
      await pollJob(root, data.job.id);
      return;
    }
    if (data.archived_to) {
      setLog(
        root,
        `Archived to ${data.archived_to}\nFiles: ${(data.files || []).join(", ")}`
      );
    } else {
      setLog(root, JSON.stringify(data, null, 2));
    }
    setBusy(root, false);
    refreshStatus(root);
  } catch (e) {
    setLog(root, `Error: ${e.message || e}`);
    setBusy(root, false);
  }
}

/**
 * Schedule a delivery-verification test email a few seconds
 * after an attack scenario is launched.
 *
 * This sends the standard, clearly-labelled TEST email
 * (alert_type=SYSTEM, "No security event occurred"). It does
 * NOT create a fake verified attack, security event, or
 * mitigation alert, and does NOT write to the alert history.
 *
 * @param {HTMLElement} root
 * @param {string} label human-readable scenario label
 * @param {HTMLElement|null} emailResultEl result slot to update
 */
function scheduleScenarioTestEmail(root, label, emailResultEl) {
  setLog(
    root,
    `${label} launched — delivery test email scheduled in ${
      SCENARIO_EMAIL_DELAY_MS / 1000
    }s…`
  );
  const timer = setTimeout(async () => {
    try {
      // Pass the scenario label so the email's
      // "Detection Source" field shows which attack
      // scenario button was used (e.g. "S2 SYN Flood").
      const data = await sendTestEmail({ label });
      if (!emailResultEl) return;
      if (data && data.ok) {
        emailResultEl.innerHTML =
          `<div class="state-panel" style="border-color:rgba(34,197,94,.4)">` +
          `<strong>Scenario email sent</strong><p>${escapeHtml(
            data.message ||
              "Test email sent after scenario launch. Check your inbox and spam folder."
          )}</p></div>`;
      } else {
        emailResultEl.innerHTML =
          `<div class="state-panel state-error"><strong>Scenario email failed</strong><p>${escapeHtml(
            (data && data.message) || "Test email failed."
          )}</p></div>`;
      }
    } catch (e) {
      if (emailResultEl) {
        emailResultEl.innerHTML =
          `<div class="state-panel state-error"><strong>Scenario email failed</strong><p>${escapeHtml(
            (e && e.message) || "Could not send test email."
          )}</p></div>`;
      }
    }
  }, SCENARIO_EMAIL_DELAY_MS);
  _scenarioEmailTimers.push(timer);
}

/**
 * Launch an attack scenario and schedule a delivery-verification
 * test email. Used for attack scenarios only (never S1 Normal).
 */
function runAttackScenario(root, action, scenarioId, label, emailResultEl) {
  runAction(root, action, () => controlApi.runScenario(scenarioId));
  scheduleScenarioTestEmail(root, label, emailResultEl);
}

/**
 * @param {HTMLElement} root
 */
export async function renderLabControl(root) {
  stopJobPoll();
  root.innerHTML = `
    ${pageHeader({
      title: "Lab Control",
      subtitle: "Master Control parity — real lab orchestration via /api/control/*",
      badge: "LAB WRITE",
    })}
    <div class="advisory banner">
      These actions start/stop the OsKen controller, Mininet scenarios, metrics, and ML training.
      They do <strong>not</strong> install OpenFlow DROP rules from this page (mitigation remains controller R7 path).
      Legacy Master Control remains at <a href="/legacy">/legacy</a> for fallback.
    </div>
    ${sectionHeader("Controller status", statusBadge("LIVE", "AUTO"))}
    <div data-lab-status class="muted">Loading…</div>
    ${sectionHeader("Controller & logs", statusBadge("ADVISORY", "LAB"))}
    <p class="muted">Start, stop, or restart the OsKen controller and archive its logs.</p>
    <div class="btn-row">
      <button type="button" class="btn-primary" data-lab-action="restart">Restart Controller</button>
      <button type="button" class="btn-danger" data-lab-action="stop">Stop Controller</button>
      <button type="button" class="btn-secondary" data-lab-action="archive">Archive Logs</button>
    </div>
    ${sectionHeader("Attack scenarios (Mininet)", statusBadge("WARN", "TRAFFIC"))}
    <p class="muted">Launch Mininet scenarios. Amber buttons generate attack traffic; S1 runs a normal baseline.</p>
    <div class="btn-row">
      <button type="button" class="btn-secondary" data-lab-action="s1">S1 Normal</button>
      <button type="button" class="btn-warn" data-lab-action="s2">S2 SYN Flood</button>
      <button type="button" class="btn-warn" data-lab-action="s3">S3 UDP Flood</button>
      <button type="button" class="btn-warn" data-lab-action="s4">S4 Burst</button>
      <button type="button" class="btn-warn" data-lab-action="s5">S5 Mixed</button>
      <button type="button" class="btn-warn" data-lab-action="s6">S6 Zero-Day (SSL)</button>
      <button type="button" class="btn-primary" data-lab-action="batch">Run S3+S4+S5 (full eval)</button>
    </div>
    ${sectionHeader("Evaluation & ML", statusBadge("SNAPSHOT", "ML"))}
    <p class="muted">Compute metrics, retrain ML models, or bundle the current experiment.</p>
    <div class="btn-row">
      <button type="button" class="btn-secondary" data-lab-action="metrics">Compute Metrics</button>
      <button type="button" class="btn-secondary" data-lab-action="train">Retrain ML Models</button>
      <button type="button" class="btn-secondary" data-lab-action="bundle">Bundle Experiment</button>
    </div>
    <!-- Email notifications section hidden (commented out). To re-enable, remove the comment markers around this block.
    ${sectionHeader("Email notifications", "")}
    <div class="btn-row">
      <button type="button" class="btn-primary" data-email-action="test">Send Test Email</button>
      <span data-email-config class="muted" style="align-self:center">Email status: checking…</span>
    </div>
    <div data-email-result class="muted">No test email sent yet. Click the button to verify SMTP delivery.</div>
    -->
    ${sectionHeader("Operation log", statusBadge("ADVISORY", "LOG"))}
    <pre class="json-block" data-lab-log style="min-height:140px;white-space:pre-wrap">Ready. Click a button to run a lab operation…</pre>
    <p class="muted">Jobs are polled via GET /api/control/jobs/&#123;id&#125; (same as legacy).</p>
  `;

  await refreshStatus(root);

  // ── Email notifications: status hint + manual test-email button ──
  const emailBtn = root.querySelector('[data-email-action="test"]');
  const emailResult = root.querySelector("[data-email-result]");
  const emailConfig = root.querySelector("[data-email-config]");

  const showEmailResult = (html) => {
    if (emailResult) emailResult.innerHTML = html;
  };
  const emailPanel = (title, body, kind = "", style = "") => {
    const cls = kind ? `state-panel ${kind}` : "state-panel";
    const attr = style ? ` style="${style}"` : "";
    return `<div class="${cls}"${attr}><strong>${escapeHtml(
      title
    )}</strong><p>${escapeHtml(body)}</p></div>`;
  };

  // Read-only status check on render (never sends an email automatically).
  fetchEmailAlertStatus()
    .then((res) => {
      const d = res && res.state === "LIVE" ? res.data : null;
      if (!d) {
        if (emailConfig) emailConfig.textContent = "Email status: unavailable";
        return;
      }
      if (emailConfig) {
        emailConfig.textContent = d.is_configured
          ? `Email enabled → ${escapeHtml(d.recipient || "")} (cooldown ${escapeHtml(String(d.cooldown_seconds))}s)`
          : "Email disabled / not configured";
      }
    })
    .catch(() => {
      if (emailConfig) emailConfig.textContent = "Email status: unavailable";
    });

  if (emailBtn) {
    emailBtn.addEventListener("click", async () => {
      // Loading state + disable to prevent duplicate clicks.
      emailBtn.disabled = true;
      showEmailResult(
        `<div class="state-panel state-loading"><strong>Sending…</strong><p>Sending test email, waiting for SMTP delivery to complete…</p></div>`
      );
      try {
        const data = await sendTestEmail();
        if (data && data.ok) {
          showEmailResult(
            emailPanel(
              "Email sent",
              data.message ||
                "Test email sent successfully. Check your inbox and spam folder.",
              "",
              "border-color:rgba(34,197,94,.4)"
            )
          );
        } else if (data && data.status === "UNCONFIGURED") {
          showEmailResult(
            emailPanel(
              "Email not configured",
              data.message ||
                "Email alerts are disabled or SMTP configuration is incomplete.",
              "state-error"
            )
          );
        } else if (data && data.status === "SUPPRESSED") {
          showEmailResult(
            emailPanel(
              "Email already in progress",
              data.message || "A test email is already being sent. Please wait.",
              "state-offline"
            )
          );
        } else if (data && data.status === "RATE_LIMITED") {
          showEmailResult(
            emailPanel(
              "Rate limited",
              data.message || "Too many test emails. Please wait before retrying.",
              "state-offline"
            )
          );
        } else {
          showEmailResult(
            emailPanel(
              "Email failed",
              (data && data.message) || "Test email failed.",
              "state-error"
            )
          );
        }
      } catch (e) {
        // HTTP-level failures (401/429) or network errors.
        if (e && e.status === 401) {
          showEmailResult(
            emailPanel(
              "Authentication required",
              "Log in to send a test email.",
              "state-error"
            )
          );
        } else if (e && e.status === 429) {
          showEmailResult(
            emailPanel(
              "Rate limited",
              (e && e.message) || "Too many requests. Please wait before retrying.",
              "state-offline"
            )
          );
        } else {
          showEmailResult(
            emailPanel(
              "Request failed",
              (e && e.message) || "Could not reach the backend.",
              "state-error"
            )
          );
        }
      } finally {
        // Re-enable so the user can retry after a failed attempt.
        emailBtn.disabled = false;
      }
    });
  }

  const bind = (action, handler) => {
    const btn = root.querySelector(`[data-lab-action="${action}"]`);
    btn?.addEventListener("click", () => handler());
  };

  bind("restart", () =>
    runAction(root, "controller/restart", () => controlApi.restartController())
  );
  bind("stop", () => {
    if (!confirm("Stop the OsKen controller?")) return;
    runAction(root, "controller/stop", () => controlApi.stopController());
  });
  bind("archive", () => runAction(root, "archive", () => controlApi.archiveLogs()));
  bind("s1", () => runAction(root, "scenario/1", () => controlApi.runScenario("1")));
  bind("s2", () => runAttackScenario(root, "scenario/2", "2", "S2 SYN Flood", emailResult));
  bind("s3", () => runAttackScenario(root, "scenario/3", "3", "S3 UDP Flood", emailResult));
  bind("s4", () => runAttackScenario(root, "scenario/4", "4", "S4 Burst", emailResult));
  bind("s5", () => runAttackScenario(root, "scenario/5", "5", "S5 Mixed", emailResult));
  bind("s6", () => runAttackScenario(root, "scenario/6", "6", "S6 Zero-Day (SSL)", emailResult));
  bind("batch", () => {
    if (!confirm("Run Scenarios 3, 4, 5 with archive + controller restart? (~8 min)")) return;
    runAction(root, "scenarios/batch", () => controlApi.runScenarioBatch());
    scheduleScenarioTestEmail(root, "S3+S4+S5 batch", emailResult);
  });
  bind("metrics", () => runAction(root, "metrics", () => controlApi.computeMetrics()));
  bind("train", () => runAction(root, "train", () => controlApi.trainModels()));
  bind("bundle", () => runAction(root, "bundle", () => controlApi.bundleExperiment()));
}

export function destroyLabControl() {
  stopJobPoll();
  clearScenarioEmailTimers();
}
