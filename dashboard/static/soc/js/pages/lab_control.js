/**
 * Lab Control — functional parity with legacy Master Control panel.
 * Wires real POST /api/control/* endpoints. Not OpenFlow mitigation.
 */

import * as controlApi from "../api/control.js";
import { pageHeader, sectionHeader, statusBadge } from "../components/ui.js";
import { escapeHtml, na, shortTs } from "../utils/format.js";

let _jobTimer = null;
let _activeJobId = null;

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
    ${sectionHeader("Controller status", "")}
    <div data-lab-status class="muted">Loading…</div>
    ${sectionHeader("Controller & logs", "")}
    <div class="btn-row">
      <button type="button" class="btn-primary" data-lab-action="restart">Restart Controller</button>
      <button type="button" class="btn-danger" data-lab-action="stop">Stop Controller</button>
      <button type="button" class="btn-secondary" data-lab-action="archive">Archive Logs</button>
    </div>
    ${sectionHeader("Attack scenarios (Mininet)", "")}
    <div class="btn-row">
      <button type="button" class="btn-secondary" data-lab-action="s1">S1 Normal</button>
      <button type="button" class="btn-warn" data-lab-action="s2">S2 SYN Flood</button>
      <button type="button" class="btn-warn" data-lab-action="s3">S3 UDP Flood</button>
      <button type="button" class="btn-warn" data-lab-action="s4">S4 Burst</button>
      <button type="button" class="btn-warn" data-lab-action="s5">S5 Mixed</button>
      <button type="button" class="btn-primary" data-lab-action="batch">Run S3+S4+S5 (full eval)</button>
    </div>
    ${sectionHeader("Evaluation & ML", "")}
    <div class="btn-row">
      <button type="button" class="btn-secondary" data-lab-action="metrics">Compute Metrics</button>
      <button type="button" class="btn-secondary" data-lab-action="train">Retrain ML Models</button>
      <button type="button" class="btn-secondary" data-lab-action="bundle">Bundle Experiment</button>
    </div>
    ${sectionHeader("Operation log", "")}
    <pre class="json-block" data-lab-log style="min-height:140px;white-space:pre-wrap">Ready. Click a button to run a lab operation…</pre>
    <p class="muted">Jobs are polled via GET /api/control/jobs/&#123;id&#125; (same as legacy).</p>
  `;

  await refreshStatus(root);

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
  bind("s2", () => runAction(root, "scenario/2", () => controlApi.runScenario("2")));
  bind("s3", () => runAction(root, "scenario/3", () => controlApi.runScenario("3")));
  bind("s4", () => runAction(root, "scenario/4", () => controlApi.runScenario("4")));
  bind("s5", () => runAction(root, "scenario/5", () => controlApi.runScenario("5")));
  bind("batch", () => {
    if (!confirm("Run Scenarios 3, 4, 5 with archive + controller restart? (~8 min)")) return;
    runAction(root, "scenarios/batch", () => controlApi.runScenarioBatch());
  });
  bind("metrics", () => runAction(root, "metrics", () => controlApi.computeMetrics()));
  bind("train", () => runAction(root, "train", () => controlApi.trainModels()));
  bind("bundle", () => runAction(root, "bundle", () => controlApi.bundleExperiment()));
}

export function destroyLabControl() {
  stopJobPoll();
}
