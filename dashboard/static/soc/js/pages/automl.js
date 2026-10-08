/**
 * Online AutoML page renderer.
 * Professional SOC view displaying active champion model, validation policy gates,
 * training dataset telemetry metrics, candidate evaluation matrix, drift trigger status,
 * version registry history, and interactive AutoML retrain & rollback actions.
 */

import * as api from "../api/index.js";
import { pageHeader, sectionHeader, statusBadge } from "../components/ui.js";
import { escapeHtml, shortTs } from "../utils/format.js";

let _isBusy = false;

function setLog(root, msg) {
  const el = root.querySelector("[data-automl-log]");
  if (el) el.textContent = msg;
}

function setBusy(root, busy, buttonText = "") {
  _isBusy = busy;
  root.querySelectorAll("[data-automl-action]").forEach((btn) => {
    btn.disabled = !!busy;
  });
  if (buttonText) {
    const activeBtn = root.querySelector('[data-automl-action="run"]');
    if (activeBtn) activeBtn.textContent = buttonText;
  }
}

export async function renderAutoML(root, { soft = false } = {}) {
  let statusData = null;
  let errorMsg = null;

  try {
    const res = await api.fetchAutoMLStatus();
    if (res && res.state === "ERROR") {
      errorMsg = res.error || "Failed to fetch AutoML status";
    } else {
      statusData = res && res.data ? res.data : res;
    }
  } catch (e) {
    errorMsg = e.message || String(e);
  }

  if (!soft || !root.querySelector("[data-automl-container]")) {
    root.innerHTML = `
      <div data-automl-container>
        ${pageHeader("Online AutoML Intelligence", "Continuous model evaluation, ADWIN drift monitoring, candidate selection & version lifecycle management")}
        <div data-automl-content></div>
      </div>
    `;
  }

  const contentEl = root.querySelector("[data-automl-content]");
  if (!contentEl) return;

  if (errorMsg) {
    contentEl.innerHTML = `
      <div class="state-panel state-error">
        <p><strong>AutoML Service Error:</strong> ${escapeHtml(errorMsg)}</p>
      </div>
    `;
    return;
  }

  const data = statusData || {};

  // ── Map backend get_status() JSON to UI variables ──
  // Backend champion: { algorithm, model_id, candidate_id, status, metrics: {f1_score, false_positive_rate, latency_ms, precision, ...}, created_at }
  const champRaw = data.champion || null;
  const champMetrics = (champRaw && champRaw.metrics) ? champRaw.metrics : {};

  // Backend last_run_report: { dataset_size: {train, val}, timestamp, candidates: [...eval_reports], trigger_reason, deployment_status, selection_reason, ... }
  const lastRun = data.last_run_report || {};
  const lastRunCandidates = lastRun.candidates || [];

  // Backend candidates (status summary from recent_candidates): [{algorithm, candidate_id, status, metrics: {...}}]
  // Prefer last_run_report.candidates (eval_reports) which have flat keys (f1_score, false_positive_rate, latency_ms, reason, status)
  // Fall back to data.candidates (status summary) with nested metrics
  let candidates = [];
  if (lastRunCandidates.length > 0) {
    candidates = lastRunCandidates.map((c) => ({
      model_name: c.algorithm || c.candidate_id || "Unknown",
      model_type: c.model_type || "",
      status: c.status || "PENDING",
      f1_score: c.f1_score,
      fpr: c.false_positive_rate,
      precision: c.precision || (c.accuracy !== undefined ? c.accuracy : null),
      latency_ms: c.latency_ms,
      rejection_reason: c.reason || null,
    }));
  } else if (data.candidates && data.candidates.length > 0) {
    candidates = data.candidates.map((c) => {
      const m = c.metrics || {};
      return {
        model_name: c.algorithm || "Unknown",
        model_type: m.model_type || "",
        status: c.status || "PENDING",
        f1_score: m.f1_score,
        fpr: m.false_positive_rate,
        precision: m.precision,
        latency_ms: m.latency_ms,
        rejection_reason: null,
      };
    });
  }

  // Backend version_history: [{version_id, algorithm, promoted_at, metrics: {...}, status, candidate_id}]
  const registry = data.version_history || [];

  const hasChamp = !!(champRaw && champRaw.algorithm && (champRaw.status === "PROMOTED" || champRaw.status === "CHAMPION"));
  const champName = hasChamp ? champRaw.algorithm : "No Active Champion";
  const champVer = champRaw ? (champRaw.model_id || "N/A") : "N/A";
  const champF1 = champMetrics.f1_score !== undefined && champMetrics.f1_score !== null ? (champMetrics.f1_score * 100).toFixed(2) + "%" : "N/A";
  const champFPR = champMetrics.false_positive_rate !== undefined && champMetrics.false_positive_rate !== null ? (champMetrics.false_positive_rate * 100).toFixed(2) + "%" : "N/A";
  const champLat = champMetrics.latency_ms !== undefined && champMetrics.latency_ms !== null ? champMetrics.latency_ms.toFixed(2) + " ms" : "N/A";
  const champStatus = hasChamp ? "CHAMPION" : "NO CHAMPION";

  const datasetSize = lastRun.dataset_size || {};
  const trainCount = datasetSize.train !== undefined ? datasetSize.train : "N/A";
  const valCount = datasetSize.val !== undefined ? datasetSize.val : "N/A";
  const totalSamples = (typeof trainCount === 'number' && typeof valCount === 'number') ? (trainCount + valCount) : "N/A";

  const driftState = data.last_trigger_reason ? "TRIGGERED" : "NORMAL";
  const triggerReason = lastRun.trigger_reason || data.last_trigger_reason || "SCHEDULED / MANUAL";
  const deployStatus = lastRun.deployment_status || "NO_CHANGE";
  const selectionReason = lastRun.selection_reason || (hasChamp ? "Promoted based on composite validation score" : "No candidate currently meets promotion thresholds");
  const cooldown = 0;

  // Compute selection score: Score = F1 - 1.5×FPR - 0.005×Latency
  function computeScore(c) {
    const f1 = typeof c.f1_score === 'number' ? c.f1_score : 0;
    const fpr = typeof c.fpr === 'number' ? c.fpr : 0;
    const lat = typeof c.latency_ms === 'number' ? c.latency_ms : 0;
    return f1 - 1.5 * fpr - 0.005 * lat;
  }

  let bestCand = null;
  if (candidates.length > 0) {
    bestCand = [...candidates].sort((a, b) => (b.f1_score || 0) - (a.f1_score || 0))[0];
  }

  // Build candidate rows for evaluation matrix
  const candidateRows = candidates.length > 0 ? candidates.map((c) => {
    const f1Str = c.f1_score !== undefined && c.f1_score !== null ? (c.f1_score * 100).toFixed(2) + "%" : "—";
    const fprStr = c.fpr !== undefined && c.fpr !== null ? (c.fpr * 100).toFixed(2) + "%" : "—";
    const latStr = c.latency_ms !== undefined && c.latency_ms !== null ? c.latency_ms.toFixed(2) + " ms" : "—";
    const score = computeScore(c);
    const scoreStr = (c.f1_score !== undefined && c.f1_score !== null) ? score.toFixed(4) : "—";
    const isRejected = c.status === "REJECTED" || c.status === "FAIL";
    const badge = statusBadge(c.status || "PENDING");
    const reason = (c.rejection_reason && c.rejection_reason !== "Validation passed")
      ? `<span class="subtext" style="color:var(--color-danger, #f87171)">${escapeHtml(c.rejection_reason)}</span>`
      : (isRejected ? `<span class="subtext" style="color:var(--color-danger, #f87171)">Did not meet policy gates</span>` : `<span class="subtext" style="color:var(--color-success, #34d399)">Passed policy gates</span>`);
    return `
      <tr>
        <td><strong>${escapeHtml(c.model_name)}</strong> <span class="subtext">(${escapeHtml(c.model_type || '')})</span></td>
        <td>${badge}</td>
        <td>${f1Str}</td>
        <td>${fprStr}</td>
        <td>${latStr}</td>
        <td>${scoreStr}</td>
        <td>${reason}</td>
      </tr>
    `;
  }).join("") : `<tr><td colspan="7" class="text-muted">No candidate evaluation matrix available for current window. Click "Run AutoML" to execute.</td></tr>`;

  // Build registry history rows
  // Backend version_history: [{version_id, algorithm, promoted_at, metrics: {f1_score, ...}, status, candidate_id}]
  // Only mark the entry matching the current active champion as CHAMPION/DEPLOYED;
  // all others are historical records and should show as HISTORICAL/INACTIVE.
  const activeChampCandId = hasChamp && champRaw ? champRaw.candidate_id : null;
  const registryRows = registry.length > 0 ? registry.map((m) => {
    const regMetrics = m.metrics || {};
    const f1Val = regMetrics.f1_score;
    const f1Str = f1Val !== undefined && f1Val !== null ? (f1Val * 100).toFixed(2) + "%" : "—";
    const isLive = activeChampCandId && m.candidate_id === activeChampCandId;
    const statusTag = statusBadge(isLive ? "CHAMPION" : "HISTORICAL");
    const deployedTag = statusBadge(isLive ? "DEPLOYED" : "INACTIVE");
    const dateStr = m.promoted_at ? shortTs(m.promoted_at) : "—";
    return `
      <tr>
        <td><code>${escapeHtml(m.version_id || m.candidate_id || 'v1')}</code></td>
        <td><strong>${escapeHtml(m.algorithm || 'Candidate')}</strong></td>
        <td>${dateStr}</td>
        <td>${f1Str}</td>
        <td>${statusTag}</td>
        <td>${deployedTag}</td>
      </tr>
    `;
  }).join("") : `<tr><td colspan="6" class="text-muted">Registry history empty.</td></tr>`;

  contentEl.innerHTML = `
    <!-- Promotion Policy Gates Banner -->
    <div class="panel" style="margin-bottom: 1.25rem; padding: 0.85rem 1.25rem; background: rgba(30, 41, 59, 0.7); border-left: 4px solid var(--color-primary, #3b82f6);">
      <div style="display: flex; gap: 2rem; flex-wrap: wrap; align-items: center; font-size: 0.85rem;">
        <div><strong>Promotion Policy Gates:</strong></div>
        <div>F1 Target: <span style="color: var(--color-success, #34d399);">≥ 75.0%</span></div>
        <div>FPR Threshold: <span style="color: var(--color-warning, #fbbf24);">≤ 10.0%</span></div>
        <div>Precision Gate: <span style="color: var(--color-info, #60a5fa);">≥ 70.0%</span></div>
        <div>Latency SLA: <span style="color: var(--color-info, #60a5fa);">≤ 10.0 ms</span></div>
        <div>Ranking Formula: <code style="font-size: 0.8rem; background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">Score = F1 - 1.5×FPR - 0.005×Latency</code></div>
      </div>
    </div>

    <!-- No Champion Explanatory Banner (When 0/N candidates pass validation) -->
    ${!hasChamp ? `
      <div class="panel" style="margin-bottom: 1.5rem; padding: 1.25rem; background: rgba(245, 158, 11, 0.08); border-left: 4px solid var(--color-warning, #f59e0b);">
        <div style="display: flex; align-items: flex-start; gap: 0.75rem;">
          <span style="font-size: 1.5rem; line-height: 1;">🟡</span>
          <div style="flex: 1;">
            <h3 style="margin: 0 0 0.5rem 0; font-size: 1.1rem; color: #fbbf24;">No Champion Currently Deployed</h3>
            <p style="margin: 0 0 0.5rem 0; font-size: 0.9rem; line-height: 1.5;">
              AutoML evaluated <strong>${candidates.length || 5} candidate models</strong> using <strong>${totalSamples} telemetry samples</strong> (${trainCount} train / ${valCount} validation split).<br>
              <strong>0 / ${candidates.length || 5} candidates</strong> passed the strict promotion policy gates.
            </p>
            <div style="font-size: 0.85rem; color: var(--color-muted, #9ca3af); background: rgba(0,0,0,0.25); padding: 0.6rem 0.85rem; border-radius: 6px; margin-top: 0.5rem;">
              <div>• <strong>Current Deployment:</strong> <span class="badge badge-warning" style="margin-left: 4px;">${escapeHtml(deployStatus)}</span> (${escapeHtml(selectionReason)})</div>
              ${bestCand ? `<div>• <strong>Best Candidate:</strong> ${escapeHtml(bestCand.model_name || bestCand.algorithm)} — F1: <strong>${(bestCand.f1_score * 100).toFixed(2)}%</strong>, FPR: <strong>${(bestCand.fpr * 100).toFixed(2)}%</strong></div>` : ''}
              <div>• <strong>Required Policy Gates:</strong> F1 ≥ 75.0%, FPR ≤ 10.0%, Precision ≥ 70.0%</div>
            </div>
          </div>
        </div>
      </div>
    ` : ''}

    <!-- Top Metric Cards -->
    <div class="metric-grid" style="margin-bottom: 1.5rem;">
      <article class="metric-card">
        <header>
          <span class="metric-title">Active Champion</span>
          ${statusBadge(champStatus)}
        </header>
        <div class="metric-value" style="font-size: 1.15rem; margin: 0.4rem 0;">${escapeHtml(champName)}</div>
        <div class="metric-sub">Version: <code>${escapeHtml(champVer)}</code></div>
      </article>

      <article class="metric-card">
        <header><span class="metric-title">F1 Score</span></header>
        <div class="metric-value" style="color: var(--color-success, #34d399);">${champF1}</div>
        <div class="metric-sub">Min Gate: ≥ 75.0%</div>
      </article>

      <article class="metric-card">
        <header><span class="metric-title">False Positive Rate</span></header>
        <div class="metric-value" style="color: ${(champMetrics.false_positive_rate || 0) > 0.10 ? 'var(--color-warning, #fbbf24)' : 'var(--color-text, #f3f4f6)'};">${champFPR}</div>
        <div class="metric-sub">Max Threshold: ≤ 10.0%</div>
      </article>

      <article class="metric-card">
        <header><span class="metric-title">Inference Latency</span></header>
        <div class="metric-value">${champLat}</div>
        <div class="metric-sub">Max SLA: ≤ 10.0 ms</div>
      </article>

      <article class="metric-card">
        <header>
          <span class="metric-title">Drift / Trigger Status</span>
          ${statusBadge(driftState)}
        </header>
        <div class="metric-value" style="font-size: 0.95rem; margin: 0.4rem 0;">
          ${data.total_triggers !== undefined ? `ADWIN Active (${data.total_triggers} triggers)` : "ADWIN Monitoring Active"}
        </div>
        <div class="metric-sub">Cooldown: ${cooldown}s remaining</div>
      </article>
    </div>

    <!-- Training Telemetry Data & Champion Decision Panel -->
    <div class="chart-grid" style="margin-bottom: 1.5rem;">
      <!-- Training Telemetry Panel -->
      <div class="panel" style="padding: 1.25rem;">
        ${sectionHeader("Training Data & Feature Schema", "Live OpenFlow telemetry dataset powering AutoML candidate training")}
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-top: 1rem;">
          <div>
            <span class="subtext">Telemetry Source:</span>
            <div style="font-weight: 600; margin-top: 2px;"><code>logs/ml_features.csv</code></div>
          </div>
          <div>
            <span class="subtext">Dataset Size:</span>
            <div style="font-weight: 600; margin-top: 2px;">${trainCount} train / ${valCount} val</div>
          </div>
          <div>
            <span class="subtext">Feature Vector Schema:</span>
            <div style="font-weight: 600; margin-top: 2px;">15 OpenFlow Features</div>
          </div>
          <div>
            <span class="subtext">Last Pipeline Run:</span>
            <div style="font-weight: 600; margin-top: 2px;">${lastRun.timestamp ? shortTs(lastRun.timestamp) : "Never"}</div>
          </div>
        </div>
      </div>

      <!-- Champion Decision Summary Panel -->
      <div class="panel" style="padding: 1.25rem;">
        ${sectionHeader("Champion Decision Summary", "Latest candidate promotion status and evaluation decision")}
        <div style="margin-top: 1rem;">
          <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem;">
            <span>Deployment Result:</span>
            ${statusBadge(deployStatus)}
            <span class="subtext">(${escapeHtml(triggerReason)})</span>
          </div>
          <p class="muted" style="margin: 0; font-size: 0.9rem;">
            <strong>Decision Reason:</strong> ${escapeHtml(selectionReason)}
          </p>
        </div>
      </div>
    </div>

    <!-- Actions & Control Bar -->
    <div class="panel" style="margin-bottom: 1.5rem; padding: 1.25rem;">
      ${sectionHeader("AutoML Lifecycle Operations", "Trigger candidate training & validation pipeline, or rollback champion model")}
      <div style="display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; margin-top: 1rem;">
        <button type="button" class="btn btn-primary" data-automl-action="run" ${_isBusy ? "disabled" : ""}>
          ⚡ Run AutoML / Retrain Candidates
        </button>
        <button type="button" class="btn btn-danger" data-automl-action="rollback" ${_isBusy ? "disabled" : ""}>
          ↩ Rollback to Previous Champion
        </button>
      </div>
      <div data-automl-log style="margin-top: 0.75rem; font-family: var(--font-mono, monospace); font-size: 0.85rem; color: var(--color-primary, #60a5fa); min-height: 1.2rem;"></div>
    </div>

    <!-- Candidate Evaluation Results Table -->
    <div class="panel" style="margin-bottom: 1.5rem;">
      ${sectionHeader("Candidate Models & Evaluation Matrix", "Comparison of Decision Trees, Random Forests, Extra Trees, Isolation Forest, and SGD One-Class SVM")}
      <div class="table-responsive" style="margin-top: 1rem;">
        <table class="data-table">
          <thead>
            <tr>
              <th>Candidate Model</th>
              <th>Status</th>
              <th>F1 Score</th>
              <th>FPR</th>
              <th>Latency</th>
              <th>Selection Score</th>
              <th>Rejection / Validation Notes</th>
            </tr>
          </thead>
          <tbody>
            ${candidateRows}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Model Version Registry -->
    <div class="panel">
      ${sectionHeader("Model Version Registry", "Deployment lineage and champion revision history")}
      <div class="table-responsive" style="margin-top: 1rem;">
        <table class="data-table">
          <thead>
            <tr>
              <th>Version</th>
              <th>Model Name</th>
              <th>Registered At</th>
              <th>F1 Score</th>
              <th>Validation Status</th>
              <th>Deployment</th>
            </tr>
          </thead>
          <tbody>
            ${registryRows}
          </tbody>
        </table>
      </div>
    </div>
  `;

  // Attach event listeners for buttons
  const runBtn = contentEl.querySelector('[data-automl-action="run"]');
  if (runBtn) {
    runBtn.onclick = async () => {
      setBusy(root, true, "⏳ Retraining candidates & running evaluation pipeline…");
      setLog(root, "Executing Online AutoML retraining & candidate evaluation pipeline…");
      try {
        const res = await api.postAutoMLRun();
        const msg = res && res.data ? (res.data.selection_reason || res.data.message || "AutoML pipeline completed") : (res.message || "AutoML pipeline completed");
        setLog(root, `Pipeline finished: ${msg}`);
        await renderAutoML(root, { soft: false });
      } catch (e) {
        setLog(root, `Error: ${e.message || String(e)}`);
      } finally {
        setBusy(root, false);
      }
    };
  }

  const rollbackBtn = contentEl.querySelector('[data-automl-action="rollback"]');
  if (rollbackBtn) {
    rollbackBtn.onclick = async () => {
      const confirmed = window.confirm("Are you sure you want to rollback to the previous champion model in the registry?");
      if (!confirmed) return;

      setBusy(root, true);
      setLog(root, "Executing rollback to previous champion model…");
      try {
        const res = await api.postAutoMLRollback();
        const ok = res && res.ok;
        const msg = res ? (res.reason || res.message || (ok ? "Rollback succeeded" : "Rollback failed")) : "Rollback completed";
        setLog(root, `${ok ? 'Success' : 'Rollback Notice'}: ${msg}`);
        await renderAutoML(root, { soft: false });
      } catch (e) {
        setLog(root, `Error: ${e.message || String(e)}`);
      } finally {
        setBusy(root, false);
      }
    };
  }
}
