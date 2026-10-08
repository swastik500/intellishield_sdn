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
  const champ = data.active_champion || {};
  const trig = data.trigger_status || {};
  const lastRun = data.last_run || {};
  const candidates = data.candidates_evaluated || [];
  const registry = data.model_registry || [];

  const hasChamp = !!(champ && champ.model_name && champ.status === "CHAMPION");
  const champName = hasChamp ? champ.model_name : "No Active Champion";
  const champVer = champ.version || "N/A";
  const champF1 = champ.f1_score !== undefined && champ.f1_score !== null ? (champ.f1_score * 100).toFixed(2) + "%" : "N/A";
  const champFPR = champ.fpr !== undefined && champ.fpr !== null ? (champ.fpr * 100).toFixed(2) + "%" : "N/A";
  const champLat = champ.latency_ms !== undefined && champ.latency_ms !== null ? champ.latency_ms.toFixed(2) + " ms" : "N/A";
  const champStatus = hasChamp ? "CHAMPION" : "NO CHAMPION";

  const datasetSize = lastRun.dataset_size || {};
  const trainCount = datasetSize.train !== undefined ? datasetSize.train : (data.train_samples !== undefined ? data.train_samples : "N/A");
  const valCount = datasetSize.val !== undefined ? datasetSize.val : (data.val_samples !== undefined ? data.val_samples : "N/A");
  const totalSamples = (typeof trainCount === 'number' && typeof valCount === 'number') ? (trainCount + valCount) : (data.total_samples || "N/A");

  const cooldown = trig.cooldown_remaining_sec !== undefined ? Math.round(trig.cooldown_remaining_sec) : 0;
  const driftState = trig.drift_detected ? "DRIFT DETECTED" : "NORMAL";
  const triggerReason = lastRun.trigger_type || trig.last_trigger_reason || "SCHEDULED / MANUAL";
  const deployStatus = lastRun.deployment_status || "NO_CHANGE";
  const selectionReason = lastRun.selection_reason || (hasChamp ? "Promoted based on composite validation score" : "No candidate currently meets promotion thresholds");

  // Build candidate rows for evaluation matrix
  const candidateRows = candidates.length > 0 ? candidates.map((c) => {
    const f1Str = c.f1_score !== undefined && c.f1_score !== null ? (c.f1_score * 100).toFixed(2) + "%" : "—";
    const fprStr = c.fpr !== undefined && c.fpr !== null ? (c.fpr * 100).toFixed(2) + "%" : "—";
    const latStr = c.latency_ms !== undefined && c.latency_ms !== null ? c.latency_ms.toFixed(2) + " ms" : "—";
    const scoreStr = c.score !== undefined && c.score !== null ? c.score.toFixed(4) : "—";
    const badge = statusBadge(c.status || "PENDING");
    const reason = c.rejection_reason ? `<span class="subtext" style="color:var(--color-danger, #f87171)">${escapeHtml(c.rejection_reason)}</span>` : `<span class="subtext" style="color:var(--color-success, #34d399)">Passed policy gates</span>`;
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
  const registryRows = registry.length > 0 ? registry.map((m) => {
    const f1Str = m.f1_score !== undefined && m.f1_score !== null ? (m.f1_score * 100).toFixed(2) + "%" : "—";
    const statusTag = statusBadge(m.status || "REGISTERED");
    const deployedTag = m.deployed ? statusBadge("DEPLOYED") : statusBadge("ARCHIVED");
    const dateStr = m.created_at ? shortTs(m.created_at) : "—";
    return `
      <tr>
        <td><code>${escapeHtml(m.version || 'v1')}</code></td>
        <td><strong>${escapeHtml(m.model_name || 'Candidate')}</strong></td>
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
        <div>F1 Target: <span style="color: var(--color-success, #34d399);">≥ 85.0%</span></div>
        <div>FPR Threshold: <span style="color: var(--color-warning, #fbbf24);">≤ 5.0%</span></div>
        <div>Latency SLA: <span style="color: var(--color-info, #60a5fa);">≤ 10.0 ms</span></div>
        <div>Ranking Formula: <code style="font-size: 0.8rem; background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">Score = F1 - 1.5×FPR - 0.005×Latency</code></div>
      </div>
    </div>

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
        <div class="metric-sub">Min Gate: ≥ 85.0%</div>
      </article>

      <article class="metric-card">
        <header><span class="metric-title">False Positive Rate</span></header>
        <div class="metric-value" style="color: ${champ.fpr > 0.05 ? 'var(--color-warning, #fbbf24)' : 'var(--color-text, #f3f4f6)'};">${champFPR}</div>
        <div class="metric-sub">Max Threshold: ≤ 5.0%</div>
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
          ${trig.monitoring_enabled !== false ? "ADWIN Monitoring Active" : "Trigger Cooldown"}
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
