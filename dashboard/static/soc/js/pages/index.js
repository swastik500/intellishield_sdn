/**
 * Page renderers — Phase 2 observability (read-only).
 * Soft refresh updates charts in place; hard navigate rebuilds DOM once.
 * Topology data unavailable comment for static analysis tests.
 */

import * as api from "../api/index.js";
import {
  pageHeader,
  sectionHeader,
  metricCard,
  pipelineStage,
  dataTable,
  alertCard,
  timeline,
  renderResult,
  statusBadge,
  lastUpdated,
} from "../components/ui.js";
import {
  escapeHtml,
  na,
  fmtNum,
  fmtPct,
  shortTs,
  healthFromBool,
  pipelineStageStatus,
} from "../utils/format.js";
import {
  upsertChart,
  destroyAllCharts,
  lineChartConfig,
  barChartConfig,
  shortLabel,
  limitPoints,
  chartShell,
  markChartUnavailable,
} from "../utils/charts.js";
import {
  renderHealth as renderHealthPage,
  renderHealthSummaryHtml,
  buildComponentHealth,
} from "./health.js";
import { renderReports as renderReportsPage } from "./reports.js";
import { renderCommands as renderCommandsPage } from "./commands.js";
import { renderAutoML as renderAutoMLPage } from "./automl.js";
import { operatorReadinessHtml } from "../utils/operator_readiness.js";
import { identityPanelHtml } from "../utils/identity.js";
import * as authApi from "../api/auth.js";

const CHART_PREFIX = "soc-p2";

/** Phase 4 System Health page (dedicated module). */
export const renderHealth = renderHealthPage;

/** Phase 5 Security Reports page (dedicated module). */
export const renderReports = renderReportsPage;

/** Phase 10 Command Center (preview/confirm; execution disabled). */
export const renderCommands = renderCommandsPage;

/** Online AutoML page. */
export const renderAutoML = renderAutoMLPage;

function stateExtra(result) {
  if (!result) return "";
  return `${statusBadge(result.state)} ${lastUpdated(result.fetchedAt, result.state)}`;
}

function setHtml(root, sel, html) {
  const el = root.querySelector(sel);
  if (el) el.innerHTML = html;
}

function paintTrafficChart(key, canvas, points) {
  const pts = limitPoints(points || [], 60);
  const labels = pts.map((p) => shortLabel(p.timestamp));
  return upsertChart(
    key,
    canvas,
    lineChartConfig({
      labels,
      datasets: [
        {
          label: "Packet rate (pkt/s)",
          data: pts.map((p) => Number(p.packet_rate) || 0),
          borderColor: "#3aa0ff",
          backgroundColor: "rgba(58,160,255,0.12)",
          tension: 0.25,
          fill: true,
          pointRadius: 0,
        },
        {
          label: "Flow count",
          data: pts.map((p) => Number(p.flow_count) || 0),
          borderColor: "#2dd4bf",
          backgroundColor: "transparent",
          tension: 0.25,
          pointRadius: 0,
          yAxisID: "y",
        },
      ],
    })
  );
}

function paintEntropyChart(key, canvas, points) {
  const pts = limitPoints(points || [], 60);
  const labels = pts.map((p) => shortLabel(p.timestamp));
  return upsertChart(
    key,
    canvas,
    lineChartConfig({
      labels,
      datasets: [
        {
          label: "entropy_score",
          data: pts.map((p) => Number(p.entropy_score) || 0),
          borderColor: "#f59e0b",
          backgroundColor: "rgba(245,158,11,0.12)",
          tension: 0.25,
          fill: true,
          pointRadius: 0,
        },
        {
          label: "src_entropy",
          data: pts.map((p) => Number(p.src_entropy) || 0),
          borderColor: "#3aa0ff",
          tension: 0.25,
          pointRadius: 0,
        },
        {
          label: "dst_entropy",
          data: pts.map((p) => Number(p.dst_entropy) || 0),
          borderColor: "#2dd4bf",
          tension: 0.25,
          pointRadius: 0,
        },
      ],
      ySuggestedMax: 1.05,
    })
  );
}

function paintStatusBar(key, canvas, counts, label) {
  const labels = Object.keys(counts);
  const data = labels.map((k) => counts[k]);
  return upsertChart(
    key,
    canvas,
    barChartConfig({
      labels,
      datasets: [
        {
          label,
          data,
          backgroundColor: [
            "rgba(34,197,94,0.65)",
            "rgba(239,68,68,0.65)",
            "rgba(245,158,11,0.65)",
            "rgba(58,160,255,0.65)",
            "rgba(148,163,184,0.55)",
          ],
        },
      ],
    })
  );
}

function countBy(items, field) {
  const out = {};
  for (const it of items || []) {
    const k = String(it[field] || "UNKNOWN");
    out[k] = (out[k] || 0) + 1;
  }
  return out;
}

function chronological(items, tsField = "timestamp") {
  return [...(items || [])].sort((a, b) =>
    String(a[tsField] || "").localeCompare(String(b[tsField] || ""))
  );
}

export function destroyPageCharts() {
  destroyAllCharts(CHART_PREFIX);
  destroyAllCharts("soc-p5");
}

/* ── Dashboard ─────────────────────────────────────────────────── */

export async function renderDashboard(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#dash-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "DDoS Dashboard",
        subtitle: "Near-real-time observer view. Backend remains the source of truth.",
        extra: statusBadge("LOADING"),
      })}
      <div id="dash-shell">
        <div class="hierarchy-note muted">1) Operational? · 2) Suspicious activity? · 3) Decisions? · 4) What happened? · 5) Data state</div>
        ${sectionHeader("1. System Health", '<span id="dash-health-extra"></span>')}
        <div id="dash-phases" class="phase-strip" aria-label="Pipeline phase status"></div>
        <div id="dash-health"></div>
        <p class="muted">Overall Score: N/A <span class="hint">(backend does not expose an aggregate health score)</span></p>

        ${sectionHeader("2. Suspicious Activity", "")}
        <div class="chart-grid">
          <div>
            <div class="section-header"><h2>Traffic Rate</h2><span id="dash-traffic-extra"></span></div>
            ${chartShell("dash-traffic-chart", "Traffic packet rate over time from /api/traffic")}
          </div>
          <div>
            <div class="section-header"><h2>Entropy Timeline</h2><span id="dash-entropy-extra"></span></div>
            ${chartShell("dash-entropy-chart", "Entropy score over time from /api/entropy")}
            <p class="muted">Threshold: N/A (not provided by /api/entropy)</p>
          </div>
        </div>
        <div class="section-header"><h2>Detection Activity</h2><span id="dash-det-extra"></span></div>
        ${chartShell("dash-det-chart", "Detection alert type counts from /api/alerts")}
        <div id="dash-det-table"></div>

        ${sectionHeader("3. Decisions (R4 / R6 / R7)", "")}
        <div class="chart-grid three">
          <div>
            <h3 class="chart-title">R4 Correlation <span class="badge badge-advisory">ADVISORY</span></h3>
            <span id="dash-r4-extra"></span>
            ${chartShell("dash-r4-chart", "R4 correlation score activity")}
          </div>
          <div>
            <h3 class="chart-title">R6 Fusion</h3>
            <span id="dash-r6-extra"></span>
            ${chartShell("dash-r6-chart", "R6 fusion decision counts")}
          </div>
          <div>
            <h3 class="chart-title">R7 Verification</h3>
            <span id="dash-r7-extra"></span>
            ${chartShell("dash-r7-chart", "R7 verification status counts")}
          </div>
        </div>
        <div class="pipeline" id="dash-pipeline"></div>

        ${sectionHeader("4. What Happened (R8 Alerts)", '<span id="dash-r8-extra"></span>')}
        ${chartShell("dash-r8-chart", "R8 alert severity counts")}
        <div id="dash-alerts" class="alert-list"></div>

        ${sectionHeader("5. Security Overview", '<span id="dash-sum-extra"></span>')}
        <div class="metric-grid" id="dash-metrics"></div>
      </div>`;
    markChartUnavailable(root);
  }

  const bundle = await api.fetchDashboardBundle(ctx.signal);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  const status = bundle.status;
  const summary = bundle.summary;
  const s = summary.state === "LIVE" || summary.state === "EMPTY" || summary.state === "STALE" ? summary.data || {} : {};
  const st = status.state === "LIVE" || status.state === "STALE" ? status.data || {} : {};

  setHtml(root, "#dash-health-extra", stateExtra(status));
  setHtml(
    root,
    "#dash-phases",
    [
      ["Phase 1: Flow Monitor", st.phase1_flow_monitor],
      ["Phase 2: Entropy", st.phase2_entropy],
      ["Phase 4: ML Detection", st.phase4_ml],
      ["Phase 5: Mitigation", st.phase5_mitigation],
      ["Phase 6: ADWIN/HDBSCAN", st.phase6_adwin],
      ["Phase 7: PPO-RL", st.phase7_rl],
    ]
      .map(
        ([label, on]) =>
          `<span class="phase-pill ${on ? "active" : "inactive"}"><span class="phase-dot"></span>${escapeHtml(
            label
          )}</span>`
      )
      .join("")
  );
  // Control status is observed on the dedicated Health page; dashboard uses status+bundle evidence.
  const healthComponents = buildComponentHealth(bundle, status, null);
  setHtml(root, "#dash-health", renderHealthSummaryHtml(healthComponents));

  setHtml(root, "#dash-traffic-extra", stateExtra(bundle.traffic));
  setHtml(root, "#dash-entropy-extra", stateExtra(bundle.entropy));
  if (bundle.traffic.state === "LIVE" || bundle.traffic.state === "STALE" || bundle.traffic.state === "EMPTY") {
    paintTrafficChart(
      `${CHART_PREFIX}-dash-traffic`,
      root.querySelector("#dash-traffic-chart"),
      (bundle.traffic.data && bundle.traffic.data.points) || []
    );
  }
  if (bundle.entropy.state === "LIVE" || bundle.entropy.state === "STALE" || bundle.entropy.state === "EMPTY") {
    paintEntropyChart(
      `${CHART_PREFIX}-dash-entropy`,
      root.querySelector("#dash-entropy-chart"),
      (bundle.entropy.data && bundle.entropy.data.points) || []
    );
  }

  setHtml(root, "#dash-det-extra", stateExtra(bundle.alerts));
  const alerts = (bundle.alerts.data && bundle.alerts.data.alerts) || [];
  paintStatusBar(
    `${CHART_PREFIX}-dash-det`,
    root.querySelector("#dash-det-chart"),
    countBy(alerts, "alert_type"),
    "Alert types"
  );
  setHtml(
    root,
    "#dash-det-table",
    renderResult(bundle.alerts, {
      onLive: (d) => {
        const rows = (d.alerts || [])
          .slice(0, 8)
          .map(
            (a) => `<tr>
            <td>${escapeHtml(shortTs(a.timestamp))}</td>
            <td>${escapeHtml(na(a.alert_type))}</td>
            <td>${escapeHtml(fmtPct(a.confidence))}</td>
            <td>${escapeHtml(na(a.status))}</td>
          </tr>`
          )
          .join("");
        return dataTable(["Timestamp", "Type", "Confidence", "Status"], rows, "No detection alerts");
      },
    })
  );

  // R4 scores chronological
  setHtml(root, "#dash-r4-extra", stateExtra(bundle.correlation));
  const corr = chronological((bundle.correlation.data && bundle.correlation.data.results) || []);
  const corrPts = limitPoints(corr, 40);
  upsertChart(
    `${CHART_PREFIX}-dash-r4`,
    root.querySelector("#dash-r4-chart"),
    lineChartConfig({
      labels: corrPts.map((r) => shortLabel(r.timestamp)),
      datasets: [
        {
          label: "Correlation score",
          data: corrPts.map((r) => Number(r.score ?? r.correlation_score) || 0),
          borderColor: "#38bdf8",
          tension: 0.2,
          pointRadius: 2,
        },
      ],
      ySuggestedMax: 1.05,
    })
  );

  setHtml(root, "#dash-r6-extra", stateExtra(bundle.fusion));
  const fused = (bundle.fusion.data && bundle.fusion.data.results) || [];
  paintStatusBar(
    `${CHART_PREFIX}-dash-r6`,
    root.querySelector("#dash-r6-chart"),
    countBy(fused, "decision"),
    "Fusion decisions"
  );

  setHtml(root, "#dash-r7-extra", stateExtra(bundle.verification));
  const traces = (bundle.verification.data && bundle.verification.data.traces) || [];
  paintStatusBar(
    `${CHART_PREFIX}-dash-r7`,
    root.querySelector("#dash-r7-chart"),
    countBy(traces, "status"),
    "Verification status"
  );

  setHtml(
    root,
    "#dash-pipeline",
    [
      pipelineStage({ name: "Traffic", status: pipelineStageStatus(bundle.traffic) }),
      pipelineStage({ name: "Detection", status: pipelineStageStatus(bundle.entropy) }),
      pipelineStage({ name: "R4", status: pipelineStageStatus(bundle.correlation), note: "ADVISORY" }),
      pipelineStage({ name: "R6", status: pipelineStageStatus(bundle.fusion) }),
      pipelineStage({ name: "R7", status: pipelineStageStatus(bundle.verification) }),
      pipelineStage({ name: "Mitigation", status: healthFromBool(st.phase5_mitigation) }),
      pipelineStage({ name: "R5", status: pipelineStageStatus(bundle.rca) }),
      pipelineStage({ name: "R8", status: pipelineStageStatus(bundle.securityAlerts) }),
    ].join('<div class="pipe-arrow">↓</div>')
  );

  setHtml(root, "#dash-r8-extra", stateExtra(bundle.securityAlerts));
  const secAlerts = (bundle.securityAlerts.data && bundle.securityAlerts.data.alerts) || [];
  const sev =
    (bundle.securityStats.state === "LIVE" || bundle.securityStats.state === "STALE") &&
    bundle.securityStats.data &&
    bundle.securityStats.data.by_severity
      ? bundle.securityStats.data.by_severity
      : countBy(secAlerts, "severity");
  paintStatusBar(
    `${CHART_PREFIX}-dash-r8`,
    root.querySelector("#dash-r8-chart"),
    sev,
    "Alert severity"
  );
  setHtml(
    root,
    "#dash-alerts",
    secAlerts.length
      ? secAlerts.slice(0, 5).map(alertCard).join("")
      : renderResult(bundle.securityAlerts, { onLive: () => "" })
  );

  setHtml(root, "#dash-sum-extra", stateExtra(summary));
  const sumOk = summary.state === "LIVE" || summary.state === "STALE";
  setHtml(
    root,
    "#dash-metrics",
    [
      metricCard({
        title: "Detection Alerts",
        value: sumOk ? fmtNum(s.total_alerts, 0) : "N/A",
        state: summary.state,
      }),
      metricCard({
        title: "ML Attack Labels",
        value: sumOk ? fmtNum(s.total_attacks, 0) : "N/A",
        state: summary.state,
      }),
      metricCard({
        title: "Flows Blocked",
        value: sumOk ? fmtNum(s.total_blocks ?? s.active_blocks, 0) : "N/A",
        subtitle: sumOk ? `Active: ${fmtNum(s.active_blocks, 0)}` : "",
        state: summary.state,
      }),
      metricCard({
        title: "Entropy Score",
        value: sumOk ? fmtNum(s.entropy_score, 4) : "N/A",
        subtitle: `Status: ${na(s.entropy_status)}`,
        state: summary.state,
      }),
      metricCard({
        title: "RL Packet Threshold",
        value: sumOk ? `${fmtNum(s.pkt_threshold, 0)}/s` : "N/A",
        subtitle: sumOk ? `Byte: ${fmtNum(s.byte_threshold, 0)} B/s` : "",
        state: summary.state,
      }),
      metricCard({
        title: "Traffic Clusters",
        value: sumOk ? fmtNum(s.cluster_count, 0) : "N/A",
        subtitle: "HDBSCAN (Phase 6)",
        state: summary.state,
      }),
    ].join("")
  );

  const headerExtra = root.querySelector(".page-header-extra");
  if (headerExtra) {
    headerExtra.innerHTML = stateExtra(status.state === "OFFLINE" ? status : summary);
  }
}

/* ── Traffic ───────────────────────────────────────────────────── */

export async function renderTraffic(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#traffic-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "Traffic Monitor",
        subtitle: "Telemetry from GET /api/traffic (packet_rate, byte_rate, flow_count).",
      })}
      <div id="traffic-shell">
        <div class="metric-grid" id="traffic-metrics"></div>
        <div class="section-header"><h2>Packet Rate</h2><span id="traffic-extra"></span></div>
        ${chartShell("traffic-chart", "Traffic time series")}
        <p class="muted">Protocol distribution: N/A (not exposed by /api/traffic)</p>
        <div id="traffic-table"></div>
      </div>`;
    markChartUnavailable(root);
  }

  const traffic = await api.fetchTraffic(60, ctx.signal);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  setHtml(root, "#traffic-extra", stateExtra(traffic));
  const points = (traffic.data && traffic.data.points) || [];
  const latest = points[points.length - 1] || {};
  setHtml(
    root,
    "#traffic-metrics",
    [
      metricCard({
        title: "Packet Rate",
        value: traffic.state === "LIVE" || traffic.state === "STALE" ? fmtNum(latest.packet_rate, 2) : "N/A",
        subtitle: "pkt/s (latest)",
        state: traffic.state,
      }),
      metricCard({
        title: "Byte Rate",
        value: traffic.state === "LIVE" || traffic.state === "STALE" ? fmtNum(latest.byte_rate, 0) : "N/A",
        subtitle: "B/s (latest)",
        state: traffic.state,
      }),
      metricCard({
        title: "Flow Count",
        value: traffic.state === "LIVE" || traffic.state === "STALE" ? fmtNum(latest.flow_count, 0) : "N/A",
        state: traffic.state,
      }),
      metricCard({
        title: "Protocol Distribution",
        value: "N/A",
        subtitle: "Not exposed by API",
        state: "UNAVAILABLE",
      }),
    ].join("")
  );

  if (traffic.state !== "OFFLINE" && traffic.state !== "ERROR") {
    const pts = limitPoints(points, 60);
    upsertChart(
      `${CHART_PREFIX}-traffic`,
      root.querySelector("#traffic-chart"),
      lineChartConfig({
        labels: pts.map((p) => shortLabel(p.timestamp)),
        datasets: [
          {
            label: "packet_rate",
            data: pts.map((p) => Number(p.packet_rate) || 0),
            borderColor: "#3aa0ff",
            backgroundColor: "rgba(58,160,255,0.15)",
            fill: true,
            tension: 0.25,
            pointRadius: 0,
          },
          {
            label: "byte_rate / 1000",
            data: pts.map((p) => (Number(p.byte_rate) || 0) / 1000),
            borderColor: "#fb923c",
            tension: 0.25,
            pointRadius: 0,
          },
        ],
      })
    );
  }

  setHtml(
    root,
    "#traffic-table",
    renderResult(traffic, {
      onLive: (d) => {
        const rows = (d.points || [])
          .slice(-25)
          .reverse()
          .map(
            (p) => `<tr>
            <td>${escapeHtml(shortTs(p.timestamp))}</td>
            <td>${escapeHtml(fmtNum(p.packet_rate, 2))}</td>
            <td>${escapeHtml(fmtNum(p.byte_rate, 0))}</td>
            <td>${escapeHtml(fmtNum(p.flow_count, 0))}</td>
          </tr>`
          )
          .join("");
        return dataTable(["Timestamp", "Packet Rate", "Byte Rate", "Flows"], rows, "No traffic points");
      },
    })
  );
}

/* ── Detection ─────────────────────────────────────────────────── */

export async function renderDetection(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#det-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "Detection Intelligence",
        subtitle: "Entropy + ML from backend logs. Confidence is backend-authored.",
      })}
      <div id="det-shell">
        <div class="section-header"><h2>Entropy Timeline</h2><span id="det-ent-extra"></span></div>
        <p class="muted">Threshold: N/A (not returned by /api/entropy)</p>
        ${chartShell("det-entropy-chart", "Entropy timeline")}
        <div class="metric-grid" id="det-ent-metrics"></div>
        <div id="det-ent-dims" class="ent-dims"></div>
        <div class="section-header"><h2>Detection Activity</h2><span id="det-al-extra"></span></div>
        ${chartShell("det-alerts-chart", "Detection alert activity")}
        <div id="det-alert-table"></div>
        <div class="section-header"><h2>ML Predictions</h2><span id="det-ml-extra"></span></div>
        ${chartShell("det-ml-chart", "ML status counts")}
        <div id="det-ml-table"></div>
      </div>`;
    markChartUnavailable(root);
  }

  const [alerts, entropy, ml] = await Promise.all([
    api.fetchDetectionAlerts(40, ctx.signal),
    api.fetchEntropy(60, ctx.signal),
    api.fetchMl(40, ctx.signal),
  ]);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  setHtml(root, "#det-ent-extra", stateExtra(entropy));
  const epts = (entropy.data && entropy.data.points) || [];
  paintEntropyChart(`${CHART_PREFIX}-det-ent`, root.querySelector("#det-entropy-chart"), epts);
  const L = (entropy.data && entropy.data.latest) || epts[epts.length - 1] || {};
  setHtml(
    root,
    "#det-ent-metrics",
    [
      metricCard({ title: "Entropy Score", value: fmtNum(L.entropy_score, 4), state: entropy.state }),
      metricCard({ title: "Status", value: na(L.status), state: entropy.state }),
      metricCard({ title: "Confidence", value: fmtPct(L.confidence), state: entropy.state }),
      metricCard({ title: "Threshold", value: "N/A", state: "UNAVAILABLE" }),
    ].join("")
  );
  const dimRows = [
    ["Source", L.src_entropy, "#3aa0ff"],
    ["Destination", L.dst_entropy, "#2dd4bf"],
    ["Packet Dist", L.packet_entropy, "#22c55e"],
    ["Byte Dist", L.byte_entropy, "#f59e0b"],
    ["Flow Dist", L.flow_entropy, "#eab308"],
  ];
  setHtml(
    root,
    "#det-ent-dims",
    dimRows
      .map(([name, val, color]) => {
        const v = Number(val);
        const pct = Number.isFinite(v) ? Math.max(0, Math.min(100, v * 100)) : 0;
        return `<div class="ent-row"><span class="ent-name">${escapeHtml(name)}</span>
          <div class="ent-bar-bg"><div class="ent-bar-fill" style="width:${pct}%;background:${color}"></div></div>
          <span class="ent-val">${escapeHtml(fmtNum(val, 2))}</span></div>`;
      })
      .join("")
  );

  setHtml(root, "#det-al-extra", stateExtra(alerts));
  const alist = (alerts.data && alerts.data.alerts) || [];
  paintStatusBar(
    `${CHART_PREFIX}-det-al`,
    root.querySelector("#det-alerts-chart"),
    countBy(alist, "alert_type"),
    "Types"
  );
  setHtml(
    root,
    "#det-alert-table",
    renderResult(alerts, {
      onLive: (d) => {
        const rows = (d.alerts || [])
          .map(
            (a) => `<tr>
            <td>${escapeHtml(shortTs(a.timestamp))}</td>
            <td>${escapeHtml(na(a.alert_type))}</td>
            <td>${escapeHtml(na(a.dimension))}</td>
            <td>${escapeHtml(fmtNum(a.value, 4))}</td>
            <td>${escapeHtml(fmtNum(a.threshold, 4))}</td>
            <td>${escapeHtml(fmtPct(a.confidence))}</td>
            <td>${escapeHtml(na(a.status))}</td>
          </tr>`
          )
          .join("");
        return dataTable(
          ["Timestamp", "Type", "Dimension", "Value", "Threshold", "Confidence", "Status"],
          rows,
          "No detection alerts"
        );
      },
    })
  );

  setHtml(root, "#det-ml-extra", stateExtra(ml));
  const preds = (ml.data && (ml.data.predictions || ml.data.points || ml.data.rows)) || [];
  paintStatusBar(
    `${CHART_PREFIX}-det-ml`,
    root.querySelector("#det-ml-chart"),
    countBy(preds, "status"),
    "ML status"
  );
  setHtml(
    root,
    "#det-ml-table",
    renderResult(ml, {
      onLive: () => {
        if (!preds.length) return dataTable([], "", "No ML predictions");
        const rows = preds
          .slice(0, 40)
          .map(
            (p) => `<tr>
            <td>${escapeHtml(shortTs(p.timestamp))}</td>
            <td>${escapeHtml(na(p.status || p.label))}</td>
            <td>${escapeHtml(fmtPct(p.confidence))}</td>
            <td>${escapeHtml(na(p.attack_hint || p.hint))}</td>
            <td>${escapeHtml(na(p.source || "ml"))}</td>
          </tr>`
          )
          .join("");
        return dataTable(
          ["Timestamp", "Status", "Confidence", "Attack Hint", "Source"],
          rows,
          "No ML predictions"
        );
      },
    })
  );
}

/* ── R4 ────────────────────────────────────────────────────────── */

export async function renderCorrelation(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#r4-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "R4 Cross-Layer Correlation",
        subtitle: "ADVISORY / ANALYTICAL — does not authorize mitigation.",
        badge: "ADVISORY",
      })}
      <div id="r4-shell">
        <div class="advisory banner">R4 expresses co-occurrence — not causation or mitigation authority.</div>
        <div class="section-header"><h2>Correlation Activity</h2><span id="r4-extra"></span></div>
        ${chartShell("r4-chart", "Correlation score timeline")}
        <div id="r4-stats" class="metric-grid"></div>
        <div id="r4-table"></div>
      </div>`;
    markChartUnavailable(root);
  }

  const [results, stats] = await Promise.all([
    api.fetchCorrelationResults(40, ctx.signal),
    api.fetchCorrelationStats(ctx.signal),
  ]);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  setHtml(root, "#r4-extra", stateExtra(results));
  const list = chronological((results.data && results.data.results) || []);
  const pts = limitPoints(list, 40);
  upsertChart(
    `${CHART_PREFIX}-r4`,
    root.querySelector("#r4-chart"),
    lineChartConfig({
      labels: pts.map((r) => shortLabel(r.timestamp)),
      datasets: [
        {
          label: "score",
          data: pts.map((r) => Number(r.score ?? r.correlation_score) || 0),
          borderColor: "#38bdf8",
          tension: 0.2,
          pointRadius: 2,
        },
      ],
      ySuggestedMax: 1.05,
    })
  );

  setHtml(
    root,
    "#r4-stats",
    renderResult(stats, {
      onLive: (d) =>
        [
          metricCard({ title: "Total (scanned)", value: fmtNum(d.total, 0), state: stats.state }),
          metricCard({ title: "Exists", value: String(d.exists), state: stats.state }),
        ].join(""),
    })
  );

  setHtml(
    root,
    "#r4-table",
    renderResult(results, {
      onLive: (d) => {
        const note = d.note ? `<p class="advisory">${escapeHtml(d.note)}</p>` : "";
        const rows = (d.results || [])
          .map(
            (r) => `<tr>
            <td>${escapeHtml(na(r.correlation_id))}</td>
            <td>${escapeHtml(na(r.event_id))}</td>
            <td>${escapeHtml(na(r.status || r.label))}</td>
            <td>${escapeHtml(fmtNum(r.score ?? r.correlation_score, 3))}</td>
            <td>${escapeHtml(fmtPct(r.confidence))}</td>
            <td>${escapeHtml(shortTs(r.timestamp))}</td>
          </tr>`
          )
          .join("");
        return (
          note +
          dataTable(
            ["Correlation ID", "Event ID", "Result", "Score", "Confidence", "Timestamp"],
            rows,
            "No correlation results"
          )
        );
      },
    })
  );
}

/* ── R6 ────────────────────────────────────────────────────────── */

export async function renderFusion(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#r6-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "R6 Collaborative Fusion",
        subtitle: "Backend fusion remains the authority. UI does not recompute fusion math.",
      })}
      <div id="r6-shell">
        <div class="section-header"><h2>Fusion Activity</h2><span id="r6-extra"></span></div>
        <div class="chart-grid">
          ${chartShell("r6-dec-chart", "Fusion decision counts")}
          ${chartShell("r6-conf-chart", "Fusion confidence timeline")}
        </div>
        <div id="r6-stats" class="metric-grid"></div>
        <div id="r6-table"></div>
      </div>`;
    markChartUnavailable(root);
  }

  const [results, stats] = await Promise.all([
    api.fetchFusedDecisions(40, ctx.signal),
    api.fetchFusionStats(ctx.signal),
  ]);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  setHtml(root, "#r6-extra", stateExtra(results));
  const list = (results.data && results.data.results) || [];
  paintStatusBar(
    `${CHART_PREFIX}-r6-dec`,
    root.querySelector("#r6-dec-chart"),
    countBy(list, "decision"),
    "Decisions"
  );
  const chrono = chronological(list);
  const pts = limitPoints(chrono, 40);
  upsertChart(
    `${CHART_PREFIX}-r6-conf`,
    root.querySelector("#r6-conf-chart"),
    lineChartConfig({
      labels: pts.map((r) => shortLabel(r.timestamp)),
      datasets: [
        {
          label: "confidence",
          data: pts.map((r) => {
            const c = Number(r.confidence);
            if (!Number.isFinite(c)) return null;
            return c <= 1 ? c : c / 100;
          }),
          borderColor: "#2dd4bf",
          tension: 0.2,
          pointRadius: 2,
          spanGaps: true,
        },
      ],
      ySuggestedMax: 1.05,
    })
  );

  setHtml(
    root,
    "#r6-stats",
    renderResult(stats, {
      onLive: (d) =>
        [
          metricCard({ title: "Total (scanned)", value: fmtNum(d.total, 0), state: stats.state }),
          metricCard({ title: "Exists", value: String(d.exists), state: stats.state }),
        ].join(""),
    })
  );

  setHtml(
    root,
    "#r6-table",
    renderResult(results, {
      onLive: (d) => {
        const rows = (d.results || [])
          .map(
            (r) => `<tr>
            <td>${escapeHtml(na(r.fusion_id))}</td>
            <td>${escapeHtml(na(r.event_id))}</td>
            <td>${escapeHtml(na(r.decision))}</td>
            <td>${escapeHtml(fmtPct(r.confidence))}</td>
            <td>${escapeHtml(
              typeof r.disagreement === "boolean"
                ? String(r.disagreement)
                : na(r.disagreement)
            )}</td>
            <td>${escapeHtml(
              Array.isArray(r.participating) ? r.participating.join(", ") || "—" : "—"
            )}</td>
            <td>${escapeHtml(shortTs(r.timestamp))}</td>
          </tr>`
          )
          .join("");
        return dataTable(
          ["Fusion ID", "Event ID", "Decision", "Confidence", "Disagreement", "Sources", "Timestamp"],
          rows,
          "No fused decisions"
        );
      },
    })
  );
}

/* ── R7 ────────────────────────────────────────────────────────── */

export async function renderVerification(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#r7-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "R7 Multi-Stage Verification",
        subtitle: "Read-only timeline. No approve/verify controls.",
      })}
      <div id="r7-shell">
        <div class="pipeline compact" id="r7-ref-stages"></div>
        <div class="section-header"><h2>Status Distribution</h2><span id="r7-extra"></span></div>
        ${chartShell("r7-status-chart", "Verification status counts")}
        <div id="r7-traces"></div>
      </div>`;
    markChartUnavailable(root);
    setHtml(
      root,
      "#r7-ref-stages",
      [
        "WARMUP",
        "DETECTION_EVIDENCE",
        "ATTACK_CONFIRMATION",
        "CONFIDENCE_GATE",
        "ATTACKER_IDENTIFICATION",
        "MITIGATION_ELIGIBILITY",
      ]
        .map((n) => pipelineStage({ name: n, status: "REFERENCE" }))
        .join('<div class="pipe-arrow">→</div>')
    );
  }

  const traces = await api.fetchVerificationTraces(40, ctx.signal);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  setHtml(root, "#r7-extra", stateExtra(traces));
  const list = (traces.data && traces.data.traces) || [];
  paintStatusBar(
    `${CHART_PREFIX}-r7-status`,
    root.querySelector("#r7-status-chart"),
    countBy(list, "status"),
    "Status"
  );

  setHtml(
    root,
    "#r7-traces",
    renderResult(traces, {
      onLive: (d) =>
        (d.traces || [])
          .map((t) => {
            const stages = t.stages || [];
            return `
            <article class="verify-card">
              <header>
                ${statusBadge(t.status || "UNKNOWN")}
                <span>${escapeHtml(shortTs(t.timestamp))}</span>
              </header>
              <div class="verify-meta">
                <span>ID: ${escapeHtml(na(t.verification_id))}</span>
                <span>Event: ${escapeHtml(na(t.event_id))}</span>
                <span>Eligible: ${escapeHtml(String(t.mitigation_eligible ?? "N/A"))}</span>
                <span>Confidence: ${escapeHtml(fmtPct(t.confidence))}</span>
                ${
                  t.event_id
                    ? `<a class="investigate-link" href="#investigation/${encodeURIComponent(
                        String(t.event_id).trim()
                      )}">View Investigation</a>`
                    : ""
                }
              </div>
              <p>${escapeHtml(na(t.reason, ""))}</p>
              ${timeline(stages)}
            </article>`;
          })
          .join(""),
    })
  );
}

/* ── R8 ────────────────────────────────────────────────────────── */

export async function renderAlerts(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#r8-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "R8 Security Alerts",
        subtitle: "Observational only. No resolve/dismiss actions in this UI.",
      })}
      <div id="r8-shell">
        <div class="section-header"><h2>Severity</h2><span id="r8-extra"></span></div>
        <div class="metric-grid" id="r8-sev"></div>
        ${chartShell("r8-sev-chart", "Alert severity distribution")}
        <div class="section-header"><h2>Alert Timeline</h2></div>
        <div id="r8-list" class="alert-list"></div>
      </div>`;
    markChartUnavailable(root);
  }

  const [alerts, stats] = await Promise.all([
    api.fetchSecurityAlerts(50, ctx.signal),
    api.fetchSecurityAlertStats(ctx.signal),
  ]);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  setHtml(root, "#r8-extra", stateExtra(alerts));
  const by =
    (stats.state === "LIVE" || stats.state === "STALE") && stats.data && stats.data.by_severity
      ? stats.data.by_severity
      : countBy((alerts.data && alerts.data.alerts) || [], "severity");

  setHtml(
    root,
    "#r8-sev",
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
      .map((sev) =>
        metricCard({
          title: sev,
          value: fmtNum(by[sev] ?? 0, 0),
          state: stats.state || alerts.state,
        })
      )
      .join("")
  );
  paintStatusBar(`${CHART_PREFIX}-r8-sev`, root.querySelector("#r8-sev-chart"), by, "Severity");

  setHtml(
    root,
    "#r8-list",
    renderResult(alerts, {
      onLive: (d) => {
        const items = d.alerts || [];
        if (!items.length) return "";
        return items.map(alertCard).join("");
      },
    })
  );
}

/* ── Adaptive RL / Drift (legacy RL panel + Phase 6 drift) ───── */

export async function renderAdaptive(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#adaptive-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "Adaptive RL / Drift",
        subtitle: "Phase 7 PPO thresholds and Phase 6 ADWIN drift — observation only.",
        badge: "READ ONLY",
      })}
      <div id="adaptive-shell">
        <div class="advisory banner">
          Thresholds are adjusted by the controller PPO agent. This page does not write RL or drift state.
          Cluster count comes from GET /api/summary (same as legacy stat cards).
        </div>
        ${sectionHeader("RL Adaptive Thresholds", '<span id="ad-rl-extra"></span>')}
        <div class="metric-grid" id="ad-rl-metrics"></div>
        ${chartShell("ad-reward-chart", "RL reward history from /api/rl")}
        <div id="ad-rl-table"></div>
        ${sectionHeader("ADWIN Drift Events", '<span id="ad-drift-extra"></span>')}
        <div id="ad-drift-table"></div>
        ${sectionHeader("Traffic Clusters", '<span id="ad-cluster-extra"></span>')}
        <div class="metric-grid" id="ad-cluster-metrics"></div>
      </div>`;
    markChartUnavailable(root);
  }

  const [rl, drift, summary, ml] = await Promise.all([
    api.fetchRl(40, ctx.signal),
    api.fetchDrift(30, ctx.signal),
    api.fetchSummary(ctx.signal),
    api.fetchMl(5, ctx.signal),
  ]);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  setHtml(root, "#ad-rl-extra", stateExtra(rl));
  const points = chronological((rl.data && (rl.data.points || rl.data.decisions)) || []);
  const latest = (rl.data && rl.data.latest) || points[points.length - 1] || {};
  const mlPoints = (ml.data && (ml.data.points || ml.data.predictions)) || [];
  const mlLatest = (ml.data && ml.data.latest) || mlPoints[mlPoints.length - 1] || {};
  const pkt = Number(latest.pkt_threshold) || 0;
  const byt = Number(latest.byte_threshold) || 0;
  const conf = Number(latest.conf_threshold) || 0;
  const reward = Number(latest.reward);
  setHtml(
    root,
    "#ad-rl-metrics",
    [
      metricCard({
        title: "Packet Rate Limit",
        value: `${fmtNum(pkt, 0)} p/s`,
        state: rl.state,
      }),
      metricCard({
        title: "Byte Rate Limit",
        value: `${fmtNum(byt, 0)} B/s`,
        state: rl.state,
      }),
      metricCard({
        title: "Confidence Gate",
        value: fmtNum(conf, 2),
        state: rl.state,
      }),
      metricCard({
        title: "Last Reward",
        value: Number.isFinite(reward) ? (reward >= 0 ? `+${fmtNum(reward, 2)}` : fmtNum(reward, 2)) : "N/A",
        subtitle: mlLatest.status
          ? `Last ML: ${na(mlLatest.status)} @ ${fmtPct(mlLatest.confidence)}`
          : "Last ML: —",
        state: rl.state,
      }),
    ].join("")
  );

  const rPts = limitPoints(points, 40);
  upsertChart(
    `${CHART_PREFIX}-ad-reward`,
    root.querySelector("#ad-reward-chart"),
    lineChartConfig({
      labels: rPts.map((p) => shortLabel(p.timestamp)),
      datasets: [
        {
          label: "Reward",
          data: rPts.map((p) => Number(p.reward) || 0),
          borderColor: "#a78bfa",
          tension: 0.25,
          pointRadius: 0,
          fill: false,
        },
      ],
    })
  );

  setHtml(
    root,
    "#ad-rl-table",
    renderResult(rl, {
      onLive: () => {
        if (!points.length) return dataTable([], "", "No RL decisions");
        const rows = [...points]
          .reverse()
          .slice(0, 25)
          .map(
            (p) => `<tr>
            <td>${escapeHtml(shortTs(p.timestamp))}</td>
            <td>${escapeHtml(fmtNum(p.pkt_threshold, 0))}</td>
            <td>${escapeHtml(fmtNum(p.byte_threshold, 0))}</td>
            <td>${escapeHtml(fmtNum(p.conf_threshold, 2))}</td>
            <td>${escapeHtml(fmtNum(p.reward, 3))}</td>
            <td>${escapeHtml(na(p.ml_label))}</td>
          </tr>`
          )
          .join("");
        return dataTable(
          ["Timestamp", "Pkt thresh", "Byte thresh", "Conf", "Reward", "ML label"],
          rows,
          "No RL decisions"
        );
      },
    })
  );

  setHtml(root, "#ad-drift-extra", stateExtra(drift));
  const events = (drift.data && (drift.data.events || drift.data.alerts)) || [];
  setHtml(
    root,
    "#ad-drift-table",
    renderResult(drift, {
      onLive: () => {
        if (!events.length) return dataTable([], "", "No drift events");
        const rows = events
          .slice(0, 30)
          .map(
            (e) => `<tr>
            <td>${escapeHtml(shortTs(e.timestamp))}</td>
            <td>${escapeHtml(na(e.metric || e.metric_name))}</td>
            <td>${escapeHtml(na(e.switch_id))}</td>
            <td>${escapeHtml(fmtNum(e.old_mean, 3))}</td>
            <td>${escapeHtml(fmtNum(e.new_mean, 3))}</td>
            <td>${escapeHtml(fmtNum(e.delta, 3))}</td>
          </tr>`
          )
          .join("");
        return dataTable(
          ["Timestamp", "Metric", "Switch", "Old mean", "New mean", "Delta"],
          rows,
          "No drift events"
        );
      },
    })
  );

  setHtml(root, "#ad-cluster-extra", stateExtra(summary));
  const s =
    summary.state === "LIVE" || summary.state === "STALE" || summary.state === "EMPTY"
      ? summary.data || {}
      : {};
  setHtml(
    root,
    "#ad-cluster-metrics",
    [
      metricCard({
        title: "Cluster count",
        value:
          summary.state === "LIVE" || summary.state === "STALE"
            ? fmtNum(s.cluster_count, 0)
            : "N/A",
        subtitle: "From /api/summary (HDBSCAN)",
        state: summary.state,
      }),
    ].join("")
  );
}

/* ── Mitigation / Topology / Twin / etc. (Phase 1 + light upgrades) ─ */

export async function renderMitigation(root, ctx = {}) {
  const blocks = await api.fetchBlocklist(40, ctx.signal);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;
  root.innerHTML = `
    ${pageHeader({
      title: "Mitigation Status",
      subtitle: "READ ONLY — observation of logged OpenFlow blocks (same as legacy Mitigation Blocks).",
      badge: "READ ONLY",
      extra: stateExtra(blocks),
    })}
    <div class="advisory banner">
      Surgical DROP rules are installed by the controller only when R7 verification status is VERIFIED (fail-closed).
      This dashboard does not install, modify, or remove OpenFlow rules — matching legacy UI behavior.
      Lab orchestration (scenarios / controller) lives under <a href="#lab-control">Lab Control</a>.
    </div>
    ${sectionHeader("Block / Action History", stateExtra(blocks))}
    ${renderResult(blocks, {
      onLive: (d) => {
        const rowsSrc = d.blocks || d.actions || [];
        const rows = rowsSrc
          .map(
            (b) => `<tr>
            <td>${escapeHtml(shortTs(b.timestamp))}</td>
            <td>${escapeHtml(na(b.action || b.status))}</td>
            <td>${escapeHtml(na(b.block_type || b.attack_type))}</td>
            <td>${escapeHtml(na(b.attacker_mac || b.src_mac))}</td>
            <td>${escapeHtml(na(b.victim_mac || b.dst_mac))}</td>
            <td>${escapeHtml(fmtPct(b.confidence))}</td>
          </tr>`
          )
          .join("");
        return dataTable(
          ["Timestamp", "Action", "Type", "Attacker", "Victim", "Confidence"],
          rows,
          "No mitigation records"
        );
      },
    })}
  `;
}

export async function renderRca(root) {
  const reports = await api.fetchRcaReports(30);
  root.innerHTML = `
    ${pageHeader({
      title: "R5 Root Cause / XAI",
      subtitle: "Analytical / explanatory only.",
      badge: "ANALYTICAL",
      extra: stateExtra(reports),
    })}
    ${sectionHeader("Root Cause Reports", stateExtra(reports))}
    ${renderResult(reports, {
      onLive: (d) => {
        const rows = (d.reports || [])
          .map(
            (r) => `<tr>
            <td>${escapeHtml(na(r.report_id || r.rca_id))}</td>
            <td>${escapeHtml(na(r.event_id))}</td>
            <td>${escapeHtml(na(r.root_cause || r.summary || r.title))}</td>
            <td>${escapeHtml(fmtPct(r.confidence ?? r.rca_confidence))}</td>
            <td>${escapeHtml(na(r.verification_status))}</td>
            <td>${escapeHtml(shortTs(r.timestamp))}</td>
            <td>${
              r.event_id
                ? `<a class="investigate-link" href="#investigation/${encodeURIComponent(
                    String(r.event_id).trim()
                  )}">View Investigation</a>`
                : "N/A"
            }</td>
          </tr>`
          )
          .join("");
        return dataTable(
          ["Report ID", "Event ID", "Root Cause", "Confidence", "Verification", "Timestamp", ""],
          rows,
          "No RCA reports"
        );
      },
    })}
  `;
}

export async function renderTopology(root) {
  destroyPageCharts();
  const topo = await api.fetchTopology();
  root.innerHTML = `
    ${pageHeader({
      title: "Network Topology",
      subtitle: "READ ONLY — switches and learned hosts from the live controller snapshot.",
      badge: "READ ONLY",
      extra: stateExtra(topo),
    })}
    <div class="advisory banner">
      Observational only. Host–switch attachments come from L2 learning.
      Switch–switch links are not discovered (LLDP unused). No control actions.
    </div>
    <div id="topo-metrics" class="metric-grid"></div>
    ${sectionHeader("Switches", "")}
    <div id="topo-switches"></div>
    ${sectionHeader("Learned hosts", "")}
    <div id="topo-hosts"></div>
    ${sectionHeader("Host ↔ switch attachments", "")}
    <div id="topo-links"></div>
    <div id="topo-last-known"></div>
    <div id="topo-limits" class="panel muted" style="margin-top:1rem"></div>
  `;

  const metrics = root.querySelector("#topo-metrics");
  const swEl = root.querySelector("#topo-switches");
  const hostEl = root.querySelector("#topo-hosts");
  const linkEl = root.querySelector("#topo-links");
  const lastEl = root.querySelector("#topo-last-known");
  const limEl = root.querySelector("#topo-limits");

  const paint = (result) => {
    if (metrics) {
      metrics.innerHTML = renderResult(result, {
        onLive: (d) => {
          const freshness = d.freshness || "LIVE";
          return [
            metricCard({
              title: "Switches",
              value: fmtNum(d.switch_count, 0),
              state: freshness,
            }),
            metricCard({
              title: "Hosts",
              value: fmtNum(d.host_count, 0),
              state: freshness,
              subtitle: "Appear after traffic",
            }),
            metricCard({
              title: "Attachments",
              value: fmtNum(d.link_count, 0),
              state: freshness,
            }),
            metricCard({
              title: "Freshness",
              value: freshness,
              state: freshness,
              subtitle: d.updated_at ? `Updated ${d.updated_at}` : "No snapshot yet",
            }),
          ].join("");
        },
        onEmpty: () =>
          metricCard({
            title: "Topology",
            value: "UNAVAILABLE",
            state: "NO DATA",
            subtitle: "Start controller + Mininet to publish snapshot",
          }),
      });
    }

    if (swEl) {
      swEl.innerHTML = renderResult(result, {
        onEmpty: () =>
          emptyTopo("No switches", "Controller has not published connected datapaths yet."),
        onLive: (d) => {
          if (!(d.switches || []).length) {
            return emptyTopo(
              "No switches connected",
              "Mininet is down or the scenario ended. Last-known inventory is shown below if available. Start a legacy scenario (or Mininet) to reconnect switches."
            );
          }
          const rows = (d.switches || [])
            .map(
              (s) => `
            <tr>
              <td>${escapeHtml(na(s.name))}</td>
              <td><code>${escapeHtml(na(s.dpid_hex))}</code></td>
              <td>${escapeHtml(na(s.dpid))}</td>
            </tr>`
            )
            .join("");
          return dataTable(
            ["Switch", "DPID (hex)", "DPID"],
            rows,
            "No switches connected"
          );
        },
      });
    }

    if (hostEl) {
      hostEl.innerHTML = renderResult(result, {
        onEmpty: () =>
          emptyTopo(
            "No learned hosts",
            "Hosts appear after they send traffic (ARP/ICMP/etc.)."
          ),
        onLive: (d) => {
          if (!(d.hosts || []).length) {
            return emptyTopo(
              "No learned hosts yet",
              "Generate traffic (legacy Attack Lab / ping) so MACs are learned."
            );
          }
          const rows = (d.hosts || [])
            .map(
              (h) => `
            <tr>
              <td><code>${escapeHtml(na(h.mac))}</code></td>
              <td>${escapeHtml(na(h.switch))}</td>
              <td>${escapeHtml(na(h.port))}</td>
              <td><code>${escapeHtml(na(h.dpid_hex))}</code></td>
            </tr>`
            )
            .join("");
          return dataTable(
            ["MAC", "Switch", "Port", "DPID"],
            rows,
            "No hosts"
          );
        },
      });
    }

    if (linkEl) {
      linkEl.innerHTML = renderResult(result, {
        onEmpty: () => emptyTopo("No attachments", "No host↔switch edges yet."),
        onLive: (d) => {
          if (!(d.links || []).length) {
            return emptyTopo("No attachments yet", "Waiting for host learning.");
          }
          const rows = (d.links || [])
            .map(
              (l) => `
            <tr>
              <td><code>${escapeHtml(na(l.src))}</code></td>
              <td>${escapeHtml(na(l.dst_name || l.dst))}</td>
              <td>${escapeHtml(na(l.port))}</td>
            </tr>`
            )
            .join("");
          return dataTable(["Host MAC", "Switch", "Port"], rows, "No links");
        },
      });
    }

    if (lastEl) {
      lastEl.innerHTML = renderResult(result, {
        onLive: (d) => {
          const lk = d.last_known;
          if (!lk || d.switch_count > 0) return "";
          const swRows = (lk.switches || [])
            .map(
              (s) =>
                `<tr><td>${escapeHtml(na(s.name))}</td><td><code>${escapeHtml(
                  na(s.dpid_hex)
                )}</code></td></tr>`
            )
            .join("");
          const hRows = (lk.hosts || [])
            .slice(0, 20)
            .map(
              (h) =>
                `<tr><td><code>${escapeHtml(na(h.mac))}</code></td><td>${escapeHtml(
                  na(h.switch)
                )}</td></tr>`
            )
            .join("");
          return `
            <section class="panel" style="margin-top:1rem">
              <h3>Last known topology ${statusBadge("STALE")}</h3>
              <p class="muted">${escapeHtml(
                lk.note || "Shown because no switches are connected right now."
              )}
              Updated: ${escapeHtml(na(lk.updated_at))}</p>
              ${sectionHeader("Last known switches", "")}
              ${dataTable(["Switch", "DPID"], swRows, "None")}
              ${sectionHeader("Last known hosts", "")}
              ${dataTable(["MAC", "Switch"], hRows, "None")}
            </section>`;
        },
      });
    }

    if (limEl) {
      const d = result?.data;
      const limits = (d && d.limitations) || [];
      limEl.innerHTML = `<strong>Limitations</strong><ul>${limits
        .map((x) => `<li>${escapeHtml(String(x))}</li>`)
        .join("")}</ul><p>${escapeHtml(na(d?.note))}</p>`;
    }
  };

  function emptyTopo(title, body) {
    return `<div class="state-panel state-empty"><strong>${escapeHtml(
      title
    )}</strong><p>${escapeHtml(body)}</p></div>`;
  }

  paint(topo);
}

export async function renderTwin(root) {
  const [stats, snaps, runs, replays, sims] = await Promise.all([
    api.fetchTwinStats(),
    api.fetchTwinSnapshots(20),
    api.fetchTwinRuns(20),
    api.fetchTwinReplays(20),
    api.fetchTwinSimulations(20),
  ]);

  const fidelityBadge = (fid) => {
    if (!fid) return statusBadge("NOT_AVAILABLE");
    const o = String(fid.overall || "").toUpperCase();
    if (o === "PASS") return statusBadge("PASS");
    if (o === "FAIL") return statusBadge("FAIL");
    if (o === "PASS_WITH_GAPS") return statusBadge("PARTIAL");
    return statusBadge("SNAPSHOT");
  };

  root.innerHTML = `
    ${pageHeader({
      title: "R3 Digital Twin",
      subtitle: "DIGITAL TWIN · READ ONLY · SNAPSHOT · OBSERVATIONAL · LEVEL A",
      badge: "SNAPSHOT",
      extra: stateExtra(stats),
    })}
    <div class="advisory banner">
      Digital Twin is observational and <strong>READ ONLY</strong>.
      No Start Attack, Execute, Promote, or OpenFlow controls on this page.
      Twin never launches Mininet from the SOC.
    </div>
    ${sectionHeader("Twin Stats", stateExtra(stats))}
    ${renderResult(stats, {
      onLive: (d) => {
        const cards = [
          ["Snapshots", d.snapshots ?? 0],
          ["Replays", d.replays ?? 0],
          ["Simulations", d.simulations ?? 0],
          ["Runs", d.runs ?? 0],
        ]
          .map(
            ([t, v]) =>
              `<div class="metric-card"><div class="metric-title">${escapeHtml(
                t
              )}</div><div class="metric-value">${escapeHtml(String(v))}</div></div>`
          )
          .join("");
        return `<div class="metric-grid">${cards}</div>
          <p class="muted">control=${escapeHtml(na(d.control))} · source=${escapeHtml(
          na(d.source)
        )}</p>`;
      },
    })}
    ${sectionHeader("Snapshots + Fidelity", stateExtra(snaps))}
    ${renderResult(snaps, {
      onLive: (d) => {
        const rows = (d.snapshots || [])
          .map((s) => {
            const fid = s.fidelity || {};
            const sum = fid.summary || {};
            return `<tr>
            <td>${escapeHtml(na(s.snapshot_id || s.id))}</td>
            <td>${escapeHtml(shortTs(s.created_at || s.timestamp))}</td>
            <td>${fidelityBadge(fid)}</td>
            <td>${escapeHtml(
              `P${sum.PASS ?? "—"}/F${sum.FAIL ?? "—"}/N${sum.NOT_AVAILABLE ?? "—"}`
            )}</td>
            <td>${escapeHtml(String(s.n_windows ?? "—"))}</td>
          </tr>`;
          })
          .join("");
        return dataTable(
          ["Snapshot ID", "Created", "Overall", "PASS/FAIL/N/A", "Windows"],
          rows,
          "No snapshots"
        );
      },
    })}
    ${sectionHeader("Replays", stateExtra(replays))}
    ${renderResult(replays, {
      onLive: (d) => {
        const rows = (d.replays || [])
          .map(
            (r) => `<tr>
            <td>${escapeHtml(na(r.replay_id))}</td>
            <td>${escapeHtml(na(r.scenario_id))}</td>
            <td>${
              r.sequence_ok === true
                ? statusBadge("PASS")
                : r.sequence_ok === false
                  ? statusBadge("FAIL")
                  : statusBadge("NOT_AVAILABLE")
            }</td>
            <td>${escapeHtml(
              r.temporal_error != null ? String(r.temporal_error) : "—"
            )}</td>
            <td>${escapeHtml(na(r.snapshot_id))}</td>
          </tr>`
          )
          .join("");
        return dataTable(
          ["Replay ID", "Scenario", "Sequence", "Temporal err", "Snapshot"],
          rows,
          "No replays"
        );
      },
    })}
    ${sectionHeader("What-if Simulations", stateExtra(sims))}
    ${renderResult(sims, {
      onLive: (d) => {
        const rows = (d.simulations || [])
          .map(
            (s) => `<tr>
            <td>${escapeHtml(na(s.simulation_id))}</td>
            <td>${escapeHtml(na(s.scenario_id))}</td>
            <td>${escapeHtml(na(s.snapshot_id))}</td>
            <td><code>${escapeHtml(
              JSON.stringify(s.overrides || s.parameters || {}).slice(0, 80)
            )}</code></td>
          </tr>`
          )
          .join("");
        return dataTable(
          ["Simulation ID", "Scenario", "Snapshot", "Overrides"],
          rows,
          "No simulations"
        );
      },
    })}
    ${sectionHeader("Experiment Runs", stateExtra(runs))}
    ${renderResult(runs, {
      onLive: (d) => {
        const rows = (d.runs || [])
          .map(
            (r) => `<tr>
            <td>${escapeHtml(na(r.run_id || r.id))}</td>
            <td>${escapeHtml(na(r.status || r.validation_status))}</td>
            <td>${escapeHtml(shortTs(r.timestamp || r.created_at))}</td>
          </tr>`
          )
          .join("");
        return dataTable(["Run ID", "Status", "Timestamp"], rows, "No twin runs");
      },
    })}
  `;
}

export async function renderAttackLab(root) {
  destroyPageCharts();
  root.innerHTML = `
    ${pageHeader({
      title: "Attack Lab",
      subtitle: "Redirected — use Lab Control for real scenario / controller actions.",
      badge: "MOVED",
    })}
    <div class="advisory banner">
      Legacy Master Control write actions are available under
      <a href="#lab-control"><strong>Lab Control</strong></a>
      (restart/stop controller, archive, scenarios S1–S5, batch eval, metrics, train, bundle).
      This route is kept as an alias so old bookmarks still resolve.
    </div>
    <p class="muted"><a href="#lab-control">Open Lab Control →</a> · Legacy fallback: <a href="/legacy">/legacy</a></p>
  `;
}

export async function renderSettings(root) {
  destroyPageCharts();
  root.innerHTML = `
    ${pageHeader({
      title: "Settings",
      subtitle: "Identity and readiness. Backend detection/mitigation thresholds are not editable from the browser.",
      badge: "READ ONLY",
    })}
    <div class="settings-grid" data-settings-root>
      <section class="panel">
        <h3>Current backend configuration</h3>
        <p class="muted">Not editable from this UI (same constraint as legacy). Thresholds, confidence, mitigation, and ML config remain server-side / controller-side.</p>
      </section>
      <section class="panel">
        <h3>UI preferences</h3>
        <p class="muted">No browser preference editor existed in the legacy UI. Operational parity does not require one; theme/layout remain fixed in CSS.</p>
      </section>
      <div data-identity-slot></div>
      <div data-readiness-slot></div>
    </div>
  `;

  const identitySlot = root.querySelector("[data-identity-slot]");
  const readinessSlot = root.querySelector("[data-readiness-slot]");

  async function refreshIdentity() {
    const [meRes, statusRes] = await Promise.all([
      authApi.fetchAuthMe(),
      authApi.fetchAuthStatus(),
    ]);
    const me = meRes.state === "LIVE" ? meRes.data : null;
    const status = statusRes.state === "LIVE" ? statusRes.data : null;
    const authView = {
      authentication_configured:
        (me && me.authentication_configured) ||
        (status && status.authentication_configured) ||
        false,
      authenticated: !!(me && me.authenticated),
      principal: me && me.principal,
      authorization_implemented:
        (me && me.authorization_implemented) ||
        (status && status.authorization_implemented) ||
        false,
      rbac_enabled:
        (me && me.rbac_enabled) || (status && status.rbac_enabled) || false,
      operator_controls_enabled: false,
    };
    if (identitySlot) {
      identitySlot.innerHTML = identityPanelHtml(escapeHtml, statusBadge, me, status);
      wireIdentityActions(identitySlot, refreshIdentity);
    }
    if (readinessSlot) {
      readinessSlot.innerHTML = operatorReadinessHtml(escapeHtml, statusBadge, authView);
    }
  }

  await refreshIdentity();
}

function wireIdentityActions(container, onDone) {
  const msg = container.querySelector("[data-auth-msg]");
  const loginBtn = container.querySelector("[data-auth-login]");
  const logoutBtn = container.querySelector("[data-auth-logout]");

  function showMsg(text, isError) {
    if (!msg) return;
    msg.hidden = !text;
    msg.textContent = text || "";
    msg.classList.toggle("identity-error", !!isError);
  }

  if (loginBtn) {
    loginBtn.addEventListener("click", async () => {
      const userEl = container.querySelector('input[name="username"]');
      const passEl = container.querySelector('input[name="password"]');
      const username = userEl ? userEl.value : "";
      const password = passEl ? passEl.value : "";
      showMsg("Signing in…", false);
      const result = await authApi.login({ username, password });
      if (!result.ok) {
        showMsg(result.error || "Authentication failed", true);
        return;
      }
      // Clear password field from DOM
      if (passEl) passEl.value = "";
      await onDone();
    });
  }
  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      await authApi.logout();
      await onDone();
    });
  }
}
