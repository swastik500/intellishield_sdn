/**
 * Phase 5 — Security Reports & Historical Analysis (read-only).
 * Aggregates bounded GET data. No operator actions. Does not invent historical records.
 */

import { fetchReportsBundle } from "../api/reports.js";
import {
  pageHeader,
  sectionHeader,
  metricCard,
  statusBadge,
  dataTable,
  comingSoon,
  provenanceBanner,
  investigationNav,
  dataQualitySummary,
} from "../components/ui.js";
import { escapeHtml, na, fmtNum, fmtPct, shortTs } from "../utils/format.js";
import {
  upsertChart,
  destroyAllCharts,
  lineChartConfig,
  barChartConfig,
  chartShell,
  markChartUnavailable,
  shortLabel,
  limitPoints,
} from "../utils/charts.js";
import {
  TIME_RANGES,
  REPORT_LIMIT,
  DATA_AVAILABILITY,
  resolveRange,
  filterByTime,
  countBy,
  bucketByTime,
  sectionState,
  extractFeatureNames,
  safeExportPayload,
  toCsv,
  downloadBlob,
  CHART_POINT_LIMIT,
  parseTs,
} from "../utils/report.js";
import {
  buildProvenance,
  FilterMode,
  Completeness,
  Linkability,
  QUALITY_SUMMARY,
  datasetJoinability,
  validateListResponse,
  normalizeList,
} from "../utils/provenance.js";

const CHART_PREFIX = "soc-p5-reports";

let uiState = {
  rangeKey: "24h",
  customFrom: "",
  customTo: "",
  severity: "",
};

function setHtml(root, sel, html) {
  const el = root.querySelector(sel);
  if (el) el.innerHTML = html;
}

function limitNote(shown, fetched, cap, filterMode) {
  const mode = filterMode || "CLIENT FILTERED";
  if (fetched >= cap) {
    return `${mode}. Showing ${shown} of ${fetched} retrieved (API bound ≤ ${cap}). Additional older records may exist on disk — this is not a complete historical population.`;
  }
  return `${mode}. Showing ${shown} of ${fetched} retrieved records (API bound ≤ ${cap}).`;
}

function invLink(eventId) {
  return investigationNav(eventId);
}

function makeProv(sourceKey, result, displayed, retrieved, opts = {}) {
  const total =
    result?.data && typeof result.data.total === "number" ? result.data.total : null;
  return buildProvenance({
    sourceKey,
    result,
    retrievedCount: retrieved,
    displayedCount: displayed,
    totalReported: total != null && total !== retrieved ? total : null,
    filterMode: opts.filterMode || FilterMode.CLIENT,
    historical: true,
    snapshot: !!opts.snapshot,
    joinability: opts.joinability || Linkability.UNKNOWN,
    completeness: opts.completeness || Completeness.BOUNDED,
    limitations: opts.limitations || [],
    timeRangeLabel: opts.timeRangeLabel || null,
  });
}

function notAvailable(title, body) {
  return `
    <div class="state-panel state-empty">
      <strong>${escapeHtml(title)}</strong>
      <p>${escapeHtml(body)}</p>
    </div>`;
}

function paintBar(key, canvas, counts, label) {
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
            "rgba(45,212,191,0.55)",
          ],
        },
      ],
    })
  );
}

function paintActivity(key, canvas, bucket) {
  const labels = (bucket.labels || []).slice(-CHART_POINT_LIMIT);
  const data = (bucket.counts || []).slice(-CHART_POINT_LIMIT);
  return upsertChart(
    key,
    canvas,
    lineChartConfig({
      labels,
      datasets: [
        {
          label: "Count",
          data,
          borderColor: "#3aa0ff",
          backgroundColor: "rgba(58,160,255,0.12)",
          fill: true,
          tension: 0.2,
          pointRadius: 0,
        },
      ],
    })
  );
}

function buildExportObject(ctx) {
  const { range, sections, unavailable, provenanceBySection } = ctx;
  return safeExportPayload({
    title: "IntelliShield Security Report",
    generated: new Date().toISOString(),
    data_period: range.label,
    range_from: range.fromMs ? new Date(range.fromMs).toISOString() : null,
    range_to: range.toMs ? new Date(range.toMs).toISOString() : null,
    data_state: unavailable.length ? "PARTIAL REPORT" : "HISTORICAL",
    unavailable_sections: unavailable,
    provenance: provenanceBySection || {},
    timezone_note:
      "Timestamps are backend-authored. Display follows source strings; range selection uses browser clock only as a window bound.",
    overall_threat_score: null,
    overall_security_score: null,
    sections,
  });
}

function bindControls(root, reload) {
  const shell = root.querySelector("#reports-shell");
  if (!shell || shell.dataset.bound === "1") return;
  shell.dataset.bound = "1";

  shell.addEventListener("change", (ev) => {
    const t = ev.target;
    if (!(t instanceof HTMLElement)) return;
    if (t.id === "rep-range") {
      uiState.rangeKey = t.value;
      root.querySelector("#rep-custom")?.classList.toggle("hidden", t.value !== "custom");
    }
    if (t.id === "rep-from") uiState.customFrom = t.value;
    if (t.id === "rep-to") uiState.customTo = t.value;
    if (t.id === "rep-severity") uiState.severity = t.value;
  });

  shell.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-rep-action]");
    if (!btn) return;
    const action = btn.getAttribute("data-rep-action");
    if (action === "reload") reload();
    if (action === "export-json") {
      const payload = window.__SOC_REPORT_EXPORT__;
      if (!payload) return;
      downloadBlob(
        `intellishield-report-${Date.now()}.json`,
        JSON.stringify(payload, null, 2),
        "application/json"
      );
    }
    if (action === "export-csv") {
      const rows = window.__SOC_REPORT_CSV_ROWS__ || [];
      const headers = [
        "section",
        "timestamp",
        "event_id",
        "status",
        "severity",
        "decision",
        "score",
        "confidence",
      ];
      downloadBlob(`intellishield-report-${Date.now()}.csv`, toCsv(rows, headers), "text/csv");
    }
    if (action === "print") window.print();
  });
}

function overviewMetrics(agg) {
  return [
    metricCard({
      title: "Detection Events",
      value: fmtNum(agg.detectionCount, 0),
      state: "HISTORICAL",
      subtitle: "From detection API records in window",
    }),
    metricCard({
      title: "Verified (R7)",
      value: fmtNum(agg.verified, 0),
      state: "HISTORICAL",
    }),
    metricCard({
      title: "Pending (R7)",
      value: fmtNum(agg.pending, 0),
      state: "HISTORICAL",
    }),
    metricCard({
      title: "Ineligible (R7)",
      value: fmtNum(agg.ineligible, 0),
      state: "HISTORICAL",
    }),
    metricCard({
      title: "Critical Alerts (R8)",
      value: fmtNum(agg.critical, 0),
      state: "HISTORICAL",
    }),
    metricCard({
      title: "High Alerts (R8)",
      value: fmtNum(agg.high, 0),
      state: "HISTORICAL",
    }),
    metricCard({
      title: "R4 Correlations",
      value: fmtNum(agg.r4, 0),
      state: "HISTORICAL",
      subtitle: "ADVISORY",
    }),
    metricCard({
      title: "R6 Fusion Decisions",
      value: fmtNum(agg.r6, 0),
      state: "HISTORICAL",
    }),
    metricCard({
      title: "R5 RCA Reports",
      value: fmtNum(agg.r5, 0),
      state: "HISTORICAL",
    }),
    metricCard({
      title: "Overall Security Score",
      value: "N/A",
      state: "NOT AVAILABLE",
      subtitle: "Not exposed by backend",
    }),
  ].join("");
}

export async function renderReports(root, ctx = {}) {
  const soft = false; // historical reports: load on entry / explicit reload only
  destroyAllCharts(CHART_PREFIX);

  if (!root.querySelector("#reports-shell")) {
    root.innerHTML = `
      ${pageHeader({
        title: "Security Reports",
        subtitle: "Historical analysis from bounded GET records. Observer mode — no report jobs or reprocessing.",
        badge: "READ ONLY",
      })}
      <div id="reports-shell">
        <section class="panel report-controls" aria-label="Report filters">
          <div class="controls-row">
            <label>
              Time range
              <select id="rep-range">
                ${Object.entries(TIME_RANGES)
                  .map(
                    ([k, v]) =>
                      `<option value="${escapeHtml(k)}" ${
                        k === uiState.rangeKey ? "selected" : ""
                      }>${escapeHtml(v.label)}</option>`
                  )
                  .join("")}
              </select>
            </label>
            <div id="rep-custom" class="controls-row ${uiState.rangeKey === "custom" ? "" : "hidden"}">
              <label>From <input id="rep-from" type="datetime-local" value="${escapeHtml(
                uiState.customFrom
              )}" /></label>
              <label>To <input id="rep-to" type="datetime-local" value="${escapeHtml(
                uiState.customTo
              )}" /></label>
            </div>
            <label>
              R8 severity (API filter)
              <select id="rep-severity">
                <option value="">All</option>
                ${["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                  .map(
                    (s) =>
                      `<option value="${s}" ${uiState.severity === s ? "selected" : ""}>${s}</option>`
                  )
                  .join("")}
              </select>
            </label>
            <button type="button" class="btn" data-rep-action="reload">Reload report</button>
            <button type="button" class="btn ghost" data-rep-action="export-json">Export JSON</button>
            <button type="button" class="btn ghost" data-rep-action="export-csv">Export CSV</button>
            <button type="button" class="btn ghost" data-rep-action="print">Print</button>
          </div>
          <p class="muted" id="rep-range-note"></p>
          <p class="muted">Selecting a time range does <strong>not</strong> guarantee backend filtering except where noted (R8 since/until). Other sections filter client-side on bounded retrieved records.</p>
        </section>

        <div id="rep-body" aria-busy="true">
          <div class="state-panel"><strong>LOADING</strong><p>Retrieving bounded historical records…</p></div>
        </div>
      </div>`;
    markChartUnavailable(root);
  }

  const reload = () => renderReports(root, { ...ctx, soft: false });
  bindControls(root, reload);

  // Sync controls from uiState
  const rangeEl = root.querySelector("#rep-range");
  if (rangeEl) rangeEl.value = uiState.rangeKey;
  const sevEl = root.querySelector("#rep-severity");
  if (sevEl) sevEl.value = uiState.severity;

  const range = resolveRange(uiState.rangeKey, uiState.customFrom, uiState.customTo);
  setHtml(root, "#rep-range-note", escapeHtml(range.note));

  const sinceIso = range.fromMs != null ? new Date(range.fromMs).toISOString() : null;
  const untilIso = range.toMs != null ? new Date(range.toMs).toISOString() : null;

  const bundle = await fetchReportsBundle({
    signal: ctx.signal,
    sinceIso: uiState.rangeKey === "all" ? null : sinceIso,
    untilIso: uiState.rangeKey === "all" ? null : untilIso,
    severity: uiState.severity || undefined,
  });
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  // Optional client severity re-filter if API ignored empty
  let r8raw = (bundle.securityAlerts.data && bundle.securityAlerts.data.alerts) || [];
  if (uiState.severity) {
    r8raw = r8raw.filter((a) => String(a.severity || "").toUpperCase() === uiState.severity);
  }
  // When backend since/until used, still allow client filter for consistency
  const r8 = filterByTime(r8raw, "timestamp", range.fromMs, range.toMs);

  const detRaw = (bundle.detection.data && bundle.detection.data.alerts) || [];
  const det = filterByTime(detRaw, "timestamp", range.fromMs, range.toMs);

  const r4Raw = (bundle.correlation.data && bundle.correlation.data.results) || [];
  const r4 = filterByTime(r4Raw, "timestamp", range.fromMs, range.toMs);

  const r6Raw = (bundle.fusion.data && bundle.fusion.data.results) || [];
  const r6 = filterByTime(r6Raw, "timestamp", range.fromMs, range.toMs);

  const r7Raw = (bundle.verification.data && bundle.verification.data.traces) || [];
  const r7 = filterByTime(r7Raw, "timestamp", range.fromMs, range.toMs);

  const r5Raw = (bundle.rca.data && bundle.rca.data.reports) || [];
  const r5 = filterByTime(r5Raw, "timestamp", range.fromMs, range.toMs);

  const trafRaw = (bundle.traffic.data && bundle.traffic.data.points) || [];
  const traf = filterByTime(trafRaw, "timestamp", range.fromMs, range.toMs);

  const entRaw = (bundle.entropy.data && bundle.entropy.data.points) || [];
  const ent = filterByTime(entRaw, "timestamp", range.fromMs, range.toMs);

  const twinSnaps = (bundle.twinSnapshots.data && bundle.twinSnapshots.data.snapshots) || [];
  const twinRuns = (bundle.twinRuns.data && bundle.twinRuns.data.runs) || [];
  const twinReplays = (bundle.twinReplays && bundle.twinReplays.data && bundle.twinReplays.data.replays) || [];
  const twinSims =
    (bundle.twinSimulations && bundle.twinSimulations.data && bundle.twinSimulations.data.simulations) ||
    [];
  const twinWithFid = twinSnaps.filter((s) => s.fidelity && s.fidelity.overall);
  const twinOverallCounts = twinWithFid.reduce((acc, s) => {
    const o = s.fidelity.overall || "UNKNOWN";
    acc[o] = (acc[o] || 0) + 1;
    return acc;
  }, {});

  const r7ByStatus = countBy(r7, "status");
  const r8BySev = countBy(r8, "severity");
  const features = extractFeatureNames(r5);

  const agg = {
    detectionCount: det.length,
    verified: r7ByStatus.VERIFIED || 0,
    pending: r7ByStatus.PENDING || 0,
    ineligible: r7ByStatus.INELIGIBLE || 0,
    failed: r7ByStatus.FAILED || 0,
    critical: r8BySev.CRITICAL || 0,
    high: r8BySev.HIGH || 0,
    r4: r4.length,
    r6: r6.length,
    r5: r5.length,
  };

  const unavailable = DATA_AVAILABILITY.filter((d) => !d.available).map((d) => d.name);

  const csvRows = [];
  for (const a of det.slice(0, 500)) {
    csvRows.push({
      section: "detection",
      timestamp: a.timestamp || "",
      event_id: a.event_id || "",
      status: a.status || a.alert_type || "",
      severity: "",
      decision: "",
      score: "",
      confidence: a.confidence ?? "",
    });
  }
  for (const a of r4.slice(0, 500)) {
    csvRows.push({
      section: "r4",
      timestamp: a.timestamp || "",
      event_id: a.event_id || "",
      status: a.status || a.label || "",
      severity: "",
      decision: "",
      score: a.score ?? a.correlation_score ?? "",
      confidence: a.confidence ?? "",
    });
  }
  for (const a of r6.slice(0, 500)) {
    csvRows.push({
      section: "r6",
      timestamp: a.timestamp || "",
      event_id: a.event_id || "",
      status: "",
      severity: "",
      decision: a.decision || "",
      score: "",
      confidence: a.confidence ?? "",
    });
  }
  for (const a of r7.slice(0, 500)) {
    csvRows.push({
      section: "r7",
      timestamp: a.timestamp || "",
      event_id: a.event_id || "",
      status: a.status || "",
      severity: "",
      decision: "",
      score: "",
      confidence: a.confidence ?? "",
    });
  }
  for (const a of r8.slice(0, 500)) {
    csvRows.push({
      section: "r8",
      timestamp: a.timestamp || "",
      event_id: a.event_id || "",
      status: a.alert_type || "",
      severity: a.severity || "",
      decision: "",
      score: "",
      confidence: a.confidence ?? "",
    });
  }
  for (const a of r5.slice(0, 500)) {
    csvRows.push({
      section: "r5",
      timestamp: a.timestamp || "",
      event_id: a.event_id || "",
      status: a.verification_status || "",
      severity: "",
      decision: a.root_cause || a.summary || "",
      score: "",
      confidence: a.confidence ?? a.rca_confidence ?? "",
    });
  }

  const period = range.label;
  const stDet = sectionState(bundle.detection, det.length, detRaw.length > 0);
  const stR4 = sectionState(bundle.correlation, r4.length, r4Raw.length > 0);
  const stR6 = sectionState(bundle.fusion, r6.length, r6Raw.length > 0);
  const stR7 = sectionState(bundle.verification, r7.length, r7Raw.length > 0);
  const stR8 = sectionState(bundle.securityAlerts, r8.length, r8raw.length > 0);
  const stR5 = sectionState(bundle.rca, r5.length, r5Raw.length > 0);
  void sectionState(bundle.traffic, traf.length, trafRaw.length > 0);
  void sectionState(bundle.entropy, ent.length, entRaw.length > 0);

  // Soft validation — flag data errors without crashing
  const detShape = validateListResponse(bundle.detection?.data, "alerts");
  const r8Shape = validateListResponse(bundle.securityAlerts?.data, "alerts");

  const provDet = makeProv("detection", bundle.detection, det.length, detRaw.length, {
    filterMode: FilterMode.CLIENT,
    joinability: Linkability.NOT_AVAILABLE,
    completeness: Completeness.PARTIAL,
    timeRangeLabel: period,
    limitations: [
      "Legacy source",
      "Event linkage unavailable (no reliable event_id)",
      "Server-side time filtering not available",
    ],
  });
  const provR4 = makeProv("r4", bundle.correlation, r4.length, r4Raw.length, {
    joinability: datasetJoinability({ capabilityEventId: true, records: r4 }),
    completeness: Completeness.BOUNDED,
    timeRangeLabel: period,
    limitations: ["ADVISORY / ANALYTICAL — does not authorize mitigation", "CLIENT FILTERED on bounded GET"],
  });
  const provR6 = makeProv("r6", bundle.fusion, r6.length, r6Raw.length, {
    joinability: datasetJoinability({ capabilityEventId: true, records: r6 }),
    completeness: Completeness.BOUNDED,
    timeRangeLabel: period,
  });
  const provR7 = makeProv("r7", bundle.verification, r7.length, r7Raw.length, {
    joinability: datasetJoinability({ capabilityEventId: true, records: r7 }),
    completeness: Completeness.BOUNDED,
    timeRangeLabel: period,
  });
  const r8ServerFiltered = uiState.rangeKey !== "all";
  const provR8 = makeProv("r8", bundle.securityAlerts, r8.length, r8raw.length, {
    filterMode: r8ServerFiltered ? FilterMode.SERVER : FilterMode.NONE,
    joinability: datasetJoinability({ capabilityEventId: true, records: r8 }),
    completeness: Completeness.COMPLETE,
    timeRangeLabel: period,
    limitations: r8ServerFiltered
      ? ["SERVER FILTERED via since/until when ranged"]
      : ["No time window applied (all retrieved)"],
  });
  const provR5 = makeProv("r5", bundle.rca, r5.length, r5Raw.length, {
    joinability: datasetJoinability({ capabilityEventId: true, records: r5 }),
    completeness: Completeness.BOUNDED,
    timeRangeLabel: period,
    limitations: ["XAI contribution weights NOT AVAILABLE — feature presence only"],
  });
  const provTraf = makeProv("traffic", bundle.traffic, traf.length, trafRaw.length, {
    joinability: Linkability.NOT_AVAILABLE,
    completeness: Completeness.BOUNDED,
    timeRangeLabel: period,
    limitations: ["No event_id", "Protocol distribution NOT AVAILABLE"],
  });
  const provEnt = makeProv("entropy", bundle.entropy, ent.length, entRaw.length, {
    joinability: Linkability.NOT_AVAILABLE,
    completeness: Completeness.BOUNDED,
    timeRangeLabel: period,
    limitations: ["Entropy threshold N/A — not exposed by backend"],
  });
  const provTwin = makeProv("twin", bundle.twinSnapshots, twinSnaps.length, twinSnaps.length, {
    snapshot: true,
    filterMode: FilterMode.NONE,
    joinability: Linkability.NOT_AVAILABLE,
    completeness: Completeness.BOUNDED,
    timeRangeLabel: period,
    limitations: ["SNAPSHOT · OBSERVATIONAL · READ ONLY — not production attack history"],
  });

  void normalizeList; // available for callers; lists already filtered from API arrays

  const exportObj = buildExportObject({
    range,
    unavailable,
    provenanceBySection: {
      detection: provDet,
      r4: provR4,
      r6: provR6,
      r7: provR7,
      r8: provR8,
      r5: provR5,
      traffic: provTraf,
      entropy: provEnt,
      twin: provTwin,
    },
    sections: {
      overview: agg,
      detection: { count: det.length, by_type: countBy(det, "alert_type") },
      r4: { count: r4.length, by_status: countBy(r4, "status") },
      r6: { count: r6.length, by_decision: countBy(r6, "decision") },
      r7: { count: r7.length, by_status: r7ByStatus },
      r8: { count: r8.length, by_severity: r8BySev },
      r5: { count: r5.length, feature_presence: features },
      traffic: { count: traf.length },
      entropy: { count: ent.length },
      twin: {
        snapshots: twinSnaps.length,
        runs: twinRuns.length,
        label: "SNAPSHOT · OBSERVATIONAL",
      },
      health_history: "NOT AVAILABLE",
      topology_history: "NOT AVAILABLE",
      xai_weights: "NOT AVAILABLE",
    },
  });
  window.__SOC_REPORT_EXPORT__ = exportObj;
  window.__SOC_REPORT_CSV_ROWS__ = csvRows;

  const body = `
    ${dataQualitySummary(QUALITY_SUMMARY)}

    ${sectionHeader("Overview", statusBadge("HISTORICAL"))}
    <div class="metric-grid">${overviewMetrics(agg)}</div>
    <p class="muted">${escapeHtml(
      limitNote(
        Math.max(det.length, r8.length),
        Math.max(detRaw.length, r8raw.length),
        REPORT_LIMIT,
        "MIXED FILTERING"
      )
    )}</p>
    ${
      !detShape.ok || !r8Shape.ok
        ? `<div class="state-panel state-error"><strong>DATA ERROR</strong><p>Unable to interpret response for ${
            !detShape.ok ? "detection" : "alerts"
          }: ${escapeHtml((!detShape.ok ? detShape.reason : r8Shape.reason) || "")}</p></div>`
        : ""
    }

    ${sectionHeader("Detection", statusBadge(stDet))}
    ${provenanceBanner(provDet, {
      title: "Detection Events",
      note: limitNote(det.length, detRaw.length, REPORT_LIMIT, FilterMode.CLIENT),
    })}
    <div class="chart-grid">
      ${chartShell("rep-det-types", "Detection type distribution")}
      ${chartShell("rep-det-time", "Detection activity over time")}
    </div>
    <div id="rep-det-table"></div>

    ${sectionHeader("R4 Correlation", `${statusBadge(stR4)} <span class="badge badge-advisory">ADVISORY</span>`)}
    ${provenanceBanner(provR4, {
      title: "Correlation Results",
      note: "Analytical only — does not authorize mitigation.",
    })}
    <div class="chart-grid">
      ${chartShell("rep-r4-time", "R4 activity over time")}
      ${chartShell("rep-r4-status", "R4 result labels")}
    </div>
    <div id="rep-r4-table"></div>

    ${sectionHeader("R6 Fusion", statusBadge(stR6))}
    ${provenanceBanner(provR6, { title: "Fusion Decisions" })}
    <div class="chart-grid">
      ${chartShell("rep-r6-dec", "Decision distribution")}
      ${chartShell("rep-r6-time", "Fusion activity over time")}
    </div>
    <div id="rep-r6-table"></div>

    ${sectionHeader("R7 Verification", statusBadge(stR7))}
    ${provenanceBanner(provR7, { title: "Verification Traces" })}
    <div class="chart-grid">
      ${chartShell("rep-r7-status", "Verification status distribution")}
      ${chartShell("rep-r7-time", "Verification activity over time")}
    </div>
    <div id="rep-r7-table"></div>

    ${sectionHeader("R8 Security Alerts", statusBadge(stR8))}
    ${provenanceBanner(provR8, {
      title: "Security Alerts",
      note: r8ServerFiltered
        ? "Filtering: SERVER FILTERED (since/until)."
        : "Filtering: NONE (all retrieved).",
    })}
    <div class="chart-grid">
      ${chartShell("rep-r8-sev", "Severity distribution")}
      ${chartShell("rep-r8-time", "Alerts over time")}
    </div>
    <div id="rep-r8-table"></div>

    ${sectionHeader("R5 RCA / XAI", statusBadge(stR5))}
    ${provenanceBanner(provR5, { title: "Root Cause Reports" })}
    <div class="chart-grid">
      ${chartShell("rep-r5-time", "RCA reports over time")}
      <div>
        <h3 class="chart-title">Observed XAI Features (FEATURE PRESENCE)</h3>
        ${notAvailable(
          "XAI contribution weights — NOT AVAILABLE",
          "Current backend exposes feature names only. This is FEATURE PRESENCE, not FEATURE IMPORTANCE. No weight bars or percentages are shown."
        )}
        ${
          features.length
            ? `<p class="muted">Observed features:</p><ul class="xai-list">${features
                .map((f) => `<li>${escapeHtml(f)}</li>`)
                .join("")}</ul>`
            : `<p class="muted">No feature names in retrieved RCA records.</p>`
        }
      </div>
    </div>
    <div id="rep-r5-table"></div>

    ${sectionHeader("Traffic / Entropy", "")}
    ${provenanceBanner(provTraf, { title: "Traffic Observations" })}
    ${provenanceBanner(provEnt, {
      title: "Entropy Observations",
      note: "Threshold: N/A — Not exposed by backend. Not derived from mean/median/stdev.",
    })}
    <div class="chart-grid">
      ${chartShell("rep-traf", "Traffic packet rate over time")}
      ${chartShell("rep-ent", "Entropy score over time")}
    </div>
    <p class="muted">Protocol Distribution: Not available from backend</p>

    ${sectionHeader("System Health", statusBadge("NOT_AVAILABLE"))}
    ${notAvailable(
      "System Health History — NOT AVAILABLE",
      "The backend exposes current health/status (CURRENT) but not a historical health time-series. Frontend polling is not treated as historical records."
    )}
    <p class="muted">Current status (CURRENT / SNAPSHOT of availability): ${statusBadge(
      bundle.status.state || "UNKNOWN"
    )} — see <a href="#health">System Health</a> for live observation.</p>

    ${sectionHeader("Digital Twin", statusBadge("SNAPSHOT"))}
    ${provenanceBanner(provTwin, {
      title: "Digital Twin",
      note: "SNAPSHOT · OBSERVATIONAL · READ ONLY — never mixed with production attack counts. No execute controls.",
    })}
    <div class="metric-grid">
      ${metricCard({
        title: "Snapshots (retrieved)",
        value: fmtNum(twinSnaps.length, 0),
        state: "SNAPSHOT",
      })}
      ${metricCard({
        title: "Replays (retrieved)",
        value: fmtNum(twinReplays.length, 0),
        state: "SNAPSHOT",
      })}
      ${metricCard({
        title: "Simulations (retrieved)",
        value: fmtNum(twinSims.length, 0),
        state: "SNAPSHOT",
      })}
      ${metricCard({
        title: "Runs (retrieved)",
        value: fmtNum(twinRuns.length, 0),
        state: "SNAPSHOT",
      })}
    </div>
    <p class="muted">Fidelity overall counts (snapshots with attached report): ${escapeHtml(
      Object.keys(twinOverallCounts).length
        ? Object.entries(twinOverallCounts)
            .map(([k, v]) => `${k}=${v}`)
            .join(" · ")
        : "none attached yet — run Level A ingest / demo"
    )}</p>
    ${
      twinWithFid.length
        ? dataTable(
            ["Snapshot", "Overall", "PASS/FAIL/N/A", "Created"],
            twinWithFid
              .slice(0, 8)
              .map((s) => {
                const sum = (s.fidelity && s.fidelity.summary) || {};
                return `<tr>
                <td>${escapeHtml(na(s.snapshot_id))}</td>
                <td>${statusBadge(s.fidelity.overall || "SNAPSHOT")}</td>
                <td>${escapeHtml(
                  `P${sum.PASS ?? "—"}/F${sum.FAIL ?? "—"}/N${sum.NOT_AVAILABLE ?? "—"}`
                )}</td>
                <td>${escapeHtml(shortTs(s.created_at))}</td>
              </tr>`;
              })
              .join(""),
            "No fidelity-attached snapshots"
          )
        : `<p class="muted">Open <a href="#twin">Digital Twin</a> for full snapshot / replay / simulation tables.</p>`
    }

    ${sectionHeader("Data Availability", "")}
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>Source</th><th>Historical</th><th>Timestamp</th><th>Event ID</th>
          <th>Filtering</th><th>Completeness</th><th>Type</th><th>Notes</th>
        </tr></thead>
        <tbody>
          ${DATA_AVAILABILITY.map(
            (d) => `<tr>
              <td>${escapeHtml(d.name)}</td>
              <td>${d.available ? statusBadge("AVAILABLE") : statusBadge("NOT_AVAILABLE")}</td>
              <td>${d.timestamp ? "YES" : "NO"}</td>
              <td>${d.eventId ? "YES" : "NO"}</td>
              <td>${escapeHtml(d.filterLabel || (d.timeFilterApi ? "Server" : "Client"))}</td>
              <td>${statusBadge(d.completeness || "UNKNOWN")}</td>
              <td>${escapeHtml(d.dataKind || "")}</td>
              <td class="muted">${escapeHtml(d.note)}</td>
            </tr>`
          ).join("")}
        </tbody>
      </table>
    </div>
  `;

  setHtml(root, "#rep-body", body);
  markChartUnavailable(root);
  root.querySelector("#rep-body")?.setAttribute("aria-busy", "false");

  // Charts
  paintBar(`${CHART_PREFIX}-det-types`, root.querySelector("#rep-det-types"), countBy(det, "alert_type"), "Types");
  paintActivity(`${CHART_PREFIX}-det-time`, root.querySelector("#rep-det-time"), bucketByTime(det, "timestamp"));
  paintActivity(`${CHART_PREFIX}-r4-time`, root.querySelector("#rep-r4-time"), bucketByTime(r4, "timestamp"));
  paintBar(
    `${CHART_PREFIX}-r4-status`,
    root.querySelector("#rep-r4-status"),
    countBy(r4, "status"),
    "R4"
  );
  paintBar(`${CHART_PREFIX}-r6-dec`, root.querySelector("#rep-r6-dec"), countBy(r6, "decision"), "Decisions");
  paintActivity(`${CHART_PREFIX}-r6-time`, root.querySelector("#rep-r6-time"), bucketByTime(r6, "timestamp"));
  paintBar(`${CHART_PREFIX}-r7-status`, root.querySelector("#rep-r7-status"), r7ByStatus, "Status");
  paintActivity(`${CHART_PREFIX}-r7-time`, root.querySelector("#rep-r7-time"), bucketByTime(r7, "timestamp"));
  paintBar(`${CHART_PREFIX}-r8-sev`, root.querySelector("#rep-r8-sev"), r8BySev, "Severity");
  paintActivity(`${CHART_PREFIX}-r8-time`, root.querySelector("#rep-r8-time"), bucketByTime(r8, "timestamp"));
  paintActivity(`${CHART_PREFIX}-r5-time`, root.querySelector("#rep-r5-time"), bucketByTime(r5, "timestamp"));

  const trafPts = limitPoints(traf, CHART_POINT_LIMIT);
  upsertChart(
    `${CHART_PREFIX}-traf`,
    root.querySelector("#rep-traf"),
    lineChartConfig({
      labels: trafPts.map((p) => shortLabel(p.timestamp)),
      datasets: [
        {
          label: "packet_rate",
          data: trafPts.map((p) => Number(p.packet_rate) || 0),
          borderColor: "#3aa0ff",
          tension: 0.25,
          pointRadius: 0,
          fill: true,
          backgroundColor: "rgba(58,160,255,0.12)",
        },
      ],
    })
  );
  const entPts = limitPoints(ent, CHART_POINT_LIMIT);
  upsertChart(
    `${CHART_PREFIX}-ent`,
    root.querySelector("#rep-ent"),
    lineChartConfig({
      labels: entPts.map((p) => shortLabel(p.timestamp)),
      datasets: [
        {
          label: "entropy_score",
          data: entPts.map((p) => Number(p.entropy_score) || 0),
          borderColor: "#f59e0b",
          tension: 0.25,
          pointRadius: 0,
          fill: true,
          backgroundColor: "rgba(245,158,11,0.12)",
        },
      ],
      ySuggestedMax: 1.05,
    })
  );

  // Tables
  setHtml(
    root,
    "#rep-det-table",
    dataTable(
      ["Timestamp", "Type", "Confidence", "Status"],
      det
        .slice(0, 25)
        .map(
          (a) => `<tr>
          <td>${escapeHtml(shortTs(a.timestamp))}</td>
          <td>${escapeHtml(na(a.alert_type))}</td>
          <td>${escapeHtml(fmtPct(a.confidence))}</td>
          <td>${escapeHtml(na(a.status))}</td>
        </tr>`
        )
        .join(""),
      "No detection events in window"
    )
  );

  setHtml(
    root,
    "#rep-r4-table",
    dataTable(
      ["Timestamp", "Event ID", "Score", "Status", ""],
      r4
        .slice(0, 25)
        .map(
          (r) => `<tr>
          <td>${escapeHtml(shortTs(r.timestamp))}</td>
          <td>${escapeHtml(na(r.event_id))}</td>
          <td>${escapeHtml(fmtNum(r.score ?? r.correlation_score, 3))}</td>
          <td>${escapeHtml(na(r.status || r.label))}</td>
          <td>${invLink(r.event_id)}</td>
        </tr>`
        )
        .join(""),
      "No correlation results in window"
    )
  );

  setHtml(
    root,
    "#rep-r6-table",
    dataTable(
      ["Timestamp", "Event ID", "Decision", "Confidence", ""],
      r6
        .slice(0, 25)
        .map(
          (r) => `<tr>
          <td>${escapeHtml(shortTs(r.timestamp))}</td>
          <td>${escapeHtml(na(r.event_id))}</td>
          <td>${escapeHtml(na(r.decision))}</td>
          <td>${escapeHtml(fmtPct(r.confidence))}</td>
          <td>${invLink(r.event_id)}</td>
        </tr>`
        )
        .join(""),
      "No fusion decisions in window"
    )
  );

  setHtml(
    root,
    "#rep-r7-table",
    dataTable(
      ["Timestamp", "Event ID", "Status", "Eligible", ""],
      r7
        .slice(0, 25)
        .map(
          (t) => `<tr>
          <td>${escapeHtml(shortTs(t.timestamp))}</td>
          <td>${escapeHtml(na(t.event_id))}</td>
          <td>${escapeHtml(na(t.status))}</td>
          <td>${escapeHtml(String(t.mitigation_eligible ?? "N/A"))}</td>
          <td>${invLink(t.event_id)}</td>
        </tr>`
        )
        .join(""),
      "No verification traces in window"
    )
  );

  setHtml(
    root,
    "#rep-r8-table",
    dataTable(
      ["Timestamp", "Event ID", "Severity", "Type", ""],
      r8
        .slice(0, 25)
        .map(
          (a) => `<tr>
          <td>${escapeHtml(shortTs(a.timestamp))}</td>
          <td>${escapeHtml(na(a.event_id))}</td>
          <td>${escapeHtml(na(a.severity))}</td>
          <td>${escapeHtml(na(a.alert_type))}</td>
          <td>${invLink(a.event_id)}</td>
        </tr>`
        )
        .join(""),
      "No security alerts in window"
    )
  );

  setHtml(
    root,
    "#rep-r5-table",
    dataTable(
      ["Timestamp", "Event ID", "Root Cause", "Confidence", ""],
      r5
        .slice(0, 25)
        .map(
          (r) => `<tr>
          <td>${escapeHtml(shortTs(r.timestamp))}</td>
          <td>${escapeHtml(na(r.event_id))}</td>
          <td>${escapeHtml(na(r.root_cause || r.summary || r.title))}</td>
          <td>${escapeHtml(fmtPct(r.confidence ?? r.rca_confidence))}</td>
          <td>${invLink(r.event_id)}</td>
        </tr>`
        )
        .join(""),
      "No RCA reports in window"
    )
  );

  // silence unused
  void soft;
  void parseTs;
  void comingSoon;
}

export { resolveRange, filterByTime, countBy, bucketByTime, DATA_AVAILABILITY };
