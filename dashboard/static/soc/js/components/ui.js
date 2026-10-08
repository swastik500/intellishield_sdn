/** Reusable SOC UI primitives — Phase 1. */

import { ageLabel } from "../api/client.js";
import { escapeHtml, na } from "../utils/format.js";

export function statusBadge(state, label = null) {
  const text = label || state || "UNKNOWN";
  const cls = String(state || "UNKNOWN").toLowerCase().replace(/[^a-z0-9]+/g, "-");
  return `<span class="badge badge-${cls}" title="${escapeHtml(text)}">${escapeHtml(text)}</span>`;
}

export function lastUpdated(fetchedAt, state) {
  if (!fetchedAt) {
    return `<span class="last-updated muted">Last updated: N/A</span>`;
  }
  const label = state === "STALE" ? "Last successful update" : "Last updated";
  return `<span class="last-updated">${escapeHtml(label)}: ${escapeHtml(ageLabel(fetchedAt))}</span>`;
}

export function metricCard({ title, value, subtitle = "", state = "LIVE", hint = "" }) {
  return `
    <article class="metric-card" data-state="${escapeHtml(state)}">
      <header>
        <span class="metric-title">${escapeHtml(title)}</span>
        ${statusBadge(state)}
      </header>
      <div class="metric-value">${escapeHtml(na(value))}</div>
      ${subtitle ? `<div class="metric-sub">${escapeHtml(subtitle)}</div>` : ""}
      ${hint ? `<div class="metric-hint">${escapeHtml(hint)}</div>` : ""}
    </article>`;
}

export function healthCard({ name, status, detail = "" }) {
  const st = status || "NO DATA";
  return `
    <div class="health-card status-${escapeHtml(String(st).toLowerCase().replace(/\s+/g, "-"))}">
      <div class="health-name">${escapeHtml(name)}</div>
      <div class="health-status">${statusBadge(st)}</div>
      ${detail ? `<div class="health-detail">${escapeHtml(detail)}</div>` : ""}
    </div>`;
}

export function pipelineStage({ name, status, note = "" }) {
  return `
    <div class="pipe-stage status-${escapeHtml(String(status).toLowerCase().replace(/\s+/g, "-"))}">
      <div class="pipe-name">${escapeHtml(name)}</div>
      <div class="pipe-status">${escapeHtml(status)}</div>
      ${note ? `<div class="pipe-note">${escapeHtml(note)}</div>` : ""}
    </div>`;
}

export function emptyState(title, body) {
  return `
    <div class="state-panel state-empty">
      <strong>${escapeHtml(title)}</strong>
      <p>${escapeHtml(body)}</p>
    </div>`;
}

export function errorState(title, body) {
  return `
    <div class="state-panel state-error">
      <strong>${escapeHtml(title)}</strong>
      <p>${escapeHtml(body)}</p>
    </div>`;
}

export function offlineState(title = "Backend unavailable", body = "The IntelliShield API could not be reached.") {
  return `
    <div class="state-panel state-offline">
      <strong>${escapeHtml(title)}</strong>
      <p>${escapeHtml(body)}</p>
    </div>`;
}

export function loadingState(label = "Loading…") {
  return `<div class="state-panel state-loading">${escapeHtml(label)}</div>`;
}

export function pageHeader({ title, subtitle = "", badge = "READ ONLY", extra = "" }) {
  return `
    <div class="page-header">
      <div>
        <div class="page-kicker">${statusBadge(badge)} <span class="observer-tag">Observer mode</span></div>
        <h1>${escapeHtml(title)}</h1>
        ${subtitle ? `<p class="page-sub">${escapeHtml(subtitle)}</p>` : ""}
      </div>
      <div class="page-header-extra">${extra}</div>
    </div>`;
}

export function sectionHeader(title, rightHtml = "") {
  return `
    <div class="section-header">
      <h2>${escapeHtml(title)}</h2>
      <div>${rightHtml}</div>
    </div>`;
}

export function dataTable(headers, rowsHtml, emptyMessage = "No data") {
  if (!rowsHtml) {
    return emptyState("No data", emptyMessage);
  }
  return `
    <div class="table-wrap">
      <table class="data-table">
        <thead><tr>${headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead>
        <tbody>${rowsHtml}</tbody>
      </table>
    </div>`;
}

export function alertCard(alert) {
  const sev = alert.severity || "UNKNOWN";
  const eid = alert.event_id != null ? String(alert.event_id).trim() : "";
  const inv =
    eid && eid !== "N/A" && eid !== "UNAVAILABLE"
      ? `<a class="investigate-link" href="#investigation/${encodeURIComponent(eid)}">View Investigation</a>`
      : `<span class="muted">Investigation unavailable</span>`;
  return `
    <article class="alert-card sev-${escapeHtml(String(sev).toLowerCase())}">
      <header>
        ${statusBadge(sev)}
        <span class="alert-time">${escapeHtml(na(alert.timestamp))}</span>
      </header>
      <h3>${escapeHtml(na(alert.title, alert.alert_type || "Alert"))}</h3>
      <p>${escapeHtml(na(alert.message, "No description"))}</p>
      <footer>
        <span>ID: ${escapeHtml(na(alert.alert_id))}</span>
        <span>Event: ${escapeHtml(na(alert.event_id))}</span>
        ${inv}
      </footer>
    </article>`;
}

export function timeline(stages) {
  if (!stages || !stages.length) {
    return emptyState("No stages", "Verification stage timeline unavailable.");
  }
  return `
    <ol class="timeline">
      ${stages
        .map((s) => {
          const passed = s.passed === true ? "PASS" : s.passed === false ? "FAIL" : "PENDING";
          return `<li class="tl-${passed.toLowerCase()}">
            <div class="tl-name">${escapeHtml(s.stage_name || s.name || "Stage")}</div>
            <div class="tl-status">${escapeHtml(passed)}</div>
            <div class="tl-reason">${escapeHtml(na(s.reason, ""))}</div>
          </li>`;
        })
        .join("")}
    </ol>`;
}

export function comingSoon(feature) {
  return `
    <div class="state-panel state-coming">
      <strong>${escapeHtml(feature)}</strong>
      <p>READ ONLY · OBSERVATION MODE · Coming in a later phase</p>
      <p>No runtime control is available from this UI.</p>
    </div>`;
}

/**
 * Render section based on ApiResult state.
 */
export function renderResult(result, { onLive, loadingLabel = "Loading…" }) {
  if (!result || result.state === "LOADING") return loadingState(loadingLabel);
  if (result.state === "OFFLINE") {
    return offlineState(
      "Backend unavailable",
      result.error || "The IntelliShield API could not be reached."
    );
  }
  if (result.state === "ERROR" || result.state === "UNAVAILABLE") {
    const malformed =
      result.error && /malformed|invalid structure|json/i.test(String(result.error));
    if (malformed) {
      return errorState(
        "DATA ERROR",
        "Unable to interpret response. API returned HTTP success but the structure was invalid."
      );
    }
    return errorState(
      result.state === "UNAVAILABLE" ? "Unavailable" : "Error",
      result.error || "Request failed"
    );
  }
  if (result.state === "EMPTY") {
    return emptyState("No data", "Backend returned an empty result set.");
  }
  return onLive(result.data, result);
}

/**
 * Compact provenance banner + expandable data details (Phase 6).
 * @param {object} prov from buildProvenance()
 * @param {{ title?: string, note?: string }} [opts]
 */
export function provenanceBanner(prov, opts = {}) {
  if (!prov) return "";
  const title = opts.title || prov.source || "Dataset";
  const note = opts.note || "";
  const detailsId = `prov-${String(prov.sourceKey || "x").replace(/[^a-z0-9_-]/gi, "")}-${Math.abs(
    // Stable-ish id without Math.random — use fetchedAt + counts
    ((prov.fetchedAt || 0) + (prov.retrievedCount || 0) * 17 + (prov.displayedCount || 0) * 31) % 1e9
  )}`;
  return `
    <div class="provenance-banner" data-state="${escapeHtml(prov.dataState)}">
      <div class="prov-head">
        <strong>${escapeHtml(title)}</strong>
        ${statusBadge(prov.dataState)}
        ${statusBadge(prov.dataKind)}
        ${statusBadge(prov.joinability, `Event linkage: ${prov.joinability}`)}
      </div>
      <div class="prov-meta muted">
        <span>Source: ${escapeHtml(prov.source)}</span>
        <span>Filtering: ${escapeHtml(prov.filterMode)}</span>
        <span>Completeness: ${escapeHtml(prov.completeness)}</span>
        <span>${escapeHtml(
          prov.displayedCount != null && prov.retrievedCount != null
            ? `Showing ${prov.displayedCount} of ${prov.retrievedCount} retrieved`
            : "Records: N/A"
        )}</span>
      </div>
      ${note ? `<p class="muted prov-note">${escapeHtml(note)}</p>` : ""}
      <details class="prov-details" id="${escapeHtml(detailsId)}">
        <summary>Data details</summary>
        <div class="prov-facts">${provenanceFactsInner(prov)}</div>
      </details>
    </div>`;
}

function provenanceFactsInner(prov) {
  const rows = [
    ["Source", `${prov.source} (${prov.sourcePath})`],
    ["Data type", prov.dataKind],
    ["Data state", prov.dataState],
    ["Event linkage", prov.joinability],
    ["Filtering", prov.filterMode],
    ["Completeness", prov.completeness],
    ["Time range", prov.timeRangeLabel || "N/A"],
    ["Retrieved", prov.retrievedCount == null ? "N/A" : String(prov.retrievedCount)],
    ["Displayed", prov.displayedCount == null ? "N/A" : String(prov.displayedCount)],
  ];
  if (prov.totalReported != null) {
    rows.push(["Backend total (reported)", String(prov.totalReported)]);
  }
  if (prov.limitations && prov.limitations.length) {
    rows.push(["Limitations", prov.limitations.join("; ")]);
  }
  if (prov.error) {
    rows.push(["API error", String(prov.error)]);
  }
  return rows
    .map(
      ([k, v]) =>
        `<div class="prov-fact"><span class="k">${escapeHtml(k)}</span><span class="v">${escapeHtml(
          String(v)
        )}</span></div>`
    )
    .join("");
}

/** Investigation link only when event_id is valid (no synthetic IDs). */
export function investigationNav(eventId, label = "View Investigation") {
  const eid = eventId == null ? "" : String(eventId).trim();
  if (
    !eid ||
    eid === "N/A" ||
    eid === "UNAVAILABLE" ||
    eid.toUpperCase() === "NULL" ||
    eid === "-"
  ) {
    return `<span class="muted">Investigation unavailable</span>`;
  }
  return `<a class="investigate-link" href="#investigation/${encodeURIComponent(eid)}">${escapeHtml(
    label
  )}</a>`;
}

/** SOC data quality summary strip. */
export function dataQualitySummary(items) {
  const rows = (items || [])
    .map(
      (it) => `<div class="dq-item">
        <span class="dq-label">${escapeHtml(it.label)}</span>
        ${statusBadge(it.value)}
        <span class="muted dq-note">${escapeHtml(it.note || "")}</span>
      </div>`
    )
    .join("");
  return `
    <section class="data-quality-summary panel" aria-label="SOC data quality">
      <h3>SOC Data Quality</h3>
      ${rows}
    </section>`;
}
