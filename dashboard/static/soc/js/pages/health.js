/**
 * Phase 4 — System Health & Operational Observability (read-only).
 */

import * as api from "../api/index.js";
import {
  pageHeader,
  sectionHeader,
  statusBadge,
  lastUpdated,
  metricCard,
} from "../components/ui.js";
import { escapeHtml, na, shortTs } from "../utils/format.js";
import {
  buildComponentHealth,
  PIPELINE_IDS,
  freshnessLabel,
  documentedStaleWindowMs,
  redactDiagnostics,
  HealthState,
} from "../utils/health.js";

let selectedId = null;

function setHtml(root, sel, html) {
  const el = root.querySelector(sel);
  if (el) el.innerHTML = html;
}

function healthCardClickable(c) {
  const selected = c.id === selectedId ? " selected" : "";
  return `
    <button type="button" class="health-card-btn${selected}" data-health-id="${escapeHtml(c.id)}"
      aria-pressed="${c.id === selectedId ? "true" : "false"}"
      aria-label="${escapeHtml(c.name)} status ${escapeHtml(c.state)}">
      <div class="health-card status-${escapeHtml(String(c.state).toLowerCase().replace(/\s+/g, "-"))}">
        <div class="health-name">${escapeHtml(c.name)}</div>
        <div class="health-status">${statusBadge(c.state)}</div>
        <div class="health-detail">${escapeHtml(c.detail || "")}</div>
        <div class="health-fresh muted">${escapeHtml(freshnessLabel(c.fetchedAt, c.state))}</div>
      </div>
    </button>`;
}

function renderPipeline(components) {
  const byId = Object.fromEntries(components.map((c) => [c.id, c]));
  return PIPELINE_IDS.map((id, i) => {
    const c = byId[id];
    if (!c) return "";
    return `
      ${i ? '<div class="pipe-arrow" aria-hidden="true">↓</div>' : ""}
      <div class="pipe-stage status-${escapeHtml(String(c.state).toLowerCase().replace(/\s+/g, "-"))}">
        <div class="pipe-name">${escapeHtml(c.name)}</div>
        <div class="pipe-status" aria-label="${escapeHtml(c.state)}">${escapeHtml(c.state)}</div>
        <div class="pipe-note">${escapeHtml(freshnessLabel(c.fetchedAt, c.state))}</div>
      </div>`;
  }).join("");
}

function renderDetail(c) {
  if (!c) {
    return `<div class="state-panel state-empty"><strong>Select a component</strong><p>Click a health card for source and activity details.</p></div>`;
  }
  return `
    <article class="health-detail-drawer panel" aria-live="polite">
      <header>
        <h3>${escapeHtml(c.name)}</h3>
        ${statusBadge(c.state)}
      </header>
      <div class="fact-grid">
        <div><span class="k">Status</span><span class="v">${escapeHtml(c.state)}</span></div>
        <div><span class="k">Freshness</span><span class="v">${escapeHtml(
          freshnessLabel(c.fetchedAt, c.state)
        )}</span></div>
        <div><span class="k">Data source</span><span class="v">${escapeHtml(c.source)}</span></div>
        <div><span class="k">Recent activity count</span><span class="v">${escapeHtml(
          c.activity == null ? "N/A" : String(c.activity)
        )}</span></div>
        <div><span class="k">Last observed timestamp</span><span class="v">${escapeHtml(
          c.lastEventTs ? shortTs(c.lastEventTs) : "N/A"
        )}</span></div>
        <div><span class="k">Control</span><span class="v">${escapeHtml(c.control || "READ ONLY")}</span></div>
      </div>
      <p class="muted">${escapeHtml(c.notes || "")}</p>
      <p class="muted">Overall system health score: N/A (not exposed by backend; UI does not invent one).</p>
    </article>`;
}

function ensureCardDelegation(root, getComponents) {
  const shell = root.querySelector("#health-shell");
  if (!shell || shell.dataset.healthBound === "1") return;
  shell.dataset.healthBound = "1";
  shell.addEventListener("click", (ev) => {
    const btn = ev.target.closest("[data-health-id]");
    if (!btn || !shell.contains(btn)) return;
    selectedId = btn.getAttribute("data-health-id");
    const components = getComponents() || [];
    const c = components.find((x) => x.id === selectedId);
    setHtml(root, "#health-detail", renderDetail(c));
    root.querySelectorAll(".health-card-btn").forEach((b) => {
      const on = b.getAttribute("data-health-id") === selectedId;
      b.classList.toggle("selected", on);
      b.setAttribute("aria-pressed", on ? "true" : "false");
    });
  });
}

function activityStrip(bundle, status) {
  const st = status?.data || {};
  const items = [
    {
      title: "Last traffic point",
      value: shortTs(
        (bundle.traffic?.data?.points || []).slice(-1)[0]?.timestamp
      ),
    },
    {
      title: "Last entropy point",
      value: shortTs(
        bundle.entropy?.data?.latest?.timestamp ||
          (bundle.entropy?.data?.points || []).slice(-1)[0]?.timestamp
      ),
    },
    {
      title: "Last correlation",
      value: shortTs((bundle.correlation?.data?.results || [])[0]?.timestamp),
    },
    {
      title: "Last fusion",
      value: shortTs((bundle.fusion?.data?.results || [])[0]?.timestamp),
    },
    {
      title: "Last verification",
      value: shortTs((bundle.verification?.data?.traces || [])[0]?.timestamp),
    },
    {
      title: "Last RCA",
      value: shortTs((bundle.rca?.data?.reports || [])[0]?.timestamp),
    },
    {
      title: "Last R8 alert",
      value: shortTs((bundle.securityAlerts?.data?.alerts || [])[0]?.timestamp),
    },
    {
      title: "Server time (IST)",
      value: na(st.server_time),
    },
  ];
  return items
    .map(
      (it) =>
        metricCard({
          title: it.title,
          value: it.value === "N/A" || !it.value ? "N/A" : it.value,
          state: it.value && it.value !== "N/A" ? "LIVE" : "EMPTY",
        })
    )
    .join("");
}

let _lastComponents = [];

export async function renderHealth(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#health-shell");
  if (!soft) {
    selectedId = selectedId || "controller";
    root.innerHTML = `
      ${pageHeader({
        title: "System Health",
        subtitle: "Operational observability — availability, freshness, activity. No operator controls.",
        badge: "READ ONLY",
      })}
      <div id="health-shell">
        <p class="muted">Overall Score: <strong>N/A</strong> — backend does not expose an aggregate health score; UI does not invent one.</p>
        <p class="muted"><strong>CURRENT</strong> observability only. Historical health time-series: <strong>NOT AVAILABLE</strong> — polling is not treated as history.</p>
        <p class="muted">Documented client STALE window after successful fetch: ${documentedStaleWindowMs() / 1000}s (presentation aid, not a security threshold).</p>

        ${sectionHeader("Component health", '<span id="health-extra"></span>')}
        <div class="health-grid clickable" id="health-cards"></div>

        ${sectionHeader("Security pipeline health", "")}
        <div class="pipeline health-pipeline" id="health-pipeline" role="list"></div>
        <p class="muted">R3 Digital Twin is observational and listed separately — not a production mitigation stage.</p>

        ${sectionHeader("Component detail", "")}
        <div id="health-detail"></div>

        ${sectionHeader("Last observed activity (backend timestamps)", "")}
        <div class="metric-grid" id="health-activity"></div>

        ${sectionHeader("Historical health trend", "")}
        <div class="state-panel state-empty">
          <strong>Not available from backend</strong>
          <p>No health time-series API is exposed. The UI does not synthesize history from polling.</p>
        </div>

        ${sectionHeader("API / diagnostics (redacted)", "")}
        <div class="chart-grid">
          <div>
            <h3 class="chart-title">GET /api/status</h3>
            <pre class="json-block" id="health-status-json"></pre>
          </div>
          <div>
            <h3 class="chart-title">GET /api/control/status (read)</h3>
            <pre class="json-block" id="health-control-json"></pre>
          </div>
        </div>
        <div>
          <h3 class="chart-title">GET /api/summary</h3>
          <pre class="json-block" id="health-summary-json"></pre>
        </div>
      </div>`;
  }

  const [bundle, status, control, summary] = await Promise.all([
    api.fetchDashboardBundle(ctx.signal),
    api.fetchStatus(ctx.signal),
    api.fetchControlStatus(ctx.signal),
    api.fetchSummary(ctx.signal),
  ]);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  const components = buildComponentHealth(bundle, status, control);
  _lastComponents = components;
  const selected = components.find((c) => c.id === selectedId) || components[0];

  setHtml(
    root,
    "#health-extra",
    `${statusBadge(status.state)} ${lastUpdated(status.fetchedAt, status.state)}`
  );
  setHtml(root, "#health-cards", components.map(healthCardClickable).join(""));
  setHtml(root, "#health-pipeline", renderPipeline(components));
  setHtml(root, "#health-detail", renderDetail(selected));
  setHtml(root, "#health-activity", activityStrip(bundle, status));

  const statusEl = root.querySelector("#health-status-json");
  if (statusEl) {
    statusEl.textContent =
      status.state === "OFFLINE" || status.state === "ERROR"
        ? status.error || status.state
        : JSON.stringify(redactDiagnostics(status.data || {}), null, 2);
  }
  const controlEl = root.querySelector("#health-control-json");
  if (controlEl) {
    controlEl.textContent =
      control.state === "OFFLINE" || control.state === "ERROR"
        ? control.error || control.state
        : JSON.stringify(redactDiagnostics(control.data || {}), null, 2);
  }
  const sumEl = root.querySelector("#health-summary-json");
  if (sumEl) {
    sumEl.textContent =
      summary.state === "OFFLINE" || summary.state === "ERROR"
        ? summary.error || summary.state
        : JSON.stringify(redactDiagnostics(summary.data || {}), null, 2);
  }

  ensureCardDelegation(root, () => _lastComponents);

  const headerExtra = root.querySelector(".page-header-extra");
  if (headerExtra) {
    headerExtra.innerHTML = `${statusBadge(status.state)} ${lastUpdated(
      status.fetchedAt,
      status.state
    )}`;
  }
}

/** Compact summary HTML for dashboard (no invented score). */
export function renderHealthSummaryHtml(components) {
  const focus = [
    "controller",
    "detection",
    "r4",
    "r6",
    "r7",
    "mitigation",
    "r5",
    "r8",
  ];
  const byId = Object.fromEntries(components.map((c) => [c.id, c]));
  return `
    <div class="health-summary-strip" role="list">
      ${focus
        .map((id) => {
          const c = byId[id];
          if (!c) return "";
          return `<a class="health-summary-item" href="#health" role="listitem" title="${escapeHtml(c.name)}">
            <span class="hs-name">${escapeHtml(c.name)}</span>
            ${statusBadge(c.state)}
          </a>`;
        })
        .join("")}
      <a class="health-summary-item more" href="#health">Open System Health →</a>
    </div>
    <p class="muted">Overall Score: N/A</p>`;
}

export { buildComponentHealth, HealthState };
