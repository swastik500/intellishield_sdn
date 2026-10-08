/**
 * Phase 3 — Security Event Investigation (read-only).
 * Backend remains the sole source of truth. No operator actions.
 */

import {
  fetchInvestigationBundle,
  fetchRecentEventIndex,
  sameEventId,
  DataState,
} from "../api/investigation.js";
import {
  pageHeader,
  sectionHeader,
  metricCard,
  statusBadge,
  lastUpdated,
  renderResult,
  timeline,
  alertCard,
  emptyState,
  errorState,
  offlineState,
  loadingState,
  provenanceBanner,
} from "../components/ui.js";
import { escapeHtml, na, fmtNum, fmtPct, shortTs } from "../utils/format.js";
import {
  buildProvenance,
  isValidEventId,
  Linkability,
  FilterMode,
  Completeness,
  ObsState,
} from "../utils/provenance.js";

function stateExtra(result) {
  if (!result) return "";
  return `${statusBadge(result.state)} ${lastUpdated(result.fetchedAt, result.state)}`;
}

function investigateHref(eventId) {
  return `#investigation/${encodeURIComponent(String(eventId).trim())}`;
}

export function investigateLink(eventId, label = "View Investigation") {
  if (!isValidEventId(eventId)) {
    return `<span class="muted">Investigation unavailable</span>`;
  }
  const eid = String(eventId).trim();
  return `<a class="investigate-link" href="${investigateHref(eid)}">${escapeHtml(label)}</a>`;
}

function sliceStateLabel(result) {
  if (!result) return "NO DATA";
  if (result.state === DataState.LIVE || result.state === DataState.STALE) return result.state;
  if (result.state === DataState.EMPTY) return "NO DATA";
  if (result.state === DataState.OFFLINE) return "OFFLINE";
  if (result.state === DataState.ERROR) return "ERROR";
  if (result.state === DataState.UNAVAILABLE) return "UNAVAILABLE";
  if (result.state === DataState.LOADING) return "LOADING";
  return String(result.state);
}

function pickFirst(arr) {
  return Array.isArray(arr) && arr.length ? arr[0] : null;
}

/**
 * Build unified timeline from backend records only.
 * Stages included only when a record exists. Timestamps from backend only.
 */
export function buildInvestigationTimeline(bundle) {
  const stages = [];

  const corr = pickFirst(bundle.correlation?.data?.results);
  const fus = pickFirst(bundle.fusion?.data?.results);
  const ver = pickFirst(bundle.verification?.data?.traces);
  const rca = bundle.rca?.data;
  const alert = pickFirst(bundle.alerts?.data?.alerts);

  // Detection: only when fusion/RCA/correlation expose detection-related fields
  // Legacy CSV alerts have no event_id — do not invent a detection stage from them.
  const detHint =
    (rca && rca.attack_hint && rca.attack_hint !== "UNAVAILABLE" && rca.attack_hint) ||
    (fus && fus.decision) ||
    null;
  const detTs =
    (rca && rca.timestamp) ||
    (fus && fus.timestamp) ||
    (corr && corr.timestamp) ||
    null;
  if (detHint || (fus && fus.decision)) {
    stages.push({
      key: "detection",
      title: "Detection",
      category: "decision",
      timestamp: detTs || null,
      summary: detHint
        ? `Backend attack hint / decision context: ${detHint}`
        : "Detection-linked fields present via pipeline records",
      status: detHint || "AVAILABLE",
      source: "R6/R5 linked fields (CSV detection alerts are not event_id-keyed)",
    });
  }

  if (corr && bundle.correlation.state !== DataState.EMPTY) {
    stages.push({
      key: "r4",
      title: "R4 Correlation",
      category: "analysis",
      timestamp: corr.timestamp || null,
      summary: `Score ${corr.score ?? corr.correlation_score ?? "N/A"} · ${corr.status || corr.label || "result"}`,
      status: corr.status || corr.label || "AVAILABLE",
      source: "R4",
      advisory: true,
    });
  }

  if (fus && bundle.fusion.state !== DataState.EMPTY) {
    stages.push({
      key: "r6",
      title: "R6 Collaborative Fusion",
      category: "decision",
      timestamp: fus.timestamp || null,
      summary: `Decision ${fus.decision || "N/A"} · confidence ${fus.confidence ?? "N/A"}`,
      status: fus.decision || "AVAILABLE",
      source: "R6",
    });
  }

  if (ver && bundle.verification.state !== DataState.EMPTY) {
    stages.push({
      key: "r7",
      title: "R7 Verification",
      category: "decision",
      timestamp: ver.timestamp || null,
      summary: `Status ${ver.status || "N/A"} · eligible ${String(ver.mitigation_eligible ?? "N/A")}`,
      status: ver.status || "AVAILABLE",
      source: "R7",
    });
  }

  if (rca && bundle.rca.state === DataState.LIVE) {
    stages.push({
      key: "r5",
      title: "R5 RCA / XAI",
      category: "analysis",
      timestamp: rca.timestamp || null,
      summary: rca.summary || rca.explanation_summary || "RCA report available",
      status: "AVAILABLE",
      source: "R5",
    });
  }

  if (alert && bundle.alerts.state !== DataState.EMPTY) {
    stages.push({
      key: "r8",
      title: "R8 Alert",
      category: "alert",
      timestamp: alert.timestamp || null,
      summary: `${alert.severity || "N/A"} · ${alert.title || alert.alert_type || "Alert"}`,
      status: alert.severity || "AVAILABLE",
      source: "R8",
    });
  }

  // Sort by backend timestamp when both present; unknowns last (stable by key order)
  const order = { detection: 1, r4: 2, r6: 3, r7: 4, r5: 5, r8: 6 };
  stages.sort((a, b) => {
    const ta = a.timestamp ? String(a.timestamp) : "";
    const tb = b.timestamp ? String(b.timestamp) : "";
    if (ta && tb && ta !== tb) return ta.localeCompare(tb);
    if (ta && !tb) return -1;
    if (!ta && tb) return 1;
    return (order[a.key] || 99) - (order[b.key] || 99);
  });

  return stages;
}

function renderUnifiedTimeline(stages) {
  if (!stages.length) {
    return emptyState(
      "Empty timeline",
      "No pipeline records with this event_id were returned by the backend."
    );
  }
  return `
    <ol class="inv-timeline">
      ${stages
        .map(
          (s, i) => `
        <li class="inv-tl cat-${escapeHtml(s.category)}">
          <div class="inv-tl-time">${escapeHtml(s.timestamp ? shortTs(s.timestamp) : "Time unavailable")}</div>
          <div class="inv-tl-dot" aria-hidden="true"></div>
          <div class="inv-tl-body">
            <div class="inv-tl-title">
              ${escapeHtml(s.title)}
              ${statusBadge(s.status)}
              ${s.advisory ? statusBadge("ADVISORY") : ""}
            </div>
            <p>${escapeHtml(s.summary)}</p>
            <div class="inv-tl-source muted">Provenance: ${escapeHtml(s.source)}</div>
          </div>
          ${i < stages.length - 1 ? '<div class="inv-tl-connector" aria-hidden="true"></div>' : ""}
        </li>`
        )
        .join("")}
    </ol>`;
}

function panelShell(title, category, result, bodyHtml) {
  return `
    <section class="inv-panel cat-${escapeHtml(category)}" data-slice-state="${escapeHtml(result?.state || "NO DATA")}">
      <header class="inv-panel-header">
        <h3>${escapeHtml(title)}</h3>
        <div>${statusBadge(sliceStateLabel(result))} ${lastUpdated(result?.fetchedAt, result?.state)}</div>
      </header>
      <div class="inv-panel-body">${bodyHtml}</div>
    </section>`;
}

function renderDetectionPanel(bundle) {
  const rca = bundle.rca?.data;
  const fus = pickFirst(bundle.fusion?.data?.results);
  const corr = pickFirst(bundle.correlation?.data?.results);

  // No event_id on entropy/ML CSV — show only linked backend fields
  if (!rca && !fus && !corr) {
    return panelShell(
      "Detection Evidence",
      "observed",
      { state: DataState.UNAVAILABLE, fetchedAt: Date.now() },
      emptyState(
        "Detection evidence not linkable",
        "Legacy /api/alerts and /api/ml rows are not keyed by event_id. Detection context appears when R5/R6/R4 records for this event include attack hints or decisions."
      )
    );
  }

  const body = `
    <div class="fact-grid">
      <div><span class="k">Attack hint</span><span class="v">${escapeHtml(na(rca?.attack_hint))}</span></div>
      <div><span class="k">Fusion decision</span><span class="v">${escapeHtml(na(fus?.decision))}</span></div>
      <div><span class="k">Fusion confidence</span><span class="v">${escapeHtml(fmtPct(fus?.confidence))}</span></div>
      <div><span class="k">Prediction (RCA/XAI)</span><span class="v">${escapeHtml(na(rca?.prediction))}</span></div>
      <div><span class="k">Participating detectors</span><span class="v">${escapeHtml(
        Array.isArray(fus?.participating) ? fus.participating.join(", ") || "N/A" : "N/A"
      )}</span></div>
      <div><span class="k">CSV detection join</span><span class="v">N/A (no event_id)</span></div>
    </div>
    <p class="muted">Values above are backend-authored. The UI does not reclassify attacks.</p>`;

  const st =
    bundle.rca?.state === DataState.LIVE || bundle.fusion?.state === DataState.LIVE
      ? { state: DataState.LIVE, fetchedAt: bundle.fusion?.fetchedAt || bundle.rca?.fetchedAt }
      : bundle.fusion || bundle.rca || { state: DataState.EMPTY, fetchedAt: Date.now() };

  return panelShell("Detection Evidence", "decision", st, body);
}

function renderR4Panel(bundle) {
  const result = bundle.correlation;
  if (result.state === DataState.OFFLINE) {
    return panelShell("R4 Correlation", "analysis", result, offlineState());
  }
  if (result.state === DataState.ERROR) {
    return panelShell("R4 Correlation", "analysis", result, errorState("Error", result.error || "Failed"));
  }
  if (result.state === DataState.EMPTY || !result.data?.results?.length) {
    return panelShell(
      "R4 Correlation",
      "analysis",
      result,
      emptyState("R4 unavailable for this event", "No correlation_results with this event_id.")
    );
  }
  const rows = result.data.results
    .map(
      (r) => `<tr>
      <td>${escapeHtml(na(r.correlation_id))}</td>
      <td>${escapeHtml(na(r.status || r.label))}</td>
      <td>${escapeHtml(fmtNum(r.score ?? r.correlation_score, 3))}</td>
      <td>${escapeHtml(fmtPct(r.confidence))}</td>
      <td>${escapeHtml(shortTs(r.timestamp) || "Time unavailable")}</td>
    </tr>`
    )
    .join("");
  const body = `
    <p class="advisory">ADVISORY / ANALYTICAL — co-occurrence evidence only. Does not authorize mitigation.</p>
    <div class="table-wrap"><table class="data-table">
      <thead><tr><th>Correlation ID</th><th>Result</th><th>Score</th><th>Confidence</th><th>Timestamp</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
  return panelShell("R4 Correlation", "analysis", result, body);
}

function renderR6Panel(bundle) {
  const result = bundle.fusion;
  if (result.state === DataState.OFFLINE) {
    return panelShell("R6 Fusion", "decision", result, offlineState());
  }
  if (result.state === DataState.EMPTY || !result.data?.results?.length) {
    return panelShell(
      "R6 Fusion",
      "decision",
      result,
      emptyState("R6 unavailable for this event", "No fused_decisions with this event_id.")
    );
  }
  const rows = result.data.results
    .map(
      (r) => `<tr>
      <td>${escapeHtml(na(r.fusion_id))}</td>
      <td>${escapeHtml(na(r.decision))}</td>
      <td>${escapeHtml(fmtPct(r.confidence))}</td>
      <td>${escapeHtml(typeof r.disagreement === "boolean" ? String(r.disagreement) : na(r.disagreement))}</td>
      <td>${escapeHtml(Array.isArray(r.participating) ? r.participating.join(", ") : "N/A")}</td>
      <td>${escapeHtml(shortTs(r.timestamp) || "Time unavailable")}</td>
    </tr>`
    )
    .join("");
  const body = `
    <p class="muted">Fusion mathematics are not recomputed in the browser.</p>
    <div class="table-wrap"><table class="data-table">
      <thead><tr><th>Fusion ID</th><th>Decision</th><th>Confidence</th><th>Disagreement</th><th>Sources</th><th>Timestamp</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
  return panelShell("R6 Collaborative Fusion", "decision", result, body);
}

function renderR7Panel(bundle) {
  const result = bundle.verification;
  if (result.state === DataState.OFFLINE) {
    return panelShell("R7 Verification", "decision", result, offlineState());
  }
  if (result.state === DataState.EMPTY || !result.data?.traces?.length) {
    return panelShell(
      "R7 Verification",
      "decision",
      result,
      emptyState("R7 unavailable for this event", "No verification_trace rows with this event_id.")
    );
  }
  const body = result.data.traces
    .map((t) => {
      const stages = t.stages || [];
      return `
        <article class="verify-card">
          <header>
            ${statusBadge(t.status || "UNKNOWN")}
            <span>${escapeHtml(shortTs(t.timestamp) || "Time unavailable")}</span>
          </header>
          <div class="verify-meta">
            <span>Verification ID: ${escapeHtml(na(t.verification_id))}</span>
            <span>Eligible: ${escapeHtml(String(t.mitigation_eligible ?? "N/A"))}</span>
            <span>Confidence: ${escapeHtml(fmtPct(t.confidence))}</span>
          </div>
          <p>${escapeHtml(na(t.reason, ""))}</p>
          <p class="muted">Reference stages: WARMUP → DETECTION_EVIDENCE → ATTACK_CONFIRMATION → CONFIDENCE_GATE → ATTACKER_IDENTIFICATION → MITIGATION_ELIGIBILITY</p>
          ${timeline(stages)}
        </article>`;
    })
    .join("");
  return panelShell("R7 Multi-Stage Verification", "decision", result, body);
}

function renderMitigationPanel(bundle) {
  const rca = bundle.rca?.data;
  const ver = pickFirst(bundle.verification?.data?.traces);
  const has =
    (rca && (rca.mitigation_eligible != null || rca.mitigation_strategy)) ||
    (ver && ver.mitigation_eligible != null);

  if (!has) {
    return panelShell(
      "Mitigation Status (observation)",
      "decision",
      bundle.blocklist,
      emptyState(
        "Mitigation information unavailable",
        "No mitigation fields on linked R5/R7 records. Blocklist API is not keyed by event_id — not joined."
      )
    );
  }

  const body = `
    <div class="fact-grid">
      <div><span class="k">Mitigation eligible (R7/R5)</span><span class="v">${escapeHtml(
        String(ver?.mitigation_eligible ?? rca?.mitigation_eligible ?? "N/A")
      )}</span></div>
      <div><span class="k">Strategy (R5)</span><span class="v">${escapeHtml(na(rca?.mitigation_strategy))}</span></div>
      <div><span class="k">Verification status</span><span class="v">${escapeHtml(
        na(ver?.status || rca?.verification_status)
      )}</span></div>
      <div><span class="k">Blocklist join</span><span class="v">N/A (no event_id)</span></div>
    </div>
    <p class="advisory">READ ONLY — no block/unblock controls.</p>`;

  return panelShell(
    "Mitigation Status (observation)",
    "decision",
    { state: DataState.LIVE, fetchedAt: bundle.verification?.fetchedAt || bundle.rca?.fetchedAt },
    body
  );
}

function renderR5Panel(bundle) {
  const result = bundle.rca;
  if (result.state === DataState.OFFLINE) {
    return panelShell("R5 RCA / XAI", "analysis", result, offlineState());
  }
  if (result.state === DataState.EMPTY || !result.data) {
    return panelShell(
      "R5 RCA / XAI",
      "analysis",
      result,
      emptyState("R5 Analysis unavailable", "No root-cause report for this event_id.")
    );
  }
  const r = result.data;
  const features = Array.isArray(r.decision_evidence) ? r.decision_evidence : [];
  const evidence = Array.isArray(r.evidence_items) ? r.evidence_items : [];

  let xaiHtml;
  if (!features.length) {
    xaiHtml = emptyState(
      "Feature contribution data unavailable",
      "Backend did not expose XAI local path features for this report."
    );
  } else {
    // Names only — no synthetic contribution weights
    xaiHtml = `
      <p class="muted">XAI local path features (presence only — contribution weights not exposed by API):</p>
      <ul class="xai-list">
        ${features.map((f) => `<li>${escapeHtml(String(f))}</li>`).join("")}
      </ul>`;
  }

  const body = `
    <div class="fact-grid">
      <div><span class="k">Report ID</span><span class="v">${escapeHtml(na(r.report_id))}</span></div>
      <div><span class="k">Summary</span><span class="v">${escapeHtml(na(r.summary))}</span></div>
      <div><span class="k">Suspected source</span><span class="v">${escapeHtml(na(r.suspected_source))}</span></div>
      <div><span class="k">Affected target</span><span class="v">${escapeHtml(na(r.affected_target))}</span></div>
      <div><span class="k">RCA confidence</span><span class="v">${escapeHtml(fmtPct(r.rca_confidence))}</span></div>
      <div><span class="k">Confidence semantics</span><span class="v">${escapeHtml(na(r.rca_confidence_semantics))}</span></div>
      <div><span class="k">Correlation ID</span><span class="v">${escapeHtml(na(r.correlation_id))}</span></div>
      <div><span class="k">Fusion ID</span><span class="v">${escapeHtml(na(r.fusion_id))}</span></div>
    </div>
    <h4>Explanation</h4>
    <p>${escapeHtml(na(r.explanation_summary))}</p>
    <h4>Evidence items</h4>
    ${
      evidence.length
        ? `<ul class="evidence-list">${evidence
            .map(
              (e) =>
                `<li><span class="badge badge-${escapeHtml(String(e.kind || "unknown").toLowerCase())}">${escapeHtml(
                  e.kind || "UNKNOWN"
                )}</span> ${escapeHtml(e.statement || e.key || "")}</li>`
            )
            .join("")}</ul>`
        : "<p class=\"muted\">No evidence items</p>"
    }
    <h4>XAI Feature Path</h4>
    ${xaiHtml}`;

  return panelShell("R5 Root Cause / XAI", "analysis", result, body);
}

function renderR8Panel(bundle) {
  const result = bundle.alerts;
  if (result.state === DataState.OFFLINE) {
    return panelShell("R8 Alerts", "alert", result, offlineState());
  }
  if (result.state === DataState.EMPTY || !result.data?.alerts?.length) {
    return panelShell(
      "R8 Alerts",
      "alert",
      result,
      emptyState("No alerts for this event", "No security-alerts with matching event_id.")
    );
  }
  const body = `<div class="alert-list">${result.data.alerts.map(alertCard).join("")}</div>`;
  return panelShell("R8 Security Alerts", "alert", result, body);
}

function renderProvenance(bundle) {
  const rows = [
    ["R4 Correlation", sliceStateLabel(bundle.correlation)],
    ["R6 Fusion", sliceStateLabel(bundle.fusion)],
    ["R7 Verification", sliceStateLabel(bundle.verification)],
    ["R5 RCA", sliceStateLabel(bundle.rca)],
    ["R8 Alerting", sliceStateLabel(bundle.alerts)],
    ["Mitigation blocklist", "UNAVAILABLE (no event_id)"],
  ];
  return `
    <div class="provenance-grid">
      ${rows
        .map(
          ([name, st]) =>
            `<div class="prov-row"><span>${escapeHtml(name)}</span>${statusBadge(st)}</div>`
        )
        .join("")}
    </div>`;
}

export async function renderEvents(root, ctx = {}) {
  root.innerHTML =
    pageHeader({
      title: "Security Events",
      subtitle: "Event IDs collected from backend records (explicit event_id only).",
      extra: statusBadge("LOADING"),
    }) + loadingState("Indexing events…");

  const index = await fetchRecentEventIndex(ctx.signal);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  const rows = (index.events || [])
    .map(
      (e) => `<tr>
      <td><code>${escapeHtml(e.eventId)}</code></td>
      <td>${escapeHtml(e.sources.join(", "))}</td>
      <td>${escapeHtml(e.latestTimestamp ? shortTs(e.latestTimestamp) : "Time unavailable")}</td>
      <td>${investigateLink(e.eventId)}</td>
    </tr>`
    )
    .join("");

  root.innerHTML = `
    ${pageHeader({
      title: "Security Events",
      subtitle: "Select an event_id to open a read-only investigation. No heuristic matching.",
      extra: statusBadge(index.state),
    })}
    <nav class="inv-nav">
      <a href="#dashboard">Back to Dashboard</a>
      <a href="#alerts">Back to Alerts</a>
    </nav>
    ${
      !rows
        ? emptyState("No events", "No event_id values found in recent R4/R6/R7/R5/R8 records.")
        : `<div class="table-wrap"><table class="data-table">
            <thead><tr><th>Event ID</th><th>Sources</th><th>Latest timestamp</th><th></th></tr></thead>
            <tbody>${rows}</tbody>
          </table></div>`
    }
  `;
}

export async function renderInvestigation(root, ctx = {}) {
  const eventId = String(ctx.eventId || "").trim();

  root.innerHTML =
    pageHeader({
      title: "Security Event Investigation",
      subtitle: "Read-only observer view of the IntelliShield pipeline for one event_id.",
      badge: "READ ONLY",
      extra: statusBadge("LOADING"),
    }) + loadingState("Loading investigation…");

  if (!eventId || !isValidEventId(eventId)) {
    root.innerHTML = `
      ${pageHeader({ title: "Security Event Investigation", badge: "READ ONLY" })}
      ${errorState("Missing event ID", "Navigate from Alerts, Events, R7, or R5 with a real event_id. Synthetic IDs are not created.")}
      <nav class="inv-nav"><a href="#events">Back to Events</a></nav>`;
    return;
  }

  const bundle = await fetchInvestigationBundle(eventId, ctx.signal);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  const corr = pickFirst(bundle.correlation?.data?.results);
  const fus = pickFirst(bundle.fusion?.data?.results);
  const ver = pickFirst(bundle.verification?.data?.traces);
  const rca = bundle.rca?.data;
  const alert = pickFirst(bundle.alerts?.data?.alerts);

  const anyLive = ["correlation", "fusion", "verification", "rca", "alerts"].some((k) => {
    const s = bundle[k]?.state;
    return s === DataState.LIVE || s === DataState.STALE;
  });
  const allOffline = ["correlation", "fusion", "verification", "rca", "alerts"].every((k) => {
    const s = bundle[k]?.state;
    return s === DataState.OFFLINE || s === DataState.ERROR;
  });
  const headerState = allOffline ? "OFFLINE" : anyLive ? "PARTIAL" : "NO DATA";

  const stages = buildInvestigationTimeline(bundle);

  // Validate joins — every shown record must match event_id
  const joinOk =
    (!corr || sameEventId(corr.event_id, eventId)) &&
    (!fus || sameEventId(fus.event_id, eventId)) &&
    (!ver || sameEventId(ver.event_id, eventId)) &&
    (!rca || sameEventId(rca.event_id, eventId)) &&
    (!alert || sameEventId(alert.event_id, eventId));

  const invProv = buildProvenance({
    sourceKey: "r7",
    result: bundle.verification || { state: DataState.EMPTY, fetchedAt: Date.now() },
    retrievedCount: null,
    displayedCount: null,
    filterMode: FilterMode.SERVER,
    historical: true,
    joinability: Linkability.JOINABLE,
    completeness: Completeness.PARTIAL,
    limitations: [
      "Investigation joins use explicit event_id only",
      "Legacy detection CSV is not event_id-keyed (PARTIAL)",
      "Blocklist is not event_id-keyed (NOT JOINABLE)",
    ],
    timeRangeLabel: "Single event",
  });
  invProv.dataState = headerState === "OFFLINE" ? ObsState.OFFLINE : ObsState.PARTIAL;
  invProv.source = "Investigation bundle (R4/R6/R7/R5/R8 by event_id)";
  invProv.sourcePath = "Multiple GET …?event_id=";

  const layerRows = [
    ["Detection (legacy CSV)", "PARTIAL", "Legacy records do not reliably contain event_id"],
    ["R4 Correlation", corr ? "JOINABLE" : "NO DATA", corr ? "Matched event_id" : "No associated report"],
    ["R6 Fusion", fus ? "JOINABLE" : "NO DATA", fus ? "Matched event_id" : "No associated report"],
    ["R7 Verification", ver ? "JOINABLE" : "NO DATA", ver ? "Matched event_id" : "No associated report"],
    ["R5 RCA", rca ? "JOINABLE" : "NO DATA", rca ? "Matched event_id" : "No associated report"],
    ["R8 Alert", alert ? "JOINABLE" : "NO DATA", alert ? "Matched event_id" : "No associated report"],
    ["Mitigation blocklist", "NOT_AVAILABLE", "Blocklist API is not keyed by event_id"],
  ]
    .map(
      ([name, st, reason]) =>
        `<tr><td>${escapeHtml(name)}</td><td>${statusBadge(st)}</td><td class="muted">${escapeHtml(
          reason
        )}</td></tr>`
    )
    .join("");

  root.innerHTML = `
    ${pageHeader({
      title: "Security Event Investigation",
      subtitle: "WHAT HAPPENED → DETECTED → CORRELATED → FUSED → VERIFIED → ANALYZED → ALERTED",
      badge: "READ ONLY",
      extra: `${statusBadge(headerState)}`,
    })}
    <nav class="inv-nav" aria-label="Investigation navigation">
      <a href="#events">Back to Events</a>
      <a href="#alerts">Back to Alerts</a>
      <a href="#dashboard">Back to Dashboard</a>
      <a href="#verification">Back to R7</a>
      <a href="#rca">Back to R5</a>
    </nav>

    <section class="inv-header panel">
      <div class="inv-kicker">SECURITY EVENT</div>
      <h2><code>${escapeHtml(eventId)}</code></h2>
      <div class="fact-grid">
        <div><span class="k">Event ID</span><span class="v">${escapeHtml(eventId)}</span></div>
        <div><span class="k">Linkability</span><span class="v">${statusBadge("JOINABLE")}</span></div>
        <div><span class="k">Detected / latest TS</span><span class="v">${escapeHtml(
          shortTs(
            alert?.timestamp || ver?.timestamp || fus?.timestamp || corr?.timestamp || rca?.timestamp
          ) || "Time unavailable"
        )}</span></div>
        <div><span class="k">Backend status</span><span class="v">${escapeHtml(
          na(ver?.status || fus?.decision || alert?.severity)
        )}</span></div>
        <div><span class="k">Data sources</span><span class="v">${escapeHtml(
          [
            corr && "R4",
            fus && "R6",
            ver && "R7",
            rca && "R5",
            alert && "R8",
          ]
            .filter(Boolean)
            .join(", ") || "N/A"
        )}</span></div>
      </div>
      ${provenanceBanner(invProv, { title: "Investigation provenance" })}
      <div class="table-wrap" style="margin-top:12px">
        <table class="data-table">
          <thead><tr><th>Layer</th><th>Linkage</th><th>Reason</th></tr></thead>
          <tbody>${layerRows}</tbody>
        </table>
      </div>
      <div class="fact-grid" style="margin-top:12px">
        <div><span class="k">Correlation ID</span><span class="v">${escapeHtml(
          na(corr?.correlation_id || rca?.correlation_id)
        )}</span></div>
        <div><span class="k">Fusion ID</span><span class="v">${escapeHtml(
          na(fus?.fusion_id || rca?.fusion_id)
        )}</span></div>
        <div><span class="k">Verification ID</span><span class="v">${escapeHtml(na(ver?.verification_id))}</span></div>
        <div><span class="k">Alert ID</span><span class="v">${escapeHtml(na(alert?.alert_id))}</span></div>
        <div><span class="k">RCA Report ID</span><span class="v">${escapeHtml(na(rca?.report_id))}</span></div>
      </div>
      <p class="muted">Overall frontend verdict: N/A — UI presents backend results only.</p>
      ${joinOk ? "" : `<p class="advisory">Join integrity warning: a returned record did not match event_id.</p>`}
    </section>

    ${sectionHeader("Evidence provenance", "")}
    ${renderProvenance(bundle)}

    ${sectionHeader("Unified pipeline timeline", "")}
    ${renderUnifiedTimeline(stages)}

    ${sectionHeader("Layer detail", "")}
    <div class="inv-panels">
      ${renderDetectionPanel(bundle)}
      ${renderR4Panel(bundle)}
      ${renderR6Panel(bundle)}
      ${renderR7Panel(bundle)}
      ${renderMitigationPanel(bundle)}
      ${renderR5Panel(bundle)}
      ${renderR8Panel(bundle)}
    </div>
  `;
}

// Re-export for tests
export { sameEventId };
