/**
 * Phase 3 — investigation read helpers.
 * Joins ONLY on explicit event_id (never timestamp/IP heuristics).
 * GET-only.
 */

import {
  getJSON,
  withEmpty,
  DataState,
  fetchCorrelationResults,
  fetchFusedDecisions,
  fetchVerificationTraces,
  fetchSecurityAlerts,
  fetchRcaReports,
} from "./index.js";

function emptyList(key) {
  return (data) => {
    const arr = data && data[key];
    return !Array.isArray(arr) || arr.length === 0;
  };
}

function optsOf(signal) {
  return signal ? { signal } : {};
}

/** Exact event_id match only. */
export function sameEventId(a, b) {
  if (a == null || b == null) return false;
  const x = String(a).trim();
  const y = String(b).trim();
  if (!x || !y || x === "N/A" || y === "N/A" || x === "UNAVAILABLE") return false;
  return x === y;
}

export function fetchRcaByEvent(eventId, signal) {
  const eid = encodeURIComponent(String(eventId).trim());
  return getJSON(`/api/root-cause-reports/by-event/${eid}`, optsOf(signal)).then((r) => {
    if (r.status === 404) {
      return { ...r, state: DataState.EMPTY, data: null, error: null };
    }
    return r;
  });
}

export function fetchCorrelationByEvent(eventId, signal, limit = 20) {
  const eid = encodeURIComponent(String(eventId).trim());
  return getJSON(
    `/api/correlation-results?limit=${limit}&event_id=${eid}`,
    optsOf(signal)
  ).then((r) => withEmpty(r, emptyList("results")));
}

export function fetchFusionByEvent(eventId, signal, limit = 20) {
  const eid = encodeURIComponent(String(eventId).trim());
  return getJSON(
    `/api/fused-decisions?limit=${limit}&event_id=${eid}`,
    optsOf(signal)
  ).then((r) => withEmpty(r, emptyList("results")));
}

export function fetchVerificationByEvent(eventId, signal, limit = 20) {
  const eid = encodeURIComponent(String(eventId).trim());
  return getJSON(
    `/api/verification-traces?limit=${limit}&event_id=${eid}`,
    optsOf(signal)
  ).then((r) => withEmpty(r, emptyList("traces")));
}

/**
 * R8 has no event_id query param — fetch bounded history and filter by exact event_id.
 * This is ID equality filtering, not heuristic matching.
 */
export async function fetchAlertsForEvent(eventId, signal, scanLimit = 200) {
  const res = await fetchSecurityAlerts(scanLimit, signal);
  if (res.state !== DataState.LIVE && res.state !== DataState.EMPTY) return res;
  const alerts = ((res.data && res.data.alerts) || []).filter((a) =>
    sameEventId(a.event_id, eventId)
  );
  if (!alerts.length) {
    return {
      ...res,
      state: DataState.EMPTY,
      data: { alerts: [], total: 0, source: res.data && res.data.source },
    };
  }
  return {
    ...res,
    state: DataState.LIVE,
    data: { alerts, total: alerts.length, source: res.data && res.data.source },
  };
}

/**
 * Load all investigation slices for one event_id in parallel.
 * Partial failures remain section-local.
 */
export async function fetchInvestigationBundle(eventId, signal) {
  const eid = String(eventId || "").trim();
  if (!eid) {
    return {
      eventId: "",
      invalid: true,
      correlation: { state: DataState.EMPTY, data: null, error: "Missing event id", fetchedAt: Date.now() },
      fusion: { state: DataState.EMPTY, data: null, error: "Missing event id", fetchedAt: Date.now() },
      verification: { state: DataState.EMPTY, data: null, error: "Missing event id", fetchedAt: Date.now() },
      rca: { state: DataState.EMPTY, data: null, error: "Missing event id", fetchedAt: Date.now() },
      alerts: { state: DataState.EMPTY, data: null, error: "Missing event id", fetchedAt: Date.now() },
      blocklist: { state: DataState.UNAVAILABLE, data: null, error: "Not joined by event_id", fetchedAt: Date.now() },
    };
  }

  const [correlation, fusion, verification, rca, alerts, blocklist] = await Promise.all([
    fetchCorrelationByEvent(eid, signal),
    fetchFusionByEvent(eid, signal),
    fetchVerificationByEvent(eid, signal),
    fetchRcaByEvent(eid, signal),
    fetchAlertsForEvent(eid, signal),
    // Blocklist has no event_id — surface as unavailable for join, not invented
    Promise.resolve({
      state: DataState.UNAVAILABLE,
      data: null,
      error: "Mitigation blocklist is not keyed by event_id",
      fetchedAt: Date.now(),
      path: "/api/blocklist",
      status: null,
    }),
  ]);

  return {
    eventId: eid,
    invalid: false,
    correlation,
    fusion,
    verification,
    rca,
    alerts,
    blocklist,
  };
}

/**
 * Collect distinct event_ids from recent backend surfaces (explicit field only).
 */
export async function fetchRecentEventIndex(signal) {
  const [alerts, verification, correlation, fusion, rca] = await Promise.all([
    fetchSecurityAlerts(50, signal),
    fetchVerificationTraces(50, signal),
    fetchCorrelationResults(50, signal),
    fetchFusedDecisions(50, signal),
    fetchRcaReports(50, signal),
  ]);

  /** @type {Map<string, { eventId: string, sources: Set<string>, timestamps: string[] }>} */
  const map = new Map();

  function add(eventId, source, ts) {
    const eid = String(eventId || "").trim();
    if (!eid || eid === "UNAVAILABLE" || eid === "N/A") return;
    let row = map.get(eid);
    if (!row) {
      row = { eventId: eid, sources: new Set(), timestamps: [] };
      map.set(eid, row);
    }
    row.sources.add(source);
    if (ts) row.timestamps.push(String(ts));
  }

  for (const a of (alerts.data && alerts.data.alerts) || []) {
    add(a.event_id, "R8", a.timestamp);
  }
  for (const t of (verification.data && verification.data.traces) || []) {
    add(t.event_id, "R7", t.timestamp);
  }
  for (const r of (correlation.data && correlation.data.results) || []) {
    add(r.event_id, "R4", r.timestamp);
  }
  for (const r of (fusion.data && fusion.data.results) || []) {
    add(r.event_id, "R6", r.timestamp);
  }
  for (const r of (rca.data && rca.data.reports) || []) {
    add(r.event_id, "R5", r.timestamp);
  }

  const events = [...map.values()].map((row) => {
    const times = row.timestamps.filter(Boolean).sort();
    return {
      eventId: row.eventId,
      sources: [...row.sources].sort(),
      latestTimestamp: times.length ? times[times.length - 1] : null,
      earliestTimestamp: times.length ? times[0] : null,
    };
  });

  // Sort by latest timestamp desc when available
  events.sort((a, b) =>
    String(b.latestTimestamp || "").localeCompare(String(a.latestTimestamp || ""))
  );

  const anyOffline = [alerts, verification, correlation, fusion, rca].some(
    (r) => r.state === DataState.OFFLINE || r.state === DataState.ERROR
  );

  return {
    state: events.length ? DataState.LIVE : anyOffline ? DataState.OFFLINE : DataState.EMPTY,
    events,
    slices: { alerts, verification, correlation, fusion, rca },
    fetchedAt: Date.now(),
  };
}

export { DataState };
