/**
 * Phase 4 — System health model (observation only).
 * Derives component states from API evidence. No invented scores or averages.
 */

import { DataState, ageLabel, STALE_AFTER_MS } from "../api/client.js";

export const HealthState = Object.freeze({
  HEALTHY: "HEALTHY",
  DEGRADED: "DEGRADED",
  STALE: "STALE",
  OFFLINE: "OFFLINE",
  NO_DATA: "NO DATA",
  UNKNOWN: "UNKNOWN",
  SNAPSHOT: "SNAPSHOT",
  LOADING: "LOADING",
});

/** Map ApiResult.state → health label (no scoring). */
export function healthFromApiResult(result) {
  if (!result) return HealthState.UNKNOWN;
  switch (result.state) {
    case DataState.LIVE:
      return HealthState.HEALTHY;
    case DataState.STALE:
      return HealthState.STALE;
    case DataState.EMPTY:
      return HealthState.NO_DATA;
    case DataState.OFFLINE:
      return HealthState.OFFLINE;
    case DataState.ERROR:
      return HealthState.DEGRADED;
    case DataState.UNAVAILABLE:
      return HealthState.UNKNOWN;
    case DataState.LOADING:
      return HealthState.LOADING;
    case DataState.SNAPSHOT:
      return HealthState.SNAPSHOT;
    default:
      return HealthState.UNKNOWN;
  }
}

/** Backend /api/status boolean freshness flags. */
export function healthFromStatusFlag(flag) {
  if (flag === true) return HealthState.HEALTHY;
  if (flag === false) return HealthState.NO_DATA;
  return HealthState.UNKNOWN;
}

/**
 * Redact likely secrets from diagnostic payloads before display.
 * Never invents fields — only strips sensitive keys.
 */
const SENSITIVE_KEY = /pass(word)?|secret|token|api[_-]?key|credential|private[_-]?key|aws|authorization|cookie/i;

export function redactDiagnostics(value, depth = 0) {
  if (depth > 6) return "[truncated]";
  if (value == null) return value;
  if (Array.isArray(value)) {
    return value.slice(0, 40).map((v) => redactDiagnostics(v, depth + 1));
  }
  if (typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (SENSITIVE_KEY.test(k)) {
        out[k] = "[redacted]";
      } else {
        out[k] = redactDiagnostics(v, depth + 1);
      }
    }
    return out;
  }
  return value;
}

function countFrom(result, keys) {
  if (!result || !result.data) return null;
  const d = result.data;
  for (const k of keys) {
    if (Array.isArray(d[k])) return d[k].length;
    if (typeof d[k] === "number") return d[k];
  }
  if (typeof d.total === "number") return d.total;
  return null;
}

function latestTs(result, listKey, tsFields = ["timestamp"]) {
  if (!result || !result.data) return null;
  const list = result.data[listKey];
  if (!Array.isArray(list) || !list.length) {
    const latest = result.data.latest;
    if (latest && typeof latest === "object") {
      for (const f of tsFields) {
        if (latest[f]) return latest[f];
      }
    }
    return null;
  }
  // Prefer first (APIs often newest-first) else scan
  for (const row of list) {
    for (const f of tsFields) {
      if (row && row[f]) return row[f];
    }
  }
  return null;
}

/**
 * Build component health cards from a dashboard-like bundle + status/control.
 * @returns {Array<object>}
 */
export function buildComponentHealth(bundle, statusResult, controlResult) {
  const st =
    statusResult &&
    (statusResult.state === DataState.LIVE || statusResult.state === DataState.STALE) &&
    statusResult.data
      ? statusResult.data
      : {};

  const dashboardApi = {
    id: "dashboard-api",
    name: "Dashboard API",
    state: healthFromApiResult(statusResult),
    source: "GET /api/status",
    sourceLabel: "Status API",
    fetchedAt: statusResult?.fetchedAt || null,
    detail:
      statusResult?.state === DataState.LIVE
        ? `Reachable · server_time=${st.server_time || "N/A"}`
        : statusResult?.error || "Status endpoint observation",
    activity: null,
    lastEventTs: st.server_time || null,
    notes: "Availability of the FastAPI status surface.",
    control: "READ ONLY",
  };

  const controller = {
    id: "controller",
    name: "Controller",
    state:
      statusResult?.state === DataState.OFFLINE
        ? HealthState.OFFLINE
        : healthFromStatusFlag(st.controller_running),
    source: "GET /api/status → controller_running",
    sourceLabel: "Status API",
    fetchedAt: statusResult?.fetchedAt || null,
    detail: st.controller_running
      ? "Backend reports fresh port/flow stats (<5 min)"
      : "No fresh controller telemetry flag",
    activity: null,
    lastEventTs: st.server_time || null,
    notes: "Flag is file-freshness based in dashboard/api.py.",
    control: "READ ONLY",
  };

  const traffic = {
    id: "traffic",
    name: "Traffic Monitoring",
    state: healthFromApiResult(bundle.traffic),
    source: "GET /api/traffic",
    sourceLabel: "Traffic API",
    fetchedAt: bundle.traffic?.fetchedAt || null,
    detail:
      bundle.traffic?.state === DataState.LIVE || bundle.traffic?.state === DataState.STALE
        ? `${countFrom(bundle.traffic, ["points"]) ?? 0} traffic points`
        : bundle.traffic?.error || "Traffic observations",
    activity: countFrom(bundle.traffic, ["points"]),
    lastEventTs: latestTs(bundle.traffic, "points"),
    notes: "Fields: packet_rate, byte_rate, flow_count. Protocol distribution: not exposed.",
    control: "READ ONLY",
  };

  const detection = {
    id: "detection",
    name: "Detection",
    state: (() => {
      if (statusResult?.state === DataState.OFFLINE) return HealthState.OFFLINE;
      const ent = healthFromStatusFlag(st.phase2_entropy);
      const ml = healthFromStatusFlag(st.phase4_ml);
      if (ent === HealthState.HEALTHY || ml === HealthState.HEALTHY) return HealthState.HEALTHY;
      const apiEnt = healthFromApiResult(bundle.entropy);
      const apiAl = healthFromApiResult(bundle.alerts);
      if (apiEnt === HealthState.HEALTHY || apiAl === HealthState.HEALTHY) return HealthState.HEALTHY;
      if (apiEnt === HealthState.STALE || apiAl === HealthState.STALE) return HealthState.STALE;
      if (apiEnt === HealthState.OFFLINE && apiAl === HealthState.OFFLINE) return HealthState.OFFLINE;
      if (ent === HealthState.NO_DATA && ml === HealthState.NO_DATA) return HealthState.NO_DATA;
      return HealthState.UNKNOWN;
    })(),
    source: "GET /api/status + /api/entropy + /api/alerts",
    sourceLabel: "Detection surfaces",
    fetchedAt: bundle.entropy?.fetchedAt || bundle.alerts?.fetchedAt || null,
    detail: `Entropy flag=${String(st.phase2_entropy)} · ML flag=${String(st.phase4_ml)}`,
    activity: countFrom(bundle.alerts, ["alerts"]),
    lastEventTs: latestTs(bundle.alerts, "alerts") || latestTs(bundle.entropy, "points"),
    notes: "Legacy CSV detection rows are not event_id-keyed.",
    control: "READ ONLY",
  };

  function sliceCard(id, name, result, listKey, source, notes) {
    return {
      id,
      name,
      state: healthFromApiResult(result),
      source,
      sourceLabel: source.replace(/^GET\s+/, ""),
      fetchedAt: result?.fetchedAt || null,
      detail:
        result?.state === DataState.LIVE || result?.state === DataState.STALE
          ? `${countFrom(result, [listKey, "total"]) ?? 0} records in response`
          : result?.error || result?.state || "N/A",
      activity: countFrom(result, [listKey, "total"]),
      lastEventTs: latestTs(result, listKey),
      notes,
      control: "READ ONLY",
    };
  }

  const r4 = sliceCard(
    "r4",
    "R4 Correlation",
    bundle.correlation,
    "results",
    "GET /api/correlation-results",
    "ADVISORY / ANALYTICAL — does not authorize mitigation."
  );

  const r6 = sliceCard(
    "r6",
    "R6 Collaborative Fusion",
    bundle.fusion,
    "results",
    "GET /api/fused-decisions",
    "Fusion math is not recomputed in the UI."
  );

  const r7 = sliceCard(
    "r7",
    "R7 Verification",
    bundle.verification,
    "traces",
    "GET /api/verification-traces",
    "Statuses are backend-authored (VERIFIED/PENDING/INELIGIBLE/FAILED)."
  );

  const mitigation = {
    id: "mitigation",
    name: "Mitigation",
    state:
      statusResult?.state === DataState.OFFLINE
        ? HealthState.OFFLINE
        : healthFromStatusFlag(st.phase5_mitigation),
    source: "GET /api/status → phase5_mitigation (+ optional /api/blocklist)",
    sourceLabel: "Status / blocklist",
    fetchedAt: statusResult?.fetchedAt || bundle.blocklist?.fetchedAt || null,
    detail: st.phase5_mitigation
      ? "Mitigation log file present (existence flag)"
      : "Mitigation log flag false / absent",
    activity: countFrom(bundle.blocklist, ["blocks", "actions"]),
    lastEventTs: latestTs(bundle.blocklist, "blocks") || latestTs(bundle.blocklist, "actions"),
    notes: "Observation only. Blocklist is not keyed by event_id.",
    control: "READ ONLY",
  };

  const r5 = sliceCard(
    "r5",
    "R5 RCA / XAI",
    bundle.rca,
    "reports",
    "GET /api/root-cause-reports",
    "Analytical / explanatory. Not inferred from R7 alone."
  );

  const r8 = sliceCard(
    "r8",
    "R8 Alerting",
    bundle.securityAlerts,
    "alerts",
    "GET /api/security-alerts",
    "Alert creation/mutation is not available from the UI."
  );

  const twin = {
    id: "twin",
    name: "R3 Digital Twin",
    state:
      healthFromApiResult(bundle.twinStats) === HealthState.HEALTHY ||
      healthFromApiResult(bundle.twinSnapshots) === HealthState.HEALTHY
        ? HealthState.SNAPSHOT
        : healthFromApiResult(bundle.twinStats) === HealthState.OFFLINE
          ? HealthState.OFFLINE
          : healthFromApiResult(bundle.twinStats) === HealthState.NO_DATA &&
              healthFromApiResult(bundle.twinSnapshots) === HealthState.NO_DATA
            ? HealthState.NO_DATA
            : healthFromApiResult(bundle.twinStats),
    source: "GET /api/digital-twin/stats|snapshots|runs",
    sourceLabel: "Digital Twin APIs",
    fetchedAt: bundle.twinStats?.fetchedAt || bundle.twinSnapshots?.fetchedAt || null,
    detail: "SNAPSHOT · OBSERVATIONAL · READ ONLY",
    activity: countFrom(bundle.twinSnapshots, ["snapshots"]),
    lastEventTs: latestTs(bundle.twinSnapshots, "snapshots", ["timestamp", "created_at"]),
    notes: "Twin availability is not production mitigation availability.",
    control: "READ ONLY",
  };

  const control = {
    id: "control-status",
    name: "Control Panel Status",
    state: healthFromApiResult(controlResult),
    source: "GET /api/control/status",
    sourceLabel: "Control status (read)",
    fetchedAt: controlResult?.fetchedAt || null,
    detail: "Status observation only — no start/stop/scenario actions in UI.",
    activity: null,
    lastEventTs: null,
    notes: "Write endpoints under /api/control/* are not called by the SOC.",
    control: "READ ONLY",
  };

  return [
    dashboardApi,
    controller,
    traffic,
    detection,
    r4,
    r6,
    r7,
    mitigation,
    r5,
    r8,
    twin,
    control,
  ];
}

/** Pipeline order for visualization (R3 excluded from production path). */
export const PIPELINE_IDS = [
  "traffic",
  "detection",
  "r4",
  "r6",
  "r7",
  "mitigation",
  "r5",
  "r8",
];

export function freshnessLabel(fetchedAt, state) {
  if (!fetchedAt) return "Freshness: N/A";
  const age = ageLabel(fetchedAt);
  if (state === HealthState.STALE || state === DataState.STALE) {
    return `STALE · Last updated: ${age}`;
  }
  return `Last updated: ${age}`;
}

export function documentedStaleWindowMs() {
  return STALE_AFTER_MS;
}
