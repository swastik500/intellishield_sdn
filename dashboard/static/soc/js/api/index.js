/** Phase 1/2 read-only API surface — GET endpoints only. */

import { getJSON, withEmpty, DataState } from "./client.js";

export { DataState, getJSON, withEmpty, maybeStale, ageLabel, STALE_AFTER_MS } from "./client.js";

const emptyList = (key) => (data) => {
  const arr = data && data[key];
  return !Array.isArray(arr) || arr.length === 0;
};

function optsOf(signal) {
  return signal ? { signal } : {};
}

export function fetchStatus(signal) {
  return getJSON("/api/status", optsOf(signal));
}

export function fetchSummary(signal) {
  return getJSON("/api/summary", optsOf(signal));
}

export function fetchTraffic(n = 60, signal) {
  return getJSON(`/api/traffic?n=${encodeURIComponent(n)}`, optsOf(signal)).then((r) =>
    withEmpty(r, emptyList("points"))
  );
}

export function fetchEntropy(n = 60, signal) {
  return getJSON(`/api/entropy?n=${encodeURIComponent(n)}`, optsOf(signal)).then((r) =>
    withEmpty(r, (d) => !d || (!d.latest && (!d.points || !d.points.length)))
  );
}

export function fetchDetectionAlerts(n = 40, signal) {
  return getJSON(`/api/alerts?n=${encodeURIComponent(n)}`, optsOf(signal)).then((r) =>
    withEmpty(r, emptyList("alerts"))
  );
}

export function fetchMl(n = 40, signal) {
  return getJSON(`/api/ml?n=${encodeURIComponent(n)}`, optsOf(signal)).then((r) =>
    withEmpty(r, (d) => {
      if (!d) return true;
      if (Array.isArray(d.predictions)) return d.predictions.length === 0;
      if (Array.isArray(d.points)) return d.points.length === 0;
      return false;
    })
  );
}

export function fetchDrift(n = 20, signal) {
  return getJSON(`/api/drift?n=${encodeURIComponent(n)}`, optsOf(signal)).then((r) =>
    withEmpty(r, (d) => {
      if (!d) return true;
      if (Array.isArray(d.alerts)) return d.alerts.length === 0;
      if (Array.isArray(d.events)) return d.events.length === 0;
      return false;
    })
  );
}

export function fetchBlocklist(n = 20, signal) {
  return getJSON(`/api/blocklist?n=${encodeURIComponent(n)}`, optsOf(signal)).then((r) =>
    withEmpty(r, (d) => {
      if (!d) return true;
      if (Array.isArray(d.blocks)) return d.blocks.length === 0;
      if (Array.isArray(d.actions)) return d.actions.length === 0;
      return false;
    })
  );
}

export function fetchRl(n = 20, signal) {
  return getJSON(`/api/rl?n=${encodeURIComponent(n)}`, optsOf(signal)).then((r) =>
    withEmpty(r, (d) => {
      if (!d) return true;
      if (Array.isArray(d.decisions)) return d.decisions.length === 0;
      if (Array.isArray(d.points)) return d.points.length === 0;
      return false;
    })
  );
}

export function fetchSecurityAlerts(limit = 40, signal) {
  return getJSON(`/api/security-alerts?limit=${encodeURIComponent(limit)}`, optsOf(signal)).then(
    (r) => withEmpty(r, emptyList("alerts"))
  );
}

export function fetchSecurityAlertStats(signal) {
  return getJSON("/api/security-alerts/stats", optsOf(signal));
}

export function fetchCorrelationResults(limit = 40, signal) {
  return getJSON(
    `/api/correlation-results?limit=${encodeURIComponent(limit)}`,
    optsOf(signal)
  ).then((r) => withEmpty(r, emptyList("results")));
}

export function fetchCorrelationStats(signal) {
  return getJSON("/api/correlation-results/stats", optsOf(signal));
}

export function fetchFusedDecisions(limit = 40, signal) {
  return getJSON(`/api/fused-decisions?limit=${encodeURIComponent(limit)}`, optsOf(signal)).then(
    (r) => withEmpty(r, emptyList("results"))
  );
}

export function fetchFusionStats(signal) {
  return getJSON("/api/fused-decisions/stats", optsOf(signal));
}

export function fetchVerificationTraces(limit = 40, signal) {
  return getJSON(
    `/api/verification-traces?limit=${encodeURIComponent(limit)}`,
    optsOf(signal)
  ).then((r) => {
    if (r.status === 404) {
      return { ...r, state: DataState.UNAVAILABLE, error: "Verification read API unavailable" };
    }
    return withEmpty(r, emptyList("traces"));
  });
}

export function fetchRcaReports(limit = 20, signal) {
  return getJSON(
    `/api/root-cause-reports?limit=${encodeURIComponent(limit)}`,
    optsOf(signal)
  ).then((r) => withEmpty(r, emptyList("reports")));
}

export function fetchTwinRuns(limit = 15, signal) {
  return getJSON(`/api/digital-twin/runs?limit=${encodeURIComponent(limit)}`, optsOf(signal)).then(
    (r) => withEmpty(r, emptyList("runs"))
  );
}

export function fetchTwinSnapshots(limit = 15, signal) {
  return getJSON(
    `/api/digital-twin/snapshots?limit=${encodeURIComponent(limit)}`,
    optsOf(signal)
  ).then((r) => withEmpty(r, emptyList("snapshots")));
}

export function fetchTwinSnapshot(snapshotId, signal) {
  if (!snapshotId) {
    return Promise.resolve({
      state: "EMPTY",
      data: null,
      error: "snapshot_id required",
      fetchedAt: new Date().toISOString(),
    });
  }
  return getJSON(
    `/api/digital-twin/snapshots/${encodeURIComponent(snapshotId)}`,
    optsOf(signal)
  );
}

export function fetchTwinReplays(limit = 15, signal) {
  return getJSON(
    `/api/digital-twin/replays?limit=${encodeURIComponent(limit)}`,
    optsOf(signal)
  ).then((r) => withEmpty(r, emptyList("replays")));
}

export function fetchTwinSimulations(limit = 15, signal) {
  return getJSON(
    `/api/digital-twin/simulations?limit=${encodeURIComponent(limit)}`,
    optsOf(signal)
  ).then((r) => withEmpty(r, emptyList("simulations")));
}

export function fetchTwinStats(signal) {
  return getJSON("/api/digital-twin/stats", optsOf(signal));
}

export function fetchControlStatus(signal) {
  return getJSON("/api/control/status", optsOf(signal));
}

export function fetchMetrics(signal) {
  return getJSON("/api/metrics", optsOf(signal));
}

/** Read-only switches + learned hosts (no switch–switch LLDP links). */
export function fetchTopology(signal) {
  return getJSON("/api/topology", optsOf(signal)).then((r) => {
    if (!r || r.state === "ERROR" || r.state === "OFFLINE") return r;
    const d = r.data;
    if (!d || d.available === false) {
      return withEmpty(r, () => true);
    }
    return r;
  });
}

/** Parallel dashboard bootstrap — partial failures stay section-local. */
export async function fetchDashboardBundle(signal) {
  const keys = [
    "status",
    "summary",
    "traffic",
    "entropy",
    "alerts",
    "securityAlerts",
    "securityStats",
    "correlation",
    "fusion",
    "verification",
    "rca",
    "blocklist",
    "ml",
    "twinStats",
    "twinSnapshots",
  ];
  const promises = [
    fetchStatus(signal),
    fetchSummary(signal),
    fetchTraffic(60, signal),
    fetchEntropy(60, signal),
    fetchDetectionAlerts(25, signal),
    fetchSecurityAlerts(25, signal),
    fetchSecurityAlertStats(signal),
    fetchCorrelationResults(20, signal),
    fetchFusedDecisions(20, signal),
    fetchVerificationTraces(20, signal),
    fetchRcaReports(8, signal),
    fetchBlocklist(10, signal),
    fetchMl(30, signal),
    fetchTwinStats(signal),
    fetchTwinSnapshots(5, signal),
  ];
  const settled = await Promise.all(promises);
  const out = {};
  keys.forEach((k, i) => {
    out[k] = settled[i];
  });
  return out;
}
