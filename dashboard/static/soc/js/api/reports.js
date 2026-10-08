/**
 * Phase 5 — bounded report data fetches (GET only).
 */

import {
  fetchTraffic,
  fetchEntropy,
  fetchDetectionAlerts,
  fetchSecurityAlerts,
  fetchSecurityAlertStats,
  fetchCorrelationResults,
  fetchFusedDecisions,
  fetchVerificationTraces,
  fetchRcaReports,
  fetchTwinStats,
  fetchTwinSnapshots,
  fetchTwinRuns,
  fetchTwinReplays,
  fetchTwinSimulations,
  fetchStatus,
  getJSON,
  withEmpty,
  DataState,
} from "./index.js";
import { REPORT_LIMIT, TRAFFIC_LIMIT } from "../utils/report.js";

function optsOf(signal) {
  return signal ? { signal } : {};
}

/** R8 with optional backend since/until (ISO strings). */
export function fetchSecurityAlertsRanged({ limit = REPORT_LIMIT, since, until, severity, signal } = {}) {
  const q = new URLSearchParams();
  q.set("limit", String(limit));
  if (since) q.set("since", since);
  if (until) q.set("until", until);
  if (severity) q.set("severity", severity);
  return getJSON(`/api/security-alerts?${q.toString()}`, optsOf(signal)).then((r) =>
    withEmpty(r, (d) => !d || !Array.isArray(d.alerts) || d.alerts.length === 0)
  );
}

/**
 * Load bounded historical slices for the reports page.
 * Does not invent data. Partial failures stay section-local.
 */
export async function fetchReportsBundle({ signal, sinceIso, untilIso, severity } = {}) {
  const [
    status,
    traffic,
    entropy,
    detection,
    correlation,
    fusion,
    verification,
    rca,
    securityAlerts,
    securityStats,
    twinStats,
    twinSnapshots,
    twinRuns,
    twinReplays,
    twinSimulations,
  ] = await Promise.all([
    fetchStatus(signal),
    fetchTraffic(TRAFFIC_LIMIT, signal),
    fetchEntropy(TRAFFIC_LIMIT, signal),
    fetchDetectionAlerts(REPORT_LIMIT, signal),
    fetchCorrelationResults(REPORT_LIMIT, signal),
    fetchFusedDecisions(REPORT_LIMIT, signal),
    fetchVerificationTraces(REPORT_LIMIT, signal),
    fetchRcaReports(REPORT_LIMIT, signal),
    fetchSecurityAlertsRanged({
      limit: REPORT_LIMIT,
      since: sinceIso || undefined,
      until: untilIso || undefined,
      severity: severity || undefined,
      signal,
    }),
    fetchSecurityAlertStats(signal),
    fetchTwinStats(signal),
    fetchTwinSnapshots(40, signal),
    fetchTwinRuns(40, signal),
    fetchTwinReplays(40, signal),
    fetchTwinSimulations(40, signal),
  ]);

  return {
    status,
    traffic,
    entropy,
    detection,
    correlation,
    fusion,
    verification,
    rca,
    securityAlerts,
    securityStats,
    twinStats,
    twinSnapshots,
    twinRuns,
    twinReplays,
    twinSimulations,
    meta: {
      reportLimit: REPORT_LIMIT,
      trafficLimit: TRAFFIC_LIMIT,
      fetchedAt: Date.now(),
      dataState: DataState.LIVE,
    },
  };
}
