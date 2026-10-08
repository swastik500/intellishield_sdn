/**
 * Phase 6 — SOC data provenance, linkability, and tolerant response validation.
 * Presentation metadata only. No security decisions. No synthetic IDs.
 */

import { DataState } from "../api/client.js";
import { escapeHtml } from "./format.js";

/** Explicit observability states (do not collapse distinct conditions). */
export const ObsState = Object.freeze({
  LIVE: "LIVE",
  HISTORICAL: "HISTORICAL",
  SNAPSHOT: "SNAPSHOT",
  STALE: "STALE",
  OFFLINE: "OFFLINE",
  NO_DATA: "NO_DATA",
  PARTIAL: "PARTIAL",
  NOT_AVAILABLE: "NOT_AVAILABLE",
  UNKNOWN: "UNKNOWN",
  DATA_ERROR: "DATA_ERROR",
});

export const DataKind = Object.freeze({
  OBSERVED: "OBSERVED",
  BACKEND_DECISION: "BACKEND DECISION",
  ANALYTICAL: "ANALYTICAL",
  ALERT: "ALERT",
  SNAPSHOT: "SNAPSHOT",
  ADVISORY: "ADVISORY",
});

export const Linkability = Object.freeze({
  JOINABLE: "JOINABLE",
  NOT_JOINABLE: "NOT_JOINABLE",
  PARTIAL: "PARTIAL",
  UNKNOWN: "UNKNOWN",
  NOT_AVAILABLE: "NOT_AVAILABLE",
});

export const FilterMode = Object.freeze({
  SERVER: "SERVER FILTERED",
  CLIENT: "CLIENT FILTERED",
  NONE: "NONE",
  NOT_APPLICABLE: "NOT APPLICABLE",
});

export const Completeness = Object.freeze({
  COMPLETE: "COMPLETE",
  PARTIAL: "PARTIAL",
  BOUNDED: "BOUNDED",
  NOT_AVAILABLE: "NOT_AVAILABLE",
  UNKNOWN: "UNKNOWN",
});

/** Known sources — labels for UI (no secrets). */
export const SOURCES = Object.freeze({
  traffic: { id: "traffic", label: "Traffic API", path: "GET /api/traffic", kind: DataKind.OBSERVED },
  entropy: { id: "entropy", label: "Entropy API", path: "GET /api/entropy", kind: DataKind.OBSERVED },
  detection: {
    id: "detection",
    label: "Detection API (legacy)",
    path: "GET /api/alerts",
    kind: DataKind.OBSERVED,
  },
  ml: { id: "ml", label: "ML API (legacy)", path: "GET /api/ml", kind: DataKind.OBSERVED },
  r4: {
    id: "r4",
    label: "Correlation Results API",
    path: "GET /api/correlation-results",
    kind: DataKind.ADVISORY,
  },
  r6: {
    id: "r6",
    label: "Fusion Decisions API",
    path: "GET /api/fused-decisions",
    kind: DataKind.BACKEND_DECISION,
  },
  r7: {
    id: "r7",
    label: "Verification Trace API",
    path: "GET /api/verification-traces",
    kind: DataKind.BACKEND_DECISION,
  },
  r5: {
    id: "r5",
    label: "Root Cause Reports API",
    path: "GET /api/root-cause-reports",
    kind: DataKind.ANALYTICAL,
  },
  r8: {
    id: "r8",
    label: "Security Alerts API",
    path: "GET /api/security-alerts",
    kind: DataKind.ALERT,
  },
  twin: {
    id: "twin",
    label: "Digital Twin API",
    path: "GET /api/digital-twin/*",
    kind: DataKind.SNAPSHOT,
  },
  health: {
    id: "health",
    label: "Status API",
    path: "GET /api/status",
    kind: DataKind.OBSERVED,
  },
});

/**
 * Valid event_id for investigation navigation.
 * Rejects empty, N/A, UNAVAILABLE, numeric indexes alone are allowed if backend sent them as strings —
 * but we never synthesize from array index.
 */
export function isValidEventId(value) {
  if (value == null) return false;
  const s = String(value).trim();
  if (!s) return false;
  const upper = s.toUpperCase();
  if (upper === "N/A" || upper === "NA" || upper === "UNAVAILABLE" || upper === "NULL" || upper === "UNDEFINED") {
    return false;
  }
  // Malformed: pure whitespace already handled; reject obvious placeholders
  if (s === "-" || s === "—") return false;
  return true;
}

export function eventLinkability(recordOrId) {
  const id =
    recordOrId && typeof recordOrId === "object" ? recordOrId.event_id : recordOrId;
  if (isValidEventId(id)) return Linkability.JOINABLE;
  if (id == null || id === "") return Linkability.NOT_AVAILABLE;
  return Linkability.NOT_JOINABLE;
}

/** Map ApiResult.state → ObsState without inventing success. */
export function obsStateFromApi(result, { historical = false, snapshot = false } = {}) {
  if (!result) return ObsState.UNKNOWN;
  switch (result.state) {
    case DataState.LIVE:
      if (snapshot) return ObsState.SNAPSHOT;
      return historical ? ObsState.HISTORICAL : ObsState.LIVE;
    case DataState.STALE:
      return ObsState.STALE;
    case DataState.EMPTY:
      return ObsState.NO_DATA;
    case DataState.OFFLINE:
      return ObsState.OFFLINE;
    case DataState.ERROR:
      // Distinguish transport/parse errors — client already sets Malformed JSON
      if (result.error && /malformed|invalid structure|json/i.test(String(result.error))) {
        return ObsState.DATA_ERROR;
      }
      return ObsState.PARTIAL;
    case DataState.UNAVAILABLE:
      return ObsState.NOT_AVAILABLE;
    case DataState.SNAPSHOT:
      return ObsState.SNAPSHOT;
    case DataState.LOADING:
      return ObsState.UNKNOWN;
    default:
      return ObsState.UNKNOWN;
  }
}

/**
 * Build a provenance descriptor from an existing API result + display counts.
 * Does not perform extra network I/O.
 */
export function buildProvenance({
  sourceKey,
  result,
  retrievedCount = null,
  displayedCount = null,
  totalReported = null,
  filterMode = FilterMode.NONE,
  historical = false,
  snapshot = false,
  joinability = Linkability.UNKNOWN,
  completeness = Completeness.UNKNOWN,
  limitations = [],
  timeRangeLabel = null,
} = {}) {
  const src = SOURCES[sourceKey] || {
    id: sourceKey || "unknown",
    label: sourceKey || "Unknown",
    path: "N/A",
    kind: DataKind.OBSERVED,
  };
  const state = obsStateFromApi(result, { historical, snapshot });
  return {
    source: src.label,
    sourcePath: src.path,
    sourceKey: src.id,
    dataKind: src.kind,
    dataState: state,
    fetchedAt: result?.fetchedAt ?? null,
    historical: !!historical,
    snapshot: !!snapshot || src.kind === DataKind.SNAPSHOT,
    joinability,
    completeness,
    filterMode,
    recordCount: displayedCount,
    retrievedCount,
    displayedCount,
    totalReported,
    timeRangeLabel,
    limitations: Array.isArray(limitations) ? limitations : [],
    httpStatus: result?.status ?? null,
    error: result?.error ?? null,
  };
}

export function countNote(prov) {
  const parts = [];
  if (prov.displayedCount != null && prov.retrievedCount != null) {
    parts.push(`Showing ${prov.displayedCount} of ${prov.retrievedCount} retrieved`);
  } else if (prov.displayedCount != null) {
    parts.push(`Displayed: ${prov.displayedCount}`);
  }
  if (prov.totalReported != null && prov.retrievedCount != null && prov.totalReported > prov.retrievedCount) {
    parts.push(`Backend total (if reported): ${prov.totalReported}; retrieved bound: ${prov.retrievedCount}`);
  }
  return parts.join(". ") || "Record counts: N/A";
}

/**
 * Tolerant structural validation — does not reject optional fields.
 * @returns {{ ok: boolean, reason?: string, shape: string }}
 */
export function validateListResponse(data, listKey) {
  if (data == null) {
    return { ok: false, reason: "Empty body", shape: "null" };
  }
  if (typeof data !== "object" || Array.isArray(data)) {
    return { ok: false, reason: "Expected object envelope", shape: Array.isArray(data) ? "array" : typeof data };
  }
  if (!(listKey in data)) {
    // Some endpoints nest differently — not necessarily fatal
    return { ok: true, reason: `Optional list key '${listKey}' absent`, shape: "object" };
  }
  if (!Array.isArray(data[listKey])) {
    return { ok: false, reason: `Expected array at '${listKey}'`, shape: typeof data[listKey] };
  }
  return { ok: true, shape: "object+array" };
}

/** Soft field normalization for presentation only (does not mutate security semantics). */
export function normalizeRecord(raw) {
  if (!raw || typeof raw !== "object") return null;
  const event_id =
    raw.event_id != null
      ? raw.event_id
      : raw.eventId != null
        ? raw.eventId
        : null;
  const timestamp =
    raw.timestamp != null
      ? raw.timestamp
      : raw.ts != null
        ? raw.ts
        : raw.created_at != null
          ? raw.created_at
          : null;
  const status = raw.status != null ? raw.status : raw.state != null ? raw.state : null;
  const severity = raw.severity != null ? raw.severity : null;
  return { ...raw, event_id, timestamp, status, severity };
}

export function normalizeList(records) {
  if (!Array.isArray(records)) return [];
  return records.map(normalizeRecord).filter(Boolean);
}

/** Dataset joinability from capability flags + sample of records. */
export function datasetJoinability({ capabilityEventId, records }) {
  if (capabilityEventId === false) return Linkability.NOT_AVAILABLE;
  if (capabilityEventId == null) return Linkability.UNKNOWN;
  const list = Array.isArray(records) ? records : [];
  if (!list.length) return Linkability.JOINABLE; // source supports IDs; empty is not NOT_JOINABLE
  let withId = 0;
  for (const r of list) {
    if (isValidEventId(r && r.event_id)) withId += 1;
  }
  if (withId === list.length) return Linkability.JOINABLE;
  if (withId === 0) return Linkability.PARTIAL;
  return Linkability.PARTIAL;
}

/** Compact SOC data-quality summary (static contract + live flags). */
export const QUALITY_SUMMARY = Object.freeze([
  {
    label: "R4/R6/R7/R5/R8 event linkage",
    value: "AVAILABLE",
    note: "Explicit event_id on JSONL surfaces",
  },
  {
    label: "Legacy detection linkage",
    value: "PARTIAL",
    note: "Legacy CSV may lack event_id",
  },
  {
    label: "Traffic event linkage",
    value: "NOT AVAILABLE",
    note: "No event_id on traffic points",
  },
  {
    label: "Health history",
    value: "NOT AVAILABLE",
    note: "Current /api/status only",
  },
  {
    label: "XAI weights",
    value: "NOT AVAILABLE",
    note: "Feature names (presence) only",
  },
  {
    label: "Topology",
    value: "AVAILABLE",
    note: "GET /api/topology — switches + learned hosts (no LLDP links)",
  },
]);

/** Escape-safe HTML for a fact row inside details. */
export function provenanceFactsHtml(prov) {
  const rows = [
    ["Source", prov.source],
    ["API", prov.sourcePath],
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
  return rows
    .map(
      ([k, v]) =>
        `<div class="prov-fact"><span class="k">${escapeHtml(k)}</span><span class="v">${escapeHtml(
          String(v)
        )}</span></div>`
    )
    .join("");
}
