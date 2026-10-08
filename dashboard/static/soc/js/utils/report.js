/**
 * Phase 5 — Historical report helpers (presentation/aggregation only).
 * Uses backend record timestamps. No invented metrics or heuristic joins.
 */

import { redactDiagnostics } from "./health.js";

export const REPORT_LIMIT = 200;
export const TRAFFIC_LIMIT = 200;
export const CHART_POINT_LIMIT = 80;

export const TIME_RANGES = Object.freeze({
  "1h": { label: "Last 1 hour", ms: 60 * 60 * 1000 },
  "6h": { label: "Last 6 hours", ms: 6 * 60 * 60 * 1000 },
  "24h": { label: "Last 24 hours", ms: 24 * 60 * 60 * 1000 },
  "7d": { label: "Last 7 days", ms: 7 * 24 * 60 * 60 * 1000 },
  all: { label: "All retrieved (bounded)", ms: null },
  custom: { label: "Custom range", ms: null },
});

/** Parse backend timestamp strings; returns epoch ms or null. Does not invent time. */
export function parseTs(value) {
  if (value == null || value === "") return null;
  if (typeof value === "number" && Number.isFinite(value)) {
    return value < 1e12 ? value * 1000 : value;
  }
  const s = String(value).trim();
  if (!s) return null;
  // Prefer ISO / "YYYY-MM-DD HH:MM:SS"
  const normalized = s.includes("T") ? s : s.replace(" ", "T");
  const ms = Date.parse(normalized);
  if (Number.isFinite(ms)) return ms;
  const ms2 = Date.parse(s);
  return Number.isFinite(ms2) ? ms2 : null;
}

export function inRange(tsMs, fromMs, toMs) {
  if (tsMs == null) return false;
  if (fromMs != null && tsMs < fromMs) return false;
  if (toMs != null && tsMs > toMs) return false;
  return true;
}

/**
 * Filter records by timestamp field using client-side range.
 * Records without parseable timestamps are excluded from ranged views
 * (not counted as zero activity).
 */
export function filterByTime(records, tsField, fromMs, toMs) {
  const list = Array.isArray(records) ? records : [];
  if (fromMs == null && toMs == null) return list.slice();
  return list.filter((r) => inRange(parseTs(r && r[tsField]), fromMs, toMs));
}

export function countBy(records, field) {
  const out = {};
  for (const r of records || []) {
    const k = String((r && r[field]) != null && (r && r[field]) !== "" ? r[field] : "UNKNOWN");
    out[k] = (out[k] || 0) + 1;
  }
  return out;
}

/** Bucket counts by time for charts. Uses backend timestamps only. */
export function bucketByTime(records, tsField, bucketMs = 60 * 60 * 1000) {
  const map = new Map();
  for (const r of records || []) {
    const ms = parseTs(r && r[tsField]);
    if (ms == null) continue;
    const key = Math.floor(ms / bucketMs) * bucketMs;
    map.set(key, (map.get(key) || 0) + 1);
  }
  const keys = [...map.keys()].sort((a, b) => a - b);
  return {
    labels: keys.map((k) => new Date(k).toISOString().slice(0, 16).replace("T", " ")),
    counts: keys.map((k) => map.get(k)),
    bucketMs,
  };
}

export function resolveRange(rangeKey, customFrom, customTo, nowMs = Date.now()) {
  const def = TIME_RANGES[rangeKey] || TIME_RANGES["24h"];
  if (rangeKey === "custom") {
    const fromMs = parseTs(customFrom);
    const toMs = parseTs(customTo) ?? nowMs;
    return {
      key: "custom",
      label: def.label,
      fromMs,
      toMs,
      note:
        fromMs == null
          ? "Custom from-time could not be parsed; showing all retrieved records."
          : "Custom range applied client-side to records with parseable timestamps.",
    };
  }
  if (rangeKey === "all" || def.ms == null) {
    return {
      key: "all",
      label: def.label,
      fromMs: null,
      toMs: null,
      note: "No client time filter. Showing all records returned by bounded GET.",
    };
  }
  return {
    key: rangeKey,
    label: def.label,
    fromMs: nowMs - def.ms,
    toMs: nowMs,
    note:
      "Time window uses browser clock only to select records whose backend timestamps fall in range. Record timestamps are not modified.",
  };
}

/** Data availability matrix — static audit of known GET capabilities. */
export const DATA_AVAILABILITY = Object.freeze([
  {
    id: "traffic",
    name: "Traffic history",
    available: true,
    timestamp: true,
    eventId: false,
    timeFilterApi: false,
    filterLabel: "Client",
    completeness: "BOUNDED",
    dataKind: "OBSERVED",
    source: "GET /api/traffic?n=",
    note: "Bounded CSV tail; client-side time filter only.",
  },
  {
    id: "entropy",
    name: "Entropy history",
    available: true,
    timestamp: true,
    eventId: false,
    timeFilterApi: false,
    filterLabel: "Client",
    completeness: "BOUNDED",
    dataKind: "OBSERVED",
    source: "GET /api/entropy?n=",
    note: "Bounded CSV tail; threshold not exposed.",
  },
  {
    id: "detection",
    name: "Detection history",
    available: true,
    timestamp: true,
    eventId: false,
    timeFilterApi: false,
    filterLabel: "Client",
    completeness: "PARTIAL",
    dataKind: "OBSERVED",
    source: "GET /api/alerts?n=",
    note: "Legacy detection_alerts.csv; not event_id-keyed.",
  },
  {
    id: "r4",
    name: "R4 history",
    available: true,
    timestamp: true,
    eventId: true,
    timeFilterApi: false,
    filterLabel: "Client",
    completeness: "BOUNDED",
    dataKind: "ADVISORY",
    source: "GET /api/correlation-results",
    note: "ADVISORY. Limit + optional event_id; client time filter.",
  },
  {
    id: "r6",
    name: "R6 history",
    available: true,
    timestamp: true,
    eventId: true,
    timeFilterApi: false,
    filterLabel: "Client",
    completeness: "BOUNDED",
    dataKind: "BACKEND DECISION",
    source: "GET /api/fused-decisions",
    note: "Limit + optional event_id; client time filter.",
  },
  {
    id: "r7",
    name: "R7 history",
    available: true,
    timestamp: true,
    eventId: true,
    timeFilterApi: false,
    filterLabel: "Client",
    completeness: "BOUNDED",
    dataKind: "BACKEND DECISION",
    source: "GET /api/verification-traces",
    note: "Limit + event_id/status filters; client time filter.",
  },
  {
    id: "r5",
    name: "RCA history",
    available: true,
    timestamp: true,
    eventId: true,
    timeFilterApi: false,
    filterLabel: "Client",
    completeness: "BOUNDED",
    dataKind: "ANALYTICAL",
    source: "GET /api/root-cause-reports",
    note: "Limit + optional event_id; client time filter.",
  },
  {
    id: "r8",
    name: "R8 alert history",
    available: true,
    timestamp: true,
    eventId: true,
    timeFilterApi: true,
    filterLabel: "Server",
    completeness: "COMPLETE",
    dataKind: "ALERT",
    source: "GET /api/security-alerts (since/until)",
    note: "Backend supports since/until + severity/type within retrieved window.",
  },
  {
    id: "health",
    name: "Health history",
    available: false,
    timestamp: false,
    eventId: false,
    timeFilterApi: false,
    filterLabel: "N/A",
    completeness: "NOT_AVAILABLE",
    dataKind: "OBSERVED",
    source: "N/A",
    note: "No health time-series API. Current status only.",
  },
  {
    id: "topology",
    name: "Topology history",
    available: false,
    timestamp: false,
    eventId: false,
    timeFilterApi: false,
    filterLabel: "N/A",
    completeness: "NOT_AVAILABLE",
    dataKind: "OBSERVED",
    source: "N/A",
    note: "GET /api/topology — switches + learned hosts.",
  },
  {
    id: "xai",
    name: "XAI contribution weights",
    available: false,
    timestamp: false,
    eventId: false,
    timeFilterApi: false,
    filterLabel: "N/A",
    completeness: "NOT_AVAILABLE",
    dataKind: "ANALYTICAL",
    source: "RCA decision_evidence (names only)",
    note: "Feature presence may appear in RCA; weights not exposed.",
  },
  {
    id: "twin",
    name: "Digital Twin history",
    available: true,
    timestamp: true,
    eventId: false,
    timeFilterApi: false,
    filterLabel: "Client",
    completeness: "BOUNDED",
    dataKind: "SNAPSHOT",
    source: "GET /api/digital-twin/*",
    note: "SNAPSHOT · OBSERVATIONAL — not production attack history.",
  },
]);

export function sectionState(result, filteredCount, hadRaw) {
  if (!result) return "NOT AVAILABLE";
  if (result.state === "OFFLINE") return "OFFLINE";
  if (result.state === "ERROR") return "PARTIAL";
  if (result.state === "UNAVAILABLE") return "NOT AVAILABLE";
  if (result.state === "EMPTY" || (hadRaw && filteredCount === 0 && result.state !== "LIVE" && result.state !== "STALE")) {
    return filteredCount === 0 ? "NO DATA" : "HISTORICAL";
  }
  if (result.state === "STALE") return "STALE";
  if (filteredCount === 0) return "NO DATA";
  return "HISTORICAL";
}

export function extractFeatureNames(reports) {
  const names = new Set();
  for (const r of reports || []) {
    const feats = r.decision_evidence || r.features || r.xai_features;
    if (Array.isArray(feats)) {
      for (const f of feats) {
        if (typeof f === "string" && f.trim()) names.add(f.trim());
        else if (f && typeof f === "object" && f.name) names.add(String(f.name));
      }
    }
  }
  return [...names].sort();
}

export function safeExportPayload(report) {
  return redactDiagnostics(report);
}

export function toCsv(rows, headers) {
  const esc = (v) => {
    const s = v == null ? "" : String(v);
    if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
    return s;
  };
  const lines = [headers.join(",")];
  for (const row of rows) {
    lines.push(headers.map((h) => esc(row[h])).join(","));
  }
  return lines.join("\n");
}

export function downloadBlob(filename, text, mime) {
  const blob = new Blob([text], { type: mime || "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
