/** Shared format / display helpers — no invented metrics. */

export function na(value, fallback = "N/A") {
  if (value === null || value === undefined || value === "") return fallback;
  return value;
}

export function fmtNum(value, digits = 2) {
  if (value === null || value === undefined || value === "") return "N/A";
  const n = Number(value);
  if (!Number.isFinite(n)) return "N/A";
  return n.toLocaleString(undefined, {
    maximumFractionDigits: digits,
    minimumFractionDigits: 0,
  });
}

export function fmtPct(value) {
  if (value === null || value === undefined || value === "") return "N/A";
  const n = Number(value);
  if (!Number.isFinite(n)) return "N/A";
  // Backend may use 0–1 or 0–100
  const pct = n <= 1 ? n * 100 : n;
  return `${pct.toFixed(1)}%`;
}

export function shortTs(value) {
  if (!value) return "N/A";
  const s = String(value);
  // Prefer time portion for dense tables
  if (s.includes("T")) {
    return s.replace("T", " ").replace("Z", "").slice(0, 19);
  }
  if (s.length >= 19) return s.slice(0, 19);
  return s;
}

export function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function healthFromBool(active) {
  if (active === true) return "HEALTHY";
  if (active === false) return "NO DATA";
  return "OFFLINE";
}

export function pipelineStageStatus(result) {
  if (!result) return "OFFLINE";
  switch (result.state) {
    case "LIVE":
      return "ACTIVE";
    case "EMPTY":
      return "NO DATA";
    case "STALE":
      return "DEGRADED";
    case "ERROR":
      return "DEGRADED";
    case "UNAVAILABLE":
      return "NO DATA";
    case "OFFLINE":
      return "OFFLINE";
    case "LOADING":
      return "ACTIVE";
    case "SNAPSHOT":
      return "ACTIVE";
    default:
      return "NO DATA";
  }
}
