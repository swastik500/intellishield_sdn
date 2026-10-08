/**
 * Phase 12 — Command Center API (preview/confirm/execute).
 * Backend is authoritative. Only allowlisted COMMAND_DRY_RUN may execute.
 * Never calls mitigation, controllers, flow installs, or lab control writes.
 */

import { getJSON } from "./client.js";

export async function fetchCommands(limit = 50, opts = {}) {
  return getJSON(`/api/operator/commands?limit=${encodeURIComponent(limit)}`, opts);
}

export async function fetchCommand(commandId, opts = {}) {
  return getJSON(`/api/operator/commands/${encodeURIComponent(commandId)}`, opts);
}

export async function fetchAudits(limit = 50, opts = {}) {
  return getJSON(`/api/operator/audits?limit=${encodeURIComponent(limit)}`, opts);
}

/**
 * Preview — does not execute.
 * @param {object} payload
 */
export async function previewCommand(payload) {
  const res = await fetch("/api/operator/commands/preview", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    credentials: "same-origin",
    body: JSON.stringify(payload),
    cache: "no-store",
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  return { ok: res.ok, status: res.status, data };
}

/**
 * Confirm — READY_FOR_EXECUTION (allowlisted) or EXECUTION_DISABLED.
 */
export async function confirmCommand(commandId, confirmationToken) {
  const res = await fetch(
    `/api/operator/commands/${encodeURIComponent(commandId)}/confirm`,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      credentials: "same-origin",
      body: JSON.stringify({ confirmation_token: confirmationToken }),
      cache: "no-store",
    }
  );
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  return { ok: res.ok, status: res.status, data };
}

/**
 * Phase 12 controlled execute — allowlisted COMMAND_DRY_RUN only.
 */
export async function executeCommand(commandId) {
  const res = await fetch(
    `/api/operator/commands/${encodeURIComponent(commandId)}/execute`,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      credentials: "same-origin",
      body: "{}",
      cache: "no-store",
    }
  );
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  return { ok: res.ok, status: res.status, data };
}
