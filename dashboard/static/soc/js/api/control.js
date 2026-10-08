/**
 * Lab Master Control API — real POST /api/control/* operations
 * (parity with legacy Master Control panel).
 * These are lab orchestration endpoints, not OpenFlow mitigation.
 */

import { getJSON } from "./client.js";

function optsOf(signal) {
  return signal ? { signal } : {};
}

export async function fetchControlStatus(signal) {
  return getJSON("/api/control/status", optsOf(signal));
}

export async function fetchControlJobs(signal) {
  return getJSON("/api/control/jobs", optsOf(signal));
}

export async function fetchControlJob(jobId, signal) {
  return getJSON(`/api/control/jobs/${encodeURIComponent(jobId)}`, optsOf(signal));
}

/**
 * @param {string} path e.g. "archive", "controller/restart", "scenario/2"
 * @param {object|null} body
 */
export async function postControl(path, body = null) {
  const opts = { method: "post".toUpperCase() };
  if (body != null) {
    opts.headers = { "Content-Type": "application/json" };
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(`/api/control/${path}`, opts);
  let data = {};
  try {
    data = await res.json();
  } catch {
    data = {};
  }
  if (!res.ok) {
    const detail = data.detail || res.statusText || `HTTP ${res.status}`;
    const err = new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

export function archiveLogs() {
  return postControl("archive");
}

export function restartController() {
  return postControl("controller/restart");
}

export function stopController() {
  return postControl("controller/stop");
}

export function runScenario(scenarioId) {
  return postControl(`scenario/${encodeURIComponent(String(scenarioId))}`);
}

export function runScenarioBatch(payload = {}) {
  return postControl("scenarios/batch", {
    scenario_ids: payload.scenario_ids || ["3", "4", "5"],
    archive_first: payload.archive_first !== false,
    restart_controller: payload.restart_controller !== false,
  });
}

export function computeMetrics() {
  return postControl("metrics");
}

export function trainModels() {
  return postControl("train");
}

export function bundleExperiment() {
  return postControl("bundle");
}
