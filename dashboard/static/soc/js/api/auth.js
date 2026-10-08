/**
 * Phase 8 — Authentication API client.
 *
 * Login/logout may POST to /api/auth/* (infrastructure only).
 * Never POSTs to operator command or mitigation endpoints.
 * Browser storage is NEVER used as proof of authentication.
 */

import { getJSON, DataState } from "./client.js";

/**
 * Fetch server-derived identity status (GET).
 * Unauthenticated → authenticated:false (HTTP 200).
 */
export async function fetchAuthMe(opts = {}) {
  return getJSON("/api/auth/me", opts);
}

/** Non-sensitive configuration status for Operator Readiness. */
export async function fetchAuthStatus(opts = {}) {
  return getJSON("/api/auth/status", opts);
}

/**
 * Authenticate. Server sets HttpOnly session cookie.
 * Does not persist credentials in browser storage.
 *
 * @param {{ username: string, password: string }} credentials
 */
export async function login(credentials) {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    credentials: "same-origin",
    body: JSON.stringify({
      username: credentials.username,
      password: credentials.password,
    }),
    cache: "no-store",
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  return {
    ok: res.ok,
    status: res.status,
    data,
    error: res.ok
      ? null
      : (data && data.error && data.error.message) || `HTTP ${res.status}`,
  };
}

/** Invalidate server session. Idempotent. */
export async function logout() {
  const res = await fetch("/api/auth/logout", {
    method: "POST",
    headers: { Accept: "application/json" },
    credentials: "same-origin",
    cache: "no-store",
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  return {
    ok: res.ok,
    status: res.status,
    data,
  };
}

export { DataState };
