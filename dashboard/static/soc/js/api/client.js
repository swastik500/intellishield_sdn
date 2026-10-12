/**
 * IntelliShield SOC — Phase 1/2 read-only HTTP client.
 * GET only. Never invents metrics. Surfaces LIVE / STALE / OFFLINE / ERROR / EMPTY.
 */

export const DataState = Object.freeze({
  LIVE: "LIVE",
  STALE: "STALE",
  OFFLINE: "OFFLINE",
  LAB: "LAB",
  SNAPSHOT: "SNAPSHOT",
  DEMO: "DEMO",
  LOADING: "LOADING",
  ERROR: "ERROR",
  EMPTY: "EMPTY",
  UNAVAILABLE: "UNAVAILABLE",
});

const DEFAULT_TIMEOUT_MS = 8000;
export const STALE_AFTER_MS = 60_000;

/**
 * @param {string} path
 * @param {{ timeoutMs?: number, signal?: AbortSignal }} [opts]
 */
export async function getJSON(path, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const onOuterAbort = () => controller.abort();
  if (opts.signal) {
    if (opts.signal.aborted) {
      clearTimeout(timer);
      return {
        state: DataState.OFFLINE,
        data: null,
        error: "Request aborted",
        fetchedAt: Date.now(),
        status: null,
        path,
      };
    }
    opts.signal.addEventListener("abort", onOuterAbort, { once: true });
  }

  const fetchedAt = Date.now();
  try {
    const res = await fetch(path, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: controller.signal,
      cache: "no-store",
    });
    clearTimeout(timer);
    if (opts.signal) opts.signal.removeEventListener("abort", onOuterAbort);

    if (!res.ok) {
      return {
        state: DataState.ERROR,
        data: null,
        error: `HTTP ${res.status}`,
        fetchedAt,
        status: res.status,
        path,
      };
    }

    let data;
    try {
      data = await res.json();
    } catch {
      return {
        state: DataState.ERROR,
        data: null,
        error: "Malformed JSON",
        fetchedAt,
        status: res.status,
        path,
      };
    }

    return {
      state: DataState.LIVE,
      data,
      error: null,
      fetchedAt,
      status: res.status,
      path,
    };
  } catch (err) {
    clearTimeout(timer);
    if (opts.signal) opts.signal.removeEventListener("abort", onOuterAbort);
    const aborted = err && err.name === "AbortError";
    return {
      state: DataState.OFFLINE,
      data: null,
      error: aborted ? "Request timeout" : "Backend unavailable",
      fetchedAt,
      status: null,
      path,
    };
  }
}

/**
 * POST JSON to a path with a timeout. Throws on non-2xx with a
 * parsed error (message / detail) attached. Same-origin requests
 * include cookies (session) by default.
 *
 * @param {string} path
 * @param {object|null} body
 * @param {{ timeoutMs?: number, signal?: AbortSignal }} [opts]
 * @returns {Promise<object>} parsed JSON body
 */
export async function postJSON(path, body = null, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const onOuterAbort = () => controller.abort();
  if (opts.signal) {
    if (opts.signal.aborted) {
      clearTimeout(timer);
      const err = new Error("Request aborted");
      err.name = "AbortError";
      throw err;
    }
    opts.signal.addEventListener("abort", onOuterAbort, { once: true });
  }

  const init = { method: "post".toUpperCase(), signal: controller.signal, cache: "no-store" };
  if (body != null) {
    init.headers = { "Content-Type": "application/json", Accept: "application/json" };
    init.body = JSON.stringify(body);
  } else {
    init.headers = { Accept: "application/json" };
  }

  try {
    const res = await fetch(path, init);
    clearTimeout(timer);
    if (opts.signal) opts.signal.removeEventListener("abort", onOuterAbort);

    let data = {};
    try {
      data = await res.json();
    } catch {
      data = {};
    }
    if (!res.ok) {
      const detail =
        (data && (data.detail || (data.error && data.error.message))) ||
        res.statusText ||
        `HTTP ${res.status}`;
      const err = new Error(
        typeof detail === "string" ? detail : JSON.stringify(detail)
      );
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  } catch (err) {
    clearTimeout(timer);
    if (opts.signal) opts.signal.removeEventListener("abort", onOuterAbort);
    if (err && err.name === "AbortError") {
      const e = new Error("Request timeout");
      e.name = "AbortError";
      throw e;
    }
    throw err;
  }
}

export function withEmpty(result, isEmpty) {
  if (result.state !== DataState.LIVE || result.data == null) return result;
  if (isEmpty(result.data)) {
    return { ...result, state: DataState.EMPTY };
  }
  return result;
}

export function maybeStale(previous, now = Date.now()) {
  if (!previous || !previous.fetchedAt) return previous;
  if (previous.state !== DataState.LIVE && previous.state !== DataState.EMPTY) {
    return previous;
  }
  if (now - previous.fetchedAt > STALE_AFTER_MS) {
    return { ...previous, state: DataState.STALE };
  }
  return previous;
}

export function ageLabel(fetchedAt, now = Date.now()) {
  if (!fetchedAt) return "N/A";
  const sec = Math.max(0, Math.round((now - fetchedAt) / 1000));
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ${sec % 60}s ago`;
  const hr = Math.floor(min / 60);
  return `${hr}h ${min % 60}m ago`;
}
