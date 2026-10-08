/**
 * Phase 2 — centralized refresh manager (single timer, generation guards).
 * Prevents duplicate intervals and stale response overwrites.
 */

export class RefreshManager {
  /**
   * @param {{ intervalMs?: number }} [opts]
   */
  constructor(opts = {}) {
    this.intervalMs = Math.max(5000, opts.intervalMs ?? 8000);
    this._timer = null;
    this._generation = 0;
    this._running = false;
    this._tickHandler = null;
    this._paused = false;
  }

  /** Monotonic generation for race guards. */
  nextGeneration() {
    this._generation += 1;
    return this._generation;
  }

  get generation() {
    return this._generation;
  }

  isCurrent(gen) {
    return gen === this._generation;
  }

  /**
   * @param {(ctx: { generation: number, signal: AbortSignal }) => Promise<void>} handler
   */
  setHandler(handler) {
    this._tickHandler = handler;
  }

  start() {
    if (this._timer) return;
    this._timer = setInterval(() => this.tick(), this.intervalMs);
  }

  stop() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
    if (this._abort) {
      this._abort.abort();
      this._abort = null;
    }
    this._running = false;
  }

  pause() {
    this._paused = true;
  }

  resume() {
    this._paused = false;
  }

  async tick(force = false) {
    if (this._paused && !force) return;
    if (document.hidden && !force) return;
    if (this._running) return; // skip overlapping ticks
    if (!this._tickHandler) return;

    this._running = true;
    if (this._abort) this._abort.abort();
    this._abort = new AbortController();
    const generation = this.nextGeneration();
    const signal = this._abort.signal;

    try {
      await this._tickHandler({ generation, signal });
    } catch (err) {
      if (!(err && err.name === "AbortError")) {
        console.warn("[RefreshManager]", err);
      }
    } finally {
      if (this.isCurrent(generation)) {
        this._running = false;
      }
    }
  }
}

/** Routes that opt into soft polling (observer). */
export const POLLED_ROUTES = new Set([
  "dashboard",
  "traffic",
  "detection",
  "correlation",
  "fusion",
  "verification",
  "adaptive",
  "alerts",
  "health",
  "mitigation",
]);
