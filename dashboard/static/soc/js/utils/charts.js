/**
 * Phase 2 Chart.js helpers — create/update/destroy without duplicates.
 * Chart.js must be loaded globally as window.Chart (CDN).
 * Never invents data. Empty arrays → empty chart.
 */

const registry = new Map();

function chartAvailable() {
  return typeof window !== "undefined" && typeof window.Chart === "function";
}

export function destroyChart(key) {
  const existing = registry.get(key);
  if (existing) {
    try {
      existing.destroy();
    } catch {
      /* ignore */
    }
    registry.delete(key);
  }
}

export function destroyAllCharts(prefix = "") {
  for (const key of [...registry.keys()]) {
    if (!prefix || key.startsWith(prefix)) destroyChart(key);
  }
}

/**
 * Upsert a line/bar chart on a canvas.
 * @param {string} key unique id
 * @param {HTMLCanvasElement|null} canvas
 * @param {object} config Chart.js config (type, data, options)
 */
export function upsertChart(key, canvas, config) {
  if (!canvas || !chartAvailable()) return null;

  const existing = registry.get(key);
  if (existing) {
    // Update datasets in place
    try {
      existing.data.labels = config.data.labels || [];
      existing.data.datasets = config.data.datasets || [];
      if (config.options) {
        existing.options = { ...existing.options, ...config.options };
      }
      existing.update("none");
      return existing;
    } catch {
      destroyChart(key);
    }
  }

  const chart = new window.Chart(canvas.getContext("2d"), config);
  registry.set(key, chart);
  return chart;
}

export function shortLabel(ts) {
  if (!ts) return "";
  const s = String(ts);
  if (s.includes("T")) return s.replace("T", " ").slice(11, 19);
  if (s.length >= 19) return s.slice(11, 19);
  return s.slice(-8);
}

const baseOptions = {
  responsive: true,
  maintainAspectRatio: false,
  animation: false,
  plugins: {
    legend: {
      labels: { color: "#8ea0b8", boxWidth: 12, font: { size: 11 } },
    },
    tooltip: {
      mode: "index",
      intersect: false,
    },
  },
  scales: {
    x: {
      ticks: { color: "#8ea0b8", maxRotation: 0, autoSkip: true, maxTicksLimit: 8 },
      grid: { color: "rgba(148,163,184,0.08)" },
    },
    y: {
      ticks: { color: "#8ea0b8" },
      grid: { color: "rgba(148,163,184,0.08)" },
      beginAtZero: true,
    },
  },
};

export function lineChartConfig({ labels, datasets, ySuggestedMax }) {
  const opts = structuredClone
    ? structuredClone(baseOptions)
    : JSON.parse(JSON.stringify(baseOptions));
  if (ySuggestedMax != null) {
    opts.scales.y.suggestedMax = ySuggestedMax;
  }
  return {
    type: "line",
    data: { labels, datasets },
    options: opts,
  };
}

export function barChartConfig({ labels, datasets }) {
  const opts = structuredClone
    ? structuredClone(baseOptions)
    : JSON.parse(JSON.stringify(baseOptions));
  return {
    type: "bar",
    data: { labels, datasets },
    options: opts,
  };
}

/** Limit points for performance — keep newest N. */
export function limitPoints(arr, n = 60) {
  if (!Array.isArray(arr)) return [];
  if (arr.length <= n) return arr;
  return arr.slice(arr.length - n);
}

export function chartShell(canvasId, ariaLabel) {
  return `
    <div class="chart-panel">
      <canvas id="${canvasId}" role="img" aria-label="${ariaLabel}"></canvas>
      <p class="chart-fallback muted" hidden>Chart library unavailable — table data still shown below.</p>
    </div>`;
}

export function markChartUnavailable(root) {
  if (!chartAvailable()) {
    root?.querySelectorAll(".chart-fallback").forEach((el) => {
      el.hidden = false;
    });
  }
}
