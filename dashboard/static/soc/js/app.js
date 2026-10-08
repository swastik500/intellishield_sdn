/**
 * IntelliShield DDoS Dashboard shell.
 * Hash routes: #page or #investigation/<eventId>
 * Legacy Master Control parity lives under #lab-control.
 */

import * as pages from "./pages/index.js";
import * as investigationPages from "./pages/investigation.js";
import { renderLabControl, destroyLabControl } from "./pages/lab_control.js";
import { RefreshManager, POLLED_ROUTES } from "./utils/refresh.js";
import { destroyPageCharts } from "./pages/index.js";

const ROUTES = {
  dashboard: { title: "Dashboard", render: pages.renderDashboard },
  traffic: { title: "Traffic Monitor", render: pages.renderTraffic },
  topology: { title: "Network Topology", render: pages.renderTopology },
  detection: { title: "Detection Intelligence", render: pages.renderDetection },
  fusion: { title: "Collaborative Fusion", render: pages.renderFusion },
  verification: { title: "Verification", render: pages.renderVerification },
  correlation: { title: "Cross-Layer Correlation", render: pages.renderCorrelation },
  adaptive: { title: "Adaptive RL / Drift", render: pages.renderAdaptive },
  automl: { title: "Online AutoML", render: pages.renderAutoML },
  mitigation: { title: "Mitigation Status", render: pages.renderMitigation },
  alerts: { title: "Security Alerts", render: pages.renderAlerts },
  events: { title: "Security Events", render: investigationPages.renderEvents },
  rca: { title: "Root Cause / XAI", render: pages.renderRca },
  twin: { title: "Digital Twin", render: pages.renderTwin },
  "lab-control": { title: "Lab Control", render: renderLabControl },
  "attack-lab": { title: "Lab Control", render: renderLabControl }, // alias → Lab Control
  reports: { title: "Security Reports", render: pages.renderReports },
  health: { title: "System Health", render: pages.renderHealth },
  settings: { title: "Settings", render: pages.renderSettings },
  commands: { title: "Command Center", render: pages.renderCommands },
};

const refresh = new RefreshManager({ intervalMs: 8000 });
let current = null;

/**
 * @returns {{ name: string, eventId?: string }}
 */
export function parseHash() {
  const raw = (location.hash || "#dashboard").replace(/^#/, "");
  if (raw.startsWith("investigation/") || raw === "investigation") {
    const parts = raw.split("/");
    const eventId = parts.slice(1).map(decodeURIComponent).join("/").trim();
    return { name: "investigation", eventId };
  }
  let name = raw.split("/")[0];
  if (name === "attack-lab") name = "lab-control";
  return { name: ROUTES[name] ? name : "dashboard" };
}

function setActiveNav(routeName) {
  document.querySelectorAll(".nav-item").forEach((el) => {
    const href = el.getAttribute("href") || "";
    const active =
      href === `#${routeName}` ||
      (routeName === "lab-control" && href === "#lab-control") ||
      (routeName === "investigation" && href === "#events");
    el.classList.toggle("active", active);
  });
  const pill = document.getElementById("mode-pill");
  if (pill) {
    pill.textContent =
      routeName === "lab-control"
        ? "LAB CONTROL · WRITE"
        : routeName === "commands"
          ? "COMMAND CENTER · SAFE"
          : routeName === "automl"
            ? "ONLINE AUTOML · OPERATIONAL"
            : "DDoS DASHBOARD";
  }
}

async function navigate({ soft = false } = {}) {
  const parsed = parseHash();
  const routeName = parsed.name;
  const routeChanged =
    current !== routeName &&
    !(current === "investigation" && routeName === "investigation");
  const prevEvent = window.__SOC_EVENT_ID__;
  if (routeName === "investigation" && parsed.eventId !== prevEvent) {
    soft = false;
  }
  window.__SOC_EVENT_ID__ = parsed.eventId || null;

  if (current === "lab-control" && routeName !== "lab-control") {
    destroyLabControl();
  }
  current = routeName;
  setActiveNav(routeName);

  const root = document.getElementById("page-root");
  const crumb = document.getElementById("topbar-title");
  const title =
    routeName === "investigation"
      ? "Investigation"
      : ROUTES[routeName]?.title || "Dashboard";
  if (crumb) crumb.textContent = title;
  document.title = `IntelliShield DDoS Dashboard — ${title}`;

  if (routeChanged || !soft) {
    destroyPageCharts();
    soft = false;
  }

  root.setAttribute("aria-busy", "true");
  const generation = refresh.generation;
  try {
    if (routeName === "investigation") {
      await investigationPages.renderInvestigation(root, {
        soft,
        eventId: parsed.eventId,
        signal: undefined,
        generation,
        isCurrent: (g) => {
          const p = parseHash();
          return (
            refresh.isCurrent(g) &&
            p.name === "investigation" &&
            p.eventId === parsed.eventId
          );
        },
      });
    } else {
      const def = ROUTES[routeName];
      await def.render(root, {
        soft,
        signal: undefined,
        generation,
        isCurrent: (g) => refresh.isCurrent(g) && parseHash().name === routeName,
      });
    }
  } catch (err) {
    if (!soft) {
      root.innerHTML = `
        <div class="state-panel state-error">
          <strong>Page failed to load</strong>
          <p>${String(err && err.message ? err.message : err)}</p>
        </div>`;
    }
  } finally {
    root.removeAttribute("aria-busy");
  }
}

refresh.setHandler(async ({ generation, signal }) => {
  const parsed = parseHash();
  // Historical investigation: load once via navigate; do not aggressive-poll
  if (parsed.name === "investigation") return;
  if (parsed.name === "lab-control") return; // avoid resetting lab job UI on poll
  if (!POLLED_ROUTES.has(parsed.name) && parsed.name !== "events") return;

  const root = document.getElementById("page-root");
  try {
    if (parsed.name === "events") {
      await investigationPages.renderEvents(root, {
        soft: true,
        signal,
        generation,
        isCurrent: (g) => refresh.isCurrent(g) && parseHash().name === "events",
      });
      return;
    }
    const def = ROUTES[parsed.name];
    await def.render(root, {
      soft: true,
      signal,
      generation,
      isCurrent: (g) => refresh.isCurrent(g) && parseHash().name === parsed.name,
    });
  } catch (err) {
    if (!(err && err.name === "AbortError")) {
      console.warn("[poll]", err);
    }
  }
});

function bindShell() {
  const toggle = document.getElementById("sidebar-toggle");
  const sidebar = document.getElementById("sidebar");
  if (toggle && sidebar) {
    toggle.addEventListener("click", () => sidebar.classList.toggle("open"));
  }
  window.addEventListener("hashchange", () => navigate({ soft: false }));
  document.getElementById("refresh-btn")?.addEventListener("click", () => {
    const parsed = parseHash();
    if (parsed.name === "investigation" || parsed.name === "lab-control") {
      navigate({ soft: false });
    } else {
      refresh.tick(true);
    }
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) refresh.pause();
    else refresh.resume();
  });
}

bindShell();
navigate({ soft: false });
refresh.start();

window.__INTELLISHIELD_DDOS_DASHBOARD__ = {
  refresh,
  routes: Object.keys(ROUTES).concat(["investigation"]),
  polled: [...POLLED_ROUTES],
  parseHash,
};
// Back-compat alias for any debug hooks
window.__INTELLISHIELD_SOC__ = window.__INTELLISHIELD_DDOS_DASHBOARD__;
