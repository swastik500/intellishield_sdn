/**
 * Phase 7–10 — Operator Mode readiness indicators (DISPLAY ONLY).
 */

export const OPERATOR_MODE_STATUS = Object.freeze({
  mode: "DESIGN ONLY",
  controlActions: "NOT ENABLED",
  authentication: "PHASE 8 FOUNDATION",
  authorization: "PHASE 9 RBAC",
  commandApi: "PHASE 12 CONTROLLED DRY-RUN ONLY",
  auditTrail: "PHASE 11 DURABLE APPEND-ONLY",
  confirmation: "PHASE 11 TRANSACTIONAL",
  idempotency: "PHASE 11 DURABLE",
  failClosedPolicy: "DEFINED",
  documentation: "dashboard/static/soc/CONTROLLED_OPERATION_ARCHITECTURE.md",
});
/**
 * @param {{
 *   authentication_configured?: boolean,
 *   authenticated?: boolean,
 *   authorization_implemented?: boolean,
 *   rbac_enabled?: boolean,
 * } | null} [auth]
 */
export function buildOperatorReadinessRows(auth) {
  const configured = !!(auth && auth.authentication_configured);
  const authenticated = !!(auth && auth.authenticated);
  const rbac = !!(
    auth &&
    (auth.authorization_implemented || auth.rbac_enabled)
  );
  return Object.freeze([
    { label: "Operator Mode", value: "DESIGN ONLY" },
    { label: "Authentication", value: configured ? "READY" : "NOT CONFIGURED" },
    {
      label: "Current Identity",
      value: authenticated ? "AUTHENTICATED" : "NOT AUTHENTICATED",
    },
    { label: "RBAC", value: rbac ? "READY" : "NOT IMPLEMENTED" },
    { label: "Authorization", value: rbac ? "READY" : "NOT IMPLEMENTED" },
    { label: "Command Infrastructure", value: "READY" },
    { label: "Safety Gate", value: "READY" },
    { label: "Confirmation", value: "READY" },
    { label: "Audit", value: "DURABLE" },
    { label: "Idempotency", value: "DURABLE" },
    { label: "Command API", value: "READY" },
    { label: "Persistence", value: "READY" },
    { label: "Controlled Execution", value: "DRY-RUN ONLY" },
    { label: "Execution", value: "ALLOWLISTED ONLY" },
    { label: "Fail-Closed Policy", value: "DEFINED" },
    { label: "Control Actions", value: "NOT ENABLED" },
    { label: "Mitigation", value: "NOT ENABLED" },
  ]);
}
export const OPERATOR_READINESS_ROWS = buildOperatorReadinessRows(null);

export function operatorReadinessHtml(escapeHtml, statusBadge, auth) {
  const rows = buildOperatorReadinessRows(auth || null)
    .map(
      (r) => `<div class="op-ready-row">
      <span class="op-ready-label">${escapeHtml(r.label)}</span>
      ${statusBadge(r.value)}
    </div>`
    )
    .join("");
  return `
    <section class="panel operator-readiness" aria-label="Operator readiness">
      <h3>Operator Readiness</h3>
      <p class="muted">
        Command/safety/audit infrastructure is present. The SOC remains an <strong>observer</strong>
        for operational execution.
      </p>
      ${rows}
      <p class="muted op-ready-doc">
        See <code>${escapeHtml(OPERATOR_MODE_STATUS.documentation)}</code>
      </p>
      <p class="advisory">
        Execution remains DISABLED. No Block / Unblock / Mitigate controls.
      </p>
    </section>`;
}
