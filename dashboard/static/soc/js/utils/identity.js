/**
 * Phase 8/9 — Identity panel (presentation only).
 * Never treats browser state as authorization.
 * Never enables operator controls based on identity or roles.
 */

/**
 * @param {(s: string) => string} escapeHtml
 * @param {(s: string) => string} statusBadge
 * @param {{
 *   authenticated?: boolean,
 *   principal?: { id?: string, username?: string, roles?: string[] } | null,
 *   authentication_configured?: boolean,
 *   authorization_implemented?: boolean,
 *   rbac_enabled?: boolean,
 *   permissions?: string[],
 *   operator_controls_enabled?: boolean,
 * } | null} me
 * @param {{ authentication_configured?: boolean, authorization_implemented?: boolean } | null} [status]
 */
export function identityPanelHtml(escapeHtml, statusBadge, me, status) {
  const configured =
    (me && me.authentication_configured) ||
    (status && status.authentication_configured) ||
    false;
  const authenticated = !!(me && me.authenticated && me.principal);
  const rbac =
    (me && me.authorization_implemented) ||
    (status && status.authorization_implemented) ||
    false;
  const username =
    authenticated && me.principal
      ? me.principal.username || me.principal.id || "—"
      : "—";
  const roles =
    authenticated && me.principal && Array.isArray(me.principal.roles)
      ? me.principal.roles.join(", ") || "NOT ASSIGNED"
      : "—";

  return `
    <section class="panel identity-panel" aria-label="Identity">
      <h3>Identity</h3>
      <p class="muted">
        Server-derived identity only. Browser flags are not trusted for authorization.
      </p>
      <div class="op-ready-row">
        <span class="op-ready-label">Authentication</span>
        ${statusBadge(configured ? "CONFIGURED" : "NOT CONFIGURED")}
      </div>
      <div class="op-ready-row">
        <span class="op-ready-label">Identity</span>
        ${statusBadge(authenticated ? "AUTHENTICATED" : "NOT AUTHENTICATED")}
      </div>
      <div class="op-ready-row">
        <span class="op-ready-label">Principal</span>
        <span class="identity-value">${escapeHtml(String(username))}</span>
      </div>
      <div class="op-ready-row">
        <span class="op-ready-label">Role</span>
        <span class="identity-value">${escapeHtml(String(roles))}</span>
      </div>
      <div class="op-ready-row">
        <span class="op-ready-label">Authorization</span>
        ${statusBadge(rbac ? "RBAC ENABLED" : "NOT IMPLEMENTED")}
      </div>
      <div class="op-ready-row">
        <span class="op-ready-label">Operator controls</span>
        ${statusBadge("NOT ENABLED")}
      </div>
      <div class="identity-auth-form" data-identity-form>
        ${
          authenticated
            ? `<button type="button" class="btn-secondary" data-auth-logout>Sign out</button>`
            : configured
              ? `<label class="identity-field">Username
                   <input type="text" name="username" autocomplete="username" maxlength="128" />
                 </label>
                 <label class="identity-field">Password
                   <input type="password" name="password" autocomplete="current-password" maxlength="256" />
                 </label>
                 <button type="button" class="btn-secondary" data-auth-login>Sign in</button>
                 <p class="muted identity-hint">Identity only. Roles do not unlock Operator Mode controls.</p>`
              : `<p class="muted">Set <code>INTELLISHIELD_AUTH_*</code> environment variables to enable login.</p>`
        }
        <p class="identity-msg" data-auth-msg hidden></p>
      </div>
    </section>`;
}
