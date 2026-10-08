/**
 * Phase 11 — Command Center (durable preview/confirm infrastructure).
 * Backend persistence is authoritative. Execution remains DISABLED.
 */

import {
  pageHeader,
  dataTable,
  statusBadge,
  renderResult,
} from "../components/ui.js";
import { escapeHtml, na, shortTs } from "../utils/format.js";
import * as cmdApi from "../api/commands.js";

export async function renderCommands(root) {
  root.innerHTML = `
    ${pageHeader({
      title: "Command Center",
      subtitle: "Durable command infrastructure for validation and audit. Operational execution remains DISABLED.",
      badge: "EXECUTION DISABLED",
    })}
    <section class="panel advisory-banner" aria-label="Execution disabled notice">
      <strong>CONTROLLED DRY-RUN ONLY — NO MITIGATION / NETWORK MUTATION</strong>
      <p class="muted">
        Exactly one allowlisted operation is enabled: <code>COMMAND_DRY_RUN</code>.
        Mitigation DROP rules remain controller-only (R7). Lab orchestration writes are on
        <a href="#lab-control">Lab Control</a>, not this Command Center.
        Backend state is authoritative — nothing is stored in browser storage.
      </p>
    </section>
    <div class="settings-grid">
      <section class="panel">
        <h3>Dry-run preview</h3>
        <p class="muted">Requires authenticated ANALYST+ session (INVESTIGATE_EVENTS). Does not execute.</p>
        <div class="identity-auth-form">
          <label class="identity-field">Action
            <select name="action">
              <option value="COMMAND_DRY_RUN">COMMAND_DRY_RUN</option>
              <option value="READ">READ</option>
              <option value="BLOCK_TARGET">BLOCK_TARGET (expect deny / blocked)</option>
            </select>
          </label>
          <label class="identity-field">Target type
            <input type="text" name="target_type" value="EVENT" maxlength="64" />
          </label>
          <label class="identity-field">Target / Event ID
            <input type="text" name="target_id" value="evt-demo-1" maxlength="128" />
          </label>
          <label class="identity-field">Reason
            <input type="text" name="reason" value="Controlled dry-run validation" maxlength="500" />
          </label>
          <button type="button" class="btn-secondary" data-cmd-preview>Preview</button>
          <button type="button" class="btn-secondary" data-cmd-confirm hidden>Confirm</button>
          <button type="button" class="btn-secondary" data-cmd-execute hidden>Execute dry-run</button>
          <p class="identity-msg" data-cmd-msg hidden></p>
        </div>
      </section>
      <section class="panel">
        <h3>Last preview result</h3>
        <pre class="cmd-result" data-cmd-result>No preview yet.</pre>
      </section>
    </div>
    <div data-cmd-history></div>
  `;

  const msg = root.querySelector("[data-cmd-msg]");
  const resultEl = root.querySelector("[data-cmd-result]");
  const confirmBtn = root.querySelector("[data-cmd-confirm]");
  const executeBtn = root.querySelector("[data-cmd-execute]");
  let lastPreview = null;

  function showMsg(text, isError) {
    if (!msg) return;
    msg.hidden = !text;
    msg.textContent = text || "";
    msg.classList.toggle("identity-error", !!isError);
  }

  root.querySelector("[data-cmd-preview]")?.addEventListener("click", async () => {
    const action = root.querySelector('select[name="action"]')?.value || "COMMAND_DRY_RUN";
    const target_type = root.querySelector('input[name="target_type"]')?.value || "EVENT";
    const target_id = root.querySelector('input[name="target_id"]')?.value || "";
    const reason = root.querySelector('input[name="reason"]')?.value || "";
    showMsg("Submitting preview…", false);
    const res = await cmdApi.previewCommand({
      action,
      target_type: action === "READ" ? "NONE" : target_type,
      target_id: action === "READ" ? "none" : target_id,
      event_id: action === "READ" ? null : target_id,
      reason,
    });
    const payload = res.data?.command || res.data;
    lastPreview = payload;
    if (resultEl) {
      resultEl.textContent = JSON.stringify(payload, null, 2);
    }
    if (!res.ok && res.status === 401) {
      showMsg("Authentication required — sign in under Settings.", true);
      return;
    }
    if (!res.ok && res.status === 503) {
      showMsg(
        payload?.failure_reason || "Command store unavailable (persistence failed).",
        true
      );
      if (confirmBtn) confirmBtn.hidden = true;
      return;
    }
    if (!res.ok && res.status === 403) {
      showMsg("Forbidden — insufficient permission for this action.", true);
      if (confirmBtn) confirmBtn.hidden = true;
      return;
    }
    showMsg(
      `Status: ${payload?.status || "?"} · execution_enabled=${payload?.execution_enabled === true}`,
      false
    );
    if (confirmBtn) {
      confirmBtn.hidden = !(
        payload &&
        payload.status === "AWAITING_CONFIRMATION" &&
        payload.confirmation_token
      );
    }
    if (executeBtn) executeBtn.hidden = true;
    await refreshHistory();
  });

  confirmBtn?.addEventListener("click", async () => {
    if (!lastPreview?.command_id || !lastPreview?.confirmation_token) return;
    showMsg("Confirming…", false);
    const res = await cmdApi.confirmCommand(
      lastPreview.command_id,
      lastPreview.confirmation_token
    );
    const payload = res.data?.command || res.data;
    lastPreview = payload;
    if (resultEl) resultEl.textContent = JSON.stringify(payload, null, 2);
    if (res.status === 503) {
      showMsg(
        payload?.failure_reason || "Command store unavailable (persistence failed).",
        true
      );
      return;
    }
    showMsg(
      `Status: ${payload?.status || "?"} · executed=${payload?.executed === true}`,
      !res.ok
    );
    if (confirmBtn) confirmBtn.hidden = true;
    if (executeBtn) {
      executeBtn.hidden = !(
        payload &&
        payload.status === "READY_FOR_EXECUTION" &&
        payload.execution_enabled === true
      );
    }
    await refreshHistory();
  });

  executeBtn?.addEventListener("click", async () => {
    if (!lastPreview?.command_id) return;
    if (lastPreview.status !== "READY_FOR_EXECUTION") return;
    showMsg("Executing controlled dry-run…", false);
    executeBtn.hidden = true;
    const res = await cmdApi.executeCommand(lastPreview.command_id);
    const payload = res.data?.command || res.data;
    lastPreview = payload;
    if (resultEl) resultEl.textContent = JSON.stringify(payload, null, 2);
    if (!res.ok) {
      showMsg(
        payload?.failure_reason || `Execute failed (${res.status})`,
        true
      );
    } else {
      showMsg(
        `Status: ${payload?.status || "?"} · executed=${payload?.executed === true}`,
        false
      );
    }
    await refreshHistory();
  });

  async function refreshHistory() {
    const slot = root.querySelector("[data-cmd-history]");
    if (!slot) return;
    const hist = await cmdApi.fetchCommands(25);
    if (hist && hist.persistence_available === false) {
      slot.innerHTML =
        `<section class="panel"><p class="muted">Command store unavailable — history cannot be loaded.</p></section>`;
      return;
    }
    slot.innerHTML = renderResult(hist, {
      live: (data) => {
        const rows = (data.commands || [])
          .map(
            (c) => `<tr>
              <td>${escapeHtml(na(c.command_id))}</td>
              <td>${escapeHtml(na(c.action))}</td>
              <td>${escapeHtml(na(c.target && c.target.id))}</td>
              <td>${escapeHtml(na(c.event_id))}</td>
              <td>${escapeHtml(na(c.principal_username))}</td>
              <td>${statusBadge(c.status)}</td>
              <td>${escapeHtml(na(c.authorization && c.authorization.decision))}</td>
              <td>${escapeHtml(na(c.safety && c.safety.state))}</td>
              <td>${statusBadge("EXECUTION DISABLED")}</td>
              <td>${escapeHtml(shortTs(c.created_at))}</td>
              <td>${escapeHtml(shortTs(c.expires_at))}</td>
            </tr>`
          )
          .join("");
        return `
          <section class="panel">
            <h3>Command history</h3>
            <p class="muted">Durable. Read-only. Paginated. No execution.</p>
            ${dataTable(
              [
                "Command ID",
                "Action",
                "Target",
                "Event",
                "Requester",
                "Status",
                "AuthZ",
                "Safety",
                "Execution",
                "Created",
                "Expires",
              ],
              rows,
              "No commands yet"
            )}
          </section>`;
      },
      empty: () => `<section class="panel"><p class="muted">No commands (or not authorized to list).</p></section>`,
      error: () =>
        `<section class="panel"><p class="muted">Command history unavailable (sign in as ANALYST+).</p></section>`,
      offline: () =>
        `<section class="panel"><p class="muted">Backend unavailable.</p></section>`,
    });
  }

  await refreshHistory();
}
