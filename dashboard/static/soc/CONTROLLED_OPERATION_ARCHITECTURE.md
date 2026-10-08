# Controlled Operation Architecture — Phase 12

**Status:** PARTIAL (execution boundary COMPLETE; real security-impacting ops BLOCKED)  
**Phase 12 is the first controlled operational execution phase.**  
**R7-gated operational mitigation (Phase 13) is BLOCKED — see `R7_GATED_OPERATIONAL_MITIGATION.md`.**

---

## Selected controlled operation

| Field | Value |
|-------|--------|
| **Operation** | `COMMAND_DRY_RUN` |
| **Target** | `EVENT` (`event_id`) |
| **Risk** | MEDIUM |
| **Reversibility** | Yes (no side effects — pure controlled no-op) |
| **Permission** | `INVESTIGATE_EVENTS` (ANALYST+) |
| **Timeout** | 5 seconds |
| **Mutates network?** | **No** |
| **Mutates security state?** | **No** |

### Why this operation

Inspection found **no safe existing mutating backend** suitable for Phase 12:

- Mitigation / block / unblock → OpenFlow / blocklist (HIGH) — rejected
- `/api/control/*` lab POSTs — must stay disconnected — rejected
- `ACKNOWLEDGE_ALERT` — registry entry only; **no ack backend** — would invent writes

Per Phase 12 §4, when no genuine low-risk operational backend exists, the phase implements the **execution boundary + safe dry-run adapter** and reports that real mutation is blocked.

`COMMAND_DRY_RUN` was already in the Phase 10 registry with grantable `INVESTIGATE_EVENTS`. It is the sole Phase 12 allowlisted executable action.

---

## Architecture

```
Auth → RBAC → Preview → Validate → Safety → Confirm
  → READY_FOR_EXECUTION → Final safety re-check
  → EXECUTING → ControlledExecutor (allowlist)
  → COMMAND_DRY_RUN adapter (no-op)
  → EXECUTED + durable audit/execution record
```

Unknown / non-allowlisted actions fail closed (`ExecutionDisabledError` / `EXECUTION_DISABLED`).

---

## Action registry

Server-controlled in `dashboard/commands/actions.py`.

- `execution_enabled=True` **only** for `COMMAND_DRY_RUN`
- `PHASE12_ALLOWLIST = {COMMAND_DRY_RUN}`
- Handlers mapped in `executor.py` — never from frontend input
- No `eval` / `exec` / subprocess / dynamic imports from client data

---

## Lifecycle (Phase 12 allowlisted)

```
… → AWAITING_CONFIRMATION → CONFIRMED → READY_FOR_EXECUTION
  → EXECUTING → EXECUTED | FAILED
```

Non-allowlisted actions still terminate at `EXECUTION_DISABLED` after confirm.

---

## Final pre-execution checks

On `POST /api/operator/commands/{id}/execute`:

1. Authenticated principal  
2. Principal matches command owner  
3. Command exists (durable store)  
4. State == `READY_FOR_EXECUTION`  
5. Not expired  
6. Action allowlisted + `execution_enabled`  
7. Re-authorize required permission  
8. Freshness / safety gate re-check  
9. Optimistic version / IMMEDIATE transaction claim → `EXECUTING`  
10. Idempotent if already `EXECUTED` / `EXECUTING`

---

## API

| Method | Path | Notes |
|--------|------|-------|
| POST | `/api/operator/commands/preview` | unchanged |
| POST | `/api/operator/commands/{id}/confirm` | allowlisted → READY |
| POST | `/api/operator/commands/{id}/execute` | **Phase 12 — allowlisted only** |
| GET | `/api/operator/commands` | paginated |
| GET | `/api/operator/commands/{id}` | |
| GET | `/api/operator/audits` | |

**Absent:** generic execute-anything, mitigate, block, isolate, controller/OpenFlow endpoints in operator API.

---

## Persistence

Schema v2 adds:

- `operator_commands.execution_json`, `execution_id`, `executed_at`
- `operator_executions` append-oriented execution records

SQLite WAL + `BEGIN IMMEDIATE` + optimistic `version` (Phase 11) remain authoritative.

---

## Idempotency & concurrency

- Duplicate `/execute` after `EXECUTED` → same result + `duplicate: true`
- Concurrent `/execute` → one winner `EXECUTED`; other `duplicate` / in-progress

---

## Audit

Append-only audits for confirm, ready, executing, executed/failed, rejections.

---

## Frontend

Command Center shows Preview → Confirm → **Execute dry-run** when `READY_FOR_EXECUTION`.

Backend remains authoritative. No localStorage command authority. No fabricated success.

---

## Security boundaries (unchanged)

| Plane | Status |
|-------|--------|
| Detection | Unchanged |
| R4 / R6 / R7 / R5 / R8 | Unchanged |
| R3 | Observational |
| Mitigation / OpenFlow / controller | **Not wired** |
| `/api/control/*` | **Disconnected** |

---

## Limitations / blockers for “real” ops

- No low-risk mutating backend (e.g. alert acknowledge store) existed to enable safely
- Mitigation remains Phase 13+ (R7-gated)
- PostgreSQL multi-host remains a future deployment concern

---

## Explicit statements

**Phase 12 is the first controlled operational execution phase.**

**R7-gated operational mitigation remains NOT IMPLEMENTED.**

**No automatic mitigation, bulk execution, or arbitrary controller/OpenFlow commands exist.**
