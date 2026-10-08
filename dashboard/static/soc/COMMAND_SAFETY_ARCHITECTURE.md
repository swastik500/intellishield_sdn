# IntelliShield SOC — Command Safety Architecture (Phase 10)

**Status:** Implemented (infrastructure only — **execution DISABLED**)  
**Location:** `dashboard/static/soc/COMMAND_SAFETY_ARCHITECTURE.md`

> Phase 10 builds the command lifecycle through `READY_FOR_EXECUTION`, then forces `EXECUTION_DISABLED`.  
> No mitigation, controller, OpenFlow, or `/api/control/*` integration.

---

## 1. Purpose

Establish a fail-closed, auditable command-control foundation so future Operator Mode can accept operational requests without executing them yet.

## 2–4. Relationship to Phases 7–9

| Phase | Concern |
|-------|---------|
| 7 | Threat model / Operator Mode design |
| 8 | Authentication / Principal |
| 9 | RBAC / `authorize()` / `require_permission` |
| 10 | Command model, validation, safety, confirmation, audit |

Every command requires an authenticated principal and Phase 9 authorization for the action’s required permission.

## 5. Command model

`dashboard/commands/models.py` — `Command` with server-generated `command_id`, action, target, event_id, principal, reason, timestamps, status, authorization/validation/safety/freshness, audit_id, `execution_enabled=False`.

## 6. Action registry

`dashboard/commands/actions.py` — authoritative `ACTION_REGISTRY`.

Notable actions:

| Action | Risk | Permission | Confirm | Execution |
|--------|------|------------|---------|-----------|
| READ | LOW | READ_DASHBOARD | No | Disabled |
| COMMAND_DRY_RUN | MEDIUM | INVESTIGATE_EVENTS | Yes | Disabled |
| BLOCK_TARGET / UNBLOCK / EXECUTE_MITIGATION / … | HIGH/CRITICAL | Future perms | Yes | Disabled |

Future operational permissions remain **DENIED** by Phase 9 RBAC (`POLICY_DENIED`).

## 7. Risk levels

`LOW | MEDIUM | HIGH | CRITICAL` — classification only.

## 8. Target model

`{ "type": "EVENT|ALERT|ATTACKER|…", "id": "…" }` — validation only.

## 9. Command state machine

```text
REQUESTED → VALIDATING → AUTHORIZED → SAFETY_CHECK
  → AWAITING_CONFIRMATION → CONFIRMED → READY_FOR_EXECUTION → EXECUTION_DISABLED
```

Failure terminals: `DENIED`, `INVALID`, `EXPIRED`, `STALE`, `DUPLICATE`, `SAFETY_BLOCKED`, `CANCELLED`, `FAILED`.

Invalid transitions raise `InvalidTransitionError` (fail closed).

## 10–11. Validation / Authorization

Central validators for reason, target, event_id, idempotency key.  
Authorization via `dashboard.auth.authorization.authorize` — not duplicated.

## 12–13. Event validation / Freshness

Event IDs must match explicit ID pattern (no heuristic joins).  
Freshness: `INTELLISHIELD_COMMAND_FRESHNESS_MAX_AGE_SECONDS`.  
If unset: **NOT_CONFIGURED** → **fail-closed** for HIGH/CRITICAL; LOW/MEDIUM dry-run may proceed as NOT_APPLICABLE.

Server time is authoritative.

## 14. Expiration

Commands TTL default 900s; confirmation window 300s.

## 15–16. Idempotency / Replay

In-memory index on `(principal, action, target, idempotency_key)`.  
**Limitation:** process-local — not multi-instance production-grade.  
Confirmation tokens are single-use; replay returns `duplicate`.

## 17. Confirmation

Bound to command_id + principal + token stored server-side. Wrong principal/token → deny. Expired → `EXPIRED`.

## 18. Safety gate

`evaluate_safety(...)` → `SAFE | BLOCKED | NOT_READY` with `execution_enabled` always false.

## 19. Audit trail

Append-only durable `AuditStore` (SQLite). No PUT/PATCH/DELETE.
See `COMMAND_PERSISTENCE_ARCHITECTURE.md` (Phase 11).

## Persistence (Phase 11)

Durable SQLite `CommandStore` + `AuditStore` + idempotency table.
Process restart and multi-instance consistency use DB transactions/constraints.
Execution remains DISABLED.  
**Limitation:** ephemeral / not durable multi-instance audit.

## 20. Persistence

In-memory stores replaced in Phase 11 by durable SQLite (see COMMAND_PERSISTENCE_ARCHITECTURE.md).
Phase 10 established the lifecycle contract; Phase 11 made it durable.

## 21. Concurrency

Confirmation sets `confirmation_used` under store update; second confirm → duplicate/reject.

## 22. Execution boundary (superseded by Phase 12 for one action)

Phase 10 ended at `EXECUTION_DISABLED` for all actions.  
**Phase 12** enables exactly one allowlisted action (`COMMAND_DRY_RUN`) via  
`POST /api/operator/commands/{id}/execute`. See `CONTROLLED_OPERATION_ARCHITECTURE.md`.  
All mitigation / controller / OpenFlow actions remain disabled.

## 23. `/api/control/*` separation

Lab control POSTs remain disconnected from Command Center and are never called by Phase 10.

## 24. Explicit non-goals

- No operational execution  
- No mitigation / OpenFlow / controller mutation  
- No R7 bypass  
- No Redis/Kafka/OPA  
- No production distributed idempotency claim  

## API

```text
POST /api/operator/commands/preview
POST /api/operator/commands/{id}/confirm
GET  /api/operator/commands
GET  /api/operator/commands/{id}
GET  /api/operator/audits

Operator execution endpoints: NONE
```
