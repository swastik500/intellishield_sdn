# Command Persistence Architecture — Phase 11

**Status:** Phase 11 COMPLETE (infrastructure hardening only)  
**Operational execution:** **DISABLED**

Phase 11 hardens the Phase 10 command/safety infrastructure by replacing
in-memory command, audit, and idempotency state with durable, transactional
persistence. It does **not** activate mitigation, controller, OpenFlow, or
`/api/control/*` execution.

---

## Architecture

```
SOC UI  →  FastAPI /api/operator/*  →  Command Service
                                         │
                                         ├─ Phase 8 Auth (session/principal)
                                         ├─ Phase 9 RBAC (authorize)
                                         ├─ Safety Gate / Freshness
                                         └─ Persistence layer (SQLite)
                                              ├─ operator_commands
                                              ├─ operator_idempotency
                                              └─ operator_audits (append-only)
```

Database technology: **stdlib `sqlite3`** (WAL mode).

This repository does **not** ship PostgreSQL, SQLAlchemy, or Alembic.
A second database stack was intentionally **not** introduced.
Schema versioning uses an embedded `schema_migrations` table
(`dashboard/commands/persistence/db.py`).

Environment:

| Variable | Purpose |
|----------|---------|
| `INTELLISHIELD_COMMAND_DB_PATH` | Absolute/relative path to SQLite file (default: `logs/operator/command_store.db`) |
| `INTELLISHIELD_COMMAND_FRESHNESS_MAX_AGE_SECONDS` | Required for HIGH/CRITICAL freshness; missing → fail closed |

---

## Database ownership

The command store owns **only** operator command/safety infrastructure tables.
It does **not** store detection, R4/R5/R6/R7/R8, twin, mitigation, or controller data.
Security engines must not call this persistence layer.

---

## Command schema (`operator_commands`)

Primary key: `command_id` (unique).

Persisted fields include: action, risk_level, target_type/id, event_id,
principal_id/username, reason, status, created_at, updated_at, expires_at,
confirmation fields, idempotency_key, authorization/validation/safety/freshness
JSON, audit_id, failure_reason, `execution_enabled` (always 0), `version`
(optimistic concurrency).

Secrets, passwords, and tokens are **not** stored (confirmation tokens for
pending confirmations are server-generated opaque strings, not auth credentials).

---

## State transitions

Authoritative lifecycle (server-side only):

```
REQUESTED → VALIDATING → AUTHORIZED → SAFETY_CHECK
  → AWAITING_CONFIRMATION → CONFIRMED → READY_FOR_EXECUTION
  → EXECUTION_DISABLED
```

Invalid transitions (e.g. `REQUESTED → CONFIRMED`, `EXPIRED → CONFIRMED`,
double confirm) are rejected by the state machine in `models.py`.
Clients cannot set arbitrary states.

---

## Transaction model

- Writes use `BEGIN IMMEDIATE` (reserved lock) via `persistence.db.transaction`.
- Confirmation loads, validates, updates, and appends audit in **one** transaction.
- Optimistic `version` column: concurrent updates that lose the race raise
  `concurrent_modification` and resolve to a duplicate/replay response.
- If a required persist fails → **fail closed** (HTTP 503). No in-memory fallback.

---

## Concurrency protection

Multi-instance / multi-process safety relies on:

1. SQLite WAL + `BEGIN IMMEDIATE` writer lock
2. Optimistic `version` on `UPDATE … WHERE version=?`

Two simultaneous confirms: at most one reaches `EXECUTION_DISABLED` without
`duplicate`; the other receives `confirmation_replay` / duplicate semantics.

Python locks are **not** the primary safety mechanism.

---

## Idempotency

Table `operator_idempotency` with composite primary key:

`(principal_id, action, target_type, target_id, idempotency_key)`

First request creates the command + idempotency row atomically.
Duplicate key → resolve to existing command (`duplicate: true`).
Uniqueness is database-enforced.

---

## Audit model

Table `operator_audits` — append-only.

Captures: audit_id, timestamp, principal_id, action, command_id, event_id,
previous/new status, result, failure_reason, source, parent_audit_id, payload JSON.

No update/delete API. Duplicate `audit_id` insert is rejected.
Application routes expose only `GET /api/operator/audits`.

Does not log passwords, session tokens, bearer tokens, or private keys.

---

## Expiration

Each command has durable `expires_at` (server UTC). Confirmation of expired
commands fails closed (`EXPIRED`). Expiration works after process restart
because time is evaluated against persisted timestamps.

---

## Freshness

`INTELLISHIELD_COMMAND_FRESHNESS_MAX_AGE_SECONDS`:

- HIGH/CRITICAL: if unset/invalid → `NOT_CONFIGURED` → safety **blocks** (fail closed).
- Never treats missing config as unlimited freshness for high-risk actions.
- LOW/MEDIUM dry-runs may proceed with `NOT_APPLICABLE` when unset.

This does **not** authorize execution.

---

## Failure behavior

| Failure | Behavior |
|---------|----------|
| DB unavailable | Command path unavailable (503) |
| Insert/update/audit failure | Rollback; no success claim |
| Idempotency conflict | Return existing command |
| Concurrent confirm | One winner; others duplicate/conflict |
| Missing principal / authz deny | DENIED / 403 |

Never silently falls back to Phase 10 in-memory dictionaries.

---

## Restart recovery

After restart (same DB path):

- Commands, states, confirmation, expiration, idempotency, audits remain
- No command becomes executable because of restart
- Browser/localStorage is never authoritative

---

## Multi-instance behavior

All instances must share the same `INTELLISHIELD_COMMAND_DB_PATH` (or future
shared DB). Consistency is provided by SQLite transactions/constraints, not
process-local caches.

---

## Migration strategy

- Forward: `ensure_schema()` applies `SCHEMA_VERSION = 1` DDL + records version.
- Reversible: drop Phase 11 tables only (does not touch other schemas).
- No Alembic in this repo; SQL mirror: `persistence/migrations/001_operator_command_store.sql`.

---

## Pagination

`GET /api/operator/commands?limit=&offset=&status=`  
`GET /api/operator/audits?limit=&offset=&command_id=`

Ordered by `created_at DESC`. Limits clamped (1–200).

---

## Security boundaries

Preserved:

- Phase 8 authentication (server-derived principal)
- Phase 9 RBAC (`authorize` / `require_permission`)
- Phase 10 safety gate + confirmation
- Phase 12 allowlists only `COMMAND_DRY_RUN` via `POST .../execute` (see `CONTROLLED_OPERATION_ARCHITECTURE.md`)
- Mitigation / controller / OpenFlow actions remain execution-disabled
- No wiring to `/api/control/*`, mitigation, OsKen, OpenFlow, Mininet
- Detection / R4 / R6 / R7 / R5 / R8 / R3 unchanged

---

## Frontend

Command Center reads durable backend state only.
No `localStorage` / `sessionStorage` / IndexedDB command authority.
Persistence failures surface as unavailable/error UI states (no fake success).

---

## Current limitations

- SQLite (not PostgreSQL) — adequate for lab / single-host; for multi-host
  production, migrate this schema to shared PostgreSQL later without changing
  the command contract.
- Real security-impacting operational execution remains disabled (dry-run only in Phase 12).
- Future R7-gated mitigation (Phase 13) and HIGH_RISK enablement remain separate.

---

## Explicit non-goals (Phase 11)

**Phase 11 does NOT implement operational execution.**  
**No real mitigation was implemented in Phase 11.**
