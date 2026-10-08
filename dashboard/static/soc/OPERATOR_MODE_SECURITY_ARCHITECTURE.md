# IntelliShield SOC — Operator Mode Security Architecture

**Phase:** 7 — Operator Mode Safety Architecture & Backend Enforcement Design  
**Status:** DESIGN / AUDIT / READ-ONLY PREPARATION  
**Date:** 2026-09-27  
**Document path (tracked):** `dashboard/static/soc/OPERATOR_MODE_SECURITY_ARCHITECTURE.md`  
**Note:** Repository `.gitignore` excludes `DOCS/` (case-insensitive on macOS). This SOC path is the Phase 7 deliverable (equivalent to the requested `docs/SOC_OPERATOR_MODE_SECURITY_ARCHITECTURE.md` content).

> **Current production principle:** The SOC UI is an observer, not an operator.  
> Phase 7 designs a fail-closed control plane for a *future* Operator Mode.  
> **It does not enable live mitigation, configuration, or controller commands from the SOC.**

---

## 1. Purpose

Phase 7 answers:

1. Who is allowed to perform an action?
2. What actions are allowed?
3. How is authorization enforced?
4. How is the action / target validated?
5. How is confirmation performed?
6. How is duplicate execution prevented?
7. How is the action audited?
8. What happens on failure?
9. How does the system fail safely?

This document is the reviewable contract for later phases. It is **not** permission to ship Operator Mode.

---

## 2. Current Observer-Only Model

### Enabled today (Phases 1–6)

| Capability | State |
|---|---|
| SOC viewing | Enabled (GET) |
| Investigation by `event_id` | Enabled (GET) |
| Reports / historical aggregation | Enabled (GET, client aggregation) |
| System health observation | Enabled (GET) |
| Alert / R4–R8 / Twin read surfaces | Enabled (GET) |

### Explicitly disabled in SOC UI

| Capability | State |
|---|---|
| Mitigation command (block / unblock) | Disabled |
| Threshold / detection configuration | Disabled |
| R4/R6/R7/R8 configuration | Disabled |
| Attack / traffic generation from SOC Command Center | Disabled (use Lab Control) |
| Controller start/stop/restart from Command Center | Disabled (use Lab Control) |
| Audit rewrite / delete | Not exposed |

### Existing backend note (Lab Control vs Operator Mode)

`dashboard/api.py` exposes lab/control **POST** routes under `/api/control/*` (archive, controller
restart/stop, scenarios, metrics, bundle, train). These are wired into the DDoS Dashboard
**Lab Control** page (`#lab-control`) for legacy Master Control parity. They are **not** part of
Operator Mode / Command Center execution. OpenFlow mitigation remains controller-side (R7).
Wrapping lab POSTs in Operator Mode authz is a later, authorized phase.

---

## 3. Security Boundary

```text
                    ┌──────────────────────┐
                    │       SOC UI         │
                    │    Untrusted Client   │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Authentication       │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Authorization / RBAC  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Command Validation    │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Safety / Policy Gate  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Security Engine       │
                    │ (R7 / mitigation…)    │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Execution             │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Immutable Audit Trail │
                    └──────────────────────┘
```

The frontend is **never** trusted for authorization, identity, timestamps, roles, or audit.

---

## 4. Trust Model

| Component | Trust |
|---|---|
| Frontend (SOC JS) | **UNTRUSTED** |
| HTTP API | **TRUST BOUNDARY** |
| Backend authorization | **AUTHORITATIVE** |
| Security engines (detection, R7, mitigation) | **AUTHORITATIVE** |
| UI “permissions” / readiness badges | **DISPLAY ONLY** |
| Audit log | **SERVER GENERATED** |

Forbidden as real authorization:

```text
localStorage.role = "admin"
if (user.isAdmin) { enableBlockButton() }
Browser-supplied command_id / requested_by / timestamp
```

---

## 5. Threat Model

### Threat 1 — Direct API invocation

**Threat:** Attacker bypasses UI and calls a future command endpoint.  
**Requirement:** Backend authorization rejects unauthorized requests. UI hiding controls is insufficient.

### Threat 2 — Modified frontend

**Threat:** User patches JS to reveal “controls.”  
**Requirement:** Backend must not trust frontend state or role claims.

### Threat 3 — Replay

**Threat:** Valid command resent repeatedly.  
**Requirement:** Server-side command identity / idempotency prevents unintended duplicate execution.

### Threat 4 — Privilege escalation

**Threat:** Lower-privileged principal attempts administrative action.  
**Requirement:** Backend RBAC enforces role × action × scope.

### Threat 5 — Target manipulation

**Threat:** Operator confirms action against a different target than reviewed.  
**Requirement:** Target type/id validated server-side against authoritative state; confirmation binds to server-issued preview/command id.

### Threat 6 — Stale decision

**Threat:** Action based on outdated detection/verification.  
**Requirement:** Where applicable, validate event/state freshness server-side.  
**Current status:** Formal freshness contract for operator commands = **NOT IMPLEMENTED** (must be defined before HIGH_RISK enablement).

### Threat 7 — Race condition

**Threat:** Concurrent conflicting commands (e.g. BLOCK vs UNBLOCK).  
**Requirement:** Validate current target state immediately before execution; last-writer-wins without validation is unacceptable.

### Threat 8 — Partial failure

**Threat:** API accepts request but controller fails mid-path.  
**Requirement:** Explicit multi-stage result; audit records outcome; fail safe (no silent SUCCESS).

### Threat 9 — Audit bypass

**Threat:** Execution without audit record.  
**Requirement:** No control execution if audit append fails or audit store unavailable (**fail-closed**).

### Threat 10 — Unauthorized automation

**Threat:** Non-human agent uses operator command path.  
**Requirement:** Distinguish human/operator vs machine principals; machine paths require separate, explicit contracts.

---

## 6. Roles (Conceptual RBAC)

Minimal roles (design only — **not** activated as production auth in Phase 7):

| Role | Intended permissions |
|---|---|
| **VIEWER** | Read SOC data |
| **ANALYST** | Read, investigate, generate/export reports |
| **OPERATOR** | Analyst + execute **approved** operational actions (future) |
| **ADMIN** | Manage authorization/configuration (future) |

Authentication system status in this repository: **not present as a SOC/control identity layer** (no auth modules found for Operator Mode). Phase 8+ must introduce identity before any CONTROLLED/HIGH_RISK action is enabled.

---

## 7. Action Classification

| Action | Category | Risk class | Phase 7 status |
|---|---|---|---|
| View dashboard / traffic / entropy | READ | READ_ONLY | Enabled |
| Investigate by `event_id` | INVESTIGATE | READ_ONLY | Enabled |
| View / export reports | READ | READ_ONLY | Enabled |
| View R4/R6/R7/R5/R8 | READ | READ_ONLY | Enabled |
| View blocklist history | READ | READ_ONLY | Enabled |
| Acknowledge alert | ACKNOWLEDGE | CONTROLLED | **NOT ENABLED** |
| Block attacker | MITIGATION | HIGH_RISK | **NOT ENABLED** |
| Unblock attacker | UNBLOCK | HIGH_RISK | **NOT ENABLED** |
| Change detection threshold | CONFIGURATION | HIGH_RISK | **NOT ENABLED** |
| Change R4/R6/R7/R8 config | CONFIGURATION | HIGH_RISK | **NOT ENABLED** |
| Controller restart/stop | SYSTEM_CONTROL | HIGH_RISK | **NOT ENABLED** in SOC |
| Start attack / generate traffic | SYSTEM_CONTROL | NOT_IMPLEMENTED (SOC) | Forbidden in SOC |

---

## 8. Authentication Requirements

Required before Operator Mode:

| Concern | Requirement |
|---|---|
| Identity | Authenticated principal (stable id) |
| Session / token | Server-issued, expiring credential |
| Expiration | Enforced server-side |
| Revocation | Supported (logout / invalidate) |
| Failure | Missing/invalid auth → **DENY** |

**Do not** invent a full auth stack in Phase 7. Document only.

---

## 9. Authorization Requirements

Every future control request must independently verify:

```text
authenticated principal
role permits action
target valid
scope valid
current state consistent
policy permits
audit subsystem available
```

Example (BLOCK attacker-X):

```text
Authenticated?       YES
Role permits block?  YES
Target valid?        YES
Event valid?         YES (if event-scoped)
State current?       YES / policy-defined
Policy permits?      YES
Audit prepared?      YES
→ only then may execution occur
```

Default when any check is unclear: **DENY** (fail-closed).

---

## 10. Future Command Contract (Design Only)

Conceptual envelope (adapt to project conventions when implemented; **do not activate in Phase 7**):

```json
{
  "command_id": "server-generated-id",
  "action": "ACTION_TYPE",
  "target": {
    "type": "TARGET_TYPE",
    "id": "TARGET_ID"
  },
  "event_id": "EVENT_ID_OR_NULL",
  "reason": "OPERATOR_REASON",
  "requested_by": "SERVER_DERIVED_PRINCIPAL",
  "requested_at": "SERVER_TIMESTAMP",
  "idempotency_key": "SERVER_OR_CLIENT_SUPPLIED_KEY",
  "confirmation": {
    "required": true,
    "preview_id": "server-generated-preview-id"
  },
  "expires_at": "SERVER_TIMESTAMP"
}
```

### Server-generated / server-derived fields

Never trust from the browser as authoritative:

- `command_id`
- `user_id` / `requested_by`
- `role`
- `requested_at` / `expires_at`
- audit identity

---

## 11. Confirmation

High-risk actions require:

```text
Review → Explicit confirmation → Server validation → Execution
```

“Button clicked” alone is not confirmation. Prefer a two-phase flow:

### Preview (future)

```text
POST /future-command/preview  →  NOT IMPLEMENTED IN PHASE 7
```

Returns: target, current state, action, expected effect, risk, expiry, server `preview_id`.

### Confirm (future)

```text
POST /future-command/confirm  →  NOT IMPLEMENTED IN PHASE 7
```

Binds to unexpired `preview_id` / `command_id` and re-validates state.

---

## 12. Command Expiration

High-risk commands must not remain valid indefinitely.

```text
issued_at   — server time
expires_at  — server time
```

Stale / expired commands → **EXPIRED** / **REJECTED**. Client clock is never authoritative.

---

## 13. Idempotency

```text
command_id and/or idempotency_key
→ same valid command identity
→ at-most-once security effect (or same result replay)
```

Duplicate suppression is **server-side**. Frontend debounce is not a security control.

---

## 14. Concurrency

Before execution, re-read authoritative target state.

Example conflict:

```text
Operator A: BLOCK X
Operator B: UNBLOCK X
```

Backend validates current state; rejects or sequences per policy. Do not assume UI snapshot is current.

---

## 15. Target Validation

Validate:

- target type
- target id
- existence
- current state
- scope (e.g. topology / tenant / experiment boundary)

Never trust target solely from frontend payload.

---

## 16. Event Freshness

For event-scoped actions, consider:

- `event_id`
- event timestamp (backend-authored)
- current backend verification / mitigation state

An old event must not automatically authorize a current action.

**Formal operator freshness thresholds:** NOT IMPLEMENTED — must be specified before HIGH_RISK enablement. Do not invent thresholds in the UI.

---

## 17. Audit Trail

### Minimum conceptual fields

```text
audit_id
command_id
principal_id
role
action
target_type
target_id
event_id
reason
requested_at
validated_at
executed_at
result
failure_reason
source
```

Timestamps are **server-generated**. UI must not create authoritative audit records.

### Immutability

Append-oriented. No edit/delete/rewrite from operator UI.

### Audit failure → fail-closed

If an action requires audit and the audit system is unavailable:

```text
DO NOT EXECUTE CONTROL ACTION
```

---

## 18. Fail-Closed Behavior

Future control APIs default to **DENY** when:

- authentication missing
- authorization unclear
- target invalid
- event missing (when required)
- state stale (when policy requires freshness)
- policy unavailable
- audit unavailable
- controller unavailable
- validation fails

Never default to execution.

---

## 19. Action Result Model

Do not treat HTTP 200 as proof of security success.

```text
ACCEPTED
REJECTED
DENIED
EXPIRED
DUPLICATE
INVALID
FAILED
EXECUTED
PARTIAL
```

### Controller interaction stages (must remain distinct)

```text
request accepted
controller contacted
controller acknowledged
controller executed
controller failed
```

Do not collapse into a single opaque `SUCCESS`.

---

## 20. Controller Failure Handling

On controller failure:

1. Return explicit **FAILED** / **PARTIAL** with stage.
2. Append audit with `failure_reason`.
3. Do not claim mitigation applied.
4. Prefer safe residual state (no silent half-apply without visibility).

---

## 21. R4 / R6 / R7 Boundary

| Layer | Role |
|---|---|
| **R4** | Advisory / analytical correlation — does **not** authorize mitigation |
| **R6** | Collaborative fusion / detection evidence — not causation authority |
| **R7** | Verification and mitigation eligibility — pipeline gate |
| **Mitigation** | Execution layer |

Future operator workflows must **not** silently bypass R7 unless a separately approved emergency workflow is defined in a later phase. Phase 7 does **not** create a second mitigation path and does **not** modify R7.

Pipeline remains:

```text
Detection → R4 → R6 → R7 → Mitigation → R5/R8
```

---

## 22. R5 / R8 Boundary

| Layer | Role |
|---|---|
| **R5** | Analysis / explanation — **not** authorization |
| **R8** | Alerting / notification — **not** authorization |

Forbidden:

```text
R5 says malicious → operator action auto-allowed
R8 severity CRITICAL → automatic operator authorization
```

---

## 23. R3 Digital Twin Boundary

R3 remains:

```text
SNAPSHOT
OBSERVATIONAL
READ ONLY
```

Twin predictions **never** authorize production mitigation.

---

## 24. Security Decision Table

| Capability | Current State | Future Requirement |
|---|---|---|
| SOC viewing | Enabled | Keep |
| Investigation | Enabled | Keep |
| Reports | Enabled | Keep |
| Alert viewing | Enabled | Keep |
| Authentication for control | Not available | Required before control |
| RBAC | Not active | Required before control |
| Mitigation command | Disabled in SOC | Backend authorization + R7-aware policy |
| Block / Unblock target | Disabled in SOC | Validation + authorization + audit |
| Configuration changes | Disabled in SOC | Admin authorization |
| Audit trail for control | Design only | Required; fail-closed |
| Confirmation | Design only | Required for HIGH_RISK |
| Idempotency | Design only | Required |
| Fail-closed | Defined (this doc) | Required in implementation |
| `/api/control/*` POST (lab panel) | Exists outside SOC | Must not be wired into SOC until Phase 8+ safety gates |

---

## 25. Future Implementation Sequence (Planning Only)

```text
Phase 7  — Architecture + threat model
Phase 8  — Authentication + identity foundation   COMPLETE
Phase 9  — RBAC + backend authorization           COMPLETE
Phase 10 — Command / Safety / Audit infrastructure ← CURRENT (see COMMAND_SAFETY_ARCHITECTURE.md)
Phase 11 — Controlled low-risk operator action (future)
Phase 12 — High-risk mitigation workflow (future)
```

**Phase 8:** Authentication COMPLETE.  
**Phase 9:** RBAC COMPLETE.  
**Phase 10:** Command/Safety/Audit infrastructure COMPLETE.  
**Execution:** NOT ENABLED. Mitigation: NOT ENABLED.

Do not implement operational execution in Phase 10.

---

## 26. Explicit Non-Goals (Phase 7)

- No live Operator Mode
- No SOC Block / Unblock / Mitigate / Kill Flow buttons
- No new write APIs for the SOC client
- No modification of detection / R4 / R6 / R7 / mitigation / R5 / R8 / Twin engines
- No enterprise IAM / OPA / Kafka / microservices introduction
- No database migration solely for documentation
- No frontend authorization as source of truth

---

## 27. Final Principle

> **Design the control plane before exposing the control plane.**

```text
UI cannot authorize itself
UI cannot execute directly
UI cannot bypass R7
UI cannot impersonate an operator
UI cannot create authoritative audit records
UI cannot decide permissions
UI cannot override backend safety
```

The backend remains authoritative.  
The SOC remains an observer until later phases explicitly and safely enable Operator Mode.
