# IntelliShield SOC — RBAC & Authorization Architecture (Phase 9)

**Status:** Implemented (authorization only — no Operator Mode execution)  
**Location:** `dashboard/static/soc/RBAC_AUTHORIZATION_ARCHITECTURE.md`  
**Related:**  
- Phase 8: `AUTHENTICATION_IDENTITY_ARCHITECTURE.md`  
- Phase 7: `OPERATOR_MODE_SECURITY_ARCHITECTURE.md`

> Phase 8 answered: **WHO ARE YOU?**  
> Phase 9 answers: **WHAT ARE YOU ALLOWED TO DO?**  
> Later phases answer: **HOW DO WE SAFELY EXECUTE?**

---

## 1. Purpose

Provide a centralized, fail-closed, least-privilege RBAC layer on top of Phase 8 authentication so future Operator Mode can authorize actions without trusting the frontend.

---

## 2. Relationship to Phase 8 Authentication

| Concern | Owner |
|---------|--------|
| Credentials / session / cookie / Bearer | Phase 8 (`dashboard/auth/`) |
| Server-derived `Principal` | Phase 8 |
| Role assignment at login | Phase 9 (from `INTELLISHIELD_AUTH_ROLES`) |
| Permission evaluation | Phase 9 (`authorization.py`) |
| FastAPI `require_permission(...)` | Phase 9 (`deps.py`) |

Authentication is reused; it is not redesigned. Client-supplied `role` / `permissions` / `X-Role` never authorize.

---

## 3. Roles

| Role | Semantics (Phase 9) |
|------|---------------------|
| **VIEWER** | Read observational SOC data permissions |
| **ANALYST** | VIEWER + investigate events + generate/read reports extras |
| **OPERATOR** | Same *enabled* permissions as ANALYST; future ops **NOT ENABLED** |
| **ADMIN** | Same *enabled* permissions as ANALYST; no hidden superuser; management APIs **NOT ENABLED** |

Unknown roles → **DENY** (fail-closed).  
Legacy Phase 8 informational role `observer` maps to **VIEWER**.

Default configured role: **VIEWER** (least privilege).

---

## 4. Permissions

### Enabled (may be GRANTED)

```text
READ_DASHBOARD, READ_TRAFFIC, READ_DETECTION, READ_ALERTS,
READ_CORRELATION, READ_FUSION, READ_VERIFICATION, READ_RCA,
READ_DIGITAL_TWIN, READ_HEALTH, READ_REPORTS,
INVESTIGATE_EVENTS, GENERATE_REPORTS
```

### Defined but NOT ENABLED (always DENY)

```text
ACKNOWLEDGE_ALERT, EXECUTE_MITIGATION, BLOCK_TARGET, UNBLOCK_TARGET,
MANAGE_CONFIGURATION, MANAGE_RBAC
```

---

## 5. Role → Permission Mapping

Authoritative map: `dashboard/auth/roles.py` → `ROLE_PERMISSIONS`.

| Role | Enabled permissions |
|------|---------------------|
| VIEWER | All `READ_*` listed above |
| ANALYST | VIEWER + `INVESTIGATE_EVENTS` + `GENERATE_REPORTS` |
| OPERATOR | Same as ANALYST (no future ops granted) |
| ADMIN | Same as ANALYST (no `MANAGE_*` granted yet) |

Multiple roles on a principal → **union** of enabled permissions.  
If **any** role is unknown → entire evaluation **DENY**.

---

## 6. Principal Source

Only the Phase 8 server-derived `Principal` (session / Bearer) is authoritative.

Roles are stored on the session at login from **server config** (`INTELLISHIELD_AUTH_ROLES`), never from the login JSON body.

---

## 7. Authorization Dependency

```python
from dashboard.auth import require_permission, Permission

@router.get("/...")
async def handler(principal = Depends(require_permission(Permission.READ_REPORTS))):
    ...
```

Flow:

1. `require_authenticated_principal` → 401 if missing  
2. `authorize(principal, permission, resource_*)`  
3. DENY → 403 `FORBIDDEN`  
4. ALLOW → return principal  

Module layout:

```text
dashboard/auth/permissions.py
dashboard/auth/roles.py
dashboard/auth/authorization.py
dashboard/auth/deps.py          # require_permission
```

---

## 8. 401 vs 403

| Condition | Status | Code |
|-----------|--------|------|
| No / invalid / expired credentials | 401 | `AUTHENTICATION_REQUIRED` / related auth codes |
| Authenticated, insufficient permission | 403 | `FORBIDDEN` |

---

## 9. Fail-Closed Behavior

DENY when:

- missing principal  
- unknown role  
- empty roles  
- unknown permission  
- future / not-enabled permission  
- missing permission for role  
- invalid resource context (empty type/id when both provided)  

Never default to ALLOW. Invalid `INTELLISHIELD_AUTH_ROLES` falls back to **VIEWER**, never ADMIN.

---

## 10. Least Privilege

- Default role: VIEWER  
- ADMIN is not an implicit superuser  
- OPERATOR does not receive `EXECUTE_MITIGATION` in Phase 9  

---

## 11. Resource Authorization

`authorize(..., resource_type=, resource_id=)` is supported.

Phase 9: if permission is granted, any well-formed resource pair is allowed.  
No ownership DB. Future phases may add event/alert/target rules.

---

## 12. Action Authorization

Decisions are `principal + permission + optional resource`, not bare `if role == ADMIN`.

---

## 13. Future Operator Mode Boundary

```text
ALLOW (Phase 9)
    ↓
Future command validation
    ↓
Future safety gate
    ↓
Future execution
```

**ALLOW does not execute mitigation.**

---

## 14. Existing `/api/control/*` Separation

Lab `/api/control/*` POST routes remain outside SOC Operator Mode.  
Phase 9 does not wrap them into RBAC Operator commands and does not expose them via the SOC UI.

---

## 15. Audit-Readiness

`AuthzDecision` carries:

```text
principal_id, permission, resource_type, resource_id, decision, reason, timestamp
```

Logged via `log_decision` (no tokens/secrets). No production audit database in Phase 9.

---

## 16. Frontend Limitations

SOC may display roles / “RBAC ENABLED” for UX.  
Hiding UI is **not** authorization. No control buttons are enabled by roles.

---

## 17. Testing

See `tests/test_soc_ui_phase9.py` for role matrix, 401/403, forged role/permission, fail-closed, and future-permission DENY cases.

---

## 18. Explicit Non-Goals

- No Operator Mode execution  
- No command / preview / confirmation APIs  
- No mitigation / block / unblock from SOC  
- No OPA / external IAM / permission database  
- No self-elevation APIs  
- No locking down public observational SOC GETs (Phase 8 contract preserved)

---

## Endpoint Audit

```text
Authentication:
  POST /api/auth/login
  POST /api/auth/logout
  GET  /api/auth/me
  GET  /api/auth/status

Authorization (read-only probes):
  GET  /api/auth/authorization
  GET  /api/auth/authorization/check?permission=...
  GET  /api/auth/authorized/dashboard      (requires READ_DASHBOARD)
  GET  /api/auth/authorized/investigate    (requires INVESTIGATE_EVENTS)

SOC observational GET:
  Existing public /api/* routes (unchanged)

Operator control endpoints:
  NONE
```
