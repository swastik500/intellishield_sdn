# IntelliShield SOC — Authentication & Identity Architecture (Phase 8)

**Status:** Implemented foundation (identity only)  
**Location:** `dashboard/static/soc/AUTHENTICATION_IDENTITY_ARCHITECTURE.md`  
**Related:** `OPERATOR_MODE_SECURITY_ARCHITECTURE.md` (Phase 7 design)

> Phase 8 answers: **WHO ARE YOU?**  
> Phase 9 answers: **WHAT ARE YOU ALLOWED TO DO?**  
> Authentication must not connect directly to mitigation.

---

## 1. Purpose

Establish a production-appropriate authentication and identity foundation for the FastAPI dashboard that future backend RBAC and Operator Mode can build on — without changing detection, verification, mitigation, RCA, alerting, or Digital Twin security logic.

---

## 2. Existing Authentication State (Pre–Phase 8)

Inspection found **no** prior dashboard authentication:

| Approach | Present? |
|----------|----------|
| Session authentication | No |
| JWT | No |
| OAuth/OIDC | No |
| API tokens | No |
| Reverse-proxy auth | No |
| Custom auth | No |

Phase 8 introduces a **minimal session-based** mechanism compatible with the existing FastAPI app. No enterprise IAM, OAuth, or microservices were added.

---

## 3. Authentication Mechanism

**Opaque server-side sessions** with:

- HttpOnly cookie (`is_session`) for browsers (SameSite=Lax by default)
- Optional `Authorization: Bearer <session_token>` for API clients
- Password verification via **PBKDF2-HMAC-SHA256** (stdlib; no custom crypto)
- Single configured operator credential from environment (foundation; not a full user directory)

Package: `dashboard/auth/`

---

## 4. Principal Model

Server-derived `Principal` (`dashboard/auth/principal.py`):

| Field | Meaning |
|-------|---------|
| `id` | Stable principal id (e.g. `user:<username>`) |
| `username` | Subject |
| `authentication_method` | e.g. `password` |
| `authenticated_at` | ISO UTC |
| `expires_at` | ISO UTC |
| `roles` | Informational only in Phase 8 (e.g. `observer`) |
| `session_id` | Internal; not required in public payloads |

**Never exposed:** password, password hash, raw session secret beyond the issued token at login, CSRF secrets in logs.

Roles present on the principal **do not** authorize Operator Mode actions.

---

## 5. Authentication Flow

```text
Client credentials
        ↓
POST /api/auth/login  (rate-limited)
        ↓
Verify username + PBKDF2 hash (generic failure)
        ↓
Create SessionRecord in server SessionStore
        ↓
Set HttpOnly cookie + return session_token + csrf_token
        ↓
Subsequent requests: cookie or Bearer → resolve Principal → request.state.principal
```

Logout: `POST /api/auth/logout` revokes the session server-side and clears the cookie.

---

## 6. Protected / Public Endpoint Classification

| Class | Endpoints | Phase 8 policy |
|-------|-----------|----------------|
| **PUBLIC** | Existing SOC observational `GET /api/*` (status, traffic, entropy, alerts, R4/R5/R6/R7/R8, twin, …) | Remain **public** so research/demo workflows continue |
| **AUTH INFRASTRUCTURE** | `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`, `GET /api/auth/status` | Login requires configured credentials; me/status are safe reads |
| **AUTHENTICATED READ** | Mechanism ready via `require_authenticated_principal` | Not applied to SOC GETs in Phase 8 |
| **FUTURE AUTHENTICATED CONTROL** | Future Operator command APIs | **Not implemented**; must use auth + Phase 9 RBAC + safety |

**Decision:** Preserve public read-only SOC access. Authentication is available and displayed; it is not required to view observational data. Future control APIs will require authentication (and later RBAC).

**Lab `/api/control/*` POST routes:** Wired into the DDoS Dashboard **Lab Control** page
(`#lab-control`) for Master Control parity. They remain outside Operator Mode / Command Center
execution. Legacy Master Control at `/legacy` is unchanged fallback. Auth wrapping of lab POSTs
is a separate later concern; Phase 8 left them outside the observer auth path.

---

## 7. Credential Handling

- Passwords are never stored plaintext.
- Env stores `INTELLISHIELD_AUTH_PASSWORD_HASH` only (pbkdf2 string).
- Login failures use a **generic** message (no username enumeration).
- Passwords and tokens are **not** logged.

Generate a hash:

```bash
python3 -c "from dashboard.auth.passwords import hash_password; print(hash_password('YOUR_PASSWORD'))"
```

---

## 8. Secret Management

| Variable | Role |
|----------|------|
| `INTELLISHIELD_AUTH_SECRET_KEY` | Required for configured auth (env only; never hardcoded) |
| `INTELLISHIELD_AUTH_USERNAME` | Configured username |
| `INTELLISHIELD_AUTH_PASSWORD_HASH` | PBKDF2 hash |
| `INTELLISHIELD_AUTH_ENABLED` | Optional explicit on/off |
| `INTELLISHIELD_AUTH_SESSION_TTL_SECONDS` | Default 28800 (8h); clamped |
| `INTELLISHIELD_AUTH_COOKIE_SECURE` | HTTPS-only cookie |
| `INTELLISHIELD_AUTH_COOKIE_SAMESITE` | lax \| strict \| none |
| `INTELLISHIELD_CORS_ORIGINS` | Explicit origins; empty → lab `*` **without** credentials |

No `DISABLE_AUTH` / `AUTO_LOGIN` / `BYPASS_AUTH` production switches.

---

## 9. Token / Session Lifecycle

| State | Behavior |
|-------|----------|
| **Issued** | `SessionStore.create` → opaque `session_id` |
| **Expires** | Server clock; TTL from config |
| **Invalid** | Unknown / malformed / expired token → unauthenticated |
| **Revoked** | `logout` or `revoke` removes session |

Server-side expiration is authoritative. No indefinite sessions.

---

## 10. Expiration

Default TTL: **8 hours** (`28800` seconds). Configurable via env. Minimum 60s; maximum 7 days.

---

## 11. Revocation

**Implemented:** in-memory session invalidation on logout (`SESSION_STORE.revoke`).

**Limitation:** process-local store — restart clears sessions; multi-worker deployments need a shared store in a later phase. Stateless JWT was **not** chosen so revocation remains possible without a denylist redesign.

---

## 12. CSRF Considerations

- Cookie: `HttpOnly`, `SameSite=Lax` (default).
- Each session includes a `csrf_token` returned on login / `/api/auth/me`.
- **Future** state-changing Operator APIs **must** require CSRF validation (header matching session CSRF) and must not rely on cookie alone.
- Phase 8 does **not** expose Operator state-changing endpoints; CSRF enforcement for those is deferred.

---

## 13. CORS Considerations

- Lab default: `allow_origins=["*"]` with **`allow_credentials=False`** (never `*` + credentials).
- Same-origin SOC (static + API on one origin) still sends cookies.
- For credentialed cross-origin: set `INTELLISHIELD_CORS_ORIGINS` to an explicit list (enables credentials).

---

## 14. Authentication Failure Behavior

| Condition | HTTP | Code |
|-----------|------|------|
| Missing/invalid/expired session on `require_authenticated_principal` | 401 | `AUTHENTICATION_REQUIRED` |
| Bad login credentials | 401 | `AUTHENTICATION_FAILED` |
| Auth not configured (login) | 503 | `AUTHENTICATION_NOT_CONFIGURED` |
| Rate limited | 429 | `AUTHENTICATION_RATE_LIMITED` |
| Authenticated but lacking permission | 403 | `FORBIDDEN` (**Phase 9**; helper reserved) |

Body shape:

```json
{
  "error": {
    "code": "AUTHENTICATION_REQUIRED",
    "message": "Authentication required"
  }
}
```

---

## 15. Logging Rules

**May log:** `authentication_success`, `authentication_failure`, `authentication_rate_limited`, `logout`, non-sensitive `principal_id`.

**Must not log:** password, raw token, Authorization header, cookie value, password hash.

---

## 16. Rate Limiting Considerations

In-memory per-client login limiter (`LoginRateLimiter`): default 10 attempts / 300 seconds. Not a distributed rate limiter — document upgrade need for multi-instance production.

---

## 17. Identity Propagation

- FastAPI dependency: `get_optional_principal` / `require_authenticated_principal`
- Successful resolution sets `request.state.principal`
- Routes must not trust client `user_id` / `role` / `is_admin` fields

---

## 18. `/api/auth/me` Contract

`GET /api/auth/me`

**Unauthenticated (HTTP 200):**

```json
{
  "authenticated": false,
  "principal": null,
  "authentication_configured": false,
  "authorization_implemented": false,
  "operator_controls_enabled": false
}
```

**Authenticated (HTTP 200):** includes public `principal`, `csrf_token`, `permissions` (Phase 9), and capability flags (`authorization_implemented: true` after Phase 9, `operator_controls_enabled: false`).

Chosen **200 + authenticated:false** so the SOC identity panel can poll without treating login as mandatory for observational use.

Also: `GET /api/auth/status` — non-sensitive configuration summary for Operator Readiness.

---

## 19. RBAC Integration (Phase 9)

```text
Authentication (Phase 8) → Principal → Authorization / RBAC (Phase 9) → Command safety → Execution
```

Phase 9 adds: permission evaluation, role/action mapping, 403 enforcement, authorization tests.  
See `RBAC_AUTHORIZATION_ARCHITECTURE.md`.  
**Do not** skip authorization and wire auth directly to mitigation.

---

## 20. Explicit Non-Goals (Phase 8)

- No Operator Mode controls
- No mitigation / block / unblock / controller commands from SOC
- No RBAC enforcement
- No JWT/OAuth/enterprise IAM unless later required
- No changes to detection / R4 / R6 / R7 / mitigation / R5 / R8 / Twin engines
- No frontend `localStorage` as proof of auth
- No production auth bypass flags

---

## Endpoint Audit Summary

```text
Authentication endpoints:
  POST /api/auth/login
  POST /api/auth/logout
  GET  /api/auth/me
  GET  /api/auth/status

SOC read endpoints:
  Existing GET /api/* observational routes (public in Phase 8)

Operator control endpoints:
  NONE (from SOC)
```
