"""Authentication HTTP routes — login / logout / me / authorization status.

No operator controls. No mitigation. RBAC evaluation only (Phase 9).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, Field

from .authorization import authorize, effective_permissions, log_decision
from .config import AuthConfig, load_auth_config
from .deps import COOKIE_NAME, get_optional_principal, require_authenticated_principal, require_permission
from .errors import (
    authentication_failed,
    authentication_not_configured,
    forbidden_not_authorized,
    rate_limited,
)
from .passwords import verify_password
from .permissions import FUTURE_PERMISSIONS, Permission
from .principal import Principal
from .rate_limit import LoginRateLimiter
from .sessions import SESSION_STORE

logger = logging.getLogger("intellishield.auth")

auth_router = APIRouter(prefix="/api/auth", tags=["auth"])

_rate_limiter: Optional[LoginRateLimiter] = None


def _limiter(cfg: AuthConfig) -> LoginRateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = LoginRateLimiter(
            max_attempts=cfg.login_max_attempts,
            window_seconds=cfg.login_window_seconds,
        )
    return _rate_limiter


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=256)
    # Client-supplied role / permissions / user_id are ignored by design


def _client_key(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()[:64]
    if request.client:
        return (request.client.host or "unknown")[:64]
    return "unknown"


def _set_session_cookie(response: Response, cfg: AuthConfig, session_id: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=cfg.cookie_secure,
        samesite=cfg.cookie_samesite,
        max_age=cfg.session_ttl_seconds,
        path="/",
    )


def _clear_session_cookie(response: Response, cfg: AuthConfig) -> None:
    response.delete_cookie(
        key=COOKIE_NAME,
        path="/",
        httponly=True,
        secure=cfg.cookie_secure,
        samesite=cfg.cookie_samesite,
    )


def _authz_flags(cfg: AuthConfig) -> dict[str, Any]:
    return {
        "authorization_implemented": True,
        "rbac_enabled": bool(cfg.rbac_enabled),
        "operator_controls_enabled": False,
        "future_permissions_enabled": False,
    }


@auth_router.post("/login")
async def login(body: LoginRequest, request: Request, response: Response) -> dict[str, Any]:
    """
    Authenticate with username/password. Issues opaque session (cookie + token).

    Roles come ONLY from server configuration (INTELLISHIELD_AUTH_ROLES).
    Client-supplied role/permissions never authenticate or authorize.
    """
    cfg = load_auth_config()
    if not cfg.configured:
        logger.warning("authentication_not_configured")
        raise authentication_not_configured()

    key = _client_key(request)
    lim = _limiter(cfg)
    if not lim.allow(key):
        logger.info("authentication_rate_limited client=%s", key)
        raise rate_limited()

    username_ok = body.username == cfg.username
    password_ok = False
    if username_ok:
        password_ok = verify_password(body.password, cfg.password_hash)
    else:
        verify_password(body.password, cfg.password_hash)

    if not (username_ok and password_ok):
        logger.info("authentication_failure")
        raise authentication_failed()

    lim.reset(key)

    principal_id = f"user:{cfg.username}"
    # Server-derived roles only (least privilege default VIEWER via config)
    roles: list[str] = list(cfg.roles)
    rec = SESSION_STORE.create(
        principal_id=principal_id,
        username=cfg.username,
        roles=roles,
        ttl_seconds=cfg.session_ttl_seconds,
        authentication_method="password",
    )
    principal = rec.to_principal()
    try:
        request.state.principal = principal
    except Exception:
        pass

    _set_session_cookie(response, cfg, rec.session_id)
    logger.info(
        "authentication_success principal_id=%s method=password roles=%s",
        principal_id,
        ",".join(roles),
    )

    return {
        "authenticated": True,
        "principal": principal.to_public_dict(),
        "permissions": effective_permissions(principal),
        "session_token": rec.session_id,
        "expires_at": principal.expires_at,
        "token_type": "Bearer",
        "csrf_token": rec.csrf_token,
        **_authz_flags(cfg),
    }


@auth_router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    principal: Optional[Principal] = Depends(get_optional_principal),
) -> dict[str, Any]:
    """Invalidate current session if present. Idempotent."""
    cfg = load_auth_config()
    sid = None
    if principal and principal.session_id:
        sid = principal.session_id
    else:
        sid = request.cookies.get(COOKIE_NAME)

    revoked = SESSION_STORE.revoke(sid) if sid else False
    _clear_session_cookie(response, cfg)
    if revoked:
        logger.info(
            "logout principal_id=%s",
            principal.id if principal else "unknown",
        )
    return {
        "authenticated": False,
        "revoked": bool(revoked),
    }


@auth_router.get("/me")
async def me(
    principal: Optional[Principal] = Depends(get_optional_principal),
) -> dict[str, Any]:
    """
    Safe identity + authorization summary.

    Unauthenticated → authenticated: false (HTTP 200).
    """
    cfg = load_auth_config()
    flags = _authz_flags(cfg)
    if principal is None:
        return {
            "authenticated": False,
            "principal": None,
            "permissions": [],
            "authentication_configured": cfg.configured,
            **flags,
        }
    csrf = None
    if principal.session_id:
        rec = SESSION_STORE.get(principal.session_id)
        if rec:
            csrf = rec.csrf_token
    return {
        "authenticated": True,
        "principal": principal.to_public_dict(),
        "permissions": effective_permissions(principal),
        "authentication_configured": cfg.configured,
        "csrf_token": csrf,
        **flags,
    }


@auth_router.get("/status")
async def auth_status() -> dict[str, Any]:
    """Non-sensitive configuration status for Operator Readiness (no secrets)."""
    cfg = load_auth_config()
    return {
        "authentication_configured": cfg.configured,
        "authentication_enabled": cfg.enabled,
        "session_ttl_seconds": cfg.session_ttl_seconds if cfg.configured else None,
        "cookie_name": COOKIE_NAME if cfg.configured else None,
        "csrf_required_for_future_state_changing": True,
        "revocation": "server_side_session_invalidation",
        "roles_configured": list(cfg.roles) if cfg.configured else [],
        "future_permissions": sorted(p.value for p in FUTURE_PERMISSIONS),
        **_authz_flags(cfg),
    }


@auth_router.get("/authorization")
async def authorization_summary(
    principal: Principal = Depends(require_authenticated_principal),
) -> dict[str, Any]:
    """
    Authenticated authorization summary (401 if unauthenticated).

    Does not require a specific permission beyond authentication so any
    valid principal can inspect their own effective permissions.
    """
    cfg = load_auth_config()
    return {
        "authenticated": True,
        "principal": principal.to_public_dict(),
        "permissions": effective_permissions(principal),
        "future_permissions_enabled": False,
        **_authz_flags(cfg),
    }


@auth_router.get("/authorization/check")
async def authorization_check(
    request: Request,
    permission: str = Query(..., min_length=1, max_length=64),
    resource_type: Optional[str] = Query(default=None, max_length=64),
    resource_id: Optional[str] = Query(default=None, max_length=128),
    principal: Principal = Depends(require_authenticated_principal),
) -> dict[str, Any]:
    """
    Evaluate a single permission for the server-derived principal.

    - 401 if unauthenticated
    - 403 if authenticated but permission denied (including future/unknown)
    - 200 if ALLOW

    Client role/permission query params other than the checked permission name
    do not elevate access. X-Role / body roles are ignored.
    """
    # Explicitly ignore forged elevation
    _ = request.headers.get("x-role")
    _ = request.headers.get("x-permissions")

    decision = authorize(
        principal,
        permission,
        resource_type=resource_type,
        resource_id=resource_id,
    )
    log_decision(decision)
    if not decision.allow:
        raise forbidden_not_authorized()
    return {
        "allowed": True,
        "permission": decision.permission,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "principal": {"id": principal.id, "username": principal.username},
    }


@auth_router.get("/authorized/dashboard")
async def authorized_dashboard_probe(
    principal: Principal = Depends(require_permission(Permission.READ_DASHBOARD)),
) -> dict[str, Any]:
    """
    Read-only authorization probe requiring READ_DASHBOARD.

    Demonstrates require_permission dependency. Not an operator control.
    Observational SOC GETs remain public; this endpoint is opt-in protected.
    """
    return {
        "ok": True,
        "permission": Permission.READ_DASHBOARD.value,
        "principal": {"id": principal.id, "username": principal.username},
        "operator_controls_enabled": False,
    }


@auth_router.get("/authorized/investigate")
async def authorized_investigate_probe(
    principal: Principal = Depends(require_permission(Permission.INVESTIGATE_EVENTS)),
) -> dict[str, Any]:
    """Read-only probe requiring INVESTIGATE_EVENTS (VIEWER → 403, ANALYST+ → 200)."""
    return {
        "ok": True,
        "permission": Permission.INVESTIGATE_EVENTS.value,
        "principal": {"id": principal.id, "username": principal.username},
        "operator_controls_enabled": False,
    }
