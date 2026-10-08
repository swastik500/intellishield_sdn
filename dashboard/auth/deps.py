"""FastAPI authentication + authorization dependencies."""

from __future__ import annotations

from typing import Callable, Optional

from fastapi import Cookie, Depends, Header, Request

from .authorization import authorize, log_decision
from .config import AuthConfig, load_auth_config
from .permissions import Permission
from .principal import Principal
from .sessions import SESSION_STORE


COOKIE_NAME = "is_session"


def get_auth_config() -> AuthConfig:
    return load_auth_config()


def _extract_bearer(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.strip().split(None, 1)
    if len(parts) != 2:
        return None
    scheme, token = parts[0], parts[1]
    if scheme.lower() != "bearer":
        return None
    token = token.strip()
    return token or None


def resolve_principal(
    request: Request,
    *,
    authorization: Optional[str] = None,
    session_cookie: Optional[str] = None,
) -> Optional[Principal]:
    """
    Derive principal from Authorization Bearer token or session cookie.

    Never trusts client-provided user_id / role / is_admin fields.
    """
    token = _extract_bearer(authorization)
    if not token and session_cookie:
        token = session_cookie
    if not token:
        token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None

    rec = SESSION_STORE.get(token)
    if not rec:
        return None
    principal = rec.to_principal()
    try:
        request.state.principal = principal
    except Exception:
        pass
    return principal


async def get_optional_principal(
    request: Request,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    is_session: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
) -> Optional[Principal]:
    """Optional identity — returns None if unauthenticated (no 401)."""
    return resolve_principal(
        request, authorization=authorization, session_cookie=is_session
    )


async def require_authenticated_principal(
    request: Request,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    is_session: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
) -> Principal:
    """Require authenticated principal; raises 401 if missing/invalid."""
    from .errors import authentication_required

    principal = resolve_principal(
        request, authorization=authorization, session_cookie=is_session
    )
    if principal is None:
        raise authentication_required()
    return principal


def require_permission(
    permission: Permission | str,
    *,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
) -> Callable:
    """
    FastAPI dependency factory: authenticate then authorize.

    - No/invalid credentials → 401
    - Authenticated but lacking permission → 403
    """

    async def _dependency(
        request: Request,
        principal: Principal = Depends(require_authenticated_principal),
    ) -> Principal:
        from .errors import forbidden_not_authorized

        # Client elevation headers/queries are ignored (never feed authorize()).
        _ = request.headers.get("x-role")
        _ = request.query_params.get("role")

        decision = authorize(
            principal,
            permission,
            resource_type=resource_type,
            resource_id=resource_id,
        )
        log_decision(decision)
        try:
            request.state.authz_decision = decision
        except Exception:
            pass
        if not decision.allow:
            if decision.reason == "UNAUTHENTICATED":
                from .errors import authentication_required

                raise authentication_required()
            raise forbidden_not_authorized()
        return principal

    return _dependency


CurrentPrincipal = Depends(require_authenticated_principal)
OptionalPrincipal = Depends(get_optional_principal)
