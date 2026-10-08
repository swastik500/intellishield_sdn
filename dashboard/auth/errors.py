"""Consistent authentication error responses (no credential leakage)."""

from __future__ import annotations

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse


class AuthError(HTTPException):
    """HTTPException whose JSON body is ``{"error": {...}}`` (not nested under detail)."""

    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(
            status_code=status_code,
            detail={"error": {"code": code, "message": message}},
        )
        self.code = code
        self.message = message


async def auth_exception_handler(_request: Request, exc: AuthError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content=exc.detail)


def authentication_required() -> AuthError:
    return AuthError(
        status_code=401,
        code="AUTHENTICATION_REQUIRED",
        message="Authentication required",
    )


def authentication_failed() -> AuthError:
    """Generic failure — does not reveal whether username exists."""
    return AuthError(
        status_code=401,
        code="AUTHENTICATION_FAILED",
        message="Authentication failed",
    )


def authentication_not_configured() -> AuthError:
    return AuthError(
        status_code=503,
        code="AUTHENTICATION_NOT_CONFIGURED",
        message="Authentication is not configured",
    )


def rate_limited() -> AuthError:
    return AuthError(
        status_code=429,
        code="AUTHENTICATION_RATE_LIMITED",
        message="Too many authentication attempts. Try again later.",
    )


def forbidden_not_authorized() -> AuthError:
    """Reserved for Phase 9 RBAC — authenticated but lacking permission."""
    return AuthError(
        status_code=403,
        code="FORBIDDEN",
        message="Insufficient permissions",
    )
