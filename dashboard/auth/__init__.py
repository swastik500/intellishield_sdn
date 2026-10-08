"""
IntelliShield — Authentication (Phase 8) + Authorization / RBAC (Phase 9).

Phase 8: WHO ARE YOU?
Phase 9: WHAT ARE YOU ALLOWED TO DO? (not how to execute)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .authorization import AuthzDecision, authorize, effective_permissions
from .config import AuthConfig, load_auth_config
from .permissions import Permission
from .principal import Principal
from .roles import Role
from .sessions import SESSION_STORE

if TYPE_CHECKING:
    from .deps import (
        get_optional_principal,
        require_authenticated_principal,
        require_permission,
        resolve_principal,
    )
    from .routes import auth_router

__all__ = [
    "AuthConfig",
    "AuthzDecision",
    "Permission",
    "Principal",
    "Role",
    "SESSION_STORE",
    "auth_router",
    "authorize",
    "effective_permissions",
    "get_optional_principal",
    "load_auth_config",
    "require_authenticated_principal",
    "require_permission",
    "resolve_principal",
]


def __getattr__(name: str):
    """Lazy exports that require FastAPI."""
    if name == "auth_router":
        from .routes import auth_router as _router

        return _router
    if name == "get_optional_principal":
        from .deps import get_optional_principal as _fn

        return _fn
    if name == "require_authenticated_principal":
        from .deps import require_authenticated_principal as _fn

        return _fn
    if name == "require_permission":
        from .deps import require_permission as _fn

        return _fn
    if name == "resolve_principal":
        from .deps import resolve_principal as _fn

        return _fn
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
