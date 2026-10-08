"""
Central authorization evaluation — fail-closed, least-privilege (Phase 9).

Does NOT execute Operator Mode actions. ALLOW never connects to mitigation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from .permissions import (
    FUTURE_PERMISSIONS,
    Permission,
    parse_permission,
)
from .principal import Principal
from .roles import parse_roles, permissions_for_roles

logger = logging.getLogger("intellishield.authz")


class AuthzReason:
    ALLOWED = "ALLOWED"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    UNKNOWN_ROLE = "UNKNOWN_ROLE"
    UNKNOWN_PERMISSION = "UNKNOWN_PERMISSION"
    MISSING_PERMISSION = "MISSING_PERMISSION"
    POLICY_DENIED = "POLICY_DENIED"  # future / disabled permission
    INVALID_CONTEXT = "INVALID_CONTEXT"


@dataclass(frozen=True)
class AuthzDecision:
    """Internal authorization decision (audit-ready; not fully exposed to clients)."""

    allow: bool
    reason: str
    principal_id: Optional[str]
    permission: Optional[str]
    resource_type: Optional[str]
    resource_id: Optional[str]
    timestamp: str

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "permission": self.permission,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "decision": "ALLOW" if self.allow else "DENY",
            "reason": self.reason,
            "timestamp": self.timestamp,
        }


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _deny(
    *,
    reason: str,
    principal_id: Optional[str],
    permission: Optional[str],
    resource_type: Optional[str],
    resource_id: Optional[str],
) -> AuthzDecision:
    return AuthzDecision(
        allow=False,
        reason=reason,
        principal_id=principal_id,
        permission=permission,
        resource_type=resource_type,
        resource_id=resource_id,
        timestamp=_utcnow_iso(),
    )


def authorize(
    principal: Optional[Principal],
    permission: str | Permission,
    *,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
) -> AuthzDecision:
    """
    Evaluate whether principal may perform permission on optional resource.

    Fail-closed: unknown role, unknown permission, missing principal → DENY.
    Future permissions are always DENY (POLICY_DENIED) even for OPERATOR/ADMIN.
    """
    pid = principal.id if principal else None
    perm_label = permission.value if isinstance(permission, Permission) else str(permission)

    if principal is None:
        return _deny(
            reason=AuthzReason.UNAUTHENTICATED,
            principal_id=None,
            permission=perm_label,
            resource_type=resource_type,
            resource_id=resource_id,
        )

    parsed = parse_permission(permission)
    if parsed is None:
        return _deny(
            reason=AuthzReason.UNKNOWN_PERMISSION,
            principal_id=pid,
            permission=perm_label,
            resource_type=resource_type,
            resource_id=resource_id,
        )

    # Future / not-enabled permissions — never ALLOW
    if parsed in FUTURE_PERMISSIONS:
        return _deny(
            reason=AuthzReason.POLICY_DENIED,
            principal_id=pid,
            permission=parsed.value,
            resource_type=resource_type,
            resource_id=resource_id,
        )

    roles_raw: Sequence[str] = list(principal.roles or [])
    if not roles_raw:
        return _deny(
            reason=AuthzReason.UNKNOWN_ROLE,
            principal_id=pid,
            permission=parsed.value,
            resource_type=resource_type,
            resource_id=resource_id,
        )

    known_roles, unknown = parse_roles(roles_raw)
    if unknown:
        # Any unknown role → fail closed (do not silently ignore)
        return _deny(
            reason=AuthzReason.UNKNOWN_ROLE,
            principal_id=pid,
            permission=parsed.value,
            resource_type=resource_type,
            resource_id=resource_id,
        )
    if not known_roles:
        return _deny(
            reason=AuthzReason.UNKNOWN_ROLE,
            principal_id=pid,
            permission=parsed.value,
            resource_type=resource_type,
            resource_id=resource_id,
        )

    granted = permissions_for_roles(known_roles)
    if parsed not in granted:
        return _deny(
            reason=AuthzReason.MISSING_PERMISSION,
            principal_id=pid,
            permission=parsed.value,
            resource_type=resource_type,
            resource_id=resource_id,
        )

    # Resource-level hook: Phase 9 accepts any resource when permission granted.
    # Invalid empty resource_type with resource_id is treated as invalid context.
    if resource_id is not None and resource_type is not None:
        if not str(resource_type).strip() or not str(resource_id).strip():
            return _deny(
                reason=AuthzReason.INVALID_CONTEXT,
                principal_id=pid,
                permission=parsed.value,
                resource_type=resource_type,
                resource_id=resource_id,
            )

    return AuthzDecision(
        allow=True,
        reason=AuthzReason.ALLOWED,
        principal_id=pid,
        permission=parsed.value,
        resource_type=resource_type,
        resource_id=resource_id,
        timestamp=_utcnow_iso(),
    )


def effective_permissions(principal: Optional[Principal]) -> list[str]:
    """Enabled permissions for principal; empty if unauthenticated or fail-closed."""
    if principal is None:
        return []
    known, unknown = parse_roles(principal.roles or [])
    if unknown or not known:
        return []
    return sorted(p.value for p in permissions_for_roles(known))


def log_decision(decision: AuthzDecision) -> None:
    """Safe audit log — no tokens/secrets."""
    logger.info(
        "authorization_decision decision=%s reason=%s principal_id=%s permission=%s resource=%s/%s",
        "ALLOW" if decision.allow else "DENY",
        decision.reason,
        decision.principal_id or "-",
        decision.permission or "-",
        decision.resource_type or "-",
        decision.resource_id or "-",
    )
