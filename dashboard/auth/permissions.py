"""Explicit permission vocabulary (Phase 9). Future ops remain DEFINED but NOT ENABLED."""

from __future__ import annotations

from enum import Enum
from typing import FrozenSet


class Permission(str, Enum):
    """Canonical permission identifiers. Values are stable API strings."""

    # Observational / analysis (ENABLED in Phase 9)
    READ_DASHBOARD = "READ_DASHBOARD"
    READ_TRAFFIC = "READ_TRAFFIC"
    READ_DETECTION = "READ_DETECTION"
    READ_ALERTS = "READ_ALERTS"
    READ_CORRELATION = "READ_CORRELATION"
    READ_FUSION = "READ_FUSION"
    READ_VERIFICATION = "READ_VERIFICATION"
    READ_RCA = "READ_RCA"
    READ_DIGITAL_TWIN = "READ_DIGITAL_TWIN"
    READ_HEALTH = "READ_HEALTH"
    READ_REPORTS = "READ_REPORTS"
    INVESTIGATE_EVENTS = "INVESTIGATE_EVENTS"
    GENERATE_REPORTS = "GENERATE_REPORTS"

    # Future Operator / admin (DEFINED — never granted in Phase 9)
    ACKNOWLEDGE_ALERT = "ACKNOWLEDGE_ALERT"
    EXECUTE_MITIGATION = "EXECUTE_MITIGATION"
    BLOCK_TARGET = "BLOCK_TARGET"
    UNBLOCK_TARGET = "UNBLOCK_TARGET"
    MANAGE_CONFIGURATION = "MANAGE_CONFIGURATION"
    MANAGE_RBAC = "MANAGE_RBAC"


# Permissions that authorization may currently GRANT
ENABLED_PERMISSIONS: FrozenSet[Permission] = frozenset(
    {
        Permission.READ_DASHBOARD,
        Permission.READ_TRAFFIC,
        Permission.READ_DETECTION,
        Permission.READ_ALERTS,
        Permission.READ_CORRELATION,
        Permission.READ_FUSION,
        Permission.READ_VERIFICATION,
        Permission.READ_RCA,
        Permission.READ_DIGITAL_TWIN,
        Permission.READ_HEALTH,
        Permission.READ_REPORTS,
        Permission.INVESTIGATE_EVENTS,
        Permission.GENERATE_REPORTS,
    }
)

# Defined for future Operator Mode — always DENY in Phase 9
FUTURE_PERMISSIONS: FrozenSet[Permission] = frozenset(
    {
        Permission.ACKNOWLEDGE_ALERT,
        Permission.EXECUTE_MITIGATION,
        Permission.BLOCK_TARGET,
        Permission.UNBLOCK_TARGET,
        Permission.MANAGE_CONFIGURATION,
        Permission.MANAGE_RBAC,
    }
)

ALL_PERMISSIONS: FrozenSet[Permission] = frozenset(Permission)


def parse_permission(value: str | Permission) -> Permission | None:
    """Return Permission or None if unknown (fail-closed at evaluate time)."""
    if isinstance(value, Permission):
        return value
    if not isinstance(value, str) or not value:
        return None
    try:
        return Permission(value.strip().upper())
    except ValueError:
        return None


def is_enabled_permission(perm: Permission) -> bool:
    return perm in ENABLED_PERMISSIONS
