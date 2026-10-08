"""Role definitions and authoritative role → permission mapping (Phase 9)."""

from __future__ import annotations

from enum import Enum
from typing import Dict, FrozenSet, Iterable, List, Set

from .permissions import ENABLED_PERMISSIONS, Permission


class Role(str, Enum):
    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    OPERATOR = "OPERATOR"
    ADMIN = "ADMIN"


_VIEWER_PERMS: FrozenSet[Permission] = frozenset(
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
    }
)

_ANALYST_EXTRA: FrozenSet[Permission] = frozenset(
    {
        Permission.INVESTIGATE_EVENTS,
        Permission.GENERATE_REPORTS,
    }
)

# Authoritative mapping. Future operational permissions are intentionally ABSENT
# from every role — they remain DEFINED but NOT ENABLED.
ROLE_PERMISSIONS: Dict[Role, FrozenSet[Permission]] = {
    Role.VIEWER: _VIEWER_PERMS,
    Role.ANALYST: frozenset(_VIEWER_PERMS | _ANALYST_EXTRA),
    # OPERATOR: analyst-equivalent reads only; EXECUTE_MITIGATION etc. not granted
    Role.OPERATOR: frozenset(_VIEWER_PERMS | _ANALYST_EXTRA),
    # ADMIN: no hidden superuser — only explicitly granted read/investigate perms
    Role.ADMIN: frozenset(_VIEWER_PERMS | _ANALYST_EXTRA),
}

KNOWN_ROLES: FrozenSet[Role] = frozenset(Role)

# Least-privilege default when config omits roles
DEFAULT_ROLE = Role.VIEWER


def parse_role(value: str) -> Role | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip().upper()
    # Phase 8 used informational "observer" — map to VIEWER for continuity
    if raw == "OBSERVER":
        return Role.VIEWER
    try:
        return Role(raw)
    except ValueError:
        return None


def parse_roles(values: Iterable[str]) -> tuple[List[Role], List[str]]:
    """
    Parse role names.

    Returns (known_roles, unknown_raw_names).
    Unknown names are returned for fail-closed evaluation.
    """
    known: List[Role] = []
    unknown: List[str] = []
    seen: Set[str] = set()
    for v in values or []:
        if not isinstance(v, str):
            unknown.append(str(v))
            continue
        key = v.strip()
        if not key or key.upper() in seen:
            continue
        seen.add(key.upper())
        role = parse_role(key)
        if role is None:
            unknown.append(key)
        else:
            known.append(role)
    return known, unknown


def permissions_for_roles(roles: Iterable[Role]) -> FrozenSet[Permission]:
    """Union of permissions for known roles, intersected with ENABLED set."""
    granted: Set[Permission] = set()
    for role in roles:
        granted |= set(ROLE_PERMISSIONS.get(role, frozenset()))
    # Never grant future/disabled permissions even if mistakenly mapped
    return frozenset(granted & ENABLED_PERMISSIONS)


def validate_role_names(names: Iterable[str]) -> List[str]:
    """Return list of invalid role names (empty if all valid)."""
    _, unknown = parse_roles(names)
    return unknown
