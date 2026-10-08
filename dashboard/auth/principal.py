"""Authenticated principal — server-derived identity (not browser-trusted)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Principal:
    """
    Server-side identity representation.

    Roles are assigned by the authentication layer (server config / session).
    Authorization decisions are made by dashboard.auth.authorization (Phase 9),
    never by trusting client-supplied role or permission claims.
    """

    id: str
    username: str
    authentication_method: str
    authenticated_at: str
    expires_at: str
    roles: List[str] = field(default_factory=list)
    session_id: Optional[str] = None

    def to_public_dict(self) -> dict:
        """Safe identity payload — never includes secrets or credentials."""
        return {
            "id": self.id,
            "username": self.username,
            "authentication_method": self.authentication_method,
            "authenticated_at": self.authenticated_at,
            "expires_at": self.expires_at,
            "roles": list(self.roles),
        }


def iso_utc(dt: Optional[datetime] = None) -> str:
    d = dt or _utcnow()
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
