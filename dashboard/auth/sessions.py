"""Opaque server-side session store with expiration and revocation."""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from .principal import Principal, iso_utc


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class SessionRecord:
    session_id: str
    principal_id: str
    username: str
    roles: list
    authentication_method: str
    created_at: datetime
    expires_at: datetime
    csrf_token: str = ""
    revoked: bool = False

    def is_active(self, now: Optional[datetime] = None) -> bool:
        n = now or _utcnow()
        if self.revoked:
            return False
        return self.expires_at > n

    def to_principal(self) -> Principal:
        return Principal(
            id=self.principal_id,
            username=self.username,
            authentication_method=self.authentication_method,
            authenticated_at=iso_utc(self.created_at),
            expires_at=iso_utc(self.expires_at),
            roles=list(self.roles),
            session_id=self.session_id,
        )


class SessionStore:
    """In-memory session store (process-local). Sufficient for Phase 8 foundation."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: Dict[str, SessionRecord] = {}

    def create(
        self,
        *,
        principal_id: str,
        username: str,
        roles: list,
        ttl_seconds: int,
        authentication_method: str = "password",
    ) -> SessionRecord:
        now = _utcnow()
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        rec = SessionRecord(
            session_id=sid,
            principal_id=principal_id,
            username=username,
            roles=list(roles or []),
            authentication_method=authentication_method,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            csrf_token=csrf,
            revoked=False,
        )
        with self._lock:
            self._sessions[sid] = rec
            self._purge_locked(now)
        return rec

    def get(self, session_id: Optional[str]) -> Optional[SessionRecord]:
        if not session_id:
            return None
        with self._lock:
            rec = self._sessions.get(session_id)
            if not rec:
                return None
            if not rec.is_active():
                # Expired / revoked — remove
                self._sessions.pop(session_id, None)
                return None
            return rec

    def revoke(self, session_id: Optional[str]) -> bool:
        if not session_id:
            return False
        with self._lock:
            rec = self._sessions.get(session_id)
            if not rec:
                return False
            rec.revoked = True
            self._sessions.pop(session_id, None)
            return True

    def revoke_all_for_principal(self, principal_id: str) -> int:
        with self._lock:
            victims = [sid for sid, r in self._sessions.items() if r.principal_id == principal_id]
            for sid in victims:
                self._sessions.pop(sid, None)
            return len(victims)

    def _purge_locked(self, now: datetime) -> None:
        dead = [sid for sid, r in self._sessions.items() if not r.is_active(now)]
        for sid in dead:
            self._sessions.pop(sid, None)


# Process singleton used by deps/routes
SESSION_STORE = SessionStore()
