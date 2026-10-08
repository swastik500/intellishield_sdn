"""Durable command + audit stores (Phase 11).

Replaces Phase 10 in-memory stores. SQLite is the source of truth.
No silent fallback to process-local dictionaries.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Tuple

from .models import Command
from .persistence import PersistenceUnavailableError, ensure_schema, reset_initialized_cache
from .persistence import repo
from .persistence.db import connection, get_db_path, transaction

logger = logging.getLogger("intellishield.commands.store")


class CommandStore:
    """Durable command store backed by SQLite (multi-process safe)."""

    def put(self, command: Command, *, create: bool = False) -> Command:
        try:
            return repo.save_command(command, create=create)
        except PersistenceUnavailableError:
            raise
        except Exception as exc:
            logger.error(
                "command_persist_failed command_id=%s create=%s err=%s",
                getattr(command, "command_id", None),
                create,
                type(exc).__name__,
            )
            raise PersistenceUnavailableError(str(exc)) from exc

    def get(self, command_id: str) -> Optional[Command]:
        return repo.load_command(command_id)

    def find_idempotent(
        self,
        *,
        principal_id: str,
        action: str,
        target_type: str,
        target_id: str,
        idempotency_key: str,
    ) -> Optional[Command]:
        return repo.lookup_idempotent(
            principal_id=principal_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            idempotency_key=idempotency_key,
        )

    def list_recent(
        self,
        limit: int = 50,
        *,
        offset: int = 0,
        status: Optional[str] = None,
        principal_id: Optional[str] = None,
    ) -> List[Command]:
        try:
            with connection() as conn:
                items, _total = repo.list_commands(
                    conn,
                    limit=limit,
                    offset=offset,
                    status=status,
                    principal_id=principal_id,
                )
                return items
        except PersistenceUnavailableError:
            raise
        except Exception as exc:
            raise PersistenceUnavailableError(str(exc)) from exc

    def list_page(
        self,
        limit: int = 50,
        *,
        offset: int = 0,
        status: Optional[str] = None,
        principal_id: Optional[str] = None,
    ) -> Tuple[List[Command], int]:
        try:
            with connection() as conn:
                return repo.list_commands(
                    conn,
                    limit=limit,
                    offset=offset,
                    status=status,
                    principal_id=principal_id,
                )
        except PersistenceUnavailableError:
            raise
        except Exception as exc:
            raise PersistenceUnavailableError(str(exc)) from exc

    def clear(self) -> None:
        """Test helper — wipe command + idempotency tables (not for production use)."""
        ensure_schema()
        with transaction(immediate=True) as conn:
            conn.execute("DELETE FROM operator_idempotency")
            conn.execute("DELETE FROM operator_commands")


class AuditStore:
    """Append-only durable audit log. No update/delete API."""

    def append(self, record: dict) -> dict:
        try:
            with transaction(immediate=True) as conn:
                return repo.append_audit(conn, record)
        except PersistenceUnavailableError as exc:
            if "audit_immutable" in str(exc):
                raise ValueError("audit_id already exists (immutable)") from exc
            raise
        except Exception as exc:
            logger.error(
                "audit_persist_failed audit_id=%s err=%s",
                record.get("audit_id"),
                type(exc).__name__,
            )
            raise PersistenceUnavailableError(str(exc)) from exc

    def get(self, audit_id: str) -> Optional[dict]:
        try:
            with connection() as conn:
                row = conn.execute(
                    "SELECT payload_json FROM operator_audits WHERE audit_id=?",
                    (audit_id,),
                ).fetchone()
                if not row:
                    return None
                return repo._loads(row["payload_json"])
        except PersistenceUnavailableError:
            raise
        except Exception as exc:
            raise PersistenceUnavailableError(str(exc)) from exc

    def list_recent(self, limit: int = 50, *, offset: int = 0) -> List[dict]:
        try:
            with connection() as conn:
                items, _ = repo.list_audits(conn, limit=limit, offset=offset)
                return items
        except PersistenceUnavailableError:
            raise
        except Exception as exc:
            raise PersistenceUnavailableError(str(exc)) from exc

    def list_page(
        self, limit: int = 50, *, offset: int = 0, command_id: Optional[str] = None
    ) -> Tuple[List[dict], int]:
        try:
            with connection() as conn:
                return repo.list_audits(
                    conn, limit=limit, offset=offset, command_id=command_id
                )
        except PersistenceUnavailableError:
            raise
        except Exception as exc:
            raise PersistenceUnavailableError(str(exc)) from exc

    def by_command(self, command_id: str) -> List[dict]:
        items, _ = self.list_page(limit=200, offset=0, command_id=command_id)
        return items

    def clear(self) -> None:
        """Test helper — wipe audit table."""
        ensure_schema()
        with transaction(immediate=True) as conn:
            conn.execute("DELETE FROM operator_audits")


COMMAND_STORE = CommandStore()
AUDIT_STORE = AuditStore()


def reset_persistence_for_tests(db_path: Optional[str] = None) -> None:
    """Point at a fresh temp DB and clear init cache (tests only)."""
    import os

    reset_initialized_cache()
    if db_path is not None:
        os.environ["INTELLISHIELD_COMMAND_DB_PATH"] = str(db_path)
    path = get_db_path()
    if path.exists():
        try:
            path.unlink()
        except OSError:
            pass
        for suffix in ("-wal", "-shm"):
            side = path.with_name(path.name + suffix)
            try:
                if side.exists():
                    side.unlink()
            except OSError:
                pass
    reset_initialized_cache()
    ensure_schema(path)
