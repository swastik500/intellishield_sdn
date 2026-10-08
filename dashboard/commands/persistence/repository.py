"""Durable repositories for commands, idempotency, and audits (Phase 11)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from ..models import Command, CommandStatus, Target, iso_utc, utcnow
from .db import PersistenceUnavailableError, connection, transaction


def _dt_to_str(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return iso_utc(dt)


def _str_to_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    s = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            from datetime import timezone

            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _loads(raw: Optional[str]) -> dict:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _dumps(obj: Any) -> str:
    return json.dumps(obj if obj is not None else {}, separators=(",", ":"), default=str)


def row_to_command(row: sqlite3.Row) -> Command:
    keys = set(row.keys())
    return Command(
        command_id=row["command_id"],
        action=row["action"],
        target=Target(type=row["target_type"], id=row["target_id"]),
        event_id=row["event_id"],
        principal_id=row["principal_id"],
        principal_username=row["principal_username"],
        reason=row["reason"],
        created_at=_str_to_dt(row["created_at"]) or utcnow(),
        expires_at=_str_to_dt(row["expires_at"]) or utcnow(),
        status=CommandStatus(row["status"]),
        idempotency_key=row["idempotency_key"],
        risk_level=row["risk_level"] or "LOW",
        confirmation_required=bool(row["confirmation_required"]),
        confirmation_token=row["confirmation_token"],
        confirmation_expires_at=_str_to_dt(row["confirmation_expires_at"]),
        confirmed_at=_str_to_dt(row["confirmed_at"]),
        confirmed_by=row["confirmed_by"],
        authorization=_loads(row["authorization_json"]),
        validation=_loads(row["validation_json"]),
        safety=_loads(row["safety_json"]),
        freshness=_loads(row["freshness_json"]),
        audit_id=row["audit_id"],
        failure_reason=row["failure_reason"],
        execution_enabled=bool(row["execution_enabled"]) if "execution_enabled" in keys else False,
        confirmation_used=bool(row["confirmation_used"]),
        version=int(row["version"] or 1),
        updated_at=_str_to_dt(row["updated_at"]),
        execution=_loads(row["execution_json"]) if "execution_json" in keys else {},
        execution_id=row["execution_id"] if "execution_id" in keys else None,
        executed_at=_str_to_dt(row["executed_at"]) if "executed_at" in keys else None,
    )


def insert_command(conn: sqlite3.Connection, cmd: Command) -> Command:
    now = iso_utc(cmd.updated_at or cmd.created_at or utcnow())
    conn.execute(
        """
        INSERT INTO operator_commands (
            command_id, action, risk_level, target_type, target_id, event_id,
            principal_id, principal_username, reason, status,
            created_at, updated_at, expires_at,
            confirmation_required, confirmation_token, confirmation_expires_at,
            confirmed_at, confirmed_by, confirmation_used, idempotency_key,
            authorization_json, validation_json, safety_json, freshness_json,
            audit_id, failure_reason, execution_enabled, version,
            execution_json, execution_id, executed_at
        ) VALUES (
            ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
        )
        """,
        (
            cmd.command_id,
            cmd.action,
            cmd.risk_level,
            cmd.target.type,
            cmd.target.id,
            cmd.event_id,
            cmd.principal_id,
            cmd.principal_username,
            cmd.reason,
            cmd.status.value,
            _dt_to_str(cmd.created_at),
            now,
            _dt_to_str(cmd.expires_at),
            1 if cmd.confirmation_required else 0,
            cmd.confirmation_token,
            _dt_to_str(cmd.confirmation_expires_at),
            _dt_to_str(cmd.confirmed_at),
            cmd.confirmed_by,
            1 if cmd.confirmation_used else 0,
            cmd.idempotency_key,
            _dumps(cmd.authorization),
            _dumps(cmd.validation),
            _dumps(cmd.safety),
            _dumps(cmd.freshness),
            cmd.audit_id,
            cmd.failure_reason,
            1 if cmd.execution_enabled else 0,
            int(getattr(cmd, "version", 1) or 1),
            _dumps(cmd.execution),
            cmd.execution_id,
            _dt_to_str(cmd.executed_at),
        ),
    )
    cmd.updated_at = _str_to_dt(now)
    cmd.version = int(getattr(cmd, "version", 1) or 1)
    return cmd


def update_command(
    conn: sqlite3.Connection, cmd: Command, *, expected_version: Optional[int] = None
) -> Command:
    exp = expected_version if expected_version is not None else int(getattr(cmd, "version", 1) or 1)
    now = iso_utc()
    cur = conn.execute(
        """
        UPDATE operator_commands SET
            action=?, risk_level=?, target_type=?, target_id=?, event_id=?,
            principal_id=?, principal_username=?, reason=?, status=?,
            updated_at=?, expires_at=?,
            confirmation_required=?, confirmation_token=?, confirmation_expires_at=?,
            confirmed_at=?, confirmed_by=?, confirmation_used=?, idempotency_key=?,
            authorization_json=?, validation_json=?, safety_json=?, freshness_json=?,
            audit_id=?, failure_reason=?, execution_enabled=?, version=version+1,
            execution_json=?, execution_id=?, executed_at=?
        WHERE command_id=? AND version=?
        """,
        (
            cmd.action,
            cmd.risk_level,
            cmd.target.type,
            cmd.target.id,
            cmd.event_id,
            cmd.principal_id,
            cmd.principal_username,
            cmd.reason,
            cmd.status.value,
            now,
            _dt_to_str(cmd.expires_at),
            1 if cmd.confirmation_required else 0,
            cmd.confirmation_token,
            _dt_to_str(cmd.confirmation_expires_at),
            _dt_to_str(cmd.confirmed_at),
            cmd.confirmed_by,
            1 if cmd.confirmation_used else 0,
            cmd.idempotency_key,
            _dumps(cmd.authorization),
            _dumps(cmd.validation),
            _dumps(cmd.safety),
            _dumps(cmd.freshness),
            cmd.audit_id,
            cmd.failure_reason,
            1 if cmd.execution_enabled else 0,
            _dumps(cmd.execution),
            cmd.execution_id,
            _dt_to_str(cmd.executed_at),
            cmd.command_id,
            exp,
        ),
    )
    if cur.rowcount != 1:
        raise PersistenceUnavailableError("concurrent_modification")
    cmd.version = exp + 1
    cmd.updated_at = _str_to_dt(now)
    return cmd


def get_command(conn: sqlite3.Connection, command_id: str) -> Optional[Command]:
    row = conn.execute(
        "SELECT * FROM operator_commands WHERE command_id=?",
        (command_id,),
    ).fetchone()
    return row_to_command(row) if row else None


def list_commands(
    conn: sqlite3.Connection,
    *,
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None,
    principal_id: Optional[str] = None,
) -> Tuple[List[Command], int]:
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    clauses: list[str] = []
    params: list[Any] = []
    if status:
        clauses.append("status=?")
        params.append(status)
    if principal_id:
        clauses.append("principal_id=?")
        params.append(principal_id)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    total = conn.execute(
        f"SELECT COUNT(*) AS c FROM operator_commands {where}", params
    ).fetchone()["c"]
    rows = conn.execute(
        f"""
        SELECT * FROM operator_commands {where}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        """,
        [*params, limit, offset],
    ).fetchall()
    return [row_to_command(r) for r in rows], int(total)


def insert_idempotency(
    conn: sqlite3.Connection,
    *,
    principal_id: str,
    action: str,
    target_type: str,
    target_id: str,
    idempotency_key: str,
    command_id: str,
) -> None:
    try:
        conn.execute(
            """
            INSERT INTO operator_idempotency (
                principal_id, action, target_type, target_id, idempotency_key,
                command_id, created_at
            ) VALUES (?,?,?,?,?,?,?)
            """,
            (
                principal_id,
                action,
                target_type,
                target_id,
                idempotency_key,
                command_id,
                iso_utc(),
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise PersistenceUnavailableError("idempotency_conflict") from exc


def find_idempotent(
    conn: sqlite3.Connection,
    *,
    principal_id: str,
    action: str,
    target_type: str,
    target_id: str,
    idempotency_key: str,
) -> Optional[Command]:
    row = conn.execute(
        """
        SELECT command_id FROM operator_idempotency
        WHERE principal_id=? AND action=? AND target_type=? AND target_id=? AND idempotency_key=?
        """,
        (principal_id, action, target_type, target_id, idempotency_key),
    ).fetchone()
    if not row:
        return None
    return get_command(conn, row["command_id"])


def append_audit(conn: sqlite3.Connection, record: Dict[str, Any]) -> Dict[str, Any]:
    aid = record.get("audit_id")
    if not aid:
        raise PersistenceUnavailableError("audit_id_required")
    existing = conn.execute(
        "SELECT 1 FROM operator_audits WHERE audit_id=?", (aid,)
    ).fetchone()
    if existing:
        raise PersistenceUnavailableError("audit_immutable_duplicate")
    conn.execute(
        """
        INSERT INTO operator_audits (
            audit_id, command_id, principal_id, action, status, event_id,
            previous_status, new_status, result, failure_reason, source,
            parent_audit_id, payload_json, created_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            aid,
            record.get("command_id"),
            record.get("principal_id"),
            record.get("action"),
            record.get("status"),
            record.get("event_id"),
            record.get("previous_status"),
            record.get("new_status") or record.get("status"),
            record.get("result"),
            record.get("failure_reason"),
            record.get("source"),
            record.get("parent_audit_id"),
            _dumps(record),
            record.get("requested_at")
            or record.get("finalized_at")
            or record.get("validated_at")
            or iso_utc(),
        ),
    )
    return dict(record)


def insert_execution(conn: sqlite3.Connection, record: Dict[str, Any]) -> Dict[str, Any]:
    eid = record.get("execution_id") or record.get("operation_id")
    if not eid:
        raise PersistenceUnavailableError("execution_id_required")
    conn.execute(
        """
        INSERT INTO operator_executions (
            execution_id, command_id, principal_id, action, target_type, target_id,
            event_id, started_at, completed_at, success, result_summary,
            failure_code, failure_reason, payload_json, created_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            eid,
            record.get("command_id"),
            record.get("principal_id"),
            record.get("action"),
            record.get("target_type"),
            record.get("target_id"),
            record.get("event_id"),
            record.get("started_at") or iso_utc(),
            record.get("completed_at"),
            1 if record.get("success") else 0,
            record.get("result_summary"),
            record.get("failure_code"),
            record.get("failure_reason"),
            _dumps(record),
            iso_utc(),
        ),
    )
    return dict(record)


def list_audits(
    conn: sqlite3.Connection,
    *,
    limit: int = 50,
    offset: int = 0,
    command_id: Optional[str] = None,
) -> Tuple[List[dict], int]:
    limit = max(1, min(int(limit), 200))
    offset = max(0, int(offset))
    clauses: list[str] = []
    params: list[Any] = []
    if command_id:
        clauses.append("command_id=?")
        params.append(command_id)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    total = conn.execute(
        f"SELECT COUNT(*) AS c FROM operator_audits {where}", params
    ).fetchone()["c"]
    rows = conn.execute(
        f"""
        SELECT payload_json FROM operator_audits {where}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        """,
        [*params, limit, offset],
    ).fetchall()
    return [_loads(r["payload_json"]) for r in rows], int(total)


def save_command(cmd: Command, *, create: bool = False) -> Command:
    try:
        with transaction(immediate=True) as conn:
            if create:
                insert_command(conn, cmd)
                if cmd.idempotency_key:
                    insert_idempotency(
                        conn,
                        principal_id=cmd.principal_id,
                        action=cmd.action,
                        target_type=cmd.target.type,
                        target_id=cmd.target.id,
                        idempotency_key=cmd.idempotency_key,
                        command_id=cmd.command_id,
                    )
            else:
                update_command(conn, cmd)
            return cmd
    except PersistenceUnavailableError:
        raise
    except Exception as exc:
        raise PersistenceUnavailableError(str(exc)) from exc


def load_command(command_id: str) -> Optional[Command]:
    try:
        with connection() as conn:
            return get_command(conn, command_id)
    except PersistenceUnavailableError:
        raise
    except Exception as exc:
        raise PersistenceUnavailableError(str(exc)) from exc


def lookup_idempotent(
    *,
    principal_id: str,
    action: str,
    target_type: str,
    target_id: str,
    idempotency_key: str,
) -> Optional[Command]:
    try:
        with connection() as conn:
            return find_idempotent(
                conn,
                principal_id=principal_id,
                action=action,
                target_type=target_type,
                target_id=target_id,
                idempotency_key=idempotency_key,
            )
    except PersistenceUnavailableError:
        raise
    except Exception as exc:
        raise PersistenceUnavailableError(str(exc)) from exc
