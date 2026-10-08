"""Append-only audit records for commands (Phase 10/11).

Phase 11: durable SQLite persistence. Records are immutable from the app.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .models import Command
from .store import AUDIT_STORE


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def create_audit_record(
    command: Command,
    *,
    source: str = "operator_command",
    extra: Optional[Dict[str, Any]] = None,
    previous_status: Optional[str] = None,
) -> dict:
    """Server-generated audit record. Never trusts client audit fields."""
    record = {
        "audit_id": f"aud_{secrets.token_urlsafe(16)}",
        "command_id": command.command_id,
        "principal_id": command.principal_id,
        "action": command.action,
        "target_type": command.target.type,
        "target_id": command.target.id,
        "event_id": command.event_id,
        "reason": command.reason,
        "requested_at": _iso(),
        "validated_at": None,
        "authorized_at": None,
        "confirmed_at": None,
        "finalized_at": None,
        "status": command.status.value,
        "previous_status": previous_status,
        "new_status": command.status.value,
        "authorization_result": dict(command.authorization),
        "safety_result": dict(command.safety),
        "execution_result": {
            "executed": False,
            "execution_enabled": False,
            "detail": "Phase 11 — execution disabled",
        },
        "failure_reason": command.failure_reason,
        "source": source,
        "result": command.status.value,
    }
    if extra:
        for k, v in extra.items():
            if k not in {"audit_id", "command_id", "principal_id"}:
                record[k] = v
    return AUDIT_STORE.append(record)


def append_audit_snapshot(
    command: Command, *, previous_status: Optional[str] = None
) -> dict:
    """
    Append a new audit event reflecting current command state.

    Records are immutable; follow-up rows link via command_id / parent_audit_id.
    """
    record = {
        "audit_id": f"aud_{secrets.token_urlsafe(16)}",
        "command_id": command.command_id,
        "principal_id": command.principal_id,
        "action": command.action,
        "target_type": command.target.type,
        "target_id": command.target.id,
        "event_id": command.event_id,
        "reason": command.reason,
        "requested_at": None,
        "validated_at": _iso() if command.validation else None,
        "authorized_at": _iso() if command.authorization else None,
        "confirmed_at": (
            command.confirmed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            if command.confirmed_at
            else None
        ),
        "finalized_at": _iso()
        if command.status.value
        in {
            "READY_FOR_EXECUTION",
            "EXECUTION_DISABLED",
            "DENIED",
            "INVALID",
            "EXPIRED",
            "SAFETY_BLOCKED",
            "DUPLICATE",
        }
        else None,
        "status": command.status.value,
        "previous_status": previous_status,
        "new_status": command.status.value,
        "authorization_result": dict(command.authorization),
        "safety_result": dict(command.safety),
        "execution_result": {
            "executed": False,
            "execution_enabled": False,
            "detail": "Phase 11 — execution disabled",
        },
        "failure_reason": command.failure_reason,
        "source": "operator_command",
        "parent_audit_id": command.audit_id,
        "result": command.status.value,
    }
    return AUDIT_STORE.append(record)
