"""Command domain model and explicit state machine (Phase 10)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Set, Tuple


class CommandStatus(str, Enum):
    REQUESTED = "REQUESTED"
    VALIDATING = "VALIDATING"
    AUTHORIZED = "AUTHORIZED"
    SAFETY_CHECK = "SAFETY_CHECK"
    AWAITING_CONFIRMATION = "AWAITING_CONFIRMATION"
    CONFIRMED = "CONFIRMED"
    READY_FOR_EXECUTION = "READY_FOR_EXECUTION"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    EXECUTION_DISABLED = "EXECUTION_DISABLED"
    DENIED = "DENIED"
    INVALID = "INVALID"
    EXPIRED = "EXPIRED"
    STALE = "STALE"
    DUPLICATE = "DUPLICATE"
    CANCELLED = "CANCELLED"
    SAFETY_BLOCKED = "SAFETY_BLOCKED"
    FAILED = "FAILED"


# Valid transitions (fail closed — anything else rejected)
_TRANSITIONS: Dict[CommandStatus, Set[CommandStatus]] = {
    CommandStatus.REQUESTED: {CommandStatus.VALIDATING, CommandStatus.INVALID, CommandStatus.DENIED},
    CommandStatus.VALIDATING: {
        CommandStatus.AUTHORIZED,
        CommandStatus.INVALID,
        CommandStatus.DENIED,
        CommandStatus.EXPIRED,
        CommandStatus.DUPLICATE,
    },
    CommandStatus.AUTHORIZED: {
        CommandStatus.SAFETY_CHECK,
        CommandStatus.DENIED,
        CommandStatus.EXPIRED,
    },
    CommandStatus.SAFETY_CHECK: {
        CommandStatus.AWAITING_CONFIRMATION,
        CommandStatus.READY_FOR_EXECUTION,  # low-risk, no confirmation
        CommandStatus.SAFETY_BLOCKED,
        CommandStatus.STALE,
        CommandStatus.EXPIRED,
        CommandStatus.EXECUTION_DISABLED,
    },
    CommandStatus.AWAITING_CONFIRMATION: {
        CommandStatus.CONFIRMED,
        CommandStatus.EXPIRED,
        CommandStatus.CANCELLED,
        CommandStatus.DUPLICATE,
    },
    CommandStatus.CONFIRMED: {
        CommandStatus.READY_FOR_EXECUTION,
        CommandStatus.EXPIRED,
        CommandStatus.SAFETY_BLOCKED,
    },
    CommandStatus.READY_FOR_EXECUTION: {
        CommandStatus.EXECUTING,  # Phase 12 allowlisted path
        CommandStatus.EXECUTION_DISABLED,  # non-allowlisted / Phase 10–11 path
        CommandStatus.EXPIRED,
        CommandStatus.FAILED,
    },
    CommandStatus.EXECUTING: {
        CommandStatus.EXECUTED,
        CommandStatus.FAILED,
    },
    CommandStatus.EXECUTED: set(),
    CommandStatus.EXECUTION_DISABLED: set(),
    CommandStatus.DENIED: set(),
    CommandStatus.INVALID: set(),
    CommandStatus.EXPIRED: set(),
    CommandStatus.STALE: set(),
    CommandStatus.DUPLICATE: set(),
    CommandStatus.CANCELLED: set(),
    CommandStatus.SAFETY_BLOCKED: set(),
    CommandStatus.FAILED: set(),
}


def can_transition(current: CommandStatus, new: CommandStatus) -> bool:
    return new in _TRANSITIONS.get(current, set())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(dt: Optional[datetime] = None) -> str:
    d = dt or utcnow()
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class Target:
    type: str
    id: str

    def to_dict(self) -> dict:
        return {"type": self.type, "id": self.id}


@dataclass
class Command:
    command_id: str
    action: str
    target: Target
    event_id: Optional[str]
    principal_id: str
    principal_username: str
    reason: str
    created_at: datetime
    expires_at: datetime
    status: CommandStatus
    idempotency_key: Optional[str] = None
    risk_level: str = "LOW"
    confirmation_required: bool = False
    confirmation_token: Optional[str] = None
    confirmation_expires_at: Optional[datetime] = None
    confirmed_at: Optional[datetime] = None
    confirmed_by: Optional[str] = None
    authorization: Dict[str, Any] = field(default_factory=dict)
    validation: Dict[str, Any] = field(default_factory=dict)
    safety: Dict[str, Any] = field(default_factory=dict)
    freshness: Dict[str, Any] = field(default_factory=dict)
    audit_id: Optional[str] = None
    failure_reason: Optional[str] = None
    execution_enabled: bool = False  # True only for Phase 12 allowlisted actions
    confirmation_used: bool = False
    version: int = 1  # optimistic concurrency (Phase 11)
    updated_at: Optional[datetime] = None
    execution: Dict[str, Any] = field(default_factory=dict)
    execution_id: Optional[str] = None
    executed_at: Optional[datetime] = None

    def transition(self, new_status: CommandStatus, *, reason: Optional[str] = None) -> None:
        if not can_transition(self.status, new_status):
            raise InvalidTransitionError(self.status, new_status)
        self.status = new_status
        self.updated_at = utcnow()
        if reason:
            self.failure_reason = reason

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        n = now or utcnow()
        return n > self.expires_at

    def to_public_dict(self) -> dict:
        return {
            "command_id": self.command_id,
            "action": self.action,
            "target": self.target.to_dict(),
            "event_id": self.event_id,
            "principal_id": self.principal_id,
            "principal_username": self.principal_username,
            "reason": self.reason,
            "created_at": iso_utc(self.created_at),
            "expires_at": iso_utc(self.expires_at),
            "status": self.status.value,
            "risk_level": self.risk_level,
            "confirmation_required": self.confirmation_required,
            "confirmation_expires_at": iso_utc(self.confirmation_expires_at)
            if self.confirmation_expires_at
            else None,
            "confirmed_at": iso_utc(self.confirmed_at) if self.confirmed_at else None,
            "authorization": dict(self.authorization),
            "validation": dict(self.validation),
            "safety": dict(self.safety),
            "freshness": dict(self.freshness),
            "audit_id": self.audit_id,
            "failure_reason": self.failure_reason,
            "execution_enabled": bool(self.execution_enabled),
            "idempotency_key": self.idempotency_key,
            "execution": dict(self.execution) if self.execution else {},
            "execution_id": self.execution_id,
            "executed_at": iso_utc(self.executed_at) if self.executed_at else None,
            "executed": self.status == CommandStatus.EXECUTED,
        }


class InvalidTransitionError(Exception):
    def __init__(self, current: CommandStatus, attempted: CommandStatus):
        self.current = current
        self.attempted = attempted
        super().__init__(f"Invalid transition {current.value} → {attempted.value}")
