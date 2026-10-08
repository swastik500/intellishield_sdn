"""Safety gate — fail-closed aggregate evaluation (Phase 10–12)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from .actions import ActionSpec, is_execution_allowlisted
from .freshness import FreshnessResult, FreshnessStatus
from .models import Command


class SafetyState:
    SAFE = "SAFE"
    BLOCKED = "BLOCKED"
    NOT_READY = "NOT_READY"


@dataclass
class SafetyResult:
    state: str
    reason: str
    execution_enabled: bool = False
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "reason": self.reason,
            # Reflect allowlisted Phase 12 flag only — never invent True
            "execution_enabled": bool(self.execution_enabled),
            "details": self.details or {},
        }


def evaluate_safety(
    command: Command,
    spec: ActionSpec,
    *,
    authz_allow: bool,
    validation_ok: bool,
    freshness: FreshnessResult,
    confirmation_ok: Optional[bool] = None,
    audit_ok: bool = True,
) -> SafetyResult:
    """
    Aggregate safety.

    Phase 12: allowlisted non-mutating actions may have execution_enabled=True.
    Mutating / non-allowlisted execution flags are blocked.
    """
    if not validation_ok:
        return SafetyResult(SafetyState.BLOCKED, "validation_failed")
    if not authz_allow:
        return SafetyResult(SafetyState.BLOCKED, "authorization_denied")
    if command.is_expired():
        return SafetyResult(SafetyState.BLOCKED, "command_expired")

    if freshness.blocks_high_risk and spec.risk_level.value in {"HIGH", "CRITICAL"}:
        return SafetyResult(
            SafetyState.BLOCKED,
            f"freshness_{freshness.status.lower()}",
            details=freshness.to_dict(),
        )
    if freshness.status == FreshnessStatus.STALE:
        return SafetyResult(
            SafetyState.BLOCKED,
            "freshness_stale",
            details=freshness.to_dict(),
        )

    if not audit_ok:
        return SafetyResult(SafetyState.BLOCKED, "audit_unavailable")

    allowlisted = is_execution_allowlisted(spec.name)
    if spec.execution_enabled:
        if not allowlisted:
            return SafetyResult(SafetyState.BLOCKED, "execution_flag_unexpectedly_true")
        if spec.mutates_network or spec.mutates_security_state:
            return SafetyResult(SafetyState.BLOCKED, "mutating_execution_not_allowed")

    if spec.confirmation_required and confirmation_ok is None:
        return SafetyResult(
            SafetyState.NOT_READY,
            "confirmation_required",
            details={"confirmation_required": True},
            execution_enabled=False,
        )
    if spec.confirmation_required and confirmation_ok is False:
        return SafetyResult(SafetyState.BLOCKED, "confirmation_invalid")

    return SafetyResult(
        SafetyState.SAFE,
        "preconditions_met_allowlisted"
        if allowlisted and spec.execution_enabled
        else "preconditions_met_execution_disabled",
        execution_enabled=bool(allowlisted and spec.execution_enabled),
        details={
            "confirmation_required": spec.confirmation_required,
            "confirmation_ok": confirmation_ok,
            "freshness": freshness.to_dict(),
            "allowlisted": allowlisted,
        },
    )
