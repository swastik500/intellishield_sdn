"""Controlled command executor (Phase 12).

Only explicitly allowlisted actions may execute. Unknown / high-risk actions fail closed.
Does NOT call mitigation engines, SDN controllers, flow-install APIs, blocklists,
or lab control write endpoints.
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Protocol

from .actions import Action, ActionSpec, get_action_spec, is_execution_allowlisted
from .models import Command, iso_utc, utcnow

logger = logging.getLogger("intellishield.commands.executor")


class ExecutionDisabledError(RuntimeError):
    """Raised when execution is not allowlisted / disabled."""

    def __init__(self, message: str = "Command execution is disabled"):
        super().__init__(message)


class ExecutionRejectedError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass
class ExecutionResult:
    success: bool
    operation_id: str
    command_id: str
    action: str
    started_at: str
    completed_at: str
    result_summary: str
    failure_code: Optional[str] = None
    failure_reason: Optional[str] = None
    mutates_network: bool = False
    mutates_security_state: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "operation_id": self.operation_id,
            "command_id": self.command_id,
            "action": self.action,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "result_summary": self.result_summary,
            "failure_code": self.failure_code,
            "failure_reason": self.failure_reason,
            "mutates_network": self.mutates_network,
            "mutates_security_state": self.mutates_security_state,
            "details": dict(self.details),
        }


class ActionHandler(Protocol):
    def __call__(self, command: Command, spec: ActionSpec) -> ExecutionResult: ...


def _new_operation_id() -> str:
    return f"op_{secrets.token_urlsafe(16)}"


def _controlled_dry_run(command: Command, spec: ActionSpec) -> ExecutionResult:
    """
    Phase 12 sole allowlisted operation.

    Durable no-op: validates command shape, records a structured result, mutates nothing
    in the network, mitigation engine, controller, or OpenFlow plane.
    """
    started = utcnow()
    # Bound work — intentional short sleep simulates work within timeout
    timeout = max(1, int(spec.timeout_seconds))
    deadline = time.monotonic() + timeout
    # Validate target presence (server-side)
    if not command.target or not command.target.id:
        raise ExecutionRejectedError("target_invalid", "missing target id")
    if command.target.type.upper() != "EVENT":
        raise ExecutionRejectedError("target_type_invalid", "COMMAND_DRY_RUN requires EVENT target")
    if not command.event_id:
        raise ExecutionRejectedError("event_id_required", "event_id required for dry-run")
    # Soft target format check — alphanumeric / dash / underscore, bounded
    eid = str(command.event_id).strip()
    if len(eid) < 3 or len(eid) > 128 or not all(
        c.isalnum() or c in "-_.:@" for c in eid
    ):
        raise ExecutionRejectedError("event_id_malformed", "event_id format invalid")
    if time.monotonic() > deadline:
        raise ExecutionRejectedError("timeout", "dry-run exceeded timeout before work")
    # No network / mitigation / controller side effects
    completed = utcnow()
    return ExecutionResult(
        success=True,
        operation_id=_new_operation_id(),
        command_id=command.command_id,
        action=command.action,
        started_at=iso_utc(started),
        completed_at=iso_utc(completed),
        result_summary="controlled_dry_run_completed",
        mutates_network=False,
        mutates_security_state=False,
        details={
            "adapter": "controlled_dry_run",
            "phase": 12,
            "event_id": eid,
            "target": command.target.to_dict(),
            "note": "No network or security-state mutation performed",
        },
    )


# Server-controlled handler map — never built from frontend input
_HANDLERS: Dict[Action, ActionHandler] = {
    Action.COMMAND_DRY_RUN: _controlled_dry_run,
}


class ControlledExecutor:
    """
    Allowlist-only executor.

    Rejects unknown actions, disabled actions, and anything outside PHASE12_ALLOWLIST.
    """

    execution_calls: int = 0

    def execute(self, command: Command) -> ExecutionResult:
        ControlledExecutor.execution_calls += 1
        action_raw = getattr(command, "action", None)
        if not is_execution_allowlisted(action_raw or ""):
            logger.warning(
                "execution_rejected_not_allowlisted command_id=%s action=%s",
                getattr(command, "command_id", None),
                action_raw,
            )
            raise ExecutionDisabledError(
                f"Execution not allowlisted for action {action_raw!r}"
            )
        spec = get_action_spec(action_raw)
        if spec is None or not spec.execution_enabled:
            raise ExecutionDisabledError(f"Execution disabled for action {action_raw!r}")
        if spec.mutates_network or spec.mutates_security_state:
            # Defense in depth — Phase 12 must not run mutating specs
            raise ExecutionDisabledError("Mutating operations are not enabled in Phase 12")

        handler = _HANDLERS.get(spec.name)
        if handler is None:
            raise ExecutionDisabledError(f"No handler registered for {spec.name.value}")

        logger.info(
            "controlled_execution_start command_id=%s action=%s principal_id=%s",
            command.command_id,
            spec.name.value,
            command.principal_id,
        )
        started_mono = time.monotonic()
        try:
            result = handler(command, spec)
        except ExecutionRejectedError:
            raise
        except Exception as exc:
            logger.error(
                "controlled_execution_error command_id=%s err=%s",
                command.command_id,
                type(exc).__name__,
            )
            raise ExecutionRejectedError("executor_error", str(exc) or type(exc).__name__) from exc

        elapsed = time.monotonic() - started_mono
        if elapsed > float(spec.timeout_seconds):
            raise ExecutionRejectedError("timeout", f"execution exceeded {spec.timeout_seconds}s")

        logger.info(
            "controlled_execution_done command_id=%s operation_id=%s success=%s",
            command.command_id,
            result.operation_id,
            result.success,
        )
        return result


# Back-compat names used by Phase 10/11 code paths for non-allowlisted finalize
class CommandExecutor:
    """Legacy stub used when forcing EXECUTION_DISABLED for non-allowlisted actions."""

    execution_calls: int = 0

    def execute(self, command: Any) -> None:
        CommandExecutor.execution_calls += 1
        raise ExecutionDisabledError(
            f"Execution disabled for command {getattr(command, 'command_id', '?')}"
        )


DISABLED_EXECUTOR = CommandExecutor()
CONTROLLED_EXECUTOR = ControlledExecutor()


def reset_execution_counter() -> None:
    CommandExecutor.execution_calls = 0
    ControlledExecutor.execution_calls = 0


def get_execution_attempt_count() -> int:
    return int(CommandExecutor.execution_calls) + int(ControlledExecutor.execution_calls)
