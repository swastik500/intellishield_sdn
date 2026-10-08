"""
IntelliShield Phase 10–12 — Command infrastructure, audit, safety gate, controlled execute.

Phase 12: exactly one allowlisted action (`COMMAND_DRY_RUN`) may execute.
Mitigation / controller / OpenFlow remain DISABLED. No `/api/control/*` wiring.
"""

from .actions import ACTION_REGISTRY, Action, RiskLevel
from .executor import CONTROLLED_EXECUTOR, DISABLED_EXECUTOR, ExecutionDisabledError
from .models import Command, CommandStatus

__all__ = [
    "ACTION_REGISTRY",
    "Action",
    "Command",
    "CommandStatus",
    "CONTROLLED_EXECUTOR",
    "DISABLED_EXECUTOR",
    "ExecutionDisabledError",
    "RiskLevel",
    "commands_router",
]


def __getattr__(name: str):
    if name == "commands_router":
        from .routes import commands_router

        return commands_router
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
