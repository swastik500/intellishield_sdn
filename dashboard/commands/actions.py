"""Action registry — authoritative metadata for Operator commands (Phase 10–13).

Phase 12 enables exactly ONE allowlisted action: COMMAND_DRY_RUN
(controlled no-op dry-run adapter).

Phase 13 (R7-gated operational mitigation): BLOCKED — no mitigation action is
execution_enabled. See dashboard/static/soc/R7_GATED_OPERATIONAL_MITIGATION.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, Optional

from dashboard.auth.permissions import Permission


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Action(str, Enum):
    """Command actions. Only COMMAND_DRY_RUN may execute in Phase 12."""

    READ = "READ"
    COMMAND_DRY_RUN = "COMMAND_DRY_RUN"
    ACKNOWLEDGE_ALERT = "ACKNOWLEDGE_ALERT"
    EXECUTE_MITIGATION = "EXECUTE_MITIGATION"
    BLOCK_TARGET = "BLOCK_TARGET"
    UNBLOCK_TARGET = "UNBLOCK_TARGET"
    CONFIGURATION_CHANGE = "CONFIGURATION_CHANGE"
    SYSTEM_CONTROL = "SYSTEM_CONTROL"


class TargetType(str, Enum):
    EVENT = "EVENT"
    ALERT = "ALERT"
    ATTACKER = "ATTACKER"
    FLOW = "FLOW"
    BLOCKLIST_ENTRY = "BLOCKLIST_ENTRY"
    CONTROLLER = "CONTROLLER"
    CONFIGURATION = "CONFIGURATION"
    NONE = "NONE"


@dataclass(frozen=True)
class ActionSpec:
    name: Action
    risk_level: RiskLevel
    required_permission: Permission
    confirmation_required: bool
    execution_enabled: bool
    target_type: TargetType
    description: str
    reversible: bool = False
    timeout_seconds: int = 5
    mutates_network: bool = False
    mutates_security_state: bool = False


ACTION_REGISTRY: Dict[Action, ActionSpec] = {
    Action.READ: ActionSpec(
        name=Action.READ,
        risk_level=RiskLevel.LOW,
        required_permission=Permission.READ_DASHBOARD,
        confirmation_required=False,
        execution_enabled=False,
        target_type=TargetType.NONE,
        description="Read-only infrastructure probe",
        reversible=True,
        timeout_seconds=2,
        mutates_network=False,
        mutates_security_state=False,
    ),
    # Phase 12 — sole allowlisted executable action (controlled dry-run adapter)
    Action.COMMAND_DRY_RUN: ActionSpec(
        name=Action.COMMAND_DRY_RUN,
        risk_level=RiskLevel.MEDIUM,
        required_permission=Permission.INVESTIGATE_EVENTS,
        confirmation_required=True,
        execution_enabled=True,
        target_type=TargetType.EVENT,
        description=(
            "Phase 12 controlled dry-run execution — durable no-op proving the "
            "operator safety chain; no network or security-state mutation"
        ),
        reversible=True,
        timeout_seconds=5,
        mutates_network=False,
        mutates_security_state=False,
    ),
    Action.ACKNOWLEDGE_ALERT: ActionSpec(
        name=Action.ACKNOWLEDGE_ALERT,
        risk_level=RiskLevel.MEDIUM,
        required_permission=Permission.ACKNOWLEDGE_ALERT,
        confirmation_required=True,
        execution_enabled=False,
        target_type=TargetType.ALERT,
        description="Acknowledge alert — DEFINED, execution disabled (no backend)",
        reversible=True,
        timeout_seconds=5,
        mutates_network=False,
        mutates_security_state=False,
    ),
    Action.EXECUTE_MITIGATION: ActionSpec(
        name=Action.EXECUTE_MITIGATION,
        risk_level=RiskLevel.HIGH,
        required_permission=Permission.EXECUTE_MITIGATION,
        confirmation_required=True,
        execution_enabled=False,
        target_type=TargetType.EVENT,
        description=(
            "R7-gated mitigation — DEFINED, Phase 13 BLOCKED "
            "(no safe SOC→OpenFlow bridge / event_id continuity)"
        ),
        reversible=False,
        timeout_seconds=30,
        mutates_network=True,
        mutates_security_state=True,
    ),
    Action.BLOCK_TARGET: ActionSpec(
        name=Action.BLOCK_TARGET,
        risk_level=RiskLevel.HIGH,
        required_permission=Permission.BLOCK_TARGET,
        confirmation_required=True,
        execution_enabled=False,
        target_type=TargetType.ATTACKER,
        description="Block target — DEFINED, execution disabled",
        reversible=True,
        timeout_seconds=30,
        mutates_network=True,
        mutates_security_state=True,
    ),
    Action.UNBLOCK_TARGET: ActionSpec(
        name=Action.UNBLOCK_TARGET,
        risk_level=RiskLevel.HIGH,
        required_permission=Permission.UNBLOCK_TARGET,
        confirmation_required=True,
        execution_enabled=False,
        target_type=TargetType.ATTACKER,
        description="Unblock target — DEFINED, execution disabled",
        reversible=True,
        timeout_seconds=30,
        mutates_network=True,
        mutates_security_state=True,
    ),
    Action.CONFIGURATION_CHANGE: ActionSpec(
        name=Action.CONFIGURATION_CHANGE,
        risk_level=RiskLevel.CRITICAL,
        required_permission=Permission.MANAGE_CONFIGURATION,
        confirmation_required=True,
        execution_enabled=False,
        target_type=TargetType.CONFIGURATION,
        description="Configuration change — DEFINED, execution disabled",
        reversible=False,
        timeout_seconds=60,
        mutates_network=False,
        mutates_security_state=True,
    ),
    Action.SYSTEM_CONTROL: ActionSpec(
        name=Action.SYSTEM_CONTROL,
        risk_level=RiskLevel.CRITICAL,
        required_permission=Permission.MANAGE_CONFIGURATION,
        confirmation_required=True,
        execution_enabled=False,
        target_type=TargetType.CONTROLLER,
        description="System control — DEFINED, execution disabled",
        reversible=False,
        timeout_seconds=60,
        mutates_network=True,
        mutates_security_state=True,
    ),
}

# Exactly one Phase 12 allowlisted executable action
PHASE12_ALLOWLIST: FrozenSet[Action] = frozenset({Action.COMMAND_DRY_RUN})

# Phase 13 — no real mitigation allowlisted (audit BLOCKED)
PHASE13_MITIGATION_ALLOWLIST: FrozenSet[Action] = frozenset()
PHASE13_STATUS = "BLOCKED"
PHASE13_MITIGATION_ENABLED = False


def get_action_spec(action: Action | str) -> Optional[ActionSpec]:
    if isinstance(action, Action):
        return ACTION_REGISTRY.get(action)
    try:
        return ACTION_REGISTRY.get(Action(str(action).strip().upper()))
    except ValueError:
        return None


def parse_action(value: str) -> Optional[Action]:
    try:
        return Action(str(value).strip().upper())
    except ValueError:
        return None


def is_execution_allowlisted(action: Action | str) -> bool:
    parsed = action if isinstance(action, Action) else parse_action(str(action))
    if parsed is None:
        return False
    spec = ACTION_REGISTRY.get(parsed)
    return bool(spec and spec.execution_enabled and parsed in PHASE12_ALLOWLIST)
