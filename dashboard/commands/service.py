"""Command lifecycle orchestration — preview / confirm / execute (Phase 12).

Phase 11 durable SQLite is authoritative.
Phase 12 enables exactly ONE allowlisted controlled dry-run action.
Mitigation / controller / OpenFlow remain DISABLED.
"""

from __future__ import annotations

import logging
import secrets
from datetime import timedelta
from typing import Any, Dict, Optional

from dashboard.auth.authorization import authorize
from dashboard.auth.principal import Principal

from .actions import TargetType, get_action_spec, is_execution_allowlisted, parse_action
from .audit import append_audit_snapshot, create_audit_record
from .executor import (
    CONTROLLED_EXECUTOR,
    DISABLED_EXECUTOR,
    ExecutionDisabledError,
    ExecutionRejectedError,
)
from .freshness import FreshnessResult, evaluate_freshness
from .models import Command, CommandStatus, Target, utcnow
from .persistence import PersistenceUnavailableError
from .persistence import repo
from .persistence.db import transaction
from .safety import SafetyState, evaluate_safety
from .store import AUDIT_STORE, COMMAND_STORE
from .validation import (
    validate_event_id,
    validate_idempotency_key,
    validate_reason,
    validate_target,
)

logger = logging.getLogger("intellishield.commands")

COMMAND_TTL_SECONDS = 900
CONFIRMATION_TTL_SECONDS = 300


def _new_command_id() -> str:
    return f"cmd_{secrets.token_urlsafe(18)}"


def _new_confirmation_token() -> str:
    return f"cfm_{secrets.token_urlsafe(24)}"


def _persist(cmd: Command, *, create: bool = False) -> Command:
    return COMMAND_STORE.put(cmd, create=create)


def _unavailable(reason: str = "persistence_unavailable") -> Dict[str, Any]:
    logger.error("command_path_unavailable reason=%s", reason)
    return {
        "status": "FAILED",
        "failure_reason": reason,
        "execution_enabled": False,
        "executed": False,
        "http_hint": 503,
        "persistence_available": False,
    }


def _finalize_disabled(cmd: Command, *, previous_status: Optional[str] = None) -> Dict[str, Any]:
    """READY_FOR_EXECUTION → EXECUTION_DISABLED; prove executor raises."""
    prev = previous_status or cmd.status.value
    if cmd.status == CommandStatus.READY_FOR_EXECUTION:
        cmd.transition(CommandStatus.EXECUTION_DISABLED, reason="phase11_execution_disabled")
    try:
        DISABLED_EXECUTOR.execute(cmd)
    except ExecutionDisabledError:
        pass
    try:
        with transaction(immediate=True) as conn:
            repo.update_command(conn, cmd)
            snap = {
                "audit_id": f"aud_{secrets.token_urlsafe(16)}",
                "command_id": cmd.command_id,
                "principal_id": cmd.principal_id,
                "action": cmd.action,
                "target_type": cmd.target.type,
                "target_id": cmd.target.id,
                "event_id": cmd.event_id,
                "reason": cmd.reason,
                "status": cmd.status.value,
                "previous_status": prev,
                "new_status": cmd.status.value,
                "failure_reason": cmd.failure_reason,
                "source": "operator_command",
                "parent_audit_id": cmd.audit_id,
                "authorization_result": dict(cmd.authorization),
                "safety_result": dict(cmd.safety),
                "execution_result": {
                    "executed": False,
                    "execution_enabled": False,
                    "detail": "Phase 11 — execution disabled",
                },
                "result": cmd.status.value,
                "finalized_at": utcnow().isoformat().replace("+00:00", "Z"),
            }
            repo.append_audit(conn, snap)
    except PersistenceUnavailableError:
        return _unavailable("finalize_persist_failed")
    body = cmd.to_public_dict()
    body["execution_enabled"] = False
    body["executed"] = False
    return body


def preview_command(
    principal: Principal,
    *,
    action: str,
    target_type: Optional[str],
    target_id: Optional[str],
    event_id: Optional[str],
    reason: str,
    idempotency_key: Optional[str] = None,
    event_timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate → authorize → safety. Never executes. Persists durably."""
    try:
        return _preview_command_inner(
            principal,
            action=action,
            target_type=target_type,
            target_id=target_id,
            event_id=event_id,
            reason=reason,
            idempotency_key=idempotency_key,
            event_timestamp=event_timestamp,
        )
    except PersistenceUnavailableError as exc:
        logger.error(
            "preview_persistence_failed principal_id=%s err=%s",
            principal.id,
            type(exc).__name__,
        )
        return _unavailable(str(exc) or "persistence_unavailable")


def _preview_command_inner(
    principal: Principal,
    *,
    action: str,
    target_type: Optional[str],
    target_id: Optional[str],
    event_id: Optional[str],
    reason: str,
    idempotency_key: Optional[str] = None,
    event_timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    parsed = parse_action(action)
    if parsed is None:
        return _error_payload("INVALID", "unknown_action")

    spec = get_action_spec(parsed)
    if spec is None:
        return _error_payload("INVALID", "unknown_action")

    idem_v = validate_idempotency_key(idempotency_key)
    if not idem_v.valid:
        return _error_payload("INVALID", idem_v.reason or "idempotency_key_invalid")

    tt = (target_type or TargetType.NONE.value).upper()
    tid = (target_id or "none").strip() if target_id else "none"

    if idempotency_key:
        existing = COMMAND_STORE.find_idempotent(
            principal_id=principal.id,
            action=parsed.value,
            target_type=tt,
            target_id=tid,
            idempotency_key=idempotency_key,
        )
        if existing:
            body = existing.to_public_dict()
            body["duplicate"] = True
            body["execution_enabled"] = False
            return body

    now = utcnow()
    cmd = Command(
        command_id=_new_command_id(),
        action=parsed.value,
        target=Target(type=tt, id=tid),
        event_id=event_id.strip() if event_id else None,
        principal_id=principal.id,
        principal_username=principal.username,
        reason=(reason or "").strip(),
        created_at=now,
        expires_at=now + timedelta(seconds=COMMAND_TTL_SECONDS),
        status=CommandStatus.REQUESTED,
        idempotency_key=idempotency_key,
        risk_level=spec.risk_level.value,
        confirmation_required=spec.confirmation_required,
        execution_enabled=is_execution_allowlisted(parsed),
        version=1,
        updated_at=now,
    )

    try:
        _persist(cmd, create=True)
    except PersistenceUnavailableError as exc:
        if "idempotency_conflict" in str(exc):
            existing = COMMAND_STORE.find_idempotent(
                principal_id=principal.id,
                action=parsed.value,
                target_type=tt,
                target_id=tid,
                idempotency_key=idempotency_key or "",
            )
            if existing:
                body = existing.to_public_dict()
                body["duplicate"] = True
                body["execution_enabled"] = False
                return body
        raise

    audit = create_audit_record(cmd)
    cmd.audit_id = audit["audit_id"]
    prev = cmd.status.value
    cmd.transition(CommandStatus.VALIDATING)
    _persist(cmd)

    reason_v = validate_reason(cmd.reason)
    target_v = validate_target(target_type=target_type, target_id=target_id, spec=spec)

    if spec.target_type == TargetType.EVENT and target_v.valid and not cmd.event_id:
        cmd.event_id = (target_v.details or {}).get("id")

    event_v = validate_event_id(
        cmd.event_id, required=(spec.target_type == TargetType.EVENT)
    )
    cmd.validation = {
        "reason": reason_v.to_dict(),
        "target": target_v.to_dict(),
        "event": event_v.to_dict(),
    }
    if not (reason_v.valid and target_v.valid and event_v.valid):
        cmd.transition(CommandStatus.INVALID, reason="validation_failed")
        append_audit_snapshot(cmd, previous_status=prev)
        _persist(cmd)
        return cmd.to_public_dict()

    if target_v.details:
        cmd.target = Target(
            type=target_v.details.get("type", cmd.target.type),
            id=target_v.details.get("id", cmd.target.id),
        )

    authz = authorize(
        principal,
        spec.required_permission,
        resource_type=cmd.target.type,
        resource_id=cmd.target.id,
    )
    cmd.authorization = {
        "permission": spec.required_permission.value,
        "decision": "ALLOW" if authz.allow else "DENY",
        "reason": authz.reason,
    }
    if not authz.allow:
        prev = cmd.status.value
        cmd.transition(CommandStatus.DENIED, reason=authz.reason)
        append_audit_snapshot(cmd, previous_status=prev)
        _persist(cmd)
        out = cmd.to_public_dict()
        out["http_hint"] = 403
        return out

    cmd.transition(CommandStatus.AUTHORIZED)
    cmd.transition(CommandStatus.SAFETY_CHECK)

    fresh = evaluate_freshness(spec, event_timestamp=event_timestamp)
    cmd.freshness = fresh.to_dict()
    safety = evaluate_safety(
        cmd,
        spec,
        authz_allow=True,
        validation_ok=True,
        freshness=fresh,
        confirmation_ok=None if spec.confirmation_required else True,
        audit_ok=True,
    )
    cmd.safety = safety.to_dict()

    if safety.state == SafetyState.BLOCKED:
        prev = CommandStatus.SAFETY_CHECK.value
        if fresh.status == "STALE":
            cmd.transition(CommandStatus.STALE, reason=safety.reason)
        else:
            cmd.transition(CommandStatus.SAFETY_BLOCKED, reason=safety.reason)
        append_audit_snapshot(cmd, previous_status=prev)
        _persist(cmd)
        return cmd.to_public_dict()

    if spec.confirmation_required:
        cmd.confirmation_token = _new_confirmation_token()
        cmd.confirmation_expires_at = utcnow() + timedelta(seconds=CONFIRMATION_TTL_SECONDS)
        prev = cmd.status.value
        cmd.transition(CommandStatus.AWAITING_CONFIRMATION)
        append_audit_snapshot(cmd, previous_status=prev)
        _persist(cmd)
        body = cmd.to_public_dict()
        body["confirmation_token"] = cmd.confirmation_token
        body["execution_enabled"] = is_execution_allowlisted(cmd.action)
        return body

    prev = cmd.status.value
    cmd.transition(CommandStatus.READY_FOR_EXECUTION)
    if is_execution_allowlisted(cmd.action) and spec.execution_enabled:
        cmd.execution_enabled = True
        _persist(cmd)
        body = cmd.to_public_dict()
        body["execution_enabled"] = True
        body["awaiting_execution"] = True
        return body
    return _finalize_disabled(cmd, previous_status=prev)


def confirm_command(
    principal: Principal,
    *,
    command_id: str,
    confirmation_token: str,
) -> Dict[str, Any]:
    """Confirm → READY_FOR_EXECUTION → EXECUTION_DISABLED. Never executes.

    Uses BEGIN IMMEDIATE + optimistic version to prevent concurrent confirmations.
    """
    try:
        return _confirm_command_inner(
            principal, command_id=command_id, confirmation_token=confirmation_token
        )
    except PersistenceUnavailableError as exc:
        msg = str(exc) or "persistence_unavailable"
        if "concurrent_modification" in msg:
            try:
                existing = COMMAND_STORE.get(command_id)
            except PersistenceUnavailableError:
                existing = None
            if existing and (
                existing.confirmation_used
                or existing.status
                in {
                    CommandStatus.CONFIRMED,
                    CommandStatus.READY_FOR_EXECUTION,
                    CommandStatus.EXECUTION_DISABLED,
                }
            ):
                body = existing.to_public_dict()
                body["duplicate"] = True
                body["failure_reason"] = "confirmation_replay"
                body["execution_enabled"] = False
                return body
        logger.error(
            "confirm_persistence_failed command_id=%s principal_id=%s err=%s",
            command_id,
            principal.id,
            type(exc).__name__,
        )
        return _unavailable(msg)


def _confirm_command_inner(
    principal: Principal,
    *,
    command_id: str,
    confirmation_token: str,
) -> Dict[str, Any]:
    # Single writer transaction for load → validate → confirm → audit
    try:
        with transaction(immediate=True) as conn:
            cmd = repo.get_command(conn, command_id)
            if cmd is None:
                return _error_payload("INVALID", "command_not_found", status_code=404)

            if cmd.principal_id != principal.id:
                return _error_payload(
                    "DENIED", "principal_mismatch", status_code=403, command=cmd
                )

            if cmd.is_expired():
                if cmd.status not in {
                    CommandStatus.EXPIRED,
                    CommandStatus.EXECUTION_DISABLED,
                    CommandStatus.DENIED,
                    CommandStatus.INVALID,
                    CommandStatus.SAFETY_BLOCKED,
                    CommandStatus.DUPLICATE,
                    CommandStatus.CANCELLED,
                    CommandStatus.FAILED,
                    CommandStatus.STALE,
                }:
                    prev = cmd.status.value
                    try:
                        cmd.transition(CommandStatus.EXPIRED, reason="command_expired")
                    except Exception:
                        cmd.status = CommandStatus.EXPIRED
                        cmd.failure_reason = "command_expired"
                    repo.update_command(conn, cmd)
                    _append_audit_in_tx(conn, cmd, previous_status=prev)
                return cmd.to_public_dict()

            if cmd.status != CommandStatus.AWAITING_CONFIRMATION:
                if cmd.status in {
                    CommandStatus.READY_FOR_EXECUTION,
                    CommandStatus.EXECUTION_DISABLED,
                    CommandStatus.CONFIRMED,
                } or cmd.confirmation_used:
                    body = cmd.to_public_dict()
                    body["duplicate"] = True
                    body["failure_reason"] = "confirmation_replay"
                    body["execution_enabled"] = False
                    return body
                return _error_payload(
                    cmd.status.value, "invalid_state_for_confirmation", command=cmd
                )

            if cmd.confirmation_used:
                body = cmd.to_public_dict()
                body["duplicate"] = True
                body["failure_reason"] = "confirmation_replay"
                body["execution_enabled"] = False
                return body

            if not confirmation_token or confirmation_token != cmd.confirmation_token:
                return _error_payload(
                    "DENIED", "confirmation_token_invalid", status_code=403, command=cmd
                )

            if cmd.confirmation_expires_at and utcnow() > cmd.confirmation_expires_at:
                prev = cmd.status.value
                cmd.transition(CommandStatus.EXPIRED, reason="confirmation_expired")
                repo.update_command(conn, cmd)
                _append_audit_in_tx(conn, cmd, previous_status=prev)
                return cmd.to_public_dict()

            prev = cmd.status.value
            cmd.confirmation_used = True
            cmd.confirmed_at = utcnow()
            cmd.confirmed_by = principal.id
            cmd.transition(CommandStatus.CONFIRMED)

            spec = get_action_spec(cmd.action)
            if spec is None:
                cmd.failure_reason = "action_spec_missing"
                # Cannot transition CONFIRMED → FAILED; mark SAFETY_BLOCKED
                try:
                    cmd.transition(CommandStatus.SAFETY_BLOCKED, reason="action_spec_missing")
                except Exception:
                    cmd.status = CommandStatus.SAFETY_BLOCKED
                repo.update_command(conn, cmd)
                _append_audit_in_tx(conn, cmd, previous_status=prev)
                return cmd.to_public_dict()

            stored_fresh = FreshnessResult(
                status=(cmd.freshness or {}).get("status", "NOT_APPLICABLE"),
                max_age_seconds=(cmd.freshness or {}).get("max_age_seconds"),
                age_seconds=(cmd.freshness or {}).get("age_seconds"),
                detail=(cmd.freshness or {}).get("detail"),
            )
            # Fail-closed: HIGH/CRITICAL must not proceed with undefined freshness
            if spec.risk_level.value in {"HIGH", "CRITICAL"}:
                if stored_fresh.status in {
                    "NOT_CONFIGURED",
                    "STALE",
                    "INVALID_TIMESTAMP",
                } or (
                    stored_fresh.status == "NOT_APPLICABLE"
                    and not (cmd.freshness or {}).get("max_age_seconds")
                ):
                    cmd.transition(
                        CommandStatus.SAFETY_BLOCKED,
                        reason=f"freshness_{stored_fresh.status.lower()}",
                    )
                    repo.update_command(conn, cmd)
                    _append_audit_in_tx(conn, cmd, previous_status=prev)
                    return cmd.to_public_dict()

            safety = evaluate_safety(
                cmd,
                spec,
                authz_allow=cmd.authorization.get("decision") == "ALLOW",
                validation_ok=True,
                freshness=stored_fresh,
                confirmation_ok=True,
                audit_ok=True,
            )
            cmd.safety = safety.to_dict()
            if safety.state == SafetyState.BLOCKED:
                cmd.transition(CommandStatus.SAFETY_BLOCKED, reason=safety.reason)
                repo.update_command(conn, cmd)
                _append_audit_in_tx(conn, cmd, previous_status=prev)
                return cmd.to_public_dict()

            cmd.transition(CommandStatus.READY_FOR_EXECUTION)
            # Phase 12 allowlisted actions stop here — require explicit /execute
            if is_execution_allowlisted(cmd.action) and spec.execution_enabled:
                cmd.execution_enabled = True
                repo.update_command(conn, cmd)
                _append_audit_in_tx(conn, cmd, previous_status=prev)
                body = cmd.to_public_dict()
                body["execution_enabled"] = True
                body["executed"] = False
                body["awaiting_execution"] = True
                logger.info(
                    "command_ready_for_controlled_execution command_id=%s action=%s principal_id=%s",
                    cmd.command_id,
                    cmd.action,
                    principal.id,
                )
                return body

            # Non-allowlisted: fail closed to EXECUTION_DISABLED (Phase 10/11 path)
            prev_ready = cmd.status.value
            cmd.transition(
                CommandStatus.EXECUTION_DISABLED, reason="phase12_action_not_allowlisted"
            )
            cmd.execution_enabled = False
            try:
                DISABLED_EXECUTOR.execute(cmd)
            except ExecutionDisabledError:
                pass
            repo.update_command(conn, cmd)
            _append_audit_in_tx(conn, cmd, previous_status=prev_ready)
            body = cmd.to_public_dict()
            body["execution_enabled"] = False
            body["executed"] = False
            logger.info(
                "command_confirmed_execution_disabled command_id=%s principal_id=%s",
                cmd.command_id,
                principal.id,
            )
            return body
    except PersistenceUnavailableError:
        raise


def execute_command(principal: Principal, *, command_id: str) -> Dict[str, Any]:
    """
    Final safety re-check → EXECUTING → ControlledExecutor → EXECUTED/FAILED.

    Only Phase 12 allowlisted actions may succeed. Durable + concurrent-safe.
    """
    try:
        return _execute_command_inner(principal, command_id=command_id)
    except PersistenceUnavailableError as exc:
        msg = str(exc) or "persistence_unavailable"
        if "concurrent_modification" in msg:
            try:
                existing = COMMAND_STORE.get(command_id)
            except PersistenceUnavailableError:
                existing = None
            if existing and existing.status in {
                CommandStatus.EXECUTING,
                CommandStatus.EXECUTED,
                CommandStatus.FAILED,
            }:
                body = existing.to_public_dict()
                body["duplicate"] = True
                body["failure_reason"] = body.get("failure_reason") or "execution_replay"
                return body
        logger.error(
            "execute_persistence_failed command_id=%s principal_id=%s err=%s",
            command_id,
            principal.id,
            type(exc).__name__,
        )
        return _unavailable(msg)


def _execute_command_inner(principal: Principal, *, command_id: str) -> Dict[str, Any]:
    with transaction(immediate=True) as conn:
        cmd = repo.get_command(conn, command_id)
        if cmd is None:
            return _error_payload("INVALID", "command_not_found", status_code=404)

        if cmd.principal_id != principal.id:
            return _error_payload(
                "DENIED", "principal_mismatch", status_code=403, command=cmd
            )

        # Idempotent replay: already executed
        if cmd.status == CommandStatus.EXECUTED:
            body = cmd.to_public_dict()
            body["duplicate"] = True
            body["failure_reason"] = "execution_replay"
            body["executed"] = True
            return body

        if cmd.status == CommandStatus.EXECUTING:
            body = cmd.to_public_dict()
            body["duplicate"] = True
            body["failure_reason"] = "execution_in_progress"
            return body

        if cmd.status == CommandStatus.FAILED:
            body = cmd.to_public_dict()
            body["duplicate"] = True
            body["failure_reason"] = "already_failed"
            return body

        if cmd.is_expired():
            prev = cmd.status.value
            try:
                cmd.transition(CommandStatus.EXPIRED, reason="command_expired")
            except Exception:
                cmd.status = CommandStatus.EXPIRED
                cmd.failure_reason = "command_expired"
            repo.update_command(conn, cmd)
            _append_audit_in_tx(conn, cmd, previous_status=prev)
            return cmd.to_public_dict()

        if cmd.status != CommandStatus.READY_FOR_EXECUTION:
            return _error_payload(
                cmd.status.value, "invalid_state_for_execution", command=cmd
            )

        if not is_execution_allowlisted(cmd.action):
            prev = cmd.status.value
            cmd.transition(
                CommandStatus.EXECUTION_DISABLED, reason="action_not_allowlisted"
            )
            repo.update_command(conn, cmd)
            _append_audit_in_tx(conn, cmd, previous_status=prev)
            body = cmd.to_public_dict()
            body["http_hint"] = 403
            return body

        spec = get_action_spec(cmd.action)
        if spec is None or not spec.execution_enabled:
            return _error_payload("DENIED", "execution_not_enabled", status_code=403, command=cmd)

        # Re-authorize immediately before execution
        authz = authorize(
            principal,
            spec.required_permission,
            resource_type=cmd.target.type,
            resource_id=cmd.target.id,
        )
        if not authz.allow:
            return _error_payload("DENIED", authz.reason, status_code=403, command=cmd)

        # Freshness re-check (fail-closed for HIGH/CRITICAL; MEDIUM uses stored result)
        stored_fresh = FreshnessResult(
            status=(cmd.freshness or {}).get("status", "NOT_APPLICABLE"),
            max_age_seconds=(cmd.freshness or {}).get("max_age_seconds"),
            age_seconds=(cmd.freshness or {}).get("age_seconds"),
            detail=(cmd.freshness or {}).get("detail"),
        )
        if stored_fresh.blocks_high_risk and cmd.risk_level in {"HIGH", "CRITICAL"}:
            prev = cmd.status.value
            cmd.transition(
                CommandStatus.SAFETY_BLOCKED,
                reason=f"freshness_{stored_fresh.status.lower()}",
            )
            repo.update_command(conn, cmd)
            _append_audit_in_tx(conn, cmd, previous_status=prev)
            return cmd.to_public_dict()

        safety = evaluate_safety(
            cmd,
            spec,
            authz_allow=True,
            validation_ok=True,
            freshness=stored_fresh,
            confirmation_ok=True,
            audit_ok=True,
        )
        cmd.safety = safety.to_dict()
        if safety.state == SafetyState.BLOCKED:
            prev = cmd.status.value
            cmd.transition(CommandStatus.SAFETY_BLOCKED, reason=safety.reason)
            repo.update_command(conn, cmd)
            _append_audit_in_tx(conn, cmd, previous_status=prev)
            return cmd.to_public_dict()

        # Claim execution authority (optimistic version inside update)
        prev = cmd.status.value
        cmd.transition(CommandStatus.EXECUTING)
        cmd.execution_enabled = True
        repo.update_command(conn, cmd)
        _append_audit_in_tx(conn, cmd, previous_status=prev)

    # Execute outside writer lock duration for the adapter, then persist result
    try:
        result = CONTROLLED_EXECUTOR.execute(cmd)
    except ExecutionDisabledError as exc:
        return _persist_execution_failure(
            command_id, principal, code="not_allowlisted", reason=str(exc)
        )
    except ExecutionRejectedError as exc:
        return _persist_execution_failure(
            command_id, principal, code=exc.code, reason=str(exc)
        )
    except Exception as exc:
        return _persist_execution_failure(
            command_id, principal, code="executor_error", reason=type(exc).__name__
        )

    try:
        with transaction(immediate=True) as conn:
            cmd = repo.get_command(conn, command_id)
            if cmd is None:
                return _unavailable("command_missing_after_execute")
            if cmd.status == CommandStatus.EXECUTED:
                body = cmd.to_public_dict()
                body["duplicate"] = True
                return body
            if cmd.status != CommandStatus.EXECUTING:
                return _error_payload(
                    cmd.status.value, "invalid_state_after_execute", command=cmd
                )
            prev = cmd.status.value
            cmd.execution = result.to_dict()
            cmd.execution_id = result.operation_id
            cmd.executed_at = utcnow()
            if result.success:
                cmd.transition(CommandStatus.EXECUTED)
            else:
                cmd.transition(
                    CommandStatus.FAILED,
                    reason=result.failure_reason or "execution_failed",
                )
            repo.update_command(conn, cmd)
            repo.insert_execution(
                conn,
                {
                    **result.to_dict(),
                    "execution_id": result.operation_id,
                    "principal_id": principal.id,
                    "target_type": cmd.target.type,
                    "target_id": cmd.target.id,
                    "event_id": cmd.event_id,
                },
            )
            _append_audit_in_tx(conn, cmd, previous_status=prev)
            body = cmd.to_public_dict()
            body["executed"] = bool(result.success)
            body["execution_enabled"] = True
            logger.info(
                "command_executed command_id=%s operation_id=%s success=%s",
                cmd.command_id,
                result.operation_id,
                result.success,
            )
            return body
    except PersistenceUnavailableError as exc:
        # Adapter already ran — fail closed on result claim if we cannot persist
        logger.error(
            "execution_result_persist_failed command_id=%s err=%s",
            command_id,
            type(exc).__name__,
        )
        return _unavailable("execution_result_persist_failed")


def _persist_execution_failure(
    command_id: str, principal: Principal, *, code: str, reason: str
) -> Dict[str, Any]:
    try:
        with transaction(immediate=True) as conn:
            cmd = repo.get_command(conn, command_id)
            if cmd is None:
                return _error_payload("INVALID", "command_not_found", status_code=404)
            if cmd.status == CommandStatus.EXECUTED:
                body = cmd.to_public_dict()
                body["duplicate"] = True
                return body
            prev = cmd.status.value
            if cmd.status == CommandStatus.EXECUTING:
                try:
                    cmd.transition(CommandStatus.FAILED, reason=f"{code}:{reason}")
                except Exception:
                    cmd.status = CommandStatus.FAILED
                    cmd.failure_reason = f"{code}:{reason}"
            cmd.execution = {
                "success": False,
                "failure_code": code,
                "failure_reason": reason,
                "command_id": command_id,
            }
            repo.update_command(conn, cmd)
            _append_audit_in_tx(conn, cmd, previous_status=prev)
            body = cmd.to_public_dict()
            body["executed"] = False
            return body
    except PersistenceUnavailableError:
        return _unavailable("execution_failure_persist_failed")


def _append_audit_in_tx(conn, cmd: Command, *, previous_status: Optional[str]) -> None:
    snap = {
        "audit_id": f"aud_{secrets.token_urlsafe(16)}",
        "command_id": cmd.command_id,
        "principal_id": cmd.principal_id,
        "action": cmd.action,
        "target_type": cmd.target.type,
        "target_id": cmd.target.id,
        "event_id": cmd.event_id,
        "reason": cmd.reason,
        "status": cmd.status.value,
        "previous_status": previous_status,
        "new_status": cmd.status.value,
        "failure_reason": cmd.failure_reason,
        "source": "operator_command",
        "parent_audit_id": cmd.audit_id,
        "authorization_result": dict(cmd.authorization),
        "safety_result": dict(cmd.safety),
        "execution_result": {
            "executed": False,
            "execution_enabled": False,
            "detail": "Phase 11 — execution disabled",
        },
        "result": cmd.status.value,
        "confirmed_at": (
            cmd.confirmed_at.isoformat().replace("+00:00", "Z")
            if cmd.confirmed_at
            else None
        ),
        "finalized_at": utcnow().isoformat().replace("+00:00", "Z")
        if cmd.status
        in {
            CommandStatus.EXECUTION_DISABLED,
            CommandStatus.EXECUTED,
            CommandStatus.EXPIRED,
            CommandStatus.SAFETY_BLOCKED,
            CommandStatus.DENIED,
            CommandStatus.INVALID,
            CommandStatus.FAILED,
        }
        else None,
    }
    repo.append_audit(conn, snap)


def get_command(command_id: str) -> Optional[Dict[str, Any]]:
    try:
        cmd = COMMAND_STORE.get(command_id)
        return cmd.to_public_dict() if cmd else None
    except PersistenceUnavailableError:
        return None


def list_commands(
    limit: int = 50,
    *,
    offset: int = 0,
    status: Optional[str] = None,
    principal_id: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        items, total = COMMAND_STORE.list_page(
            limit, offset=offset, status=status, principal_id=principal_id
        )
        return {
            "commands": [c.to_public_dict() for c in items],
            "total": total,
            "limit": limit,
            "offset": offset,
            "execution_enabled": False,
        }
    except PersistenceUnavailableError:
        return {
            "commands": [],
            "total": 0,
            "limit": limit,
            "offset": offset,
            "execution_enabled": False,
            "persistence_available": False,
            "failure_reason": "persistence_unavailable",
            "http_hint": 503,
        }


def list_audits(
    limit: int = 50, *, offset: int = 0, command_id: Optional[str] = None
) -> Dict[str, Any]:
    try:
        items, total = AUDIT_STORE.list_page(
            limit, offset=offset, command_id=command_id
        )
        return {
            "audits": items,
            "total": total,
            "limit": limit,
            "offset": offset,
        }
    except PersistenceUnavailableError:
        return {
            "audits": [],
            "total": 0,
            "limit": limit,
            "offset": offset,
            "persistence_available": False,
            "failure_reason": "persistence_unavailable",
            "http_hint": 503,
        }


def _error_payload(
    status: str,
    reason: str,
    *,
    status_code: int = 400,
    command: Optional[Command] = None,
) -> Dict[str, Any]:
    if command:
        body = command.to_public_dict()
        body["failure_reason"] = reason
        body["execution_enabled"] = False
        body["http_hint"] = status_code
        return body
    return {
        "status": status,
        "failure_reason": reason,
        "execution_enabled": False,
        "executed": False,
        "http_hint": status_code,
    }
