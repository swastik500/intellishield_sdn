"""Operator command infrastructure HTTP routes — preview/confirm/execute/status."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from dashboard.auth.deps import require_authenticated_principal, require_permission
from dashboard.auth.permissions import Permission
from dashboard.auth.principal import Principal

from . import service as cmd_service
from .actions import is_execution_allowlisted

commands_router = APIRouter(prefix="/api/operator", tags=["operator-commands"])


class PreviewRequest(BaseModel):
    action: str = Field(..., min_length=1, max_length=64)
    target_type: Optional[str] = Field(default=None, max_length=64)
    target_id: Optional[str] = Field(default=None, max_length=128)
    event_id: Optional[str] = Field(default=None, max_length=128)
    reason: str = Field(..., min_length=1, max_length=500)
    idempotency_key: Optional[str] = Field(default=None, max_length=128)
    event_timestamp: Optional[str] = Field(default=None, max_length=64)


class ConfirmRequest(BaseModel):
    confirmation_token: str = Field(..., min_length=8, max_length=256)


def _respond(body: dict) -> Any:
    hint = body.pop("http_hint", None)
    # Preserve server-authored execution flags when present (Phase 12)
    if "execution_enabled" not in body:
        body["execution_enabled"] = False
    if "executed" not in body:
        body["executed"] = False
    if hint == 503 or body.get("persistence_available") is False:
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "code": "PERSISTENCE_UNAVAILABLE",
                    "message": body.get("failure_reason") or "Command store unavailable",
                },
                "command": body,
                "execution_enabled": body.get("execution_enabled", False),
                "executed": body.get("executed", False),
            },
        )
    if body.get("status") == "DENIED" or hint == 403:
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "code": "FORBIDDEN",
                    "message": body.get("failure_reason") or "Insufficient permissions",
                },
                "command": body,
            },
        )
    if hint == 404:
        return JSONResponse(
            status_code=404,
            content={
                "error": {"code": "NOT_FOUND", "message": body.get("failure_reason") or "Not found"},
                "command": body,
            },
        )
    return body


@commands_router.post("/commands/preview")
async def preview(
    body: PreviewRequest,
    principal: Principal = Depends(require_authenticated_principal),
) -> Any:
    """Command preview. Does not execute."""
    result = cmd_service.preview_command(
        principal,
        action=body.action,
        target_type=body.target_type,
        target_id=body.target_id,
        event_id=body.event_id,
        reason=body.reason,
        idempotency_key=body.idempotency_key,
        event_timestamp=body.event_timestamp,
    )
    return _respond(result)


@commands_router.post("/commands/{command_id}/confirm")
async def confirm(
    command_id: str,
    body: ConfirmRequest,
    principal: Principal = Depends(require_authenticated_principal),
) -> Any:
    """Confirm pending command → READY_FOR_EXECUTION (allowlisted) or EXECUTION_DISABLED."""
    result = cmd_service.confirm_command(
        principal,
        command_id=command_id,
        confirmation_token=body.confirmation_token,
    )
    return _respond(result)


@commands_router.post("/commands/{command_id}/execute")
async def execute(
    command_id: str,
    principal: Principal = Depends(require_authenticated_principal),
) -> Any:
    """
    Phase 12 controlled execution for the single allowlisted action only.

    Requires prior confirmation and READY_FOR_EXECUTION. No mitigation or flow installs.
    """
    result = cmd_service.execute_command(principal, command_id=command_id)
    return _respond(result)


@commands_router.get("/commands")
async def list_commands(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = Query(default=None, max_length=64),
    principal: Principal = Depends(require_permission(Permission.INVESTIGATE_EVENTS)),
) -> Any:
    """Paginated read-only command history (durable store)."""
    body = cmd_service.list_commands(
        limit=limit, offset=offset, status=status, principal_id=None
    )
    return _respond(body) if body.get("http_hint") else body


@commands_router.get("/commands/{command_id}")
async def get_command(
    command_id: str,
    principal: Principal = Depends(require_permission(Permission.INVESTIGATE_EVENTS)),
) -> Any:
    """Read-only command status."""
    body = cmd_service.get_command(command_id)
    if not body:
        return JSONResponse(
            status_code=404,
            content={"error": {"code": "NOT_FOUND", "message": "Command not found"}},
        )
    # Reflect persisted allowlist / execution state (do not force False)
    action = body.get("action")
    if "execution_enabled" not in body:
        body["execution_enabled"] = bool(action and is_execution_allowlisted(action))
    if "executed" not in body:
        body["executed"] = body.get("status") == "EXECUTED"
    return body


@commands_router.get("/audits")
async def list_audits(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    command_id: Optional[str] = Query(default=None, max_length=128),
    principal: Principal = Depends(require_permission(Permission.INVESTIGATE_EVENTS)),
) -> Any:
    """Paginated read-only audit trail (append-only durable source)."""
    body = cmd_service.list_audits(limit=limit, offset=offset, command_id=command_id)
    return _respond(body) if body.get("http_hint") else body
