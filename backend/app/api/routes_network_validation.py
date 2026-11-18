import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from backend.app.config import settings
from backend.app.core.models import AuthorizedNetworkScope, ActiveValidationResult
from backend.app.database.repository import repo
from backend.app.core.user_auth import get_current_user
from backend.app.analyzers.network.active_validator import (
    active_validator,
    set_external_request_kill_switch,
    is_kill_switch_active
)

router = APIRouter(prefix="/api/network-validation", tags=["Authorized Network Validation"])

class CreateScopeRequest(BaseModel):
    investigation_id: str
    case_id: Optional[str] = None
    authorized_targets: List[str] = Field(..., min_length=1)
    allowed_test_types: List[str] = Field(default=["DNS", "TCP_CONNECT", "TLS_INSPECT", "HTTPS_HEAD"])
    allowed_ports: List[int] = Field(default=[80, 443])
    authorization_note: str = Field(..., min_length=5)
    operator_name: str = Field(..., min_length=2)
    operator_confirmed: bool = Field(..., description="Operator must explicitly confirm authorization")
    request_budget: int = Field(default=20, ge=1, le=100)
    duration_hours: int = Field(default=24, ge=1, le=168) # 1 hour to 7 days

class ExecuteValidationRequest(BaseModel):
    scope_id: str
    investigation_id: str
    target: str
    test_type: str # DNS, TCP_CONNECT, TLS_INSPECT, HTTPS_HEAD
    port: Optional[int] = None

class KillSwitchRequest(BaseModel):
    active: bool
    reason: Optional[str] = None

@router.post("/scopes", response_model=AuthorizedNetworkScope)
def create_scope(payload: CreateScopeRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Creates an explicit, auditable authorized target scope record.
    Requires explicit operator confirmation and defined request budget.
    """
    if not payload.operator_confirmed:
        raise HTTPException(
            status_code=400,
            detail="Scope creation rejected: Explicit operator confirmation is mandatory."
        )

    now = datetime.utcnow()
    expires_at = now + timedelta(hours=payload.duration_hours)

    scope_id = f"SCOPE-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    scope = AuthorizedNetworkScope(
        id=scope_id,
        investigation_id=payload.investigation_id,
        case_id=payload.case_id or payload.investigation_id,
        authorized_targets=[t.strip() for t in payload.authorized_targets if t.strip()],
        allowed_test_types=payload.allowed_test_types,
        allowed_ports=payload.allowed_ports,
        authorization_note=payload.authorization_note,
        operator_name=payload.operator_name,
        operator_confirmed=payload.operator_confirmed,
        request_budget=payload.request_budget,
        requests_used=0,
        created_at_utc=now.isoformat(),
        expires_at_utc=expires_at.isoformat(),
        is_revoked=False
    )
    repo.create_authorized_scope(scope)
    return scope

@router.get("/scopes/{investigation_id}", response_model=List[AuthorizedNetworkScope])
def list_scopes(investigation_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Lists all active and expired scopes for an investigation."""
    return repo.list_authorized_scopes(investigation_id)

@router.post("/scopes/{scope_id}/revoke")
def revoke_scope(scope_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Immediately revokes an authorization scope."""
    scope = repo.get_authorized_scope(scope_id)
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found.")
    repo.revoke_scope(scope_id)
    return {"status": "success", "message": f"Scope {scope_id} revoked immediately."}

@router.post("/execute", response_model=ActiveValidationResult)
def execute_validation_test(payload: ExecuteValidationRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Executes a low-impact network validation check against an explicitly authorized target.
    Enforces scope allowlist, SSRF / RFC 1918 blocking, and budget limits.
    """
    ttype = payload.test_type.upper()
    if ttype == "DNS":
        return active_validator.execute_dns_lookup(
            payload.scope_id,
            payload.investigation_id,
            payload.target
        )
    elif ttype == "TCP_CONNECT":
        port = payload.port or 443
        return active_validator.execute_tcp_connect(
            payload.scope_id,
            payload.investigation_id,
            payload.target,
            port=port
        )
    elif ttype == "TLS_INSPECT":
        port = payload.port or 443
        return active_validator.execute_tls_inspection(
            payload.scope_id,
            payload.investigation_id,
            payload.target,
            port=port
        )
    elif ttype == "HTTPS_HEAD":
        return active_validator.execute_https_head(
            payload.scope_id,
            payload.investigation_id,
            payload.target
        )
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported validation test type '{payload.test_type}'. Allowed: DNS, TCP_CONNECT, TLS_INSPECT, HTTPS_HEAD."
        )

@router.get("/results/{investigation_id}", response_model=List[ActiveValidationResult])
def list_validation_results(investigation_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Lists all active validation check results and diagnostics for an investigation."""
    return repo.list_active_validation_results(investigation_id)

@router.post("/kill-switch")
def update_kill_switch(payload: KillSwitchRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Engages or disengages the emergency external-request kill switch."""
    set_external_request_kill_switch(payload.active)
    state_str = "ACTIVATED" if payload.active else "DEACTIVATED"
    return {
        "status": "success",
        "kill_switch_active": payload.active,
        "message": f"Emergency external-request kill switch {state_str}. Reason: {payload.reason or 'Manual operator action'}"
    }

@router.get("/kill-switch/status")
def get_kill_switch_status(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Returns the current state of the global external-request kill switch."""
    return {
        "kill_switch_active": is_kill_switch_active(),
        "local_only_mode": settings.LOCAL_ONLY_MODE
    }
