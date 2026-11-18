"""
TraceX Network Privacy Mode API Routes
======================================
Provides user-facing endpoints to query and mutate the authoritative
network mode between LOCAL_ONLY and HYBRID.
"""

from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Depends
from backend.app.core.network_mode import (
    get_current_network_mode,
    set_network_mode,
    NetworkMode
)
from backend.app.core.user_auth import get_current_user_optional

router = APIRouter(prefix="/api", tags=["Network Privacy Mode"])


class NetworkModeRequest(BaseModel):
    mode: Optional[str] = Field(None, description="Network mode: 'LOCAL_ONLY' or 'HYBRID'")
    local_only_mode: Optional[bool] = Field(None, description="Alternative boolean flag: true for LOCAL_ONLY, false for HYBRID")


@router.get("/system/network-mode")
@router.get("/network-mode")
def get_network_mode_endpoint(current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """
    Retrieves the authoritative current network privacy mode.
    Returns current mode, local_only_mode boolean flag, description, and feature lists.
    """
    return get_current_network_mode()


@router.post("/system/network-mode")
@router.post("/network-mode")
def update_network_mode_endpoint(
    payload: NetworkModeRequest,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """
    Updates and persists the global network privacy mode.
    Accepts mode='LOCAL_ONLY' or mode='HYBRID' (or local_only_mode=true/false).
    Immediately updates runtime settings and database.
    """
    target_mode = payload.mode
    if not target_mode and payload.local_only_mode is not None:
        target_mode = NetworkMode.LOCAL_ONLY.value if payload.local_only_mode else NetworkMode.HYBRID.value

    if not target_mode:
        raise HTTPException(
            status_code=400,
            detail="Missing required field: specify 'mode' ('LOCAL_ONLY' or 'HYBRID') or 'local_only_mode' (boolean)."
        )

    try:
        result = set_network_mode(target_mode)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
