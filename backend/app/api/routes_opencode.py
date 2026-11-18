"""
TraceX OpenCode Forensic Engine API Routes
==========================================
Provides endpoints to manage OpenCode CLI integration, test installation and
synthetic analysis, configure execution parameters, trigger on-demand forensic
analysis, and review unverified AI observations.
"""

import logging
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Depends

from backend.app.config import settings
from backend.app.core.models import (
    AIObservation,
    AIRecommendation,
    AIAssistedNotes,
    AIObservationReviewRequest,
)
from backend.app.core.user_auth import get_current_user_optional, get_current_user
from backend.app.database.repository import repo
from backend.app.analyzers.universal.integrity_ledger import record_custody_event
from backend.app.integrations.opencode_engine import (
    detect_opencode_status,
    test_opencode_installation,
    test_opencode_analysis,
    analyze_investigation,
)

logger = logging.getLogger("tracex.routes_opencode")

router = APIRouter(prefix="/api", tags=["OpenCode AI Forensic Engine"])


class OpenCodeConfigRequest(BaseModel):
    enabled: Optional[bool] = None
    model: Optional[str] = None
    timeout_seconds: Optional[int] = None


class AIAnalyzeRequest(BaseModel):
    consent_approved: bool = False
    model: Optional[str] = None


class TestAnalysisRequest(BaseModel):
    consent_approved: bool = False


@router.get("/opencode/status")
def get_opencode_status_endpoint(
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Returns the operational status, installation info, version, and execution mode of OpenCode CLI."""
    return detect_opencode_status()


@router.post("/opencode/test-installation")
def post_test_installation_endpoint(
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Executes a diagnostic check against the local OpenCode CLI installation."""
    return test_opencode_installation()


@router.post("/opencode/test-analysis")
def post_test_analysis_endpoint(
    payload: Optional[TestAnalysisRequest] = None,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Executes a synthetic static forensic analysis to verify prompt dispatch and parsing."""
    consent = payload.consent_approved if payload else False
    return test_opencode_analysis(consent_approved=consent)


@router.post("/opencode/config")
def update_opencode_config_endpoint(
    payload: OpenCodeConfigRequest,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """Configures OpenCode CLI integration (enable/disable, model identifier, execution timeout)."""
    if payload.enabled is not None:
        settings.OPENCODE_ENABLED = payload.enabled
        repo.save_setting("opencode_enabled", "true" if payload.enabled else "false")

    if payload.model is not None:
        model_clean = payload.model.strip()
        settings.OPENCODE_MODEL = model_clean
        repo.save_setting("opencode_model", model_clean)

    if payload.timeout_seconds is not None:
        if payload.timeout_seconds < 5 or payload.timeout_seconds > 600:
            raise HTTPException(status_code=400, detail="Timeout must be between 5 and 600 seconds.")
        settings.OPENCODE_TIMEOUT_SECONDS = payload.timeout_seconds
        repo.save_setting("opencode_timeout_seconds", str(payload.timeout_seconds))

    return {
        "success": True,
        "message": "OpenCode configuration updated successfully.",
        "status": detect_opencode_status()
    }


@router.post("/investigations/{investigation_id}/ai-analyze")
def trigger_ai_analysis_endpoint(
    investigation_id: str,
    payload: Optional[AIAnalyzeRequest] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Triggers on-demand AI-assisted forensic analysis for an existing investigation.
    Runs in a safe subprocess, respects LOCAL_ONLY / HYBRID privacy modes,
    and returns observations and recommendations.
    """
    detail = repo.get_investigation_detail(investigation_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    record = detail.record
    consent = payload.consent_approved if payload else False
    override_model = payload.model if payload else None

    notes, obs, recs = analyze_investigation(
        investigation_id=investigation_id,
        detail=detail,
        filename=record.filename,
        file_type=record.file_type or "unknown",
        file_size_bytes=record.original_size or 0,
        sha256_hash=record.sha256 or "",
        consent_approved=consent,
        override_model=override_model
    )

    # Log an auditable Chain of Custody event if analysis completed or ran
    try:
        record_custody_event(
            investigation_id=investigation_id,
            event_type="AI_ANALYSIS_EXECUTED",
            examiner=current_user.get("username", "Examiner"),
            evidence_id=investigation_id,
            original_hash=record.sha256,
            working_copy_hash=record.sha256,
            verification_result="COMPLETED" if notes.execution_status == "COMPLETED" else "SKIPPED",
            details={
                "execution_status": notes.execution_status,
                "model_provider": notes.model_provider,
                "observations_count": len(obs),
                "recommendations_count": len(recs),
                "consent_approved": consent
            }
        )
    except Exception as e:
        logger.warning(f"Failed to record custody event for AI analysis: {e}")

    return {
        "success": notes.execution_status == "COMPLETED",
        "notes": notes,
        "observations": obs,
        "recommendations": recs
    }


@router.post("/investigations/{investigation_id}/ai-observations/{obs_id}/review")
def review_ai_observation_endpoint(
    investigation_id: str,
    obs_id: str,
    payload: AIObservationReviewRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Allows a human examiner to review an unverified AI observation.
    Accepts status='ACCEPTED', 'REJECTED', or 'UNVERIFIED'.
    Logs an auditable Chain of Custody record when an observation is accepted.
    """
    valid_statuses = ("ACCEPTED", "REJECTED", "UNVERIFIED")
    target_status = payload.status.upper().strip()
    if target_status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{payload.status}'. Must be one of: {', '.join(valid_statuses)}"
        )

    examiner_name = current_user.get("username", "Examiner")
    updated = repo.update_ai_observation_status(
        obs_id=obs_id,
        status=target_status,
        reviewer=examiner_name,
        review_notes=payload.review_notes
    )

    if not updated:
        raise HTTPException(status_code=404, detail="AI Observation not found.")

    # Record custody review event
    try:
        record_custody_event(
            investigation_id=investigation_id,
            event_type="AI_OBSERVATION_REVIEWED",
            examiner=examiner_name,
            evidence_id=obs_id,
            original_hash="",
            working_copy_hash="",
            verification_result=target_status,
            details={
                "observation_id": obs_id,
                "status": target_status,
                "title": updated.title,
                "review_notes": payload.review_notes
            }
        )
    except Exception as e:
        logger.warning(f"Failed to record custody event for observation review: {e}")

    return {
        "success": True,
        "message": f"AI Observation status updated to {target_status}.",
        "observation": updated
    }
