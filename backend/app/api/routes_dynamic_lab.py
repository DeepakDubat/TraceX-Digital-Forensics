import json
import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks, Request, Header
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from backend.app.config import settings
from backend.app.core.models import (
    DynamicSandboxRun,
    SandboxCapabilityMatrix,
    SandboxEnvironmentInfo,
    DynamicTelemetryEvent,
    NetworkFlowRecord,
    DynamicObservation,
    DynamicArtifact,
    DynamicReport,
    ProcessTreeNode
)
from backend.app.database.repository import repo
from backend.app.core.user_auth import get_current_user
from backend.app.analyzers.dynamic.sandbox_manager import sandbox_manager
from backend.app.analyzers.dynamic.process_monitor import process_monitor
from backend.app.analyzers.dynamic.network_monitor import dynamic_network_monitor
from backend.app.analyzers.dynamic.filesystem_monitor import filesystem_monitor
from backend.app.analyzers.dynamic.registry_monitor import registry_monitor
from backend.app.analyzers.dynamic.sandbox_registry import sandbox_registry
from backend.app.analyzers.dynamic.vm_detector import vm_detector
from backend.app.analyzers.dynamic.worker_auth import worker_auth_manager, WorkerAuthError
from backend.app.analyzers.dynamic.resource_manager import vm_resource_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dynamic", tags=["Dynamic Analysis Lab"])

# ==============================================================================
# REQUEST & RESPONSE SCHEMAS
# ==============================================================================

class CreateAnalysisRequest(BaseModel):
    investigation_id: str
    evidence_id: Optional[str] = None
    environment_id: str = "env-windows-sandbox"
    network_policy: Optional[str] = None
    network_mode: Optional[str] = None
    timeout_seconds: int = 120
    sample_type: Optional[str] = None
    sample_path: Optional[str] = None
    sample_name: Optional[str] = None
    analysis_options: Optional[Dict[str, Any]] = None

class StartAnalysisRequest(BaseModel):
    confirm_execution: bool = True
    analyst_notes: Optional[str] = None

class FinalizeAnalysisRequest(BaseModel):
    duration_seconds: float = 60.0

# ==============================================================================
# CAPABILITIES & ENVIRONMENT DISCOVERY ENDPOINTS
# ==============================================================================

@router.get("/capabilities", response_model=SandboxCapabilityMatrix)
def get_capabilities(
    refresh: bool = Query(False),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Returns the comprehensive host virtualization, container, and emulator capability matrix.
    Reports honest ground truth without assumptions.
    """
    return sandbox_manager.get_capabilities(force_refresh=refresh)

@router.get("/environments", response_model=List[SandboxEnvironmentInfo])
def list_environments(
    refresh: bool = Query(False),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Lists all supported, configured, and discovered sandbox execution environments.
    """
    return sandbox_manager.list_environments(force_refresh=refresh)

@router.get("/dashboard")
def get_dashboard_summary(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Returns aggregated KPIs, active analyses count, detections, and environment health.
    """
    return sandbox_manager.get_dashboard_metrics()

@router.post("/environments/{env_id}/test")
def test_environment_readiness(
    env_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Executes a live preflight diagnostic test against a specific sandbox environment.
    """
    provider = sandbox_registry.get_provider(env_id)
    if not provider:
        raise HTTPException(status_code=404, detail=f"Environment '{env_id}' not found.")
    return provider.preflight()

# ==============================================================================
# DYNAMIC ANALYSIS LIFECYCLE ENDPOINTS
# ==============================================================================

@router.post("/analyses", response_model=DynamicSandboxRun)
def create_analysis_session(
    payload: CreateAnalysisRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Creates and stages a dynamic analysis session.
    Verifies that the target file is genuine evidence, verifies SHA-256,
    and stages an isolated working copy in staging/. Zero host execution.
    """
    try:
        user_id = current_user.get("id") if isinstance(current_user, dict) else None
        evidence_id = payload.evidence_id or payload.investigation_id
        net_policy = payload.network_policy or payload.network_mode or "DISABLED"
        return sandbox_manager.create_analysis_session(
            investigation_id=payload.investigation_id,
            evidence_id=evidence_id,
            environment_id=payload.environment_id,
            network_policy=net_policy,
            timeout_seconds=payload.timeout_seconds,
            user_id=user_id
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create dynamic analysis session: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to stage dynamic analysis: {str(e)}")

@router.get("/analyses", response_model=List[DynamicSandboxRun])
def list_analyses(
    investigation_id: Optional[str] = Query(None),
    target_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retrieves a list of dynamic analysis runs.
    """
    if investigation_id:
        return repo.list_sandbox_runs(investigation_id)
    return repo.list_all_sandbox_runs(target_type=target_type, status=status, limit=limit, offset=offset)

@router.get("/analyses/{analysis_id}", response_model=DynamicSandboxRun)
def get_analysis_session(
    analysis_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retrieves full details of a specific dynamic analysis run.
    """
    run = repo.get_sandbox_run(analysis_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis session not found.")
    return run

@router.post("/analyses/{analysis_id}/start", response_model=DynamicSandboxRun)
def start_analysis_session(
    analysis_id: str,
    payload: Optional[StartAnalysisRequest] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Commences isolated execution in the designated guest environment.
    Requires explicit examiner confirmation.
    """
    payload = payload or StartAnalysisRequest()
    if not payload.confirm_execution:
        raise HTTPException(status_code=400, detail="Explicit examiner confirmation is required to commence dynamic execution.")

    try:
        return sandbox_manager.start_analysis_session(analysis_id)
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to start dynamic session {analysis_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyses/{analysis_id}/finalize", response_model=DynamicReport)
def finalize_analysis_session(
    analysis_id: str,
    payload: Optional[FinalizeAnalysisRequest] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Finalizes dynamic analysis: ingests telemetry, performs behavioral heuristic analysis,
    generates sealed report, restores guest snapshot, and cleans up host staging.
    """
    payload = payload or FinalizeAnalysisRequest()
    try:
        return sandbox_manager.finalize_analysis_session(analysis_id, duration=payload.duration_seconds)
    except Exception as e:
        logger.error(f"Failed to finalize dynamic session {analysis_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyses/{analysis_id}/cancel", response_model=DynamicSandboxRun)
def cancel_analysis_session(
    analysis_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Emergency cancellation: immediately kills guest execution, restores snapshot,
    and cleans up staging files.
    """
    return sandbox_manager.cancel_analysis_session(analysis_id)

# ==============================================================================
# TELEMETRY, PROCESS TREE & ARTIFACT ENDPOINTS
# ==============================================================================

@router.get("/analyses/{analysis_id}/events", response_model=List[DynamicTelemetryEvent])
def get_analysis_events(
    analysis_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retrieves all recorded runtime events (processes, files, registry, sockets).
    """
    run = repo.get_sandbox_run(analysis_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis session not found.")
    return repo.list_telemetry_events(run.investigation_id, run_id=analysis_id)

@router.get("/analyses/{analysis_id}/process-tree", response_model=List[ProcessTreeNode])
def get_process_tree(
    analysis_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Reconstructs the hierarchical parent-child process execution tree.
    """
    run = repo.get_sandbox_run(analysis_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis session not found.")
    return process_monitor.build_process_tree(run.investigation_id, run_id=analysis_id)

@router.get("/analyses/{analysis_id}/network", response_model=List[NetworkFlowRecord])
def get_network_flows(
    analysis_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retrieves all outbound network flows, DNS resolutions, and HTTP metadata.
    """
    run = repo.get_sandbox_run(analysis_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis session not found.")
    return repo.list_network_flow_records(run.investigation_id, run_id=analysis_id)

@router.get("/analyses/{analysis_id}/observations", response_model=List[DynamicObservation])
def get_observations(
    analysis_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retrieves high-confidence behavioral observations mapped to MITRE ATT&CK.
    """
    run = repo.get_sandbox_run(analysis_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis session not found.")
    return repo.list_dynamic_observations(run.investigation_id, run_id=analysis_id)

@router.get("/analyses/{analysis_id}/artifacts", response_model=List[DynamicArtifact])
def get_artifacts(
    analysis_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retrieves all cryptographically hashed dropped files, PCAP captures, and memory artifacts.
    """
    run = repo.get_sandbox_run(analysis_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis session not found.")
    return repo.list_dynamic_artifacts(run.investigation_id, run_id=analysis_id)

@router.get("/analyses/{analysis_id}/report", response_model=DynamicReport)
def get_analysis_report(
    analysis_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retrieves the sealed dynamic forensic report for an analysis run.
    """
    report = repo.get_dynamic_report_by_run(analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report has not yet been generated for this session.")
    return report


# ==============================================================================
# VM ENVIRONMENT & RESOURCE MANAGEMENT ENDPOINTS
# ==============================================================================

@router.get("/vm-environment")
def get_vm_environment_status(
    current_user: Dict[str, Any] = Depends(get_current_user),
    refresh: bool = False
):
    """
    Returns full topometry of the VM environment, hypervisor detection,
    nested virtualization extensions, resource allocations, and setup guidance.
    """
    env_info = vm_detector.get_environment_info(force_refresh=refresh)
    res_status = vm_resource_manager.get_resource_status()
    return {
        "environment": env_info,
        "resources": res_status,
        "two_plane_architecture": {
            "manager_plane": "Active (Protected Forensics Environment)",
            "worker_plane": "Disposable Analysis Environments",
            "zero_host_execution_guaranteed": True
        }
    }


@router.post("/vm-environment/test-nested")
def test_nested_virtualization(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Executes a live test to verify if nested virtualization (VT-x/AMD-V)
    is active and capable of hosting child VMs or emulators.
    """
    env_info = vm_detector.get_environment_info(force_refresh=True)
    nested = env_info.get("cpu_virtualization", {}).get("nested_virtualization_available", False)
    details = env_info.get("cpu_virtualization", {}).get("nested_details", "")
    return {
        "nested_virtualization_active": nested,
        "details": details,
        "recommended_action": env_info.get("deployment_mode", {}).get("actionable_setup", [])
    }


# ==============================================================================
# MANAGER-WORKER RESTRICTED COMMUNICATION ENDPOINTS (PHASE 8)
# ==============================================================================

def _extract_worker_token(request: Request, authorization: Optional[str] = Header(None)) -> str:
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
    elif request.headers.get("X-Worker-Token"):
        token = request.headers.get("X-Worker-Token")
    elif request.query_params.get("token"):
        token = request.query_params.get("token")

    if not token:
        raise HTTPException(status_code=401, detail="Worker authentication required: missing worker authorization token.")
    return token


@router.get("/workers/{run_id}/payload")
def get_worker_payload(
    run_id: str,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """
    Restricted Worker API: Streams the staged evidence payload to the worker VM.
    Enforces per-worker cryptographic token validation and SHA-256 integrity verification.
    Workers CANNOT access manager credentials, user sessions, or databases.
    """
    token = _extract_worker_token(request, authorization)
    try:
        worker_auth_manager.validate_worker_token(run_id, token)
    except WorkerAuthError as e:
        raise HTTPException(status_code=403, detail=str(e))

    run = repo.get_sandbox_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Analysis run not found.")

    staged_path = settings.DATA_DIR / "staging" / run_id / run.target_binary
    if not staged_path.exists():
        raise HTTPException(status_code=404, detail="Staged evidence file not found.")

    file_bytes = staged_path.read_bytes()
    file_sha256 = getattr(run, "target_sha256", None)

    import io
    return StreamingResponse(
        io.BytesIO(file_bytes),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{run.target_binary}"',
            "X-Evidence-SHA256": file_sha256 or "",
            "X-Target-Binary": run.target_binary,
            "X-Timeout-Seconds": str(getattr(run, "timeout_seconds", 120))
        }
    )


@router.post("/workers/{run_id}/heartbeat")
def worker_heartbeat(
    run_id: str,
    request: Request,
    payload: Optional[Dict[str, Any]] = None,
    authorization: Optional[str] = Header(None)
):
    """
    Restricted Worker API: Records worker health heartbeat and active status.
    """
    token = _extract_worker_token(request, authorization)
    try:
        worker_auth_manager.validate_worker_token(run_id, token)
    except WorkerAuthError as e:
        raise HTTPException(status_code=403, detail=str(e))

    client_ip = request.client.host if request.client else "unknown"
    agent_ver = (payload or {}).get("agent_version")
    ack = worker_auth_manager.record_heartbeat(run_id, client_ip, agent_ver)
    return ack


@router.post("/workers/{run_id}/telemetry")
def worker_submit_telemetry(
    run_id: str,
    payload: Dict[str, Any],
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """
    Restricted Worker API: Receives normalized telemetry batches (processes, files, registry, net flows).
    """
    token = _extract_worker_token(request, authorization)
    try:
        worker_auth_manager.validate_worker_token(run_id, token)
    except WorkerAuthError as e:
        raise HTTPException(status_code=403, detail=str(e))

    ingested = worker_auth_manager.record_telemetry_batch(run_id, payload)
    return {"status": "success", "run_id": run_id, "events_ingested": ingested}


@router.post("/workers/{run_id}/artifacts")
async def worker_upload_artifact(
    run_id: str,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """
    Restricted Worker API: Receives dropped files recovered during dynamic execution.
    """
    token = _extract_worker_token(request, authorization)
    try:
        worker_auth_manager.validate_worker_token(run_id, token)
    except WorkerAuthError as e:
        raise HTTPException(status_code=403, detail=str(e))

    filename = request.headers.get("X-Artifact-Filename", "dropped_artifact.bin")
    rel_path = request.headers.get("X-Artifact-Path", filename)
    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="Empty artifact body.")

    record = worker_auth_manager.record_dropped_artifact(run_id, filename, body, rel_path)
    return {"status": "success", "artifact": record}
