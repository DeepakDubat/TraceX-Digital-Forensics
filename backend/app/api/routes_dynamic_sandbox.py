import uuid
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Depends
from pydantic import BaseModel

from backend.app.config import settings
from backend.app.core.models import (
    SandboxToolStatus,
    DynamicSandboxRun,
    DynamicTelemetryEvent,
    NetworkFlowRecord,
    StaticDynamicCorrelation,
    EvidenceRiskAssessment
)
from backend.app.database.repository import repo
from backend.app.integrations.sandbox.sandbox_detector import sandbox_detector
from backend.app.integrations.sandbox.sandbox_manager import sandbox_manager
from backend.app.analyzers.universal.static_dynamic_correlator import StaticDynamicCorrelator
from backend.app.analyzers.universal.evidence_risk_assessor import EvidenceRiskAssessor
from backend.app.core.security import safe_copy_upload
from backend.app.core.user_auth import get_current_user

router = APIRouter(prefix="/api/sandbox", tags=["Dynamic Sandbox Analysis"])

class ImportTelemetryRequest(BaseModel):
    investigation_id: str
    evidence_id: str
    target_binary: str
    sandbox_environment: str = "Simulated Network (FakeNet-NG)"
    is_simulated_network: bool = True
    telemetry_json: Optional[Dict[str, Any]] = None

@router.get("/tools", response_model=List[SandboxToolStatus])
def get_sandbox_tools_status():
    """
    Detects and returns the actual operational availability of dynamic analysis sandboxes,
    network simulators, and packet dissectors (CAPE, FakeNet-NG, INetSim, Wireshark/tshark, Zeek, Suricata).
    """
    return sandbox_detector.detect_all_tools()

@router.get("/runs/{investigation_id}", response_model=List[DynamicSandboxRun])
def list_sandbox_runs(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Lists all dynamic sandbox runs for an investigation."""
    return repo.list_sandbox_runs(investigation_id)

@router.get("/runs/{run_id}/telemetry", response_model=List[DynamicTelemetryEvent])
def get_run_telemetry(
    run_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Retrieves process, file, registry, and API telemetry events for a specific sandbox run."""
    run = repo.get_sandbox_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Sandbox run not found.")
    return repo.list_telemetry_events(run.investigation_id, run_id=run_id)

@router.get("/runs/{run_id}/flows", response_model=List[NetworkFlowRecord])
def get_run_network_flows(
    run_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Retrieves all observed network flow records for a specific sandbox run."""
    run = repo.get_sandbox_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Sandbox run not found.")
    return repo.list_network_flow_records(run.investigation_id, run_id=run_id)

@router.post("/import-telemetry", response_model=DynamicSandboxRun)
def import_telemetry(
    payload: ImportTelemetryRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Imports structured telemetry events from an isolated guest VM or external network simulation.
    Strictly preserves zero-execution policy on the host workstation.
    """
    return sandbox_manager.import_sandbox_telemetry(
        investigation_id=payload.investigation_id,
        evidence_id=payload.evidence_id,
        target_binary=payload.target_binary,
        sandbox_environment=payload.sandbox_environment,
        is_simulated_network=payload.is_simulated_network,
        telemetry_json=payload.telemetry_json
    )

@router.post("/upload-pcap", response_model=DynamicSandboxRun)
async def upload_and_analyze_pcap(
    investigation_id: str = Form(...),
    evidence_id: str = Form(...),
    sandbox_environment: str = Form("Dedicated Analysis VM"),
    is_simulated_network: bool = Form(True),
    file: UploadFile = File(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Ingests and analyzes a PCAP/PCAPNG packet capture file associated with an investigation.
    Extracts flows, DNS queries, TLS SNI, HTTP requests, packet references, and computes SHA-256 hash.
    Does not execute binaries on the host workstation.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided.")

    dest_dir = settings.DATA_DIR / investigation_id / "captures"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / file.filename

    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    upload_error = None
    with open(dest_path, "wb") as dst:
        try:
            safe_copy_upload(file.file, dst, max_bytes=max_bytes)
        except ValueError as e:
            upload_error = (413, str(e))
        except (IOError, OSError) as e:
            upload_error = (507, f"Insufficient disk space or storage error: {str(e)}")
        except Exception as e:
            upload_error = (500, f"Upload processing failure: {str(e)}")
        finally:
            file.file.close()

    if upload_error:
        dest_path.unlink(missing_ok=True)
        err_status, err_detail = upload_error
        raise HTTPException(status_code=err_status, detail=err_detail)

    return sandbox_manager.import_sandbox_telemetry(
        investigation_id=investigation_id,
        evidence_id=evidence_id,
        target_binary=file.filename,
        sandbox_environment=sandbox_environment,
        is_simulated_network=is_simulated_network,
        pcap_file_path=dest_path
    )

correlator = StaticDynamicCorrelator()
risk_assessor = EvidenceRiskAssessor()

@router.post("/correlate/{investigation_id}", response_model=List[StaticDynamicCorrelation])
def trigger_correlation(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Correlates static capabilities (domains, imports, hashes) with dynamic runtime observations.
    Records honest confidence, alternative explanations, and forensic limitations.
    """
    detail = repo.get_universal_investigation_detail(investigation_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return correlator.correlate_investigation(detail)

@router.get("/correlations/{investigation_id}", response_model=List[StaticDynamicCorrelation])
def get_correlations(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Retrieves all static-versus-dynamic correlation records for an investigation."""
    return repo.list_static_dynamic_correlations(investigation_id)

@router.post("/assess-risk/{investigation_id}", response_model=EvidenceRiskAssessment)
def trigger_risk_assessment(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Generates an explainable multi-dimensional risk score across 7 distinct dimensions.
    """
    detail = repo.get_universal_investigation_detail(investigation_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return risk_assessor.assess_investigation(detail)

@router.get("/risk-assessment/{investigation_id}", response_model=Optional[EvidenceRiskAssessment])
def get_risk_assessment(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Retrieves the latest dimensional risk assessment for an investigation."""
    return repo.get_risk_assessment(investigation_id)
    """Retrieves the latest dimensional risk assessment for an investigation."""
    return repo.get_risk_assessment(investigation_id)

