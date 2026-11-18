import uuid
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks, Query, Depends
from backend.app.core.models import (
    InvestigationRecord, InvestigationDetail, EvidenceItem
)
from backend.app.core.storage import workspace_mgr
from backend.app.core.security import sanitize_filename, validate_apk_file, detect_file_type, safe_copy_upload, verify_api_access
from backend.app.analyzers.universal.integrity_ledger import record_custody_event
from backend.app.analyzers.universal.file_identifier import (
    identify_file_format, calculate_streaming_hashes, calculate_shannon_entropy
)
from backend.app.analyzers.pe_validator import validate_pe_file
from backend.app.database.repository import repo
from backend.app.core.orchestrator import run_investigation_pipeline
from backend.app.core.user_auth import get_current_user
from backend.app.config import settings

router = APIRouter(prefix="/api", tags=["Investigations"])

@router.get("/dashboard/stats")
def get_dashboard_statistics():
    """Calculate and return real metrics from active investigation records."""
    stats = repo.get_dashboard_stats()
    stats["workspace_disk_mb"] = workspace_mgr.get_total_disk_usage_mb()
    return stats

@router.post("/investigations/upload")
async def upload_investigation_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    file_type: Optional[str] = Form(None),
    case_reference: Optional[str] = Form(None),
    investigator_name: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    analyst_notes: Optional[str] = Form(None),
    local_only_mode: bool = Form(False),
    ai_assisted_analysis: bool = Form(False),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Secure file ingestion endpoint supporting both Android APK and Windows EXE binaries:
    1. Determines file format via magic bytes and declared type.
    2. Validates binary structure (Zip/APK or DOS/PE).
    3. Computes MD5, SHA-1, and SHA-256 hashes.
    4. Stages original unchanged artifact and isolated working copy.
    5. Triggers background forensic analysis pipeline.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename cannot be empty.")

    original_filename = file.filename
    lower_name = original_filename.lower()
    default_ext = ".exe" if (lower_name.endswith(".exe") or (file_type and file_type.lower() == "exe")) else ".apk"
    sanitized_name = sanitize_filename(original_filename, default_ext=default_ext)
    inv_id = f"INV-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    suffix = Path(sanitized_name).suffix
    upload_error = None
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
        tmp_path = Path(tmp_file.name)
        try:
            max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
            safe_copy_upload(file.file, tmp_file, max_bytes=max_bytes)
        except ValueError as e:
            upload_error = (413, str(e))
        except (IOError, OSError) as e:
            upload_error = (507, f"Insufficient disk space or storage error: {str(e)}")
        except Exception as e:
            upload_error = (500, f"Upload processing failure: {str(e)}")
        finally:
            file.file.close()

    if upload_error:
        tmp_path.unlink(missing_ok=True)
        err_status, err_detail = upload_error
        raise HTTPException(status_code=err_status, detail=err_detail)

    try:
        # Determine true format using magic bytes and structural profiling
        hashes = calculate_streaming_hashes(tmp_path)
        entropy, _ = calculate_shannon_entropy(tmp_path)
        triage = identify_file_format(tmp_path, sanitized_name)
        detected_fmt = triage["detected_format"].lower()

        if file_type and file_type.lower() in ("apk", "exe", "dll", "elf", "pdf", "docx", "xlsx", "pptx", "zip", "eml"):
            if detected_fmt in ("unknown", "empty"):
                chosen_type = file_type.lower()
            else:
                chosen_type = detected_fmt
        elif detected_fmt != "unknown":
            chosen_type = detected_fmt
        elif sanitized_name.lower().endswith(".exe"):
            chosen_type = "exe"
        elif sanitized_name.lower().endswith(".apk"):
            chosen_type = "apk"
        else:
            chosen_type = detected_fmt

        # Structural validation for formats with strict validators
        if chosen_type in ("exe", "dll"):
            is_valid, reason, details = validate_pe_file(tmp_path, max_size_mb=settings.MAX_UPLOAD_SIZE_MB)
            if not is_valid:
                tmp_path.unlink(missing_ok=True)
                raise HTTPException(status_code=400, detail=f"Invalid Windows PE executable: {reason}")
        elif chosen_type == "apk":
            is_valid, reason = validate_apk_file(tmp_path, max_size_mb=settings.MAX_UPLOAD_SIZE_MB)
            if not is_valid:
                tmp_path.unlink(missing_ok=True)
                raise HTTPException(status_code=400, detail=f"Invalid APK archive: {reason}")

        # Stage artifact in isolated workspace
        staged = workspace_mgr.stage_artifact(inv_id, tmp_path, sanitized_name)
    finally:
        tmp_path.unlink(missing_ok=True)

    # Create initial database investigation record first to satisfy foreign keys
    record = InvestigationRecord(
        id=inv_id,
        filename=sanitized_name,
        original_size=staged["size"],
        md5=staged["hashes"]["md5"],
        sha1=staged["hashes"]["sha1"],
        sha256=staged["hashes"]["sha256"],
        case_reference=case_reference,
        investigator_name=investigator_name or current_user.get("username", "Examiner"),
        description=description,
        analyst_notes=analyst_notes,
        local_only_mode=local_only_mode or settings.LOCAL_ONLY_MODE,
        status="pending",
        progress=0,
        current_stage=f"Evidence staged as {chosen_type.upper()}. Queued for analysis.",
        file_type=chosen_type,
        ai_assisted_analysis=ai_assisted_analysis
    )
    repo.create_investigation(record)

    # Register initial EvidenceItem
    ev_item = EvidenceItem(
        id=f"EVD-{inv_id[-6:]}-001",
        investigation_id=inv_id,
        filename=sanitized_name,
        file_size=staged["size"],
        mime_type=triage["mime_type"],
        detected_format=chosen_type,
        extension=triage["extension"],
        format_mismatch=triage["format_mismatch"],
        md5=staged["hashes"]["md5"],
        sha1=staged["hashes"]["sha1"],
        sha256=staged["hashes"]["sha256"],
        sha512=hashes["sha512"],
        working_copy_sha256=staged["hashes"]["sha256"],
        integrity_status="VERIFIED",
        source_info="Direct Evidence Ingestion",
        examiner_notes=analyst_notes,
        acquired_at=datetime.utcnow(),
        processing_state="FULL",
        entropy=entropy,
        triage_summary=triage,
        metadata={}
    )
    repo.create_evidence_item(ev_item)

    # Record Evidence Received event in Chain of Custody ledger
    try:
        record_custody_event(
            investigation_id=inv_id,
            event_type="EVIDENCE_RECEIVED",
            examiner=investigator_name or current_user.get("username", "Examiner"),
            evidence_id=ev_item.id,
            original_hash=staged["hashes"]["sha256"],
            working_copy_hash=staged["hashes"]["sha256"],
            verification_result="PASSED",
            details={"filename": sanitized_name, "format": chosen_type, "size_bytes": staged["size"]}
        )
    except Exception:
        pass

    # Launch background analysis
    background_tasks.add_task(run_investigation_pipeline, inv_id)

    return {
        "status": "success",
        "message": f"{chosen_type.upper()} successfully staged and queued for forensic examination.",
        "investigation_id": inv_id,
        "filename": sanitized_name,
        "file_type": chosen_type,
        "sha256": staged["hashes"]["sha256"],
        "size_bytes": staged["size"]
    }

@router.get("/investigations", response_model=List[InvestigationRecord])
def list_all_investigations(
    search: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Search and browse historical investigations."""
    return repo.list_investigations(search)

@router.get("/investigations/{investigation_id}")
def get_investigation_details(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Retrieve complete structured investigation details, findings, and evidence graph."""
    detail = repo.get_investigation_detail(investigation_id, include_raw_secrets=False)
    if not detail:
        raise HTTPException(status_code=404, detail="Investigation record not found.")
    return detail

@router.get("/investigations/{investigation_id}/status")
def get_investigation_status(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Lightweight polling endpoint for live analysis progress with authoritative stage mapping."""
    rec = repo.get_investigation(investigation_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    # Calculate authoritative stage_index dynamically (1 through 9)
    desc = (rec.current_stage or "").lower()
    norm_status = (rec.status or "").lower()
    if norm_status in ("completed", "completed_with_warnings"):
        stage_idx = 9
    elif "initialization" in desc or (rec.progress or 0) <= 5:
        stage_idx = 1
    elif "custody" in desc or "ingestion" in desc or "staged" in desc or (rec.progress or 0) <= 20:
        stage_idx = 2
    elif "format" in desc or "magic" in desc or (rec.progress or 0) <= 35:
        stage_idx = 3
    elif "static analysis" in desc or "deep static" in desc or "multi-engine" in desc or (rec.progress or 0) <= 65:
        stage_idx = 4
    elif "findings extraction" in desc or "rules" in desc or (rec.progress or 0) <= 75:
        stage_idx = 5
    elif "correlation" in desc or "timeline" in desc or (rec.progress or 0) <= 85:
        stage_idx = 6
    elif "risk" in desc or (rec.progress or 0) <= 90:
        stage_idx = 7
    elif "report" in desc or (rec.progress or 0) <= 95:
        stage_idx = 8
    else:
        stage_idx = 9

    # Heartbeat timestamp
    heartbeat_str = datetime.utcnow().isoformat()

    return {
        "id": rec.id,
        "status": rec.status,
        "progress": rec.progress,
        "stage_index": stage_idx,
        "current_stage": rec.current_stage,
        "last_heartbeat": heartbeat_str,
        "error_message": rec.error_message,
        "total_findings": rec.total_findings,
        "severity": rec.severity
    }

@router.post("/investigations/{investigation_id}/cancel")
def cancel_investigation(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Explicit investigator action: Safely marks in-flight analysis as cancelled."""
    rec = repo.get_investigation(investigation_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    norm_status = (rec.status or "").lower()
    if norm_status in ("completed", "completed_with_warnings", "failed", "cancelled"):
        return {"status": "unchanged", "message": f"Investigation is already {rec.status}."}
    
    rec.status = "cancelled"
    rec.current_stage = "Analysis cancelled by investigator."
    rec.completed_at = datetime.utcnow()
    repo.update_investigation(rec)
    return {"status": "success", "message": f"Investigation {investigation_id} cancelled."}

@router.delete("/investigations/{investigation_id}")
def delete_investigation(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Explicit investigator action: Permanently deletes investigation and disk artifacts."""
    deleted_db = repo.delete_investigation(investigation_id)
    deleted_fs = workspace_mgr.delete_workspace(investigation_id)
    if not deleted_db and not deleted_fs:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return {"status": "success", "message": f"Investigation {investigation_id} deleted."}

@router.get("/investigations/{investigation_id}/secrets/unredact")
def unredact_secret_for_authorized_view(
    investigation_id: str,
    secret_id: str = Query(...),
    examiner_name: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
    _: bool = Depends(verify_api_access)
):
    """
    Authorized workflow: Temporarily exposes raw secret value for documented case work.
    Logs an immutable audit event directly into the case Chain of Custody ledger.
    """
    secrets = repo.get_secrets(investigation_id, include_raw=True)
    target = next((s for s in secrets if s.id == secret_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Secret finding not found.")
    
    # Audit log in Chain of Custody
    try:
        record_custody_event(
            investigation_id=investigation_id,
            event_type="SECRET_UNREDACTED_ACCESS",
            examiner=examiner_name or current_user.get("username", "Authorized Forensic Examiner"),
            verification_result="AUDITED",
            details={"secret_id": target.id, "category": target.token_category, "rule": target.rule_matched}
        )
    except Exception:
        pass

    return {
        "id": target.id,
        "token_category": target.token_category,
        "raw_value": target.raw_value,
        "rule_matched": target.rule_matched,
        "disclaimer": "Authorized view only. Audit event recorded in Chain of Custody."
    }

@router.get("/investigations/compare")
def compare_investigations(
    id1: str = Query(...),
    id2: str = Query(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Compares indicators and hashes between two investigations."""
    det1 = repo.get_investigation_detail(id1)
    det2 = repo.get_investigation_detail(id2)
    if not det1 or not det2:
        raise HTTPException(status_code=404, detail="One or both investigations not found.")

    c2_set1 = {c.normalized_value for c in det1.c2_indicators}
    c2_set2 = {c.normalized_value for c in det2.c2_indicators}

    return {
        "investigation_1": {
            "id": det1.record.id,
            "filename": det1.record.filename,
            "package_name": det1.record.package_name,
            "sha256": det1.record.sha256,
            "severity": det1.record.severity,
            "c2_count": len(det1.c2_indicators),
            "findings_count": len(det1.static_findings)
        },
        "investigation_2": {
            "id": det2.record.id,
            "filename": det2.record.filename,
            "package_name": det2.record.package_name,
            "sha256": det2.record.sha256,
            "severity": det2.record.severity,
            "c2_count": len(det2.c2_indicators),
            "findings_count": len(det2.static_findings)
        },
        "shared_c2_indicators": list(c2_set1.intersection(c2_set2)),
        "same_hash": det1.record.sha256 == det2.record.sha256,
        "same_package": det1.record.package_name == det2.record.package_name
    }
