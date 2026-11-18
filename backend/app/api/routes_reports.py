from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Query, Response, Depends
from fastapi.responses import PlainTextResponse
from backend.app.database.repository import repo
from backend.app.core.storage import workspace_mgr
from backend.app.core.user_auth import get_current_user
from backend.app.reporting.txt_generator import (
    generate_txt_forensic_report, export_iocs_csv
)
from backend.app.reporting.exe_txt_generator import (
    generate_exe_forensic_report, export_pe_iocs_csv
)
from backend.app.reporting.master_report_generator import generate_master_txt_report
from backend.app.core.redaction import redact_investigation_detail, redact_sensitive_text

router = APIRouter(prefix="/api", tags=["Reports"])

@router.get("/investigations/{investigation_id}/report/txt")
def download_txt_report(
    investigation_id: str,
    unredact: bool = Query(False),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Serves comprehensive plain-text forensic report (.txt).
    For APK: 14-section Android report.
    For EXE: 22-section Windows PE report.
    Unredacted exports require authentication and are audited to Chain of Custody.
    """
    detail = repo.get_investigation_detail(investigation_id, include_raw_secrets=unredact)
    if not detail:
        raise HTTPException(status_code=404, detail="Investigation record not found.")

    if unredact:
        from backend.app.analyzers.universal.integrity_ledger import record_custody_event
        try:
            record_custody_event(
                investigation_id=investigation_id,
                event_type="UNREDACTED_REPORT_DOWNLOAD",
                examiner=current_user.get("username", "Examiner"),
                verification_result="AUDITED",
                details={"action": "export_unredacted_txt_report", "user_id": current_user.get("id")}
            )
        except Exception:
            pass

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    if detail.record.file_type in ("exe", "dll"):
        report_text = generate_exe_forensic_report(detail, unredact_secrets=unredact)
        filename = f"EXE_Forensic_Report_{investigation_id}_{timestamp}.txt"
    elif detail.record.file_type == "apk":
        report_text = generate_txt_forensic_report(detail, unredact_secrets=unredact)
        filename = f"APK_Forensic_Report_{investigation_id}_{timestamp}.txt"
    else:
        u_detail = repo.get_universal_investigation_detail(investigation_id)
        if u_detail:
            report_text = generate_master_txt_report(u_detail)
        else:
            report_text = generate_txt_forensic_report(detail, unredact_secrets=unredact)
        filename = f"Master_Forensic_Report_{investigation_id}_{timestamp}.txt"

    return Response(
        content=report_text,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=\"{filename}\""}
    )

@router.get("/investigations/{investigation_id}/report/preview", response_class=PlainTextResponse)
def preview_txt_report(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Returns the plain-text report for viewing in the UI Report Viewer."""
    detail = repo.get_investigation_detail(investigation_id, include_raw_secrets=False)
    if not detail:
        raise HTTPException(status_code=404, detail="Investigation record not found.")
    if detail.record.file_type == "exe":
        return generate_exe_forensic_report(detail, unredact_secrets=False)
    elif detail.record.file_type == "apk":
        return generate_txt_forensic_report(detail, unredact_secrets=False)
    else:
        u_detail = repo.get_universal_investigation_detail(investigation_id)
        if u_detail:
            return generate_master_txt_report(u_detail)
        return generate_txt_forensic_report(detail, unredact_secrets=False)

@router.get("/investigations/{investigation_id}/report/html")
def download_html_report(
    investigation_id: str,
    unredact: bool = Query(False),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Serves comprehensive, responsive HTML forensic report (.html).
    Works universally across APK, EXE, and multi-artifact cases.
    """
    from backend.app.reporting.pdf_generator import generate_apk_html_report
    from backend.app.reporting.master_report_generator import generate_master_html_report

    detail = repo.get_investigation_detail(investigation_id, include_raw_secrets=unredact)
    if not detail:
        raise HTTPException(status_code=404, detail="Investigation record not found.")

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    if detail.record.file_type == "apk":
        html_content = generate_apk_html_report(detail, unredact_secrets=unredact)
        filename = f"APK_Forensic_Report_{investigation_id}_{timestamp}.html"
    else:
        u_detail = repo.get_universal_investigation_detail(investigation_id)
        if u_detail:
            html_content = generate_master_html_report(u_detail)
        else:
            html_content = generate_apk_html_report(detail, unredact_secrets=unredact)
        filename = f"Forensic_Report_{investigation_id}_{timestamp}.html"

    return Response(
        content=html_content,
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=\"{filename}\""}
    )

@router.get("/investigations/{investigation_id}/report/pdf")
def download_pdf_report(
    investigation_id: str,
    unredact: bool = Query(False),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Serves print-ready, professional digital forensics PDF report (.pdf).
    Law-enforcement and cyber-cell audit compliant.
    """
    from backend.app.reporting.pdf_generator import generate_apk_pdf_report

    detail = repo.get_investigation_detail(investigation_id, include_raw_secrets=unredact)
    if not detail:
        raise HTTPException(status_code=404, detail="Investigation record not found.")

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    pdf_bytes = generate_apk_pdf_report(detail, unredact_secrets=unredact)
    filename = f"Forensic_Report_{investigation_id}_{timestamp}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=\"{filename}\""}
    )

@router.get("/investigations/{investigation_id}/report/csv")
def download_csv_iocs(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Serves normalized IOC table in CSV format."""
    detail = repo.get_investigation_detail(investigation_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Investigation record not found.")

    if detail.record.file_type == "exe":
        csv_data = export_pe_iocs_csv(detail.network_iocs, detail.c2_indicators)
        filename = f"EXE_IOCs_{investigation_id}.csv"
    else:
        csv_data = export_iocs_csv(detail.network_iocs, detail.c2_indicators)
        filename = f"APK_IOCs_{investigation_id}.csv"

    return Response(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=\"{filename}\""}
    )

@router.get("/investigations/{investigation_id}/report/json")
def download_json_export(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Serves complete structured investigation detail in JSON format."""
    detail = repo.get_investigation_detail(investigation_id, include_raw_secrets=False)
    if not detail:
        raise HTTPException(status_code=404, detail="Investigation record not found.")

    safe_detail = redact_investigation_detail(detail, unredact_secrets=False)
    json_str = redact_sensitive_text(safe_detail.model_dump_json(indent=2))
    prefix = "EXE" if detail.record.file_type == "exe" else "APK"
    filename = f"{prefix}_Investigation_{investigation_id}.json"

    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=\"{filename}\""}
    )

@router.get("/investigations/{investigation_id}/report/osint/indicators.csv")
def download_osint_indicators_csv(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Exports OSINT indicators as CSV."""
    from backend.app.reporting.master_report_generator import export_osint_indicators_csv
    indicators = repo.list_osint_indicators(investigation_id)
    csv_data = export_osint_indicators_csv(indicators)
    return Response(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=\"OSINT_Indicators_{investigation_id}.csv\""}
    )

@router.get("/investigations/{investigation_id}/report/osint/observations.csv")
def download_osint_observations_csv(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Exports OSINT observations as CSV."""
    from backend.app.reporting.master_report_generator import export_osint_observations_csv
    observations = repo.list_osint_observations(investigation_id)
    csv_data = export_osint_observations_csv(observations)
    return Response(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=\"OSINT_Observations_{investigation_id}.csv\""}
    )

@router.get("/investigations/{investigation_id}/report/osint/secrets.csv")
def download_secret_exposures_csv(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Exports secret exposures register as CSV."""
    from backend.app.reporting.master_report_generator import export_secret_exposure_csv
    secrets = repo.list_secret_exposure_findings(investigation_id)
    csv_data = export_secret_exposure_csv(secrets)
    return Response(
        content=csv_data,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=\"Secret_Exposures_{investigation_id}.csv\""}
    )

@router.get("/investigations/{investigation_id}/report/bundle")
def download_reproducibility_bundle(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Serves forensic reproducibility bundle ZIP.
    Works universally: if universal record exists, exports full multi-file bundle;
    otherwise generates a standalone forensic bundle containing TXT, HTML, PDF, and CSV.
    """
    import io
    import zipfile
    from backend.app.reporting.master_report_generator import export_reproducibility_bundle_zip
    from backend.app.reporting.pdf_generator import generate_apk_pdf_report, generate_apk_html_report
    from backend.app.reporting.txt_generator import generate_txt_forensic_report, export_iocs_csv
    from backend.app.reporting.exe_txt_generator import generate_exe_forensic_report, export_pe_iocs_csv

    u_detail = repo.get_universal_investigation_detail(investigation_id)
    if u_detail:
        zip_bytes = export_reproducibility_bundle_zip(u_detail)
    else:
        detail = repo.get_investigation_detail(investigation_id, include_raw_secrets=False)
        if not detail:
            raise HTTPException(status_code=404, detail="Investigation record not found.")

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            if detail.record.file_type == "exe":
                zf.writestr(f"{investigation_id}_Forensic_Report.txt", generate_exe_forensic_report(detail, False))
                zf.writestr(f"{investigation_id}_IOCs.csv", export_pe_iocs_csv(detail.network_iocs, detail.c2_indicators))
            else:
                zf.writestr(f"{investigation_id}_Forensic_Report.txt", generate_txt_forensic_report(detail, False))
                zf.writestr(f"{investigation_id}_IOCs.csv", export_iocs_csv(detail.network_iocs, detail.c2_indicators))

            zf.writestr(f"{investigation_id}_Forensic_Report.html", generate_apk_html_report(detail, False))
            try:
                zf.writestr(f"{investigation_id}_Forensic_Report.pdf", generate_apk_pdf_report(detail, False))
            except Exception:
                pass

        zip_bytes = buf.getvalue()

    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=\"Forensic_Bundle_{investigation_id}.zip\""}
    )


# ==============================================================================
# CENTRAL REPORT STORAGE & NATIVE DOWNLOAD MANAGER ROUTES
# ==============================================================================

class ReportSaveRequest(BaseModel):
    format: str = "pdf"
    unredact: bool = False
    overwrite: bool = False
    custom_filename: Optional[str] = None

class ReportPathActionRequest(BaseModel):
    filepath: str

@router.post("/investigations/{investigation_id}/report/save")
def save_report_to_documents(
    investigation_id: str,
    req: ReportSaveRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Compiles forensic report and saves it directly to:
    %USERPROFILE%\\Documents\\TraceX\\Reports\\<INVESTIGATION_ID>\\
    Performs atomic write, verifies file existence and non-zero size on disk.
    """
    from backend.app.reporting.download_manager import verify_and_save_report

    result = verify_and_save_report(
        investigation_id=investigation_id,
        format_type=req.format,
        unredact=req.unredact,
        overwrite=req.overwrite,
        custom_filename=req.custom_filename
    )

    if result.get("status") != "success":
        raise HTTPException(
            status_code=500,
            detail=result.get("error", "Failed to compile and save report to disk.")
        )

    return result

@router.get("/investigations/{investigation_id}/report/saved-files")
def get_saved_reports_for_investigation(
    investigation_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Returns list of all reports verified and saved on disk in:
    %USERPROFILE%\\Documents\\TraceX\\Reports\\<INVESTIGATION_ID>\\
    """
    from backend.app.reporting.download_manager import list_saved_reports_for_investigation
    return list_saved_reports_for_investigation(investigation_id)

@router.post("/reports/open-file")
def open_report_file(
    req: ReportPathActionRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Launches the report in the operating system's default viewer (PDF reader, browser).
    Guarded against path traversal attacks.
    """
    from backend.app.reporting.download_manager import open_report_in_system
    try:
        return open_report_in_system(req.filepath)
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except FileNotFoundError as fe:
        raise HTTPException(status_code=404, detail=str(fe))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to open report: {str(e)}")

@router.post("/reports/show-in-folder")
def show_report_in_folder(
    req: ReportPathActionRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Opens Windows File Explorer and selects/highlights the saved report file.
    Guarded against path traversal attacks.
    """
    from backend.app.reporting.download_manager import show_report_in_file_explorer
    try:
        return show_report_in_file_explorer(req.filepath)
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except FileNotFoundError as fe:
        raise HTTPException(status_code=404, detail=str(fe))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to show report in folder: {str(e)}")

@router.post("/reports/verify-path")
def verify_report_path(
    req: ReportPathActionRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Verifies that a report exists on disk within approved TraceX report roots.
    Validates path containment and returns metadata for clipboard and UI actions.
    """
    from backend.app.reporting.download_manager import verify_report_path_exists
    try:
        return verify_report_path_exists(req.filepath)
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except FileNotFoundError as fe:
        raise HTTPException(status_code=404, detail=str(fe))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to verify report path: {str(e)}")



