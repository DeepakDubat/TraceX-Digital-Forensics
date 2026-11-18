"""
TraceX Central Report Storage & Download Manager
Universal Digital Forensics & Cyber Investigation Suite v2.0.0

Manages persistent on-disk report generation, storage, and operating system integration:
1. Central Storage Root: %USERPROFILE%\\Documents\\TraceX\\Reports
2. Investigation Isolation: Documents\\TraceX\\Reports\\<INVESTIGATION_ID>\\
3. Collision Handling & Versioning: Safe unique naming without unintentional overwrites
4. Filesystem Verification: Verifies file existence and non-zero size before confirming success
5. OS Shell Integration: "Open Report" and "Show in Folder" (Windows Explorer selection)
6. Diagnostic Logging: Structured audit trail without credential or PII leakage
"""

import os
import re
import sys
import uuid
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger("tracex.download_manager")

def get_reports_root_dir() -> Path:
    """
    Returns the central report storage location on Windows.
    Default: %USERPROFILE%\\Documents\\TraceX\\Reports
    Automatically creates the hierarchy if missing.
    """
    user_profile = os.environ.get("USERPROFILE") or str(Path.home())
    root_dir = Path(user_profile) / "Documents" / "TraceX" / "Reports"
    root_dir.mkdir(parents=True, exist_ok=True)
    return root_dir.resolve()

def get_ip_reports_root_dir() -> Path:
    """
    Returns the central IP intelligence reports storage location on Windows.
    Default: %USERPROFILE%\\Documents\\TraceX\\IP Reports
    Automatically creates the hierarchy if missing.
    """
    user_profile = os.environ.get("USERPROFILE") or str(Path.home())
    root_dir = Path(user_profile) / "Documents" / "TraceX" / "IP Reports"
    root_dir.mkdir(parents=True, exist_ok=True)
    return root_dir.resolve()

def get_approved_report_roots() -> List[Path]:
    """
    Returns canonical, resolved paths for all approved TraceX report root directories:
    1. Documents\\TraceX\\Reports\\
    2. Documents\\TraceX\\IP Reports\\
    """
    return [
        get_reports_root_dir().resolve(),
        get_ip_reports_root_dir().resolve()
    ]

def validate_safe_report_path(filepath_str: str) -> Path:
    """
    Validates that the provided filepath resides strictly within one of the approved
    TraceX report root directories.

    Security Guarantees:
    - Resolves all symlinks and relative path segments (Path.resolve())
    - Uses strict path containment check (target.relative_to(root))
    - Completely prevents directory traversal (../ or ..\\)
    - Rejects access to arbitrary directories or similarly named folders (e.g. Reports_evil)
    """
    if not filepath_str or not isinstance(filepath_str, str):
        raise ValueError("Invalid filepath: Path must be a non-empty string.")

    target = Path(filepath_str).resolve()
    approved_roots = get_approved_report_roots()

    for root in approved_roots:
        try:
            target.relative_to(root)
            return target
        except ValueError:
            continue

    raise PermissionError(
        f"Access denied: Target path '{target}' is outside approved TraceX report directories."
    )

def sanitize_filename_component(name: str) -> str:
    """Removes or replaces invalid Windows filesystem characters."""
    # Invalid characters in Windows filenames: \ / : * ? " < > |
    cleaned = re.sub(r'[\\/*?:"<>|]', '_', name.strip())
    # Remove control characters
    cleaned = "".join(c for c in cleaned if ord(c) >= 32)
    return cleaned or "Report"

def get_investigation_reports_dir(investigation_id: str) -> Path:
    """
    Returns the isolated directory for a specific investigation.
    e.g. %USERPROFILE%\\Documents\\TraceX\\Reports\\INV-20261117-4E15E0
    """
    safe_id = sanitize_filename_component(investigation_id)
    inv_dir = get_reports_root_dir() / safe_id
    inv_dir.mkdir(parents=True, exist_ok=True)
    return inv_dir.resolve()

def resolve_unique_filepath(target_dir: Path, base_filename: str, overwrite: bool = False) -> Path:
    """
    Resolves destination path. If overwrite is False and file exists,
    generates a versioned name like 'Forensic_Report (1).pdf'.
    """
    safe_name = sanitize_filename_component(base_filename)
    dest = target_dir / safe_name
    if overwrite or not dest.exists():
        return dest

    stem = dest.stem
    ext = dest.suffix
    counter = 1
    while True:
        candidate = target_dir / f"{stem} ({counter}){ext}"
        if not candidate.exists():
            return candidate
        counter += 1

def format_file_size(size_bytes: int) -> str:
    """Formats bytes into human readable string (KB, MB)."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"

def verify_and_save_report(
    investigation_id: str,
    format_type: str,
    unredact: bool = False,
    overwrite: bool = False,
    custom_filename: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates report, saves directly to %USERPROFILE%\\Documents\\TraceX\\Reports\\<ID>\\,
    verifies file exists and size > 0, records diagnostic log, and returns report metadata.
    """
    from backend.app.database.repository import repo
    from backend.app.reporting.pdf_generator import generate_apk_pdf_report, generate_apk_html_report
    from backend.app.reporting.txt_generator import generate_txt_forensic_report, export_iocs_csv
    from backend.app.reporting.exe_txt_generator import generate_exe_forensic_report, export_pe_iocs_csv
    from backend.app.reporting.master_report_generator import (
        generate_master_txt_report,
        generate_master_html_report,
        export_reproducibility_bundle_zip
    )
    from backend.app.core.redaction import redact_investigation_detail, redact_sensitive_text

    request_id = f"DLREQ-{uuid.uuid4().hex[:8].upper()}"
    norm_format = format_type.strip().lower()
    start_time = datetime.utcnow()

    # Step 1: Query investigation record
    detail = repo.get_investigation_detail(investigation_id, include_raw_secrets=unredact)
    if not detail:
        err_msg = f"Investigation record '{investigation_id}' not found in database."
        logger.error(f"[{request_id}] Failed: {err_msg}")
        return {
            "status": "failed",
            "request_id": request_id,
            "investigation_id": investigation_id,
            "error": err_msg
        }

    # Step 2: Target directory & filename resolution
    target_dir = get_investigation_reports_dir(investigation_id)
    app_prefix = "APK" if detail.record.file_type == "apk" else ("EXE" if detail.record.file_type in ("exe", "dll") else "Master")

    if custom_filename:
        base_name = custom_filename
    else:
        if norm_format == "pdf":
            base_name = f"Forensic_Report_{investigation_id}.pdf"
        elif norm_format == "html":
            base_name = f"Forensic_Report_{investigation_id}.html"
        elif norm_format == "txt":
            base_name = f"Forensic_Report_{investigation_id}.txt"
        elif norm_format == "csv":
            base_name = f"IOCs_{investigation_id}.csv"
        elif norm_format == "json":
            base_name = f"Evidence_Export_{investigation_id}.json"
        elif norm_format == "bundle" or norm_format == "zip":
            base_name = f"Forensic_Bundle_{investigation_id}.zip"
        else:
            base_name = f"Report_{investigation_id}.{norm_format}"

    target_path = resolve_unique_filepath(target_dir, base_name, overwrite=overwrite)

    # Step 3: Generate report content in memory
    try:
        content_bytes: bytes = b""

        if norm_format == "pdf":
            # Native PyMuPDF vector PDF
            content_bytes = generate_apk_pdf_report(detail, unredact_secrets=unredact)

        elif norm_format == "html":
            if detail.record.file_type == "apk":
                html_str = generate_apk_html_report(detail, unredact_secrets=unredact)
            else:
                u_detail = repo.get_universal_investigation_detail(investigation_id)
                if u_detail:
                    html_str = generate_master_html_report(u_detail)
                else:
                    html_str = generate_apk_html_report(detail, unredact_secrets=unredact)
            content_bytes = html_str.encode("utf-8")

        elif norm_format == "txt":
            if detail.record.file_type in ("exe", "dll"):
                txt_str = generate_exe_forensic_report(detail, unredact_secrets=unredact)
            elif detail.record.file_type == "apk":
                txt_str = generate_txt_forensic_report(detail, unredact_secrets=unredact)
            else:
                u_detail = repo.get_universal_investigation_detail(investigation_id)
                if u_detail:
                    txt_str = generate_master_txt_report(u_detail)
                else:
                    txt_str = generate_txt_forensic_report(detail, unredact_secrets=unredact)
            content_bytes = txt_str.encode("utf-8")

        elif norm_format == "csv":
            if detail.record.file_type in ("exe", "dll"):
                csv_str = export_pe_iocs_csv(detail.network_iocs, detail.c2_indicators)
            else:
                csv_str = export_iocs_csv(detail.network_iocs, detail.c2_indicators)
            content_bytes = csv_str.encode("utf-8")

        elif norm_format == "json":
            safe_detail = redact_investigation_detail(detail, unredact_secrets=unredact)
            json_str = redact_sensitive_text(safe_detail.model_dump_json(indent=2))
            content_bytes = json_str.encode("utf-8")

        elif norm_format in ("bundle", "zip"):
            import io
            import zipfile
            u_detail = repo.get_universal_investigation_detail(investigation_id)
            if u_detail:
                content_bytes = export_reproducibility_bundle_zip(u_detail)
            else:
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                    if detail.record.file_type in ("exe", "dll"):
                        zf.writestr(f"{investigation_id}_Forensic_Report.txt", generate_exe_forensic_report(detail, unredact))
                        zf.writestr(f"{investigation_id}_IOCs.csv", export_pe_iocs_csv(detail.network_iocs, detail.c2_indicators))
                    else:
                        zf.writestr(f"{investigation_id}_Forensic_Report.txt", generate_txt_forensic_report(detail, unredact))
                        zf.writestr(f"{investigation_id}_IOCs.csv", export_iocs_csv(detail.network_iocs, detail.c2_indicators))

                    zf.writestr(f"{investigation_id}_Forensic_Report.html", generate_apk_html_report(detail, unredact))
                    try:
                        zf.writestr(f"{investigation_id}_Forensic_Report.pdf", generate_apk_pdf_report(detail, unredact))
                    except Exception:
                        pass
                content_bytes = buf.getvalue()
        else:
            raise ValueError(f"Unsupported report format: '{format_type}'")

    except Exception as e:
        logger.exception(f"[{request_id}] Error compiling {format_type} report: {e}")
        return {
            "status": "failed",
            "request_id": request_id,
            "investigation_id": investigation_id,
            "error": f"Report compilation failed: {str(e)}"
        }

    # Step 4: Write to Windows filesystem with atomic safety
    try:
        temp_dest = target_path.with_suffix(target_path.suffix + f".tmp_{uuid.uuid4().hex[:6]}")
        with open(temp_dest, "wb") as f:
            f.write(content_bytes)
            f.flush()
            os.fsync(f.fileno())

        # Atomic replacement / rename
        if target_path.exists() and overwrite:
            target_path.unlink()
        temp_dest.replace(target_path)

    except Exception as e:
        if temp_dest.exists():
            try:
                temp_dest.unlink()
            except Exception:
                pass
        err_msg = f"Failed writing report to destination '{target_path}': {str(e)}"
        logger.error(f"[{request_id}] {err_msg}")
        return {
            "status": "failed",
            "request_id": request_id,
            "investigation_id": investigation_id,
            "error": err_msg
        }

    # Step 5: Critical Filesystem Verification: Check existence and non-zero size
    if not target_path.exists():
        err_msg = f"Post-write verification failed: File does not exist on disk at {target_path}"
        logger.error(f"[{request_id}] {err_msg}")
        return {
            "status": "failed",
            "request_id": request_id,
            "investigation_id": investigation_id,
            "error": err_msg
        }

    file_size = target_path.stat().st_size
    if file_size <= 0:
        err_msg = f"Post-write verification failed: File size is 0 bytes at {target_path}"
        logger.error(f"[{request_id}] {err_msg}")
        return {
            "status": "failed",
            "request_id": request_id,
            "investigation_id": investigation_id,
            "error": err_msg
        }

    # Step 6: Diagnostic Audit Logging
    duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
    logger.info(
        f"[DOWNLOAD_SUCCESS] req_id={request_id} inv_id={investigation_id} "
        f"format={norm_format} file={target_path.name} size={file_size} bytes ({format_file_size(file_size)}) "
        f"dest='{target_path}' duration={duration_ms:.1f}ms"
    )

    return {
        "status": "success",
        "request_id": request_id,
        "investigation_id": investigation_id,
        "format": norm_format,
        "filename": target_path.name,
        "filepath": str(target_path.resolve()),
        "directory": str(target_dir.resolve()),
        "file_size": file_size,
        "file_size_formatted": format_file_size(file_size),
        "created_at": datetime.utcnow().isoformat() + "Z"
    }

def list_saved_reports_for_investigation(investigation_id: str) -> List[Dict[str, Any]]:
    """Returns list of all verified reports saved on disk for an investigation."""
    inv_dir = get_investigation_reports_dir(investigation_id)
    if not inv_dir.exists():
        return []

    reports = []
    for item in inv_dir.iterdir():
        if item.is_file() and not item.name.endswith(".tmp"):
            try:
                st = item.stat()
                if st.st_size > 0:
                    ext = item.suffix.lstrip(".").lower()
                    reports.append({
                        "filename": item.name,
                        "filepath": str(item.resolve()),
                        "directory": str(inv_dir.resolve()),
                        "file_size": st.st_size,
                        "file_size_formatted": format_file_size(st.st_size),
                        "format": ext,
                        "modified_at": datetime.fromtimestamp(st.st_mtime).isoformat() + "Z"
                    })
            except Exception:
                pass

    # Sort descending by modified_at
    reports.sort(key=lambda x: x.get("modified_at", ""), reverse=True)
    return reports

def open_report_in_system(filepath_str: str) -> Dict[str, Any]:
    """
    Opens the report file in the user's default system application (PDF viewer, browser, etc.).
    Includes path traversal validation to ensure the file resides strictly within approved TraceX report roots.
    """
    target = validate_safe_report_path(filepath_str)

    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Report file not found: {target}")

    if os.name == "nt":
        os.startfile(str(target))
    else:
        subprocess.Popen(["xdg-open" if sys.platform != "darwin" else "open", str(target)])

    return {"status": "success", "action": "open", "filepath": str(target)}

def show_report_in_file_explorer(filepath_str: str) -> Dict[str, Any]:
    """
    Opens Windows File Explorer and highlights the specified report file,
    or opens the containing directory if selecting is unavailable or if target is a folder.
    Guarded against path traversal and restricted to approved report roots.
    """
    target = validate_safe_report_path(filepath_str)

    if not target.exists():
        raise FileNotFoundError(f"Target path not found: {target}")

    if os.name == "nt":
        if target.is_file():
            # Open explorer and select/highlight the specific report file
            try:
                subprocess.Popen(f'explorer.exe /select,"{target}"')
            except Exception as e:
                logger.warning(f"Failed to highlight file via explorer /select: {e}. Opening parent folder.")
                subprocess.Popen(f'explorer.exe "{target.parent}"')
        else:
            subprocess.Popen(f'explorer.exe "{target}"')
    else:
        folder = target.parent if target.is_file() else target
        subprocess.Popen(["xdg-open" if sys.platform != "darwin" else "open", str(folder)])

    return {"status": "success", "action": "show_in_folder", "target": str(target)}

def verify_report_path_exists(filepath_str: str) -> Dict[str, Any]:
    """
    Validates path containment and confirms the report file exists on disk with non-zero size.
    Used for safe clipboard copy and file actions.
    """
    target = validate_safe_report_path(filepath_str)

    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"Report file not found on disk: {target}")

    st = target.stat()
    return {
        "status": "success",
        "exists": True,
        "filepath": str(target),
        "filename": target.name,
        "file_size": st.st_size,
        "file_size_formatted": format_file_size(st.st_size)
    }
