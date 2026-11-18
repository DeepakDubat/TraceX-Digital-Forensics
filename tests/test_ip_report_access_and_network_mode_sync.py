"""
TraceX Security & Integrity Test Suite:
IP Report Access, Filesystem Sandbox Containment, and Network Mode Synchronization
Universal Digital Forensics & Cyber Investigation Suite v2.0.0
"""

import os
import sys
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database.repository import repo
from backend.app.core.models import InvestigationRecord
from backend.app.core.network_mode import (
    get_network_mode,
    get_current_network_mode,
    set_network_mode,
    NetworkMode
)
from backend.app.reporting.download_manager import (
    get_reports_root_dir,
    get_ip_reports_root_dir,
    get_approved_report_roots,
    validate_safe_report_path,
    open_report_in_system,
    show_report_in_file_explorer,
    verify_report_path_exists
)

client = TestClient(app)

TARGET_INV_ID = "INV-20261117-4BC62D"
ACTUAL_PDF_NAME = f"All_IPs_Intelligence_Dossier_{TARGET_INV_ID}.pdf"


@pytest.fixture(autouse=True)
def setup_test_investigation():
    # Ensure test investigation exists in DB
    if not repo.get_investigation_detail(TARGET_INV_ID):
        rec = InvestigationRecord(
            id=TARGET_INV_ID,
            filename="TestTarget.apk",
            original_size=1024000,
            md5="11112222333344445555666677778888",
            sha1="1111222233334444555566667777888899990000",
            sha256="1111222233334444555566667777888899990000111122223333444455556666",
            status="COMPLETED",
            risk_score=75.0
        )
        repo.create_investigation(rec)


# =============================================================================
# 1 & 2: REPORT ACCESS IN TRACEX\REPORTS AND TRACEX\IP REPORTS
# =============================================================================

def test_open_pdf_inside_tracex_reports():
    """Verify open_report_in_system validates and accepts files in Documents\\TraceX\\Reports."""
    reports_root = get_reports_root_dir()
    test_file = reports_root / "test_main_report.pdf"
    test_file.write_bytes(b"%PDF-1.4 Mock Main Report Content")

    try:
        with patch("os.startfile", create=True) as mock_startfile:
            res = open_report_in_system(str(test_file))
            assert res["status"] == "success"
            assert res["action"] == "open"
            assert res["filepath"] == str(test_file.resolve())
            mock_startfile.assert_called_once_with(str(test_file.resolve()))
    finally:
        if test_file.exists():
            test_file.unlink()


def test_open_pdf_inside_tracex_ip_reports():
    """Verify open_report_in_system validates and accepts files in Documents\\TraceX\\IP Reports."""
    ip_root = get_ip_reports_root_dir()
    inv_dir = ip_root / TARGET_INV_ID
    inv_dir.mkdir(parents=True, exist_ok=True)
    test_pdf = inv_dir / ACTUAL_PDF_NAME
    test_pdf.write_bytes(b"%PDF-1.4 Mock All IPs Intelligence Dossier")

    try:
        with patch("os.startfile", create=True) as mock_startfile:
            res = open_report_in_system(str(test_pdf))
            assert res["status"] == "success"
            assert res["action"] == "open"
            assert res["filepath"] == str(test_pdf.resolve())
            mock_startfile.assert_called_once_with(str(test_pdf.resolve()))
    finally:
        pass  # Keep actual target PDF if user needs it


# =============================================================================
# 3: SHOW IN FILE EXPLORER FOR IP REPORT
# =============================================================================

def test_show_ip_report_in_file_explorer():
    """Verify show_report_in_file_explorer targets the file with explorer /select."""
    ip_root = get_ip_reports_root_dir()
    inv_dir = ip_root / TARGET_INV_ID
    inv_dir.mkdir(parents=True, exist_ok=True)
    test_pdf = inv_dir / ACTUAL_PDF_NAME
    if not test_pdf.exists():
        test_pdf.write_bytes(b"%PDF-1.4 Mock Report")

    with patch("subprocess.Popen") as mock_popen:
        res = show_report_in_file_explorer(str(test_pdf))
        assert res["status"] == "success"
        assert res["action"] == "show_in_folder"
        assert res["target"] == str(test_pdf.resolve())
        mock_popen.assert_called_once()
        call_arg = mock_popen.call_args[0][0]
        assert "/select," in call_arg
        assert str(test_pdf.resolve()) in call_arg


# =============================================================================
# 4: COPY PATH VERIFICATION
# =============================================================================

def test_copy_path_verification_on_disk():
    """Verify verify_report_path_exists confirms existing file and metadata."""
    ip_root = get_ip_reports_root_dir()
    inv_dir = ip_root / TARGET_INV_ID
    test_pdf = inv_dir / ACTUAL_PDF_NAME
    if not test_pdf.exists():
        test_pdf.write_bytes(b"%PDF-1.4 Mock Report Data")

    res = verify_report_path_exists(str(test_pdf))
    assert res["status"] == "success"
    assert res["exists"] is True
    assert res["filepath"] == str(test_pdf.resolve())
    assert res["filename"] == ACTUAL_PDF_NAME
    assert res["file_size"] > 0

    # Also test API route POST /api/reports/verify-path
    api_res = client.post("/api/reports/verify-path", json={"filepath": str(test_pdf)})
    assert api_res.status_code == 200
    data = api_res.json()
    assert data["exists"] is True
    assert data["filepath"] == str(test_pdf.resolve())


# =============================================================================
# 5, 6, 7: SECURITY REJECTION OF ARBITRARY, TRAVERSAL & SIMILARLY NAMED PATHS
# =============================================================================

def test_reject_arbitrary_paths_outside_approved():
    """Reject system binaries, arbitrary external folders, and user directories."""
    arbitrary_paths = [
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\System32\calc.exe",
        r"C:\Users\Deepak\Downloads\report.pdf",
        r"C:\Users\Deepak\Desktop\malware.exe",
        r"C:\Program Files\Wireshark\tshark.exe"
    ]
    for p in arbitrary_paths:
        with pytest.raises(PermissionError):
            validate_safe_report_path(p)

        # Via API
        api_res = client.post("/api/reports/open-file", json={"filepath": p})
        assert api_res.status_code == 403


def test_reject_directory_traversal_attempts():
    """Reject directory traversal using ../ or ..\\ escaping approved roots."""
    reports_root = get_reports_root_dir()
    ip_root = get_ip_reports_root_dir()

    traversals = [
        str(reports_root / ".." / ".." / "Windows" / "calc.exe"),
        str(reports_root / ".." / "sensitive.txt"),
        str(ip_root / ".." / ".." / "secret.env"),
        str(ip_root / ".." / "Reports_fake" / "file.pdf"),
        "../../../../../../etc/passwd",
        r"..\..\..\..\..\Windows\cmd.exe"
    ]
    for t in traversals:
        with pytest.raises(PermissionError):
            validate_safe_report_path(t)

        api_res = client.post("/api/reports/show-in-folder", json={"filepath": t})
        assert api_res.status_code == 403


def test_reject_similarly_named_unauthorized_folders():
    """Ensure Reports_fake or IP Reports_evil are not treated as valid roots."""
    user_docs = Path.home() / "Documents" / "TraceX"
    spoofed = [
        str(user_docs / "Reports_evil" / "report.pdf"),
        str(user_docs / "IP Reports_spoofed" / "dossier.pdf"),
        str(user_docs / "Reports2" / "test.html")
    ]
    for s in spoofed:
        with pytest.raises(PermissionError):
            validate_safe_report_path(s)


# =============================================================================
# 8: HANDLING MISSING REPORT FILES
# =============================================================================

def test_handle_missing_report_file():
    """Verify FileNotFoundError (HTTP 404) when file is inside root but does not exist."""
    reports_root = get_reports_root_dir()
    non_existent = reports_root / TARGET_INV_ID / "Non_Existent_File_12345.pdf"

    with pytest.raises(FileNotFoundError):
        open_report_in_system(str(non_existent))

    with pytest.raises(FileNotFoundError):
        show_report_in_file_explorer(str(non_existent))

    with pytest.raises(FileNotFoundError):
        verify_report_path_exists(str(non_existent))

    api_res = client.post("/api/reports/open-file", json={"filepath": str(non_existent)})
    assert api_res.status_code == 404


# =============================================================================
# 9, 10, 11: NETWORK MODE HEADER/BANNER CONSISTENCY & PERSISTENCE
# =============================================================================

def test_local_only_mode_consistency():
    """Verify LOCAL_ONLY mode is returned consistently across all endpoints."""
    set_network_mode("LOCAL_ONLY")

    # 1. Authoritative core engine
    assert get_network_mode() == NetworkMode.LOCAL_ONLY
    status = get_current_network_mode()
    assert status["mode"] == "LOCAL_ONLY"
    assert status["local_only_mode"] is True

    # 2. API GET /api/network-mode
    res_mode = client.get("/api/network-mode")
    assert res_mode.status_code == 200
    assert res_mode.json()["mode"] == "LOCAL_ONLY"
    assert res_mode.json()["local_only_mode"] is True

    # 3. IP Details summary endpoint GET /api/investigations/{id}/ip-details
    res_ip = client.get(f"/api/investigations/{TARGET_INV_ID}/ip-details")
    assert res_ip.status_code == 200
    assert res_ip.json()["network_mode"] == "LOCAL_ONLY"


def test_hybrid_mode_consistency():
    """Verify HYBRID mode is returned consistently across all endpoints."""
    set_network_mode("HYBRID")

    # 1. Authoritative core engine
    assert get_network_mode() == NetworkMode.HYBRID
    status = get_current_network_mode()
    assert status["mode"] == "HYBRID"
    assert status["local_only_mode"] is False

    # 2. API GET /api/network-mode
    res_mode = client.get("/api/network-mode")
    assert res_mode.status_code == 200
    assert res_mode.json()["mode"] == "HYBRID"
    assert res_mode.json()["local_only_mode"] is False

    # 3. IP Details summary endpoint GET /api/investigations/{id}/ip-details
    res_ip = client.get(f"/api/investigations/{TARGET_INV_ID}/ip-details")
    assert res_ip.status_code == 200
    assert res_ip.json()["network_mode"] == "HYBRID"


def test_network_mode_persistence_after_restart():
    """Verify network mode is safely persisted to database settings table."""
    # Set mode to HYBRID
    set_network_mode("HYBRID")
    assert repo.get_setting("network_mode") == "HYBRID"

    # Simulate restart by reading directly from storage
    restored = get_network_mode()
    assert restored == NetworkMode.HYBRID

    # Restore default safe LOCAL_ONLY mode
    set_network_mode("LOCAL_ONLY")
    assert repo.get_setting("network_mode") == "LOCAL_ONLY"
    assert get_network_mode() == NetworkMode.LOCAL_ONLY


# =============================================================================
# 12: ACTUAL USER SCREENSHOT PATH VERIFICATION
# =============================================================================

def test_actual_user_ip_report_path_verification():
    """
    Test the exact file path from the user's error message:
    C:\\Users\\Deepak\\Documents\\TraceX\\IP Reports\\INV-20261117-4BC62D\\All_IPs_Intelligence_Dossier_INV-20261117-4BC62D.pdf
    """
    actual_path = r"C:\Users\Deepak\Documents\TraceX\IP Reports\INV-20261117-4BC62D\All_IPs_Intelligence_Dossier_INV-20261117-4BC62D.pdf"
    
    # 1. Path must be recognized as valid and safe
    validated = validate_safe_report_path(actual_path)
    assert "TraceX\\IP Reports" in str(validated) or "TraceX/IP Reports" in str(validated)

    # 2. Path verification endpoint
    api_verify = client.post("/api/reports/verify-path", json={"filepath": actual_path})
    assert api_verify.status_code in (200, 404)
    # If the file exists on the tester's machine, it returns 200 and matches
    if Path(actual_path).exists():
        assert api_verify.status_code == 200
        assert api_verify.json()["exists"] is True

        # Show in folder API must succeed (HTTP 200) without 403
        with patch("subprocess.Popen"):
            api_show = client.post("/api/reports/show-in-folder", json={"filepath": actual_path})
            assert api_show.status_code == 200

        # Open file API must succeed (HTTP 200) without 403
        with patch("os.startfile", create=True):
            api_open = client.post("/api/reports/open-file", json={"filepath": actual_path})
            assert api_open.status_code == 200
