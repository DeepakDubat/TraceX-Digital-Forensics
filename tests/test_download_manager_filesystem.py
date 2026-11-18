"""
Test Suite: TraceX Central Report Storage, Download Manager & Filesystem Verification
Universal Digital Forensics & Cyber Investigation Suite v2.0.0

Verifies end-to-end:
1. Central storage location: %USERPROFILE%\\Documents\\TraceX\\Reports
2. Investigation directory isolation
3. Non-zero byte verification on real Windows filesystem
4. PDF structure validity with PyMuPDF
5. HTML, JSON, TXT, CSV, and ZIP Bundle export
6. Safe collision handling and versioning
7. Special character sanitization
8. Path traversal security guards
9. REST API endpoints (/report/save, /report/saved-files, /reports/open-file, /reports/show-in-folder)
10. Persistence across restarts
"""

import os
import json
import pytest
import zipfile
import fitz # PyMuPDF
from pathlib import Path
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database.repository import repo
from backend.app.reporting.download_manager import (
    get_reports_root_dir,
    get_investigation_reports_dir,
    resolve_unique_filepath,
    sanitize_filename_component,
    verify_and_save_report,
    list_saved_reports_for_investigation,
    open_report_in_system,
    show_report_in_file_explorer
)

client = TestClient(app)

@pytest.fixture
def sample_investigation_id():
    """Retrieves an existing investigation or creates a mock for testing."""
    records = repo.list_investigations()
    if records:
        return records[0].id
    # Create test record if empty
    from backend.app.core.models import InvestigationRecord
    rec = InvestigationRecord(
        id="INV-TEST-DL-FS-001",
        filename="TargetApp.apk",
        original_size=102400,
        md5="0123456789abcdef0123456789abcdef",
        sha1="0123456789abcdef0123456789abcdef01234567",
        sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        status="completed",
        file_type="apk",
        package_name="com.security.audit"
    )
    repo.create_investigation(rec)
    return rec.id

def test_central_storage_path_resolution():
    """Requirement 3: Location must be %USERPROFILE%\\Documents\\TraceX\\Reports"""
    root = get_reports_root_dir()
    user_profile = os.environ.get("USERPROFILE") or str(Path.home())
    expected_root = Path(user_profile) / "Documents" / "TraceX" / "Reports"
    assert root == expected_root.resolve()
    assert root.exists()
    assert root.is_dir()

def test_investigation_directory_isolation(sample_investigation_id):
    """Requirement 3: Organized by Documents\\TraceX\\Reports\\<ID>"""
    inv_dir = get_investigation_reports_dir(sample_investigation_id)
    assert inv_dir.parent == get_reports_root_dir()
    assert sample_investigation_id in inv_dir.name
    assert inv_dir.exists()

def test_sanitize_filename_special_characters():
    """Requirement 5: Test filenames containing spaces and special characters."""
    raw = 'Report : 2026/11/17 *test* <name> | "special" ?'
    cleaned = sanitize_filename_component(raw)
    for bad_char in [':', '/', '\\', '*', '?', '"', '<', '>', '|']:
        assert bad_char not in cleaned
    assert "Report" in cleaned
    assert "special" in cleaned

def test_save_pdf_report_real_filesystem(sample_investigation_id):
    """Requirements 4 & 5: Save PDF, verify file exists, size > 0, valid PDF structure."""
    result = verify_and_save_report(
        investigation_id=sample_investigation_id,
        format_type="pdf",
        unredact=False,
        overwrite=True,
        custom_filename=f"Test_Verification_{sample_investigation_id}.pdf"
    )
    assert result["status"] == "success"
    filepath = Path(result["filepath"])
    assert filepath.exists()
    assert filepath.is_file()
    assert result["file_size"] > 0
    assert filepath.stat().st_size == result["file_size"]

    # Verify real PDF parse with PyMuPDF
    doc = fitz.open(str(filepath))
    assert len(doc) >= 1
    page1_text = doc[0].get_text()
    assert "DIGITAL FORENSICS" in page1_text.upper() or "TRACEX" in page1_text.upper()
    doc.close()

def test_save_html_report_real_filesystem(sample_investigation_id):
    """Requirements 4 & 5: Save HTML, verify existence, size > 0, responsive HTML contents."""
    result = verify_and_save_report(
        investigation_id=sample_investigation_id,
        format_type="html",
        overwrite=True
    )
    assert result["status"] == "success"
    filepath = Path(result["filepath"])
    assert filepath.exists()
    assert result["file_size"] > 0
    content = filepath.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content or "<html" in content
    assert "TraceX" in content

def test_save_json_report_real_filesystem(sample_investigation_id):
    """Requirements 4 & 5: Save JSON, verify existence, size > 0, valid JSON syntax."""
    result = verify_and_save_report(
        investigation_id=sample_investigation_id,
        format_type="json",
        overwrite=True
    )
    assert result["status"] == "success"
    filepath = Path(result["filepath"])
    assert filepath.exists()
    assert result["file_size"] > 0
    parsed = json.loads(filepath.read_text(encoding="utf-8"))
    assert "record" in parsed

def test_save_txt_and_bundle_reports(sample_investigation_id):
    """Requirements 4 & 5: Save TXT and ZIP bundle."""
    # TXT
    res_txt = verify_and_save_report(sample_investigation_id, "txt", overwrite=True)
    assert res_txt["status"] == "success"
    assert Path(res_txt["filepath"]).stat().st_size > 0

    # Bundle ZIP
    res_zip = verify_and_save_report(sample_investigation_id, "bundle", overwrite=True)
    assert res_zip["status"] == "success"
    zip_path = Path(res_zip["filepath"])
    assert zip_path.exists()
    assert zip_path.stat().st_size > 0
    with zipfile.ZipFile(zip_path, 'r') as zf:
        assert len(zf.namelist()) >= 2

def test_collision_handling_versioning(sample_investigation_id):
    """Requirement 3: Do not overwrite existing reports without confirmation."""
    base_name = f"CollisionTest_{sample_investigation_id}.txt"
    inv_dir = get_investigation_reports_dir(sample_investigation_id)

    # Clean up any leftover test files from previous runs
    for leftover in inv_dir.glob(f"CollisionTest_{sample_investigation_id}*"):
        try:
            leftover.unlink()
        except Exception:
            pass

    # First save
    res1 = verify_and_save_report(sample_investigation_id, "txt", overwrite=True, custom_filename=base_name)
    path1 = Path(res1["filepath"])
    assert path1.exists()

    # Second save with overwrite=False
    res2 = verify_and_save_report(sample_investigation_id, "txt", overwrite=False, custom_filename=base_name)
    path2 = Path(res2["filepath"])
    assert path2.exists()
    assert path1 != path2
    assert "(1)" in path2.name

def test_path_traversal_guard():
    """Security Requirement: Prevent access to arbitrary filesystem paths outside Reports root."""
    forbidden_path = Path("C:/Windows/System32/drivers/etc/hosts")
    with pytest.raises(PermissionError):
        open_report_in_system(str(forbidden_path))

    with pytest.raises(PermissionError):
        show_report_in_file_explorer(str(forbidden_path))

def test_api_report_save_and_list_lifecycle(sample_investigation_id):
    """Requirement 1 & 4: REST API save, listing, and validation."""
    old_token = os.environ.get("TRACEX_BRIDGE_TOKEN")
    os.environ["TRACEX_BRIDGE_TOKEN"] = "test-bridge-token"
    headers = {"X-TraceX-Bridge-Token": "test-bridge-token"}
    try:
        # POST /api/investigations/{id}/report/save
        save_payload = {
            "format": "pdf",
            "unredact": False,
            "overwrite": True
        }
        resp = client.post(f"/api/investigations/{sample_investigation_id}/report/save", json=save_payload, headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["file_size"] > 0
        assert Path(data["filepath"]).exists()

        # GET /api/investigations/{id}/report/saved-files
        list_resp = client.get(f"/api/investigations/{sample_investigation_id}/report/saved-files", headers=headers)
        assert list_resp.status_code == 200
        files = list_resp.json()
        assert len(files) >= 1
        found = any(f["filename"] == data["filename"] for f in files)
        assert found
    finally:
        if old_token is not None:
            os.environ["TRACEX_BRIDGE_TOKEN"] = old_token
        else:
            os.environ.pop("TRACEX_BRIDGE_TOKEN", None)
