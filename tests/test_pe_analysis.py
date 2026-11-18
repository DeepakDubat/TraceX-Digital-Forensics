import pytest
import pefile
from pathlib import Path
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.storage import workspace_mgr
from backend.app.core.models import InvestigationRecord
from backend.app.database.repository import repo
from backend.app.analyzers.pe_validator import validate_pe_file
from backend.app.analyzers.pe_metadata_analyzer import analyze_pe_metadata
from backend.app.analyzers.pe_section_analyzer import analyze_pe_sections
from backend.app.analyzers.pe_import_analyzer import analyze_pe_imports
from backend.app.analyzers.pe_string_analyzer import analyze_pe_strings, try_decode_string
from backend.app.analyzers.pe_secret_analyzer import analyze_pe_secrets
from backend.app.analyzers.pe_c2_analyzer import analyze_pe_c2_infrastructure
from backend.app.analyzers.pe_persistence_analyzer import analyze_pe_persistence
from backend.app.analyzers.pe_risk_engine import evaluate_pe_malware_risk
from backend.app.reporting.exe_txt_generator import generate_exe_forensic_report, export_pe_iocs_csv
from backend.app.core.orchestrator import run_investigation_pipeline

from tests.create_pe_fixtures import create_minimal_pe32, create_minimal_pe64

client = TestClient(app)

def test_validate_valid_pe32(tmp_path):
    pe_path = tmp_path / "valid_sample.exe"
    create_minimal_pe32(pe_path)
    is_valid, reason, details = validate_pe_file(pe_path)
    assert is_valid is True
    assert "Valid Windows" in reason
    assert details["is_pe32_plus"] is False
    assert details["sections_count"] == 2

def test_validate_valid_pe64(tmp_path):
    pe_path = tmp_path / "valid_x64.exe"
    create_minimal_pe64(pe_path)
    is_valid, reason, details = validate_pe_file(pe_path)
    assert is_valid is True
    assert details["is_pe32_plus"] is True
    assert "AMD64" in details["machine"]

def test_validate_corrupted_pe(tmp_path):
    corrupt_path = tmp_path / "corrupt.exe"
    corrupt_path.write_bytes(b"NOT_A_PE_HEADER_DATA_PADDING_MORE_BYTES_TO_EXCEED_64_BYTES_OF_DOS_HEADER")
    is_valid, reason, _ = validate_pe_file(corrupt_path)
    assert is_valid is False
    assert "Missing DOS header" in reason

    # Test file smaller than 64 bytes
    tiny_path = tmp_path / "tiny.exe"
    tiny_path.write_bytes(b"TINY")
    is_valid_tiny, reason_tiny, _ = validate_pe_file(tiny_path)
    assert is_valid_tiny is False
    assert "too small" in reason_tiny

def test_validate_invalid_lfanew(tmp_path):
    bad_lfanew = tmp_path / "bad_offset.exe"
    # Valid MZ header with e_lfanew pointing outside the file
    data = bytearray(64)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = b"\xFF\xFF\x00\x00"
    bad_lfanew.write_bytes(data)
    is_valid, reason, _ = validate_pe_file(bad_lfanew)
    assert is_valid is False
    assert "Invalid e_lfanew offset" in reason

def test_section_wx_and_packer_detection(tmp_path):
    wx_path = tmp_path / "packed_wx.exe"
    # Create sample with W+X section and UPX0 section name
    create_minimal_pe32(wx_path, make_wx_section=True, section_name_override="UPX0")
    
    pe = pefile.PE(str(wx_path))
    file_size = wx_path.stat().st_size
    sections, findings, summary = analyze_pe_sections(pe, file_size)
    pe.close()

    assert summary["writable_executable_sections"] >= 1
    assert any("UPX" in p for p in summary["packer_indicators"])
    finding_titles = [f.title for f in findings]
    assert any("Writable and Executable" in t for t in finding_titles)
    assert any("Packer" in t for t in finding_titles)

def test_pe_string_extraction_and_c2(tmp_path):
    test_exe = tmp_path / "sample_strings.exe"
    payload = (
        b"powershell.exe -ExecutionPolicy Bypass -enc AAAA\x00"
        b"http://malware-beacon.duckdns.org:9999/gate\x00"
        b"198.51.100.77\x00"
        b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        b"AIzaSyA1234567890GoogleTestApiKeyForensics\x00"
    )
    create_minimal_pe32(test_exe, custom_strings=payload)
    
    pe = pefile.PE(str(test_exe))
    classified = analyze_pe_strings(test_exe, pe)
    pe.close()

    assert len(classified["urls"]) >= 1
    assert any("duckdns.org" in u["url"] for u in classified["urls"])
    assert any("198.51.100.77" in ip["ip"] for ip in classified["ips"])
    assert len(classified["shell_commands"]) >= 1
    assert any("PowerShell" in cmd["type"] for cmd in classified["shell_commands"])

    # Test C2 Analysis
    c2_indicators = analyze_pe_c2_infrastructure(
        classified["urls"], classified["ips"], classified["domains"], classified["decoded_items"],
        imported_apis=["InternetOpenUrlA", "connect"]
    )
    c2_types = [c.classification for c in c2_indicators]
    assert "potential_c2" in c2_types

def test_pe_secrets_and_persistence(tmp_path):
    raw_strings = [
        {"value": "AIzaSyA1234567890GoogleTestApiKeyForensics", "offset": 0x400, "section": ".data"},
        {"value": "123456789:ABCdefGHIjklMNOpqrsTUVwxyz012345678", "offset": 0x450, "section": ".data"}, # Telegram bot
        {"value": "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "offset": 0x500, "section": ".data"},
        {"value": "vssadmin delete shadows /all /quiet", "offset": 0x550, "section": ".data"}
    ]
    
    secrets = analyze_pe_secrets(raw_strings)
    assert len(secrets) >= 2
    # Verify default redaction
    for s in secrets:
        assert "••••" in s.redacted_value

    persistence = analyze_pe_persistence(raw_strings, imported_apis=["RegSetValueExA"])
    mechanisms = [p.mechanism for p in persistence]
    assert any("Run Key" in m for m in mechanisms)
    assert any("Ransomware" in m or "Shadow" in m for m in mechanisms)

def test_api_pe_upload_and_e2e_pipeline(tmp_path):
    # Create test PE
    exe_file = tmp_path / "forensic_target.exe"
    create_minimal_pe32(exe_file)

    # 1. Test Upload API for Windows EXE
    with open(exe_file, "rb") as f:
        res = client.post(
            "/api/investigations/upload",
            files={"file": ("forensic_target.exe", f, "application/vnd.microsoft.portable-executable")},
            data={"case_reference": "CASE-EXE-TEST-001", "local_only_mode": "true", "file_type": "exe"}
        )

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["file_type"] == "exe"
    inv_id = data["investigation_id"]

    # 2. Execute PE pipeline synchronously
    run_investigation_pipeline(inv_id)

    # 3. Verify Investigation Details
    detail_res = client.get(f"/api/investigations/{inv_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["record"]["status"] == "completed"
    assert detail["record"]["file_type"] == "exe"
    assert detail["pe_metadata"] is not None
    assert len(detail["pe_metadata"]["sections"]) >= 1

    # 4. Verify 22-Section TXT Report Endpoint
    report_res = client.get(f"/api/investigations/{inv_id}/report/txt")
    assert report_res.status_code == 200
    report_text = report_res.text
    assert "WINDOWS EXECUTABLE FORENSIC & MALWARE THREAT INTELLIGENCE REPORT" in report_text
    assert "SECTION 5: PE METADATA & HEADERS" in report_text
    assert "SECTION 6: PE SECTION ANALYSIS" in report_text
    assert "SECTION 12: WINDOWS PERSISTENCE & EXECUTION INDICATORS" in report_text
    assert "SECTION 22: FINAL ASSESSMENT, LIMITATIONS & RECOMMENDED ACTIONS" in report_text
    assert "Content-Disposition" in report_res.headers
    assert "EXE_Forensic_Report_" in report_res.headers["Content-Disposition"]

    # 5. Verify CSV and JSON export endpoints
    csv_res = client.get(f"/api/investigations/{inv_id}/report/csv")
    assert csv_res.status_code == 200
    assert "Indicator_ID" in csv_res.text

    json_res = client.get(f"/api/investigations/{inv_id}/report/json")
    assert json_res.status_code == 200
    assert json_res.json()["record"]["id"] == inv_id
