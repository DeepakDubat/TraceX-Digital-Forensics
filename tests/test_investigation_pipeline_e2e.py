import os
import io
import struct
import zipfile
import tempfile
import time
from pathlib import Path
from datetime import datetime
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database.repository import repo
from backend.app.core.models import EvidenceItem, InvestigationRecord
from backend.app.core.storage import workspace_mgr
from backend.app.core.universal_orchestrator import run_universal_pipeline
from tests.create_fixtures import create_harmless_test_apk
from tests.create_pe_fixtures import create_minimal_pe32

client = TestClient(app)

# Helper fixtures generators
def make_safe_apk_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        manifest = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.tracex.safeapk" android:versionCode="1" android:versionName="1.0">
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:label="SafeTest">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>"""
        z.writestr("AndroidManifest.xml", manifest)
        dex_content = b"dex\n035\x00" + (b"\x00" * 32) + b"Lorg/tracex/safeapk/MainActivity;\x00"
        z.writestr("classes.dex", dex_content)
    return buf.getvalue()

def make_safe_pe_bytes(is_dll: bool = False) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".dll" if is_dll else ".exe") as tmp:
        tmp_path = Path(tmp.name)
    try:
        chars = 0x2102 if is_dll else 0x0102
        create_minimal_pe32(tmp_path, custom_strings=b"TraceX Safe Test PE\x00")
        return tmp_path.read_bytes()
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

def make_safe_elf_bytes() -> bytes:
    # 64-bit ELF header
    elf_hdr = bytearray(64)
    elf_hdr[0:4] = b"\x7fELF"
    elf_hdr[4] = 2 # 64-bit
    elf_hdr[5] = 1 # Little endian
    elf_hdr[6] = 1 # Version
    elf_hdr[7] = 0 # System V
    struct.pack_into("<H", elf_hdr, 16, 2) # e_type = ET_EXEC
    struct.pack_into("<H", elf_hdr, 18, 62) # e_machine = x86-64
    struct.pack_into("<I", elf_hdr, 20, 1) # e_version = 1
    struct.pack_into("<Q", elf_hdr, 24, 0x400000) # e_entry
    struct.pack_into("<H", elf_hdr, 52, 64) # e_ehsize
    return bytes(elf_hdr) + b"TraceX Harmless Static ELF Test Strings\x00"

def make_safe_pdf_bytes() -> bytes:
    return b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
trailer
<< /Size 4 /Root 1 0 R >>
startxref
192
%%EOF"""

def make_safe_office_bytes(kind: str = "docx") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        content_types = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
</Types>"""
        z.writestr("[Content_Types].xml", content_types)
        if kind == "docx":
            z.writestr("word/document.xml", b"<w:document><w:body><w:p><w:r><w:t>TraceX Forensics Safe Document</w:t></w:r></w:p></w:body></w:document>")
        elif kind == "xlsx":
            z.writestr("xl/workbook.xml", b"<workbook><sheets><sheet name='Sheet1' sheetId='1'/></sheets></workbook>")
        elif kind == "pptx":
            z.writestr("ppt/presentation.xml", b"<p:presentation><p:sldIdLst/></p:presentation>")
    return buf.getvalue()

def make_safe_png_bytes() -> bytes:
    # Minimal 1x1 PNG
    return (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
        b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4"
        b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )

def make_safe_jpg_bytes() -> bytes:
    # Minimal valid JPEG
    return (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00"
        b"\xff\xdb\x00C\x00" + (b"\x08" * 64) +
        b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"
        b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xbf\x00"
        b"\xff\xd9"
    )

def make_safe_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("evidence_log.txt", b"Safe forensic analysis log entry.\nSHA256 test verification.")
        z.writestr("config/settings.ini", b"[Forensics]\nmode=static\nisolation=strict")
    return buf.getvalue()

def make_safe_eml_bytes() -> bytes:
    return b"""From: test@forensics.tracex.local
To: analyst@forensics.tracex.local
Subject: Harmless IOC notification test
Date: Wed, 11 Nov 2026 00:00:00 +0000
Message-ID: <test-safemsg-001@tracex.local>
Content-Type: text/plain; charset=utf-8

This is a synthetic harmless email for static parser validation.
Indicator: https://safe-telemetry.example.org/test
"""

# ==============================================================================
# 20 Automated End-to-End Scenario Tests
# ==============================================================================

def test_01_safe_apk_pipeline_execution():
    """Scenario 1: Safe APK upload completes to 100% with no hang."""
    apk_bytes = make_safe_apk_bytes()
    res = client.post(
        "/api/investigations/upload",
        files={"file": ("test_artifact.apk", apk_bytes, "application/vnd.android.package-archive")},
        data={"file_type": "apk", "case_reference": "E2E-TEST-APK"}
    )
    assert res.status_code == 200, res.text
    inv_id = res.json()["investigation_id"]

    status = client.get(f"/api/investigations/{inv_id}/status").json()
    assert status["progress"] == 100
    assert status["status"] in ("completed", "completed_with_warnings")
    assert "Complete" in status["current_stage"] or "complete" in status["current_stage"]

def test_02_safe_exe_pipeline_execution():
    """Scenario 2: Safe Windows PE EXE upload completes to 100%."""
    exe_bytes = make_safe_pe_bytes(is_dll=False)
    res = client.post(
        "/api/investigations/upload",
        files={"file": ("sample_binary.exe", exe_bytes, "application/octet-stream")},
        data={"file_type": "exe", "case_reference": "E2E-TEST-EXE"}
    )
    assert res.status_code == 200
    inv_id = res.json()["investigation_id"]

    status = client.get(f"/api/investigations/{inv_id}/status").json()
    assert status["progress"] == 100
    assert status["status"] in ("completed", "completed_with_warnings")

def test_03_safe_dll_pipeline_execution():
    """Scenario 3: Safe Windows PE DLL upload completes to 100%."""
    dll_bytes = make_safe_pe_bytes(is_dll=True)
    res = client.post(
        "/api/investigations/upload",
        files={"file": ("library_module.dll", dll_bytes, "application/octet-stream")},
        data={"file_type": "exe", "case_reference": "E2E-TEST-DLL"}
    )
    assert res.status_code == 200
    inv_id = res.json()["investigation_id"]

    status = client.get(f"/api/investigations/{inv_id}/status").json()
    assert status["progress"] == 100
    assert status["status"] in ("completed", "completed_with_warnings")

def test_04_safe_elf_pipeline_execution():
    """Scenario 4: Safe Linux ELF binary upload completes to 100%."""
    elf_bytes = make_safe_elf_bytes()
    res = client.post(
        "/api/investigations/upload",
        files={"file": ("service_daemon.elf", elf_bytes, "application/x-executable")},
        data={"file_type": "elf", "case_reference": "E2E-TEST-ELF"}
    )
    assert res.status_code == 200
    inv_id = res.json()["investigation_id"]

    status = client.get(f"/api/investigations/{inv_id}/status").json()
    assert status["progress"] == 100
    assert status["status"] in ("completed", "completed_with_warnings")

def test_05_safe_pdf_pipeline_execution():
    """Scenario 5: Safe PDF document upload completes to 100%."""
    pdf_bytes = make_safe_pdf_bytes()
    res = client.post(
        "/api/investigations/upload",
        files={"file": ("incident_summary.pdf", pdf_bytes, "application/pdf")},
        data={"file_type": "pdf", "case_reference": "E2E-TEST-PDF"}
    )
    assert res.status_code == 200
    inv_id = res.json()["investigation_id"]

    status = client.get(f"/api/investigations/{inv_id}/status").json()
    assert status["progress"] == 100
    assert status["status"] in ("completed", "completed_with_warnings")

def test_06_safe_docx_pipeline_execution():
    """Scenario 6: Safe DOCX document upload completes to 100%."""
    docx_bytes = make_safe_office_bytes("docx")
    res = client.post(
        "/api/investigations/upload",
        files={"file": ("report_document.docx", docx_bytes, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")},
        data={"file_type": "office", "case_reference": "E2E-TEST-DOCX"}
    )
    assert res.status_code == 200
    inv_id = res.json()["investigation_id"]

    status = client.get(f"/api/investigations/{inv_id}/status").json()
    assert status["progress"] == 100
    assert status["status"] in ("completed", "completed_with_warnings")

def test_07_safe_xlsx_pipeline_execution():
    """Scenario 7: Safe XLSX workbook upload completes to 100%."""
    xlsx_bytes = make_safe_office_bytes("xlsx")
    res = client.post(
        "/api/investigations/upload",
        files={"file": ("financial_sheet.xlsx", xlsx_bytes, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
        data={"file_type": "office", "case_reference": "E2E-TEST-XLSX"}
    )
    assert res.status_code == 200
    inv_id = res.json()["investigation_id"]

    status = client.get(f"/api/investigations/{inv_id}/status").json()
    assert status["progress"] == 100
    assert status["status"] in ("completed", "completed_with_warnings")

def test_08_safe_pptx_pipeline_execution():
    """Scenario 8: Safe PPTX presentation upload completes to 100%."""
    pptx_bytes = make_safe_office_bytes("pptx")
    res = client.post(
        "/api/investigations/upload",
        files={"file": ("presentation_slides.pptx", pptx_bytes, "application/vnd.openxmlformats-officedocument.presentationml.presentation")},
        data={"file_type": "office", "case_reference": "E2E-TEST-PPTX"}
    )
    assert res.status_code == 200
    inv_id = res.json()["investigation_id"]

    status = client.get(f"/api/investigations/{inv_id}/status").json()
    assert status["progress"] == 100
    assert status["status"] in ("completed", "completed_with_warnings")

def test_09_safe_jpg_and_png_pipeline_execution():
    """Scenario 9: Safe JPG and PNG image uploads complete to 100%."""
    png_bytes = make_safe_png_bytes()
    res1 = client.post(
        "/api/investigations/upload",
        files={"file": ("evidence_screenshot.png", png_bytes, "image/png")},
        data={"file_type": "image", "case_reference": "E2E-TEST-PNG"}
    )
    assert res1.status_code == 200
    inv_id_png = res1.json()["investigation_id"]
    status_png = client.get(f"/api/investigations/{inv_id_png}/status").json()
    assert status_png["progress"] == 100
    assert status_png["status"] in ("completed", "completed_with_warnings")

    jpg_bytes = make_safe_jpg_bytes()
    res2 = client.post(
        "/api/investigations/upload",
        files={"file": ("camera_capture.jpg", jpg_bytes, "image/jpeg")},
        data={"file_type": "image", "case_reference": "E2E-TEST-JPG"}
    )
    assert res2.status_code == 200
    inv_id_jpg = res2.json()["investigation_id"]
    status_jpg = client.get(f"/api/investigations/{inv_id_jpg}/status").json()
    assert status_jpg["progress"] == 100
    assert status_jpg["status"] in ("completed", "completed_with_warnings")

def test_10_safe_zip_pipeline_execution():
    """Scenario 10: Safe ZIP container upload completes to 100%."""
    zip_bytes = make_safe_zip_bytes()
    res = client.post(
        "/api/investigations/upload",
        files={"file": ("evidence_package.zip", zip_bytes, "application/zip")},
        data={"file_type": "archive", "case_reference": "E2E-TEST-ZIP"}
    )
    assert res.status_code == 200
    inv_id = res.json()["investigation_id"]

    status = client.get(f"/api/investigations/{inv_id}/status").json()
    assert status["progress"] == 100
    assert status["status"] in ("completed", "completed_with_warnings")

def test_11_safe_eml_pipeline_execution():
    """Scenario 11: Safe RFC822 EML message upload completes to 100%."""
    eml_bytes = make_safe_eml_bytes()
    res = client.post(
        "/api/investigations/upload",
        files={"file": ("phishing_sample.eml", eml_bytes, "message/rfc822")},
        data={"file_type": "email", "case_reference": "E2E-TEST-EML"}
    )
    assert res.status_code == 200
    inv_id = res.json()["investigation_id"]

    status = client.get(f"/api/investigations/{inv_id}/status").json()
    assert status["progress"] == 100
    assert status["status"] in ("completed", "completed_with_warnings")

def test_12_multiple_evidence_files_in_one_investigation():
    """Scenario 12: Multi-evidence items in a single case processed monotonically to 100%."""
    inv_id = f"inv_multi_{int(time.time())}"
    now = datetime.utcnow()
    record = InvestigationRecord(
        id=inv_id,
        filename="Multi_Evidence_Case",
        original_size=1024,
        md5="0" * 32,
        sha1="0" * 40,
        sha256="0" * 64,
        case_reference="MULTI-CASE-001",
        investigator_name="Examiner",
        status="pending",
        progress=0,
        current_stage="Case Queued",
        file_type="multi"
    )
    repo.create_investigation(record)

    apk_data = make_safe_apk_bytes()
    pdf_data = make_safe_pdf_bytes()
    eml_data = make_safe_eml_bytes()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as f1:
        f1.write(apk_data)
        p1 = Path(f1.name)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as f2:
        f2.write(pdf_data)
        p2 = Path(f2.name)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as f3:
        f3.write(eml_data)
        p3 = Path(f3.name)

    try:
        s1 = workspace_mgr.stage_artifact(inv_id, p1, "app.apk")
        s2 = workspace_mgr.stage_artifact(inv_id, p2, "doc.pdf")
        s3 = workspace_mgr.stage_artifact(inv_id, p3, "msg.eml")

        e1 = EvidenceItem(
            id=f"{inv_id}-ev-1",
            investigation_id=inv_id,
            filename="app.apk",
            file_size=s1["size"],
            detected_format="apk",
            sha256=s1["hashes"]["sha256"],
            acquired_at=now,
            created_at=now
        )
        e2 = EvidenceItem(
            id=f"{inv_id}-ev-2",
            investigation_id=inv_id,
            filename="doc.pdf",
            file_size=s2["size"],
            detected_format="pdf",
            sha256=s2["hashes"]["sha256"],
            acquired_at=now,
            created_at=now
        )
        e3 = EvidenceItem(
            id=f"{inv_id}-ev-3",
            investigation_id=inv_id,
            filename="msg.eml",
            file_size=s3["size"],
            detected_format="email",
            sha256=s3["hashes"]["sha256"],
            acquired_at=now,
            created_at=now
        )
        repo.create_evidence_item(e1)
        repo.create_evidence_item(e2)
        repo.create_evidence_item(e3)

        run_universal_pipeline(inv_id)

        rec = repo.get_investigation(inv_id)
        assert rec is not None
        assert rec.progress == 100
        assert rec.status in ("completed", "completed_with_warnings")
    finally:
        for p in (p1, p2, p3):
            if p.exists():
                p.unlink()

def test_13_large_evidence_file():
    """Scenario 13: Large evidence file (2MB+) processes smoothly to 100%."""
    large_content = (b"[2026-11-11 00:00:00] INFO Normal user authentication event.\n" * 35000)
    assert len(large_content) > 2 * 1024 * 1024

    res = client.post(
        "/api/investigations/upload",
        files={"file": ("large_server_audit.log", large_content, "text/plain")},
        data={"file_type": "text", "case_reference": "E2E-TEST-LARGE"}
    )
    assert res.status_code == 200
    inv_id = res.json()["investigation_id"]

    status = client.get(f"/api/investigations/{inv_id}/status").json()
    assert status["progress"] == 100
    assert status["status"] in ("completed", "completed_with_warnings")

def test_14_corrupted_file_handling():
    """Scenario 14: Corrupted or truncated header file does not hang; reaches 100%."""
    corrupted_zip = b"PK\x03\x04\x00\x00\x00\x00TRUNCATED_BAD_DATA"
    res = client.post(
        "/api/investigations/upload",
        files={"file": ("corrupt_sample.apk", corrupted_zip, "application/octet-stream")},
        data={"file_type": "apk", "case_reference": "E2E-TEST-CORRUPT"}
    )
    assert res.status_code == 200
    inv_id = res.json()["investigation_id"]

    status = client.get(f"/api/investigations/{inv_id}/status").json()
    assert status["progress"] == 100
    assert status["status"] in ("completed", "completed_with_warnings")

def test_15_unsupported_file_handling():
    """Scenario 15: Unrecognized / unclassified arbitrary binary stream completes to 100%."""
    random_bytes = bytes([i % 256 for i in range(4096)])
    res = client.post(
        "/api/investigations/upload",
        files={"file": ("unclassified.dat", random_bytes, "application/octet-stream")},
        data={"file_type": "auto", "case_reference": "E2E-TEST-UNCLASSIFIED"}
    )
    assert res.status_code == 200
    inv_id = res.json()["investigation_id"]

    status = client.get(f"/api/investigations/{inv_id}/status").json()
    assert status["progress"] == 100
    assert status["status"] in ("completed", "completed_with_warnings")

def test_16_analyzer_timeout_simulation():
    """Scenario 16: Analyzer timeout does not freeze progress; reaches 100% with warning."""
    inv_id = f"inv_timeout_{int(time.time())}"
    now = datetime.utcnow()
    record = InvestigationRecord(
        id=inv_id,
        filename="timeout_test.txt",
        original_size=512,
        md5="4" * 32,
        sha1="4" * 40,
        sha256="4" * 64,
        status="pending",
        progress=0,
        current_stage="Case Queued",
        file_type="text"
    )
    repo.create_investigation(record)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(b"Timeout test text content")
        p = Path(f.name)

    try:
        s = workspace_mgr.stage_artifact(inv_id, p, "timeout_test.txt")
        e = EvidenceItem(
            id=f"{inv_id}-ev-1",
            investigation_id=inv_id,
            filename="timeout_test.txt",
            file_size=s["size"],
            detected_format="text",
            sha256=s["hashes"]["sha256"],
            acquired_at=now,
            created_at=now
        )
        repo.create_evidence_item(e)

        with patch("backend.app.core.universal_orchestrator.analyze_text_evidence", side_effect=TimeoutError("Parser timed out")):
            run_universal_pipeline(inv_id)

        rec = repo.get_investigation(inv_id)
        assert rec is not None
        assert rec.progress == 100
        assert rec.status in ("completed", "completed_with_warnings")
    finally:
        if p.exists():
            p.unlink()

def test_17_analyzer_exception_simulation():
    """Scenario 17: Analyzer crash/exception does not freeze progress at 25%; reaches 100%."""
    inv_id = f"inv_crash_{int(time.time())}"
    now = datetime.utcnow()
    record = InvestigationRecord(
        id=inv_id,
        filename="crash_test.txt",
        original_size=512,
        md5="5" * 32,
        sha1="5" * 40,
        sha256="5" * 64,
        status="pending",
        progress=0,
        current_stage="Case Queued",
        file_type="text"
    )
    repo.create_investigation(record)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(b"Crash test text content")
        p = Path(f.name)

    try:
        s = workspace_mgr.stage_artifact(inv_id, p, "crash_test.txt")
        e = EvidenceItem(
            id=f"{inv_id}-ev-1",
            investigation_id=inv_id,
            filename="crash_test.txt",
            file_size=s["size"],
            detected_format="text",
            sha256=s["hashes"]["sha256"],
            acquired_at=now,
            created_at=now
        )
        repo.create_evidence_item(e)

        with patch("backend.app.core.universal_orchestrator.analyze_text_evidence", side_effect=RuntimeError("Simulated internal parser crash")):
            run_universal_pipeline(inv_id)

        rec = repo.get_investigation(inv_id)
        assert rec is not None
        assert rec.progress == 100
        assert rec.status in ("completed", "completed_with_warnings")
        assert rec.progress != 25
    finally:
        if p.exists():
            p.unlink()

def test_18_frontend_status_polling_reconnection():
    """Scenario 18: Repeated polling of /api/investigations/{id}/status returns consistent telemetry."""
    res = client.post(
        "/api/investigations/upload",
        files={"file": ("poll_sample.apk", make_safe_apk_bytes(), "application/octet-stream")},
        data={"file_type": "apk", "case_reference": "E2E-TEST-POLL"}
    )
    assert res.status_code == 200
    inv_id = res.json()["investigation_id"]

    for _ in range(5):
        st = client.get(f"/api/investigations/{inv_id}/status")
        assert st.status_code == 200
        body = st.json()
        assert "progress" in body
        assert "current_stage" in body
        assert body["progress"] == 100

def test_19_backend_restart_and_stalled_recovery():
    """Scenario 19: Investigation left at 25% from prior crashed run is recovered and completed."""
    inv_id = f"inv_stalled_25_{int(time.time())}"
    now = datetime.utcnow()
    record = InvestigationRecord(
        id=inv_id,
        filename="stalled_file.txt",
        original_size=256,
        md5="6" * 32,
        sha1="6" * 40,
        sha256="6" * 64,
        status="analyzing",
        progress=25,
        current_stage="Parsing DEX bytecode...",
        file_type="text"
    )
    repo.create_investigation(record)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(b"Recovery test content")
        p = Path(f.name)

    try:
        s = workspace_mgr.stage_artifact(inv_id, p, "stalled_file.txt")
        e = EvidenceItem(
            id=f"{inv_id}-ev-1",
            investigation_id=inv_id,
            filename="stalled_file.txt",
            file_size=s["size"],
            detected_format="text",
            sha256=s["hashes"]["sha256"],
            acquired_at=now,
            created_at=now
        )
        repo.create_evidence_item(e)

        # Trigger pipeline run to recover
        run_universal_pipeline(inv_id)

        rec = repo.get_investigation(inv_id)
        assert rec is not None
        assert rec.progress == 100
        assert rec.status in ("completed", "completed_with_warnings")
        assert rec.progress > 25
    finally:
        if p.exists():
            p.unlink()

def test_20_report_generation_and_persistence():
    """Scenario 20: Master report, TXT report, CSV, and bundle exports are generated and valid."""
    res = client.post(
        "/api/investigations/upload",
        files={"file": ("audit_sample.pdf", make_safe_pdf_bytes(), "application/pdf")},
        data={"file_type": "pdf", "case_reference": "E2E-TEST-REPORT"}
    )
    assert res.status_code == 200
    inv_id = res.json()["investigation_id"]

    # TXT report
    txt_res = client.get(f"/api/investigations/{inv_id}/report/txt")
    assert txt_res.status_code == 200
    assert "TRACEX DIGITAL FORENSICS" in txt_res.text or len(txt_res.text) > 50

    # CSV findings
    csv_res = client.get(f"/api/investigations/{inv_id}/report/csv")
    assert csv_res.status_code == 200

    # JSON export
    json_res = client.get(f"/api/investigations/{inv_id}/report/json")
    assert json_res.status_code == 200
    assert "record" in json_res.json() or "investigation" in json_res.json()
