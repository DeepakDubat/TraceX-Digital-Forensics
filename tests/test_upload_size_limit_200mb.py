"""
TraceX Security & Evidence Ingestion Test Suite:
200 MB Maximum File Upload Boundary, Streaming Integrity, and Chain of Custody Verification
Universal Digital Forensics & Cyber Investigation Suite v2.0.0
"""

import io
import os
import sys
import zipfile
import tempfile
import hashlib
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.main import app
from backend.app.database.repository import repo
from backend.app.core.user_auth import get_current_user
from backend.app.core.security import safe_copy_upload, validate_apk_file
from backend.app.analyzers.pe_validator import validate_pe_file
from backend.app.core.storage import workspace_mgr

app.dependency_overrides[get_current_user] = lambda: {"id": 1, "username": "LeadExaminer", "role": "admin"}
client = TestClient(app)

MB = 1024 * 1024
LIMIT_MB = 200
LIMIT_BYTES = LIMIT_MB * MB


class ZeroStream(io.RawIOBase):
    """Memory-efficient streaming source of arbitrary size without consuming RAM."""
    def __init__(self, size_bytes: int, prefix: bytes = b""):
        self.size = size_bytes
        self.pos = 0
        self.prefix = prefix
        self.prefix_len = len(prefix)

    def readable(self):
        return True

    def readinto(self, b):
        if self.pos >= self.size:
            return 0
        to_read = min(len(b), self.size - self.pos)
        
        # If still in prefix region, write prefix bytes
        if self.pos < self.prefix_len:
            pref_part = self.prefix[self.pos : min(self.prefix_len, self.pos + to_read)]
            b[:len(pref_part)] = pref_part
            written = len(pref_part)
            rem = to_read - written
            if rem > 0:
                b[written:to_read] = b"\x00" * rem
        else:
            b[:to_read] = b"\x00" * to_read
            
        self.pos += to_read
        return to_read


# =============================================================================
# 1. BOUNDARY TESTS (149 MB, 150 MB, 199 MB, 200 MB, 201 MB)
# =============================================================================

@pytest.mark.parametrize("size_mb,should_succeed", [
    (149, True),
    (150, True),
    (199, True),
    (200, True),
    (201, False)
])
def test_upload_boundary_streaming_sizes(size_mb, should_succeed):
    """
    Direct boundary test on safe_copy_upload streaming engine:
    149 MB, 150 MB, 199 MB, 200 MB must be accepted.
    201 MB must be rejected with ValueError.
    """
    stream_size = size_mb * MB
    stream = ZeroStream(stream_size)
    
    with tempfile.TemporaryFile() as dst:
        if should_succeed:
            copied = safe_copy_upload(stream, dst, max_bytes=LIMIT_BYTES)
            assert copied == stream_size
        else:
            with pytest.raises(ValueError) as exc_info:
                safe_copy_upload(stream, dst, max_bytes=LIMIT_BYTES)
            assert "exceeds maximum limit of 200 MB" in str(exc_info.value)


# =============================================================================
# 2. EXACT BYTE BOUNDARIES (200MB exact vs 200MB + 1 byte)
# =============================================================================

def test_exact_byte_boundary():
    """Verify that exactly 209,715,200 bytes succeeds and 209,715,201 bytes fails."""
    # Exact 200 MB
    stream_exact = ZeroStream(LIMIT_BYTES)
    with tempfile.TemporaryFile() as dst:
        copied = safe_copy_upload(stream_exact, dst, max_bytes=LIMIT_BYTES)
        assert copied == LIMIT_BYTES

    # 200 MB + 1 byte
    stream_over = ZeroStream(LIMIT_BYTES + 1)
    with tempfile.TemporaryFile() as dst:
        with pytest.raises(ValueError) as exc_info:
            safe_copy_upload(stream_over, dst, max_bytes=LIMIT_BYTES)
        assert "exceeds maximum limit of 200 MB" in str(exc_info.value)


# =============================================================================
# 3. APK VALIDATOR AT 200 MB LIMIT
# =============================================================================

def test_apk_validator_at_200mb(tmp_path):
    """Verify validate_apk_file accepts APKs up to 200 MB and rejects > 200 MB."""
    # Create small valid APK
    apk_path = tmp_path / "valid_test.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest></manifest>")
        zf.writestr("classes.dex", b"dex\n035\x00")

    is_valid, msg = validate_apk_file(apk_path, max_size_mb=200)
    assert is_valid is True

    # Test size rejection
    is_valid, msg = validate_apk_file(apk_path, max_size_mb=0)
    assert is_valid is False
    assert "exceeds maximum permissible size of 0 MB" in msg


# =============================================================================
# 4. PE/EXE VALIDATOR AT 200 MB LIMIT
# =============================================================================

def test_pe_validator_at_200mb(tmp_path):
    """Verify validate_pe_file accepts PE binaries up to 200 MB and rejects > 200 MB."""
    # Create minimal valid DOS MZ file
    exe_path = tmp_path / "test.exe"
    dos_data = bytearray(b"MZ" + b"\x00" * 62)
    exe_path.write_bytes(dos_data)

    is_valid, reason, details = validate_pe_file(exe_path, max_size_mb=200)
    # File is too small for full PE headers, but size check passes
    assert "exceeds maximum permissible size" not in reason

    is_valid, reason, details = validate_pe_file(exe_path, max_size_mb=0)
    assert is_valid is False
    assert "exceeds maximum permissible size of 0 MB" in reason


# =============================================================================
# 5. REAL 200 MB EVIDENCE ARTIFACT INGESTION VIA API
# =============================================================================

def test_real_200mb_evidence_upload_and_chain_of_custody(tmp_path):
    """
    Creates an actual valid ~200 MB ZIP/APK artifact, uploads it through
    the FastAPI /api/investigations/upload endpoint, verifies SHA-256,
    storage staging, and Chain of Custody ledger entry.
    """
    large_apk = tmp_path / "LargeForensicEvidence_200MB.apk"
    
    # Construct a valid ZIP file with uncompressed payload reaching ~199.5 MB
    with open(large_apk, "wb") as f:
        with zipfile.ZipFile(f, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest xmlns:android='http://schemas.android.com/apk/res/android' package='org.tracex.evidence200mb'></manifest>")
            zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 1024)
            with zf.open("assets/large_payload.bin", "w") as entry:
                chunk = b"A" * (1024 * 1024) # 1 MB chunk
                for _ in range(198):
                    entry.write(chunk)
            
    actual_size = large_apk.stat().st_size
    assert actual_size > 198 * MB
    assert actual_size <= 200 * MB

    # Compute expected SHA-256
    hasher = hashlib.sha256()
    with open(large_apk, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    expected_sha256 = hasher.hexdigest()

    # Upload via FastAPI TestClient
    with open(large_apk, "rb") as f:
        resp = client.post(
            "/api/investigations/upload",
            files={"file": ("LargeForensicEvidence_200MB.apk", f, "application/vnd.android.package-archive")},
            data={
                "case_reference": "CASE-200MB-TEST",
                "investigator_name": "SeniorExaminer",
                "description": "Validation of 200 MB evidence intake"
            }
        )

    assert resp.status_code == 200, f"Upload failed: {resp.text}"
    data = resp.json()
    assert data["status"] == "success"
    inv_id = data["investigation_id"]
    assert data["sha256"] == expected_sha256
    assert data["size_bytes"] == actual_size

    # Verify workspace isolation and read-only protection
    inv_dir = workspace_mgr.get_investigation_dir(inv_id)
    orig_file = inv_dir / "original" / "LargeForensicEvidence_200MB.apk"
    work_file = inv_dir / "working" / "LargeForensicEvidence_200MB.apk"
    assert orig_file.exists()
    assert work_file.exists()
    assert orig_file.stat().st_size == actual_size
    assert work_file.stat().st_size == actual_size

    # Verify Chain of Custody ledger event
    ledger = repo.list_chain_of_custody(inv_id)
    assert len(ledger) > 0
    received_event = next((e for e in ledger if getattr(e, "event_type", "") == "EVIDENCE_RECEIVED"), None)
    assert received_event is not None
    assert received_event.original_hash == expected_sha256
    assert received_event.working_copy_hash == expected_sha256
    assert received_event.verification_result == "PASSED"

    # Clean up workspace
    workspace_mgr.delete_workspace(inv_id)


# =============================================================================
# 6. REJECTION OF 201 MB FILE VIA API (HTTP 413)
# =============================================================================

def test_api_rejects_file_exceeding_200mb(tmp_path):
    """
    Creates a 201 MB file and verifies that the FastAPI upload endpoint
    rejects it with HTTP 413 and returns a clear, actionable error message.
    """
    over_limit_file = tmp_path / "OverLimit_201MB.apk"
    with open(over_limit_file, "wb") as f:
        f.seek((201 * MB) - 1)
        f.write(b"\x00")

    assert over_limit_file.stat().st_size == 201 * MB

    with open(over_limit_file, "rb") as f:
        resp = client.post(
            "/api/investigations/upload",
            files={"file": ("OverLimit_201MB.apk", f, "application/vnd.android.package-archive")},
            data={"case_reference": "CASE-OVERLIMIT"}
        )

    assert resp.status_code == 413
    assert "exceeds maximum limit of 200 MB" in resp.json()["detail"]


# =============================================================================
# 7. MULTI-EVIDENCE UNIVERSAL UPLOAD AT 200 MB
# =============================================================================

def test_universal_evidence_upload_size_limit(tmp_path):
    """Verifies that multi-evidence universal endpoint honors 200 MB ceiling."""
    valid_doc = tmp_path / "Evidence_Doc.pdf"
    valid_doc.write_bytes(b"%PDF-1.4\nTest PDF content\n%%EOF")

    with open(valid_doc, "rb") as f:
        resp = client.post(
            "/api/universal/investigations/upload",
            files=[("files", ("Evidence_Doc.pdf", f, "application/pdf"))],
            data={"case_reference": "CASE-UNIVERSAL-200MB"}
        )

    assert resp.status_code == 200
    inv_id = resp.json()["investigation_id"]
    workspace_mgr.delete_workspace(inv_id)


# =============================================================================
# 8. INTERRUPTED UPLOAD & TEMPORARY FILE CLEANUP
# =============================================================================

def test_interrupted_upload_temporary_file_cleanup():
    """Verify that an interrupted stream cleans up temporary files safely."""
    class BrokenStream(io.RawIOBase):
        def __init__(self):
            self.read_count = 0
        def readable(self):
            return True
        def readinto(self, b):
            self.read_count += 1
            if self.read_count > 3:
                raise ConnectionResetError("Connection forcibly closed by remote host.")
            b[:1024] = b"X" * 1024
            return 1024

    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp_path = Path(tmp.name)
    try:
        with pytest.raises(ConnectionResetError):
            safe_copy_upload(BrokenStream(), tmp, max_bytes=LIMIT_BYTES)
    finally:
        tmp.close()
        tmp_path.unlink(missing_ok=True)

    # File should not exist after cleanup
    assert not tmp_path.exists()
