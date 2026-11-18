import pytest
import tempfile
import zipfile
from pathlib import Path
from backend.app.core.security import (
    validate_apk_file, sanitize_filename, safe_extract_apk
)
from tests.create_fixtures import create_harmless_test_apk

def test_sanitize_filename():
    assert sanitize_filename("test.apk") == "test.apk"
    assert sanitize_filename("../../etc/passwd.apk") == "passwd.apk"
    assert sanitize_filename("my suspicious sample!@#$.apk").endswith(".apk")

def test_validate_valid_apk(tmp_path):
    apk_path = tmp_path / "valid_sample.apk"
    create_harmless_test_apk(apk_path)
    is_valid, msg = validate_apk_file(apk_path)
    assert is_valid is True
    assert "Valid APK" in msg

def test_validate_empty_file(tmp_path):
    empty = tmp_path / "empty.apk"
    empty.touch()
    is_valid, msg = validate_apk_file(empty)
    assert is_valid is False
    assert "0 bytes" in msg

def test_validate_invalid_header(tmp_path):
    fake = tmp_path / "fake.apk"
    fake.write_bytes(b"NOT_A_ZIP_HEADER_DATA")
    is_valid, msg = validate_apk_file(fake)
    assert is_valid is False
    assert "Missing standard ZIP/APK header" in msg

def test_zip_slip_protection(tmp_path):
    # Construct an archive with malicious traversal path
    malicious_zip = tmp_path / "traversal.apk"
    with zipfile.ZipFile(malicious_zip, "w") as zf:
        zf.writestr("../../evil.sh", b"echo pwned")
        zf.writestr("AndroidManifest.xml", b"<manifest/>")

    extract_dir = tmp_path / "extracted"
    extracted = safe_extract_apk(malicious_zip, extract_dir)
    
    # Verify that evil.sh did NOT escape extract_dir
    escaped_file = tmp_path / "evil.sh"
    assert not escaped_file.exists()
    assert "AndroidManifest.xml" in extracted
