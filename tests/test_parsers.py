import pytest
from backend.app.core.models import ApkMetadata, PermissionInfo, ComponentInfo
from backend.app.analyzers.manifest_analyzer import analyze_manifest
from backend.app.analyzers.string_analyzer import (
    extract_and_classify_strings, try_decode_string, is_private_ip
)

def test_manifest_dangerous_combination_detection():
    metadata = ApkMetadata(
        permissions=[
            PermissionInfo(name="android.permission.INTERNET", is_dangerous=False, is_custom=False),
            PermissionInfo(name="android.permission.READ_SMS", is_dangerous=True, is_custom=False),
            PermissionInfo(name="android.permission.BIND_ACCESSIBILITY_SERVICE", is_dangerous=True, is_custom=False),
            PermissionInfo(name="android.permission.SYSTEM_ALERT_WINDOW", is_dangerous=True, is_custom=False),
        ],
        services=[
            ComponentInfo(name="com.test.ExportedService", component_type="service", exported=True, permission=None)
        ],
        uses_cleartext_traffic=True,
        is_debuggable=True
    )

    findings, summary = analyze_manifest(metadata)
    titles = [f.title for f in findings]

    assert any("Cleartext" in t for t in titles)
    assert any("Debuggable" in t for t in titles)
    assert any("SMS Access + Internet" in t for t in titles)
    assert any("Accessibility Service" in t for t in titles)
    assert any("Exported Services" in t for t in titles)

def test_private_ip_classification():
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("198.51.100.45") is True # TEST-NET-2 documentation/reserved block

def test_offline_decoding():
    # Base64 of 'https://evil-c2.com'
    b64_str = "aHR0cHM6Ly9ldmlsLWMyLmNvbQ=="
    success, decoded, trans = try_decode_string(b64_str)
    assert success is True
    assert decoded == "https://evil-c2.com"
    assert "Base64" in trans

    # Hex of 'command_payload'
    hex_str = "636f6d6d616e645f7061796c6f6164"
    success, decoded, trans = try_decode_string(hex_str)
    assert success is True
    assert decoded == "command_payload"
    assert "Hexadecimal" in trans
