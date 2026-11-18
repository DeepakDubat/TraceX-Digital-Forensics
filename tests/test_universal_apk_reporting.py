import pytest
import io
import zipfile
from datetime import datetime
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.analyzers.permission_intel import classify_permission, ANDROID_PERMISSIONS_CATALOG
from backend.app.reporting.pdf_generator import generate_apk_pdf_report, generate_apk_html_report
from backend.app.reporting.txt_generator import generate_txt_forensic_report
from backend.app.integrations.osint.network_intelligence import NetworkIntelligence
from backend.app.database.repository import repo
from backend.app.core.models import (
    InvestigationRecord, InvestigationDetail, ApkMetadata,
    PermissionInfo, StaticFinding, C2Indicator, SecretFinding, FinalAssessment
)

client = TestClient(app)

def _create_mock_apk_investigation(inv_id: str) -> InvestigationDetail:
    rec = InvestigationRecord(
        id=inv_id,
        filename="sample_target.apk",
        original_size=543210,
        md5="112233445566778899aabbccddeeff00",
        sha1="112233445566778899aabbccddeeff0011223344",
        sha256="112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
        status="completed",
        severity="High",
        confidence="High",
        package_name="com.security.forensicapp",
        file_type="apk"
    )
    repo.create_investigation(rec)

    meta = ApkMetadata(
        app_name="Forensic Target App",
        package_name="com.security.forensicapp",
        version_name="2.1.0",
        version_code="210",
        target_sdk_version="34",
        min_sdk_version="24",
        launcher_activity="com.security.forensicapp.MainActivity",
        permissions=[
            PermissionInfo(name="android.permission.INTERNET", is_dangerous=False, description="Internet access"),
            PermissionInfo(name="android.permission.SEND_SMS", is_dangerous=True, description="Send SMS messages"),
            PermissionInfo(name="android.permission.CAMERA", is_dangerous=True, description="Camera access"),
            PermissionInfo(name="android.permission.ACCESS_FINE_LOCATION", is_dangerous=True, description="Precise GPS"),
            PermissionInfo(name="android.permission.SYSTEM_ALERT_WINDOW", is_dangerous=True, description="Overlay window"),
        ]
    )
    repo.save_metadata(inv_id, meta)

    findings = [
        StaticFinding(
            id="MAN-COMB-01",
            category="manifest",
            severity="High",
            confidence="High",
            title="Suspicious Permission Combination: SMS Access + Internet",
            description="Application requests SMS capabilities alongside INTERNET permission.",
            source_file="AndroidManifest.xml",
            explanation="Allows potential exfiltration of SMS OTP tokens to remote infrastructure.",
            remediation_advice="Review SMS handlers in bytecode."
        )
    ]
    repo.save_static_findings(inv_id, findings)

    c2 = [
        C2Indicator(
            id="C2-001",
            indicator_type="url",
            value="http://command.target-domain.org:8080/beacon",
            normalized_value="http://command.target-domain.org:8080/beacon",
            classification="potential_c2",
            why_suspicious="Direct outbound HTTP beacon on non-standard port",
            confidence="High",
            recommended_validation="Correlate with passive DNS and WHOIS",
            source_file="classes.dex"
        )
    ]
    repo.save_c2_indicators(inv_id, c2)

    secrets = [
        SecretFinding(
            id="SEC-001",
            token_category="api_key",
            redacted_value="AIzaSyA••••••••••••••••••••••••••••",
            source_location="classes.dex",
            rule_matched="Google API Key",
            confidence="High"
        )
    ]
    repo.save_secrets(inv_id, secrets)

    assess = FinalAssessment(
        overall_severity="High",
        overall_confidence="High",
        risk_score=72,
        executive_summary="Static analysis indicates high risk due to SMS access combined with outbound network beaconing.",
        strongest_evidence=["SMS + Internet permission combination", "Outbound beacon endpoint in DEX"],
        potential_malicious_functionality=["SMS interception", "C2 communication"]
    )
    repo.save_assessment(inv_id, assess)

    return repo.get_investigation_detail(inv_id)


def test_permission_intelligence_categorization():
    """Verify universal permission classification across categories and protection levels."""
    p_sms = classify_permission("android.permission.SEND_SMS")
    assert p_sms.category == "CONTACTS & COMMUNICATION"
    assert p_sms.protection_level == "dangerous"
    assert p_sms.risk_level == "CRITICAL"
    assert "SMS" in p_sms.description or "SMS" in p_sms.access_scope

    p_net = classify_permission("android.permission.INTERNET")
    assert p_net.category == "INTERNET & NETWORK"
    assert p_net.protection_level == "normal"
    assert p_net.risk_level == "MEDIUM"

    p_cam = classify_permission("android.permission.CAMERA")
    assert p_cam.category == "CAMERA & MICROPHONE"
    assert p_cam.risk_level == "CRITICAL"

    p_loc = classify_permission("android.permission.ACCESS_FINE_LOCATION")
    assert p_loc.category == "LOCATION"
    assert p_loc.risk_level == "CRITICAL"

    p_overlay = classify_permission("android.permission.SYSTEM_ALERT_WINDOW")
    assert p_overlay.category == "DEVICE & SYSTEM"
    assert p_overlay.protection_level == "special_access"
    assert p_overlay.risk_level == "CRITICAL"

    # Custom permission dynamic fallback
    p_custom = classify_permission("com.custom.banking.INJECT_HOOK")
    assert p_custom.protection_level == "custom"
    assert p_custom.risk_level == "LOW"


def test_report_downloads_all_formats():
    """Verify end-to-end report generation and download for TXT, HTML, PDF, JSON, and Bundle."""
    inv_id = "INV-TEST-REPORT-DL-001"
    detail = _create_mock_apk_investigation(inv_id)
    assert detail is not None, f"Investigation {inv_id} created"

    # 1. TXT Report
    r_txt = client.get(f"/api/investigations/{inv_id}/report/txt")
    assert r_txt.status_code == 200
    assert "text/plain" in r_txt.headers.get("content-type", "")
    assert "attachment" in r_txt.headers.get("content-disposition", "")
    assert "APK FORENSICS" in r_txt.text
    assert "Permission Summary Dashboard" in r_txt.text
    assert "android.permission.SEND_SMS" in r_txt.text

    # 2. HTML Report
    r_html = client.get(f"/api/investigations/{inv_id}/report/html")
    assert r_html.status_code == 200
    assert "text/html" in r_html.headers.get("content-type", "")
    assert "<!DOCTYPE html>" in r_html.text
    assert "TRACEX" in r_html.text
    assert "Section 3: Android Permission Intelligence" in r_html.text

    # 3. PDF Report
    r_pdf = client.get(f"/api/investigations/{inv_id}/report/pdf")
    assert r_pdf.status_code == 200
    assert "application/pdf" in r_pdf.headers.get("content-type", "")
    assert r_pdf.content.startswith(b"%PDF")
    assert len(r_pdf.content) > 5000

    # 4. JSON Export
    r_json = client.get(f"/api/investigations/{inv_id}/report/json")
    assert r_json.status_code == 200
    assert "application/json" in r_json.headers.get("content-type", "")
    data = r_json.json()
    assert "record" in data
    assert data["record"]["id"] == inv_id

    # 5. Reproducibility ZIP Bundle
    r_bundle = client.get(f"/api/investigations/{inv_id}/report/bundle")
    assert r_bundle.status_code == 200
    assert "application/zip" in r_bundle.headers.get("content-type", "")
    zf = zipfile.ZipFile(io.BytesIO(r_bundle.content))
    namelist = zf.namelist()
    assert any(n.endswith(".txt") for n in namelist)
    assert any(n.endswith(".html") for n in namelist)
    assert any(n.endswith(".pdf") for n in namelist)


def test_ip_intelligence_rfc1918_and_airgap():
    """Verify IP classification without external lookups for private IPs and air-gap mode."""
    # Private IP
    net = NetworkIntelligence(local_only_mode=False)
    obs_priv = net.query_ip("192.168.1.100", "INV-TEST", "IND-1")
    assert obs_priv.status == "SUCCESS"
    assert obs_priv.normalized_data["is_private"] is True
    assert "RFC 1918" in obs_priv.normalized_data["network_type"]

    # Loopback IP
    obs_loop = net.query_ip("127.0.0.1", "INV-TEST", "IND-2")
    assert obs_loop.normalized_data["is_private"] is True

    # Air-gap LOCAL_ONLY mode
    net_local = NetworkIntelligence(local_only_mode=True)
    obs_airgap = net_local.query_ip("8.8.8.8", "INV-TEST", "IND-3")
    assert obs_airgap.status == "SKIPPED_LOCAL_ONLY"
    assert "local-only mode is active" in obs_airgap.limitations
