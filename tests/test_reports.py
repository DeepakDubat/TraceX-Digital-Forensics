import pytest
from datetime import datetime
from backend.app.core.models import (
    InvestigationRecord, InvestigationDetail, ApkMetadata,
    StaticFinding, C2Indicator, SecretFinding, ReverseShellFinding,
    NetworkIOC, FinalAssessment
)
from backend.app.reporting.txt_generator import (
    generate_txt_forensic_report, export_iocs_csv
)

def test_14_sections_in_txt_report():
    rec = InvestigationRecord(
        id="INV-20261019-TEST01",
        filename="suspicious_app.apk",
        original_size=1024567,
        md5="d41d8cd98f00b204e9800998ecf8427e",
        sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status="completed",
        severity="Critical",
        confidence="High",
        package_name="org.forensics.testapp",
        c2_count=1,
        secret_count=1,
        reverse_shell_detected=True
    )
    meta = ApkMetadata(
        app_name="TestApp",
        package_name="org.forensics.testapp",
        version_name="1.0",
        version_code="1"
    )
    c2 = [
        C2Indicator(
            id="C2-001",
            indicator_type="url",
            value="http://c2.duckdns.org:4444",
            normalized_value="http://c2.duckdns.org:4444",
            source_file="classes.dex",
            port=4444,
            classification="potential_c2",
            why_suspicious="Dynamic DNS non-standard port",
            confidence="High",
            recommended_validation="Check DNS"
        )
    ]
    secrets = [
        SecretFinding(
            id="SEC-001",
            token_category="api_key",
            redacted_value="AIza••••••••1234",
            source_location="classes.dex",
            rule_matched="Google API Key",
            confidence="High",
            verification_status="Pattern matched"
        )
    ]
    rs = [
        ReverseShellFinding(
            id="RS-001",
            pattern_type="socket_command_chain",
            title="Probable Reverse Shell",
            severity="Critical",
            confidence="Probable Reverse-Shell",
            execution_chain=["Socket", "Shell process", "Stream redirect"],
            explanation="Piped streams",
            limitations="Passive static inspection only"
        )
    ]
    assess = FinalAssessment(
        overall_severity="Critical",
        overall_confidence="High",
        risk_score=85,
        executive_summary="Critical indicators detected in test app.",
        strongest_evidence=["Interactive reverse shell", "C2 DuckDNS"],
        potential_malicious_functionality=["Remote access"]
    )

    detail = InvestigationDetail(
        record=rec,
        metadata=meta,
        c2_indicators=c2,
        secrets=secrets,
        reverse_shell_findings=rs,
        assessment=assess
    )

    report_text = generate_txt_forensic_report(detail)

    # Verify all 14 mandatory sections exist in the plain text report
    for sec_num in range(1, 15):
        assert f"SECTION {sec_num} --" in report_text

    # Verify key fields
    assert "INV-20261019-TEST01" in report_text
    assert "suspicious_app.apk" in report_text
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in report_text
    assert "CRITICAL" in report_text
    assert "c2.duckdns.org" in report_text
    assert "AIza••••••••1234" in report_text

def test_csv_ioc_export():
    c2 = [
        C2Indicator(
            id="C2-001",
            indicator_type="url",
            value="http://c2.duckdns.org:4444",
            normalized_value="http://c2.duckdns.org:4444",
            source_file="classes.dex",
            port=4444,
            classification="potential_c2",
            why_suspicious="Dynamic DNS",
            confidence="High",
            recommended_validation="Check DNS"
        )
    ]
    csv_out = export_iocs_csv([], c2)
    assert "c2.duckdns.org" in csv_out
    assert "potential_c2" in csv_out
