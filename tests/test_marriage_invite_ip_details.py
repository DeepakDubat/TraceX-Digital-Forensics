import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database.repository import repo
from backend.app.core.models import (
    InvestigationRecord, C2Indicator, NetworkIOC
)
from backend.app.analyzers.ip_evidence_extractor import extract_all_ips_from_investigation
from backend.app.analyzers.ip_intelligence_engine import (
    build_ip_intelligence_record,
    get_current_network_mode
)
from backend.app.core.network_mode import set_network_mode

client = TestClient(app)

MARRIAGE_INV_ID = "INV-20261022-6840AD"

@pytest.fixture(autouse=True)
def setup_marriage_invite_investigation():
    # Setup test investigation matching production MarriageInvite.apk
    rec = InvestigationRecord(
        id=MARRIAGE_INV_ID,
        filename="MarriageInvite.apk",
        original_size=2048000,
        md5="1234567890abcdef1234567890abcdef",
        sha1="1234567890abcdef1234567890abcdef12345678",
        sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        status="completed",
        severity="High",
        confidence="High",
        package_name="com.neel.anju",
        file_type="apk"
    )
    repo.create_investigation(rec)

    # Real C2 indicators matching production MarriageInvite.apk
    c2s = [
        C2Indicator(
            id="C2-IND-008",
            indicator_type="url",
            value="http://118.196.64.77/api/v1/photos/upload",
            normalized_value="http://118.196.64.77/api/v1/photos/upload",
            source_file="assets/config.json",
            classification="potential_c2",
            why_suspicious="Direct raw public IP communication without DNS hostname resolution.",
            confidence="High",
            threat_intel_status="clean",
            recommended_validation="Correlate with reverse DNS"
        ),
        C2Indicator(
            id="C2-IND-009",
            indicator_type="url",
            value="http://118.196.64.77/api/v1/invite/send",
            normalized_value="http://118.196.64.77/api/v1/invite/send",
            source_file="assets/config.json",
            classification="potential_c2",
            why_suspicious="Direct raw public IP communication without DNS hostname resolution.",
            confidence="High",
            threat_intel_status="clean",
            recommended_validation="Correlate with reverse DNS"
        ),
        C2Indicator(
            id="C2-IND-010",
            indicator_type="url",
            value="http://118.196.64.77:8080/admin",
            normalized_value="http://118.196.64.77:8080/admin",
            source_file="assets/config.json",
            classification="potential_c2",
            why_suspicious="URL path '/admin' matches common botnet check-in, beaconing, or panel endpoints.",
            confidence="High",
            threat_intel_status="clean",
            recommended_validation="Correlate with reverse DNS"
        ),
        C2Indicator(
            id="C2-IND-011",
            indicator_type="url",
            value="http://118.196.64.77/health",
            normalized_value="http://118.196.64.77/health",
            source_file="assets/config.json",
            classification="potential_c2",
            why_suspicious="Direct raw public IP communication without DNS hostname resolution.",
            confidence="High",
            threat_intel_status="clean",
            recommended_validation="Correlate with reverse DNS"
        ),
        C2Indicator(
            id="C2-IND-016",
            indicator_type="ip",
            value="118.196.64.77",
            normalized_value="118.196.64.77",
            source_file="assets/app.properties",
            classification="potential_c2",
            why_suspicious="Extracted public IP address embedded in application strings.",
            confidence="High",
            threat_intel_status="clean",
            recommended_validation="Correlate with reverse DNS"
        )
    ]
    repo.save_c2_indicators(MARRIAGE_INV_ID, c2s)

    # Real Network IOCs
    iocs = [
        NetworkIOC(
            id="IOC-DOM-002",
            ioc_type="domain",
            value="smtp.host",
            source_file="assets/config.json",
            confidence="Medium"
        ),
        NetworkIOC(
            id="IOC-DOM-006",
            ioc_type="domain",
            value="gmail.com",
            source_file="assets/config.json",
            confidence="Low"
        )
    ]
    repo.save_network_iocs(MARRIAGE_INV_ID, iocs)


def test_marriage_invite_database_evidence_exists():
    """Verify MarriageInvite.apk investigation exists with real evidence."""
    detail = repo.get_investigation_detail(MARRIAGE_INV_ID)
    assert detail is not None
    assert detail.record.filename == "MarriageInvite.apk"
    assert detail.record.package_name == "com.neel.anju"

    # Verify C2 indicators contains the IP and associated URLs
    c2_values = [c.value for c in detail.c2_indicators]
    assert any("118.196.64.77" in v for v in c2_values)


def test_marriage_invite_ip_extraction():
    """Verify IP evidence extractor discovers 118.196.64.77 with all 5 evidence references."""
    detail = repo.get_investigation_detail(MARRIAGE_INV_ID)
    raw = extract_all_ips_from_investigation(detail)

    assert "118.196.64.77" in raw
    entry = raw["118.196.64.77"]
    assert entry["ip_address"] == "118.196.64.77"
    assert entry["ip_version"] == "IPv4"
    assert len(entry["evidence_references"]) >= 5

    # Check evidence references provenance
    files = [r.source_file for r in entry["evidence_references"]]
    assert "assets/config.json" in files
    assert "assets/app.properties" in files


def test_marriage_invite_sidebar_count_consistency():
    """Verify that sidebar calculation matches the extracted IP count."""
    detail = repo.get_investigation_detail(MARRIAGE_INV_ID)
    raw = extract_all_ips_from_investigation(detail)
    unique_extracted_count = len(raw)
    assert unique_extracted_count == 1

    # Simulate frontend sidebar count logic
    ips = set()
    for ioc in detail.network_iocs:
        if ioc.ioc_type in ("ipv4", "ipv6"):
            ips.add(ioc.value)
    for c2 in detail.c2_indicators:
        if c2.indicator_type == "ip":
            ips.add(c2.value)

    assert len(ips) == 1
    assert "118.196.64.77" in ips


def test_marriage_invite_api_summary_endpoint():
    """Verify GET /api/investigations/{id}/ip-details returns 200 with 1 IP."""
    res = client.get(f"/api/investigations/{MARRIAGE_INV_ID}/ip-details")
    assert res.status_code == 200
    data = res.json()

    assert data["investigation_id"] == MARRIAGE_INV_ID
    assert data["total_unique_ips"] == 1
    assert data["ipv4_count"] == 1
    assert data["ipv6_count"] == 0
    assert len(data["ips"]) == 1

    rec = data["ips"][0]
    assert rec["ip_address"] == "118.196.64.77"
    assert rec["ip_version"] == "IPv4"
    assert len(rec["evidence_references"]) >= 5


def test_marriage_invite_local_only_mode_restrictions():
    """Verify LOCAL_ONLY mode blocks outbound queries and reports SKIPPED_LOCAL_ONLY."""
    set_network_mode("LOCAL_ONLY")
    detail = repo.get_investigation_detail(MARRIAGE_INV_ID)
    raw = extract_all_ips_from_investigation(detail)
    entry = raw["118.196.64.77"]

    rec = build_ip_intelligence_record(
        investigation_id=MARRIAGE_INV_ID,
        ip_str="118.196.64.77",
        ip_version="IPv4",
        evidence_references=entry["evidence_references"],
        associated_urls=entry["associated_urls"],
        associated_domains=entry["associated_domains"],
        force_refresh=True
    )

    assert rec.lookup_status == "SKIPPED_LOCAL_ONLY"
    assert "LOCAL_ONLY" in rec.network_info.comment
    assert rec.threat_info.threat_status == "UNKNOWN"
    assert "Not Evaluated" in rec.threat_info.blacklist_status


def test_marriage_invite_report_exports():
    """Verify export of individual IP reports for MarriageInvite.apk in PDF, HTML, TXT, JSON."""
    res_pdf = client.post(
        f"/api/investigations/{MARRIAGE_INV_ID}/ip-details/118.196.64.77/export",
        json={"format": "pdf", "overwrite": True}
    )
    assert res_pdf.status_code == 200
    pdf_path = Path(res_pdf.json()["filepath"])
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 0

    res_html = client.post(
        f"/api/investigations/{MARRIAGE_INV_ID}/ip-details/118.196.64.77/export",
        json={"format": "html", "overwrite": True}
    )
    assert res_html.status_code == 200
    html_path = Path(res_html.json()["filepath"])
    assert html_path.exists()
    assert html_path.stat().st_size > 0

    res_txt = client.post(
        f"/api/investigations/{MARRIAGE_INV_ID}/ip-details/118.196.64.77/export",
        json={"format": "txt", "overwrite": True}
    )
    assert res_txt.status_code == 200
    txt_path = Path(res_txt.json()["filepath"])
    assert txt_path.exists()
    assert txt_path.stat().st_size > 0

    res_json = client.post(
        f"/api/investigations/{MARRIAGE_INV_ID}/ip-details/118.196.64.77/export",
        json={"format": "json", "overwrite": True}
    )
    assert res_json.status_code == 200
    json_path = Path(res_json.json()["filepath"])
    assert json_path.exists()
    assert json_path.stat().st_size > 0
