import os
import shutil
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database.repository import repo
from backend.app.core.models import (
    InvestigationRecord, StaticFinding, C2Indicator, NetworkIOC
)
from backend.app.models.ip_details import (
    IPEvidenceReference,
    InvestigationIPsSummary
)
from backend.app.analyzers.ip_evidence_extractor import (
    extract_all_ips_from_investigation,
    classify_ip_network,
    detect_cloud_infrastructure
)
from backend.app.analyzers.ip_intelligence_engine import (
    build_ip_intelligence_record,
    parse_rdap_vcard
)
from backend.app.reporting.ip_report_generator import (
    export_individual_ip_report_to_disk,
    export_all_ips_report_to_disk,
    list_saved_reports_for_ip,
    sanitize_ip_for_path,
    get_individual_ip_storage_dir,
    get_all_ips_storage_dir
)
from backend.app.core.network_mode import set_network_mode

client = TestClient(app)

TEST_INV_ID = "test-inv-ip-intel-001"

@pytest.fixture(autouse=True)
def setup_and_teardown_investigation():
    # Setup test investigation
    rec = InvestigationRecord(
        id=TEST_INV_ID,
        filename="threat_sample.apk",
        original_size=1048576,
        md5="d41d8cd98f00b204e9800998ecf8427e",
        sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status="completed",
        severity="High",
        confidence="High",
        package_name="com.threat.analyzer",
        file_type="apk"
    )
    repo.create_investigation(rec)

    # Static findings with IPs
    findings = [
        StaticFinding(
            id="FINDING-IP-01",
            category="network",
            severity="High",
            confidence="High",
            title="Hardcoded C2 IP Address Detected",
            description="Found hardcoded IPv4 address 8.8.8.8 in CommandHandler class communicating on port 4444",
            source_file="sources/com/threat/CommandHandler.java",
            evidence_snippet='String c2 = "http://8.8.8.8:4444/beacon";',
            technical_explanation="Hardcoded public IP used for beaconing."
        ),
        StaticFinding(
            id="FINDING-IP-02",
            category="network",
            severity="Low",
            confidence="High",
            title="Local Debugging Server Detected",
            description="Application binds to internal private IP address 192.168.1.100 for local debugging proxy.",
            source_file="sources/com/threat/DebugService.java",
            evidence_snippet='Socket s = new Socket("192.168.1.100", 8080);'
        ),
        StaticFinding(
            id="FINDING-IP-03",
            category="network",
            severity="Medium",
            confidence="High",
            title="AWS Cloud Endpoint Reference",
            description="Hardcoded AWS EC2 IP address 3.235.12.44 detected in network configuration payload.",
            source_file="res/raw/network_config.json",
            evidence_snippet='{"server": "3.235.12.44"}'
        ),
        StaticFinding(
            id="FINDING-IP-04",
            category="network",
            severity="Info",
            confidence="High",
            title="IPv6 Public Resolver Reference",
            description="Referenced Google IPv6 public DNS server 2001:4860:4860::8888 in resolver fallback logic.",
            source_file="sources/com/threat/DnsHelper.java",
            evidence_snippet='InetAddress dns = InetAddress.getByName("2001:4860:4860::8888");'
        )
    ]
    repo.save_static_findings(TEST_INV_ID, findings)

    # C2 Indicators
    c2s = [
        C2Indicator(
            id="C2-IND-01",
            indicator_type="ip",
            value="8.8.8.8",
            normalized_value="8.8.8.8",
            source_file="sources/com/threat/CommandHandler.java",
            classification="potential_c2",
            why_suspicious="Direct IP communication without DNS resolution",
            confidence="High",
            threat_intel_status="clean",
            recommended_validation="Confirm if legitimate DNS or masqueraded C2"
        )
    ]
    repo.save_c2_indicators(TEST_INV_ID, c2s)

    # Network IOCs
    iocs = [
        NetworkIOC(
            id="IOC-01",
            ioc_type="ipv4",
            value="8.8.8.8",
            source_file="sources/com/threat/CommandHandler.java",
            confidence="High"
        ),
        NetworkIOC(
            id="IOC-02",
            ioc_type="ipv4",
            value="127.0.0.1",
            source_file="sources/com/threat/LocalServer.java",
            confidence="High"
        ),
        NetworkIOC(
            id="IOC-03",
            ioc_type="ipv6",
            value="2001:4860:4860::8888",
            source_file="sources/com/threat/DnsHelper.java",
            confidence="High"
        )
    ]
    repo.save_network_iocs(TEST_INV_ID, iocs)

    yield

    # Teardown directory
    try:
        report_dir = get_all_ips_storage_dir(TEST_INV_ID)
        if report_dir.exists():
            shutil.rmtree(report_dir, ignore_errors=True)
    except Exception:
        pass


def test_ip_evidence_extraction():
    detail = repo.get_investigation_detail(TEST_INV_ID)
    assert detail is not None

    evidence_map = extract_all_ips_from_investigation(detail)
    # Check that all unique IPs were discovered
    assert "8.8.8.8" in evidence_map
    assert "192.168.1.100" in evidence_map
    assert "3.235.12.44" in evidence_map
    assert "127.0.0.1" in evidence_map
    assert "2001:4860:4860::8888" in evidence_map

    # Check evidence traceability for 8.8.8.8
    entry_8888 = evidence_map["8.8.8.8"]
    refs = entry_8888["evidence_references"]
    assert len(refs) >= 2  # Discovered across static finding, C2, and network IOC
    source_files = [r.source_file for r in refs]
    assert "sources/com/threat/CommandHandler.java" in source_files
    # Check code snippet preserved
    snippets = [r.context_snippet for r in refs if r.context_snippet]
    assert any("8.8.8.8:4444" in s for s in snippets)


def test_ip_classification_subnets():
    # RFC 1918 Private
    c_priv = classify_ip_network("192.168.1.100")
    assert c_priv.is_private is True
    assert "Private" in c_priv.classification_label

    # Loopback
    c_loop = classify_ip_network("127.0.0.1")
    assert c_loop.is_loopback is True
    assert "Loopback" in c_loop.classification_label

    # IPv6 Loopback
    c_loop6 = classify_ip_network("::1")
    assert c_loop6.is_loopback is True
    assert "Loopback" in c_loop6.classification_label

    # Public IPv4 (Google DNS)
    c_pub = classify_ip_network("8.8.8.8")
    assert c_pub.is_private is False
    assert c_pub.is_public_dns is True
    assert "Google Public DNS" in c_pub.classification_label

    # AWS Cloud IP
    cloud_name, _ = detect_cloud_infrastructure("3.235.12.44")
    assert cloud_name == "Amazon Web Services"

    # Cloudflare Public DNS
    c_cf = classify_ip_network("1.1.1.1")
    assert c_cf.is_public_dns is True


def test_network_privacy_mode_enforcement():
    # Set LOCAL_ONLY mode
    set_network_mode("LOCAL_ONLY")
    detail = repo.get_investigation_detail(TEST_INV_ID)
    evidence_map = extract_all_ips_from_investigation(detail)

    entry = evidence_map.get("8.8.8.8")
    rec = build_ip_intelligence_record(
        investigation_id=TEST_INV_ID,
        ip_str="8.8.8.8",
        ip_version="IPv4",
        evidence_references=entry["evidence_references"],
        associated_urls=list(entry.get("associated_urls", [])),
        force_refresh=True
    )
    assert rec.lookup_status == "SKIPPED_LOCAL_ONLY"
    assert rec.threat_info.threat_status == "CLEAN"
    assert rec.domain_dns_info.reverse_dns is None
    assert "approximate" in rec.geolocation_info.disclaimer.lower()


def test_rdap_vcard_extraction():
    sample_vcard = [
        "vcard",
        [
            ["version", {}, "text", "4.0"],
            ["fn", {}, "text", "Google LLC"],
            ["org", {}, "text", "Google LLC"],
            ["email", {}, "text", "network-abuse@google.com"],
            ["tel", {}, "text", "+1-650-253-0000"],
            ["adr", {}, "text", ["", "", "1600 Amphitheatre Parkway", "Mountain View", "CA", "94043", "US"]]
        ]
    ]

    card = parse_rdap_vcard(sample_vcard)
    assert card["fn"] == "Google LLC"
    assert card["org"] == "Google LLC"
    assert card["email"] == "network-abuse@google.com"
    assert card["tel"] == "+1-650-253-0000"
    assert "Mountain View" in card["adr"]


def test_single_ip_report_generation_and_storage():
    detail = repo.get_investigation_detail(TEST_INV_ID)
    evidence_map = extract_all_ips_from_investigation(detail)
    entry = evidence_map.get("8.8.8.8")

    rec = build_ip_intelligence_record(
        investigation_id=TEST_INV_ID,
        ip_str="8.8.8.8",
        ip_version="IPv4",
        evidence_references=entry["evidence_references"],
        associated_urls=list(entry.get("associated_urls", [])),
        force_refresh=True
    )

    # Test PDF export
    pdf_res = export_individual_ip_report_to_disk(rec, format_type="pdf")
    assert pdf_res["status"] == "success"
    pdf_path = Path(pdf_res["filepath"])
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 0
    assert "8.8.8.8" in pdf_path.name

    # Test HTML export
    html_res = export_individual_ip_report_to_disk(rec, format_type="html")
    assert html_res["status"] == "success"
    html_path = Path(html_res["filepath"])
    assert html_path.exists()
    assert html_path.stat().st_size > 0
    html_content = html_path.read_text(encoding="utf-8")
    assert "8.8.8.8" in html_content
    assert "approximate" in html_content.lower()

    # Test TXT export
    txt_res = export_individual_ip_report_to_disk(rec, format_type="txt")
    assert txt_res["status"] == "success"
    txt_path = Path(txt_res["filepath"])
    assert txt_path.exists()
    assert txt_path.stat().st_size > 0
    txt_content = txt_path.read_text(encoding="utf-8")
    assert "8.8.8.8" in txt_content
    assert "TRACEX" in txt_content

    # Test JSON export
    json_res = export_individual_ip_report_to_disk(rec, format_type="json")
    assert json_res["status"] == "success"
    json_path = Path(json_res["filepath"])
    assert json_path.exists()
    assert json_path.stat().st_size > 0
    json_content = json_path.read_text(encoding="utf-8")
    assert '"8.8.8.8"' in json_content


def test_ipv6_storage_path_sanitization():
    raw_ip = "2001:4860:4860::8888"
    sanitized = sanitize_ip_for_path(raw_ip)
    assert ":" not in sanitized
    assert sanitized == "2001_4860_4860__8888"

    detail = repo.get_investigation_detail(TEST_INV_ID)
    evidence_map = extract_all_ips_from_investigation(detail)
    entry = evidence_map.get(raw_ip)

    rec_v6 = build_ip_intelligence_record(
        investigation_id=TEST_INV_ID,
        ip_str=raw_ip,
        ip_version="IPv6",
        evidence_references=entry["evidence_references"],
        associated_urls=list(entry.get("associated_urls", [])),
        force_refresh=True
    )

    pdf_res = export_individual_ip_report_to_disk(rec_v6, format_type="pdf")
    assert pdf_res["status"] == "success"
    pdf_path = Path(pdf_res["filepath"])
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 0
    assert ":" not in str(pdf_path.name)


def test_all_ips_report_generation():
    detail = repo.get_investigation_detail(TEST_INV_ID)
    evidence_map = extract_all_ips_from_investigation(detail)

    records = [
        build_ip_intelligence_record(
            investigation_id=TEST_INV_ID,
            ip_str=ip,
            ip_version=data["ip_version"],
            evidence_references=data["evidence_references"],
            associated_urls=list(data.get("associated_urls", [])),
            force_refresh=True
        )
        for ip, data in evidence_map.items()
    ]

    summary = InvestigationIPsSummary(
        investigation_id=TEST_INV_ID,
        total_unique_ips=len(records),
        ipv4_count=sum(1 for r in records if r.ip_version == "IPv4"),
        ipv6_count=sum(1 for r in records if r.ip_version == "IPv6"),
        public_ip_count=sum(1 for r in records if not (r.classification.is_private or r.classification.is_loopback)),
        private_ip_count=sum(1 for r in records if r.classification.is_private),
        cloud_ip_count=sum(1 for r in records if r.classification.is_cloud),
        malicious_ip_count=0,
        suspicious_ip_count=0,
        clean_ip_count=len(records),
        unknown_ip_count=0,
        network_mode="LOCAL_ONLY",
        extraction_timestamp_utc="2026-11-17T00:00:00Z",
        ips=records
    )

    # HTML Dossier
    html_res = export_all_ips_report_to_disk(summary, format_type="html")
    assert html_res["status"] == "success"
    html_path = Path(html_res["filepath"])
    assert html_path.exists()
    assert html_path.stat().st_size > 0
    html_content = html_path.read_text(encoding="utf-8")
    assert "8.8.8.8" in html_content
    assert "192.168.1.100" in html_content

    # PDF Dossier
    pdf_res = export_all_ips_report_to_disk(summary, format_type="pdf")
    assert pdf_res["status"] == "success"
    pdf_path = Path(pdf_res["filepath"])
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 0


def test_api_ip_details_endpoints():
    # 1. Summary endpoint
    res = client.get(f"/api/investigations/{TEST_INV_ID}/ip-details")
    assert res.status_code == 200
    data = res.json()
    assert "total_unique_ips" in data
    assert data["total_unique_ips"] >= 5
    assert len(data["ips"]) >= 5

    # 2. Single IP endpoint
    res_single = client.get(f"/api/investigations/{TEST_INV_ID}/ip-details/8.8.8.8")
    assert res_single.status_code == 200
    single_data = res_single.json()
    assert single_data["ip_address"] == "8.8.8.8"
    assert len(single_data["evidence_references"]) >= 2

    # 3. Export Single IP endpoint
    res_exp = client.post(
        f"/api/investigations/{TEST_INV_ID}/ip-details/8.8.8.8/export",
        json={"format": "html", "overwrite": True}
    )
    assert res_exp.status_code == 200
    exp_data = res_exp.json()
    assert exp_data["status"] == "success"
    assert Path(exp_data["filepath"]).exists()

    # 4. Export All IPs endpoint
    res_exp_all = client.post(
        f"/api/investigations/{TEST_INV_ID}/ip-details/export-all",
        json={"format": "pdf", "overwrite": True}
    )
    assert res_exp_all.status_code == 200
    exp_all_data = res_exp_all.json()
    assert exp_all_data["status"] == "success"
    assert Path(exp_all_data["filepath"]).exists()

    # 5. Saved files endpoint
    res_saved = client.get(f"/api/investigations/{TEST_INV_ID}/ip-details/8.8.8.8/saved-files")
    assert res_saved.status_code == 200
    saved_data = res_saved.json()
    assert len(saved_data) > 0
    assert any("8.8.8.8" in f["filename"] for f in saved_data)
