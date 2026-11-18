import io
import struct
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta

from backend.app.config import settings
from backend.app.database.db import init_db
from backend.app.core.models import (
    AuthorizedNetworkScope,
    ActiveValidationResult,
    InvestigationRecord,
    UniversalInvestigationDetail,
    StaticFinding,
    C2Indicator,
    SecretFinding,
    ReverseShellFinding,
    DynamicTelemetryEvent,
    NetworkFlowRecord,
    DroppedArtifactRecord,
    DynamicSandboxRun,
    OSINTIndicator
)
from backend.app.integrations.osint.providers.base_provider import (
    ProviderStatus,
    STATUS_SUCCESS,
    STATUS_NOT_FOUND,
    STATUS_RATE_LIMITED,
    STATUS_INVALID_INDICATOR,
    STATUS_UNAUTHORIZED,
    STATUS_UNAVAILABLE
)
from backend.app.integrations.osint.providers.provider_registry import provider_registry
from backend.app.analyzers.network.active_validator import (
    active_validator,
    set_external_request_kill_switch,
    is_kill_switch_active,
    ActiveNetworkValidator
)
from backend.app.integrations.sandbox.sandbox_detector import sandbox_detector
from backend.app.analyzers.network.pcap_telemetry_engine import pcap_telemetry_engine
from backend.app.analyzers.universal.static_dynamic_correlator import StaticDynamicCorrelator
from backend.app.analyzers.universal.evidence_risk_assessor import EvidenceRiskAssessor
from backend.app.reporting.master_report_generator import (
    generate_master_txt_report,
    export_network_flows_csv,
    export_active_validation_csv,
    export_static_dynamic_correlations_csv
)
from backend.app.database.repository import repo


@pytest.fixture(autouse=True, scope="module")
def setup_isolated_test_db():
    """Configures a dedicated isolated SQLite test database to prevent lock contention."""
    set_external_request_kill_switch(False)
    temp_dir = tempfile.mkdtemp()
    test_db_path = Path(temp_dir) / "test_advanced_workbench.db"
    orig_db = settings.DB_PATH
    settings.DB_PATH = test_db_path
    init_db()

    # Pre-populate test investigation records for foreign keys
    test_invs = ["INV-1", "INV-SCOPE-TEST", "INV-SSRF", "INV-KILL", "INV-CORR-TEST", "INV-RISK-TEST", "INV-RPT-TEST"]
    for inv_id in test_invs:
        try:
            rec = InvestigationRecord(
                id=inv_id,
                filename="sample.bin",
                original_size=1024,
                md5="d41d8cd98f00b204e9800998ecf8427e",
                sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
                sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                file_type="exe",
                local_only_mode=False,
                status="completed",
                progress=100,
                current_stage="Done",
                created_at=datetime.utcnow(),
                total_findings=0,
                severity="Informational",
                confidence="High",
                c2_count=0,
                secret_count=0,
                reverse_shell_detected=False
            )
            repo.create_investigation(rec)
        except Exception:
            pass

    yield

    set_external_request_kill_switch(False)
    settings.DB_PATH = orig_db
    if test_db_path.exists():
        try:
            test_db_path.unlink()
        except Exception:
            pass


# ========================================================
# 1. OSINT PROVIDER ADAPTER TESTS (ALL 16 PROVIDERS)
# ========================================================

def test_provider_registry_contains_all_16_providers():
    providers = provider_registry.list_providers()
    assert len(providers) >= 16

    expected_ids = {
        "virustotal", "alienvault_otx", "abuseipdb", "urlhaus",
        "malwarebazaar", "urlscan", "dns", "rdap",
        "network_info", "cert_transparency", "ipinfo",
        "shodan", "censys", "greynoise", "misp", "passive_dns"
    }
    registered_ids = {p.provider_id for p in providers}
    for pid in expected_ids:
        assert pid in registered_ids, f"Provider {pid} missing from registry"


def test_virustotal_adapter_explicit_statuses():
    vt = provider_registry.get_provider("virustotal")
    assert vt is not None

    # Invalid indicator type
    res = vt.query("asn", "AS15169", "INV-1", "IND-1")
    assert res.status == STATUS_INVALID_INDICATOR

    # Mocked SUCCESS response
    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 12, "suspicious": 2, "undetected": 50},
                    "reputation": -20
                }
            }
        }
        mock_get.return_value = mock_resp

        with patch.object(vt, "_get_api_key", return_value="test_key"):
            res = vt.query("domain", "evil-c2.com", "INV-1", "IND-1")
            assert res.status == STATUS_SUCCESS
            assert res.normalized_data["malicious_count"] == 12

    # Mocked 404 NOT_FOUND
    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        with patch.object(vt, "_get_api_key", return_value="test_key"):
            res = vt.query("domain", "never-seen-domain-998877.com", "INV-1", "IND-1")
            assert res.status == STATUS_NOT_FOUND

    # Mocked 429 RATE_LIMITED
    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp

        with patch.object(vt, "_get_api_key", return_value="test_key"):
            res = vt.query("domain", "evil-c2.com", "INV-1", "IND-1")
            assert res.status == STATUS_RATE_LIMITED


def test_abuseipdb_adapter_mocked():
    ab = provider_registry.get_provider("abuseipdb")
    assert ab is not None

    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 88,
                "totalReports": 34,
                "countryCode": "RU",
                "usageType": "Data Center/Web Hosting"
            }
        }
        mock_get.return_value = mock_resp

        with patch.object(ab, "_get_api_key", return_value="test_key"):
            res = ab.query("ip", "198.51.100.5", "INV-1", "IND-1")
            assert res.status == STATUS_SUCCESS
            assert res.normalized_data["abuse_confidence_score"] == 88


def test_dns_and_rdap_adapters():
    dns_prov = provider_registry.get_provider("dns")
    rdap_prov = provider_registry.get_provider("rdap")

    # Test DNS provider with mock
    with patch("socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 80))]
        res = dns_prov.query("domain", "example.com", "INV-1", "IND-1")
        assert res.status == STATUS_SUCCESS
        assert "93.184.216.34" in res.normalized_data["resolved_ips"]

    # Test RDAP provider with mock
    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "ldhName": "EXAMPLE.COM",
            "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}]
        }
        mock_get.return_value = mock_resp

        res = rdap_prov.query("domain", "example.com", "INV-1", "IND-1")
        assert res.status == STATUS_SUCCESS


def test_optional_providers_status_when_no_credentials():
    shodan = provider_registry.get_provider("shodan")
    censys = provider_registry.get_provider("censys")
    greynoise = provider_registry.get_provider("greynoise")
    misp = provider_registry.get_provider("misp")

    with patch.object(shodan, "_get_api_key", return_value=""):
        res = shodan.query("ip", "8.8.8.8", "INV-1", "IND-1")
        assert res.status in (STATUS_UNAVAILABLE, STATUS_UNAUTHORIZED)

    with patch.object(censys, "_get_credentials", return_value=("", "")):
        res = censys.query("ip", "8.8.8.8", "INV-1", "IND-1")
        assert res.status in (STATUS_UNAVAILABLE, STATUS_UNAUTHORIZED)

    with patch.object(greynoise, "_get_api_key", return_value=""):
        res = greynoise.query("ip", "8.8.8.8", "INV-1", "IND-1")
        assert res.status in (STATUS_UNAVAILABLE, STATUS_UNAUTHORIZED)

    with patch.object(misp, "_get_config", return_value=("", "")):
        res = misp.query("domain", "evil.com", "INV-1", "IND-1")
        assert res.status in (STATUS_UNAVAILABLE, STATUS_UNAUTHORIZED)


# ========================================================
# 2. AUTHORIZED NETWORK VALIDATION & SAFETY CONTROLS
# ========================================================

def test_scope_creation_and_enforcement():
    inv_id = "INV-SCOPE-TEST"
    scope_id = "SCOPE-TEST-001"
    now = datetime.utcnow()

    scope = AuthorizedNetworkScope(
        id=scope_id,
        investigation_id=inv_id,
        authorized_targets=["authorized-target.org", "93.184.216.34"],
        allowed_test_types=["DNS", "TCP_CONNECT", "TLS_INSPECT", "HTTPS_HEAD"],
        allowed_ports=[80, 443],
        authorization_note="Explicitly authorized warrant test",
        operator_name="Forensic Analyst",
        operator_confirmed=True,
        request_budget=5,
        requests_used=0,
        created_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(hours=2)).isoformat(),
        is_revoked=False
    )
    repo.create_authorized_scope(scope)

    # 1. Unapproved target should be rejected immediately
    res_rejected = active_validator.execute_dns_lookup(scope_id, inv_id, "malicious-unapproved-site.com")
    assert res_rejected.status == "SCOPE_REJECTED"
    assert "allowlist" in res_rejected.diagnostic_message.lower()

    # 2. Approved target allowed
    with patch("socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 80))]
        res_approved = active_validator.execute_dns_lookup(scope_id, inv_id, "authorized-target.org")
        assert res_approved.status == "SUCCESS"
        assert "93.184.216.34" in res_approved.resolved_ips

    # 3. Budget tracking: 1 query used
    updated_scope = repo.get_authorized_scope(scope_id)
    assert updated_scope.requests_used == 1

    # 4. Revocation enforcement
    repo.revoke_scope(scope_id)
    res_revoked = active_validator.execute_dns_lookup(scope_id, inv_id, "authorized-target.org")
    assert res_revoked.status == "SCOPE_REJECTED"
    assert "revoked" in res_revoked.diagnostic_message.lower()


def test_ssrf_and_private_ip_blocking():
    scope_id = "SCOPE-SSRF-TEST"
    now = datetime.utcnow()
    scope = AuthorizedNetworkScope(
        id=scope_id,
        investigation_id="INV-SSRF",
        authorized_targets=["127.0.0.1", "10.0.0.5", "169.254.169.254", "internal-dev.local"],
        allowed_test_types=["DNS", "TCP_CONNECT"],
        allowed_ports=[80, 443],
        authorization_note="SSRF test",
        operator_name="Analyst",
        operator_confirmed=True,
        request_budget=10,
        requests_used=0,
        created_at_utc=now.isoformat(),
        expires_at_utc=(now + timedelta(hours=2)).isoformat(),
        is_revoked=False
    )
    repo.create_authorized_scope(scope)

    # 1. Loopback IP blocked
    res_loop = active_validator.execute_tcp_connect(scope_id, "INV-SSRF", "127.0.0.1", port=80)
    assert res_loop.status == "PRIVATE_IP_BLOCKED"

    # 2. RFC 1918 Private IP blocked
    res_priv = active_validator.execute_tcp_connect(scope_id, "INV-SSRF", "10.0.0.5", port=443)
    assert res_priv.status == "PRIVATE_IP_BLOCKED"

    # 3. Cloud metadata endpoint (169.254.169.254) blocked
    res_meta = active_validator.execute_tcp_connect(scope_id, "INV-SSRF", "169.254.169.254", port=80)
    assert res_meta.status == "PRIVATE_IP_BLOCKED"


def test_emergency_kill_switch():
    set_external_request_kill_switch(True)
    assert is_kill_switch_active() is True

    # Any network check under active kill switch must return CANCELLED immediately
    scope_id = "SCOPE-KILL-TEST"
    scope = AuthorizedNetworkScope(
        id=scope_id,
        investigation_id="INV-KILL",
        authorized_targets=["example.com"],
        allowed_test_types=["DNS"],
        allowed_ports=[80],
        authorization_note="Kill switch test",
        operator_name="Analyst",
        operator_confirmed=True,
        request_budget=5,
        requests_used=0,
        created_at_utc=datetime.utcnow().isoformat(),
        expires_at_utc=(datetime.utcnow() + timedelta(hours=1)).isoformat()
    )
    repo.create_authorized_scope(scope)

    res = active_validator.execute_dns_lookup(scope_id, "INV-KILL", "example.com")
    assert res.status == "CANCELLED"
    assert "kill switch" in res.diagnostic_message.lower()

    # Disarm kill switch
    set_external_request_kill_switch(False)
    assert is_kill_switch_active() is False


# ========================================================
# 3. DYNAMIC SANDBOX & PCAP TELEMETRY ENGINE
# ========================================================

def test_sandbox_tools_detector():
    tools = sandbox_detector.detect_all_tools()
    assert len(tools) >= 6
    tool_names = {t.tool_name for t in tools}
    assert "CAPE Sandbox" in tool_names
    assert "FakeNet-NG" in tool_names
    assert "INetSim" in tool_names
    assert "Wireshark/tshark" in tool_names
    assert "Zeek" in tool_names
    assert "Suricata" in tool_names

    for t in tools:
        assert t.status in ("INSTALLED", "NOT_CONFIGURED", "UNAVAILABLE")


def _create_synthetic_pcap_bytes() -> bytes:
    """Creates a minimal valid synthetic PCAP stream with 1 DNS packet and 1 TCP packet."""
    buf = io.BytesIO()
    # PCAP Global Header: magic 0xa1b2c3d4, version 2.4, thiszone 0, sigfigs 0, snaplen 65535, network 1 (Ethernet)
    buf.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

    # Packet 1: Ethernet + IPv4 (192.168.1.100 -> 8.8.8.8) + UDP + DNS query for 'evil-domain.com'
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip_header = bytes([
        0x45, 0x00, 0x00, 0x38,  # version/IHL, diffserv, total length 56
        0x12, 0x34, 0x00, 0x00,  # id, flags
        0x40, 0x11, 0x00, 0x00,  # TTL 64, protocol 17 (UDP), checksum 0
        192, 168, 1, 100,        # src IP
        8, 8, 8, 8               # dst IP
    ])
    udp_header = struct.pack("!HHHH", 53535, 53, 28, 0)
    dns_payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0bevil-domain\x03com\x00\x00\x01\x00\x01"
    packet_data = eth + ip_header + udp_header + dns_payload

    buf.write(struct.pack("<IIII", 1600000000, 0, len(packet_data), len(packet_data)))
    buf.write(packet_data)
    return buf.getvalue()


def test_pure_python_pcap_parsing():
    pcap_bytes = _create_synthetic_pcap_bytes()

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(pcap_bytes)
        temp_pcap_path = Path(f.name)

    try:
        flows, events, meta = pcap_telemetry_engine.analyze_pcap(
            file_path=temp_pcap_path,
            investigation_id="INV-PCAP-TEST",
            run_id="RUN-PCAP-001",
            is_simulated=True
        )

        assert meta["total_packets"] >= 1
        assert meta["pcap_sha256"] is not None
        assert len(flows) >= 1

        flow = flows[0]
        assert flow.src_ip == "192.168.1.100"
        assert flow.dst_ip == "8.8.8.8"
        assert flow.protocol == "UDP"
        assert flow.is_simulated is True
        assert flow.packet_reference == "Packet #1"
    finally:
        if temp_pcap_path.exists():
            temp_pcap_path.unlink()


# ========================================================
# 4. STATIC-DYNAMIC CORRELATION & RISK ENGINE
# ========================================================

def test_static_dynamic_correlation():
    correlator = StaticDynamicCorrelator()

    inv_id = "INV-CORR-TEST"
    detail = UniversalInvestigationDetail(
        record=InvestigationRecord(
            id=inv_id,
            filename="trojan_sample.exe",
            original_size=512000,
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            file_type="exe",
            local_only_mode=False,
            status="completed",
            progress=100,
            current_stage="Done",
            created_at=datetime.utcnow(),
            total_findings=3,
            severity="High",
            confidence="High",
            c2_count=1,
            secret_count=0,
            reverse_shell_detected=False
        ),
        osint_indicators=[
            OSINTIndicator(
                id="IND-001",
                investigation_id=inv_id,
                indicator_type="domain",
                value="evil-c2.com",
                normalized_value="evil-c2.com",
                provenance_type="Direct Evidence",
                extractor_or_provider="PE Strings Extractor",
                confidence="High",
                pivot_depth=0,
                first_seen_utc=datetime.utcnow().isoformat(),
                last_updated_utc=datetime.utcnow().isoformat(),
                is_sensitive_secret=False
            )
        ]
    )

    run = DynamicSandboxRun(
        id="RUN-001",
        investigation_id=inv_id,
        evidence_id="EV-01",
        target_binary="trojan_sample.exe",
        sandbox_environment="FakeNet-NG Network Simulator",
        status="completed",
        started_at_utc=datetime.utcnow().isoformat(),
        completed_at_utc=datetime.utcnow().isoformat(),
        is_simulated_network=True,
        limitations="Simulated traffic only"
    )
    repo.create_sandbox_run(run)

    ev = DynamicTelemetryEvent(
        id="EV-DNS-001",
        run_id="RUN-001",
        investigation_id=inv_id,
        event_category="DNS_QUERY",
        timestamp_utc=datetime.utcnow().isoformat(),
        operation="DNS_QUERY",
        details={"query_domain": "evil-c2.com", "resolved_ip": "198.51.100.22"},
        is_simulated=True
    )
    repo.add_telemetry_event(ev)

    correlations = correlator.correlate_investigation(detail)
    assert len(correlations) >= 1

    c = correlations[0]
    assert c.indicator_value == "evil-c2.com"
    assert c.correlation_method == "DOMAIN_MATCH_IN_DYNAMIC_DNS"
    assert "evil-c2.com" in c.supporting_event_summary
    assert c.is_simulated_event is True
    assert len(c.alternative_explanation) > 0
    assert len(c.limitations) > 0


def test_evidence_backed_risk_assessment():
    assessor = EvidenceRiskAssessor()
    inv_id = "INV-RISK-TEST"

    detail = UniversalInvestigationDetail(
        record=InvestigationRecord(
            id=inv_id,
            filename="reverse_tcp_payload.exe",
            original_size=245000,
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            file_type="exe",
            local_only_mode=False,
            status="completed",
            progress=100,
            current_stage="Done",
            created_at=datetime.utcnow(),
            total_findings=5,
            severity="Critical",
            confidence="High",
            c2_count=2,
            secret_count=1,
            reverse_shell_detected=True
        ),
        reverse_shell_findings=[
            ReverseShellFinding(
                id="REV-01",
                pattern_type="cmd_socket_duplication",
                title="Interactive Cmd.exe Reverse Shell",
                severity="Critical",
                confidence="High",
                code_references=["sub_401200"],
                execution_chain=["CreateProcessW(cmd.exe)", "WSASocketW"],
                explanation="Binds command shell to socket",
                limitations="Static signature match"
            )
        ],
        c2_indicators=[
            C2Indicator(
                id="C2-01",
                indicator_type="domain",
                value="command.darknet.org",
                normalized_value="command.darknet.org",
                source_file="trojan.exe",
                classification="potential_c2",
                why_suspicious="Hardcoded C2 channel",
                confidence="High",
                threat_intel_status="clean",
                recommended_validation="Active scope verification"
            )
        ]
    )

    assessment = assessor.assess_investigation(detail)
    assert assessment.overall_risk_score > 0.0
    assert assessment.static_capability_score >= 4.0
    assert assessment.severity in ("Informational", "Low", "Medium", "High", "Critical")
    assert len(assessment.score_inputs) >= 1
    assert "Evidence-Corroborated Dimensional Scoring" in assessment.weighting_method


# ========================================================
# 5. FORENSIC REPORT GENERATOR & CSV EXPORTS
# ========================================================

def test_report_generator_with_flows_and_correlations():
    inv_id = "INV-RPT-TEST"
    detail = UniversalInvestigationDetail(
        record=InvestigationRecord(
            id=inv_id,
            filename="malware_package.apk",
            original_size=1024000,
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            file_type="apk",
            local_only_mode=False,
            status="completed",
            progress=100,
            current_stage="Done",
            created_at=datetime.utcnow(),
            total_findings=4,
            severity="High",
            confidence="High",
            c2_count=1,
            secret_count=0,
            reverse_shell_detected=False
        ),
        network_flows=[
            NetworkFlowRecord(
                id="FLOW-01",
                run_id="RUN-01",
                investigation_id=inv_id,
                timestamp_utc=datetime.utcnow().isoformat(),
                src_ip="10.0.2.15",
                src_port=44321,
                dst_ip="198.51.100.10",
                dst_port=443,
                protocol="TLS",
                direction="OUTBOUND",
                tls_sni="api.telemetry-beacon.org",
                packet_count=15,
                byte_count=4200,
                packet_reference="Packet #14",
                is_simulated=True,
                related_indicator_ids=[]
            )
        ]
    )

    # 1. Master Text Report
    txt_report = generate_master_txt_report(detail)
    assert "SECTION 14: NETWORK CAPTURE (PCAP/PCAPNG) & FLOW TELEMETRY" in txt_report
    assert "SECTION 17B: AUTHORIZED ACTIVE NETWORK VALIDATION" in txt_report
    assert "SECTION 17C: ISOLATED DYNAMIC SANDBOX EXECUTION LEDGER" in txt_report
    assert "SECTION 18B: STATIC-VERSUS-DYNAMIC FINDING CORRELATION" in txt_report
    assert "SECTION 22: MULTI-DIMENSIONAL EVIDENCE-BACKED RISK ASSESSMENT" in txt_report
    assert "api.telemetry-beacon.org" in txt_report

    # 2. Flows CSV Export
    flows_csv = export_network_flows_csv(detail.network_flows)
    assert "Flow ID,Run ID,Timestamp UTC" in flows_csv
    assert "api.telemetry-beacon.org" in flows_csv
    assert "True" in flows_csv or "SIMULATED" in flows_csv or "1" in flows_csv

    # 3. Active Validations CSV Export
    val_csv = export_active_validation_csv(detail.active_validation_results)
    assert "Validation ID,Scope ID,Target" in val_csv

    # 4. Correlations CSV Export
    corr_csv = export_static_dynamic_correlations_csv(detail.static_dynamic_correlations)
    assert "Correlation ID,Static Finding ID" in corr_csv
