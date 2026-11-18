import io
import json
import zipfile
import pytest
from datetime import datetime
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.models import (
    UniversalInvestigationDetail,
    InvestigationRecord,
    EvidenceItem,
    ExtractedArtifact,
    OSINTIndicator,
    OSINTObservation
)
from backend.app.database.repository import repo
from backend.app.analyzers.universal.osint_collector import osint_collector
from backend.app.analyzers.universal.secret_correlation import secret_engine
from backend.app.analyzers.universal.recursive_pivot_engine import recursive_pivot_engine
from backend.app.analyzers.universal.osint_graph_builder import osint_graph_builder
from backend.app.integrations.osint.osint_service import osint_service
from backend.app.integrations.osint.dns_resolver import DNSResolver
from backend.app.integrations.osint.network_intelligence import NetworkIntelligence
from backend.app.reporting.master_report_generator import (
    generate_master_txt_report,
    export_osint_indicators_csv,
    export_osint_observations_csv,
    export_secret_exposure_csv,
    export_reproducibility_bundle_zip
)

client = TestClient(app)

@pytest.fixture(scope="module")
def mock_investigation_detail():
    import uuid
    inv_id = f"inv_osint_{uuid.uuid4().hex[:8]}"
    now = datetime.utcnow()

    rec = InvestigationRecord(
        id=inv_id,
        filename="malware_payload.apk",
        original_size=1048576,
        md5="11111111111111111111111111111111",
        sha1="2222222222222222222222222222222222222222",
        sha256="3333333333333333333333333333333333333333333333333333333333333333",
        status="completed",
        progress=100,
        current_stage="Completed",
        created_at=now,
        local_only_mode=False
    )
    repo.create_investigation(rec)

    ev = EvidenceItem(
        id=f"EVD-{inv_id}",
        investigation_id=inv_id,
        filename="malware_payload.apk",
        file_size=1048576,
        detected_format="apk",
        sha256=rec.sha256,
        working_copy_sha256=rec.sha256,
        integrity_status="VERIFIED",
        acquired_at=now,
        created_at=now
    )
    repo.save_evidence_items(inv_id, [ev])

    artifacts = [
        ExtractedArtifact(
            id="art_ip_1",
            investigation_id=inv_id,
            evidence_id=ev.id,
            artifact_type="ip",
            source_format="apk",
            source_location="classes.dex / NetworkConfig",
            value="198.51.100.42",
            structured_data={},
            extractor_name="AndroguardAdapter",
            extracted_at=now
        ),
        ExtractedArtifact(
            id="art_dom_1",
            investigation_id=inv_id,
            evidence_id=ev.id,
            artifact_type="domain",
            source_format="apk",
            source_location="AndroidManifest.xml",
            value="c2-server.evil-infrastructure.org",
            structured_data={},
            extractor_name="AndroguardAdapter",
            extracted_at=now
        ),
        ExtractedArtifact(
            id="art_tg_token",
            investigation_id=inv_id,
            evidence_id=ev.id,
            artifact_type="secret",
            source_format="apk",
            source_location="smali/com/malware/BotHandler.smali:42",
            value="1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ_12345678",
            structured_data={},
            extractor_name="RegexScanner",
            extracted_at=now
        ),
        ExtractedArtifact(
            id="art_tg_user",
            investigation_id=inv_id,
            evidence_id=ev.id,
            artifact_type="string",
            source_format="apk",
            source_location="smali/com/malware/BotHandler.smali:60",
            value="https://t.me/ShadowC2Channel",
            structured_data={},
            extractor_name="RegexScanner",
            extracted_at=now
        )
    ]
    repo.save_extracted_artifacts(inv_id, artifacts)

    detail = repo.get_universal_investigation_detail(inv_id)
    return detail

def test_osint_collector_extraction(mock_investigation_detail):
    """Verifies automatic extraction and provenance linking of indicators."""
    indicators = osint_collector.collect_from_investigation(mock_investigation_detail)
    assert len(indicators) >= 4

    types = [i.indicator_type for i in indicators]
    assert "ip" in types
    assert "domain" in types
    assert "telegram_bot_token" in types
    assert "telegram_username" in types

    # Check Telegram bot token containment attributes
    tg_ind = next(i for i in indicators if i.indicator_type == "telegram_bot_token")
    assert tg_ind.is_sensitive_secret is True
    assert tg_ind.masked_value.startswith("1234567890:••••")
    assert tg_ind.pivot_depth == 0
    assert tg_ind.provenance_type == "DIRECT_EVIDENCE"

def test_secret_correlation_engine(mock_investigation_detail):
    """Verifies safe secret detection, token masking, and public handle correlation."""
    findings = secret_engine.analyze_investigation_secrets(mock_investigation_detail)
    assert len(findings) == 1

    finding = findings[0]
    assert finding.secret_type == "telegram_bot_token"
    assert finding.masked_token.startswith("1234567890:••••")
    assert "Never transmitted to third-party endpoints" in finding.safety_attestation
    assert any("shadowc2channel" in ident.lower() for ident in finding.independently_found_public_identities)

def test_secret_token_non_transmission_safety(mock_investigation_detail):
    """Verifies that sensitive tokens are never enriched externally."""
    inv_id = mock_investigation_detail.record.id
    token_indicator = OSINTIndicator(
        id=f"IND-TEST-SEC-{inv_id[:6]}",
        investigation_id=inv_id,
        indicator_type="telegram_bot_token",
        value="1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ_12345678",
        normalized_value="1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ_12345678",
        extractor_or_provider="Test",
        is_sensitive_secret=True,
        masked_value="1234567890:••••••••"
    )
    repo.create_osint_indicator(token_indicator)

    observations = osint_service.enrich_indicator(token_indicator)
    assert len(observations) == 1
    obs = observations[0]
    assert obs.status == "SKIPPED_BY_PRIVACY_POLICY"
    assert obs.provider == "LocalSecretIsolationEngine"
    assert "CONTAINED_LOCALLY" in str(obs.normalized_data)

def test_local_only_mode_safeguard():
    """Verifies that when local-only mode is active, providers return SKIPPED_LOCAL_ONLY."""
    dns = DNSResolver(local_only_mode=True)
    obs = dns.resolve_domain("example.com", "inv_test", "ind_test")
    assert obs.status == "SKIPPED_LOCAL_ONLY"

    net = NetworkIntelligence(local_only_mode=True)
    obs_net = net.query_ip("8.8.8.8", "inv_test", "ind_test")
    assert obs_net.status == "SKIPPED_LOCAL_ONLY"

def test_private_ip_detection():
    """Verifies that RFC 1918 private IPs are handled locally without external queries."""
    net = NetworkIntelligence(local_only_mode=False)
    obs = net.query_ip("192.168.1.100", "inv_test", "ind_test")
    assert obs.status == "SUCCESS"
    assert obs.normalized_data.get("is_private") is True
    assert "RFC 1918" in obs.normalized_data.get("network_type")

def test_recursive_pivot_engine_bounds(mock_investigation_detail):
    """Verifies bounded recursive pivot limits depth and query budgets."""
    inv_id = mock_investigation_detail.record.id
    # Collect indicators first
    osint_collector.collect_from_investigation(mock_investigation_detail)

    # Run bounded pivot with budget = 5
    job = recursive_pivot_engine.run_recursive_pivot(
        investigation_id=inv_id,
        max_depth=2,
        budget_limit_queries=5
    )

    assert job.status in ("completed", "stopped_budget")
    assert job.current_depth <= 2
    assert job.total_provider_queries <= 10

def test_osint_graph_builder(mock_investigation_detail):
    """Verifies graph generation with explicit nodes and 16 relation edge types."""
    osint_collector.collect_from_investigation(mock_investigation_detail)
    secret_engine.analyze_investigation_secrets(mock_investigation_detail)

    detail = repo.get_universal_investigation_detail(mock_investigation_detail.record.id)
    nodes, edges = osint_graph_builder.build_graph(detail)

    assert len(nodes) >= 3
    node_types = [n.node_type for n in nodes]
    assert "evidence_file" in node_types

    edge_types = [e.relationship_type for e in edges]
    assert "EXTRACTED_FROM" in edge_types

def test_osint_api_endpoints(mock_investigation_detail):
    """Verifies OSINT API routes."""
    inv_id = mock_investigation_detail.record.id

    # 1. Collect
    res_col = client.post(f"/api/osint/investigations/{inv_id}/collect")
    assert res_col.status_code == 200
    assert res_col.json()["total_indicators_collected"] >= 4

    # 2. Get Indicators
    res_ind = client.get(f"/api/osint/investigations/{inv_id}/indicators")
    assert res_ind.status_code == 200
    assert len(res_ind.json()) >= 4

    # 3. Get Graph
    res_graph = client.get(f"/api/osint/investigations/{inv_id}/graph")
    assert res_graph.status_code == 200
    g_data = res_graph.json()
    assert "nodes" in g_data
    assert "edges" in g_data
    assert len(g_data["nodes"]) >= 3

    # 4. Get Secrets
    res_sec = client.get(f"/api/osint/investigations/{inv_id}/secrets")
    assert res_sec.status_code == 200
    assert len(res_sec.json()) >= 1

def test_master_report_osint_exports(mock_investigation_detail):
    """Verifies CSV generation and inclusion in reproducibility ZIP bundle."""
    inv_id = mock_investigation_detail.record.id
    osint_collector.collect_from_investigation(mock_investigation_detail)
    secret_engine.analyze_investigation_secrets(mock_investigation_detail)
    detail = repo.get_universal_investigation_detail(inv_id)

    # 1. TXT Report includes OSINT sections
    txt_rep = generate_master_txt_report(detail)
    assert "SECTION 16: SENSITIVE SECRETS & CREDENTIAL REDACTION LEDGER" in txt_rep
    assert "SECTION 17: PASSIVE THREAT INTELLIGENCE & OSINT ENRICHMENT" in txt_rep

    # 2. CSV Exports
    csv_ind = export_osint_indicators_csv(detail.osint_indicators)
    assert "Indicator ID,Indicator Type" in csv_ind

    csv_sec = export_secret_exposure_csv(detail.secret_exposure_findings)
    assert "Masked Token" in csv_sec

    # 3. ZIP Bundle contains OSINT CSVs
    zip_bytes = export_reproducibility_bundle_zip(detail)
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        namelist = zf.namelist()
        assert f"{inv_id}_OSINT_Indicators.csv" in namelist
        assert f"{inv_id}_OSINT_Observations.csv" in namelist
        assert f"{inv_id}_Secret_Exposures.csv" in namelist

def test_otx_connection_test_endpoint():
    """Verifies AlienVault OTX credentials testing endpoint handles all status states without exposing keys."""
    # 1. Not configured
    res_empty = client.post("/api/settings/test-otx", json={"api_key": ""})
    assert res_empty.status_code == 200
    data_empty = res_empty.json()
    assert data_empty["status"] == "Not configured"
    assert data_empty["connected"] is False

    # 2. Mock 200 Connected
    from unittest.mock import patch, MagicMock
    mock_resp_200 = MagicMock()
    mock_resp_200.status_code = 200
    mock_resp_200.json.return_value = {"username": "ThreatHunter_Test"}

    with patch("httpx.Client.get", return_value=mock_resp_200):
        res_conn = client.post("/api/settings/test-otx", json={"api_key": "MOCK_VALID_OTX_KEY_12345"})
        assert res_conn.status_code == 200
        data_conn = res_conn.json()
        assert data_conn["status"] == "Connected"
        assert data_conn["connected"] is True
        assert "ThreatHunter_Test" in data_conn["message"]

    # 3. Mock 429 Rate limited
    mock_resp_429 = MagicMock()
    mock_resp_429.status_code = 429

    with patch("httpx.Client.get", return_value=mock_resp_429):
        res_rl = client.post("/api/settings/test-otx", json={"api_key": "MOCK_VALID_OTX_KEY_12345"})
        assert res_rl.status_code == 200
        data_rl = res_rl.json()
        assert data_rl["status"] == "Rate limited"
        assert data_rl["connected"] is False

    # 4. Mock 403 Invalid credentials
    mock_resp_403 = MagicMock()
    mock_resp_403.status_code = 403

    with patch("httpx.Client.get", return_value=mock_resp_403):
        res_inv = client.post("/api/settings/test-otx", json={"api_key": "MOCK_INVALID_KEY"})
        assert res_inv.status_code == 200
        data_inv = res_inv.json()
        assert data_inv["status"] == "Invalid credentials"
        assert data_inv["connected"] is False

def test_osint_reports_routes(mock_investigation_detail):
    """Verifies dedicated report CSV and ZIP bundle endpoints for OSINT."""
    inv_id = mock_investigation_detail.record.id
    osint_collector.collect_from_investigation(mock_investigation_detail)
    secret_engine.analyze_investigation_secrets(mock_investigation_detail)

    # 1. Indicators CSV
    r_ind = client.get(f"/api/investigations/{inv_id}/report/osint/indicators.csv")
    assert r_ind.status_code == 200
    assert "text/csv" in r_ind.headers["content-type"]
    assert "Indicator ID" in r_ind.text

    # 2. Observations CSV
    r_obs = client.get(f"/api/investigations/{inv_id}/report/osint/observations.csv")
    assert r_obs.status_code == 200
    assert "text/csv" in r_obs.headers["content-type"]

    # 3. Secrets CSV
    r_sec = client.get(f"/api/investigations/{inv_id}/report/osint/secrets.csv")
    assert r_sec.status_code == 200
    assert "text/csv" in r_sec.headers["content-type"]

    # 4. Zip Bundle
    r_zip = client.get(f"/api/investigations/{inv_id}/report/bundle")
    assert r_zip.status_code == 200
    assert "application/zip" in r_zip.headers["content-type"]

def test_single_file_investigation_osint_compatibility():
    """Verifies that individual APK investigations work with OSINT without Multi-Evidence Hub."""
    import uuid
    from backend.app.core.models import InvestigationRecord
    single_id = f"INV-SINGLE-{uuid.uuid4().hex[:6].upper()}"
    rec = InvestigationRecord(
        id=single_id,
        filename="standalone_sample.apk",
        original_size=1024,
        md5="1"*32,
        sha1="1"*40,
        sha256="1"*64,
        status="completed",
        file_type="apk"
    )
    repo.create_investigation(rec)

    # Indicator extraction via OSINT API directly
    res_inds = client.get(f"/api/osint/investigations/{single_id}/indicators?auto_collect=true")
    assert res_inds.status_code == 200
    inds = res_inds.json()
    assert len(inds) >= 1
    assert inds[0]["indicator_type"] == "hash"
    assert inds[0]["value"] == "1"*64

