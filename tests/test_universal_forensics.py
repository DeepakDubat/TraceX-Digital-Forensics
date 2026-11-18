import io
import os
import zipfile
import struct
import tempfile
from pathlib import Path
from datetime import datetime
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database.repository import repo
from backend.app.analyzers.universal.file_identifier import (
    identify_file_format,
    calculate_streaming_hashes,
    calculate_shannon_entropy
)
from backend.app.analyzers.universal.archive_analyzer import analyze_archive_evidence
from backend.app.analyzers.universal.pdf_analyzer import analyze_pdf_evidence
from backend.app.analyzers.universal.image_analyzer import analyze_image_evidence
from backend.app.analyzers.universal.email_analyzer import analyze_email_evidence
from backend.app.analyzers.universal.network_analyzer import analyze_pcap_evidence
from backend.app.analyzers.universal.text_config_analyzer import analyze_text_evidence
from backend.app.analyzers.universal.correlation_engine import correlate_investigation_evidence
from backend.app.analyzers.universal.timeline_engine import build_investigation_timeline
from backend.app.analyzers.universal.integrity_ledger import record_custody_event, verify_ledger_integrity
from backend.app.reporting.master_report_generator import (
    generate_master_txt_report,
    generate_master_html_report,
    export_evidence_inventory_csv,
    export_findings_csv,
    export_reproducibility_bundle_zip
)
from backend.app.core.models import (
    EvidenceItem, FindingRecord, ExtractedArtifact,
    UniversalInvestigationDetail, InvestigationRecord
)

client = TestClient(app)

def test_file_identification_independent_of_extension():
    # PDF with masqueraded .txt extension
    pdf_content = b"%PDF-1.7\n%Fake PDF content for signature testing\n%%EOF"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(pdf_content)
        temp_pdf = f.name
    try:
        res = identify_file_format(Path(temp_pdf), "suspicious_document.txt")
        assert res["detected_format"] == "pdf"
        assert res["format_mismatch"] is True
        assert res["mime_type"] == "application/pdf"
    finally:
        if os.path.exists(temp_pdf):
            os.remove(temp_pdf)

    # PNG with masqueraded .bin extension
    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + (b"\x00" * 40)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(png_header)
        temp_png = f.name
    try:
        res_png = identify_file_format(Path(temp_png), "malware.bin")
        assert res_png["detected_format"] == "png"
        assert res_png["format_mismatch"] is True
    finally:
        if os.path.exists(temp_png):
            os.remove(temp_png)

    # Empty file detection
    with tempfile.NamedTemporaryFile(delete=False) as f:
        temp_empty = f.name
    try:
        res_empty = identify_file_format(Path(temp_empty), "empty.dat")
        assert res_empty["detected_format"] == "empty"
    finally:
        if os.path.exists(temp_empty):
            os.remove(temp_empty)

def test_streaming_hashes_and_entropy():
    sample_data = b"Antigravity Universal Digital Forensics Platform Verification Byte Stream"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(sample_data)
        temp_path = f.name
    try:
        hashes = calculate_streaming_hashes(Path(temp_path))
        entropy, assessment = calculate_shannon_entropy(Path(temp_path))
        assert len(hashes["sha256"]) == 64
        assert len(hashes["sha512"]) == 128
        assert len(hashes["md5"]) == 32
        assert len(hashes["sha1"]) == 40
        assert entropy > 0.0
        assert isinstance(assessment, str)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def test_archive_analyzer_zip_slip_protection():
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("safe_file.txt", "Forensic analysis contents")
        # Attempted directory traversal (Zip-Slip)
        zf.writestr("../../../../../etc/passwd", "root:x:0:0:")
    zip_bytes = zip_buffer.getvalue()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as zf_file:
        zf_file.write(zip_bytes)
        zip_path = zf_file.name

    with tempfile.TemporaryDirectory() as out_dir:
        try:
            meta, artifacts, findings, child_items = analyze_archive_evidence(
                Path(zip_path), "EVD-TEST-ARCH", "CASE-TEST", Path(out_dir)
            )
            assert meta["archive_type"] == "ZIP"
            slip_finding = next((f for f in findings if "Zip-Slip" in f.title), None)
            assert slip_finding is not None
            assert slip_finding.severity in ("Critical", "High")
            # Verify no parent directory escaping
            for item in os.listdir(out_dir):
                assert not item.startswith("..")
        finally:
            if os.path.exists(zip_path):
                os.remove(zip_path)

def test_pdf_analyzer_structural_inspection():
    pdf_bytes = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >> endobj\n"
        b"4 0 obj << /Type /Action /S /Launch /F (cmd.exe) >> endobj\n"
        b"5 0 obj << /Type /Action /S /JavaScript /JS (app.alert('malicious');) >> endobj\n"
        b"xref\n0 6\n0000000000 65535 f \n"
        b"trailer << /Size 6 /Root 1 0 R >>\nstartxref\n180\n%%EOF"
    )
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as f:
        f.write(pdf_bytes)
        pdf_path = f.name
    try:
        meta, artifacts, findings = analyze_pdf_evidence(Path(pdf_path), "EVD-PDF-001", "CASE-TEST")
        launch_finding = next((f for f in findings if "Launch" in f.title), None)
        assert launch_finding is not None
        assert launch_finding.severity in ("Critical", "High")
    finally:
        if os.path.exists(pdf_path):
            os.remove(pdf_path)

def test_image_analyzer_perceptual_hash():
    from PIL import Image
    img = Image.new("RGB", (64, 64), color=(73, 109, 137))
    img_io = io.BytesIO()
    img.save(img_io, format="PNG")
    img_bytes = img_io.getvalue()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as f:
        f.write(img_bytes)
        img_path = f.name
    try:
        meta, artifacts, findings = analyze_image_evidence(Path(img_path), "EVD-IMG-001", "CASE-TEST")
        assert meta["format"] == "image"
        assert meta["width"] == 64
        assert meta["height"] == 64
        assert len(meta["dhash"]) > 0
    finally:
        if os.path.exists(img_path):
            os.remove(img_path)

def test_network_pcap_analyzer():
    pcap_hdr = struct.pack("=IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 36, 1, 0, 64, 17, 0, b"\xc0\xa8\x01\x32", b"\x08\x08\x08\x08")
    dns = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04evil\x03com\x00\x00\x01\x00\x01"
    udp = struct.pack("!HHHH", 53535, 53, 8 + len(dns), 0) + dns
    pkt_data = eth + ip + udp
    pkt_hdr = struct.pack("=IIII", 1600000000, 0, len(pkt_data), len(pkt_data))
    full_pcap = pcap_hdr + pkt_hdr + pkt_data

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as f:
        f.write(full_pcap)
        pcap_path = f.name
    try:
        meta, artifacts, findings = analyze_pcap_evidence(Path(pcap_path), "EVD-PCAP-001", "CASE-TEST")
        assert meta["total_packets"] == 1
        assert "192.168.1.50" in meta["unique_ips"]
        assert "8.8.8.8" in meta["unique_ips"]
        assert "evil.com" in meta["dns_queries"]
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)

def test_text_and_secret_redaction():
    text_content = (
        "Configuration file\n"
        "DATABASE_URL=postgres://admin:topsecret@db.internal:5432/main\n"
        "C2_SERVER=https://command.darkdomain.ru/beacon\n"
        "GOOGLE_API_KEY=AIzaSyD-1234567890abcdef1234567890abcde\n"
    )
    with tempfile.NamedTemporaryFile(delete=False, suffix=".env") as f:
        f.write(text_content.encode("utf-8"))
        text_path = f.name
    try:
        meta, artifacts, findings = analyze_text_evidence(Path(text_path), "EVD-TXT-001", "CASE-TEST", "txt")
        extracted_vals = [a.value for a in artifacts]
        assert any("command.darkdomain.ru" in v for v in extracted_vals)
        secret_finding = next((f for f in findings if "Credential" in f.title or "API Key" in f.title or "Secret" in f.title), None)
        assert secret_finding is not None
        # Verify that raw secret is redacted
        assert "AIzaSyD-1234567890abcdef1234567890abcde" not in secret_finding.description
    finally:
        if os.path.exists(text_path):
            os.remove(text_path)

def test_cross_file_correlation_engine():
    evd1 = EvidenceItem(
        id="EVD-001",
        investigation_id="CASE-1",
        filename="payload.exe",
        file_size=1024,
        sha256="aabbccddeeff11223344556677889900aabbccddeeff11223344556677889900",
        sha512="d"*128,
        detected_format="pe"
    )
    evd2 = EvidenceItem(
        id="EVD-002",
        investigation_id="CASE-1",
        filename="copy_of_payload.exe",
        file_size=1024,
        sha256="aabbccddeeff11223344556677889900aabbccddeeff11223344556677889900",
        sha512="d"*128,
        detected_format="pe"
    )

    art1 = ExtractedArtifact(
        id="ART-1",
        investigation_id="CASE-1",
        evidence_id="EVD-001",
        artifact_type="ip_endpoint",
        value="198.51.100.23",
        source_format="pe",
        extractor_name="PE Header Analyzer"
    )
    art2 = ExtractedArtifact(
        id="ART-2",
        investigation_id="CASE-1",
        evidence_id="EVD-002",
        artifact_type="ip_endpoint",
        value="198.51.100.23",
        source_format="pe",
        extractor_name="PE Header Analyzer"
    )

    rels = correlate_investigation_evidence("CASE-1", [evd1, evd2], [art1, art2])
    rel_types = [r.relationship_type for r in rels]
    assert "EXACT_HASH_MATCH" in rel_types
    assert "SHARED_IP" in rel_types

def test_timeline_engine_contradiction_detection():
    evd = EvidenceItem(
        id="EVD-001",
        investigation_id="CASE-1",
        filename="suspicious.exe",
        file_size=2048,
        sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        sha512="d"*128,
        detected_format="exe",
        metadata={"compilation_timestamp": "2035-12-31T23:59:59"}
    )
    events, contradictions = build_investigation_timeline("CASE-1", [evd])
    assert len(events) >= 1
    future_contra = next((c for c in contradictions if "Future" in c.title or "Timestamp" in c.category), None)
    assert future_contra is not None
    assert "future" in future_contra.details.lower()

def test_chain_of_custody_cryptographic_chain():
    import uuid
    case_id = f"CASE-INTEGRITY-{uuid.uuid4().hex[:8]}"
    rec = InvestigationRecord(
        id=case_id,
        filename="test_evidence.bin",
        original_size=512,
        md5="0"*32,
        sha1="0"*40,
        sha256="0"*64,
        status="pending",
        progress=0,
        current_stage="Testing",
        file_type="generic"
    )
    repo.create_investigation(rec)

    evd_id = "EVD-001"
    evd = EvidenceItem(
        id=evd_id,
        investigation_id=case_id,
        filename="test_evidence.bin",
        file_size=512,
        sha256="0"*64,
        sha512="0"*128,
        detected_format="generic"
    )
    repo.create_evidence_item(evd)

    ev1 = record_custody_event(case_id, "EVIDENCE_INTAKE", "Lead Examiner", evd_id)
    ev2 = record_custody_event(case_id, "HASH_VERIFICATION", "Lead Examiner", evd_id)
    ev3 = record_custody_event(case_id, "REPORT_GENERATED", "Lead Examiner", evd_id)

    audit = verify_ledger_integrity(case_id)
    assert audit["valid"] is True
    assert audit["event_count"] >= 3

def test_31_section_master_report_generation():
    evd = EvidenceItem(
        id="EVD-REP-001",
        investigation_id="CASE-REP",
        filename="sample_evidence.pdf",
        file_size=4096,
        sha256="44556677889900aabbccddeeff11223344556677889900aabbccddeeff112233",
        sha512="a"*128,
        detected_format="pdf"
    )
    finding = FindingRecord(
        id="FND-001",
        investigation_id="CASE-REP",
        evidence_id="EVD-REP-001",
        title="PDF OpenAction Detected",
        description="PDF catalog defines an automatic launch action",
        observation="Observed OpenAction token in document catalog",
        interpretation="Executable action executes automatically on document open",
        severity="High",
        confidence="High",
        analysis_method="Static PDF Parser",
        analyzer_name="pdf_analyzer",
        analyzer_version="1.0.0"
    )
    rec = InvestigationRecord(
        id="CASE-REP",
        filename="sample_evidence.pdf",
        original_size=4096,
        md5="d"*32,
        sha1="e"*40,
        sha256="44556677889900aabbccddeeff11223344556677889900aabbccddeeff112233",
        case_reference="REF-2026-99",
        investigator_name="Specialist Forensic Examiner",
        local_only_mode=True,
        status="completed",
        progress=100,
        current_stage="Completed",
        created_at="2026-10-21T12:00:00Z",
        total_findings=1,
        severity="High",
        confidence="High",
        c2_count=0,
        secret_count=0,
        reverse_shell_detected=False,
        file_type="generic"
    )
    detail = UniversalInvestigationDetail(
        record=rec,
        evidence_items=[evd],
        extracted_artifacts=[],
        findings_register=[finding],
        evidence_relationships=[],
        timeline_events=[],
        chain_of_custody=[],
        coverage_matrix=[],
        contradictions=[]
    )

    txt_rep = generate_master_txt_report(detail)
    html_rep = generate_master_html_report(detail)
    csv_evd = export_evidence_inventory_csv([evd])
    csv_fnd = export_findings_csv([finding])
    bundle_zip = export_reproducibility_bundle_zip(detail)

    assert "UNIVERSAL DIGITAL FORENSICS & EVIDENCE INTELLIGENCE MASTER REPORT" in txt_rep
    assert "SECTION 31: FINAL ASSESSMENT & EXAMINER ATTESTATION" in txt_rep
    assert len(html_rep) > 1000
    assert "EVD-REP-001" in csv_evd
    assert "FND-001" in csv_fnd
    assert len(bundle_zip) > 200

def test_risk_assessor_double_counting_prevention():
    from backend.app.analyzers.universal.evidence_risk_assessor import EvidenceRiskAssessor
    from backend.app.core.models import (
        UniversalInvestigationDetail, InvestigationRecord, C2Indicator, SecretFinding, StaticFinding
    )
    assessor = EvidenceRiskAssessor()
    
    rec = InvestigationRecord(
        id="TEST-INV-RISK-01",
        case_reference="CASE-RISK",
        filename="sample.apk",
        file_type="apk",
        original_size=1024,
        md5="0"*32,
        sha1="0"*40,
        sha256="0"*64,
        status="completed",
        created_at=datetime.utcnow()
    )
    
    try:
        repo.create_investigation(rec)
        detail = UniversalInvestigationDetail(
            record=rec,
            c2_indicators=[
                C2Indicator(
                    id="C2-1", indicator_type="url", value="http://c2.test/gate",
                    normalized_value="http://c2.test/gate", classification="potential_c2",
                    source_file="classes.dex", why_suspicious="Suspicious C2 gate", confidence="High",
                    recommended_validation="Observe network"
                )
            ],
            secrets=[
                SecretFinding(
                    id="SEC-1", token_category="api_key", rule_matched="API Key",
                    redacted_value="ak••••••••1234", source_location="classes.dex",
                    confidence="High", in_network_path=False
                )
            ],
            static_findings=[
                # Category 'c2_channel' - already scored under c2_indicators
                StaticFinding(id="F-1", category="c2_channel", title="Covert C2", severity="High", confidence="High", description="C2 channel"),
                # Category 'credentials' - already scored under secrets
                StaticFinding(id="F-2", category="credentials", title="API Key", severity="High", confidence="High", description="API Key"),
                # Category 'telephony' - independent finding
                StaticFinding(id="F-3", category="telephony", title="SMS Dispatch", severity="High", confidence="High", description="SMS send")
            ]
        )
        
        assessment = assessor.assess_investigation(detail)
        # static_cap = 0.8 (c2) + 0.5 (secret) + 0.6 (1 independent high finding, NOT 3) = 1.9
        assert assessment.static_capability_score == pytest.approx(1.9, 0.05)
        # Verify score inputs note only 1 independent static code pattern
        assert any("independent static code patterns (1 findings)" in inp for inp in assessment.score_inputs)
    finally:
        from backend.app.database.db import get_db_connection
        conn = get_db_connection()
        conn.execute("DELETE FROM investigations WHERE id = ?", (rec.id,))
        conn.execute("DELETE FROM evidence_risk_assessments WHERE investigation_id = ?", (rec.id,))
        conn.commit()
        conn.close()

def test_universal_api_routes():
    # Test uploading via universal multi-evidence intake endpoint
    file_bytes = b"Universal Forensic Evidence Content for Test"
    files = [
        ("files", ("evidence_sample.txt", file_bytes, "text/plain"))
    ]
    data = {
        "case_reference": "CASE-API-2026",
        "investigator_name": "Lead Forensic Examiner",
        "analyst_notes": "Testing multi-file universal endpoints",
        "local_only_mode": "true"
    }
    res = client.post("/api/universal/investigations/upload", files=files, data=data)
    assert res.status_code == 200
    resp_data = res.json()
    assert resp_data["status"] == "success"
    case_id = resp_data["investigation_id"]

    # Verify detail retrieval
    detail_res = client.get(f"/api/universal/investigations/{case_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["record"]["id"] == case_id
    assert detail["record"]["case_reference"] == "CASE-API-2026"
    assert len(detail["evidence_items"]) >= 1

    # Test cross-case duplicate search endpoint
    search_res = client.get("/api/universal/cross-case-search?query=CASE-API")
    assert search_res.status_code == 200
    search_json = search_res.json()
    assert "exact_matches" in search_json
    assert "total_matches" in search_json
