import pytest
from pathlib import Path
from backend.app.core.storage import workspace_mgr
from backend.app.database.repository import repo
from backend.app.core.orchestrator import run_investigation_pipeline
from backend.app.reporting.txt_generator import generate_txt_forensic_report
from backend.app.core.models import InvestigationRecord
from tests.create_fixtures import create_harmless_test_apk

def test_full_pipeline_execution(tmp_path):
    apk_file = tmp_path / "forensic_sample.apk"
    create_harmless_test_apk(apk_file)
    
    inv_id = "INV-E2E-TEST-001"
    staged = workspace_mgr.stage_apk(inv_id, apk_file, "forensic_sample.apk")
    
    record = InvestigationRecord(
        id=inv_id,
        filename="forensic_sample.apk",
        original_size=staged["size"],
        md5=staged["hashes"]["md5"],
        sha1=staged["hashes"]["sha1"],
        sha256=staged["hashes"]["sha256"],
        local_only_mode=True,
        case_reference="CASE-E2E-AUTOMATED",
        investigator_name="Automated Test Runner",
        status="pending",
        progress=0,
        current_stage="Staged"
    )
    repo.create_investigation(record)
    
    # Run pipeline synchronously
    run_investigation_pipeline(inv_id)
    
    # Verify final completed state in database
    completed_rec = repo.get_investigation(inv_id)
    assert completed_rec is not None
    assert completed_rec.status == "completed"
    assert completed_rec.progress == 100
    assert completed_rec.package_name == "org.forensics.testapp"
    assert completed_rec.c2_count > 0
    assert completed_rec.secret_count > 0
    assert completed_rec.reverse_shell_detected is True
    assert completed_rec.severity in ("High", "Critical")
    
    # Verify full detail record
    detail = repo.get_investigation_detail(inv_id)
    assert detail is not None
    assert len(detail.static_findings) > 0
    assert len(detail.c2_indicators) > 0
    assert len(detail.secrets) > 0
    assert len(detail.reverse_shell_findings) > 0
    assert detail.assessment is not None
    assert detail.assessment.risk_score > 50
    
    # Verify generated TXT report exists on disk and has 14 sections
    reports_dir = workspace_mgr.get_investigation_dir(inv_id) / "reports"
    report_files = sorted(reports_dir.glob("*.txt"), key=lambda f: f.stat().st_mtime)
    assert len(report_files) >= 1
    
    report_content = report_files[-1].read_text(encoding="utf-8")
    for sec_num in range(1, 15):
        assert f"SECTION {sec_num} --" in report_content
        
    assert "org.forensics.testapp" in report_content
    assert completed_rec.sha256 in report_content
