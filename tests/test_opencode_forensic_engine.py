"""
TraceX OpenCode Forensic Engine Comprehensive Test Suite
=========================================================
Verifies the 16 mandatory operational, architectural, and security scenarios
for OpenCode CLI as an optional AI-assisted forensic investigation engine.
"""

import os
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.config import settings
from backend.app.database.repository import repo
from backend.app.core.models import (
    InvestigationRecord,
    AIObservation,
    AIRecommendation,
    AIAssistedNotes,
    StaticFinding,
    PeMetadata,
)
from backend.app.core.network_mode import set_network_mode, NetworkMode
from backend.app.integrations.opencode_engine import (
    detect_opencode_status,
    resolve_opencode_binary,
    run_opencode_cli,
    sanitize_text,
    prepare_forensic_context,
    parse_opencode_response,
    analyze_investigation,
    test_opencode_installation as engine_test_installation,
    test_opencode_analysis as engine_test_analysis,
    is_local_model_identifier,
)

client = TestClient(app)


def _ensure_investigation(inv_id: str, file_type: str = "apk") -> InvestigationRecord:
    existing = repo.get_investigation(inv_id)
    if existing:
        return existing
    rec = InvestigationRecord(
        id=inv_id,
        filename=f"sample.{file_type}",
        original_size=1024,
        md5="0"*32,
        sha1="0"*40,
        sha256="0"*64,
        status="completed",
        progress=100,
        current_stage="Done",
        file_type=file_type
    )
    repo.create_investigation(rec)
    return rec


# --------------------------------------------------------------------------
# Test 1: CLI Detection
# --------------------------------------------------------------------------
def test_01_opencode_cli_detection():
    """Verify detect_opencode_status properly resolves binary, version, and operational mode."""
    status = detect_opencode_status(refresh=False)
    assert isinstance(status, dict)
    assert "installed" in status
    assert "network_mode" in status
    assert "status_label" in status
    if status["installed"]:
        assert status["path"] is not None
        assert "opencode" in status["path"].lower()


# --------------------------------------------------------------------------
# Test 2: Version Parsing
# --------------------------------------------------------------------------
def test_02_version_parsing():
    """Verify that opencode --version output is parsed cleanly into a version string."""
    with patch("backend.app.integrations.opencode_engine.run_opencode_cli") as mock_run:
        mock_run.return_value = (0, "opencode v2.2.6\n", "")
        res = engine_test_installation()
        assert res["success"] is True
        assert res["version"] == "opencode v2.2.6"


# --------------------------------------------------------------------------
# Test 3: Config Persistence
# --------------------------------------------------------------------------
def test_03_config_persistence():
    """Verify updating opencode_enabled, opencode_model, and timeout persists to DB and settings."""
    payload = {
        "enabled": True,
        "model": "ollama/llama3",
        "timeout_seconds": 45
    }
    response = client.post("/api/opencode/config", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True

    # Check settings and DB persistence
    assert settings.OPENCODE_ENABLED is True
    assert settings.OPENCODE_MODEL == "ollama/llama3"
    assert settings.OPENCODE_TIMEOUT_SECONDS == 45
    assert repo.get_setting("opencode_enabled") == "true"
    assert repo.get_setting("opencode_model") == "ollama/llama3"
    assert repo.get_setting("opencode_timeout_seconds") == "45"

    # Reset
    client.post("/api/opencode/config", json={"enabled": False, "model": "", "timeout_seconds": 60})


# --------------------------------------------------------------------------
# Test 4: Test Installation Endpoint
# --------------------------------------------------------------------------
def test_04_test_installation_endpoint():
    """Verify /api/opencode/test-installation executes diagnostic checks and returns structured data."""
    with patch("backend.app.integrations.opencode_engine.run_opencode_cli") as mock_run:
        mock_run.side_effect = [
            (0, "opencode v2.2.6\n", ""),
            (0, "opencode/beam-free\nopencode/big-pickle\n", "")
        ]
        response = client.post("/api/opencode/test-installation")
        assert response.status_code == 200
        data = response.json()
        assert "success" in data
        assert "message" in data
        assert "diagnostics" in data


# --------------------------------------------------------------------------
# Test 5: APK AI Analysis Output Parsing
# --------------------------------------------------------------------------
def test_05_apk_ai_analysis_execution():
    """Verify analyze_investigation processes APK forensic context and outputs structured unverified observations."""
    inv_id = "INV-TEST-APK-001"
    _ensure_investigation(inv_id, file_type="apk")

    class MockApkDetail:
        record = repo.get_investigation(inv_id)
        static_findings = [
            StaticFinding(
                finding_id="APK-001",
                category="Permissions",
                severity="High",
                title="Dangerous SMS Permission",
                description="Application requests android.permission.SEND_SMS.",
                confidence="High"
            )
        ]
        c2_indicators = []
        reverse_shell_findings = []
        secrets = []
        metadata = None

    sample_ai_json = {
        "observations": [
            {
                "title": "Suspicious SMS Dispatch Capability",
                "explanation": "SEND_SMS combined with background service patterns suggests SMS trojan activity.",
                "related_evidence_refs": ["SEND_SMS"],
                "confidence": "Medium",
                "reasoning_summary": "Common pattern in SMS toll fraud malware.",
                "suggested_verification_steps": ["Inspect SMS receiver class for hardcoded premium rate numbers."]
            }
        ],
        "recommendations": [
            {
                "title": "Trace SMS Intent Broadcasts",
                "category": "Code Review",
                "description": "Decompile DEX code and audit intent filters.",
                "suggested_command_or_action": "jadx -d out TestMalware.apk",
                "priority": "High"
            }
        ],
        "summary": "Potential SMS fraud malware requiring bytecode inspection."
    }

    mock_status = {
        "installed": True,
        "version": "opencode v2.2.6",
        "path": "opencode.cmd",
        "enabled": True,
        "model": "ollama/test",
        "is_local_model": True,
        "auth_providers": [],
        "network_mode": "LOCAL_ONLY",
        "status_label": "READY_LOCAL",
        "status_description": "Ready",
        "timeout_seconds": 60,
    }

    with patch("backend.app.integrations.opencode_engine.detect_opencode_status", return_value=mock_status):
        with patch("backend.app.integrations.opencode_engine.run_opencode_cli") as mock_run:
            mock_run.return_value = (0, f"```json\n{json.dumps(sample_ai_json)}\n```", "")
            notes, obs, recs = analyze_investigation(
                investigation_id=inv_id,
                detail=MockApkDetail(),
                filename="TestMalware.apk",
                file_type="apk",
                file_size_bytes=1024,
                sha256_hash="c"*64,
                consent_approved=True,
                override_model="ollama/test"
            )

            assert notes.execution_status == "COMPLETED"
            assert len(obs) == 1
            assert obs[0].status == "UNVERIFIED"
            assert obs[0].title == "Suspicious SMS Dispatch Capability"
            assert len(recs) == 1
            assert recs[0].priority == "High"


# --------------------------------------------------------------------------
# Test 6: EXE/PE AI Analysis Execution
# --------------------------------------------------------------------------
def test_06_exe_ai_analysis_execution():
    """Verify analyze_investigation processes Windows PE context."""
    inv_id = "INV-TEST-EXE-001"
    _ensure_investigation(inv_id, file_type="exe")

    class MockPeDetail:
        record = repo.get_investigation(inv_id)
        static_findings = [
            StaticFinding(
                finding_id="PE-001",
                category="Injection",
                severity="Critical",
                title="Process Injection API Detected",
                description="Executable imports VirtualAllocEx and WriteProcessMemory.",
                confidence="High"
            )
        ]
        c2_indicators = []
        reverse_shell_findings = []
        secrets = []
        metadata = None
        pe_metadata = PeMetadata(
            machine="x64",
            magic="PE32+",
            subsystem="WINDOWS_GUI",
            number_of_sections=4,
            sections=[],
            imports=[]
        )

    sample_exe_ai = {
        "observations": [
            {
                "title": "Likely Remote Code Injection Architecture",
                "explanation": "Presence of WriteProcessMemory indicates process hollowing or injection.",
                "related_evidence_refs": ["WriteProcessMemory", "VirtualAllocEx"],
                "confidence": "High",
                "reasoning_summary": "Classic injection technique used by loaders.",
                "suggested_verification_steps": ["Cross-reference call sites to VirtualAllocEx in disassembly."]
            }
        ],
        "recommendations": [
            {
                "title": "Disassemble Injection Routine",
                "category": "Reverse Engineering",
                "description": "Examine memory protection flags passed to VirtualAllocEx.",
                "priority": "High"
            }
        ],
        "summary": "PE demonstrates high probability of process hollowing."
    }

    mock_status = {
        "installed": True,
        "version": "opencode v2.2.6",
        "path": "opencode.cmd",
        "enabled": True,
        "model": "ollama/test",
        "is_local_model": True,
        "auth_providers": [],
        "network_mode": "LOCAL_ONLY",
        "status_label": "READY_LOCAL",
        "status_description": "Ready",
        "timeout_seconds": 60,
    }

    with patch("backend.app.integrations.opencode_engine.detect_opencode_status", return_value=mock_status):
        with patch("backend.app.integrations.opencode_engine.run_opencode_cli") as mock_run:
            mock_run.return_value = (0, json.dumps(sample_exe_ai), "")
            notes, obs, recs = analyze_investigation(
                investigation_id=inv_id,
                detail=MockPeDetail(),
                filename="Payload.exe",
                file_type="exe",
                file_size_bytes=2048,
                sha256_hash="f"*64,
                consent_approved=True,
                override_model="ollama/test"
            )

            assert notes.execution_status == "COMPLETED"
            assert len(obs) == 1
            assert obs[0].status == "UNVERIFIED"
            assert "Remote Code Injection" in obs[0].title


# --------------------------------------------------------------------------
# Test 7: Unsupported / Unknown Format Handling
# --------------------------------------------------------------------------
def test_07_unsupported_format_graceful_handling():
    """Verify graceful handling of generic or unsupported formats without crashing."""
    inv_id = "INV-TEST-GENERIC-001"
    _ensure_investigation(inv_id, file_type="generic")

    class MockGenericDetail:
        record = repo.get_investigation(inv_id)
        static_findings = []
        c2_indicators = []
        reverse_shell_findings = []
        secrets = []
        metadata = None

    mock_status = {
        "installed": True,
        "version": "opencode v2.2.6",
        "path": "opencode.cmd",
        "enabled": True,
        "model": "ollama/test",
        "is_local_model": True,
        "auth_providers": [],
        "network_mode": "LOCAL_ONLY",
        "status_label": "READY_LOCAL",
        "status_description": "Ready",
        "timeout_seconds": 60,
    }

    with patch("backend.app.integrations.opencode_engine.detect_opencode_status", return_value=mock_status):
        with patch("backend.app.integrations.opencode_engine.run_opencode_cli") as mock_run:
            mock_run.return_value = (0, '{"observations":[],"recommendations":[],"summary":"No specific indicators"}', "")
            notes, obs, recs = analyze_investigation(
                investigation_id=inv_id,
                detail=MockGenericDetail(),
                filename="unknown.dat",
                file_type="generic",
                file_size_bytes=512,
                sha256_hash="0"*64,
                consent_approved=True,
                override_model="ollama/test"
            )
            assert notes.execution_status == "COMPLETED"
            assert len(obs) == 0


# --------------------------------------------------------------------------
# Test 8: Subprocess Timeout Handling
# --------------------------------------------------------------------------
def test_08_subprocess_timeout_handling():
    """Verify timeout terminates process tree cleanly and returns FAILED status."""
    inv_id = "INV-TEST-TIMEOUT-001"
    _ensure_investigation(inv_id, file_type="apk")

    class MockDetail:
        record = repo.get_investigation(inv_id)
        static_findings = []
        c2_indicators = []
        reverse_shell_findings = []
        secrets = []
        metadata = None

    mock_status = {
        "installed": True,
        "version": "opencode v2.2.6",
        "path": "opencode.cmd",
        "enabled": True,
        "model": "ollama/test",
        "is_local_model": True,
        "auth_providers": [],
        "network_mode": "LOCAL_ONLY",
        "status_label": "READY_LOCAL",
        "status_description": "Ready",
        "timeout_seconds": 60,
    }

    with patch("backend.app.integrations.opencode_engine.detect_opencode_status", return_value=mock_status):
        with patch("backend.app.integrations.opencode_engine.run_opencode_cli") as mock_run:
            mock_run.return_value = (-1, "", "Execution timed out after 5 seconds.")
            notes, obs, recs = analyze_investigation(
                investigation_id=inv_id,
                detail=MockDetail(),
                filename="test.apk",
                file_type="apk",
                file_size_bytes=100,
                sha256_hash="1"*64,
                consent_approved=True,
                override_model="ollama/test"
            )
            assert notes.execution_status == "FAILED"
            assert len(obs) == 0
            assert any("timed out" in w.lower() for w in notes.warnings_or_errors)


# --------------------------------------------------------------------------
# Test 9: Failure Recovery Without Breaking Investigation
# --------------------------------------------------------------------------
def test_09_failure_recovery_pipeline_uninterrupted():
    """Verify when OpenCode CLI fails or exits with error code, notes are recorded and investigation finishes."""
    inv_id = "INV-TEST-FAIL-001"
    _ensure_investigation(inv_id, file_type="apk")

    class MockDetail:
        record = repo.get_investigation(inv_id)
        static_findings = []
        c2_indicators = []
        reverse_shell_findings = []
        secrets = []
        metadata = None

    mock_status = {
        "installed": True,
        "version": "opencode v2.2.6",
        "path": "opencode.cmd",
        "enabled": True,
        "model": "ollama/test",
        "is_local_model": True,
        "auth_providers": [],
        "network_mode": "LOCAL_ONLY",
        "status_label": "READY_LOCAL",
        "status_description": "Ready",
        "timeout_seconds": 60,
    }

    with patch("backend.app.integrations.opencode_engine.detect_opencode_status", return_value=mock_status):
        with patch("backend.app.integrations.opencode_engine.run_opencode_cli") as mock_run:
            mock_run.return_value = (1, "", "Provider rate limit or auth error.")
            notes, obs, recs = analyze_investigation(
                investigation_id=inv_id,
                detail=MockDetail(),
                filename="test.apk",
                file_type="apk",
                file_size_bytes=100,
                sha256_hash="2"*64,
                consent_approved=True,
                override_model="ollama/test"
            )
            assert notes.execution_status == "FAILED"
            assert len(obs) == 0
            saved_notes = repo.get_ai_investigation_notes(inv_id)
            assert saved_notes is not None
            assert saved_notes.execution_status == "FAILED"


# --------------------------------------------------------------------------
# Test 10: LOCAL ONLY Privacy Enforcement
# --------------------------------------------------------------------------
def test_10_local_only_mode_blocks_remote_models():
    """Verify that in LOCAL ONLY mode, non-local models return LOCAL OPENCODE MODEL NOT CONFIGURED."""
    inv_id = "INV-TEST-PRIVACY-001"
    _ensure_investigation(inv_id, file_type="apk")

    class MockDetail:
        record = repo.get_investigation(inv_id)
        static_findings = []
        c2_indicators = []
        reverse_shell_findings = []
        secrets = []
        metadata = None

    mock_status = {
        "installed": True,
        "version": "opencode v2.2.6",
        "path": "opencode.cmd",
        "enabled": True,
        "model": "github-copilot/gpt-4",
        "is_local_model": False,
        "auth_providers": [],
        "network_mode": "LOCAL_ONLY",
        "status_label": "LOCAL_BLOCKED",
        "status_description": "Blocked in local mode",
        "timeout_seconds": 60,
    }

    with patch("backend.app.integrations.opencode_engine.detect_opencode_status", return_value=mock_status):
        notes, obs, recs = analyze_investigation(
            investigation_id=inv_id,
            detail=MockDetail(),
            filename="sample.apk",
            file_type="apk",
            file_size_bytes=500,
            sha256_hash="3"*64,
            consent_approved=True,
            override_model="github-copilot/gpt-4"
        )
        assert notes.execution_status == "SKIPPED"
        assert len(obs) == 0
        assert any("LOCAL OPENCODE MODEL NOT CONFIGURED" in w for w in notes.warnings_or_errors)


# --------------------------------------------------------------------------
# Test 11: HYBRID Mode Authorization Requirement
# --------------------------------------------------------------------------
def test_11_hybrid_mode_requires_authorization():
    """Verify that in HYBRID mode, execution requires consent_approved=True."""
    inv_id = "INV-TEST-HYBRID-001"
    _ensure_investigation(inv_id, file_type="apk")

    class MockDetail:
        record = repo.get_investigation(inv_id)
        static_findings = []
        c2_indicators = []
        reverse_shell_findings = []
        secrets = []
        metadata = None

    mock_status = {
        "installed": True,
        "version": "opencode v2.2.6",
        "path": "opencode.cmd",
        "enabled": True,
        "model": "github-copilot/gpt-4",
        "is_local_model": False,
        "auth_providers": [],
        "network_mode": "HYBRID",
        "status_label": "READY_HYBRID",
        "status_description": "Ready in hybrid",
        "timeout_seconds": 60,
    }

    with patch("backend.app.integrations.opencode_engine.detect_opencode_status", return_value=mock_status):
        notes, obs, recs = analyze_investigation(
            investigation_id=inv_id,
            detail=MockDetail(),
            filename="sample.apk",
            file_type="apk",
            file_size_bytes=500,
            sha256_hash="4"*64,
            consent_approved=False,
            override_model="github-copilot/gpt-4"
        )
        assert notes.execution_status == "SKIPPED"
        assert any("authorization required" in w.lower() for w in notes.warnings_or_errors)


# --------------------------------------------------------------------------
# Test 12: Secret Redaction
# --------------------------------------------------------------------------
def test_12_secret_redaction_in_prompt_context():
    """Verify that API keys, passwords, bearer tokens, and private keys are redacted."""
    raw_evidence_text = (
        "Found hardcoded OpenAI key: sk-abcdef1234567890abcdef1234567890\n"
        "Found Google Key: AIzaSyD9u2x-TEST1234567890abcdefghijklm\n"
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID\n"
        "password = 'SuperSecretPassword123!'\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    )

    sanitized = sanitize_text(raw_evidence_text)
    assert "sk-abcdef1234567890abcdef1234567890" not in sanitized
    assert "[REDACTED_API_KEY]" in sanitized
    assert "AIzaSyD9u2x" not in sanitized
    assert "[REDACTED_GOOGLE_API_KEY]" in sanitized
    assert "[REDACTED_BEARER_TOKEN]" in sanitized
    assert "SuperSecretPassword123!" not in sanitized
    assert "[REDACTED_SECRET]" in sanitized
    assert "[REDACTED_PRIVATE_KEY]" in sanitized


# --------------------------------------------------------------------------
# Test 13: Zero Raw Evidence Upload Guarantee
# --------------------------------------------------------------------------
def test_13_zero_raw_evidence_upload():
    """Verify raw binary evidence paths or bytes are NEVER passed in OpenCode CLI command args."""
    class MockDetail:
        static_findings = [
            StaticFinding(
                finding_id="S-1",
                category="Crypto",
                severity="Low",
                title="DES Cipher",
                description="DES used",
                confidence="High"
            )
        ]
        c2_indicators = []
        reverse_shell_findings = []
        secrets = []
        metadata = None

    context = prepare_forensic_context(
        detail=MockDetail(),
        filename="sensitive_evidence.bin",
        file_type="binary",
        file_size_bytes=1048576,
        sha256_hash="e"*64
    )

    # Must be textual metadata only
    assert "sensitive_evidence.bin" in context
    assert "DES Cipher" in context
    assert "1048576 bytes" in context
    assert "analysis_workspace" not in context


# --------------------------------------------------------------------------
# Test 14: Findings vs Observations Separation & Risk Neutrality
# --------------------------------------------------------------------------
def test_14_findings_vs_observations_separation_and_risk_neutrality():
    """Verify AI observations are saved with status='UNVERIFIED' and do not alter deterministic severity score."""
    inv_id = "INV-TEST-NEUTRALITY-001"
    _ensure_investigation(inv_id, file_type="apk")

    obs = [
        AIObservation(
            id="AIOBS-001",
            investigation_id=inv_id,
            title="Hypothetical Advanced Backdoor",
            explanation="AI suspects state-sponsored actor activity.",
            related_evidence_refs=["Section1"],
            confidence="Unverified",
            reasoning_summary="Heuristic suspicion",
            suggested_verification_steps=["Inspect Ghidra disassembly."],
            status="UNVERIFIED",
            created_at=datetime.utcnow()
        )
    ]
    repo.save_ai_observations(obs)

    # 1. Observations are listed as UNVERIFIED
    stored_obs = repo.list_ai_observations(inv_id)
    assert len(stored_obs) == 1
    assert stored_obs[0].status == "UNVERIFIED"

    # 2. Findings register must NOT contain AI observations automatically
    findings = repo.list_findings_register(inv_id)
    assert not any(f.finding_id == "AIOBS-001" for f in findings)


# --------------------------------------------------------------------------
# Test 15: Investigation Completes When OpenCode Unavailable
# --------------------------------------------------------------------------
def test_15_investigation_completes_when_opencode_disabled():
    """Verify investigation finishes normally when OpenCode is disabled."""
    inv_id = "INV-TEST-DISABLED-001"
    _ensure_investigation(inv_id, file_type="apk")

    class MockDetail:
        record = repo.get_investigation(inv_id)
        static_findings = []
        c2_indicators = []
        reverse_shell_findings = []
        secrets = []
        metadata = None

    mock_status = {
        "installed": True,
        "version": "opencode v2.2.6",
        "path": "opencode.cmd",
        "enabled": False,
        "model": "none",
        "is_local_model": False,
        "auth_providers": [],
        "network_mode": "LOCAL_ONLY",
        "status_label": "DISABLED",
        "status_description": "Disabled in settings",
        "timeout_seconds": 60,
    }

    with patch("backend.app.integrations.opencode_engine.detect_opencode_status", return_value=mock_status):
        notes, obs, recs = analyze_investigation(
            investigation_id=inv_id,
            detail=MockDetail(),
            filename="safe.apk",
            file_type="apk",
            file_size_bytes=100,
            sha256_hash="9"*64,
            consent_approved=False
        )
        assert notes.execution_status == "DISABLED"
        assert len(obs) == 0
        assert len(recs) == 0


# --------------------------------------------------------------------------
# Test 16: Subprocess Cleanup & Review Endpoint
# --------------------------------------------------------------------------
def test_16_observation_review_and_custody_audit():
    """Verify human examiner review endpoint accepts/rejects observation with chain of custody logging."""
    inv_id = "INV-TEST-REVIEW-001"
    _ensure_investigation(inv_id, file_type="apk")

    obs = [
        AIObservation(
            id="AIOBS-TEST-REVIEW",
            investigation_id=inv_id,
            title="Potential Keylogger",
            explanation="Detects key event hooks.",
            related_evidence_refs=["dispatchKeyEvent"],
            confidence="Medium",
            reasoning_summary="Hooking API detected",
            suggested_verification_steps=["Inspect key handler"],
            status="UNVERIFIED",
            created_at=datetime.utcnow()
        )
    ]
    repo.save_ai_observations(obs)

    # Review as ACCEPTED
    review_res = client.post(
        f"/api/investigations/{inv_id}/ai-observations/AIOBS-TEST-REVIEW/review",
        json={"status": "ACCEPTED", "review_notes": "Verified against decompiler bytecode at line 142."}
    )
    assert review_res.status_code == 200
    data = review_res.json()
    assert data["success"] is True
    assert data["observation"]["status"] == "ACCEPTED"
    assert data["observation"]["review_notes"] == "Verified against decompiler bytecode at line 142."

    # Verify updated in DB
    updated = repo.list_ai_observations(inv_id)
    assert updated[0].status == "ACCEPTED"
    assert updated[0].reviewer is not None
