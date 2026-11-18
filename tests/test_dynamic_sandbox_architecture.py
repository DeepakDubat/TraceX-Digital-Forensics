"""
TraceX Digital Forensics & Cyber Investigation Suite
Test Suite: Dynamic Sandbox Architecture, Safety Policy & API Verification
"""

import os
import tempfile
import hashlib
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.main import app
from backend.app.core.models import (
    DynamicSandboxRun,
    DynamicTelemetryEvent,
    DynamicObservation,
    DynamicArtifact,
    ProcessTreeNode,
    InvestigationRecord
)
from backend.app.database.repository import repo
from backend.app.analyzers.dynamic.sandbox_capabilities import sandbox_capabilities
from backend.app.analyzers.dynamic.sandbox_registry import sandbox_registry
from backend.app.analyzers.dynamic.sandbox_policy import (
    sandbox_policy,
    SandboxSecurityViolation
)
from backend.app.analyzers.dynamic.windows_sandbox import WindowsSandboxProvider
from backend.app.analyzers.dynamic.telemetry_collector import telemetry_collector
from backend.app.analyzers.dynamic.process_monitor import process_monitor
from backend.app.analyzers.dynamic.behavior_analyzer import behavior_analyzer
from backend.app.analyzers.dynamic.dynamic_report_generator import dynamic_report_generator


@pytest.fixture
def test_sample_file(tmp_path):
    """Creates a dummy sample file for testing staging and isolation."""
    sample_file = tmp_path / "test_malware_sample.exe"
    content = b"\x4D\x5A\x90\x00Dummy executable content for sandbox testing"
    sample_file.write_bytes(content)
    sha256 = hashlib.sha256(content).hexdigest().upper()
    return sample_file, sha256


def _ensure_investigation(inv_id: str, filename: str = "sample.exe", sha256: str = "TESTSHA256") -> InvestigationRecord:
    existing = repo.get_investigation(inv_id)
    if existing:
        return existing
    inv = InvestigationRecord(
        id=inv_id,
        filename=filename,
        original_size=4096,
        md5="0123456789abcdef0123456789abcdef",
        sha1="0123456789abcdef0123456789abcdef01234567",
        sha256=sha256,
        status="completed",
        file_type="exe"
    )
    repo.create_investigation(inv)
    return inv


# =====================================================================
# 1. CAPABILITY DETECTION & PREFLIGHT AUDIT
# =====================================================================

def test_capabilities_truthful_detection():
    """Verify capabilities accurately reflect the host OS without fabrication."""
    matrix = sandbox_capabilities.get_capabilities(force_refresh=True)
    assert matrix is not None
    assert isinstance(matrix.os_name, str)
    assert len(matrix.os_name) > 0
    assert isinstance(matrix.cpu_virtualization_enabled, bool)

    # Windows Sandbox check on Windows 11 Home Single Language
    # Must report windows_sandbox_installed == False
    if "home" in matrix.os_name.lower():
        assert matrix.windows_sandbox_installed is False

    envs = sandbox_capabilities.list_environments(force_refresh=True)
    assert len(envs) >= 4
    wsb_env = next((e for e in envs if e.provider_type == "windows_sandbox"), None)
    assert wsb_env is not None
    if not matrix.windows_sandbox_installed:
        assert wsb_env.status in ("UNSUPPORTED_PLATFORM", "NOT_CONFIGURED")


# =====================================================================
# 2. PROVIDER REGISTRY TESTS
# =====================================================================

def test_provider_registry_enumeration():
    """Verify all providers are registered and resolvable."""
    providers = sandbox_registry.list_providers()
    assert len(providers) >= 4

    provider_ids = [p.provider_id for p in providers]
    assert "windows_sandbox" in provider_ids
    assert "hyperv" in provider_ids
    assert "android_emulator" in provider_ids

    # Query by platform
    win_providers = sandbox_registry.list_providers(os_family="windows")
    assert any(p.provider_id == "windows_sandbox" for p in win_providers)

    android_providers = sandbox_registry.list_providers(os_family="android")
    assert any(p.provider_id == "android_emulator" for p in android_providers)


# =====================================================================
# 3. SAFETY POLICY & ZERO HOST EXECUTION GUARANTEE
# =====================================================================

def test_zero_host_execution_guarantee(test_sample_file):
    """Verify isolation policy strictly forbids direct host execution."""
    sample_path, sha256 = test_sample_file

    # Attempting to designate host as execution target raises SandboxSecurityViolation
    for bad_env in ("host", "local_host", "workstation", "direct", "subprocess"):
        with pytest.raises(SandboxSecurityViolation) as exc_info:
            sandbox_policy.validate_execution_target(bad_env, sample_path, sha256)
        assert "CRITICAL SECURITY REJECTION" in str(exc_info.value)

    # Valid isolated environment
    valid = sandbox_policy.validate_execution_target("env-wsb-host", sample_path, sha256)
    assert valid is True


def test_staging_sample_integrity(test_sample_file, tmp_path):
    """Verify sample is copied to an isolated staging area with verified SHA-256."""
    sample_path, expected_sha = test_sample_file
    analysis_id = "test-analysis-stage-01"

    staged_path, digest = sandbox_policy.create_isolated_staging_copy(
        analysis_id=analysis_id,
        original_evidence_path=sample_path,
        expected_sha256=expected_sha
    )

    assert staged_path.exists()
    assert staged_path != sample_path
    assert digest == expected_sha

    # Verify content match
    assert sample_path.read_bytes() == staged_path.read_bytes()


def test_network_policy_containment():
    """Verify network policy enforcement in local-only / air-gap environments."""
    assert sandbox_policy.enforce_network_policy("DISABLED") == "DISABLED"
    assert sandbox_policy.enforce_network_policy("ISOLATED_SIMULATION") == "ISOLATED_SIMULATION"
    assert sandbox_policy.enforce_network_policy("INVALID_MODE") == "DISABLED"


# =====================================================================
# 4. WINDOWS SANDBOX WSB XML PROVISIONING
# =====================================================================

def test_wsb_xml_isolation_tags(tmp_path):
    """Verify generated .wsb XML adheres to strict isolation rules."""
    inv_id = "inv-wsb-test-01"
    _ensure_investigation(inv_id, filename="sample.exe", sha256="TESTSHA256")

    staged_dir = tmp_path / "staged"
    staged_dir.mkdir()
    sample_file = staged_dir / "sample.exe"
    sample_file.write_bytes(b"MZTestBinary")

    run = DynamicSandboxRun(
        id="run-wsb-test-01",
        investigation_id=inv_id,
        evidence_id="ev-test-01",
        target_binary="sample.exe",
        target_sha256="TESTSHA256",
        target_type="exe",
        sandbox_environment="Windows Sandbox",
        provider="windows_sandbox",
        network_policy="DISABLED",
        timeout_seconds=120
    )

    provider = WindowsSandboxProvider()
    result = provider.provision(run, sample_file)

    wsb_file = Path(result["wsb_path"])
    assert wsb_file.exists()
    wsb_content = wsb_file.read_text(encoding="utf-8")

    assert "<Networking>Disable</Networking>" in wsb_content
    assert "<ReadOnly>true</ReadOnly>" in wsb_content
    assert "<ClipboardRedirection>Disable</ClipboardRedirection>" in wsb_content
    assert "<MemoryInMB>4096</MemoryInMB>" in wsb_content
    assert "<LogonCommand>" in wsb_content
    assert "bootstrap.cmd" in wsb_content


# =====================================================================
# 5. TELEMETRY NORMALIZATION & PROCESS MONITOR
# =====================================================================

def test_telemetry_collector_and_process_tree(tmp_path):
    """Verify telemetry bundle ingestion and process tree reconstruction."""
    inv_id = "inv-telemetry-test-01"
    _ensure_investigation(inv_id, filename="malware.exe", sha256="TESTHASH")
    run_id = "run-telemetry-test-01"

    run = DynamicSandboxRun(
        id=run_id,
        investigation_id=inv_id,
        evidence_id="ev-telemetry-01",
        target_binary="malware.exe",
        target_sha256="TESTHASH",
        target_type="exe",
        sandbox_environment="Windows Sandbox",
        provider="windows_sandbox",
        status="RUNNING"
    )
    repo.create_sandbox_run(run)

    bundle = {
        "processes": [
            {
                "pid": 1000,
                "ppid": 4,
                "name": "explorer.exe",
                "cmdline": "explorer.exe",
                "integrity": "medium"
            },
            {
                "pid": 2000,
                "ppid": 1000,
                "name": "malware.exe",
                "cmdline": "C:\\Temp\\malware.exe",
                "integrity": "medium"
            },
            {
                "pid": 3000,
                "ppid": 2000,
                "name": "cmd.exe",
                "cmdline": "cmd.exe /c powershell -enc AAAA",
                "integrity": "medium"
            }
        ],
        "files": [
            {
                "path": "C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Temp\\dropped.dll",
                "action": "CREATE",
                "size": 52400,
                "sha256": "DROPPEDSHA256"
            }
        ],
        "registry": [
            {
                "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": "BackdoorRun",
                "value_data": "dropped.dll",
                "action": "SET_VALUE"
            }
        ],
        "network": [
            {
                "src_ip": "192.168.1.10",
                "src_port": 49152,
                "dst_ip": "185.220.101.5",
                "dst_port": 443,
                "protocol": "TCP",
                "packets": 5,
                "bytes": 512,
                "is_simulated": True
            }
        ]
    }

    counts = telemetry_collector.ingest_bundle(run, bundle)
    assert counts["processes"] == 3
    assert counts["files"] == 1
    assert counts["registry"] == 1
    assert counts["network"] == 1

    # Reconstruct Process Tree
    tree = process_monitor.build_process_tree(inv_id, run_id=run_id)
    assert len(tree) >= 1
    root = next(n for n in tree if n.pid == 1000)
    assert len(root.children) == 1
    assert root.children[0].name == "malware.exe"
    assert root.children[0].children[0].name == "cmd.exe"
    assert root.children[0].children[0].is_suspicious is True


# =====================================================================
# 6. BEHAVIOR ANALYSIS & DYNAMIC REPORT GENERATION
# =====================================================================

def test_behavior_analysis_and_report():
    """Verify behavior analyzer maps observations and generates reports."""
    inv_id = "inv-report-test-01"
    _ensure_investigation(inv_id, filename="trojan.exe", sha256="TROJANSHA256")
    run_id = "run-report-test-01"

    run = DynamicSandboxRun(
        id=run_id,
        investigation_id=inv_id,
        evidence_id="ev-report-01",
        target_binary="trojan.exe",
        target_sha256="TROJANSHA256",
        target_type="exe",
        sandbox_environment="Windows Sandbox",
        provider="windows_sandbox",
        network_policy="ISOLATED_SIMULATION",
        status="RUNNING"
    )
    repo.create_sandbox_run(run)

    # Ingest a persistence registry event and network flow
    bundle = {
        "registry": [
            {
                "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": "Updater",
                "value_data": "trojan.exe",
                "action": "SET_VALUE"
            }
        ],
        "network": [
            {
                "src_ip": "10.0.0.5",
                "src_port": 50000,
                "dst_ip": "45.33.32.156",
                "dst_port": 8080,
                "protocol": "TCP",
                "packets": 10,
                "bytes": 2048,
                "is_simulated": True
            }
        ]
    }
    telemetry_collector.ingest_bundle(run, bundle)

    # Run behavior analyzer
    observations = behavior_analyzer.analyze_run_behavior(run)
    assert len(observations) >= 1
    assert run.risk_score > 0

    # Generate Dynamic Report
    report = dynamic_report_generator.generate_report(run)
    assert report is not None
    assert report.run_id == run_id
    assert "Executive Summary" in report.summary_markdown
    assert "trojan.exe" in report.summary_markdown


# =====================================================================
# 7. REST API ENDPOINTS & AUTHENTICATION
# =====================================================================

def test_dynamic_api_auth_enforcement():
    """Verify /api/dynamic endpoints reject unauthenticated requests."""
    client = TestClient(app)
    # Anonymous request
    res = client.get("/api/dynamic/capabilities", headers={"X-Anonymous": "1"})
    assert res.status_code == 401


def test_dynamic_api_capabilities_and_dashboard():
    """Verify authenticated /api/dynamic/capabilities and /dashboard work properly."""
    client = TestClient(app)
    res = client.get("/api/dynamic/capabilities")
    assert res.status_code == 200
    data = res.json()
    assert "os_name" in data
    assert "os_version" in data

    res_dash = client.get("/api/dynamic/dashboard")
    assert res_dash.status_code == 200
    dash_data = res_dash.json()
    assert "total_dynamic_analyses" in dash_data
    assert "available_environments" in dash_data


def test_dynamic_api_analysis_lifecycle():
    """Verify dynamic analysis creation, start, and observation retrieval."""
    client = TestClient(app)

    # Set up genuine test evidence on disk and in database
    inv_id = "test-inv-lifecycle-01"
    ev_dir = settings.DATA_DIR / inv_id / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    sample_file = ev_dir / "test_sample.exe"
    sample_content = b"\x4D\x5A\x90\x00LiveLifecycleSample"
    sample_file.write_bytes(sample_content)
    sha256 = hashlib.sha256(sample_content).hexdigest().upper()
    md5 = hashlib.md5(sample_content).hexdigest().upper()
    sha1 = hashlib.sha1(sample_content).hexdigest().upper()

    inv = InvestigationRecord(
        id=inv_id,
        filename="test_sample.exe",
        original_size=len(sample_content),
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        status="completed",
        file_type="exe"
    )
    repo.create_investigation(inv)

    # 1. Create analysis run
    payload = {
        "investigation_id": inv_id,
        "evidence_id": "ev-lifecycle-01",
        "sample_type": "PE",
        "sample_name": "test_sample.exe",
        "environment_id": "windows_sandbox",
        "network_policy": "DISABLED",
        "timeout_seconds": 60
    }

    create_res = client.post("/api/dynamic/analyses", json=payload)
    assert create_res.status_code == 200
    run_info = create_res.json()
    run_id = run_info["id"]
    assert run_id is not None
    assert run_info["status"] == "PENDING"

    # 2. Start analysis
    start_res = client.post(f"/api/dynamic/analyses/{run_id}/start")
    assert start_res.status_code in (200, 400)
    if start_res.status_code == 200:
        assert start_res.json()["status"] in ("RUNNING", "FAILED", "PENDING")
    else:
        assert "not ready" in start_res.json()["detail"].lower() or "not configured" in start_res.json()["detail"].lower()

    # 3. Finalize analysis
    finalize_res = client.post(f"/api/dynamic/analyses/{run_id}/finalize", json={
        "duration_seconds": 15.0
    })
    assert finalize_res.status_code == 200
    assert finalize_res.json()["report_type"] == "DYNAMIC"

    # 4. Check process tree & report
    pt_res = client.get(f"/api/dynamic/analyses/{run_id}/process-tree")
    assert pt_res.status_code == 200

    rep_res = client.get(f"/api/dynamic/analyses/{run_id}/report")
    assert rep_res.status_code == 200
    report_data = rep_res.json()
    assert "summary_markdown" in report_data
    assert report_data["run_id"] == run_id
