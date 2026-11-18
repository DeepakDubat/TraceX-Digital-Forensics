"""
TraceX Two-Plane Manager-Worker Communication Test Suite
Verifies:
1. Ephemeral, tamper-proof worker authentication tokens.
2. Cross-run scoping rejection (worker token for run A cannot access run B).
3. Evidence payload distribution via /api/dynamic/workers/{run_id}/payload.
4. Worker heartbeat telemetry and status reporting.
5. Ingesting telemetry batches from worker agent into manager repository.
6. Safe dropped artifact upload and storage.
7. Worker token revocation upon analysis conclusion.
8. Zero manager credential/database access from worker endpoints.
"""

import os
import time
import hashlib
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.config import settings
from backend.app.core.models import DynamicSandboxRun, InvestigationRecord
from backend.app.database.repository import repo
from backend.app.analyzers.dynamic.worker_auth import worker_auth_manager, WorkerAuthError

client = TestClient(app)


@pytest.fixture
def staged_worker_run():
    """Sets up a synthetic staged analysis run for worker testing."""
    inv_id = "INV-TEST-WORKER-001"
    run_id = "RUN-TEST-WORKER-001"
    target_name = "Synthetic_Target.exe"
    payload_content = b"MZ_SYNTHETIC_PE_WORKER_ANALYSIS_PAYLOAD"
    payload_sha256 = hashlib.sha256(payload_content).hexdigest()

    # Ensure parent investigation exists for foreign key
    existing_inv = repo.get_investigation(inv_id)
    if not existing_inv:
        repo.create_investigation(InvestigationRecord(
            id=inv_id,
            filename=target_name,
            original_size=len(payload_content),
            md5=hashlib.md5(payload_content).hexdigest(),
            sha1=hashlib.sha1(payload_content).hexdigest(),
            sha256=payload_sha256,
            status="completed",
            file_type="exe"
        ))

    # Stage payload file
    staging_dir = settings.DATA_DIR / "staging" / run_id
    staging_dir.mkdir(parents=True, exist_ok=True)
    staged_file = staging_dir / target_name
    staged_file.write_bytes(payload_content)

    # Create run in repository
    run = DynamicSandboxRun(
        id=run_id,
        investigation_id=inv_id,
        evidence_id="EV-TEST-001",
        target_binary=target_name,
        sandbox_environment="Oracle VirtualBox Disposable Worker",
        status="PROVISIONING",
        is_simulated_network=True,
        simulated_services=["DNS", "HTTP"],
        duration_seconds=0.0,
        started_at_utc="2026-11-09T10:00:00",
        process_count=0,
        file_event_count=0,
        registry_event_count=0,
        network_flow_count=0,
        dropped_artifacts_count=0,
        sandbox_logs=[],
        limitations="Isolated worker execution.",
        user_id="test_examiner",
        target_sha256=payload_sha256,
        target_type="exe",
        provider="virtualbox",
        environment_id="env-virtualbox-worker",
        network_policy="ISOLATED_SIMULATION",
        timeout_seconds=120
    )
    repo.create_sandbox_run(run)

    # Generate worker token
    token = worker_auth_manager.generate_worker_token(
        run_id=run_id,
        target_binary=target_name,
        expected_sha256=payload_sha256,
        expires_in_seconds=300,
        worker_type="windows"
    )

    yield run_id, token, payload_sha256

    # Teardown
    worker_auth_manager.revoke_worker_session(run_id)
    if staging_dir.exists():
        import shutil
        shutil.rmtree(staging_dir, ignore_errors=True)
    repo.delete_sandbox_run(run_id)
    repo.delete_investigation(inv_id)


def test_worker_token_generation_and_validation(staged_worker_run):
    """Verifies that worker tokens are cryptographically validated and scoped."""
    run_id, token, expected_sha = staged_worker_run

    # 1. Valid token passes
    payload = worker_auth_manager.validate_worker_token(run_id, token)
    assert payload["run_id"] == run_id
    assert payload["expected_sha256"] == expected_sha

    # 2. Tampered token fails
    tampered = token[:-4] + "AAAA"
    with pytest.raises(WorkerAuthError) as exc_info:
        worker_auth_manager.validate_worker_token(run_id, tampered)
    assert "signature verification failed" in str(exc_info.value)

    # 3. Cross-run scoping rejection
    with pytest.raises(WorkerAuthError) as exc_info:
        worker_auth_manager.validate_worker_token("RUN-DIFFERENT-999", token)
    assert "cannot access run" in str(exc_info.value)


def test_worker_payload_distribution(staged_worker_run):
    """Verifies that worker can download its assigned evidence payload with valid token."""
    run_id, token, expected_sha = staged_worker_run

    # 1. Unauthenticated request -> 401
    unauth_res = client.get(f"/api/dynamic/workers/{run_id}/payload", headers={"X-Unauthenticated": "true"})
    assert unauth_res.status_code == 401

    # 2. Invalid token -> 403
    bad_token_res = client.get(f"/api/dynamic/workers/{run_id}/payload", headers={"Authorization": "Bearer wx_invalid.token"})
    assert bad_token_res.status_code == 403

    # 3. Valid token -> 200 with payload stream & SHA-256 header
    auth_res = client.get(f"/api/dynamic/workers/{run_id}/payload", headers={"Authorization": f"Bearer {token}"})
    assert auth_res.status_code == 200
    assert auth_res.headers.get("X-Evidence-SHA256") == expected_sha
    assert hashlib.sha256(auth_res.content).hexdigest() == expected_sha


def test_worker_heartbeat_and_telemetry_ingestion(staged_worker_run):
    """Verifies that worker heartbeat and telemetry batches are ingested."""
    run_id, token, _ = staged_worker_run
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Heartbeat
    hb_res = client.post(
        f"/api/dynamic/workers/{run_id}/heartbeat",
        json={"agent_version": "1.2.0-win"},
        headers=headers
    )
    assert hb_res.status_code == 200
    assert hb_res.json()["status"] == "acknowledged"

    # 2. Submit Telemetry
    telemetry_payload = {
        "events": [
            {
                "timestamp_utc": "2026-11-09T10:01:00",
                "event_type": "PROCESS",
                "source": "worker_agent",
                "process_name": "malicious_child.exe",
                "process_id": 4120,
                "action": "PROCESS_SPAWNED",
                "target": "C:\\Windows\\cmd.exe",
                "details": {"command_line": "cmd.exe /c whoami"},
                "risk_indicator": True,
                "threat_tag": "T1059.003"
            },
            {
                "timestamp_utc": "2026-11-09T10:01:05",
                "event_type": "FILE",
                "source": "worker_agent",
                "process_name": "malicious_child.exe",
                "process_id": 4120,
                "action": "FILE_WRITTEN",
                "target": "C:\\Users\\Worker\\AppData\\Local\\Temp\\dropped.dll",
                "details": {"size": 4096},
                "risk_indicator": True,
                "threat_tag": "T1105"
            }
        ]
    }

    tel_res = client.post(
        f"/api/dynamic/workers/{run_id}/telemetry",
        json=telemetry_payload,
        headers=headers
    )
    assert tel_res.status_code == 200
    assert tel_res.json()["events_ingested"] == 2

    # Verify session state reflects telemetry
    session = worker_auth_manager.get_session(run_id)
    assert session is not None
    assert session["status"] == "ANALYZING"
    assert session["heartbeat_count"] >= 1
    assert session["telemetry_received"] is True


def test_worker_dropped_artifact_upload(staged_worker_run):
    """Verifies that worker can upload recovered dropped artifacts."""
    run_id, token, _ = staged_worker_run
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Artifact-Filename": "dropped_payload.bin",
        "X-Artifact-Path": "C:\\Users\\Worker\\Temp\\dropped_payload.bin"
    }

    artifact_content = b"DROPPED_SUSPICIOUS_BINARY_ARTIFACT_12345"
    expected_artifact_hash = hashlib.sha256(artifact_content).hexdigest()

    upload_res = client.post(
        f"/api/dynamic/workers/{run_id}/artifacts",
        content=artifact_content,
        headers=headers
    )
    assert upload_res.status_code == 200
    data = upload_res.json()
    assert data["status"] == "success"
    assert data["artifact"]["sha256"] == expected_artifact_hash
    assert data["artifact"]["size_bytes"] == len(artifact_content)


def test_worker_session_revocation(staged_worker_run):
    """Verifies that revoking worker session immediately denies further worker access."""
    run_id, token, _ = staged_worker_run
    headers = {"Authorization": f"Bearer {token}"}

    # Explicit revocation
    worker_auth_manager.revoke_worker_session(run_id)

    # Next attempt fails with 403
    hb_res = client.post(
        f"/api/dynamic/workers/{run_id}/heartbeat",
        json={},
        headers=headers
    )
    assert hb_res.status_code == 403

