import io
from fastapi.testclient import TestClient
import pytest

from backend.app.main import app
from backend.app.config import settings
from backend.app.database.repository import repo
from backend.app.core.models import InvestigationRecord

client = TestClient(app)

class TestAPISecurityAndAuth:
    """Security tests verifying authentication boundaries, workstation trust model, and upload limits."""

    def test_health_check_endpoint_public(self):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "local_only_mode" in data

    def test_standalone_workstation_mode_allows_local_access(self):
        # In standalone workstation mode (default: WORKBENCH_API_KEY is None), local access is permitted
        original_key = settings.WORKBENCH_API_KEY
        settings.WORKBENCH_API_KEY = None
        try:
            resp = client.get("/api/dashboard/stats")
            assert resp.status_code == 200
            assert "total_investigations" in resp.json()
        finally:
            settings.WORKBENCH_API_KEY = original_key

    def test_authenticated_mode_enforces_api_key_header(self):
        original_key = settings.WORKBENCH_API_KEY
        test_key = "secure-forensic-examiner-token-998877"
        settings.WORKBENCH_API_KEY = test_key
        try:
            # 1. Accessing protected endpoint without X-API-Key returns 401
            resp_no_key = client.get(
                "/api/investigations/INV-BENCH/secrets/unredact?secret_id=SEC-01",
                headers={"X-Anonymous": "1"}
            )
            assert resp_no_key.status_code == 401
            assert "Unauthorized" in resp_no_key.json()["detail"] or "Authentication required" in resp_no_key.json()["detail"]

            # 2. Accessing with invalid X-API-Key returns 401
            resp_bad_key = client.get(
                "/api/investigations/INV-BENCH/secrets/unredact?secret_id=SEC-01",
                headers={"X-API-Key": "wrong-token-abc"}
            )
            assert resp_bad_key.status_code == 401

            # 3. Accessing with valid X-API-Key succeeds past the auth gate (returns 404 for missing dummy secret)
            resp_valid = client.get(
                "/api/investigations/INV-BENCH/secrets/unredact?secret_id=SEC-01",
                headers={"X-API-Key": test_key}
            )
            assert resp_valid.status_code == 404 # Auth passed, secret not found
        finally:
            settings.WORKBENCH_API_KEY = original_key

    def test_unredact_secret_logs_chain_of_custody_audit(self):
        # Create a mock investigation and secret
        inv_id = "INV-AUTH-AUDIT-TEST"
        try:
            rec = InvestigationRecord(
                id=inv_id,
                filename="audit_sample.apk",
                original_size=1024,
                md5="0"*32,
                sha1="0"*40,
                sha256="0"*64,
                status="COMPLETED",
                created_at="2026-11-06T00:00:00Z"
            )
            repo.create_investigation(rec)

            # Ingest secret
            from backend.app.core.models import SecretFinding
            s = SecretFinding(
                id="SEC-TEST-001",
                investigation_id=inv_id,
                token_category="AWS_ACCESS_KEY",
                redacted_value="AKIA••••••••ABCD",
                raw_value="AKIAIOSFODNN7EXAMPLE",
                source_location="config.json",
                rule_matched="AWS Access Key Pattern",
                severity="High",
                entropy=4.2,
                confidence="Confirmed"
            )
            repo.save_secrets(inv_id, [s])

            # Call unredact endpoint
            resp = client.get(
                f"/api/investigations/{inv_id}/secrets/unredact?secret_id=SEC-TEST-001&examiner_name=AuditorSmith"
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["raw_value"] == "AKIAIOSFODNN7EXAMPLE"
            assert "Audit event recorded in Chain of Custody" in data["disclaimer"]

            # Verify event was recorded in chain_of_custody table
            ledger = repo.list_chain_of_custody(inv_id)
            audit_events = [e for e in ledger if e.event_type == "SECRET_UNREDACTED_ACCESS"]
            assert len(audit_events) >= 1
            assert audit_events[0].examiner == "AuditorSmith"
            assert audit_events[0].verification_result == "AUDITED"
        finally:
            repo.delete_investigation(inv_id)

    def test_upload_exceeding_max_size_rejected(self):
        original_limit = settings.MAX_UPLOAD_SIZE_MB
        # Temporarily set limit to 1 MB for testing
        settings.MAX_UPLOAD_SIZE_MB = 1
        try:
            # Create a 2 MB file payload
            large_content = b"X" * (2 * 1024 * 1024)
            files = {"file": ("oversized.apk", io.BytesIO(large_content), "application/vnd.android.package-archive")}
            resp = client.post("/api/investigations/upload", files=files)
            assert resp.status_code == 413
            assert "exceeds maximum limit" in resp.json()["detail"].lower()
        finally:
            settings.MAX_UPLOAD_SIZE_MB = original_limit
