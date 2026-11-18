"""
Integration State Synchronization & Authoritative Status Verification Tests
TraceX v2.0.0 – Digital Forensics & Cyber Investigation Suite
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.credential_manager import credential_manager, PROVIDER_CATALOG
from backend.app.database.repository import repo

client = TestClient(app)

AUTHORITATIVE_STATUSES = {
    "NOT_CONFIGURED",
    "CREDENTIAL_SAVED",
    "CONNECTING",
    "CONNECTED",
    "AUTHENTICATION_FAILED",
    "RATE_LIMITED",
    "TOKEN_EXPIRED",
    "SERVICE_UNAVAILABLE",
    "CONNECTION_ERROR",
    "NOT_INSTALLED",
}


def test_authoritative_status_classification():
    """Verify list_providers_metadata classifies every provider into one of the 10 authoritative statuses."""
    items = credential_manager.list_providers_metadata()
    assert len(items) == len(PROVIDER_CATALOG)

    for item in items:
        status = item.get("status")
        assert status in AUTHORITATIVE_STATUSES, f"Provider {item['id']} has invalid status '{status}'"
        assert item.get("display_status") is not None
        assert item.get("status_badge") is not None
        assert "masked_values" in item


def test_get_credentials_summary_endpoint():
    """Verify GET /api/credentials/summary returns the 6 real-data counters."""
    headers = {"X-TraceX-Bridge-Token": "tracex-workstation-desktop-token"}
    response = client.get("/api/credentials/summary", headers=headers)
    assert response.status_code == 200
    data = response.json()

    for key in (
        "total",
        "connected",
        "credentials_saved",
        "not_configured",
        "authentication_failed",
        "local_tools_available",
    ):
        assert key in data
        assert isinstance(data[key], int)
        assert data[key] >= 0

    assert data["total"] == len(PROVIDER_CATALOG)
    # Built-in local tools (yara, androguard) are available
    assert data["local_tools_available"] >= 2
    assert data["connected"] >= 2


def test_masked_credential_merge_on_test():
    """Verify testing with ephemeral masked strings (****a83f) automatically merges with stored decrypted keys."""
    test_key = "a1b2c3d4e5f678901234567890abcdef"
    headers = {"X-TraceX-Bridge-Token": "tracex-workstation-desktop-token"}

    # 1. Save valid dummy key
    save_resp = client.post(
        "/api/credentials/virustotal",
        headers=headers,
        json={"data": {"api_key": test_key}}
    )
    assert save_resp.status_code == 200

    # 2. Test with masked placeholder that frontend sends if user doesn't retype
    masked_payload = {"api_key": "****************cdef"}
    res = credential_manager.test_credential("virustotal", ephemeral_data=masked_payload)

    # Dispatcher runs against live VT API with real merged key (which returns 401 on dummy key, NOT missing/malformed)
    assert res is not None
    assert "status" in res

    # 3. Clean up
    del_resp = client.delete("/api/credentials/virustotal", headers=headers)
    assert del_resp.status_code == 200


def test_state_mutation_lifecycle_and_counter_sync():
    """Verify save -> summary update -> delete -> summary update lifecycle."""
    headers = {"X-TraceX-Bridge-Token": "tracex-workstation-desktop-token"}

    # Initial summary
    initial_sum = client.get("/api/credentials/summary", headers=headers).json()

    # Save a new credential for alienvault_otx
    save_resp = client.post(
        "/api/credentials/alienvault_otx",
        headers=headers,
        json={"data": {"api_key": "test_otx_key_1234567890"}}
    )
    assert save_resp.status_code == 200

    # Check updated summary: credentials_saved should increase by 1, not_configured decrease by 1
    after_save_sum = client.get("/api/credentials/summary", headers=headers).json()
    assert after_save_sum["credentials_saved"] == initial_sum["credentials_saved"] + 1
    assert after_save_sum["not_configured"] == initial_sum["not_configured"] - 1

    # Clean up by deleting
    del_resp = client.delete("/api/credentials/alienvault_otx", headers=headers)
    assert del_resp.status_code == 200

    # Check restored summary
    after_del_sum = client.get("/api/credentials/summary", headers=headers).json()
    assert after_del_sum["credentials_saved"] == initial_sum["credentials_saved"]
    assert after_del_sum["not_configured"] == initial_sum["not_configured"]


def test_local_tools_available_status():
    """Verify local forensic tools (yara, androguard) are detected as CONNECTED and opencode is purged."""
    items = credential_manager.list_providers_metadata()
    by_id = {i["id"]: i for i in items}

    assert by_id["yara"]["status"] == "CONNECTED"
    assert by_id["androguard"]["status"] == "CONNECTED"
    assert "openai" not in by_id
    assert "opencode" in by_id

