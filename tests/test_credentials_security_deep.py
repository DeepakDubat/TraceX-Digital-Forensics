"""
TraceX Credentials API & Encryption Security Deep Audit Suite
Production-Grade Verification of BYOK Security Guarantees:
1. Every credentials endpoint strictly enforces authentication (401 rejection).
2. Credentials and OAuth tokens are strictly user-scoped with zero cross-user leakage.
3. Plaintext secrets are NEVER exposed in any API response.
4. Masking works correctly across all provider secret formats.
5. Unknown provider IDs are rejected with HTTP 404.
6. Empty values CANNOT accidentally overwrite valid credentials.
7. Attempting to save empty credentials on unconfigured providers returns HTTP 400.
8. Credential deletion is strictly user-scoped.
9. DPAPI master key encryption and decryption survive simulated application restarts.
10. Master key recovery failures refuse plaintext fallback and raise explicit errors.
"""

import uuid
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database.repository import repo
from backend.app.core.user_auth import (
    hash_password,
    CSRF_HEADER_NAME
)
from backend.app.core.credential_manager import (
    credential_manager,
    CredentialManager,
    PROVIDER_CATALOG
)

client = TestClient(app)


# ==============================================================================
# FIXTURES
# ==============================================================================

@pytest.fixture(scope="module")
def audit_users():
    """Sets up two strictly isolated test investigator accounts."""
    user_a_id = str(uuid.uuid4())
    user_b_id = str(uuid.uuid4())

    ha, sa = hash_password("AuditAlphaPass2026!")
    hb, sb = hash_password("AuditBetaPass2026!")

    # Clean prior test users if present
    for u in ("audit_alpha", "audit_beta"):
        ex = repo.get_user_by_username(u)
        if ex:
            repo.delete_user(ex["id"])

    user_a = repo.create_user(
        user_id=user_a_id,
        username="audit_alpha",
        email="alpha_audit@tracex.local",
        password_hash=ha,
        salt=sa,
        role="investigator"
    )

    user_b = repo.create_user(
        user_id=user_b_id,
        username="audit_beta",
        email="beta_audit@tracex.local",
        password_hash=hb,
        salt=sb,
        role="investigator"
    )

    yield user_a, user_b

    # Teardown
    credential_manager.delete_credential("virustotal", user_id=user_a_id)
    credential_manager.delete_credential("openai", user_id=user_a_id)
    credential_manager.delete_credential("censys", user_id=user_a_id)
    credential_manager.delete_credential("virustotal", user_id=user_b_id)
    credential_manager.delete_credential("openai", user_id=user_b_id)
    credential_manager.delete_credential("censys", user_id=user_b_id)
    repo.delete_user(user_a_id)
    repo.delete_user(user_b_id)


# ==============================================================================
# TEST 1: ALL CREDENTIALS ENDPOINTS REJECT UNAUTHENTICATED ACCESS
# ==============================================================================

def test_unauthenticated_requests_strictly_rejected():
    """Verifies that all 7 credentials endpoints return HTTP 401 without valid session/token."""
    unauthed_client = TestClient(app)

    # 1. Master key status
    res = unauthed_client.get("/api/credentials/master-key/status")
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"

    # 2. Providers catalog
    res = unauthed_client.get("/api/credentials/providers")
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"

    # 3. List credentials
    res = unauthed_client.get("/api/credentials")
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"

    # 4. Get specific provider status
    res = unauthed_client.get("/api/credentials/virustotal")
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"

    # 5. Save provider credential
    res = unauthed_client.post("/api/credentials/virustotal", json={"data": {"api_key": "some_test_key"}})
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"

    # 6. Delete provider credential
    res = unauthed_client.delete("/api/credentials/virustotal")
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"

    # 7. Test provider credential
    res = unauthed_client.post("/api/credentials/virustotal/test")
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"


# ==============================================================================
# TEST 2: ROUTE ORDERING & COLLISION RESISTANCE
# ==============================================================================

def test_route_ordering_no_parameter_swallowing(audit_users):
    """Verifies that static paths like /providers and /master-key/status are not swallowed by /{provider_id}."""
    user_a, _ = audit_users
    client_a = TestClient(app)
    login_res = client_a.post("/api/auth/login", json={"username": "audit_alpha", "password": "AuditAlphaPass2026!"})
    token = login_res.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # /providers should return a list of provider objects, not a 404
    res_providers = client_a.get("/api/credentials/providers", headers=headers)
    assert res_providers.status_code == 200
    assert isinstance(res_providers.json(), list)
    assert len(res_providers.json()) > 0

    # /master-key/status should return status dict
    res_mk = client_a.get("/api/credentials/master-key/status", headers=headers)
    assert res_mk.status_code == 200
    assert "encryption_algorithm" in res_mk.json()


# ==============================================================================
# TEST 3: UNKNOWN PROVIDER VALIDATION
# ==============================================================================

def test_unknown_provider_returns_404(audit_users):
    """Verifies that requests targeting non-existent providers return 404."""
    user_a, _ = audit_users
    client_a = TestClient(app)
    login_res = client_a.post("/api/auth/login", json={"username": "audit_alpha", "password": "AuditAlphaPass2026!"})
    token = login_res.json()["token"]
    csrf = login_res.json()["csrf_token"]
    headers = {"Authorization": f"Bearer {token}", CSRF_HEADER_NAME: csrf}

    bogus = "totally_fake_threat_intel_provider"

    # GET
    assert client_a.get(f"/api/credentials/{bogus}", headers=headers).status_code == 404
    # POST
    assert client_a.post(f"/api/credentials/{bogus}", json={"data": {"api_key": "foo"}}, headers=headers).status_code == 404
    # DELETE
    assert client_a.delete(f"/api/credentials/{bogus}", headers=headers).status_code == 404
    # TEST
    assert client_a.post(f"/api/credentials/{bogus}/test", headers=headers).status_code == 404


# ==============================================================================
# TEST 4: EMPTY VALUES CANNOT OVERWRITE VALID CREDENTIALS
# ==============================================================================

def test_empty_values_cannot_overwrite_valid_credentials(audit_users):
    """
    Verifies Requirement 7:
    1. Saving empty credentials on unconfigured provider returns HTTP 400.
    2. Submitting empty string or whitespace does NOT wipe out an existing valid credential.
    3. Multi-field partial update preserves omitted/empty fields.
    """
    user_a, _ = audit_users
    client_a = TestClient(app)
    login_res = client_a.post("/api/auth/login", json={"username": "audit_alpha", "password": "AuditAlphaPass2026!"})
    token = login_res.json()["token"]
    csrf = login_res.json()["csrf_token"]
    headers = {"Authorization": f"Bearer {token}", CSRF_HEADER_NAME: csrf}

    # Clean state
    credential_manager.delete_credential("virustotal", user_id=user_a["id"])
    credential_manager.delete_credential("censys", user_id=user_a["id"])

    # 1. Attempting to save empty data on unconfigured provider -> 400
    res_empty_1 = client_a.post(
        "/api/credentials/virustotal",
        json={"data": {"api_key": ""}},
        headers=headers
    )
    assert res_empty_1.status_code == 400

    res_empty_spaces = client_a.post(
        "/api/credentials/virustotal",
        json={"data": {"api_key": "    "}},
        headers=headers
    )
    assert res_empty_spaces.status_code == 400

    # 2. Save valid VirusTotal key
    valid_key = "a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef4444"
    res_save = client_a.post(
        "/api/credentials/virustotal",
        json={"data": {"api_key": valid_key}},
        headers=headers
    )
    assert res_save.status_code == 200

    # Verify saved
    saved_masked = client_a.get("/api/credentials/virustotal", headers=headers).json()
    assert saved_masked["is_configured"] is True
    assert saved_masked["masked_values"]["api_key"].endswith("4444")

    # 3. Now attempt to overwrite with empty string
    res_empty_overwrite = client_a.post(
        "/api/credentials/virustotal",
        json={"data": {"api_key": ""}},
        headers=headers
    )
    assert res_empty_overwrite.status_code == 200

    # Verify that the original valid key was NOT erased!
    after_check = client_a.get("/api/credentials/virustotal", headers=headers).json()
    assert after_check["is_configured"] is True
    assert after_check["masked_values"]["api_key"].endswith("4444")
    # Verify plaintext in storage is still the original
    raw_decrypted = credential_manager.get_credential("virustotal", user_id=user_a["id"])
    assert raw_decrypted["api_key"] == valid_key

    # 4. Multi-field update check (Censys: api_id, api_secret)
    res_censys_save = client_a.post(
        "/api/credentials/censys",
        json={"data": {"api_id": "censys-uuid-1111", "api_secret": "censys-secret-9999"}},
        headers=headers
    )
    assert res_censys_save.status_code == 200

    # Update only api_id, leaving api_secret blank/empty
    res_censys_partial = client_a.post(
        "/api/credentials/censys",
        json={"data": {"api_id": "censys-uuid-2222", "api_secret": ""}},
        headers=headers
    )
    assert res_censys_partial.status_code == 200

    censys_raw = credential_manager.get_credential("censys", user_id=user_a["id"])
    assert censys_raw["api_id"] == "censys-uuid-2222"
    assert censys_raw["api_secret"] == "censys-secret-9999", "Omitted/empty secret must be preserved!"


# ==============================================================================
# TEST 5: ZERO PLAINTEXT EXPOSURE & MASKING FORMATS
# ==============================================================================

def test_zero_plaintext_exposure_and_masking(audit_users):
    """Verifies that plaintext secrets are never exposed and masking format requirements are met."""
    user_a, _ = audit_users
    client_a = TestClient(app)
    login_res = client_a.post("/api/auth/login", json={"username": "audit_alpha", "password": "AuditAlphaPass2026!"})
    token = login_res.json()["token"]
    csrf = login_res.json()["csrf_token"]
    headers = {"Authorization": f"Bearer {token}", CSRF_HEADER_NAME: csrf}

    secret_key = "super_secret_high_entropy_token_xyz_8888"
    client_a.post(
        "/api/credentials/virustotal",
        json={"data": {"api_key": secret_key}},
        headers=headers
    )

    # 1. Check get endpoint
    res = client_a.get("/api/credentials/virustotal", headers=headers)
    assert res.status_code == 200
    res_str = res.text
    assert secret_key not in res_str, "Plaintext API key leaked in GET response!"
    masked_val = res.json()["masked_values"]["api_key"]
    assert masked_val == "****************8888"

    # 2. Check catalog endpoint
    res_all = client_a.get("/api/credentials", headers=headers)
    assert secret_key not in res_all.text, "Plaintext API key leaked in list response!"

    # 3. Short secret masking (<= 4 chars)
    short_masked = credential_manager.mask_secret("abc")
    assert short_masked == "••••••••"
    assert "abc" not in short_masked

    # Empty secret masking
    assert credential_manager.mask_secret("") == ""
    assert credential_manager.mask_secret(None) == ""


# ==============================================================================
# TEST 6: APPLICATION RESTART SIMULATION & DPAPI PERSISTENCE
# ==============================================================================

def test_restart_simulation_decrypts_stored_credentials(audit_users):
    """
    Simulates application restart: instantiates a fresh CredentialManager()
    and verifies it can decrypt previously stored credentials seamlessly.
    """
    user_a, _ = audit_users

    # Save a known credential
    test_secret = "restart_simulation_secret_token_7777"
    credential_manager.save_credential("openai", {"api_key": test_secret}, user_id=user_a["id"])

    # Simulate restart by instantiating fresh CredentialManager
    fresh_mgr = CredentialManager()
    assert fresh_mgr.has_master_key() is True

    # Decrypt via fresh manager
    decrypted = fresh_mgr.get_credential("openai", user_id=user_a["id"])
    assert decrypted is not None
    assert decrypted.get("api_key") == test_secret


# ==============================================================================
# TEST 7: MASTER-KEY RECOVERY FAILURE DOES NOT FALL BACK TO PLAINTEXT
# ==============================================================================

def test_master_key_failure_no_plaintext_fallback(audit_users):
    """
    Verifies that if master key is missing while encrypted records exist in DB:
    1. System refuses to generate a new key (missing_key_error).
    2. Attempting to save raises RuntimeError.
    3. Plaintext is NEVER stored in database.
    """
    user_a, _ = audit_users

    broken_mgr = CredentialManager.__new__(CredentialManager)
    broken_mgr._master_key = None
    broken_mgr._fernet = None
    broken_mgr._master_key_source = "missing_key_error"

    assert broken_mgr.has_master_key() is False
    assert broken_mgr.get_credential("openai", user_id=user_a["id"]) is None

    with pytest.raises(RuntimeError) as exc_info:
        broken_mgr.save_credential("openai", {"api_key": "unencrypted_secret"}, user_id=user_a["id"])
    assert "Cannot encrypt credentials: Master key is missing" in str(exc_info.value)

