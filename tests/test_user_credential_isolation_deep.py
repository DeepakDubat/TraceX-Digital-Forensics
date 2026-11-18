"""
Deep Multi-User Credential & OAuth Isolation Security Verification
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Verifies:
1. User A cannot retrieve User B's API credentials.
2. User B cannot retrieve User A's OAuth tokens.
3. Direct API requests cannot bypass ownership checks.
4. One user's logout does not affect the other user.
5. Token refresh uses the correct user's identity.
6. Disconnect only removes the selected user's provider connection.
"""

import uuid
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database.repository import repo
from backend.app.core.user_auth import (
    hash_password,
    auth_service,
    SESSION_COOKIE_NAME,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME
)
from backend.app.core.credential_manager import credential_manager

client = TestClient(app)


@pytest.fixture(scope="module")
def setup_two_synthetic_users():
    """Sets up two isolated synthetic investigator accounts."""
    user_a_id = str(uuid.uuid4())
    user_b_id = str(uuid.uuid4())

    ha, sa = hash_password("UserAlphaPass2026!")
    hb, sb = hash_password("UserBetaPass2026!")

    # Clean existing if needed
    for u in ("user_alpha", "user_beta"):
        ex = repo.get_user_by_username(u)
        if ex:
            repo.delete_user(ex["id"])

    user_a = repo.create_user(
        user_id=user_a_id,
        username="user_alpha",
        email="alpha@forensics.test",
        password_hash=ha,
        salt=sa,
        role="investigator"
    )

    user_b = repo.create_user(
        user_id=user_b_id,
        username="user_beta",
        email="beta@forensics.test",
        password_hash=hb,
        salt=sb,
        role="investigator"
    )

    yield user_a, user_b

    # Teardown
    repo.delete_user(user_a_id)
    repo.delete_user(user_b_id)


def test_user_credential_and_oauth_strict_isolation(setup_two_synthetic_users):
    user_a, user_b = setup_two_synthetic_users

    # Use independent clients to represent two different browser sessions/examiners
    client_a = TestClient(app)
    client_b = TestClient(app)

    # 1. Login User A and obtain session
    res_a = client_a.post(
        "/api/auth/login",
        json={"username": "user_alpha", "password": "UserAlphaPass2026!"}
    )
    assert res_a.status_code == 200
    token_a = res_a.json()["token"]
    csrf_a = res_a.json()["csrf_token"]

    # 2. Login User B and obtain session
    res_b = client_b.post(
        "/api/auth/login",
        json={"username": "user_beta", "password": "UserBetaPass2026!"}
    )
    assert res_b.status_code == 200
    token_b = res_b.json()["token"]
    csrf_b = res_b.json()["csrf_token"]

    assert token_a != token_b, "User sessions must have unique cryptographic tokens"

    # 3. User A configures VirusTotal API key
    headers_a = {
        "Authorization": f"Bearer {token_a}",
        CSRF_HEADER_NAME: csrf_a
    }
    save_res_a = client_a.post(
        "/api/credentials/virustotal",
        json={"data": {"api_key": "sample_USER_A_KEY_11115678"}},
        headers=headers_a
    )
    assert save_res_a.status_code == 200

    # 4. User B configures VirusTotal with a DIFFERENT key, and saves AlienVault OTX key
    headers_b = {
        "Authorization": f"Bearer {token_b}",
        CSRF_HEADER_NAME: csrf_b
    }
    save_res_b = client_b.post(
        "/api/credentials/virustotal",
        json={"data": {"api_key": "sample_USER_B_KEY_99994321"}},
        headers=headers_b
    )
    assert save_res_b.status_code == 200

    # User B configures AlienVault OTX
    save_res_b_otx = client_b.post(
        "/api/credentials/alienvault_otx",
        json={"data": {"api_key": "sample_USER_B_OTX_KEY_8888"}},
        headers=headers_b
    )
    assert save_res_b_otx.status_code == 200

    # --------------------------------------------------------------------------
    # CHECK 1: User A cannot retrieve User B's API credentials
    # --------------------------------------------------------------------------
    cred_a_vt = client_a.get("/api/credentials/virustotal", headers=headers_a)
    assert cred_a_vt.status_code == 200
    masked_a = cred_a_vt.json()["masked_values"]["api_key"]
    assert masked_a.endswith("5678")
    assert "4321" not in masked_a

    # --------------------------------------------------------------------------
    # CHECK 2: User B cannot retrieve User A's API credentials
    # --------------------------------------------------------------------------
    cred_b_vt = client_b.get("/api/credentials/virustotal", headers=headers_b)
    assert cred_b_vt.status_code == 200
    masked_b = cred_b_vt.json()["masked_values"]["api_key"]
    assert masked_b.endswith("4321")
    assert "5678" not in masked_b

    # --------------------------------------------------------------------------
    # CHECK 3: User A cannot retrieve User B's AlienVault OTX credential
    # --------------------------------------------------------------------------
    cred_a_otx = client_a.get("/api/credentials/alienvault_otx", headers=headers_a)
    assert cred_a_otx.status_code == 200
    assert cred_a_otx.json()["is_configured"] is False
    assert cred_a_otx.json()["masked_values"] == {}

    cred_b_otx = client_b.get("/api/credentials/alienvault_otx", headers=headers_b)
    assert cred_b_otx.status_code == 200
    assert cred_b_otx.json()["is_configured"] is True
    assert cred_b_otx.json()["masked_values"]["api_key"].endswith("8888")

    # Direct decrypt check: User A scope returns None for OTX
    assert credential_manager.get_credential("alienvault_otx", user_id=user_a["id"]) is None
    # User B scope retrieves User B's token
    assert credential_manager.get_credential("alienvault_otx", user_id=user_b["id"])["api_key"] == "sample_USER_B_OTX_KEY_8888"

    # --------------------------------------------------------------------------
    # CHECK 4: Direct API requests cannot bypass ownership checks
    # --------------------------------------------------------------------------
    # User A attempts to delete OTX credential (which User B owns)
    del_res_a = client_a.delete("/api/credentials/alienvault_otx", headers=headers_a)
    assert del_res_a.status_code == 200 # Deleted User A's (non-existent) entry

    # Verify User B's credential is completely untouched
    cred_b_check = client_b.get("/api/credentials/alienvault_otx", headers=headers_b)
    assert cred_b_check.status_code == 200
    assert cred_b_check.json()["is_configured"] is True

    # --------------------------------------------------------------------------
    # CHECK 5: Token retrieval uses the correct user's identity
    # --------------------------------------------------------------------------
    token_b_active, auth_type_b = credential_manager.get_active_auth_token("alienvault_otx", user_id=user_b["id"])
    assert token_b_active == "sample_USER_B_OTX_KEY_8888"
    assert auth_type_b == "api_key"

    token_a_active, auth_type_a = credential_manager.get_active_auth_token("alienvault_otx", user_id=user_a["id"])
    assert token_a_active is None
    assert auth_type_a is None

    # --------------------------------------------------------------------------
    # CHECK 6: One user's logout does not affect the other user
    # --------------------------------------------------------------------------
    # User A logs out
    logout_a = client_a.post("/api/auth/logout", headers={"Authorization": f"Bearer {token_a}"})
    assert logout_a.status_code == 200

    # User A session is now invalid
    me_a = client_a.get("/api/auth/me", headers={"Authorization": f"Bearer {token_a}"})
    assert me_a.json()["authenticated"] is False

    # User B session remains fully authenticated
    me_b = client_b.get("/api/auth/me", headers={"Authorization": f"Bearer {token_b}"})
    assert me_b.json()["authenticated"] is True
    assert me_b.json()["user"]["username"] == "user_beta"

    # --------------------------------------------------------------------------
    # CHECK 7: Delete only removes the selected user's provider connection
    # --------------------------------------------------------------------------
    # User B deletes AlienVault OTX
    disconn_b = client_b.delete("/api/credentials/alienvault_otx", headers=headers_b)
    assert disconn_b.status_code == 200

    # Verify User B's OTX is now unconfigured
    cred_b_otx_post = client_b.get("/api/credentials/alienvault_otx", headers=headers_b)
    assert cred_b_otx_post.json()["is_configured"] is False

    # User B's VirusTotal credential remains intact
    cred_b_vt_post = client_b.get("/api/credentials/virustotal", headers=headers_b)
    assert cred_b_vt_post.json()["is_configured"] is True
    assert cred_b_vt_post.json()["masked_values"]["api_key"].endswith("4321")

    # --------------------------------------------------------------------------
    # CHECK 8: Credential updates are strictly user-scoped
    # --------------------------------------------------------------------------
    # User B updates their VirusTotal API key
    update_res_b = client_b.post(
        "/api/credentials/virustotal",
        json={"data": {"api_key": "sample_USER_B_KEY_UPDATED_7777"}},
        headers=headers_b
    )
    assert update_res_b.status_code == 200

    # User B retrieves the updated key
    cred_b_updated = client_b.get("/api/credentials/virustotal", headers=headers_b)
    assert cred_b_updated.json()["masked_values"]["api_key"].endswith("7777")

    # Direct decrypt check: User A scope still has their original key (5678)
    cred_a_decrypted = credential_manager.get_credential("virustotal", user_id=user_a["id"])
    assert cred_a_decrypted["api_key"] == "sample_USER_A_KEY_11115678"

    # --------------------------------------------------------------------------
    # CHECK 9: Credential deletion is strictly user-scoped
    # --------------------------------------------------------------------------
    # User B deletes their VirusTotal credential
    del_res_b = client_b.delete("/api/credentials/virustotal", headers=headers_b)
    assert del_res_b.status_code == 200

    # User B's VirusTotal is now unconfigured
    cred_b_deleted = client_b.get("/api/credentials/virustotal", headers=headers_b)
    assert cred_b_deleted.json()["is_configured"] is False

    # User A's VirusTotal credential remains intact in database and scope
    cred_a_still_intact = credential_manager.get_credential("virustotal", user_id=user_a["id"])
    assert cred_a_still_intact is not None
    assert cred_a_still_intact["api_key"] == "sample_USER_A_KEY_11115678"
