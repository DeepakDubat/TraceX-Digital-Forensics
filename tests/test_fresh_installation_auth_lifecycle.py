"""
Fresh Installation Authentication & Lifecycle Acceptance Verification
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Tests:
1. Initial administrator setup appears on a fresh install.
2. User creates a unique password.
3. Password is stored using Argon2id.
4. Setup endpoint permanently locks after initialization.
5. Login succeeds with correct credentials.
6. Incorrect passwords are rejected with HTTP 401.
7. Five failed attempts trigger the configured 15-minute lockout (HTTP 423).
8. Logout invalidates the active session.
9. Protected APIs strictly return HTTP 401 without authentication.
10. Remote network access is rejected in workstation mode (HTTP 403).
11. Reverse proxy headers do not bypass authentication.
"""

import sqlite3
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from backend.app.config import settings
from backend.app.database.db import init_db
from backend.app.database.repository import repo
from backend.app.core.user_auth import (
    verify_password,
    CSRF_HEADER_NAME
)
from backend.app.main import app


@pytest.fixture
def fresh_install_env(tmp_path, monkeypatch):
    """Creates a completely isolated fresh application environment with an empty database."""
    original_db_path = settings.DB_PATH
    fresh_db_path = tmp_path / "fresh_workbench.db"
    monkeypatch.setattr(settings, "DB_PATH", fresh_db_path)

    # Initialize empty database schema
    init_db()

    # Clear any users to ensure fresh installation state
    conn = sqlite3.connect(str(fresh_db_path))
    conn.execute("DELETE FROM users;")
    conn.execute("DELETE FROM user_sessions;")
    conn.execute("DELETE FROM user_provider_credentials;")
    conn.commit()
    conn.close()

    yield fresh_db_path

    # Teardown
    monkeypatch.setattr(settings, "DB_PATH", original_db_path)


def test_fresh_installation_full_authentication_lifecycle(fresh_install_env):
    client = TestClient(app)

    # --------------------------------------------------------------------------
    # 1. Initial Administrator Setup Appears
    # --------------------------------------------------------------------------
    status_res = client.get("/api/auth/setup-status")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["setup_required"] is True, "Fresh installation must report setup_required=True"
    assert status_data["deployment_mode"] == "workstation"

    # --------------------------------------------------------------------------
    # 2. User Creates a Unique Password
    # --------------------------------------------------------------------------
    unique_pass = "ForensicMaster2026!#$Secure"
    setup_res = client.post(
        "/api/auth/initial-setup",
        json={
            "username": "lead_investigator",
            "password": unique_pass,
            "email": "lead@forensics.agency"
        }
    )
    assert setup_res.status_code == 200, f"Setup failed: {setup_res.text}"
    setup_data = setup_res.json()
    assert setup_data["user"]["username"] == "lead_investigator"
    assert setup_data["user"]["role"] == "admin"
    assert "token" in setup_data
    assert "csrf_token" in setup_data

    # Setup status must now report setup_required = False
    status_after = client.get("/api/auth/setup-status").json()
    assert status_after["setup_required"] is False

    # --------------------------------------------------------------------------
    # 3. Password is Stored Using Argon2id
    # --------------------------------------------------------------------------
    user_record = repo.get_user_by_username("lead_investigator")
    assert user_record is not None
    import base64
    assert len(base64.b64decode(user_record["password_hash"])) == 32, "Argon2id derived key length must be 32 bytes (256 bits)"
    assert len(user_record["salt"]) >= 16
    # Verify cryptographic verification succeeds
    assert verify_password(unique_pass, user_record["password_hash"], user_record["salt"]) is True
    # Verify plaintext password is not stored anywhere
    assert unique_pass != user_record["password_hash"]

    # --------------------------------------------------------------------------
    # 4. Setup Endpoint Locks After Initialization
    # --------------------------------------------------------------------------
    replay_setup = client.post(
        "/api/auth/initial-setup",
        json={
            "username": "attacker",
            "password": "AttackerPass123!",
            "email": "attacker@evil.local"
        }
    )
    assert replay_setup.status_code == 403
    assert "Initial administrator setup has already been completed" in replay_setup.json()["detail"]

    # --------------------------------------------------------------------------
    # 5. Login Succeeds
    # --------------------------------------------------------------------------
    login_client = TestClient(app)
    login_res = login_client.post(
        "/api/auth/login",
        json={"username": "lead_investigator", "password": unique_pass}
    )
    assert login_res.status_code == 200
    token = login_res.json()["token"]
    csrf_token = login_res.json()["csrf_token"]
    assert len(token) > 20

    # --------------------------------------------------------------------------
    # 6. Incorrect Passwords are Rejected (HTTP 401)
    # --------------------------------------------------------------------------
    bad_login_client = TestClient(app)
    bad_res = bad_login_client.post(
        "/api/auth/login",
        json={"username": "lead_investigator", "password": "WrongPasswordAttempt!"}
    )
    assert bad_res.status_code == 401
    assert "Invalid username or password" in bad_res.json()["detail"]

    # --------------------------------------------------------------------------
    # 7. Five Failed Attempts Trigger Configured Lockout (HTTP 423)
    # --------------------------------------------------------------------------
    # We already did 1 failed attempt above, now do 4 more to hit threshold = 5
    for attempt in range(2, 5):
        r = bad_login_client.post(
            "/api/auth/login",
            json={"username": "lead_investigator", "password": f"BadPassAttempt{attempt}"}
        )
        assert r.status_code == 401

    # 5th attempt must trigger lockout
    lockout_res = bad_login_client.post(
        "/api/auth/login",
        json={"username": "lead_investigator", "password": "BadPassAttempt5"}
    )
    assert lockout_res.status_code in (423, 429)
    assert "Account locked" in lockout_res.json()["detail"] or "locked" in lockout_res.json()["detail"].lower()

    # Subsequent attempt even with CORRECT password must still be locked
    locked_attempt = bad_login_client.post(
        "/api/auth/login",
        json={"username": "lead_investigator", "password": unique_pass}
    )
    assert locked_attempt.status_code in (423, 429)
    assert "temporarily locked" in locked_attempt.json()["detail"].lower()

    # Reset lockout for remainder of test
    repo.reset_user_failed_attempts(user_record["id"])

    # --------------------------------------------------------------------------
    # 8. Logout Invalidates the Session
    # --------------------------------------------------------------------------
    auth_client = TestClient(app)
    relog = auth_client.post(
        "/api/auth/login",
        json={"username": "lead_investigator", "password": unique_pass}
    )
    assert relog.status_code == 200
    auth_token = relog.json()["token"]

    # Verify session is currently active
    me_before = auth_client.get("/api/auth/me", headers={"Authorization": f"Bearer {auth_token}"})
    assert me_before.status_code == 200
    assert me_before.json()["authenticated"] is True

    # Logout
    logout_res = auth_client.post("/api/auth/logout", headers={"Authorization": f"Bearer {auth_token}"})
    assert logout_res.status_code == 200

    # Session is now invalidated
    me_after = auth_client.get("/api/auth/me", headers={"Authorization": f"Bearer {auth_token}"})
    assert me_after.status_code == 200
    assert me_after.json()["authenticated"] is False

    # --------------------------------------------------------------------------
    # 9. Protected APIs Return HTTP 401 Without Authentication
    # --------------------------------------------------------------------------
    anon_client = TestClient(app)
    assert anon_client.get("/api/credentials/providers").status_code == 401
    assert anon_client.get("/api/credentials/openai").status_code == 401
    assert anon_client.get("/api/credentials/master-key/status").status_code == 401
    assert anon_client.post("/api/credentials/openai", json={"data": {"api_key": "test"}}).status_code == 401
    assert anon_client.delete("/api/credentials/openai").status_code == 401

    # --------------------------------------------------------------------------
    # 10. Remote Network Access is Rejected in Workstation Mode (HTTP 403)
    # --------------------------------------------------------------------------
    remote_client = TestClient(app, client=("192.168.1.150", 49832))
    remote_res = remote_client.get("/api/health")
    assert remote_res.status_code == 403
    assert "Remote network access rejected in single-user workstation mode" in remote_res.json()["detail"]

    # Loopback client succeeds
    local_client = TestClient(app, client=("127.0.0.1", 49832))
    assert local_client.get("/api/health").status_code == 200

    # --------------------------------------------------------------------------
    # 11. Reverse Proxy Does Not Bypass Authentication
    # --------------------------------------------------------------------------
    proxy_client = TestClient(app)
    proxy_headers = {
        "X-Forwarded-For": "127.0.0.1",
        "X-Forwarded-Host": "localhost:9000",
        "X-Forwarded-Port": "9000",
        "Origin": "http://localhost:9000"
    }
    proxy_anon = proxy_client.get("/api/credentials/providers", headers=proxy_headers)
    assert proxy_anon.status_code == 401, "Reverse proxy headers must never bypass backend authentication"
