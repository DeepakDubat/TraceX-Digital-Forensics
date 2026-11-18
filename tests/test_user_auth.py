"""
User Authentication & Session Management Security Tests
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0
"""

import pytest
import time
from datetime import datetime, timedelta
from fastapi import HTTPException

from backend.app.core.user_auth import (
    hash_password,
    verify_password,
    auth_service,
    MAX_FAILED_ATTEMPTS,
    LOCKOUT_MINUTES
)
from backend.app.database.repository import repo


def test_argon2id_hashing_and_verification():
    """Verify Argon2id derives unique salts, validates correct passwords, and rejects wrong ones."""
    pw = "SuperSecurePass123!"
    h1, s1 = hash_password(pw)
    h2, s2 = hash_password(pw)

    assert h1 != h2, "Different salts must produce different hashes"
    assert s1 != s2, "Salts must be randomly generated per hash"

    assert verify_password(pw, h1, s1) is True
    assert verify_password(pw, h2, s2) is True
    assert verify_password("WrongPassword123!", h1, s1) is False
    assert verify_password("", h1, s1) is False


def test_password_length_enforcement():
    """Verify passwords shorter than 8 characters are rejected."""
    with pytest.raises(ValueError, match="at least 8 characters"):
        hash_password("short")


def test_account_lockout_policy():
    """Verify 5 consecutive failed logins triggers a 15-minute freeze."""
    username = "lockout_test_user"
    email = "lockout@forensics.test"
    password = "CorrectPassword123!"

    # Clean up if exists
    existing = repo.get_user_by_username(username)
    if existing:
        repo.delete_user(existing["id"])

    h, s = hash_password(password)
    user = repo.create_user(
        user_id="test_lockout_id_001",
        username=username,
        email=email,
        password_hash=h,
        salt=s,
        role="investigator"
    )

    # 4 consecutive failures should not lock
    for attempt in range(1, MAX_FAILED_ATTEMPTS):
        with pytest.raises(HTTPException) as exc:
            auth_service.authenticate_user(username, "BadPassword!")
        assert exc.value.status_code == 401
        assert "remaining before lockout" in exc.value.detail

    # 5th failure must trigger 429 Too Many Requests (Lockout)
    with pytest.raises(HTTPException) as exc:
        auth_service.authenticate_user(username, "BadPassword!")
    assert exc.value.status_code == 429
    assert f"Account locked for {LOCKOUT_MINUTES} minutes" in exc.value.detail

    # Subsequent attempt even with correct password must be blocked during freeze
    with pytest.raises(HTTPException) as exc:
        auth_service.authenticate_user(username, password)
    assert exc.value.status_code == 429
    assert "Account temporarily locked" in exc.value.detail

    # Clean up
    repo.delete_user("test_lockout_id_001")


def test_session_lifecycle_and_invalidation():
    """Verify session creation, hashing, and revocation."""
    users = repo.list_users()
    if not users:
        h, s = hash_password("ValidPassword123!")
        user = repo.create_user(
            user_id="test_session_user_001",
            username="session_test_admin",
            email="session_admin@test.local",
            password_hash=h,
            salt=s,
            role="admin"
        )
    else:
        user = users[0]

    token, session_record, csrf_token = auth_service.create_session(user["id"])
    assert len(token) > 30
    assert len(csrf_token) > 30

    # Validate active session
    validated = auth_service.validate_session(token)
    assert validated is not None
    assert validated["user_id"] == user["id"]

    # Invalidate session
    revoked = auth_service.revoke_session(token)
    assert revoked is True

    # Validate again should return None
    assert auth_service.validate_session(token) is None


def test_unauthenticated_requests_strictly_rejected():
    """Verify that unauthenticated requests to protected endpoints return HTTP 401 (No implicit admin fallback)."""
    from fastapi.testclient import TestClient
    from backend.app.main import app

    client = TestClient(app)
    # Clear any leftover cookies on client
    client.cookies.clear()

    # 1. Credentials catalog endpoint without session must return 401
    res = client.get("/api/credentials/providers")
    assert res.status_code == 401
    assert "Authentication required" in res.json()["detail"]

    # 2. Master key status endpoint without session must return 401
    res_mk = client.get("/api/credentials/master-key/status")
    assert res_mk.status_code == 401

    # 3. /me endpoint without session returns authenticated: false
    res_me = client.get("/api/auth/me")
    assert res_me.status_code == 200
    assert res_me.json()["authenticated"] is False
    assert res_me.json()["user"] is None


def test_setup_status_endpoint():
    """Verify setup-status returns setup status and workstation deployment mode."""
    from fastapi.testclient import TestClient
    from backend.app.main import app

    client = TestClient(app)
    res = client.get("/api/auth/setup-status")
    assert res.status_code == 200
    data = res.json()
    assert "setup_required" in data
    assert data["deployment_mode"] == "workstation"


def test_workstation_security_boundary_rejects_remote_access():
    """Verify that remote non-loopback requests are rejected with HTTP 403 in workstation mode."""
    from fastapi.testclient import TestClient
    from backend.app.main import app

    # Simulated remote network client (e.g. 192.168.1.50)
    remote_client = TestClient(app, client=("192.168.1.50", 54321))
    res = remote_client.get("/api/health")
    assert res.status_code == 403
    assert "Remote network access rejected" in res.json()["detail"]

    # Local loopback client (127.0.0.1) is permitted
    local_client = TestClient(app, client=("127.0.0.1", 54321))
    res_local = local_client.get("/api/health")
    assert res_local.status_code == 200

