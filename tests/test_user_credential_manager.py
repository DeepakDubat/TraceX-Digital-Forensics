"""
User Credential Manager & Isolation Tests
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0
"""

import pytest
from backend.app.core.credential_manager import credential_manager
from backend.app.core.user_auth import auth_service, hash_password
from backend.app.database.repository import repo


def test_user_credential_isolation():
    """Verify credentials configured by User A are strictly isolated from User B."""
    # Create two test users
    h, s = hash_password("TestPassword123!")
    user_a = repo.create_user("user_a_id", "user_alpha", "alpha@test.local", h, s, "investigator")
    user_b = repo.create_user("user_b_id", "user_beta", "beta@test.local", h, s, "investigator")

    # User A saves OpenAI API key
    credential_manager.save_credential(
        provider_name="openai",
        data={"api_key": "sk-proj-alphaKey1234567890"},
        user_id=user_a["id"]
    )

    # User B saves different OpenAI API key
    credential_manager.save_credential(
        provider_name="openai",
        data={"api_key": "sk-proj-betaKey9999999999"},
        user_id=user_b["id"]
    )

    # Verify retrieval returns respective keys
    creds_a = credential_manager.get_credential("openai", user_id=user_a["id"])
    creds_b = credential_manager.get_credential("openai", user_id=user_b["id"])

    assert creds_a["api_key"] == "sk-proj-alphaKey1234567890"
    assert creds_b["api_key"] == "sk-proj-betaKey9999999999"

    # Clean up
    repo.delete_user("user_a_id")
    repo.delete_user("user_b_id")


def test_whitespace_and_newline_stripping():
    """Verify keys with copy-pasted trailing newlines are sanitized to prevent illegal header errors."""
    dirty_key = "  AIzaSyDirtyKeyWithNewlines12345\r\n  "
    credential_manager.save_credential(
        provider_name="gemini",
        data={"api_key": dirty_key}
    )

    creds = credential_manager.get_credential("gemini")
    assert creds["api_key"] == "AIzaSyDirtyKeyWithNewlines12345"
    assert "\r" not in creds["api_key"]
    assert "\n" not in creds["api_key"]
    credential_manager.delete_credential("gemini")


def test_credential_masking():
    """Verify sensitive keys are masked and never exposed in metadata."""
    secret = "AIzaSySecretTestKey9876543210abcd"
    masked = credential_manager.mask_secret(secret)
    assert masked.startswith("****************")
    assert masked.endswith("abcd")
    assert "9876" not in masked

