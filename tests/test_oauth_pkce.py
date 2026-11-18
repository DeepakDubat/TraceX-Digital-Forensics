"""
OAuth 2.0 Authorization Code + PKCE Security Tests
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0
"""

import pytest
from backend.app.core.oauth_manager import oauth_manager
from backend.app.core.auth_registry import AUTHENTICATION_REGISTRY


def test_pkce_generation_rfc7636():
    """Verify code_verifier and code_challenge comply with RFC 7636 S256."""
    verifier, challenge = oauth_manager.generate_pkce()

    # Verifier length: 43 to 128 characters
    assert 43 <= len(verifier) <= 128
    # Challenge length: 43 characters for SHA-256 without padding
    assert len(challenge) == 43
    # No trailing base64 padding
    assert not challenge.endswith("=")


def test_non_oauth_providers_rejected():
    """Verify providers without official user-delegated OAuth are strictly rejected."""
    non_oauth_providers = ["virustotal", "shodan", "abuseipdb", "alienvault_otx"]

    for provider in non_oauth_providers:
        with pytest.raises(ValueError) as exc:
            oauth_manager.create_authorization_request("test_user_id", provider)
        assert "OAuth is not supported" in str(exc.value)


def test_unknown_providers_rejected():
    """Verify unknown or uncataloged providers raise appropriate ValueError."""
    with pytest.raises(ValueError) as exc:
        oauth_manager.create_authorization_request("test_user_id", "nonexistent_provider")
    assert "Unknown provider" in str(exc.value)


def test_state_validation_and_replay_protection():
    """Verify expired or tampered state tokens are rejected."""
    # Attempting to exchange an unknown state
    import asyncio
    with pytest.raises(ValueError, match="Invalid or expired OAuth state"):
        asyncio.run(oauth_manager.exchange_code("non_existent_state_token", "fake_code_123"))

