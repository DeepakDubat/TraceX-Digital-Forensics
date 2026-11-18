import pytest
import os
import json
from unittest.mock import patch, MagicMock
from backend.app.core.credential_manager import CredentialManager, PROVIDER_CATALOG, credential_manager
from backend.app.config import settings

def test_credential_masking():
    cm = CredentialManager()
    assert cm.mask_secret("") == ""
    assert cm.mask_secret(None) == ""
    assert cm.mask_secret("123") == "••••••••"
    assert cm.mask_secret("abcdefgh") == "****************efgh"
    
    mock_key = "deadbeef00112233445566778899aabbccddeeff00112233445566778899e895"
    masked = cm.mask_secret(mock_key)
    assert masked.startswith("****************")
    assert masked.endswith("e895")
    assert mock_key[:8] not in masked

def test_encryption_decryption_roundtrip(tmp_path):
    with patch.dict(os.environ, {"WORKBENCH_MASTER_KEY": "test_passphrase_for_byok_crypto_123"}):
        cm = CredentialManager()
        assert cm.master_key_source == "environment"

        test_data = {"api_key": "my_super_secret_token_12345678", "url": "https://example.com/api"}
        save_res = cm.save_credential("test_provider", test_data, credential_type="api_key")
        assert save_res["status"] == "success"

        # Verify decryption in memory
        decrypted = cm.get_credential("test_provider")
        assert decrypted == test_data

        # Verify masked retrieval
        masked = cm.get_masked_credential("test_provider")
        assert masked["url"] == "https://example.com/api"
        assert masked["api_key"].startswith("****************")
        assert masked["api_key"].endswith("5678")
        assert "super_secret" not in masked["api_key"]

        # Clean up
        deleted = cm.delete_credential("test_provider")
        assert deleted is True
        assert cm.get_credential("test_provider") is None

def test_catalog_metadata_zero_plaintext_leakage():
    cm = CredentialManager()
    metadata = cm.list_providers_metadata()
    assert len(metadata) >= 20

    for p in metadata:
        assert "id" in p
        assert "name" in p
        assert "category" in p
        assert "fields" in p
        assert "is_configured" in p
        assert "status_badge" in p

        # Verify no unmasked secrets exist in the metadata
        if p.get("masked_values"):
            for k, val in p["masked_values"].items():
                if k in ("api_key", "api_secret", "token", "password"):
                    assert val.startswith("****") or val.startswith("••••") or val == ""

def test_unconfigured_provider_graceful_handling():
    cm = CredentialManager()
    res = cm.test_credential("shodan", ephemeral_data={})
    assert res["connected"] is False
    assert res["status"] in ("Not Configured", "Unknown Provider", "Blocked by Local-Only Mode")

def test_local_only_mode_blocks_external_queries():
    cm = CredentialManager()
    with patch.object(settings, "LOCAL_ONLY_MODE", True):
        res = cm.test_credential("virustotal", ephemeral_data={"api_key": "some_test_key"})
        assert res["connected"] is False
        assert "Local-Only Mode" in res["status"] or "Local-Only Mode" in res["message"]
