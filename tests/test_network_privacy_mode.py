import pytest
import os
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.config import settings
from backend.app.core.network_mode import (
    NetworkMode,
    get_current_network_mode,
    set_network_mode,
    init_network_mode,
)
from backend.app.core.credential_manager import credential_manager
from backend.app.database.repository import Repository

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_network_mode_state():
    """Ensure tests start in a clean state and restore LOCAL_ONLY afterwards."""
    set_network_mode(NetworkMode.LOCAL_ONLY)
    yield
    # Teardown: restore LOCAL_ONLY mode
    set_network_mode(NetworkMode.LOCAL_ONLY)


def test_01_default_mode_is_local_only():
    """Scenario 1: Fresh or reset system defaults to LOCAL_ONLY mode."""
    set_network_mode(NetworkMode.LOCAL_ONLY)
    mode_info = get_current_network_mode()
    assert mode_info["mode"] == "LOCAL_ONLY"
    assert mode_info["local_only_mode"] is True
    assert settings.LOCAL_ONLY_MODE is True


def test_02_get_system_network_mode_endpoint():
    """Scenario 2: GET /api/system/network-mode returns accurate schema and active state."""
    set_network_mode(NetworkMode.LOCAL_ONLY)
    resp = client.get("/api/system/network-mode")
    assert resp.status_code == 200
    data = resp.json()

    assert data["success"] is True
    assert data["mode"] == "LOCAL_ONLY"
    assert data["local_only_mode"] is True
    assert "local computer" in data["description"].lower()
    assert "evidence_stays_local" in data["privacy_guarantees"]
    assert data["available_modes"] == ["LOCAL_ONLY", "HYBRID"]

    # Test compatibility route GET /api/network-mode
    resp_compat = client.get("/api/network-mode")
    assert resp_compat.status_code == 200
    assert resp_compat.json()["mode"] == "LOCAL_ONLY"


def test_03_post_switch_to_hybrid_mode():
    """Scenario 3: POST /api/system/network-mode with HYBRID switches backend mode and settings."""
    resp = client.post("/api/system/network-mode", json={"mode": "HYBRID"})
    assert resp.status_code == 200
    data = resp.json()

    assert data["success"] is True
    assert data["mode"] == "HYBRID"
    assert data["local_only_mode"] is False
    assert settings.LOCAL_ONLY_MODE is False
    assert get_current_network_mode()["mode"] == "HYBRID"


def test_04_shodan_blocked_in_local_only_mode():
    """Scenario 4: When in LOCAL_ONLY, Shodan connection test returns 'Blocked by Local-Only Mode' immediately."""
    set_network_mode(NetworkMode.LOCAL_ONLY)
    assert settings.LOCAL_ONLY_MODE is True

    result = credential_manager.test_credential("shodan", {"api_key": "dummy_shodan_key_12345"})
    assert result["connected"] is False
    assert result["status"] == "Blocked by Local-Only Mode"
    assert "Local-Only Mode" in result["message"]

    # Also verify through the API endpoint
    api_resp = client.post(
        "/api/credentials/shodan/test",
        json={"api_key": "dummy_shodan_key_12345"},
    )
    assert api_resp.status_code == 200
    api_data = api_resp.json()
    assert api_data["connected"] is False
    assert api_data["status"] == "Blocked by Local-Only Mode"


def test_05_shodan_dispatches_in_hybrid_with_invalid_key():
    """Scenario 5: When in HYBRID mode, Shodan test attempts network connection and reports 401 for bad key."""
    set_network_mode(NetworkMode.HYBRID)
    assert settings.LOCAL_ONLY_MODE is False

    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = "Invalid API key"

    with patch("httpx.Client.get", return_value=mock_resp):
        result = credential_manager.test_credential("shodan", {"api_key": "invalid_test_key"})
        assert result["connected"] is False
        assert result["status"] == "Authentication Failed (401)"
        assert "Invalid" in result["message"]


def test_06_shodan_connected_in_hybrid_with_valid_key():
    """Scenario 6: When in HYBRID mode, Shodan test succeeds when API returns 200 OK."""
    set_network_mode(NetworkMode.HYBRID)
    assert settings.LOCAL_ONLY_MODE is False

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query_credits": 100,
    }

    with patch("httpx.Client.get", return_value=mock_resp):
        result = credential_manager.test_credential("shodan", {"api_key": "valid_test_key_12345"})
        assert result["connected"] is True
        assert result["status"] == "Connected"
        assert "Connected (100 query credits available)" in result["message"]


def test_07_switching_back_to_local_only_immediately_blocks():
    """Scenario 7: Toggling back to LOCAL_ONLY instantly blocks external requests with no restart."""
    set_network_mode(NetworkMode.HYBRID)
    assert settings.LOCAL_ONLY_MODE is False

    # Switch back via API
    resp = client.post("/api/system/network-mode", json={"mode": "LOCAL_ONLY"})
    assert resp.status_code == 200
    assert resp.json()["mode"] == "LOCAL_ONLY"
    assert settings.LOCAL_ONLY_MODE is True

    # Test Shodan immediately
    result = credential_manager.test_credential("shodan", {"api_key": "dummy_key"})
    assert result["connected"] is False
    assert result["status"] == "Blocked by Local-Only Mode"


def test_08_restart_simulation_restores_persisted_mode():
    """Scenario 8: Simulating app restart via init_network_mode() loads persisted state from SQLite."""
    # Persist HYBRID
    set_network_mode(NetworkMode.HYBRID)
    assert settings.LOCAL_ONLY_MODE is False

    # Force in-memory settings to LOCAL_ONLY as if a new process launched
    settings.LOCAL_ONLY_MODE = True

    # Call startup initializer
    restored_mode = init_network_mode()
    assert restored_mode == "HYBRID"
    assert settings.LOCAL_ONLY_MODE is False
    assert get_current_network_mode()["mode"] == "HYBRID"


def test_09_saved_credentials_remain_intact_across_mode_changes():
    """Scenario 9: Saved credentials and masked values persist when toggling between LOCAL_ONLY and HYBRID."""
    with patch.dict(os.environ, {"WORKBENCH_MASTER_KEY": "test_passphrase_for_mode_switch_123"}):
        credential_manager.save_credential("virustotal", {"api_key": "vt_secret_test_key_99887766"})

        # Verify saved in LOCAL_ONLY
        set_network_mode(NetworkMode.LOCAL_ONLY)
        masked_local = credential_manager.get_masked_credential("virustotal")
        assert masked_local["api_key"].endswith("7766")

        # Switch to HYBRID
        set_network_mode(NetworkMode.HYBRID)
        masked_hybrid = credential_manager.get_masked_credential("virustotal")
        assert masked_hybrid["api_key"] == masked_local["api_key"]

        # Decrypted secret remains fully accessible for authorized queries in HYBRID
        raw = credential_manager.get_credential("virustotal")
        assert raw["api_key"] == "vt_secret_test_key_99887766"

        # Cleanup
        credential_manager.delete_credential("virustotal")


def test_10_local_tools_unaffected_by_network_mode():
    """Scenario 10: Local forensic tools (YARA, JADX, Androguard) operate normally in either mode."""
    for mode in [NetworkMode.LOCAL_ONLY, NetworkMode.HYBRID]:
        set_network_mode(mode)
        # YARA test does not make external network calls
        result = credential_manager.test_credential("yara")
        # Should not be blocked by local-only mode
        assert "Blocked by Local-Only Mode" not in result["status"]


def test_11_other_threat_intel_adhere_to_network_mode():
    """Scenario 11: VirusTotal, AbuseIPDB, AlienVault OTX all block when LOCAL_ONLY, dispatch when HYBRID."""
    providers = ["virustotal", "abuseipdb", "alienvault_otx", "urlscan"]

    # In LOCAL_ONLY mode, all external providers are blocked
    set_network_mode(NetworkMode.LOCAL_ONLY)
    for p in providers:
        res = credential_manager.test_credential(p, {"api_key": "some_dummy_key"})
        assert res["connected"] is False
        assert res["status"] == "Blocked by Local-Only Mode", f"Provider {p} should be blocked in LOCAL_ONLY"

    # In HYBRID mode, none are blocked by Local-Only Mode
    set_network_mode(NetworkMode.HYBRID)
    for p in providers:
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "unauthorized"
        with patch("httpx.Client.get", return_value=mock_resp):
            res = credential_manager.test_credential(p, {"api_key": "invalid_key"})
            assert res["status"] != "Blocked by Local-Only Mode", f"Provider {p} should not be blocked in HYBRID"


def test_12_invalid_mode_rejected():
    """Scenario 12: Sending an unsupported mode returns 400 Bad Request."""
    resp = client.post("/api/system/network-mode", json={"mode": "INVALID_MODE"})
    assert resp.status_code == 400
    assert "Invalid network mode" in resp.json()["detail"]


def test_13_catalog_metadata_reflects_blocked_badge():
    """Scenario 13: Provider metadata returns 'BLOCKED BY LOCAL-ONLY MODE' badge when in LOCAL_ONLY."""
    set_network_mode(NetworkMode.LOCAL_ONLY)
    catalog = credential_manager.list_providers_metadata()
    shodan_item = next((item for item in catalog if item["id"] == "shodan"), None)
    assert shodan_item is not None
    assert shodan_item.get("blocked_by_local_only") is True
    assert shodan_item.get("status_badge") == "local_only_blocked"
    assert "BLOCKED BY LOCAL-ONLY MODE" in shodan_item.get("display_status", "")

    # In HYBRID mode, blocked badge is not applied
    set_network_mode(NetworkMode.HYBRID)
    catalog_hybrid = credential_manager.list_providers_metadata()
    shodan_hybrid = next((item for item in catalog_hybrid if item["id"] == "shodan"), None)
    assert shodan_hybrid is not None
    assert shodan_hybrid.get("blocked_by_local_only") is False
    assert shodan_hybrid.get("status_badge") != "local_only_blocked"
