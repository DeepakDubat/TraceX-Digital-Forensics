import sys
import shutil
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import httpx

from backend.app.config import settings
from backend.app.integrations.tool_registry import (
    test_androguard_tool as check_androguard_tool,
    test_yara_tool as check_yara_tool,
    test_jadx_tool as check_jadx_tool,
    test_jadx_gui_tool as check_jadx_gui_tool,
    test_apktool_tool as check_apktool_tool,
    test_mobsf_tool as check_mobsf_tool,
    test_tool_execution as run_tool_execution,
    detect_system_tools
)
from backend.app.integrations.mobsf_adapter import test_mobsf_service as check_mobsf_service
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

# ==========================================
# 1. LIVE ANDROGUARD TESTS
# ==========================================
def test_androguard_live_import_and_smoke():
    """Confirms Androguard imports in active interpreter and passes smoke test."""
    res = check_androguard_tool()
    assert res["success"] is True
    assert res["installed"] is True
    assert res["status"] == "INSTALLED / TEST PASSED"
    assert res["test_status"] == "passed"
    assert "Androguard" in res["diagnostic_message"]
    assert res["details"]["python_interpreter"] == sys.executable

# ==========================================
# 2. LIVE YARA TESTS
# ==========================================
def test_yara_live_module_import():
    """Confirms yara-python imports in active interpreter."""
    import yara
    assert getattr(yara, "__version__", None) is not None

def test_yara_live_minimal_rule_compilation():
    """Confirms minimal test rule compiles independently from project rules."""
    import yara
    minimal = yara.compile(source="rule MinimalTest { condition: true }")
    assert len(list(minimal)) == 1

def test_yara_live_application_ruleset_compilation():
    """Confirms application production rule set compiles cleanly with 0 syntax errors."""
    res = check_yara_tool()
    assert res["success"] is True
    assert res["installed"] is True
    assert res["status"] == "INSTALLED / TEST PASSED"
    assert res["test_status"] == "passed"
    assert res["details"]["rules_compiled"] == 5
    assert "yara_rules.yar" in res["diagnostic_message"]

# ==========================================
# 3. JADX DETECTION & EXECUTION TESTS
# ==========================================
def test_jadx_missing_executable():
    """Confirms accurate status and helpful instructions when JADX is not configured."""
    res = check_jadx_tool(custom_path="")
    assert res["success"] is False
    assert res["installed"] is False
    assert "NOT INSTALLED" in res["status"]
    assert "https://github.com/skylot/jadx/releases" in res["diagnostic_message"]
    assert "jadx.bat" in res["diagnostic_message"]

def test_jadx_invalid_configured_path():
    """Confirms failure reported when configured path does not exist on disk."""
    res = check_jadx_tool(custom_path="C:\\nonexistent_path\\jadx.bat")
    assert res["success"] is False
    assert res["installed"] is False
    assert "PATH NOT CONFIGURED" in res["status"]
    assert "does not exist on disk" in res["diagnostic_message"]

def test_jadx_valid_executable_mocked():
    """Confirms version parsing when executable is valid."""
    with patch("backend.app.integrations.tool_registry.Path.is_file", return_value=True), \
         patch("backend.app.integrations.tool_registry.safe_run_command", return_value=(0, "jadx 1.5.0\n", "")):
        res = check_jadx_tool(custom_path="C:\\tools\\jadx\\bin\\jadx.bat")
        assert res["success"] is True
        assert res["installed"] is True
        assert res["status"] == "INSTALLED / TEST PASSED"
        assert res["version"] == "jadx 1.5.0"
        assert "jadx 1.5.0" in res["diagnostic_message"]

def test_jadx_live_verified_cli():
    """Confirms live execution of verified jadx.bat CLI executable if present on host."""
    found_bin = shutil.which("jadx.bat")
    jadx_bat = Path(found_bin) if found_bin else (Path.home() / "Tools" / "bin" / "jadx.bat")
    if jadx_bat.is_file():
        res = check_jadx_tool(custom_path=str(jadx_bat))
        assert res["success"] is True
        assert res["installed"] is True
        assert res["status"] == "INSTALLED / TEST PASSED"
        assert res["details"]["cli_executable"] == str(jadx_bat.resolve())

def test_jadx_gui_launcher_only_explanation():
    """Confirms that providing jadx-gui without CLI triggers clear explanation, not ready status."""
    res = check_jadx_tool(custom_path=r"C:\isolated\jadx-gui.bat")
    assert res["success"] is False
    assert res["status"] == "CLI EXECUTABLE REQUIRED"
    assert "jadx.bat" in res["diagnostic_message"]
    assert "CLI executable" in res["diagnostic_message"]

def test_jadx_gui_tool_live():
    """Confirms testing the JADX GUI launcher specifically.

    Resolves the launcher from the active configuration (or the per-user
    tool directory) instead of a hard-coded developer path, so the test is
    meaningful on any machine that has JADX installed.
    """
    candidates = []
    if settings.JADX_GUI_PATH:
        candidates.append(Path(settings.JADX_GUI_PATH))
    candidates.append(Path.home() / "Tools" / "jadx" / "bin" / "jadx-gui.bat")
    candidates.append(Path.home() / "Tools" / "bin" / "jadx-gui.bat")

    for jadx_gui in candidates:
        if jadx_gui.is_file():
            res = check_jadx_gui_tool(custom_path=str(jadx_gui))
            assert res["success"] is True
            assert res["installed"] is True
            assert res["status"] == "INSTALLED / READY"
            break

# ==========================================
# 4. APKTOOL DETECTION & EXECUTION TESTS
# ==========================================
def test_apktool_missing_executable():
    """Confirms accurate status and instructions when Apktool is not configured.

    Uses a path that cannot exist so the assertion holds on hosts where
    Apktool IS installed (the previous empty-string form made this test
    depend on the machine having no Apktool at all).
    """
    res = check_apktool_tool(custom_path=r"C:\definitely\not\here\apktool.bat")
    assert res["success"] is False
    assert res["installed"] is False
    assert "NOT INSTALLED" in res["status"]
    assert "https://apktool.org/docs/install" in res["diagnostic_message"]

def test_apktool_valid_executable_mocked():
    """Confirms version parsing when Apktool is valid."""
    with patch("backend.app.integrations.tool_registry.Path.is_file", return_value=True), \
         patch("backend.app.integrations.tool_registry.safe_run_command", return_value=(0, "2.9.3\n", "")):
        res = check_apktool_tool(custom_path="C:\\tools\\apktool\\apktool.bat")
        assert res["success"] is True
        assert res["installed"] is True
        assert res["status"] == "INSTALLED / TEST PASSED"
        assert res["version"] == "2.9.3"

# ==========================================
# 5. MOBSF CONFIGURATION & REST API TESTS
# ==========================================
def test_mobsf_port_conflict_detection():
    """Confirms port collision with FastAPI backend (port 8000) is detected and warned."""
    res = check_mobsf_service(url="http://127.0.0.1:8000", api_key="test_api_key_12345")
    assert res["success"] is False
    assert res["status"] == "PORT CONFLICT"
    assert "Port conflict" in res["message"]
    assert "8001" in res["message"]

def test_mobsf_service_unavailable():
    """Confirms clear error message when MobSF host is unreachable."""
    with patch("httpx.Client.get", side_effect=httpx.ConnectError("Connection refused")):
        res = check_mobsf_service(url="http://127.0.0.1:8001", api_key="secret_key_123")
        assert res["success"] is False
        assert res["status"] == "SERVICE UNREACHABLE"
        assert "Cannot connect to MobSF" in res["message"]

def test_mobsf_auth_failure():
    """Confirms HTTP 401/403 returns AUTHENTICATION FAILED status."""
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    with patch("httpx.Client.get", return_value=mock_resp):
        res = check_mobsf_service(url="http://127.0.0.1:8001", api_key="invalid_key")
        assert res["success"] is False
        assert res["status"] == "AUTHENTICATION FAILED"
        assert "Invalid MobSF API Key" in res["message"]

def test_mobsf_valid_response():
    """Confirms HTTP 200 marks MobSF as verified and ready."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("httpx.Client.get", return_value=mock_resp):
        res = check_mobsf_service(url="http://127.0.0.1:8001", api_key="valid_mobsf_token_abc")
        assert res["success"] is True
        assert res["status"] == "INSTALLED / TEST PASSED"
        assert "online at" in res["message"]

def test_mobsf_local_directory_rejection():
    """Confirms local filesystem path is rejected and clearly distinguished from service URL."""
    res = check_mobsf_service(url=r"C:\Tools\.MobSF\tools\jadx\jadx-1.5.0", api_key="test_key")
    assert res["success"] is False
    assert res["status"] == "INVALID URL (LOCAL PATH DETECTED)"
    assert "local filesystem directory" in res["message"]
    assert "http://127.0.0.1:8001" in res["message"]

def test_mobsf_timeout_handling():
    """Confirms timeout handling is caught safely."""
    with patch("httpx.Client.get", side_effect=httpx.TimeoutException("Read timed out")):
        res = check_mobsf_service(url="http://127.0.0.1:8001", api_key="test_key")
        assert res["success"] is False
        assert res["status"] == "TEST TIMEOUT"
        assert "timed out after 5.0 seconds" in res["message"]

# ==========================================
# 6. STRUCTURED STATUS & API ENDPOINT TESTS
# ==========================================
def test_detect_system_tools_structure():
    """Confirms detect_system_tools returns complete structured status model for all 15 forensic tools."""
    tools = detect_system_tools()
    assert len(tools) == 15
    names = [t.tool_name for t in tools]
    assert "Androguard" in names
    assert "YARA" in names
    assert "JADX Decompiler" in names
    assert "Apktool" in names
    assert "MobSF REST Service" in names
    assert "Wireshark / TShark" in names
    assert "Strings Utilities" in names
    assert "File Identification Utilities" in names
    assert "ExifTool" in names
    assert "Tesseract OCR" in names
    assert "Volatility" in names
    assert "Nmap Network Scanner" in names
    assert "Nikto Web Scanner" in names
    assert "OWASP ZAP" in names
    assert "SQLMap" in names

    for t in tools:
        assert t.tool_name
        assert t.status
        assert t.test_status in ("passed", "failed", "not_run", "error")
        assert t.diagnostic_message is not None
        assert t.category is not None

def test_tshark_tool_integration():
    """Tests TShark packet dissector detection and safe arguments."""
    from backend.app.integrations.tool_registry import test_tshark_tool
    res = test_tshark_tool()
    assert res["tool_name"] == "Wireshark / TShark"
    assert "status" in res
    assert res["category"] == "Forensics & Network Dissection"
    assert ".pcap" in res["supported_inputs"]

def test_strings_and_file_utilities_builtin():
    """Confirms built-in pure Python engines are always verified and operational."""
    from backend.app.integrations.tool_registry import test_strings_tool, test_file_util_tool
    s_res = test_strings_tool()
    assert s_res["installed"] is True
    assert s_res["test_status"] == "passed"
    assert "BUILT-IN ACTIVE" in s_res["status"] or "ACCELERATED" in s_res["status"]

    f_res = test_file_util_tool()
    assert f_res["installed"] is True
    assert f_res["test_status"] == "passed"
    assert "BUILT-IN ACTIVE" in f_res["status"]

def test_authorized_target_assessment_boundaries():
    """Confirms Nmap, Nikto, ZAP, and SQLMap enforce authorized scope boundary."""
    from backend.app.integrations.tool_registry import (
        test_nmap_tool, test_nikto_tool, test_zap_tool, test_sqlmap_tool
    )
    for fn, expected_name in [
        (test_nmap_tool, "Nmap Network Scanner"),
        (test_nikto_tool, "Nikto Web Scanner"),
        (test_zap_tool, "OWASP ZAP"),
        (test_sqlmap_tool, "SQLMap")
    ]:
        res = fn()
        assert res["tool_name"] == expected_name
        assert res["category"] == "Authorized Target Assessment"
        assert "details" in res

def test_api_test_tool_androguard_endpoint():
    """Confirms POST /api/settings/test-tool works for Androguard."""
    resp = client.post("/api/settings/test-tool", json={"tool_name": "Androguard"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["status"] == "INSTALLED / TEST PASSED"
    assert "Androguard" in data["message"]

def test_api_test_tool_yara_endpoint():
    """Confirms POST /api/settings/test-tool works for YARA."""
    resp = client.post("/api/settings/test-tool", json={"tool_name": "YARA"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["status"] == "INSTALLED / TEST PASSED"
    assert "yara-python" in data["message"]

def test_credential_redaction_in_tool_responses():
    """Confirms no raw API keys are leaked in tool test responses."""
    resp = client.post("/api/settings/test-mobsf", json={"url": "http://127.0.0.1:8001", "api_key": "SECRET_KEY_XYZ_99999"})
    data = resp.json()
    assert "SECRET_KEY_XYZ_99999" not in str(data)
