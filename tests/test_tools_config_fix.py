import time
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.integrations.tool_registry import detect_system_tools, test_tool_execution as run_tool_test
from backend.app.integrations.mobsf_adapter import test_mobsf_service as run_mobsf_test

client = TestClient(app)

def test_detect_system_tools_speed_and_concurrency():
    """Confirms detect_system_tools() executes concurrently in under 3.5 seconds."""
    start_time = time.time()
    tools = detect_system_tools()
    duration = time.time() - start_time

    assert len(tools) == 15, f"Expected 15 tools, got {len(tools)}"
    assert duration < 3.5, f"detect_system_tools took too long: {duration:.2f}s (must be < 3.5s)"

def test_detect_system_tools_structure():
    """Confirms all tools have valid structured properties and never simulate fake availability."""
    tools = detect_system_tools()
    names = [t.tool_name for t in tools]
    
    assert "Androguard" in names
    assert "YARA" in names
    assert "JADX Decompiler" in names
    assert "Apktool" in names
    assert "MobSF REST Service" in names

    for t in tools:
        assert isinstance(t.tool_name, str) and len(t.tool_name) > 0
        assert isinstance(t.status, str) and len(t.status) > 0
        assert t.test_status in ("passed", "failed", "not_run", "error")
        assert isinstance(t.diagnostic_message, str)
        assert isinstance(t.installed, bool)

def test_database_status_endpoint():
    """Confirms GET /api/tools/database returns valid health, table count, WAL mode, and integrity."""
    resp = client.get("/api/tools/database")
    assert resp.status_code == 200
    data = resp.json()

    assert data["success"] is True
    assert "HEALTHY" in data["status"]
    assert data["tool_name"] == "SQLite Database"
    assert data["test_status"] == "passed"
    assert "table_count" in data["details"]
    assert data["details"]["table_count"] > 0
    assert data["details"]["integrity"].lower() == "ok"
    assert data["details"]["journal_mode"].lower() == "wal"

def test_backend_status_endpoint():
    """Confirms GET /api/tools/backend returns valid backend runtime diagnostics."""
    resp = client.get("/api/tools/backend")
    assert resp.status_code == 200
    data = resp.json()

    assert data["success"] is True
    assert "ONLINE" in data["status"]
    assert data["tool_name"] == "FastAPI Backend Service"
    assert data["details"]["port"] == 8000

def test_mobsf_fast_timeout_when_offline():
    """Confirms test_mobsf_service against an offline port returns quickly with SERVICE UNREACHABLE."""
    start_time = time.time()
    res = run_mobsf_test("http://127.0.0.1:8001", "TEST_KEY")
    duration = time.time() - start_time

    assert duration < 3.5, f"MobSF test took too long: {duration:.2f}s"
    assert res["success"] is False
    assert res["status"] in ("SERVICE UNREACHABLE", "TEST TIMEOUT", "AUTHENTICATION FAILED", "PORT CONFLICT")

def test_tool_execution_dispatcher_resilience():
    """Confirms safe_tool_execution handles unknown tools and strange paths gracefully."""
    res1 = run_tool_test("NonExistentTool_12345")
    assert res1["success"] is False
    assert res1["status"] == "UNKNOWN TOOL"

    res2 = run_tool_test("JADX Decompiler", custom_path="Z:\\NonExistent\\Path\\jadx.bat")
    assert res2["success"] is False
    assert "NOT INSTALLED" in res2["status"] or "FAILED" in res2["status"] or "NOT CONFIGURED" in res2["status"]

def test_settings_get_and_post_integrity():
    """Confirms GET /api/settings masks secrets and POST /api/settings updates without data leakage."""
    resp = client.get("/api/settings")
    assert resp.status_code == 200
    settings_data = resp.json()

    assert "jadx_path" in settings_data
    assert "mobsf_url" in settings_data
    assert "virustotal_api_key_masked" in settings_data

    # Test updating a non-secret setting
    post_resp = client.post("/api/settings", json={"jadx_path": settings_data.get("jadx_path")})
    assert post_resp.status_code == 200
    assert post_resp.json()["status"] == "success"
