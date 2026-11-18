import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from tests.create_fixtures import create_harmless_test_apk

client = TestClient(app)

def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "TraceX" in data["service"] or "Forensics" in data["service"]

def test_api_tools_status():
    res = client.get("/api/tools")
    assert res.status_code == 200
    tools = res.json()
    assert isinstance(tools, list)
    assert any(t["tool_name"] == "Androguard" for t in tools)
    assert any(t["tool_name"] == "YARA" for t in tools)

def test_api_dashboard_stats():
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    stats = res.json()
    assert "total_investigations" in stats
    assert "potential_c2_configurations" in stats

def test_api_apk_upload(tmp_path):
    apk_file = tmp_path / "fixture.apk"
    create_harmless_test_apk(apk_file)

    with open(apk_file, "rb") as f:
        res = client.post(
            "/api/investigations/upload",
            files={"file": ("fixture.apk", f, "application/vnd.android.package-archive")},
            data={"case_reference": "CASE-TEST-001", "local_only_mode": "true"}
        )

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "investigation_id" in data
    assert "sha256" in data

    # Verify status endpoint works
    inv_id = data["investigation_id"]
    status_res = client.get(f"/api/investigations/{inv_id}/status")
    assert status_res.status_code == 200
