from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def _install_fake_tkinter(monkeypatch, selected_path):
    import tkinter
    from tkinter import filedialog

    class FakeRoot:
        def withdraw(self):
            pass

        def attributes(self, *_args, **_kwargs):
            pass

        def destroy(self):
            pass

    captured = {}

    def fake_picker(**kwargs):
        captured.update(kwargs)
        return selected_path

    monkeypatch.setattr(tkinter, "Tk", lambda: FakeRoot())
    monkeypatch.setattr(filedialog, "askopenfilename", fake_picker)
    return captured


def test_local_tools_status_route_shape():
    resp = client.get("/api/credentials/local-tools/status")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "tools" in data
    ids = {t["id"] for t in data["tools"]}
    assert ids == {"jadx", "jadx_gui", "apktool", "androguard", "yara", "tesseract"}
    for t in data["tools"]:
        for key in ("installed", "version", "executable_path", "path_configured", "status", "test_status", "diagnostic_message"):
            assert key in t


def test_browse_file_route_returns_selected_path(monkeypatch):
    selected = r"C:\Tools\jadx\bin\jadx.bat"
    captured = _install_fake_tkinter(monkeypatch, selected)

    resp = client.post(
        "/api/settings/browse-file",
        json={"title": "Select JADX executable", "initial_dir": r"C:\Tools\jadx\bin"},
    )

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data == {"success": True, "path": selected}
    assert captured["title"] == "Select JADX executable"
    assert captured["initialdir"] == r"C:\Tools\jadx\bin"


def test_browse_file_route_reports_cancel(monkeypatch):
    _install_fake_tkinter(monkeypatch, "")

    resp = client.post("/api/settings/browse-file", json={"title": "Select executable"})

    assert resp.status_code == 200, resp.text
    assert resp.json() == {"success": False, "path": ""}
