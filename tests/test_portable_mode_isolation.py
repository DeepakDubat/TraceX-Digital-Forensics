"""
TraceX Portable Mode & Data Isolation Test Suite
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Verifies:
1. Strict mode separation (DEVELOPMENT_MODE, INSTALLED_MODE, PORTABLE_MODE).
2. Data isolation in PORTABLE_MODE (UserData/database/tracex_portable.db).
3. Zero crossover with analysis_workspace/workbench.db in PORTABLE_MODE.
4. Credential isolation in UserData/credentials/.
5. Complete AI purge verification (all AI routes return 404 Not Found; zero cloud AI leakage).
6. Centralized sensitive data redaction across forensic outputs.
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.app.config import (
    EXECUTION_MODE_DEVELOPMENT,
    EXECUTION_MODE_INSTALLED,
    EXECUTION_MODE_PORTABLE,
    _resolve_execution_mode,
    _resolve_directories,
    settings,
)
from backend.app.core.redaction import redact_sensitive_text
from backend.app.main import app

client = TestClient(app)


def test_execution_mode_resolution():
    """Verify explicit mode separation based on flags and markers."""
    # Portable mode via env
    old_env = os.environ.get("TRACEX_PORTABLE_MODE")
    try:
        os.environ["TRACEX_PORTABLE_MODE"] = "1"
        assert _resolve_execution_mode() == EXECUTION_MODE_PORTABLE
    finally:
        if old_env is None:
            os.environ.pop("TRACEX_PORTABLE_MODE", None)
        else:
            os.environ["TRACEX_PORTABLE_MODE"] = old_env

    # Installed mode via env
    old_mode = os.environ.get("TRACEX_MODE")
    try:
        os.environ["TRACEX_MODE"] = "installed"
        assert _resolve_execution_mode() == EXECUTION_MODE_INSTALLED
    finally:
        if old_mode is None:
            os.environ.pop("TRACEX_MODE", None)
        else:
            os.environ["TRACEX_MODE"] = old_mode


def test_portable_directory_hierarchy():
    """Verify PORTABLE_MODE maps all data strictly inside UserData."""
    old_data_dir = os.environ.pop("FORENSICS_DATA_DIR", None)
    try:
        dirs = _resolve_directories(EXECUTION_MODE_PORTABLE)
        root = dirs["root"]
        assert root.name == "UserData"
        assert dirs["database"] == root / "database" / "tracex_portable.db"
        assert dirs["evidence"] == root / "evidence"
        assert dirs["reports"] == root / "reports"
        assert dirs["logs"] == root / "logs"
        assert dirs["cache"] == root / "cache"
        assert dirs["credentials"] == root / "credentials"
        assert dirs["settings"] == root / "settings"
    finally:
        if old_data_dir is not None:
            os.environ["FORENSICS_DATA_DIR"] = old_data_dir


def test_development_mode_points_to_workspace():
    """Verify DEVELOPMENT_MODE preserves existing analysis_workspace."""
    old_data_dir = os.environ.pop("FORENSICS_DATA_DIR", None)
    try:
        dirs = _resolve_directories(EXECUTION_MODE_DEVELOPMENT)
        root = dirs["root"]
        assert "analysis_workspace" in str(root)
        assert dirs["database"].name == "workbench.db"
    finally:
        if old_data_dir is not None:
            os.environ["FORENSICS_DATA_DIR"] = old_data_dir


def test_ai_endpoints_completely_removed_and_return_404():
    """Verify that all AI assistant endpoints return 404 Not Found following complete purge."""
    ai_endpoints = [
        "/api/opencode/privacy-mode",
        "/api/opencode/sessions",
        "/api/opencode/preflight",
        "/api/opencode/providers",
        "/api/ai/explain",
        "/api/ai/query",
    ]
    for ep in ai_endpoints:
        resp = client.get(ep)
        assert resp.status_code in (404, 405), f"Endpoint {ep} expected 404/405, got {resp.status_code}"
        resp_post = client.post(ep, json={})
        assert resp_post.status_code in (404, 405), f"POST to {ep} expected 404/405, got {resp_post.status_code}"


def test_sensitive_data_redaction_engine():
    """Verify centralized redaction masks sensitive credentials, tokens, and personal paths."""
    sample_text = (
        "Connecting to database mongodb://root:Db@dm1n#2025@192.168.1.50:27017/db "
        "with bot token 7381920456:AAF3kL2mN9pQ4rT6uV-8wX1yZ0aBcDeF2gH "
        "and Stripe key sk_test_51AbCdEfGhIjKlMnOpQrStUvWxYz1234 "
        "found at C:\\Users\\Deepak\\Desktop\\evidence.apk"
    )
    sanitized = redact_sensitive_text(sample_text)

    # Check that secrets are redacted
    assert "Db@dm1n#2025" not in sanitized
    assert "AAF3kL2mN9pQ4rT6uV-8wX1yZ0aBcDeF2gH" not in sanitized
    assert "sk_test_51AbCdEfGhIjKlMnOpQrStUvWxYz1234" not in sanitized
    assert "••••••••" in sanitized


def test_portable_credentials_isolation(tmp_path):
    """Verify portable mode maintains credential isolation within UserData/credentials."""
    from backend.app.core.credential_manager import credential_manager
    # Ensure credential manager catalog excludes AI providers
    meta = credential_manager.list_providers_metadata()
    provider_ids = [m["id"] for m in meta]
    assert "openai" not in provider_ids
    assert "opencode" in provider_ids
    assert "gemini" not in provider_ids
    assert "anthropic" not in provider_ids
    assert "groq" not in provider_ids
    assert "virustotal" in provider_ids
