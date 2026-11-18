import os
import sys
import tempfile
import shutil
from pathlib import Path
import pytest

# SEC-QA-001: Automatic isolation of test database from production workbench.db
if not os.environ.get("FORENSICS_DATA_DIR"):
    _pytest_temp_workspace = Path(tempfile.mkdtemp(prefix="tracex_pytest_workspace_"))
    os.environ["FORENSICS_DATA_DIR"] = str(_pytest_temp_workspace)
    from backend.app.config import settings, BASE_DIR
    settings.DATA_ROOT = _pytest_temp_workspace
    settings.DB_PATH = _pytest_temp_workspace / "workbench.db"
    settings.RULES_DIR = BASE_DIR / "rules"
    from backend.app.database.db import init_db
    init_db()

from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database.repository import repo
from backend.app.core.user_auth import (
    auth_service,
    hash_password,
    SESSION_COOKIE_NAME,
    CSRF_COOKIE_NAME
)

_test_session_token = None
_test_csrf_token = None

EXEMPT_TEST_MODULES = (
    "test_user_auth",
    "test_fresh_installation_auth_lifecycle",
    "test_user_credential_isolation_deep",
    "test_credentials_security_deep",
    "test_tracex_security_hardening",
    "test_manager_worker_architecture",
)

def _is_exempt_test():
    current_test = os.environ.get("PYTEST_CURRENT_TEST", "")
    return any(mod in current_test for mod in EXEMPT_TEST_MODULES)

def get_or_create_test_session():
    global _test_session_token, _test_csrf_token
    if _test_session_token:
        sess = auth_service.validate_session(_test_session_token)
        if sess:
            return _test_session_token, _test_csrf_token

    user = repo.get_user_by_username("admin")
    if not user:
        user_id = "test-admin-uuid-001"
        h, s = hash_password("AdminTestPass2026!")
        repo.create_user(
            user_id=user_id,
            username="admin",
            email="admin@test.local",
            password_hash=h,
            salt=s,
            role="admin"
        )
        user = repo.get_user_by_username("admin")

    raw_token, session_record, csrf = auth_service.create_session(user["id"])
    _test_session_token = raw_token
    _test_csrf_token = csrf
    return _test_session_token, _test_csrf_token

_orig_request = TestClient.request
_orig_stream = TestClient.stream

def _patched_request(self, method, url, *args, **kwargs):
    if _is_exempt_test():
        return _orig_request(self, method, url, *args, **kwargs)

    headers = kwargs.get("headers") or {}
    if isinstance(headers, dict) and (headers.get("X-Anonymous") or headers.get("X-Unauthenticated")):
        new_headers = {k: v for k, v in headers.items() if k not in ("X-Anonymous", "X-Unauthenticated")}
        kwargs["headers"] = new_headers
        return _orig_request(self, method, url, *args, **kwargs)

    cookies = kwargs.get("cookies") or {}
    has_auth_cookie = SESSION_COOKIE_NAME in cookies or (hasattr(self, "cookies") and SESSION_COOKIE_NAME in self.cookies)
    has_auth_header = isinstance(headers, dict) and any(
        k.lower() in ("authorization", "x-api-key") for k in headers.keys()
    )

    if not has_auth_cookie and not has_auth_header:
        token, csrf = get_or_create_test_session()
        new_cookies = dict(cookies)
        new_cookies[SESSION_COOKIE_NAME] = token
        new_cookies[CSRF_COOKIE_NAME] = csrf
        kwargs["cookies"] = new_cookies
        if isinstance(headers, dict) and "x-csrf-token" not in [k.lower() for k in headers.keys()]:
            new_headers = dict(headers)
            new_headers["x-csrf-token"] = csrf
            kwargs["headers"] = new_headers

    return _orig_request(self, method, url, *args, **kwargs)

def _patched_stream(self, method, url, *args, **kwargs):
    if _is_exempt_test():
        return _orig_stream(self, method, url, *args, **kwargs)

    headers = kwargs.get("headers") or {}
    if isinstance(headers, dict) and (headers.get("X-Anonymous") or headers.get("X-Unauthenticated")):
        new_headers = {k: v for k, v in headers.items() if k not in ("X-Anonymous", "X-Unauthenticated")}
        kwargs["headers"] = new_headers
        return _orig_stream(self, method, url, *args, **kwargs)

    cookies = kwargs.get("cookies") or {}
    has_auth_cookie = SESSION_COOKIE_NAME in cookies or (hasattr(self, "cookies") and SESSION_COOKIE_NAME in self.cookies)
    has_auth_header = isinstance(headers, dict) and any(
        k.lower() in ("authorization", "x-api-key") for k in headers.keys()
    )

    if not has_auth_cookie and not has_auth_header:
        token, csrf = get_or_create_test_session()
        new_cookies = dict(cookies)
        new_cookies[SESSION_COOKIE_NAME] = token
        new_cookies[CSRF_COOKIE_NAME] = csrf
        kwargs["cookies"] = new_cookies
        if isinstance(headers, dict) and "x-csrf-token" not in [k.lower() for k in headers.keys()]:
            new_headers = dict(headers)
            new_headers["x-csrf-token"] = csrf
            kwargs["headers"] = new_headers

    return _orig_stream(self, method, url, *args, **kwargs)

TestClient.request = _patched_request
TestClient.stream = _patched_stream

def pytest_sessionfinish(session, exitstatus):
    """Clean up the isolated temporary test database workspace upon test completion."""
    temp_dir = os.environ.get("FORENSICS_DATA_DIR")
    if temp_dir and "tracex_pytest_workspace_" in temp_dir:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass

