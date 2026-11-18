"""
Bring Your Own Key (BYOK) & Integration Management Routes
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Provides secure endpoints for configuring, querying, testing, and deleting
credentials with strict user-level isolation and zero secret exposure.
"""

from typing import Dict, Any, Optional, List
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Depends

from backend.app.core.credential_manager import credential_manager, PROVIDER_CATALOG
from backend.app.core.user_auth import get_current_user_optional, get_current_user
from backend.app.config import settings

router = APIRouter(prefix="/api/credentials", tags=["Bring Your Own Key (BYOK) Credentials"])


class CredentialPayload(BaseModel):
    data: Dict[str, Any]
    credential_type: Optional[str] = None


class TestCredentialPayload(BaseModel):
    data: Optional[Dict[str, Any]] = None


class OpenPortalPayload(BaseModel):
    url: str


@router.post("/open-portal")
def open_external_portal(
    payload: OpenPortalPayload,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """Safely opens an official authentication or account portal in the host default system browser."""
    url = (payload.url or "").strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(status_code=400, detail="Invalid portal URL protocol.")
    import webbrowser
    webbrowser.open(url)
    return {"success": True, "opened": url}


@router.get("/master-key/status")
def get_master_key_status(user: Dict[str, Any] = Depends(get_current_user)):
    """Returns status and storage mechanism of the authenticated encryption master key."""
    status = "active" if credential_manager._fernet is not None else "missing_key_error"
    return {
        "status": status,
        "key_source": credential_manager.master_key_source,
        "encryption_algorithm": "AES-128-CBC / HMAC-SHA256 (Fernet Authenticated)",
        "zero_plaintext_guarantee": True
    }


@router.get("/providers")
def get_providers_catalog(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns full metadata for all supported integrations, including registration URLs,
    field specifications, rate limits, privacy notes, and current encrypted configuration state.
    Sensitive credentials are ALWAYS masked (e.g. ****************a83f).
    """
    return credential_manager.list_providers_metadata(user_id=user["id"])


@router.get("")
def list_credentials(user: Dict[str, Any] = Depends(get_current_user)):
    """Lists configuration status for all providers scoped to active user. Plaintext keys are never returned."""
    return credential_manager.list_providers_metadata(user_id=user["id"])


@router.get("/summary")
def get_credentials_summary(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns authoritative high-level counts across all integrations:
    - total
    - connected
    - credentials_saved
    - not_configured
    - authentication_failed
    - local_tools_available
    """
    return credential_manager.get_credentials_summary(user_id=user["id"])


LOCAL_TOOL_EXECUTION_MAP = {
    "jadx": ("JADX Decompiler", "jadx_path"),
    "jadx_gui": ("JADX GUI Launcher", "jadx_gui_path"),
    "apktool": ("Apktool", "apktool_path"),
    "androguard": ("Androguard", None),
    "yara": ("YARA", "yara_path"),
    "tesseract": ("Tesseract OCR", "tesseract_path"),
}


def _canonical_local_status(result: Dict[str, Any], builtin: bool = False) -> tuple:
    """Maps raw tool-test language onto the canonical TraceX status vocabulary."""
    raw = str(result.get("status") or "").upper()
    if builtin:
        return "BUILT-IN", "BUILT-IN / AVAILABLE"
    for status in (
        "NOT INSTALLED", "DEPENDENCY MISSING", "NOT SUPPORTED ON THIS PLATFORM",
        "CONFIGURATION ERROR", "CONFIGURING", "TESTING",
    ):
        if status in raw:
            return status, status
    if result.get("success"):
        return "CONNECTED", "CONNECTED"
    if "BUILT-IN" in raw:
        return "BUILT-IN", "BUILT-IN / AVAILABLE"
    if "AVAILABLE" in raw:
        return "AVAILABLE", "AVAILABLE"
    if "INSTALLED" in raw:
        return "INSTALLED", "INSTALLED"
    return "CONFIGURATION ERROR", "CONFIGURATION ERROR"


@router.get("/local-tools/status")
def get_local_tools_status(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Performs a real functional probe of every Local Forensic Tool and returns
    honest installed/version/executable-path/installation-status detail.
    """
    from concurrent.futures import ThreadPoolExecutor
    from datetime import datetime, timezone
    from backend.app.integrations.tool_registry import test_mobsf_tool, test_tool_execution
    from backend.app.database.repository import repo

    def probe(pid: str):
        tool_name, setting_key = LOCAL_TOOL_EXECUTION_MAP[pid]
        if pid == "mobsf":
            stored = credential_manager.get_credential("mobsf", user_id=user["id"]) or {}
            res = test_mobsf_tool(
                url=stored.get("url") or settings.MOBSF_URL,
                api_key=stored.get("api_key") or settings.MOBSF_API_KEY,
            )
        else:
            custom_path = None
            if setting_key:
                custom_path = repo.get_setting(setting_key) or getattr(settings, setting_key.upper(), "") or None
            res = test_tool_execution(tool_name, custom_path)
        details = res.get("details") or {}
        executable_path = (
            res.get("executable_path")
            or details.get("executable_path")
            or details.get("cli_executable")
            or details.get("gui_launcher_path")
            or details.get("python_interpreter")
            or ""
        )
        builtin = pid in ("strings", "androguard")
        canonical, display = _canonical_local_status(res, builtin=builtin)
        return pid, {
            "id": pid,
            "name": PROVIDER_CATALOG.get(pid, {}).get("name", pid),
            "installed": bool(res.get("installed", False)),
            "version": res.get("version"),
            "executable_path": executable_path,
            "path_configured": bool(res.get("path_configured", False)),
            "status": canonical,
            "display_status": display,
            "test_status": res.get("test_status", "not_run"),
            "diagnostic_message": res.get("diagnostic_message", ""),
            "details": details,
        }

    ids = list(LOCAL_TOOL_EXECUTION_MAP.keys())
    with ThreadPoolExecutor(max_workers=len(ids)) as executor:
        results = dict(executor.map(probe, ids))

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "tools": [results[i] for i in ids],
    }


@router.get("/{provider_id}")
def get_provider_credential_status(
    provider_id: str,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """Retrieves masked credential details for a specific provider."""
    pid = provider_id.lower().strip()
    catalog_item = PROVIDER_CATALOG.get(pid)
    if not catalog_item:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found in catalog.")

    user_id = user["id"]
    masked = credential_manager.get_masked_credential(pid, user_id=user_id) or {}
    all_meta = credential_manager.list_providers_metadata(user_id=user_id)
    metadata = next((p for p in all_meta if p["id"] == pid), None)
    return {
        "provider": pid,
        "is_configured": bool(masked and any(v for v in masked.values() if v)),
        "masked_values": masked,
        "metadata": metadata
    }


@router.post("/{provider_id}")
def save_provider_credential(
    provider_id: str,
    payload: CredentialPayload,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Encrypts and saves credentials for a specific provider scoped to user account.
    Values are authenticated and encrypted at rest with the platform master key.
    """
    pid = provider_id.lower().strip()
    if pid not in PROVIDER_CATALOG:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found in catalog.")

    is_local_tool = bool(PROVIDER_CATALOG.get(pid, {}).get("is_local_tool", False))
    if not payload.data and not is_local_tool:
        raise HTTPException(status_code=400, detail="Credential payload data cannot be empty.")

    try:
        res = credential_manager.save_credential(
            provider_name=pid,
            data=payload.data or {},
            credential_type=payload.credential_type,
            user_id=user["id"]
        )
        return res
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except RuntimeError as re:
        raise HTTPException(status_code=500, detail=str(re))


@router.delete("/{provider_id}")
def delete_provider_credential(
    provider_id: str,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """Permanently purges credentials for a provider from encrypted storage."""
    pid = provider_id.lower().strip()
    if pid not in PROVIDER_CATALOG:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found in catalog.")

    success = credential_manager.delete_credential(pid, user_id=user["id"])
    return {
        "success": True,
        "provider": pid,
        "message": f"Credentials for '{pid}' have been removed from encrypted storage."
    }


@router.post("/{provider_id}/test")
def test_provider_credential(
    provider_id: str,
    payload: Optional[TestCredentialPayload] = None,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Tests live connectivity or local execution for a provider.
    Supports testing either stored encrypted credentials or transient unsaved credentials.
    Respects LOCAL_ONLY_MODE and returns explicit connection statuses.
    """
    pid = provider_id.lower().strip()
    if pid not in PROVIDER_CATALOG:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found in catalog.")

    user_id = user["id"]
    ephemeral_data = payload.data if (payload and payload.data) else None
    result = credential_manager.test_credential(pid, ephemeral_data=ephemeral_data, user_id=user_id)
    return result
