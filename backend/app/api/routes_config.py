import shutil
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Depends
from backend.app.config import settings
from backend.app.core.security import safe_run_command
from backend.app.database.repository import repo
from backend.app.integrations.tool_registry import detect_system_tools, test_tool_execution
from backend.app.integrations.mobsf_adapter import test_mobsf_service
from backend.app.core.user_auth import get_current_user

router = APIRouter(prefix="/api", tags=["Configuration & Tools"])

class SettingsUpdate(BaseModel):
    jadx_path: Optional[str] = None
    jadx_gui_path: Optional[str] = None
    apktool_path: Optional[str] = None
    yara_path: Optional[str] = None
    mobsf_url: Optional[str] = None
    mobsf_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    alienvault_api_key: Optional[str] = None
    urlhaus_api_key: Optional[str] = None
    malwarebazaar_api_key: Optional[str] = None
    ipinfo_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    greynoise_api_key: Optional[str] = None
    misp_url: Optional[str] = None
    misp_api_key: Optional[str] = None
    cape_url: Optional[str] = None
    cape_api_key: Optional[str] = None
    fakenet_path: Optional[str] = None
    inetsim_path: Optional[str] = None
    tshark_path: Optional[str] = None
    zeek_path: Optional[str] = None
    suricata_path: Optional[str] = None
    local_only_mode: Optional[bool] = None

class ToolTestRequest(BaseModel):
    tool_name: str
    custom_path: Optional[str] = None

class MobSFTestRequest(BaseModel):
    url: Optional[str] = None
    api_key: Optional[str] = None

class BrowseFileRequest(BaseModel):
    title: Optional[str] = None
    initial_dir: Optional[str] = None
    filetypes: Optional[List[List[str]]] = None

def _mask(val: Optional[str]) -> str:
    from backend.app.core.credential_manager import credential_manager
    return credential_manager.mask_secret(val)

@router.get("/tools")
def get_tools_status():
    """Detects and returns real availability, diagnostics, and test statuses of all security tools."""
    return detect_system_tools()

@router.get("/tools/database")
def get_database_status():
    """Checks SQLite database connectivity, integrity check status, WAL mode, table count, and disk size."""
    import sqlite3
    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc).isoformat()
    db_path = settings.DB_PATH
    if not db_path.exists():
        return {
            "success": False,
            "tool_name": "SQLite Database",
            "installed": False,
            "status": "NOT FOUND",
            "test_status": "failed",
            "test_timestamp": ts,
            "diagnostic_message": f"Database file not found at {db_path}",
            "details": {"db_path": str(db_path)}
        }

    try:
        size_bytes = db_path.stat().st_size
        conn = sqlite3.connect(str(db_path), timeout=3.0)
        cur = conn.cursor()
        cur.execute("PRAGMA journal_mode;")
        journal_mode = cur.fetchone()[0]
        cur.execute("PRAGMA integrity_check(1);")
        integrity = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table';")
        table_count = cur.fetchone()[0]
        conn.close()

        healthy = integrity.lower() == "ok"
        return {
            "success": healthy,
            "tool_name": "SQLite Database",
            "installed": True,
            "status": "HEALTHY / ONLINE" if healthy else f"INTEGRITY ISSUE: {integrity}",
            "version": f"SQLite v{sqlite3.sqlite_version}",
            "test_status": "passed" if healthy else "failed",
            "test_timestamp": ts,
            "diagnostic_message": f"SQLite v{sqlite3.sqlite_version} operational ({table_count} tables, {size_bytes / 1024:.1f} KB, WAL={journal_mode.upper()}). Integrity: {integrity}.",
            "details": {
                "db_path": str(db_path),
                "journal_mode": journal_mode,
                "table_count": table_count,
                "size_bytes": size_bytes,
                "integrity": integrity
            }
        }
    except Exception as e:
        return {
            "success": False,
            "tool_name": "SQLite Database",
            "installed": True,
            "status": "ERROR",
            "test_status": "failed",
            "test_timestamp": ts,
            "diagnostic_message": f"Database check failed: {str(e)}",
            "details": {"error": str(e), "db_path": str(db_path)}
        }

@router.get("/tools/backend")
def get_backend_status():
    """Returns status of FastAPI backend service."""
    import sys
    from datetime import datetime, timezone
    return {
        "success": True,
        "tool_name": "FastAPI Backend Service",
        "installed": True,
        "status": "ONLINE / HEALTHY",
        "version": settings.VERSION,
        "test_status": "passed",
        "test_timestamp": datetime.now(timezone.utc).isoformat(),
        "diagnostic_message": f"FastAPI backend operational on port {settings.PORT} (Python {sys.version.split()[0]}, Environment: {settings.ENVIRONMENT}).",
        "details": {
            "port": settings.PORT,
            "environment": settings.ENVIRONMENT,
            "local_only_mode": settings.LOCAL_ONLY_MODE,
            "python_version": sys.version.split()[0]
        }
    }

@router.get("/settings")
def get_current_settings(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Retrieves workbench configuration with credentials securely masked."""
    from backend.app.core.credential_manager import credential_manager
    db_settings = repo.get_all_settings()
    
    def _get_masked(provider_id: str, field_name: str, fallback: str = "") -> str:
        m = credential_manager.get_masked_credential(provider_id)
        if m and m.get(field_name):
            return m[field_name]
        raw = db_settings.get(f"{provider_id}_api_key", fallback)
        return credential_manager.mask_secret(raw)

    return {
        "jadx_path": db_settings.get("jadx_path", settings.JADX_PATH),
        "jadx_gui_path": db_settings.get("jadx_gui_path", settings.JADX_GUI_PATH),
        "apktool_path": db_settings.get("apktool_path", settings.APKTOOL_PATH),
        "yara_path": db_settings.get("yara_path", settings.YARA_PATH),
        "mobsf_url": db_settings.get("mobsf_url", settings.MOBSF_URL),
        "mobsf_api_key_masked": _get_masked("mobsf", "api_key", settings.MOBSF_API_KEY),
        "virustotal_api_key_masked": _get_masked("virustotal", "api_key", settings.VIRUSTOTAL_API_KEY),
        "abuseipdb_api_key_masked": _get_masked("abuseipdb", "api_key", settings.ABUSEIPDB_API_KEY),
        "alienvault_api_key_masked": _get_masked("alienvault_otx", "api_key", settings.ALIENVAULT_OTX_API_KEY),
        "urlhaus_api_key_masked": _get_masked("urlhaus", "api_key", settings.URLHAUS_API_KEY),
        "malwarebazaar_api_key_masked": _get_masked("malwarebazaar", "api_key", settings.MALWAREBAZAAR_API_KEY),
        "ipinfo_api_key_masked": _get_masked("ipinfo", "api_key", settings.IPINFO_API_KEY),
        "shodan_api_key_masked": _get_masked("shodan", "api_key", settings.SHODAN_API_KEY),
        "censys_api_id_masked": _get_masked("censys", "api_id", settings.CENSYS_API_ID),
        "censys_api_secret_masked": _get_masked("censys", "api_secret", settings.CENSYS_API_SECRET),
        "greynoise_api_key_masked": _get_masked("greynoise", "api_key", settings.GREYNOISE_API_KEY),
        "misp_url": db_settings.get("misp_url", settings.MISP_URL),
        "misp_api_key_masked": _get_masked("misp", "api_key", settings.MISP_API_KEY),
        "cape_url": db_settings.get("cape_url", settings.CAPE_URL),
        "cape_api_key_masked": _get_masked("cape", "api_key", settings.CAPE_API_KEY),
        "fakenet_path": db_settings.get("fakenet_path", settings.FAKENET_PATH),
        "inetsim_path": db_settings.get("inetsim_path", settings.INETSIM_PATH),
        "tshark_path": db_settings.get("tshark_path", settings.TSHARK_PATH),
        "zeek_path": db_settings.get("zeek_path", settings.ZEEK_PATH),
        "suricata_path": db_settings.get("suricata_path", settings.SURICATA_PATH),
        "local_only_mode": settings.LOCAL_ONLY_MODE,
        "network_mode": "LOCAL_ONLY" if settings.LOCAL_ONLY_MODE else "HYBRID"
    }

@router.post("/settings")
def update_settings(
    payload: SettingsUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Updates tool paths, API keys, and local mode policy in database."""
    fields = payload.model_dump(exclude_unset=True)
    for k, v in fields.items():
        if v is not None:
            if isinstance(v, bool):
                repo.save_setting(k, "true" if v else "false")
            elif isinstance(v, str) and not v.startswith("•••"): # Only update if not masked placeholder
                repo.save_setting(k, v)
                attr_name = k.upper()
                if hasattr(settings, attr_name):
                    setattr(settings, attr_name, v)
                
    # Update active in-memory settings if changed
    if payload.local_only_mode is not None:
        from backend.app.core.network_mode import set_network_mode
        set_network_mode("LOCAL_ONLY" if payload.local_only_mode else "HYBRID")

    return {"status": "success", "message": "Workbench settings updated successfully."}

@router.post("/settings/browse-file")
def browse_local_file(
    payload: Optional[BrowseFileRequest] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Opens the host-native file picker so local tool paths can be configured
    without manual typing. Returns an empty path when the user cancels.
    """
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception as exc:
        return {"success": False, "path": "", "error": f"Native file dialog unavailable: {exc}"}

    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass
        selected = filedialog.askopenfilename(
            title=(payload.title if payload and payload.title else "Select local tool executable"),
            initialdir=(payload.initial_dir if payload and payload.initial_dir else None),
            filetypes=(payload.filetypes if payload and payload.filetypes else [
                ("Executable / JAR files", "*.bat *.cmd *.exe *.jar"),
                ("All files", "*.*"),
            ]),
        )
        return {"success": bool(selected), "path": selected or ""}
    except Exception as exc:
        return {"success": False, "path": "", "error": str(exc)}
    finally:
        if root is not None:
            try:
                root.destroy()
            except Exception:
                pass


@router.post("/settings/test-tool")
def test_tool_executable(
    payload: ToolTestRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Safely tests tool availability, Python module imports, ruleset compilations,
    or binary executable execution without executing malicious payloads.
    """
    res = test_tool_execution(payload.tool_name, payload.custom_path)
    return {
        "success": res.get("success", False),
        "status": res.get("status", "TEST FAILED"),
        "message": res.get("diagnostic_message", res.get("message", "")),
        "details": res.get("details", {}),
        "version": res.get("version"),
        "test_status": res.get("test_status", "failed"),
        "test_timestamp": res.get("test_timestamp")
    }

@router.post("/settings/test-mobsf")
def test_mobsf_endpoint(
    payload: Optional[MobSFTestRequest] = None,
    url: Optional[str] = None,
    api_key: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Test connection to local MobSF service endpoint with port conflict awareness."""
    target_url = (payload.url if payload and payload.url else None) or url or repo.get_setting("mobsf_url") or settings.MOBSF_URL
    target_key = (payload.api_key if payload and payload.api_key else None) or api_key or repo.get_setting("mobsf_api_key") or settings.MOBSF_API_KEY
    res = test_mobsf_service(target_url, target_key)
    return res

class OTXTestRequest(BaseModel):
    api_key: Optional[str] = None

@router.post("/settings/test-otx")
def test_otx_endpoint(
    payload: Optional[OTXTestRequest] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Safely tests AlienVault OTX credentials by calling the read-only user endpoint.
    Returns: Connected, Invalid credentials, Rate limited, Provider unavailable, Network error, or Not configured.
    """
    from backend.app.integrations.threat_intel.threat_intel_manager import threat_intel
    if payload and payload.api_key is not None:
        if payload.api_key.startswith("•••"):
            target_key = repo.get_setting("alienvault_api_key") or settings.ALIENVAULT_OTX_API_KEY
        else:
            target_key = payload.api_key
    else:
        target_key = repo.get_setting("alienvault_api_key") or settings.ALIENVAULT_OTX_API_KEY
    return threat_intel.test_alienvault_connection(target_key)

@router.get("/settings/osint-providers")
def get_osint_providers():
    """Returns the comprehensive registry of all 16 modular OSINT providers with capabilities and privacy constraints."""
    from backend.app.integrations.osint.providers.provider_registry import provider_registry
    return provider_registry.list_providers_metadata()

@router.post("/settings/test-provider/{provider_id}")
def test_osint_provider(provider_id: str):
    """Executes a safe read-only connectivity test for any modular OSINT provider."""
    from backend.app.integrations.osint.providers.provider_registry import provider_registry
    return provider_registry.test_provider(provider_id)

@router.get("/diagnostics")
def get_diagnostics():
    """Returns comprehensive system runtime, dependency, database, and tool diagnostics without secrets."""
    import sys
    import platform
    import sqlite3
    from datetime import datetime, timezone

    # 1. Python Runtime
    py_runtime = {
        "version": sys.version.split()[0],
        "full_version": sys.version,
        "executable": sys.executable,
        "is_bundled": getattr(sys, "frozen", False),
        "platform": sys.platform,
        "architecture": platform.architecture()[0],
        "machine": platform.machine()
    }

    # 2. Storage & Isolation
    storage = {
        "data_root": str(settings.DATA_ROOT),
        "evidence_dir": str(settings.DATA_DIR),
        "reports_dir": str(settings.REPORTS_DIR),
        "rules_dir": str(settings.RULES_DIR),
        "db_path": str(settings.DB_PATH),
        "is_portable": settings.IS_PORTABLE,
        "environment": settings.ENVIRONMENT
    }

    # 3. Database Health
    db_health = {"status": "UNKNOWN", "exists": False, "size_bytes": 0, "wal_mode": False}
    try:
        if settings.DB_PATH.exists():
            db_health["exists"] = True
            db_health["size_bytes"] = settings.DB_PATH.stat().st_size
            conn = sqlite3.connect(str(settings.DB_PATH))
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode;")
            row = cur.fetchone()
            db_health["wal_mode"] = (row[0].lower() == "wal") if row else False
            cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table';")
            tbl_count = cur.fetchone()[0]
            db_health["table_count"] = tbl_count
            db_health["status"] = "HEALTHY"
            conn.close()
        else:
            db_health["status"] = "NOT INITIALIZED"
    except Exception as e:
        db_health["status"] = f"ERROR: {str(e)}"

    # 4. Frontend Status
    dist_candidate = getattr(settings, "BUNDLE_FRONTEND_DIST", settings.APP_DIR / "frontend" / "dist")
    fe_status = {
        "bundled": (dist_candidate / "index.html").exists(),
        "dist_path": str(dist_candidate),
        "status": "BUILT / READY" if (dist_candidate / "index.html").exists() else "SOURCE / DEV"
    }

    # 5. Core Analyzers
    analyzers = {}
    for mod_name, label in [
        ("pefile", "PE Static Analysis Engine"),
        ("pypdf", "PDF Forensics Engine"),
        ("PIL", "Image Forensics Engine (Pillow)"),
        ("docx", "Office Document Analyzer"),
        ("openpyxl", "Spreadsheet Forensics Engine")
    ]:
        try:
            m = __import__(mod_name)
            analyzers[label] = {
                "available": True,
                "version": getattr(m, "__version__", "Available")
            }
        except ImportError:
            analyzers[label] = {"available": False, "version": None}

    # 6. Docker & External Tool Diagnostics
    docker_status = {"available": False, "version": None}
    d_bin = shutil.which("docker")
    if d_bin:
        ret, stdout, _ = safe_run_command([d_bin, "--version"], timeout=5)
        if ret == 0:
            docker_status["available"] = True
            docker_status["version"] = stdout.strip()

    network_tools = {
        "tshark": {
            "configured": bool(settings.TSHARK_PATH),
            "available": bool(settings.TSHARK_PATH and Path(settings.TSHARK_PATH).is_file()) or bool(shutil.which("tshark")),
            "path": settings.TSHARK_PATH or shutil.which("tshark") or "Not found"
        },
        "zeek": {
            "configured": bool(settings.ZEEK_PATH),
            "available": bool(settings.ZEEK_PATH and Path(settings.ZEEK_PATH).is_file()) or bool(shutil.which("zeek")),
            "path": settings.ZEEK_PATH or shutil.which("zeek") or "Not found"
        },
        "suricata": {
            "configured": bool(settings.SURICATA_PATH),
            "available": bool(settings.SURICATA_PATH and Path(settings.SURICATA_PATH).is_file()) or bool(shutil.which("suricata")),
            "path": settings.SURICATA_PATH or shutil.which("suricata") or "Not found"
        }
    }

    # 7. OSINT Providers Summary (without secrets)
    osint_summary = []
    try:
        from backend.app.integrations.osint.providers.provider_registry import provider_registry
        for p in provider_registry.list_providers_metadata():
            osint_summary.append({
                "provider_id": p.get("provider_id"),
                "name": p.get("name"),
                "configured": p.get("configured", False),
                "requires_api_key": p.get("requires_api_key", False),
                "test_status": p.get("test_status", "not_run")
            })
    except Exception:
        pass

    tools = [t.model_dump() if hasattr(t, "model_dump") else t.dict() for t in detect_system_tools()]

    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "app_name": settings.APP_NAME,
        "app_version": settings.VERSION,
        "runtime": py_runtime,
        "storage": storage,
        "database": db_health,
        "frontend": fe_status,
        "tools": tools,
        "core_analyzers": analyzers,
        "docker": docker_status,
        "network_tools": network_tools,
        "osint_providers": osint_summary
    }

@router.get("/diagnostics/export")
def export_diagnostics():
    """Generates a downloadable sanitized JSON file of all environment diagnostics."""
    from fastapi.responses import JSONResponse
    diag = get_diagnostics()
    return JSONResponse(
        content=diag,
        headers={"Content-Disposition": "attachment; filename=ForensicsWorkbench-Diagnostics.json"}
    )

