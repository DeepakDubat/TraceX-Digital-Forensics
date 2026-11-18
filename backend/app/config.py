import os
import sys
import shutil
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Determine runtime execution state
IS_FROZEN = getattr(sys, "frozen", False)
if IS_FROZEN:
    APP_DIR = Path(sys.executable).resolve().parent
    BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", APP_DIR))
else:
    APP_DIR = BASE_DIR
    BUNDLE_DIR = BASE_DIR

# ==============================================================================
# THREE EXPLICIT EXECUTION MODES
# ==============================================================================
EXECUTION_MODE_DEVELOPMENT = "DEVELOPMENT_MODE"
EXECUTION_MODE_INSTALLED = "INSTALLED_MODE"
EXECUTION_MODE_PORTABLE = "PORTABLE_MODE"

def _resolve_execution_mode() -> str:
    """
    Resolves execution mode strictly:
    1. PORTABLE_MODE: Triggered if .portable marker exists in APP_DIR or env flag set.
    2. INSTALLED_MODE: Frozen binary or TRACEX_MODE=installed without .portable.
    3. DEVELOPMENT_MODE: Unfrozen source execution without .portable.
    """
    if (
        os.getenv("TRACEX_PORTABLE_MODE", "").lower() in ("true", "1", "yes")
        or os.getenv("FORENSICS_PORTABLE_MODE", "").lower() in ("true", "1", "yes")
        or (APP_DIR / ".portable").exists()
    ):
        return EXECUTION_MODE_PORTABLE
    if IS_FROZEN or os.getenv("TRACEX_MODE", "").lower() == "installed" or os.getenv("ENVIRONMENT") == "production":
        return EXECUTION_MODE_INSTALLED
    return EXECUTION_MODE_DEVELOPMENT

EXECUTION_MODE = _resolve_execution_mode()
IS_PORTABLE = (EXECUTION_MODE == EXECUTION_MODE_PORTABLE)

# Load .env file if present (APP_DIR takes precedence, followed by BASE_DIR)
for candidate_env in (APP_DIR / ".env", BASE_DIR / ".env"):
    if candidate_env.exists():
        for line in candidate_env.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if k not in os.environ:
                    os.environ[k] = v
        break

# Re-evaluate mode after .env load
EXECUTION_MODE = _resolve_execution_mode()
IS_PORTABLE = (EXECUTION_MODE == EXECUTION_MODE_PORTABLE)

# ==============================================================================
# AUTOMATIC PROCESS ENVIRONMENT & TOOL RESOLUTION (PHASE 5)
# ==============================================================================
def _configure_process_environment(mode: str):
    """
    Auto-detects bundled tools and configures process-level environment variables
    (JAVA_HOME, PATH, TESSDATA_PREFIX) without modifying system registry,
    machine-wide PATH, or creating console windows.
    """
    tools_dir = APP_DIR / "tools"
    if not tools_dir.exists():
        tools_dir = BASE_DIR / "tools"

    # 1. Bundled Java Runtime Detection
    java_candidates = [
        tools_dir / "java",
        APP_DIR / "runtimes" / "java",
        tools_dir / "java" / "bin",
        Path("C:/Program Files/Java/jdk-21.0.10"),
    ]
    for j_cand in java_candidates:
        java_exe = j_cand / "bin" / "java.exe" if not (j_cand / "java.exe").exists() else j_cand / "java.exe"
        if java_exe.is_file():
            java_home = j_cand if (j_cand / "bin" / "java.exe").exists() else j_cand.parent
            os.environ["JAVA_HOME"] = str(java_home.resolve())
            java_bin = str((java_home / "bin").resolve())
            current_path = os.environ.get("PATH", "")
            if java_bin not in current_path:
                os.environ["PATH"] = f"{java_bin}{os.pathsep}{current_path}"
            break

    # 2. Bundled Tesseract OCR & Tessdata Setup
    tess_candidates = [
        tools_dir / "tesseract",
        tools_dir / "tesseract" / "bin",
        Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Tesseract-OCR",
    ]
    for t_cand in tess_candidates:
        tess_exe = t_cand / "tesseract.exe"
        if tess_exe.is_file():
            tess_dir = str(t_cand.resolve())
            current_path = os.environ.get("PATH", "")
            if tess_dir not in current_path:
                os.environ["PATH"] = f"{tess_dir}{os.pathsep}{current_path}"
            tessdata_dir = t_cand / "tessdata"
            if tessdata_dir.is_dir():
                os.environ["TESSDATA_PREFIX"] = str(tessdata_dir.resolve())
            break

    # 3. Bundled ExifTool Setup
    exif_candidates = [
        tools_dir / "exiftool",
        Path("C:/Tools/ExifTool"),
    ]
    for e_cand in exif_candidates:
        exif_exe = e_cand / "exiftool.exe"
        if exif_exe.is_file():
            exif_dir = str(e_cand.resolve())
            current_path = os.environ.get("PATH", "")
            if exif_dir not in current_path:
                os.environ["PATH"] = f"{exif_dir}{os.pathsep}{current_path}"
            break

_configure_process_environment(EXECUTION_MODE)

def _find_binary(name: str, fallback_candidates: List[Path]) -> str:
    # First priority: check explicit fallback candidates (bundled tools take precedence)
    for c in fallback_candidates:
        if c and c.is_file():
            return str(c.resolve())
    # Second priority: system PATH
    found = shutil.which(name)
    if found:
        return found
    return ""

def _resolve_directories(mode: str) -> dict:
    if os.getenv("FORENSICS_DATA_DIR"):
        root = Path(os.environ["FORENSICS_DATA_DIR"])
        is_dev = (mode == EXECUTION_MODE_DEVELOPMENT)
        return {
            "root": root,
            "evidence": root if is_dev else (root / "evidence"),
            "reports": (BASE_DIR / os.getenv("REPORTS_DIR", "reports")) if is_dev else (root / "reports"),
            "rules": (BASE_DIR / os.getenv("RULES_DIR", "rules")) if is_dev else (root / "rules"),
            "database": (root / "database" / "tracex_portable.db") if mode == EXECUTION_MODE_PORTABLE else ((BASE_DIR / os.getenv("DB_PATH", "analysis_workspace/workbench.db")) if is_dev else (root / "workbench.db")),
            "logs": root / "logs",
            "cache": root / "cache",
            "credentials": root if is_dev else (root / "credentials"),
            "settings": root if is_dev else (root / "settings"),
            "chat_attachments": (root / "chat_attachments") if is_dev else (root / "cache" / "attachments"),
            "tools": APP_DIR / "tools",
            "runtimes": APP_DIR / "runtimes",
        }

    if mode == EXECUTION_MODE_PORTABLE:
        # Strict isolation: APP_DIR / "UserData"
        root = APP_DIR / "UserData"
        return {
            "root": root,
            "evidence": root / "evidence",
            "reports": root / "reports",
            "rules": root / "rules",
            "database": root / "database" / "tracex_portable.db",
            "logs": root / "logs",
            "cache": root / "cache",
            "credentials": root / "credentials",
            "settings": root / "settings",
            "chat_attachments": root / "cache" / "attachments",
            "tools": APP_DIR / "tools",
            "runtimes": APP_DIR / "runtimes",
        }
    elif mode == EXECUTION_MODE_INSTALLED:
        local_app_data = os.getenv("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
        root = Path(local_app_data) / "TraceX"
        return {
            "root": root,
            "evidence": root / "evidence",
            "reports": root / "reports",
            "rules": root / "rules",
            "database": root / "workbench.db",
            "logs": root / "logs",
            "cache": root / "cache",
            "credentials": root / "credentials",
            "settings": root / "settings",
            "chat_attachments": root / "cache" / "attachments",
            "tools": APP_DIR / "tools",
            "runtimes": APP_DIR / "runtimes",
        }
    else:  # DEVELOPMENT_MODE
        root = BASE_DIR / os.getenv("DATA_DIR", "analysis_workspace")
        return {
            "root": root,
            "evidence": root,
            "reports": BASE_DIR / os.getenv("REPORTS_DIR", "reports"),
            "rules": BASE_DIR / os.getenv("RULES_DIR", "rules"),
            "database": BASE_DIR / os.getenv("DB_PATH", "analysis_workspace/workbench.db"),
            "logs": root / "logs",
            "cache": root / "cache",
            "credentials": root,
            "settings": root,
            "chat_attachments": root / "chat_attachments",
            "tools": APP_DIR / "tools",
            "runtimes": APP_DIR / "runtimes",
        }

_DIRS = _resolve_directories(EXECUTION_MODE)
_DATA_ROOT = _DIRS["root"]
_IS_DEV_WORKSPACE = (EXECUTION_MODE == EXECUTION_MODE_DEVELOPMENT)

class Settings(BaseModel):
    APP_NAME: str = "TraceX – Digital Forensics & Cyber Investigation Suite"
    VERSION: str = "2.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "production" if IS_FROZEN else "development")
    IS_FROZEN: bool = IS_FROZEN
    IS_PORTABLE: bool = IS_PORTABLE
    EXECUTION_MODE: str = EXECUTION_MODE
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # Bundle & Directory Roots
    APP_DIR: Path = APP_DIR
    BUNDLE_DIR: Path = BUNDLE_DIR
    DATA_ROOT: Path = _DATA_ROOT
    BUNDLE_RULES_DIR: Path = BUNDLE_DIR / "rules"
    BUNDLE_FRONTEND_DIST: Path = BUNDLE_DIR / "frontend" / "dist"
    
    # Workspace & Storage Paths
    DATA_DIR: Path = _DIRS["evidence"]
    CHAT_ATTACHMENTS_DIR: Path = _DIRS["chat_attachments"]
    REPORTS_DIR: Path = _DIRS["reports"]
    RULES_DIR: Path = _DIRS["rules"]
    DB_PATH: Path = _DIRS["database"]
    CREDENTIALS_DIR: Path = _DIRS["credentials"]
    SETTINGS_DIR: Path = _DIRS["settings"]
    LOGS_DIR: Path = _DIRS["logs"]
    CACHE_DIR: Path = _DIRS["cache"]
    TOOLS_DIR: Path = _DIRS["tools"]
    RUNTIMES_DIR: Path = _DIRS["runtimes"]
    
    # Tool Binaries with dynamic fallback resolution (bundled portable tools take precedence)
    JADX_PATH: str = os.getenv(
        "JADX_PATH",
        _find_binary("jadx.bat", [
            APP_DIR / "tools" / "jadx" / "bin" / "jadx.bat",
            APP_DIR / "tools" / "jadx" / "jadx.bat",
            BASE_DIR / "tools" / "jadx" / "bin" / "jadx.bat",
            Path("C:/Tools/jadx/bin/jadx.bat"),
            Path.home() / "Tools" / "bin" / "jadx.bat",
            Path.home() / "Tools" / "jadx" / "bin" / "jadx.bat",
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "jadx" / "bin" / "jadx.bat",
            _DATA_ROOT / "tools" / "jadx" / "bin" / "jadx.bat"
        ])
    )
    JADX_GUI_PATH: str = os.getenv(
        "JADX_GUI_PATH",
        _find_binary("jadx-gui.bat", [
            APP_DIR / "tools" / "jadx" / "bin" / "jadx-gui.bat",
            APP_DIR / "tools" / "jadx" / "jadx-gui.bat",
            BASE_DIR / "tools" / "jadx" / "bin" / "jadx-gui.bat",
            Path("C:/Tools/jadx/bin/jadx-gui.bat"),
            Path.home() / "Tools" / "bin" / "jadx-gui.bat",
            Path.home() / "Tools" / "jadx" / "bin" / "jadx-gui.bat",
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "jadx" / "bin" / "jadx-gui.bat",
            _DATA_ROOT / "tools" / "jadx" / "bin" / "jadx-gui.bat"
        ])
    )
    APKTOOL_PATH: str = os.getenv(
        "APKTOOL_PATH",
        _find_binary("apktool.bat", [
            APP_DIR / "tools" / "apktool" / "apktool.bat",
            BASE_DIR / "tools" / "apktool" / "apktool.bat",
            Path("C:/Tools/apktool/apktool.bat"),
            Path.home() / "Tools" / "bin" / "apktool.bat",
            Path.home() / "Tools" / "apktool" / "apktool.bat",
            _DATA_ROOT / "tools" / "apktool" / "apktool.bat"
        ])
    )
    TESSERACT_PATH: str = os.getenv(
        "TESSERACT_PATH",
        _find_binary("tesseract.exe", [
            APP_DIR / "tools" / "tesseract" / "tesseract.exe",
            BASE_DIR / "tools" / "tesseract" / "tesseract.exe",
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Tesseract-OCR" / "tesseract.exe",
            Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Tesseract-OCR" / "tesseract.exe"
        ])
    )
    EXIFTOOL_PATH: str = os.getenv(
        "EXIFTOOL_PATH",
        _find_binary("exiftool.exe", [
            APP_DIR / "tools" / "exiftool" / "exiftool.exe",
            APP_DIR / "tools" / "other" / "exiftool.exe",
            BASE_DIR / "tools" / "exiftool" / "exiftool.exe",
            Path("C:/Tools/ExifTool/exiftool.exe"),
            Path("C:/Tools/ExifTool/exiftool_files/exiftool.exe"),
            Path("C:/Tools/exiftool/exiftool.exe"),
            Path.home() / "Tools" / "ExifTool" / "exiftool.exe",
            Path.home() / "Tools" / "exiftool" / "exiftool.exe",
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "exiftool" / "exiftool.exe",
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "ExifTool" / "exiftool.exe",
            Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "exiftool" / "exiftool.exe"
        ])
    )
    STRINGS_PATH: str = os.getenv(
        "STRINGS_PATH",
        _find_binary("strings.exe", [
            APP_DIR / "tools" / "other" / "strings.exe",
            APP_DIR / "tools" / "strings" / "strings.exe",
            BASE_DIR / "tools" / "strings" / "strings.exe"
        ])
    )
    YARA_PATH: str = os.getenv("YARA_PATH", "")
    
    # MobSF integration (loopback-only static analysis service)
    MOBSF_URL: str = os.getenv("MOBSF_URL", "http://127.0.0.1:8001")
    MOBSF_API_KEY: str = os.getenv("MOBSF_API_KEY", "")
    MOBSF_DOCKER_IMAGE: str = os.getenv(
        "MOBSF_DOCKER_IMAGE", "opensecurity/mobile-security-framework-mobsf:latest"
    )
    MOBSF_CONTAINER_NAME: str = os.getenv("MOBSF_CONTAINER_NAME", "tracex-mobsf")
    
    # Threat Intelligence & OSINT APIs
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    ALIENVAULT_OTX_API_KEY: str = os.getenv("OTX_API_KEY", os.getenv("ALIENVAULT_OTX_API_KEY", ""))
    URLHAUS_API_KEY: str = os.getenv("URLHAUS_API_KEY", "")
    MALWAREBAZAAR_API_KEY: str = os.getenv("MALWAREBAZAAR_API_KEY", "")
    IPINFO_API_KEY: str = os.getenv("IPINFO_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    CENSYS_API_ID: str = os.getenv("CENSYS_API_ID", "")
    CENSYS_API_SECRET: str = os.getenv("CENSYS_API_SECRET", "")
    GREYNOISE_API_KEY: str = os.getenv("GREYNOISE_API_KEY", "")
    MISP_URL: str = os.getenv("MISP_URL", "")
    MISP_API_KEY: str = os.getenv("MISP_API_KEY", "")

    # Dynamic Sandbox & Simulation Tools
    CAPE_URL: str = os.getenv("CAPE_URL", "")
    CAPE_API_KEY: str = os.getenv("CAPE_API_KEY", "")
    FAKENET_PATH: str = os.getenv("FAKENET_PATH", "")
    INETSIM_PATH: str = os.getenv("INETSIM_PATH", "")
    TSHARK_PATH: str = os.getenv(
        "TSHARK_PATH",
        _find_binary("tshark.exe", [
            APP_DIR / "tools" / "tshark" / "tshark.exe",
            APP_DIR / "tools" / "wireshark" / "tshark.exe",
            BASE_DIR / "tools" / "tshark" / "tshark.exe",
            BASE_DIR / "tools" / "wireshark" / "tshark.exe",
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Wireshark" / "tshark.exe",
            Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Wireshark" / "tshark.exe"
        ])
    )
    ZEEK_PATH: str = os.getenv("ZEEK_PATH", "")
    ZEEK_DOCKER_IMAGE: str = os.getenv("ZEEK_DOCKER_IMAGE", "zeek/zeek:latest")
    ZEEK_DOCKER_NETWORK: str = os.getenv("ZEEK_DOCKER_NETWORK", "none")
    ZEEK_IGNORE_CHECKSUMS: bool = os.getenv("ZEEK_IGNORE_CHECKSUMS", "true").lower() in ("true", "1", "yes")

    SURICATA_PATH: str = os.getenv(
        "SURICATA_PATH",
        _find_binary("suricata.exe", [
            APP_DIR / "tools" / "suricata" / "suricata.exe",
            BASE_DIR / "tools" / "suricata" / "suricata.exe",
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Suricata" / "suricata.exe",
            Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Suricata" / "suricata.exe"
        ])
    )
    SURICATA_CONFIG_PATH: str = os.getenv(
        "SURICATA_CONFIG_PATH",
        _find_binary("suricata.yaml", [
            APP_DIR / "tools" / "suricata" / "suricata.yaml",
            BASE_DIR / "tools" / "suricata" / "suricata.yaml",
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Suricata" / "suricata.yaml"
        ])
    )
    SURICATA_RULES_PATH: str = os.getenv(
        "SURICATA_RULES_PATH", str(_DIRS["rules"] / "tracex_synthetic_validation.rules")
    )
    SURICATA_IGNORE_CHECKSUMS: bool = os.getenv("SURICATA_IGNORE_CHECKSUMS", "true").lower() in ("true", "1", "yes")

    # OpenCode CLI Forensic Investigation Engine
    OPENCODE_PATH: str = os.getenv(
        "OPENCODE_PATH",
        _find_binary("opencode.cmd", [
            Path.home() / "AppData" / "Roaming" / "npm" / "opencode.cmd",
            Path.home() / "AppData" / "Roaming" / "npm" / "opencode.ps1",
            APP_DIR / "tools" / "opencode" / "opencode.cmd",
            BASE_DIR / "tools" / "opencode" / "opencode.cmd",
            Path("C:/Program Files/nodejs/opencode.cmd"),
            Path("C:/Program Files (x86)/nodejs/opencode.cmd"),
        ]) or _find_binary("opencode.exe", [
            APP_DIR / "tools" / "opencode" / "opencode.exe",
            BASE_DIR / "tools" / "opencode" / "opencode.exe",
            Path.home() / ".opencode" / "bin" / "opencode.exe",
        ]) or _find_binary("opencode", [
            Path.home() / "AppData" / "Roaming" / "npm" / "opencode",
        ]) or "opencode"
    )
    OPENCODE_ENABLED: bool = os.getenv("OPENCODE_ENABLED", "false").lower() in ("true", "1", "yes")
    OPENCODE_MODEL: str = os.getenv("OPENCODE_MODEL", "")
    OPENCODE_TIMEOUT_SECONDS: int = int(os.getenv("OPENCODE_TIMEOUT_SECONDS", "60"))
    OPENCODE_LOCAL_ONLY_STRICT: bool = os.getenv("OPENCODE_LOCAL_ONLY_STRICT", "true").lower() in ("true", "1", "yes")

    # Local tool diagnostics, execution policy, and offline validation settings
    TOOL_DIAGNOSTICS_DIR: Path = _DIRS["logs"] / "tool_diagnostics"
    TOOL_DIAGNOSTIC_MAX_BYTES: int = int(os.getenv("TOOL_DIAGNOSTIC_MAX_BYTES", "262144"))
    TOOL_DIAGNOSTIC_BACKUP_COUNT: int = int(os.getenv("TOOL_DIAGNOSTIC_BACKUP_COUNT", "5"))
    STRINGS_MIN_LENGTH: int = int(os.getenv("STRINGS_MIN_LENGTH", "4"))
    STRINGS_MAX_RESULTS: int = int(os.getenv("STRINGS_MAX_RESULTS", "20000"))
    STRINGS_MAX_SCAN_BYTES: int = int(os.getenv("STRINGS_MAX_SCAN_BYTES", str(256 * 1024 * 1024)))
    MOBSF_SCAN_TIMEOUT_SECONDS: int = int(os.getenv("MOBSF_SCAN_TIMEOUT_SECONDS", "600"))

    # Safe Mode Policies & Access Control
    DEPLOYMENT_MODE: str = os.getenv("WORKBENCH_DEPLOYMENT_MODE", "workstation").lower()
    LOCAL_ONLY_MODE: bool = os.getenv("LOCAL_ONLY_MODE", "true").lower() in ("true", "1", "yes")
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "200"))
    TOOL_TIMEOUT_SECONDS: int = int(os.getenv("TOOL_TIMEOUT_SECONDS", "180"))
    WORKBENCH_API_KEY: Optional[str] = os.getenv("WORKBENCH_API_KEY", None)
    BRIDGE_TOKEN: Optional[str] = os.getenv("TRACEX_BRIDGE_TOKEN", None)
    ENABLE_API_DOCS: bool = os.getenv("ENABLE_API_DOCS", "true" if not IS_FROZEN else "false").lower() in ("true", "1", "yes")
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:9000",
        "http://127.0.0.1:9000",
        "tauri://localhost",
        "http://tauri.localhost",
        "https://tauri.localhost"
    ]

settings = Settings()

# Ensure directories exist
for _d in (
    settings.DATA_DIR,
    settings.REPORTS_DIR,
    settings.RULES_DIR,
    settings.CHAT_ATTACHMENTS_DIR,
    settings.CREDENTIALS_DIR,
    settings.SETTINGS_DIR,
    settings.LOGS_DIR,
    settings.CACHE_DIR,
    settings.TOOL_DIAGNOSTICS_DIR,
    settings.DB_PATH.parent
):
    _d.mkdir(parents=True, exist_ok=True)

# Initialize production rules from bundle if missing in isolated user data dir
default_yara = settings.BUNDLE_RULES_DIR / "yara_rules.yar"
target_yara = settings.RULES_DIR / "yara_rules.yar"
if default_yara.is_file() and not target_yara.is_file():
    try:
        shutil.copy2(default_yara, target_yara)
    except Exception:
        pass

default_suricata_rules = settings.BUNDLE_RULES_DIR / "tracex_synthetic_validation.rules"
target_suricata_rules = Path(settings.SURICATA_RULES_PATH)
if default_suricata_rules.is_file() and not target_suricata_rules.is_file():
    try:
        target_suricata_rules.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(default_suricata_rules, target_suricata_rules)
    except Exception:
        pass
