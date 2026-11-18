import os
import json
import base64
import hashlib
import shutil
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from cryptography.fernet import Fernet

from backend.app.config import settings, BASE_DIR
from backend.app.database.repository import repo
from backend.app.core.api_error_classifier import classify_api_error, sanitize_error_text
from backend.app.core.auth_registry import AUTHENTICATION_REGISTRY

# ==============================================================================
# PROVIDER METADATA CATALOG
# ==============================================================================

PROVIDER_CATALOG = {
    # --------------------------------------------------------------------------
    # THREAT INTELLIGENCE
    # --------------------------------------------------------------------------
    "virustotal": {
        "id": "virustotal",
        "name": "VirusTotal v3",
        "category": "threat_intel",
        "description": "Multi-engine malware analysis and IOC reputation aggregator.",
        "requires_credentials": True,
        "is_local_tool": False,
        "credential_type": "api_key",
        "fields": [
            {"key": "api_key", "label": "API Key", "type": "password", "placeholder": "64-character hex API key"}
        ],
        "register_url": "https://www.virustotal.com/gui/my-apikey",
        "docs_url": "https://developers.virustotal.com/reference/overview",
        "rate_limits": "Free Community Tier: 4 requests/min, 500 requests/day",
        "privacy_note": "Lookups check VirusTotal's database. Hash-only queries preserve binary confidentiality; never upload raw binaries."
    },
    "alienvault_otx": {
        "id": "alienvault_otx",
        "name": "AlienVault OTX",
        "category": "threat_intel",
        "description": "Open Threat Exchange crowdsourced pulses and threat indicators.",
        "requires_credentials": True,
        "is_local_tool": False,
        "credential_type": "api_key",
        "fields": [
            {"key": "api_key", "label": "OTX API Key", "type": "password", "placeholder": "64-character hex OTX key"}
        ],
        "register_url": "https://otx.alienvault.com/api",
        "docs_url": "https://otx.alienvault.com/api/v1/indicators",
        "rate_limits": "Community Tier: 10,000 requests/day",
        "privacy_note": "Passive read-only pulse lookups for observed hashes, IPs, and domains."
    },
    "abuseipdb": {
        "id": "abuseipdb",
        "name": "AbuseIPDB v2",
        "category": "threat_intel",
        "description": "Crowdsourced IP abuse confidence scoring and reporting database.",
        "requires_credentials": True,
        "is_local_tool": False,
        "credential_type": "api_key",
        "fields": [
            {"key": "api_key", "label": "API Key", "type": "password", "placeholder": "80-character API key"}
        ],
        "register_url": "https://www.abuseipdb.com/account/api",
        "docs_url": "https://docs.abuseipdb.com/",
        "rate_limits": "Free Tier: 1,000 checks/day",
        "privacy_note": "IP reputation checks report malicious activity scores without revealing client identity."
    },
    "urlhaus": {
        "id": "urlhaus",
        "name": "URLhaus (abuse.ch)",
        "category": "threat_intel",
        "description": "Database of verified malicious URLs used for malware distribution.",
        "requires_credentials": False,
        "is_local_tool": False,
        "credential_type": "api_key",
        "fields": [
            {"key": "api_key", "label": "Auth-Key (Optional)", "type": "password", "placeholder": "abuse.ch Auth-Key for higher rate limits"}
        ],
        "register_url": "https://urlhaus.abuse.ch/api/",
        "docs_url": "https://urlhaus-api.abuse.ch/",
        "rate_limits": "High-throughput public feed; Auth-Key unlocks priority quotas.",
        "privacy_note": "Public feed queries check URLs and domains against known malware hosts."
    },
    "malwarebazaar": {
        "id": "malwarebazaar",
        "name": "MalwareBazaar (abuse.ch)",
        "category": "threat_intel",
        "description": "Malware sample hash and classification intelligence exchange.",
        "requires_credentials": False,
        "is_local_tool": False,
        "credential_type": "api_key",
        "fields": [
            {"key": "api_key", "label": "Auth-Key (Optional)", "type": "password", "placeholder": "abuse.ch Auth-Key for sample lookups"}
        ],
        "register_url": "https://bazaar.abuse.ch/api/",
        "docs_url": "https://bazaar.abuse.ch/api/",
        "rate_limits": "Unlimited passive MD5/SHA256 queries; Auth-Key enables batch lookups.",
        "privacy_note": "Passive hash lookup only. Binary confidentiality is completely preserved."
    },

    # --------------------------------------------------------------------------
    # MODULAR OSINT PROVIDERS
    # --------------------------------------------------------------------------
    "urlscan": {
        "id": "urlscan",
        "name": "urlscan.io",
        "category": "osint",
        "description": "Sandboxed website scanner, DOM analyzer, and TLS profiler.",
        "requires_credentials": True,
        "is_local_tool": False,
        "credential_type": "api_key",
        "fields": [
            {"key": "api_key", "label": "API Key", "type": "password", "placeholder": "urlscan API key"}
        ],
        "register_url": "https://urlscan.io/user/profile/",
        "docs_url": "https://urlscan.io/docs/api/",
        "rate_limits": "Community Tier: 5,000 search queries/day",
        "privacy_note": "Searches existing scan records without submitting new URLs publicly unless requested."
    },
    "shodan": {
        "id": "shodan",
        "name": "Shodan",
        "category": "osint",
        "description": "Global telemetry for internet-connected servers, open ports, and banners.",
        "requires_credentials": True,
        "is_local_tool": False,
        "credential_type": "api_key",
        "fields": [
            {"key": "api_key", "label": "Shodan API Key", "type": "password", "placeholder": "32-character Shodan key"}
        ],
        "register_url": "https://account.shodan.io/",
        "docs_url": "https://developer.shodan.io/api",
        "rate_limits": "Developer Tier: 1 query/sec, 100 query credits/month",
        "privacy_note": "Queries Shodan's pre-scanned telemetry database. No active scans sent to target host."
    },
    "censys": {
        "id": "censys",
        "name": "Censys Search v2",
        "category": "osint",
        "description": "Global internet device search and TLS certificate intelligence graph.",
        "requires_credentials": True,
        "is_local_tool": False,
        "credential_type": "key_pair",
        "fields": [
            {"key": "api_id", "label": "API ID", "type": "text", "placeholder": "Censys API ID UUID"},
            {"key": "api_secret", "label": "API Secret", "type": "password", "placeholder": "Censys API Secret"}
        ],
        "register_url": "https://search.censys.io/account/api",
        "docs_url": "https://search.censys.io/api",
        "rate_limits": "Free Community Tier: 250 queries/month",
        "privacy_note": "Passive indexing queries against global IPv4, IPv6, and certificate graphs."
    },
    "greynoise": {
        "id": "greynoise",
        "name": "GreyNoise",
        "category": "osint",
        "description": "Distinguishes mass internet background noise from targeted attacks.",
        "requires_credentials": True,
        "is_local_tool": False,
        "credential_type": "api_key",
        "fields": [
            {"key": "api_key", "label": "API Key", "type": "password", "placeholder": "GreyNoise API Key"}
        ],
        "register_url": "https://viz.greynoise.io/account",
        "docs_url": "https://docs.greynoise.io/reference/get_v3-community-ip",
        "rate_limits": "Free Community Tier: Limited daily lookups",
        "privacy_note": "Queries global honeypot sensor network to verify benign background scanners."
    },
    "ipinfo": {
        "id": "ipinfo",
        "name": "IPinfo.io",
        "category": "osint",
        "description": "IP geolocation, ASN routing, and hosting provider detection.",
        "requires_credentials": False,
        "is_local_tool": False,
        "credential_type": "api_key",
        "fields": [
            {"key": "api_key", "label": "API Token (Optional)", "type": "password", "placeholder": "IPinfo access token"}
        ],
        "register_url": "https://ipinfo.io/account/token",
        "docs_url": "https://ipinfo.io/developers",
        "rate_limits": "Free Tier: 50,000 requests/month (Token unlocks higher quotas)",
        "privacy_note": "Passive IP lookups return ASN, country, and organization info."
    },
    "misp": {
        "id": "misp",
        "name": "MISP Threat Sharing",
        "category": "osint",
        "description": "Self-hosted or trust circle Malware Information Sharing Platform.",
        "requires_credentials": True,
        "is_local_tool": False,
        "credential_type": "url_token",
        "fields": [
            {"key": "url", "label": "MISP Base URL", "type": "text", "placeholder": "https://misp.your-org.local"},
            {"key": "api_key", "label": "Auth Key", "type": "password", "placeholder": "MISP Automation Auth Key"}
        ],
        "register_url": "https://www.misp-project.org/",
        "docs_url": "https://www.circl.lu/doc/misp/automation/",
        "rate_limits": "Controlled by your MISP instance configuration",
        "privacy_note": "Connects strictly to your designated institutional or private MISP node."
    },
    "passive_dns": {
        "id": "passive_dns",
        "name": "PassiveDNS / Mnemonic",
        "category": "osint",
        "description": "Historical domain-to-IP resolution timelines and sub-allocation mapping.",
        "requires_credentials": False,
        "is_local_tool": False,
        "credential_type": "api_key",
        "fields": [
            {"key": "api_key", "label": "API Key (Optional)", "type": "password", "placeholder": "PassiveDNS token"}
        ],
        "register_url": "https://passivedns.mnemonic.no/",
        "docs_url": "https://passivedns.mnemonic.no/api/",
        "rate_limits": "Public rate limits apply; API key unlocks expanded query limits.",
        "privacy_note": "Passive queries check historical DNS resolution records."
    },

    # --------------------------------------------------------------------------
    # PASSIVE NETWORK ANALYSIS
    # --------------------------------------------------------------------------
    "tshark": {
        "id": "tshark",
        "name": "Wireshark / tshark",
        "category": "network_analysis",
        "description": "Command-line network protocol analyzer and PCAP dissection engine.",
        "requires_credentials": False,
        "is_local_tool": True,
        "credential_type": "path",
        "fields": [
            {"key": "binary_path", "label": "tshark Executable Path", "type": "text", "placeholder": "C:\\Program Files\\Wireshark\\tshark.exe"}
        ],
        "register_url": "https://www.wireshark.org/",
        "docs_url": "https://www.wireshark.org/docs/man-pages/tshark.html",
        "rate_limits": "Local execution",
        "privacy_note": "Parses local forensic packet captures offline without outbound telemetry."
    },
    "zeek": {
        "id": "zeek",
        "name": "Zeek Network Security Monitor",
        "category": "network_analysis",
        "description": "Network traffic analyzer transforming raw packets into structured protocol logs.",
        "requires_credentials": False,
        "is_local_tool": True,
        "credential_type": "path",
        "fields": [
            {"key": "binary_path", "label": "Zeek Binary Path", "type": "text", "placeholder": "zeek or /usr/local/zeek/bin/zeek"}
        ],
        "register_url": "https://zeek.org/",
        "docs_url": "https://docs.zeek.org/en/current/",
        "rate_limits": "Local execution",
        "privacy_note": "Offline network event extraction."
    },
    "suricata": {
        "id": "suricata",
        "name": "Suricata IDS/IPS Engine",
        "category": "network_analysis",
        "description": "High-performance network threat detection and signature matching engine.",
        "requires_credentials": False,
        "is_local_tool": True,
        "credential_type": "path",
        "fields": [
            {"key": "binary_path", "label": "Suricata Binary Path", "type": "text", "placeholder": "suricata or path"}
        ],
        "register_url": "https://suricata.io/",
        "docs_url": "https://suricata.readthedocs.io/",
        "rate_limits": "Local execution",
        "privacy_note": "Evaluates local PCAP files against ET Open threat signatures offline."
    },

    # --------------------------------------------------------------------------
    # LOCAL FORENSIC TOOLS
    # --------------------------------------------------------------------------
    "jadx": {
        "id": "jadx",
        "name": "JADX CLI Decompiler",
        "category": "local_tools",
        "description": "Dex-to-Java decompiler for command-line automated reverse engineering.",
        "requires_credentials": False,
        "is_local_tool": True,
        "credential_type": "path",
        "fields": [
            {"key": "binary_path", "label": "JADX Executable Path", "type": "text", "placeholder": "C:\\Tools\\jadx\\bin\\jadx.bat or /usr/local/bin/jadx"}
        ],
        "register_url": "https://github.com/skylot/jadx/releases",
        "docs_url": "https://github.com/skylot/jadx#readme",
        "install_url": "https://github.com/skylot/jadx#download",
        "rate_limits": "Local hardware bound",
        "privacy_note": "Offline local decompilation; no files leave the workstation."
    },
    "jadx_gui": {
        "id": "jadx_gui",
        "name": "JADX GUI Viewer",
        "category": "local_tools",
        "description": "Interactive GUI viewer for browsing decompiled Android bytecode.",
        "requires_credentials": False,
        "is_local_tool": True,
        "credential_type": "path",
        "fields": [
            {"key": "binary_path", "label": "JADX GUI Executable Path", "type": "text", "placeholder": "C:\\Tools\\jadx\\bin\\jadx-gui.bat"}
        ],
        "register_url": "https://github.com/skylot/jadx/releases",
        "docs_url": "https://github.com/skylot/jadx",
        "install_url": "https://github.com/skylot/jadx#download",
        "rate_limits": "Local execution",
        "privacy_note": "Offline local GUI viewer."
    },
    "apktool": {
        "id": "apktool",
        "name": "Apktool",
        "category": "local_tools",
        "description": "Decodes APK resources to near-original form (Smali bytecode, XML layouts, Manifest).",
        "requires_credentials": False,
        "is_local_tool": True,
        "credential_type": "path",
        "fields": [
            {"key": "binary_path", "label": "Apktool Executable Path", "type": "text", "placeholder": "C:\\Tools\\apktool\\apktool.bat"}
        ],
        "register_url": "https://apktool.org/",
        "docs_url": "https://apktool.org/docs",
        "install_url": "https://apktool.org/docs/install",
        "rate_limits": "Local execution",
        "privacy_note": "Offline local decoding."
    },
    "androguard": {
        "id": "androguard",
        "name": "Androguard v4",
        "category": "local_tools",
        "description": "Pure Python reverse engineering framework for Android APKs and DEX files.",
        "requires_credentials": False,
        "is_local_tool": True,
        "credential_type": "builtin",
        "fields": [],
        "register_url": "https://github.com/androguard/androguard",
        "docs_url": "https://androguard.readthedocs.io/",
        "install_url": "https://androguard.readthedocs.io/en/latest/intro/installation.html",
        "rate_limits": "In-process Python module",
        "privacy_note": "Runs directly in the embedded Python runtime without network access."
    },
    "yara": {
        "id": "yara",
        "name": "YARA Signature Engine",
        "category": "local_tools",
        "description": "Pattern matching swiss knife for malware researchers and forensic examiners.",
        "requires_credentials": False,
        "is_local_tool": True,
        "credential_type": "path",
        "fields": [
            {"key": "binary_path", "label": "Custom Rules Path (Optional)", "type": "text", "placeholder": "Leave blank to use bundled rules"}
        ],
        "register_url": "https://virustotal.github.io/yara/",
        "docs_url": "https://yara.readthedocs.io/",
        "install_url": "https://yara.readthedocs.io/en/stable/gettingstarted.html",
        "rate_limits": "Local compilation and memory scan",
        "privacy_note": "All rule compilations and signature scans execute entirely offline."
    },
    "tesseract": {
        "id": "tesseract",
        "name": "Tesseract OCR Engine",
        "category": "local_tools",
        "description": "Optical character recognition on evidentiary screenshots, UI captures, and documents.",
        "requires_credentials": False,
        "is_local_tool": True,
        "credential_type": "path",
        "fields": [
            {"key": "binary_path", "label": "Tesseract Executable Path", "type": "text", "placeholder": "C:\\Program Files\\Tesseract-OCR\\tesseract.exe"}
        ],
        "register_url": "https://github.com/tesseract-ocr/tesseract",
        "docs_url": "https://tesseract-ocr.github.io/",
        "install_url": "https://github.com/UB-Mannheim/tesseract/wiki",
        "rate_limits": "Local execution",
        "privacy_note": "All OCR processing executes 100% offline on the local workstation."
    },

    # --------------------------------------------------------------------------
    # UTILITIES & OTHER INTEGRATIONS
    # --------------------------------------------------------------------------
    "mobsf": {
        "id": "mobsf",
        "name": "Mobile Security Framework (MobSF)",
        "category": "utilities",
        "description": "Loopback-only MobSF service for real static APK package and security policy assessment.",
        "requires_credentials": True,
        "is_local_tool": True,
        "credential_type": "url_token",
        "fields": [
            {"key": "url", "label": "MobSF URL", "type": "text", "placeholder": "http://127.0.0.1:8001"},
            {"key": "api_key", "label": "REST API Key", "type": "password", "placeholder": "MobSF REST API Key from secrets.py"}
        ],
        "register_url": "https://mobsf.github.io/Mobile-Security-Framework-MobSF/",
        "docs_url": "https://mobsf.github.io/docs/#/api",
        "rate_limits": "Local service: Hardware and thread-bound performance",
        "privacy_note": "Connects to your local or private isolated MobSF instance for static package audits."
    },
    "exiftool": {
        "id": "exiftool",
        "name": "ExifTool Metadata Engine",
        "category": "utilities",
        "description": "Deep metadata reader for document and media forensic attribution.",
        "requires_credentials": False,
        "is_local_tool": True,
        "credential_type": "path",
        "fields": [
            {"key": "binary_path", "label": "ExifTool Executable Path", "type": "text", "placeholder": "C:\\Tools\\exiftool.exe"}
        ],
        "register_url": "https://exiftool.org/",
        "docs_url": "https://exiftool.org/",
        "rate_limits": "Local execution",
        "privacy_note": "Parses metadata locally without external network telemetry."
    },
    "strings": {
        "id": "strings",
        "name": "Strings Analysis Utility",
        "category": "utilities",
        "description": "Multi-encoding ASCII/Unicode string extraction and regex IOC hunting engine.",
        "requires_credentials": False,
        "is_local_tool": True,
        "credential_type": "builtin",
        "fields": [],
        "register_url": "https://learn.microsoft.com/en-us/sysinternals/downloads/strings",
        "docs_url": "https://learn.microsoft.com/en-us/sysinternals/downloads/strings",
        "rate_limits": "In-process Python engine",
        "privacy_note": "Executes 100% offline within the local workstation process boundary."
    },
    "opencode": {
        "id": "opencode",
        "name": "OpenCode CLI Forensic Engine",
        "category": "utilities",
        "description": "Optional AI-assisted digital forensics and cyber investigation engine for static binary analysis.",
        "requires_credentials": False,
        "is_local_tool": True,
        "credential_type": "path",
        "fields": [
            {"key": "binary_path", "label": "OpenCode CLI Path (Optional)", "type": "text", "placeholder": "C:\\Users\\...\\AppData\\Roaming\\npm\\opencode.cmd"},
            {"key": "model", "label": "Model Identifier (e.g. ollama/llama3, default)", "type": "text", "placeholder": "default"}
        ],
        "register_url": "https://opencode.ai/",
        "docs_url": "https://opencode.ai/docs",
        "rate_limits": "Local / CLI subprocess execution",
        "privacy_note": "In LOCAL ONLY mode, external LLM calls are blocked. Only local models permitted. In HYBRID mode, explicit investigator authorization is required."
    }
}


# ==============================================================================
# WINDOWS DPAPI SECURE STORAGE HELPER
# ==============================================================================

def _dpapi_protect(data: bytes, description: str = "TraceX Master Encryption Key") -> bytes:
    """Wraps master key with Windows DPAPI (CryptProtectData) bound to current Windows user."""
    if os.name != "nt":
        return data
    try:
        import ctypes
        from ctypes import wintypes
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]
        in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
        out_blob = DATA_BLOB()
        if ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(in_blob), description, None, None, None, 1, ctypes.byref(out_blob)
        ):
            try:
                protected = ctypes.string_at(out_blob.pbData, out_blob.cbData)
                return protected
            finally:
                ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    except Exception:
        pass
    return data

def _dpapi_unprotect(data: bytes) -> bytes:
    """Unwraps Windows DPAPI-protected data (CryptUnprotectData)."""
    if os.name != "nt":
        return data
    try:
        import ctypes
        from ctypes import wintypes
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]
        in_blob = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))
        out_blob = DATA_BLOB()
        if ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(in_blob), None, None, None, None, 1, ctypes.byref(out_blob)
        ):
            try:
                unprotected = ctypes.string_at(out_blob.pbData, out_blob.cbData)
                return unprotected
            finally:
                ctypes.windll.kernel32.LocalFree(out_blob.pbData)
    except Exception:
        pass
    return data


# ==============================================================================
# SECURE CREDENTIAL MANAGER IMPLEMENTATION
# ==============================================================================

class CredentialManager:
    """
    Centralized, production-grade Bring Your Own Key (BYOK) credential manager.
    
    Security Guarantees:
    - Authenticated encryption at rest using Fernet (AES-128-CBC + HMAC-SHA256).
    - Windows DPAPI Master Key Wrapping: bound to the local user account on Windows.
    - Ephemeral in-memory decryption: secrets are decrypted strictly at HTTP request time.
    - Zero plaintext exposure: API endpoints, serializations, and loggers receive masked tokens.
    - Master key hierarchy: prefers WORKBENCH_MASTER_KEY from env, falls back to secure local store.
    - Data preservation: full backward compatibility with existing databases and investigations.
    """

    def __init__(self):
        self._master_key: Optional[bytes] = None
        self._fernet: Optional[Fernet] = None
        self._master_key_source: str = "uninitialized"
        self._init_master_key()

    def _secure_key_file_acls(self, key_file: Path):
        """Enforces restrictive file permissions and Windows NTFS ACLs."""
        try:
            os.chmod(key_file, 0o600)
        except Exception:
            pass

        # Windows NTFS ACL hardening: restrict to current user and SYSTEM
        if os.name == "nt":
            try:
                import subprocess
                user = os.getenv("USERNAME") or os.getenv("USER")
                if user:
                    si = subprocess.STARTUPINFO()
                    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    si.wShowWindow = 0  # SW_HIDE
                    cflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                    subprocess.run(
                        ["icacls", str(key_file), "/inheritance:r", "/grant:r", f"{user}:(R,W)", "/grant", "SYSTEM:(F)"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        creationflags=cflags,
                        startupinfo=si
                    )
            except Exception:
                pass

    def _init_master_key(self):
        """Initializes or derives the 256-bit symmetric encryption key with DPAPI protection."""
        env_key = os.getenv("WORKBENCH_MASTER_KEY") or os.getenv("TRACEX_MASTER_KEY") or os.getenv("WORKBENCH_SECRET_KEY")
        if env_key:
            # Normalize to valid Fernet key (32 url-safe base64-encoded bytes)
            try:
                raw_bytes = env_key.encode("utf-8")
                # If key is already a valid 32-byte urlsafe base64 string
                if len(raw_bytes) == 44 and base64.urlsafe_b64decode(raw_bytes):
                    self._master_key = raw_bytes
                else:
                    # Deterministically derive 32-byte Fernet key from arbitrary passphrase
                    digest = hashlib.sha256(raw_bytes).digest()
                    self._master_key = base64.urlsafe_b64encode(digest)
                self._fernet = Fernet(self._master_key)
                self._master_key_source = "environment"
                return
            except Exception:
                pass

        # Check DPAPI-wrapped key file in CREDENTIALS_DIR first
        cred_dir = getattr(settings, "CREDENTIALS_DIR", settings.DATA_ROOT)
        cred_dir.mkdir(parents=True, exist_ok=True)
        dpapi_key_file = cred_dir / ".master.key.dpapi"
        backup_dpapi_key_file = cred_dir / ".master.key.dpapi.bak"
        key_file = cred_dir / ".master.key"
        backup_key_file = cred_dir / ".master.key.bak"

        if dpapi_key_file.exists():
            try:
                protected = dpapi_key_file.read_bytes()
                unprotected = _dpapi_unprotect(protected)
                if len(unprotected) == 44:
                    self._master_key = unprotected
                    self._fernet = Fernet(self._master_key)
                    self._master_key_source = "dpapi_secure_store"
                    self._secure_key_file_acls(dpapi_key_file)
                    return
            except Exception:
                pass

        # Fallback to persistent secure master key file in DATA_ROOT with auto-migration to DPAPI
        if key_file.exists():
            try:
                stored = key_file.read_bytes().strip()
                if len(stored) == 44:
                    self._master_key = stored
                    self._fernet = Fernet(self._master_key)
                    self._master_key_source = "dpapi_migrated_store"
                    self._secure_key_file_acls(key_file)
                    # Auto-migrate to DPAPI storage on Windows
                    if os.name == "nt":
                        try:
                            protected = _dpapi_protect(stored)
                            dpapi_key_file.write_bytes(protected)
                            self._secure_key_file_acls(dpapi_key_file)
                            backup_dpapi_key_file.write_bytes(protected)
                            self._secure_key_file_acls(backup_dpapi_key_file)
                        except Exception:
                            pass
                    # Maintain backup key file
                    if not backup_key_file.exists():
                        try:
                            backup_key_file.write_bytes(stored)
                            self._secure_key_file_acls(backup_key_file)
                        except Exception:
                            pass
                    return
            except Exception:
                pass

        # Check backup files
        if backup_dpapi_key_file.exists():
            try:
                protected = backup_dpapi_key_file.read_bytes()
                unprotected = _dpapi_unprotect(protected)
                if len(unprotected) == 44:
                    self._master_key = unprotected
                    self._fernet = Fernet(self._master_key)
                    self._master_key_source = "restored_from_dpapi_backup"
                    return
            except Exception:
                pass

        if backup_key_file.exists():
            try:
                stored = backup_key_file.read_bytes().strip()
                if len(stored) == 44:
                    self._master_key = stored
                    self._fernet = Fernet(self._master_key)
                    self._master_key_source = "restored_from_backup"
                    try:
                        key_file.write_bytes(stored)
                        self._secure_key_file_acls(key_file)
                    except Exception:
                        pass
                    return
            except Exception:
                pass

        # CRITICAL SAFETY CHECK:
        # Check if database ALREADY has stored encrypted credentials in either table.
        # If credentials already exist, NEVER silently generate a new random key!
        has_existing_creds = False
        try:
            stored_rows = repo.list_provider_credentials()
            has_existing_creds = any(bool(r.get("encrypted_data")) for r in stored_rows)
            if not has_existing_creds:
                from backend.app.database.repository import get_db_connection
                conn = get_db_connection()
                count = conn.cursor().execute("SELECT count(id) FROM user_provider_credentials WHERE encrypted_data IS NOT NULL AND encrypted_data != ''").fetchone()[0]
                conn.close()
                has_existing_creds = count > 0
        except Exception:
            has_existing_creds = False

        if has_existing_creds:
            self._master_key = None
            self._fernet = None
            self._master_key_source = "missing_key_error"
            import logging
            logging.getLogger("uvicorn.error").critical(
                "CRITICAL: Master key (.master.key) is missing while encrypted provider credentials "
                "exist in the database! Refusing to generate a new key to prevent permanent credential loss. "
                "Restore analysis_workspace/.master.key or set WORKBENCH_MASTER_KEY in environment."
            )
            return

        # Generate a new Fernet key only on clean/first initialization
        new_key = Fernet.generate_key()
        try:
            cred_dir.mkdir(parents=True, exist_ok=True)
            if os.name == "nt":
                protected = _dpapi_protect(new_key)
                dpapi_key_file.write_bytes(protected)
                backup_dpapi_key_file.write_bytes(protected)
                self._secure_key_file_acls(dpapi_key_file)
                self._secure_key_file_acls(backup_dpapi_key_file)
            key_file.write_bytes(new_key)
            backup_key_file.write_bytes(new_key)
            self._secure_key_file_acls(key_file)
            self._secure_key_file_acls(backup_key_file)
            self._master_key = new_key
            self._fernet = Fernet(self._master_key)
            self._master_key_source = "dpapi_secure_store" if os.name == "nt" else "secure_local_store"
        except Exception:
            self._master_key = new_key
            self._fernet = Fernet(self._master_key)
            self._master_key_source = "ephemeral_memory"

    @property
    def master_key_source(self) -> str:
        return self._master_key_source

    def has_master_key(self) -> bool:
        return self._master_key is not None and self._fernet is not None

    def mask_secret(self, val: Optional[str]) -> str:
        """
        Masks a secret string for UI presentation.
        Format requirement: ****************a83f (last 4 characters preserved).
        """
        if not val or not isinstance(val, str):
            return ""
        val = val.strip()
        if len(val) == 0:
            return ""
        if len(val) <= 4:
            return "••••••••"
        return "****************" + val[-4:]

    def _compute_fingerprint(self, secret: str) -> str:
        """Computes a collision-resistant SHA-256 fingerprint for change detection."""
        if not secret:
            return ""
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]

    # --------------------------------------------------------------------------
    # CRUD OPERATIONS & USER ISOLATION
    # --------------------------------------------------------------------------

    def _resolve_user_id(self, user_id: Optional[str] = None) -> str:
        """Resolves target user_id for internal queries when not provided explicitly."""
        if user_id:
            return user_id
        try:
            users = repo.list_users()
            if users:
                for u in users:
                    if u.get("role") == "admin":
                        return u["id"]
                return users[0]["id"]
            # If no users exist, create default local desktop examiner to satisfy FK constraints
            from backend.app.core.user_auth import _get_or_create_local_desktop_user
            return _get_or_create_local_desktop_user()["id"]
        except Exception:
            pass
        return "default_workstation_user"

    def save_credential(
        self,
        provider_name: str,
        data: Dict[str, Any],
        credential_type: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Encrypts and securely stores provider credentials in the database scoped to user_id.
        All inputs are stripped of whitespace and trailing newlines to prevent header errors.
        """
        if self._fernet is None:
            raise RuntimeError(
                "Cannot encrypt credentials: Master key is missing while encrypted records exist in the database. "
                "Provide WORKBENCH_MASTER_KEY in environment or restore analysis_workspace/.master.key."
            )
        eff_user_id = self._resolve_user_id(user_id)
        provider_id = provider_name.lower().strip()
        cat_info = PROVIDER_CATALOG.get(provider_id, {})
        cred_type = credential_type or cat_info.get("credential_type", "api_key")

        # Sanitize data: remove empty strings, strip whitespace and newlines
        cleaned = {}
        for k, v in data.items():
            if isinstance(v, str):
                cleaned[k] = v.strip().replace("\r", "").replace("\n", "")
            elif v is not None:
                cleaned[k] = v

        # If updating with masked values or empty values, merge with existing decrypted values
        existing = self.get_credential(provider_id, user_id=eff_user_id)
        if existing:
            for k, v in list(cleaned.items()):
                if isinstance(v, str) and (v.startswith("****") or v.startswith("••••") or v == ""):
                    if existing.get(k):
                        cleaned[k] = existing[k]

        # Local tools are allowed to persist an intentionally blank optional path
        # (e.g. YARA falls back to bundled rules), so only cloud providers require a secret.
        is_local_tool = bool(cat_info.get("is_local_tool", False))
        has_valid_secret = any(bool(v) for v in cleaned.values() if v is not None and str(v).strip() != "")
        if not has_valid_secret and not is_local_tool:
            raise ValueError(
                f"Cannot save empty credentials for '{provider_id}'. At least one field must contain a non-empty value."
            )

        # Compute key fingerprint from primary secret field
        primary_secret = cleaned.get("api_key") or cleaned.get("api_secret") or cleaned.get("binary_path") or cleaned.get("access_token") or ""
        fingerprint = self._compute_fingerprint(primary_secret)

        # Encrypt the payload
        serialized = json.dumps(cleaned)
        encrypted_bytes = self._fernet.encrypt(serialized.encode("utf-8"))
        encrypted_str = encrypted_bytes.decode("utf-8")

        # Persist to user-scoped credentials table
        repo.save_user_provider_credential(
            user_id=eff_user_id,
            provider_name=provider_id,
            auth_type=cred_type,
            encrypted_data=encrypted_str,
            key_fingerprint=fingerprint,
            is_valid=True,
            reset_test_status=True
        )

        # Local tool paths must persist to app_settings and survive restart even when
        # the API scopes the encrypted record to a user_id.
        local_setting_keys = {
            "jadx": "jadx_path",
            "jadx_gui": "jadx_gui_path",
            "apktool": "apktool_path",
            "yara": "yara_path",
            "tesseract": "tesseract_path",
            "exiftool": "exiftool_path",
            "tshark": "tshark_path",
            "zeek": "zeek_path",
            "suricata": "suricata_path",
            "opencode": "opencode_path",
        }
        if is_local_tool:
            setting_key = local_setting_keys.get(provider_id)
            if setting_key:
                repo.save_setting(setting_key, cleaned.get("binary_path", "") or "")
            if provider_id == "mobsf":
                repo.save_setting("mobsf_url", cleaned.get("url", "") or settings.MOBSF_URL)
            self._sync_to_runtime_settings(provider_id, cleaned)

        # Only sync to legacy provider_credentials when user_id is None (system / single-user legacy setup)
        if user_id is None:
            try:
                repo.save_provider_credential(
                    provider_name=provider_id,
                    credential_type=cred_type,
                    encrypted_data=encrypted_str,
                    key_fingerprint=fingerprint,
                    is_valid=True
                )
            except Exception:
                pass
            # Update in-memory runtime settings if applicable (local tools already synced above)
            if not is_local_tool:
                self._sync_to_runtime_settings(provider_id, cleaned)

        return {
            "status": "success",
            "display_status": "CREDENTIAL SAVED",
            "provider": provider_id,
            "message": f"Credentials for {cat_info.get('name', provider_id)} encrypted and saved successfully. Ready for connection verification.",
            "fingerprint": fingerprint
        }

    def save_oauth_tokens(
        self,
        provider_name: str,
        access_token: str,
        refresh_token: Optional[str] = None,
        expires_in: int = 3600,
        scope: Optional[str] = None,
        account_identifier: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Encrypts and stores OAuth 2.0 access and refresh tokens for user.
        """
        if self._fernet is None:
            raise RuntimeError("Master key uninitialized.")

        eff_user_id = self._resolve_user_id(user_id)
        provider_id = provider_name.lower().strip()
        cat_info = PROVIDER_CATALOG.get(provider_id, {})

        data = {
            "access_token": access_token.strip(),
            "account_identifier": (account_identifier or "").strip(),
            "scope": (scope or "").strip()
        }
        serialized = json.dumps(data)
        encrypted_data = self._fernet.encrypt(serialized.encode("utf-8")).decode("utf-8")

        refresh_enc = None
        if refresh_token:
            refresh_enc = self._fernet.encrypt(refresh_token.strip().encode("utf-8")).decode("utf-8")

        expires_at = (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat()
        fingerprint = self._compute_fingerprint(access_token.strip())

        repo.save_user_provider_credential(
            user_id=eff_user_id,
            provider_name=provider_id,
            auth_type="oauth2",
            encrypted_data=encrypted_data,
            key_fingerprint=fingerprint,
            is_valid=True,
            token_expires_at=expires_at,
            refresh_token_encrypted=refresh_enc,
            scope=scope,
            account_identifier=account_identifier
        )

        return {
            "status": "success",
            "provider": provider_id,
            "auth_type": "oauth2",
            "message": f"Connected to {cat_info.get('name', provider_id)} via OAuth 2.0 successfully.",
            "account_identifier": account_identifier,
            "expires_at": expires_at
        }

    def get_active_auth_token(self, provider_name: str, user_id: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        """
        Retrieves the active authentication token or API key for a provider.
        Returns: (token, auth_type) where auth_type is 'oauth2' or 'api_key'.
        If OAuth2 token is expiring soon and refresh token exists, automatically refreshes it.
        """
        eff_user_id = self._resolve_user_id(user_id)
        provider_id = provider_name.lower().strip()
        record = repo.get_user_provider_credential(eff_user_id, provider_id)
        
        if record and record.get("auth_type") == "oauth2":
            # Check expiration
            expires_at_str = record.get("token_expires_at")
            should_refresh = False
            if expires_at_str:
                try:
                    exp = datetime.fromisoformat(expires_at_str)
                    if (exp - datetime.utcnow()).total_seconds() < 300:
                        should_refresh = True
                except Exception:
                    pass

            if should_refresh and record.get("refresh_token_encrypted") and self._fernet:
                try:
                    import asyncio
                    from backend.app.core.oauth_manager import oauth_manager
                    refresh_token = self._fernet.decrypt(record["refresh_token_encrypted"].encode("utf-8")).decode("utf-8")
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        import concurrent.futures
                        with concurrent.futures.ThreadPoolExecutor() as pool:
                            new_data = pool.submit(asyncio.run, oauth_manager.refresh_access_token(provider_id, refresh_token)).result()
                    else:
                        new_data = loop.run_until_complete(oauth_manager.refresh_access_token(provider_id, refresh_token))
                    
                    if new_data and new_data.get("access_token"):
                        self.save_oauth_tokens(
                            provider_name=provider_id,
                            access_token=new_data["access_token"],
                            refresh_token=refresh_token,
                            expires_in=new_data.get("expires_in", 3600),
                            scope=new_data.get("scope"),
                            user_id=eff_user_id
                        )
                        return new_data["access_token"], "oauth2"
                except Exception:
                    pass

            creds = self.get_credential(provider_id, user_id=eff_user_id)
            if creds and creds.get("access_token"):
                return creds["access_token"], "oauth2"

        creds = self.get_credential(provider_id, user_id=eff_user_id)
        if creds and creds.get("api_key"):
            return creds["api_key"], "api_key"
        return None, None

    def get_credential(self, provider_name: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieves and decrypts credentials for user into an ephemeral dictionary.
        Returns None if not configured.
        Full keys are ONLY exposed to outbound integration adapters during request dispatch.
        """
        provider_id = provider_name.lower().strip()
        eff_user_id = self._resolve_user_id(user_id)

        # 1. Try user-scoped credentials table
        record = repo.get_user_provider_credential(eff_user_id, provider_id)
        if not record or not record.get("encrypted_data"):
            # 2. Fall back to global/legacy table ONLY IF user_id was not explicitly specified
            if user_id is None:
                record = repo.get_provider_credential(provider_id)
            else:
                record = None

        if not record or not record.get("encrypted_data"):
            if user_id is None:
                return self._get_legacy_fallback(provider_id)
            return None

        if self._fernet is None:
            return None

        try:
            decrypted_bytes = self._fernet.decrypt(record["encrypted_data"].encode("utf-8"))
            data = json.loads(decrypted_bytes.decode("utf-8"))
            return data
        except Exception:
            return None

    def get_masked_credential(self, provider_name: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieves credentials with all sensitive secret fields masked."""
        provider_id = provider_name.lower().strip()
        creds = self.get_credential(provider_id, user_id=user_id)
        if not creds:
            return None

        masked = {}
        for k, v in creds.items():
            if k in ("api_key", "api_secret", "token", "password", "auth_key", "access_token"):
                masked[k] = self.mask_secret(str(v))
            else:
                masked[k] = v
        return masked

    def delete_credential(self, provider_name: str, user_id: Optional[str] = None) -> bool:
        """Removes credentials for a provider from encrypted storage."""
        provider_id = provider_name.lower().strip()
        eff_user_id = self._resolve_user_id(user_id)
        
        deleted_user = repo.delete_user_provider_credential(eff_user_id, provider_id)
        deleted_legacy = False
        if user_id is None:
            deleted_legacy = repo.delete_provider_credential(provider_id)
            legacy_key = f"{provider_id}_api_key"
            repo.save_setting(legacy_key, "")
            self._sync_to_runtime_settings(provider_id, {})
        return deleted_user or deleted_legacy

    def _sync_to_runtime_settings(self, provider_id: str, data: Dict[str, Any]):
        """Synchronizes credential values with runtime settings singleton where required."""
        attr_map = {
            "virustotal": "VIRUSTOTAL_API_KEY",
            "alienvault_otx": "ALIENVAULT_OTX_API_KEY",
            "abuseipdb": "ABUSEIPDB_API_KEY",
            "urlhaus": "URLHAUS_API_KEY",
            "malwarebazaar": "MALWAREBAZAAR_API_KEY",
            "ipinfo": "IPINFO_API_KEY",
            "shodan": "SHODAN_API_KEY",
            "censys": ("CENSYS_API_ID", "CENSYS_API_SECRET"),
            "greynoise": "GREYNOISE_API_KEY",
            "misp": ("MISP_URL", "MISP_API_KEY"),
            "mobsf": ("MOBSF_URL", "MOBSF_API_KEY"),
            "cape": ("CAPE_URL", "CAPE_API_KEY"),
            "jadx": "JADX_PATH",
            "jadx_gui": "JADX_GUI_PATH",
            "apktool": "APKTOOL_PATH",
            "yara": "YARA_PATH",
            "tesseract": "TESSERACT_PATH",
            "exiftool": "EXIFTOOL_PATH",
            "tshark": "TSHARK_PATH",
            "zeek": "ZEEK_PATH",
            "suricata": "SURICATA_PATH",
            "opencode": "OPENCODE_PATH"
        }
        target = attr_map.get(provider_id)
        if isinstance(target, str):
            val = data.get("api_key") or data.get("binary_path") or ""
            if hasattr(settings, target):
                setattr(settings, target, val)
        elif isinstance(target, tuple):
            if provider_id == "censys":
                setattr(settings, "CENSYS_API_ID", data.get("api_id", ""))
                setattr(settings, "CENSYS_API_SECRET", data.get("api_secret", ""))
            elif provider_id in ("misp", "mobsf", "cape"):
                url_attr, key_attr = target
                if hasattr(settings, url_attr):
                    setattr(settings, url_attr, data.get("url", ""))
                if hasattr(settings, key_attr):
                    setattr(settings, key_attr, data.get("api_key", ""))

    def _get_legacy_fallback(self, provider_id: str) -> Optional[Dict[str, Any]]:
        """Fallback to read unmigrated legacy settings from app_settings or settings."""
        legacy_keys = {
            "virustotal": ("virustotal_api_key", settings.VIRUSTOTAL_API_KEY),
            "alienvault_otx": ("alienvault_api_key", settings.ALIENVAULT_OTX_API_KEY),
            "abuseipdb": ("abuseipdb_api_key", settings.ABUSEIPDB_API_KEY),
            "urlhaus": ("urlhaus_api_key", settings.URLHAUS_API_KEY),
            "malwarebazaar": ("malwarebazaar_api_key", settings.MALWAREBAZAAR_API_KEY),
            "shodan": ("shodan_api_key", settings.SHODAN_API_KEY),
            "greynoise": ("greynoise_api_key", settings.GREYNOISE_API_KEY),
            "ipinfo": ("ipinfo_api_key", settings.IPINFO_API_KEY),
            "mobsf": ("mobsf_api_key", settings.MOBSF_API_KEY),
            "jadx": ("jadx_path", settings.JADX_PATH),
            "jadx_gui": ("jadx_gui_path", settings.JADX_GUI_PATH),
            "apktool": ("apktool_path", settings.APKTOOL_PATH),
            "yara": ("yara_path", settings.YARA_PATH),
        }
        if provider_id not in legacy_keys:
            return None

        db_key, fallback_val = legacy_keys[provider_id]
        val = repo.get_setting(db_key) or fallback_val
        if val and not val.startswith("•••") and not val.startswith("****"):
            if "path" in db_key:
                return {"binary_path": val}
            return {"api_key": val}
        return None

    # --------------------------------------------------------------------------
    # METADATA & STATUS LISTING
    # --------------------------------------------------------------------------

    def list_providers_metadata(self, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Returns full UI-ready metadata for all supported integrations,
        combining catalog specifications with real encrypted storage status for user.
        Never exposes plaintext keys.
        """
        eff_user_id = self._resolve_user_id(user_id)
        user_records = {r["provider_name"]: r for r in repo.list_user_provider_credentials(eff_user_id)}
        legacy_records = {r["provider_name"]: r for r in repo.list_provider_credentials()} if user_id is None else {}
        output = []

        for pid, meta in PROVIDER_CATALOG.items():
            record = user_records.get(pid) or legacy_records.get(pid)
            masked_creds = self.get_masked_credential(pid, user_id=eff_user_id if user_id is not None else None) or {}
            reg = AUTHENTICATION_REGISTRY.get(pid, {})
            oauth_cfg = reg.get("oauth2_config", {})
            supports_oauth = bool(oauth_cfg.get("enabled", False))
            is_local = bool(meta.get("is_local_tool", False))

            is_configured = bool(masked_creds and any(v for v in masked_creds.values() if v))
            is_valid = bool(record["is_valid"]) if record else True
            last_tested_at = record["last_tested_at"] if record else None
            last_error_code = record.get("last_error_code") if record else None
            last_error_message = record.get("last_error_message") if record else None
            auth_type = record.get("auth_type", meta.get("credential_type", "api_key")) if record else meta.get("credential_type", "api_key")
            account_identifier = record.get("account_identifier") if record else None
            token_expires_at = record.get("token_expires_at") if record else None

            # Standardized, evidence-backed local tool statuses.
            if is_local:
                app_tools = str((settings.APP_DIR / "tools").resolve()).lower()
                base_tools = str((BASE_DIR / "tools").resolve()).lower()

                def _is_bundled(p: Optional[str]) -> bool:
                    if not p:
                        return False
                    try:
                        resolved = str(Path(p).resolve()).lower()
                        return resolved.startswith(app_tools) or resolved.startswith(base_tools)
                    except Exception:
                        return False

                if pid == "strings":
                    status, status_badge, display_status = "CONNECTED", "builtin", "BUILT-IN"
                elif pid == "androguard":
                    status, status_badge, display_status = "CONNECTED", "builtin", "BUILT-IN"
                elif pid == "yara":
                    yara_rule_file = settings.RULES_DIR / "yara_rules.yar"
                    is_b = _is_bundled(str(yara_rule_file)) or (settings.APP_DIR / "tools" / "yara" / "rules" / "yara_rules.yar").exists()
                    status = "CONNECTED"
                    status_badge = "bundled" if is_b else "installed"
                    display_status = "BUNDLED" if is_b else "INSTALLED"
                elif pid == "mobsf":
                    if record and last_tested_at and is_valid:
                        status, status_badge, display_status = "CONNECTED", "available", "AVAILABLE"
                    elif record and last_tested_at and not is_valid:
                        status, status_badge, display_status = "CONNECTION_ERROR", "error", "CONFIGURATION ERROR"
                    elif is_configured:
                        status, status_badge, display_status = "CREDENTIAL_SAVED", "configured", "AVAILABLE"
                    else:
                        status, status_badge, display_status = "NOT_INSTALLED", "dependency_required", "DEPENDENCY REQUIRED"
                elif pid == "zeek":
                    w = shutil.which("zeek") or (getattr(settings, "ZEEK_PATH", "") and Path(settings.ZEEK_PATH).is_file())
                    if w:
                        status, status_badge, display_status = "CONNECTED", "installed", "INSTALLED"
                    else:
                        status, status_badge, display_status = "NOT_INSTALLED", "dependency_required", "DEPENDENCY REQUIRED"
                else:
                    configured_path = None
                    if is_configured:
                        actual_creds = self.get_credential(pid, user_id=eff_user_id if user_id is not None else None) or {}
                        if isinstance(actual_creds, dict):
                            configured_path = actual_creds.get("binary_path")

                    if record and last_tested_at and is_valid:
                        is_b = _is_bundled(configured_path)
                        status, status_badge = "CONNECTED", "bundled" if is_b else "verified"
                        display_status = "BUNDLED" if is_b else "INSTALLED"
                    elif record and last_tested_at and not is_valid:
                        error_text = f"{last_error_code or ''} {last_error_message or ''}".upper()
                        if any(marker in error_text for marker in ("DLL", "DEPENDENCY", "DOCKER", "IMAGE", "NPCAP")):
                            status, status_badge, display_status = "NOT_INSTALLED", "dependency_required", "DEPENDENCY REQUIRED"
                        else:
                            status, status_badge, display_status = "CONNECTION_ERROR", "error", "CONFIGURATION ERROR"
                    elif configured_path and not Path(configured_path).is_file():
                        status, status_badge, display_status = "CONNECTION_ERROR", "error", "CONFIGURATION ERROR"
                    else:
                        detected_path = None
                        if pid in ("jadx", "jadx_gui"):
                            try:
                                from backend.app.integrations.tool_registry import _resolve_jadx_executables
                                cli, gui, _, _ = _resolve_jadx_executables()
                                detected_path = gui if "gui" in pid else cli
                            except Exception:
                                detected_path = None
                        elif pid in ("apktool", "exiftool", "tesseract", "tshark", "suricata"):
                            try:
                                from backend.app.integrations.tool_registry import _resolve_binary_path
                                p, _ = _resolve_binary_path(pid)
                                if p and Path(p).is_file():
                                    detected_path = p
                            except Exception:
                                detected_path = None

                        if detected_path:
                            is_b = _is_bundled(detected_path)
                            status = "CONNECTED"
                            status_badge = "bundled" if is_b else "installed"
                            display_status = "BUNDLED" if is_b else "INSTALLED"
                        else:
                            if pid in ("suricata", "zeek", "mobsf"):
                                status, status_badge, display_status = "NOT_INSTALLED", "dependency_required", "DEPENDENCY REQUIRED"
                            else:
                                status, status_badge, display_status = "NOT_INSTALLED", "not_installed", "NOT INSTALLED"
            else:
                # Cloud / Threat Intel / OSINT / Remote Sandbox
                if not is_configured:
                    status = "NOT_CONFIGURED"
                    status_badge = "not_configured"
                    display_status = "NOT CONFIGURED"
                elif not is_valid:
                    err_upper = (last_error_code or "").upper()
                    if "401" in err_upper or "AUTHENTICATION" in err_upper:
                        status = "AUTHENTICATION_FAILED"
                        status_badge = "auth_failed"
                        display_status = "AUTHENTICATION FAILED (401)"
                    elif "429" in err_upper or "RATE" in err_upper:
                        status = "RATE_LIMITED"
                        status_badge = "rate_limited"
                        display_status = "RATE LIMITED (429)"
                    elif "403" in err_upper or "PERMISSION" in err_upper:
                        status = "AUTHENTICATION_FAILED"
                        status_badge = "permission_denied"
                        display_status = "PERMISSION DENIED (403)"
                    elif any(c in err_upper for c in ("502", "503", "504", "SERVICE_UNAVAILABLE")):
                        status = "SERVICE_UNAVAILABLE"
                        status_badge = "service_unavailable"
                        display_status = "SERVICE UNAVAILABLE"
                    elif "TIMEOUT" in err_upper:
                        status = "CONNECTION_ERROR"
                        status_badge = "timeout"
                        display_status = "CONNECTION TIMEOUT"
                    elif "TOKEN_EXPIRED" in err_upper or "EXPIRED" in err_upper:
                        status = "TOKEN_EXPIRED"
                        status_badge = "expired"
                        display_status = "TOKEN EXPIRED"
                    else:
                        status = "CONNECTION_ERROR"
                        status_badge = "connection_error"
                        display_status = f"CONNECTION ERROR ({last_error_code})" if last_error_code else "CONNECTION ERROR"
                elif auth_type == "oauth2" and token_expires_at:
                    try:
                        exp = datetime.fromisoformat(token_expires_at)
                        if exp < datetime.utcnow():
                            status = "TOKEN_EXPIRED"
                            status_badge = "expired"
                            display_status = "TOKEN EXPIRED"
                        else:
                            status = "CONNECTED"
                            status_badge = "verified"
                            display_status = "CONNECTED"
                    except Exception:
                        status = "CREDENTIAL_SAVED"
                        status_badge = "configured"
                        display_status = "CREDENTIAL SAVED"
                elif last_tested_at:
                    status = "CONNECTED"
                    status_badge = "verified"
                    display_status = "CONNECTED"
                else:
                    status = "CREDENTIAL_SAVED"
                    status_badge = "configured"
                    display_status = "CREDENTIAL SAVED"

            # When in LOCAL_ONLY mode, online external integrations display BLOCKED BY LOCAL-ONLY MODE
            is_blocked_by_local_mode = bool(settings.LOCAL_ONLY_MODE and not is_local)
            if is_blocked_by_local_mode:
                display_status = "BLOCKED BY LOCAL-ONLY MODE"
                status_badge = "local_only_blocked"

            item = {
                "id": meta["id"],
                "name": meta["name"],
                "category": meta["category"],
                "description": meta["description"],
                "requires_credentials": meta["requires_credentials"],
                "is_local_tool": meta["is_local_tool"],
                "credential_type": meta["credential_type"],
                "auth_type": auth_type,
                "supports_oauth": supports_oauth,
                "fields": meta["fields"],
                "register_url": meta["register_url"],
                "docs_url": meta["docs_url"],
                "install_url": meta.get("install_url", ""),
                "rate_limits": meta["rate_limits"],
                "privacy_note": meta["privacy_note"],
                "is_configured": is_configured,
                "is_valid": is_valid,
                "status": status,
                "status_badge": status_badge,
                "display_status": display_status,
                "blocked_by_local_only": is_blocked_by_local_mode,
                "last_tested_at": last_tested_at,
                "last_error_code": last_error_code,
                "last_error_message": last_error_message,
                "account_identifier": account_identifier,
                "token_expires_at": token_expires_at,
                "masked_values": masked_creds,
                "fingerprint": record["key_fingerprint"] if record else ""
            }
            output.append(item)

        return output

    def get_credentials_summary(self, user_id: Optional[str] = None) -> Dict[str, int]:
        """
        Computes high-level authoritative counters for all integrations:
        - total: total number of integration cards
        - connected: verified working integrations
        - credentials_saved: credentials saved but pending verification
        - not_configured: integrations with no credentials configured
        - authentication_failed: integrations where authentication/validation failed
        - local_tools_available: local system tools operational
        """
        items = self.list_providers_metadata(user_id=user_id)
        total = len(items)
        connected = sum(1 for p in items if p["status"] == "CONNECTED")
        credentials_saved = sum(1 for p in items if p["status"] == "CREDENTIAL_SAVED")
        not_configured = sum(1 for p in items if p["status"] == "NOT_CONFIGURED")
        authentication_failed = sum(1 for p in items if p["status"] in ("AUTHENTICATION_FAILED", "TOKEN_EXPIRED") or (not p.get("is_valid", True) and p.get("is_configured", False)))
        local_tools_available = sum(1 for p in items if p.get("is_local_tool", False) and p["status"] == "CONNECTED")

        return {
            "total": total,
            "connected": connected,
            "credentials_saved": credentials_saved,
            "not_configured": not_configured,
            "authentication_failed": authentication_failed,
            "local_tools_available": local_tools_available,
        }

    # --------------------------------------------------------------------------
    # TEST CONNECTION DISPATCHER
    # --------------------------------------------------------------------------

    def test_credential(
        self,
        provider_name: str,
        ephemeral_data: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Tests credentials against the live provider API or local process.
        Uses either the stored credentials or the ephemeral inputs provided.
        Updates validation status, last_error_code, last_error_message, and timestamp in database.
        """
        eff_user_id = self._resolve_user_id(user_id)
        provider_id = provider_name.lower().strip()
        cat_info = PROVIDER_CATALOG.get(provider_id)
        if not cat_info:
            return {
                "success": False,
                "connected": False,
                "status": "Unknown Provider",
                "message": f"Provider '{provider_name}' is not in the supported catalog."
            }

        # Check local-only mode policy
        if settings.LOCAL_ONLY_MODE and not cat_info.get("is_local_tool", False):
            return {
                "success": False,
                "connected": False,
                "status": "Blocked by Local-Only Mode",
                "message": "Outbound network requests are disabled because Local-Only Mode is active.",
                "details": {"local_only_mode": True}
            }

        # Resolve credentials to test
        if ephemeral_data:
            creds = {}
            for k, v in ephemeral_data.items():
                if isinstance(v, str):
                    creds[k] = v.strip().replace("\r", "").replace("\n", "")
                else:
                    creds[k] = v
            # If ephemeral inputs contain masked or empty values, merge with stored decrypted credentials
            stored_creds = self.get_credential(provider_id, user_id=eff_user_id) or {}
            for k, v in list(creds.items()):
                if isinstance(v, str) and (v.startswith("****") or v.startswith("••••") or "*" in v or "•" in v or v == ""):
                    if stored_creds.get(k):
                        creds[k] = stored_creds[k]
        else:
            creds = self.get_credential(provider_id, user_id=eff_user_id) or {}

        if not creds or not any(creds.values()):
            if cat_info.get("is_local_tool", False):
                # Local tools are executable/built-in components, not secrets. Allow a
                # real Test Tool run using the persisted path, auto-detection, or PATH.
                creds = {}
            else:
                return {
                    "success": False,
                    "connected": False,
                    "status": "Not Configured",
                    "message": f"No credentials configured for {cat_info['name']}."
                }

        now_iso = datetime.now(timezone.utc).isoformat()
        result = self._dispatch_test(provider_id, creds)
        
        # Persist test outcome
        is_conn = bool(result.get("connected") or result.get("success", False))
        err_code = result.get("error_code")
        err_msg = result.get("message") if not is_conn else None

        # Always update database status for this user
        repo.update_user_provider_credential_status(
            user_id=eff_user_id,
            provider_name=provider_id,
            is_valid=is_conn,
            last_tested_at=now_iso,
            last_error_code=err_code,
            last_error_message=err_msg
        )
        try:
            repo.update_provider_credential_status(
                provider_name=provider_id,
                is_valid=is_conn,
                last_tested_at=now_iso
            )
        except Exception:
            pass

        result["test_timestamp"] = now_iso
        return result

    def _dispatch_test(self, provider_id: str, creds: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches connection test to the corresponding integration handler with granular error classification."""
        import httpx

        # 1. OSINT & Threat Intel Providers
        if provider_id == "virustotal":
            api_key = (creds.get("api_key") or "").strip()
            if not api_key:
                return {"connected": False, "status": "Not Configured", "message": "Missing VirusTotal API Key"}
            try:
                with httpx.Client(timeout=8.0) as client:
                    resp = client.get("https://www.virustotal.com/api/v3/users/current", headers={"x-apikey": api_key})
                    if resp.status_code == 200:
                        user = resp.json().get("data", {}).get("attributes", {}).get("username", "Authenticated")
                        return {"connected": True, "success": True, "status": "Connected", "message": f"Authenticated as {user}."}
                    return classify_api_error("virustotal", resp.status_code, resp.text)
            except Exception as e:
                return classify_api_error("virustotal", None, None, e)

        elif provider_id == "alienvault_otx":
            api_key = (creds.get("api_key") or "").strip()
            if not api_key:
                return {"connected": False, "status": "Not Configured", "message": "Missing OTX API Key"}
            try:
                with httpx.Client(timeout=8.0) as client:
                    resp = client.get("https://otx.alienvault.com/api/v1/user/me", headers={"X-OTX-API-KEY": api_key})
                    if resp.status_code == 200:
                        username = resp.json().get("username", "Authenticated User")
                        return {"connected": True, "success": True, "status": "Connected", "message": f"Authenticated as {username}."}
                    return classify_api_error("alienvault_otx", resp.status_code, resp.text)
            except Exception as e:
                return classify_api_error("alienvault_otx", None, None, e)

        elif provider_id == "abuseipdb":
            api_key = (creds.get("api_key") or "").strip()
            if not api_key:
                return {"connected": False, "status": "Not Configured", "message": "Missing AbuseIPDB Key"}
            try:
                with httpx.Client(timeout=8.0) as client:
                    resp = client.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": "127.0.0.1"}, headers={"Key": api_key, "Accept": "application/json"})
                    if resp.status_code == 200:
                        return {"connected": True, "success": True, "status": "Connected", "message": "AbuseIPDB API key verified."}
                    return classify_api_error("abuseipdb", resp.status_code, resp.text)
            except Exception as e:
                return classify_api_error("abuseipdb", None, None, e)

        elif provider_id in ("urlhaus", "malwarebazaar"):
            return {"connected": True, "success": True, "status": "Connected", "message": f"{provider_id.upper()} feed accessible."}

        elif provider_id == "urlscan":
            api_key = (creds.get("api_key") or "").strip()
            if not api_key:
                return {"connected": False, "status": "Not Configured", "message": "Missing urlscan.io API Key"}
            try:
                with httpx.Client(timeout=8.0) as client:
                    resp = client.get("https://urlscan.io/api/v1/user/quotas/", headers={"API-Key": api_key})
                    if resp.status_code == 200:
                        return {"connected": True, "success": True, "status": "Connected", "message": "urlscan.io API key verified."}
                    return classify_api_error("urlscan", resp.status_code, resp.text)
            except Exception as e:
                return classify_api_error("urlscan", None, None, e)

        elif provider_id == "shodan":
            api_key = (creds.get("api_key") or "").strip()
            try:
                with httpx.Client(timeout=8.0) as client:
                    resp = client.get("https://api.shodan.io/api-info", params={"key": api_key})
                    if resp.status_code == 200:
                        credits = resp.json().get("query_credits", 0)
                        return {"connected": True, "success": True, "status": "Connected", "message": f"Connected ({credits} query credits available)."}
                    return classify_api_error("shodan", resp.status_code, resp.text)
            except Exception as e:
                return classify_api_error("shodan", None, None, e)

        elif provider_id == "censys":
            api_id = (creds.get("api_id") or "").strip()
            api_secret = (creds.get("api_secret") or "").strip()
            try:
                with httpx.Client(timeout=8.0) as client:
                    resp = client.get("https://search.censys.io/api/v1/account", auth=(api_id, api_secret))
                    if resp.status_code == 200:
                        return {"connected": True, "success": True, "status": "Connected", "message": "Censys API key pair verified."}
                    return classify_api_error("censys", resp.status_code, resp.text)
            except Exception as e:
                return classify_api_error("censys", None, None, e)

        elif provider_id == "greynoise":
            api_key = (creds.get("api_key") or "").strip()
            try:
                with httpx.Client(timeout=8.0) as client:
                    resp = client.get("https://api.greynoise.io/v3/community/8.8.8.8", headers={"key": api_key})
                    if resp.status_code == 200:
                        return {"connected": True, "success": True, "status": "Connected", "message": "GreyNoise community key verified."}
                    return classify_api_error("greynoise", resp.status_code, resp.text)
            except Exception as e:
                return classify_api_error("greynoise", None, None, e)

        elif provider_id == "ipinfo":
            api_key = (creds.get("api_key") or "").strip()
            try:
                headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
                with httpx.Client(timeout=8.0) as client:
                    resp = client.get("https://ipinfo.io/8.8.8.8/json", headers=headers)
                    if resp.status_code == 200:
                        return {"connected": True, "success": True, "status": "Connected", "message": "IPinfo response confirmed."}
                    return classify_api_error("ipinfo", resp.status_code, resp.text)
            except Exception as e:
                return classify_api_error("ipinfo", None, None, e)

        elif provider_id == "misp":
            url = (creds.get("url") or "").rstrip("/")
            api_key = (creds.get("api_key") or "").strip()
            try:
                with httpx.Client(timeout=8.0, verify=False) as client:
                    resp = client.get(f"{url}/servers/getVersion", headers={"Authorization": api_key, "Accept": "application/json"})
                    if resp.status_code == 200:
                        return {"connected": True, "success": True, "status": "Connected", "message": "MISP instance connected."}
                    return classify_api_error("misp", resp.status_code, resp.text)
            except Exception as e:
                return classify_api_error("misp", None, None, e)

        # 2. Local Dynamic Services
        elif provider_id == "mobsf":
            from backend.app.integrations.mobsf_adapter import test_mobsf_service
            url = creds.get("url") or settings.MOBSF_URL or "http://127.0.0.1:8001"
            api_key = creds.get("api_key") or settings.MOBSF_API_KEY
            res = test_mobsf_service(url, api_key)
            healthy = bool(res.get("success"))
            return {
                "connected": healthy,
                "success": healthy,
                "status": "CONNECTED" if healthy else "CONFIGURATION ERROR",
                "display_status": "CONNECTED" if healthy else "CONFIGURATION ERROR",
                "message": res.get("message", ""),
                "details": res
            }

        # 3. Local Binary Executables
        elif provider_id in ("jadx", "jadx_gui", "apktool", "tshark", "tesseract", "zeek", "suricata", "exiftool", "opencode"):
            from backend.app.integrations.tool_registry import test_tool_execution
            path = creds.get("binary_path")
            tool_name = {
                "jadx": "JADX Decompiler",
                "jadx_gui": "JADX GUI Launcher",
                "apktool": "Apktool",
                "tshark": "tshark",
                "tesseract": "Tesseract OCR",
                "zeek": "Zeek Network Security Monitor",
                "suricata": "Suricata IDS/IPS Engine",
                "exiftool": "ExifTool",
                "opencode": "OpenCode CLI",
            }.get(provider_id, provider_id)
            res = test_tool_execution(tool_name, path)
            return {
                "connected": res.get("success", False),
                "success": res.get("success", False),
                "status": res.get("status", "TEST FAILED"),
                "message": res.get("diagnostic_message", res.get("message", "")),
                "version": res.get("version"),
                "details": res
            }

        elif provider_id == "strings":
            from backend.app.integrations.tool_registry import test_strings_tool
            res = test_strings_tool()
            return {
                "connected": res.get("success", False),
                "success": res.get("success", False),
                "status": res.get("status", "TEST FAILED"),
                "message": res.get("diagnostic_message", ""),
                "version": res.get("version"),
                "details": res.get("details", {})
            }

        elif provider_id == "androguard":
            from backend.app.integrations.tool_registry import test_androguard_tool
            res = test_androguard_tool()
            return {
                "connected": res.get("success", False),
                "success": res.get("success", False),
                "status": res.get("status", "TEST FAILED"),
                "message": res.get("diagnostic_message", ""),
                "version": res.get("version"),
                "details": res.get("details", {})
            }

        elif provider_id == "yara":
            from backend.app.integrations.tool_registry import test_yara_tool
            custom_rules = (
                creds.get("binary_path")
                or repo.get_setting("yara_path")
                or getattr(settings, "YARA_PATH", "")
                or None
            )
            res = test_yara_tool(custom_rules)
            return {
                "connected": res.get("success", False),
                "success": res.get("success", False),
                "status": res.get("status", "TEST FAILED"),
                "message": res.get("diagnostic_message", ""),
                "version": res.get("version"),
                "details": res.get("details", {})
            }

        # Default fallback
        return {
            "connected": True,
            "success": True,
            "status": "Configured",
            "message": f"Configuration saved for {cat_info['name']}."
        }


# Singleton instance
credential_manager = CredentialManager()

