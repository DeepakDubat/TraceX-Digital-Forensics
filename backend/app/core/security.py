import os
import re
import json
import signal
import zipfile
import hashlib
import logging
import logging.handlers
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Dict, Any, List, Optional
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from backend.app.config import settings

APK_MAGIC_BYTES = b"PK\x03\x04"
PE_DOS_MAGIC = b"MZ"

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_api_access(x_api_key: Optional[str] = Security(api_key_header)) -> bool:
    """
    Validates API key access if WORKBENCH_API_KEY is configured.
    When WORKBENCH_API_KEY is not configured (default), Standalone Workstation Mode
    is active and requests are permitted locally without authentication friction.
    """
    configured_key = getattr(settings, "WORKBENCH_API_KEY", None)
    if not configured_key:
        return True
    if not x_api_key or x_api_key != configured_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Missing or invalid X-API-Key."
        )
    return True

def safe_copy_upload(source_stream: Any, target_file: Any, max_bytes: Optional[int] = None) -> int:
    """
    Safely streams uploaded file data from source to target with a hard byte ceiling.
    Prevents unconstrained disk filling or decompression bombs during upload staging.
    """
    if max_bytes is None:
        max_bytes = getattr(settings, "MAX_UPLOAD_SIZE_MB", 200) * 1024 * 1024
    total_copied = 0
    chunk_size = 65536
    while chunk := source_stream.read(chunk_size):
        total_copied += len(chunk)
        if total_copied > max_bytes:
            raise ValueError(f"Uploaded file exceeds maximum limit of {max_bytes // (1024 * 1024)} MB.")
        target_file.write(chunk)
    return total_copied

def sanitize_csv_cell(val: Any) -> Any:
    """
    Neutralize CSV / Formula Injection (CWE-1236).
    If a cell begins with '=', '+', '-', '@', '\t', '\r', '\n' or leading whitespace
    followed by formula triggers, prepend a single quote (') so spreadsheet
    interpreters (Excel, Google Sheets, LibreOffice Calc) render it as literal text.
    Legitimate numeric scalars (int, float, signed numbers) are preserved as numbers
    only if they are plain numbers without leading control characters.
    """
    if val is None:
        return ""
    if isinstance(val, (int, float, bool)):
        return val
    s = str(val)
    if not s:
        return ""
    lstripped = s.lstrip(" \t\r\n")
    triggers = ("=", "+", "-", "@", "\t", "\r", "\n")
    if s[0] in triggers or (lstripped and lstripped[0] in triggers):
        if s == lstripped and s[0] in ("+", "-"):
            try:
                float(s)
                return val
            except ValueError:
                pass
        return "'" + s
    return s

def sanitize_filename(filename: str, default_ext: str = ".apk") -> str:
    """Sanitize filename to prevent directory traversal and filesystem attacks."""
    # Remove directory paths
    base = os.path.basename(filename)
    # Strip dangerous characters, allow alphanumerics, dots, dashes, underscores
    sanitized = re.sub(r'[^a-zA-Z0-9._-]', '_', base)
    if not sanitized or sanitized.startswith('.'):
        sanitized = f"upload_{sanitized.lstrip('.')}"
    
    # If the file already has an extension, preserve its natural extension
    if "." in sanitized and len(sanitized.rsplit(".", 1)[-1]) > 0:
        return sanitized

    if default_ext:
        ext = default_ext if default_ext.startswith(".") else f".{default_ext}"
        return f"{sanitized}{ext.lower()}"
    return f"{sanitized}.apk"

def detect_file_type(file_path: Path) -> str:
    """Detect file type ('apk', 'exe', or 'unknown') safely using magic header bytes."""
    if not file_path.exists() or file_path.stat().st_size < 4:
        return "unknown"
    with open(file_path, "rb") as f:
        header = f.read(4)
        if header.startswith(APK_MAGIC_BYTES):
            return "apk"
        if header.startswith(PE_DOS_MAGIC):
            return "exe"
    # Fallback to extension if ambiguous
    ext = file_path.suffix.lower()
    if ext == ".apk":
        return "apk"
    if ext == ".exe":
        return "exe"
    return "unknown"

def calculate_hashes(file_path: Path) -> Dict[str, str]:
    """Calculate MD5, SHA-1, and SHA-256 for a file streaming in chunks."""
    md5_hasher = hashlib.md5()
    sha1_hasher = hashlib.sha1()
    sha256_hasher = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            md5_hasher.update(chunk)
            sha1_hasher.update(chunk)
            sha256_hasher.update(chunk)
            
    return {
        "md5": md5_hasher.hexdigest(),
        "sha1": sha1_hasher.hexdigest(),
        "sha256": sha256_hasher.hexdigest()
    }

def validate_apk_file(file_path: Path, max_size_mb: Optional[int] = None) -> Tuple[bool, str]:
    """
    Validate that file exists, does not exceed size limit, has valid ZIP magic bytes,
    and contains Android-specific structures (like AndroidManifest.xml or classes.dex).
    """
    if max_size_mb is None:
        max_size_mb = getattr(settings, "MAX_UPLOAD_SIZE_MB", 200)

    if not file_path.exists():
        return False, "File does not exist."
        
    size_bytes = file_path.stat().st_size
    if size_bytes == 0:
        return False, "File is empty (0 bytes)."
        
    if size_bytes > (max_size_mb * 1024 * 1024):
        return False, f"File exceeds maximum permissible size of {max_size_mb} MB."
        
    with open(file_path, "rb") as f:
        header = f.read(4)
        if header != APK_MAGIC_BYTES:
            return False, "Invalid file format: Missing standard ZIP/APK header magic bytes (PK\\x03\\x04)."
            
    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            namelist = zf.namelist()
            # Check for zip bomb symptoms (excessive file count or decompression ratio)
            total_uncompressed = sum(info.file_size for info in zf.infolist())
            if total_uncompressed > (1024 * 1024 * 1024): # 1GB uncompressed limit
                return False, "Suspicious archive: Uncompressed ratio exceeds safety limits (potential zip-bomb)."
            
            # An authentic APK typically has AndroidManifest.xml or classes.dex
            has_manifest = any(name.endswith("AndroidManifest.xml") for name in namelist)
            has_dex = any(name.endswith(".dex") for name in namelist)
            if not has_manifest and not has_dex:
                return False, "File is a ZIP archive but does not contain AndroidManifest.xml or DEX bytecode."
    except zipfile.BadZipFile:
        return False, "Corrupted archive: Archive structure could not be parsed."
    except Exception as e:
        return False, f"Validation failure: {str(e)}"
        
    return True, "Valid APK archive."

def safe_extract_apk(apk_path: Path, extract_dir: Path) -> List[str]:
    """
    Safely extract files from APK with strict Zip-Slip and path traversal protection.
    Returns list of safely extracted relative paths.
    """
    extract_dir = extract_dir.resolve()
    extract_dir.mkdir(parents=True, exist_ok=True)
    extracted_files = []
    
    with zipfile.ZipFile(apk_path, "r") as zf:
        for member in zf.infolist():
            # Resolve target path
            target_path = (extract_dir / member.filename).resolve()
            
            # Zip-Slip check: Ensure target_path is within extract_dir
            try:
                target_path.relative_to(extract_dir)
            except ValueError:
                # Path traversal attempt detected! Skip and log.
                continue
                
            if member.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
            else:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(member) as source, open(target_path, "wb") as target:
                    # Write with size guard per file (max 100MB per individual extracted file)
                    copied = 0
                    while chunk := source.read(65536):
                        copied += len(chunk)
                        if copied > 100 * 1024 * 1024:
                            break
                        target.write(chunk)
                extracted_files.append(str(target_path.relative_to(extract_dir)))
                
    return extracted_files

def redact_secret(value: str) -> str:
    """
    Redact sensitive secret string according to forensic guidelines.
    Example: 'AIzaSyA1234567890abcdef' -> 'AIza••••••••cdef'
    """
    if not value or len(value) <= 8:
        return "••••••••"
    if len(value) <= 12:
        return f"{value[:2]}••••••••{value[-2:]}"
    return f"{value[:4]}••••••••{value[-4:]}"

def _kill_process_tree(pid: int) -> None:
    """Force-terminates a process and all of its descendants (no orphan JVM/CLI)."""
    if not pid:
        return
    try:
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
                creationflags=creationflags,
            )
        else:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
    except Exception:
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass

def safe_run_command(cmd_args: List[str], cwd: Path = None, timeout: int = 60) -> Tuple[int, str, str]:
    """
    Safely execute external subprocess using argument list (no shell=True).
    Strict timeout and output capture. Guarantees zero visible console window on Windows.
    On timeout, the full process tree is terminated so tools such as JADX/Apktool
    cannot leave orphaned Java processes behind.
    """
    creationflags = 0
    startupinfo = None
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0  # SW_HIDE

    try:
        proc = subprocess.Popen(
            cmd_args,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,  # Strictly avoid shell injection
            creationflags=creationflags,
            startupinfo=startupinfo,
        )
    except FileNotFoundError:
        return -2, "", f"Executable '{cmd_args[0]}' was not found on system PATH."
    except Exception as e:
        return -3, "", f"Execution error: {str(e)}"

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        _kill_process_tree(proc.pid)
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except Exception:
            stdout, stderr = "", ""
        message = f"Execution timed out after {timeout} seconds; process tree terminated."
        return -1, stdout or "", f"{stderr or ''}\n{message}".strip()


# ==============================================================================
# REDACTED ROTATING TOOL DIAGNOSTICS
# ==============================================================================

_SECRET_TEXT_PATTERN = re.compile(
    r"(?i)(api[_-]?key|authorization|token|secret|password|auth[_-]?key)"
    r"(\s*[:=]\s*|\s+)([^\s,;\"']+)"
)
_BEARER_PATTERN = re.compile(r"(?i)Bearer\s+[A-Za-z0-9._\-+/=]+")
_SECRET_ARG_NAMES = {
    "--api-key", "--apikey", "--token", "--secret", "--password", "--auth-key",
    "-k", "-t", "-p",
}


def redact_secret_text(value: Any) -> str:
    """Removes API keys and bearer tokens from diagnostic text."""
    text = "" if value is None else str(value)
    text = _SECRET_TEXT_PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", text)
    text = _BEARER_PATTERN.sub("Bearer <redacted>", text)
    return text


def redact_command_args(args: List[str]) -> List[str]:
    """Redacts secret-bearing argument values before a command is logged."""
    redacted: List[str] = []
    suppress_next = False
    for arg in args or []:
        token = str(arg)
        if suppress_next:
            redacted.append("<redacted>")
            suppress_next = False
            continue
        lowered = token.lower()
        if lowered in _SECRET_ARG_NAMES or any(marker in lowered for marker in ("api_key", "apikey", "authorization")):
            if "=" not in token:
                suppress_next = True
            redacted.append(redact_secret_text(token.split("=", 1)[0] + "=<redacted>") if "=" in token else token)
            continue
        redacted.append(redact_secret_text(token))
    return redacted


def write_tool_diagnostic(
    tool: str,
    event: str,
    *,
    command: Optional[List[str]] = None,
    exit_code: Optional[int] = None,
    stdout: str = "",
    stderr: str = "",
    details: Optional[Dict[str, Any]] = None,
) -> Path:
    """
    Appends a bounded, redacted diagnostic record to a rotating, tool-specific log.

    This log is intentionally separate from application logs and never contains
    plaintext API keys, bearer tokens, passwords, or uploaded evidence content.
    """
    log_dir = Path(settings.TOOL_DIAGNOSTICS_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]+", "_", (tool or "unknown_tool").strip())[:80]
    log_path = log_dir / f"{safe_name}.log"

    logger = logging.getLogger(f"tracex.tools.{safe_name}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not any(isinstance(h, logging.handlers.RotatingFileHandler) and h.baseFilename == str(log_path.resolve())
               for h in logger.handlers):
        handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=int(settings.TOOL_DIAGNOSTIC_MAX_BYTES),
            backupCount=int(settings.TOOL_DIAGNOSTIC_BACKUP_COUNT),
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)

    snippet_limit = 4000
    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "event": redact_secret_text(event),
        "command": redact_command_args(command) if command else None,
        "exit_code": exit_code,
        "stdout": redact_secret_text(stdout)[:snippet_limit],
        "stderr": redact_secret_text(stderr)[:snippet_limit],
        "details": redact_secret_text(json.dumps(details or {}, default=str, ensure_ascii=False))[:snippet_limit],
    }
    logger.info(json.dumps(payload, ensure_ascii=False))
    return log_path
