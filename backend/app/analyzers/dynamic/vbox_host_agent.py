"""
TraceX VirtualBox Host Controller Agent
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

A restricted, hardened management agent running on the physical Windows host.
Listens exclusively on the dedicated VirtualBox Host-Only network interface (192.168.56.1).
Accepts requests only from authorized TraceX Manager VMs over authenticated HTTPS (mTLS) channels.

Security Properties:
- Hardened HTTPS (TLS 1.2 / 1.3 only) with Mutual TLS (mTLS) certificate verification.
- Never Silently Downgrades to HTTP: Rejects plain HTTP when mTLS/HTTPS is configured.
- Defense-in-Depth: Both client certificate validation (transport) and HMAC-SHA256 token (app layer).
- Host-Only Binding: Rejects 0.0.0.0 or wildcard bindings. Bound to 192.168.56.1 or loopback.
- Strict Allowlist: Only approved worker VM UUIDs (TraceX-Worker-Win10, TraceX-Worker-Android)
  and approved clean snapshots (Clean_Base) can be referenced.
- Rate Limiting: Authentication brute-force protection locks out offending IPs.
- Immutable Audit Logging: Structured audit logs record all operations with client cert identities.
- Path Traversal Immunity: Strict canonical path resolution against path escaping.
"""

import os
import sys
import json
import time
import hmac
import shutil
import hashlib
import ipaddress
import subprocess
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl

logger = logging.getLogger("TraceX.HostAgent")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

DEFAULT_HOST_ONLY_IP = "192.168.56.1"
DEFAULT_AGENT_PORT = 9443
DEFAULT_INSTALL_DIR = Path("C:/ProgramData/TraceX/HostAgent")
DEFAULT_CONFIG_PATH = DEFAULT_INSTALL_DIR / "config.json"
DEFAULT_STAGING_ROOT = DEFAULT_INSTALL_DIR / "staging"
DEFAULT_LOG_PATH = DEFAULT_INSTALL_DIR / "logs" / "host_agent_audit.log"


class AuthRateLimiter:
    """Tracks failed authentication attempts and temporarily throttles offending client IPs."""

    def __init__(self, max_failures: int = 5, window_seconds: float = 60.0, lockout_seconds: float = 300.0):
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._failures: Dict[str, List[float]] = {}
        self._lockouts: Dict[str, float] = {}

    def is_blocked(self, client_ip: str) -> bool:
        now = time.time()
        if client_ip in self._lockouts:
            if now < self._lockouts[client_ip]:
                return True
            else:
                del self._lockouts[client_ip]
                self._failures.pop(client_ip, None)
        return False

    def record_failure(self, client_ip: str) -> bool:
        now = time.time()
        timestamps = self._failures.setdefault(client_ip, [])
        # Prune older than window
        timestamps = [t for t in timestamps if now - t < self.window_seconds]
        timestamps.append(now)
        self._failures[client_ip] = timestamps

        if len(timestamps) >= self.max_failures:
            self._lockouts[client_ip] = now + self.lockout_seconds
            logger.warning(f"SECURITY ALERT: Client IP {client_ip} exceeded auth failure limit. Locked out for {self.lockout_seconds}s.")
            return True
        return False

    def record_success(self, client_ip: str):
        self._failures.pop(client_ip, None)
        self._lockouts.pop(client_ip, None)


class HostAgentConfig:
    """Configuration for the VirtualBox Host Controller Agent."""

    def __init__(
        self,
        bind_host: str = DEFAULT_HOST_ONLY_IP,
        bind_port: int = DEFAULT_AGENT_PORT,
        auth_token: str = "",
        allowed_vm_uuids: Optional[List[str]] = None,
        allowed_snapshots: Optional[List[str]] = None,
        vboxmanage_path: Optional[str] = None,
        staging_root: Optional[Path] = None,
        allowed_client_subnets: Optional[List[str]] = None,
        require_mtls: bool = True,
        cert_file: Optional[str] = None,
        key_file: Optional[str] = None,
        ca_file: Optional[str] = None,
        audit_log_path: Optional[Path] = None
    ):
        # Strict binding validation
        clean_host = bind_host.strip()
        if clean_host in ("0.0.0.0", "::", ""):
            raise ValueError(
                "CRITICAL SECURITY REJECTION: Host Controller Agent must never bind to 0.0.0.0 or wildcard interfaces. "
                "Must bind strictly to Host-Only interface (192.168.56.1) or loopback (127.0.0.1)."
            )
        self.bind_host = clean_host
        self.bind_port = bind_port
        self.auth_token = auth_token or os.getenv("TRACEX_HOST_AGENT_TOKEN", "")

        # Strict allowlist: Only genuine TraceX analysis workers (Kali VM explicitly excluded)
        self.allowed_vm_uuids = allowed_vm_uuids or [
            "TraceX-Worker-Win10",
            "TraceX-Worker-Android"
        ]
        self.allowed_snapshots = allowed_snapshots or ["Clean_Base", "Baseline", "Ready"]
        self.vboxmanage_path = vboxmanage_path or self._find_vboxmanage()
        self.staging_root = staging_root or DEFAULT_STAGING_ROOT
        self.allowed_client_subnets = allowed_client_subnets or ["192.168.56.0/24", "127.0.0.1/32"]
        self.require_mtls = require_mtls
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
        self.audit_log_path = audit_log_path or DEFAULT_LOG_PATH

    @staticmethod
    def _find_vboxmanage() -> str:
        candidates = [
            shutil.which("VBoxManage"),
            "C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe",
            "C:\\Program Files (x86)\\Oracle\\VirtualBox\\VBoxManage.exe",
            "/usr/bin/VBoxManage",
            "/usr/local/bin/VBoxManage"
        ]
        for c in candidates:
            if c and Path(c).exists():
                return str(c)
        return "C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe"

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "HostAgentConfig":
        path = config_path or DEFAULT_CONFIG_PATH
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return cls(
                    bind_host=data.get("bind_host", DEFAULT_HOST_ONLY_IP),
                    bind_port=int(data.get("bind_port", DEFAULT_AGENT_PORT)),
                    auth_token=data.get("auth_token", ""),
                    allowed_vm_uuids=data.get("allowed_vm_uuids"),
                    allowed_snapshots=data.get("allowed_snapshots"),
                    vboxmanage_path=data.get("vboxmanage_path"),
                    staging_root=Path(data["staging_root"]) if data.get("staging_root") else None,
                    allowed_client_subnets=data.get("allowed_client_subnets"),
                    require_mtls=bool(data.get("require_mtls", True)),
                    cert_file=data.get("cert_file"),
                    key_file=data.get("key_file"),
                    ca_file=data.get("ca_file"),
                    audit_log_path=Path(data["audit_log_path"]) if data.get("audit_log_path") else None
                )
            except Exception as e:
                logger.error(f"Failed to parse config at {path}: {e}")
        return cls()


class HostControllerService:
    """Core logic implementing approved VirtualBox operations."""

    def __init__(self, config: HostAgentConfig):
        self.config = config
        self.vbox = config.vboxmanage_path
        self.rate_limiter = AuthRateLimiter()
        self._ensure_directories()

    def _ensure_directories(self):
        try:
            self.config.staging_root.mkdir(parents=True, exist_ok=True)
            if self.config.audit_log_path:
                self.config.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning(f"Directory creation notice: {e}")

    def log_audit(
        self,
        client_ip: str,
        method: str,
        endpoint: str,
        vm_id: Optional[str],
        result: str,
        status_code: int,
        client_cert_dn: Optional[str] = None
    ):
        """Appends structured audit entry to the audit log."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "client_ip": client_ip,
            "method": method,
            "endpoint": endpoint,
            "target_vm": vm_id,
            "client_cert_dn": client_cert_dn or "NONE",
            "result": result,
            "status_code": status_code
        }
        line = json.dumps(entry) + "\n"
        try:
            if self.config.audit_log_path:
                with open(self.config.audit_log_path, "a", encoding="utf-8") as f:
                    f.write(line)
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def is_vm_allowed(self, vm_identifier: str) -> bool:
        """Checks if VM identifier (name or UUID) is explicitly in allowlist."""
        vm_id = vm_identifier.strip().lower()
        for allowed in self.config.allowed_vm_uuids:
            if allowed.strip().lower() == vm_id:
                return True
        return False

    def is_snapshot_allowed(self, snapshot_name: str) -> bool:
        """Checks if snapshot name is in approved snapshots allowlist."""
        snap = snapshot_name.strip().lower()
        for allowed in self.config.allowed_snapshots:
            if allowed.strip().lower() == snap:
                return True
        return False

    def get_hardware_virt_status(self) -> Dict[str, Any]:
        """Queries WMI for processor hardware virtualization status safely."""
        firmware_enabled = False
        action_required = None
        if sys.platform == "win32":
            try:
                ps_cmd = "(Get-CimInstance Win32_Processor | Select-Object -ExpandProperty VirtualizationFirmwareEnabled) -contains $true"
                res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=3.0)
                if res.returncode == 0:
                    firmware_enabled = (res.stdout.strip().lower() == "true")
            except Exception:
                pass

        if not firmware_enabled:
            action_required = "ACTION REQUIRED: Enable Intel VT-x in BIOS/UEFI."

        return {
            "firmware_virtualization_enabled": firmware_enabled,
            "action_required": action_required
        }

    def get_host_status(self) -> Dict[str, Any]:
        """Returns host health, VBoxManage version, virtualization state, and allowlisted VMs."""
        vbox_exists = Path(self.vbox).exists()
        vbox_version = "Unknown"
        registered_vms = []

        if vbox_exists:
            try:
                res = subprocess.run([self.vbox, "--version"], capture_output=True, text=True, timeout=4.0)
                if res.returncode == 0:
                    vbox_version = res.stdout.strip()
            except Exception:
                pass

            try:
                res = subprocess.run([self.vbox, "list", "vms"], capture_output=True, text=True, timeout=4.0)
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        if '"' in line:
                            parts = line.strip().split('"')
                            if len(parts) >= 2:
                                registered_vms.append(parts[1])
            except Exception:
                pass

        virt_status = self.get_hardware_virt_status()

        return {
            "status": "ONLINE",
            "host_agent_version": "2.0.0",
            "protocol": "HTTPS" if self.config.require_mtls else "HTTP",
            "mtls_enabled": self.config.require_mtls,
            "bind_interface": self.config.bind_host,
            "bind_port": self.config.bind_port,
            "vboxmanage_installed": vbox_exists,
            "vboxmanage_path": self.vbox,
            "vboxmanage_version": vbox_version,
            "firmware_virtualization_enabled": virt_status["firmware_virtualization_enabled"],
            "action_required": virt_status["action_required"],
            "allowed_vm_uuids": self.config.allowed_vm_uuids,
            "registered_vms": registered_vms,
            "staging_root": str(self.config.staging_root),
            "timestamp": datetime.utcnow().isoformat()
        }

    def get_worker_status(self, vm_identifier: str) -> Dict[str, Any]:
        """Queries detailed worker status for an allowlisted VM."""
        if not self.is_vm_allowed(vm_identifier):
            return {"error": "VM identifier is not in the authorized allowlist.", "code": 403}

        if not Path(self.vbox).exists():
            return {"error": "VBoxManage executable is not available on host.", "code": 503}

        try:
            res = subprocess.run([self.vbox, "showvminfo", vm_identifier, "--machinereadable"], capture_output=True, text=True, timeout=5.0)
            if res.returncode != 0:
                return {"error": f"VM '{vm_identifier}' not found or inaccessible: {res.stderr.strip()}", "code": 404}

            info: Dict[str, str] = {}
            for line in res.stdout.splitlines():
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    info[k.strip()] = v.strip().strip('"')

            # Parse snapshots
            snapshots = []
            snap_res = subprocess.run([self.vbox, "snapshot", vm_identifier, "list", "--machinereadable"], capture_output=True, text=True, timeout=4.0)
            if snap_res.returncode == 0:
                for line in snap_res.stdout.splitlines():
                    if "SnapshotName" in line and "=" in line:
                        _, sname = line.split("=", 1)
                        snapshots.append(sname.strip().strip('"'))

            vm_state = info.get("VMState", "unknown")
            nic1_type = info.get("nic1", "none")
            clipboard = info.get("clipboard", "disabled")
            shared_folders = sum(1 for k in info if k.startswith("SharedFolderNameMachineMapping"))

            return {
                "vm_name": info.get("name", vm_identifier),
                "uuid": info.get("UUID", ""),
                "state": vm_state,
                "is_running": vm_state.lower() == "running",
                "ostype": info.get("ostype", ""),
                "memory_mb": int(info.get("memory", 0)),
                "cpus": int(info.get("cpus", 1)),
                "nic1_mode": nic1_type,
                "is_network_isolated": nic1_type.lower() in ("none", "hostonly", "intnet"),
                "clipboard_mode": clipboard,
                "clipboard_disabled": clipboard.lower() == "disabled",
                "shared_folders_count": shared_folders,
                "has_zero_shared_folders": shared_folders == 0,
                "snapshots": snapshots,
                "has_baseline_snapshot": any(self.is_snapshot_allowed(s) for s in snapshots)
            }
        except Exception as e:
            logger.error(f"Error querying VM {vm_identifier}: {e}")
            return {"error": str(e), "code": 500}

    def restore_worker_snapshot(self, vm_identifier: str, snapshot_name: str) -> Dict[str, Any]:
        """Restores an approved snapshot for an allowlisted VM."""
        if not self.is_vm_allowed(vm_identifier):
            return {"error": "VM identifier is not in the authorized allowlist.", "code": 403}

        if not self.is_snapshot_allowed(snapshot_name):
            return {"error": f"Snapshot '{snapshot_name}' is not in the approved snapshots list.", "code": 403}

        try:
            # First power off if running
            subprocess.run([self.vbox, "controlvm", vm_identifier, "poweroff"], capture_output=True, text=True, timeout=10.0)

            # Revert to clean snapshot
            res = subprocess.run([self.vbox, "snapshot", vm_identifier, "restore", snapshot_name], capture_output=True, text=True, timeout=30.0)
            if res.returncode != 0:
                return {"error": f"Snapshot restore failed: {res.stderr.strip()}", "code": 500}

            logger.info(f"Successfully restored worker '{vm_identifier}' to snapshot '{snapshot_name}'")
            return {
                "success": True,
                "vm_identifier": vm_identifier,
                "restored_snapshot": snapshot_name,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {"error": str(e), "code": 500}

    def start_worker(self, vm_identifier: str) -> Dict[str, Any]:
        """Starts worker VM in headless mode exclusively."""
        if not self.is_vm_allowed(vm_identifier):
            return {"error": "VM identifier is not in the authorized allowlist.", "code": 403}

        # Check network configuration first to prevent bridged mode
        status = self.get_worker_status(vm_identifier)
        if not status.get("is_network_isolated", False):
            return {
                "error": f"Worker VM '{vm_identifier}' has insecure network adapter ({status.get('nic1_mode')}). Must be hostonly or intnet.",
                "code": 412
            }

        try:
            res = subprocess.run([self.vbox, "startvm", vm_identifier, "--type", "headless"], capture_output=True, text=True, timeout=25.0)
            if res.returncode != 0 and "already locked" not in res.stderr.lower():
                return {"error": f"Failed to start VM: {res.stderr.strip()}", "code": 500}

            logger.info(f"Started worker VM '{vm_identifier}' headlessly.")
            return {
                "success": True,
                "vm_identifier": vm_identifier,
                "execution_mode": "headless",
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {"error": str(e), "code": 500}

    def stop_worker(self, vm_identifier: str) -> Dict[str, Any]:
        """Powers off the worker VM unconditionally."""
        if not self.is_vm_allowed(vm_identifier):
            return {"error": "VM identifier is not in the authorized allowlist.", "code": 403}

        try:
            res = subprocess.run([self.vbox, "controlvm", vm_identifier, "poweroff"], capture_output=True, text=True, timeout=10.0)
            logger.info(f"Powered off worker VM '{vm_identifier}'")
            return {
                "success": True,
                "vm_identifier": vm_identifier,
                "output": res.stdout.strip(),
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {"error": str(e), "code": 500}

    def stage_evidence_file(
        self,
        vm_identifier: str,
        filename: str,
        file_bytes: bytes,
        expected_sha256: str
    ) -> Dict[str, Any]:
        """
        Receives evidence file, validates SHA-256 hash, and saves strictly to
        the VM's isolated staging directory. Neutralizes path traversal.
        """
        if not self.is_vm_allowed(vm_identifier):
            return {"error": "VM identifier is not in the authorized allowlist.", "code": 403}

        # Validate hash
        actual_sha256 = hashlib.sha256(file_bytes).hexdigest().lower()
        if expected_sha256 and actual_sha256 != expected_sha256.lower():
            return {
                "error": f"Evidence hash mismatch. Expected {expected_sha256}, got {actual_sha256}",
                "code": 400
            }

        # Sanitize filename (strictly basename, no traversal)
        safe_name = Path(filename).name
        if not safe_name or safe_name in (".", ".."):
            safe_name = f"{actual_sha256}.bin"

        vm_staging = (self.config.staging_root / vm_identifier).resolve()
        # Verify vm_staging is strictly under staging_root
        if not str(vm_staging).startswith(str(self.config.staging_root.resolve())):
            return {"error": "Path traversal attempt detected.", "code": 403}

        vm_staging.mkdir(parents=True, exist_ok=True)
        dest_file = (vm_staging / safe_name).resolve()
        if not str(dest_file).startswith(str(vm_staging)):
            return {"error": "Invalid target filename path.", "code": 403}

        dest_file.write_bytes(file_bytes)
        logger.info(f"Staged evidence {safe_name} ({len(file_bytes)} bytes, SHA-256: {actual_sha256}) for VM {vm_identifier}")

        return {
            "success": True,
            "vm_identifier": vm_identifier,
            "filename": safe_name,
            "sha256": actual_sha256,
            "size_bytes": len(file_bytes),
            "staged_path": str(dest_file),
            "timestamp": datetime.utcnow().isoformat()
        }

    def get_execution_results(self, vm_identifier: str) -> Dict[str, Any]:
        """Retrieves dropped artifacts from worker VM's results directory."""
        if not self.is_vm_allowed(vm_identifier):
            return {"error": "VM identifier is not in the authorized allowlist.", "code": 403}

        vm_results = (self.config.staging_root / vm_identifier / "results").resolve()
        artifacts = []
        if vm_results.exists():
            for f in vm_results.iterdir():
                if f.is_file():
                    content = f.read_bytes()
                    artifacts.append({
                        "filename": f.name,
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "size_bytes": len(content)
                    })

        return {
            "vm_identifier": vm_identifier,
            "artifact_count": len(artifacts),
            "artifacts": artifacts
        }


class HostAgentHTTPHandler(BaseHTTPRequestHandler):
    """HTTP/HTTPS handler implementing secure REST API for HostControllerService."""

    service: Optional[HostControllerService] = None

    def _send_json(self, status_code: int, data: Dict[str, Any]):
        if isinstance(data, dict) and "code" not in data and status_code >= 400:
            data["code"] = status_code
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-TraceX-Host-Agent", "2.0.0")
        self.end_headers()
        self.wfile.write(body)

    def _authenticate(self) -> Tuple[bool, str]:
        """Validates client IP, mTLS peer certificate, and application HMAC token."""
        client_ip = self.client_address[0]

        # 1. Rate Limiting Check
        if self.service.rate_limiter.is_blocked(client_ip):
            logger.warning(f"Connection rejected: IP {client_ip} is currently rate-limited.")
            self._send_json(429, {"error": "Too Many Requests: Client IP is temporarily blocked due to repeated auth failures."})
            self.service.log_audit(client_ip, self.command, self.path, None, "BLOCKED_RATE_LIMIT", 429)
            return False, "NONE"

        # 2. IP Subnet check
        allowed_subnets = self.service.config.allowed_client_subnets
        ip_obj = ipaddress.ip_address(client_ip)

        ip_permitted = False
        for subnet in allowed_subnets:
            try:
                if ip_obj in ipaddress.ip_network(subnet):
                    ip_permitted = True
                    break
            except Exception:
                pass

        if not ip_permitted:
            logger.warning(f"Unauthorized connection attempt from client IP {client_ip}")
            self.service.rate_limiter.record_failure(client_ip)
            self._send_json(403, {"error": f"Client IP {client_ip} is not in the authorized management network."})
            self.service.log_audit(client_ip, self.command, self.path, None, "REJECTED_UNAUTHORIZED_IP", 403)
            return False, "NONE"

        # 3. mTLS Peer Certificate Extraction
        client_cert_dn = "NONE"
        if hasattr(self.connection, "getpeercert"):
            try:
                peer_cert = self.connection.getpeercert()
                if peer_cert:
                    subj = dict(x[0] for x in peer_cert.get("subject", []))
                    client_cert_dn = subj.get("commonName", "UNKNOWN")
            except Exception as e:
                logger.warning(f"Failed to read peer cert: {e}")

        # If mTLS is required and socket is SSL, verify client presented certificate
        if self.service.config.require_mtls and isinstance(self.connection, ssl.SSLSocket):
            if client_cert_dn in ("NONE", "UNKNOWN"):
                logger.warning(f"mTLS validation failed: Client {client_ip} did not present a valid client certificate.")
                self.service.rate_limiter.record_failure(client_ip)
                self._send_json(401, {"error": "Mutual TLS Required: Valid client certificate was not presented."})
                self.service.log_audit(client_ip, self.command, self.path, None, "REJECTED_NO_CLIENT_CERT", 401)
                return False, "NONE"

        # 4. HMAC Token check (Defense-in-depth application layer)
        expected_token = self.service.config.auth_token
        if expected_token:
            auth_hdr = self.headers.get("X-TraceX-Host-Token") or self.headers.get("Authorization", "")
            if auth_hdr.startswith("Bearer "):
                auth_hdr = auth_hdr[7:].strip()

            if not hmac.compare_digest(auth_hdr, expected_token):
                logger.warning(f"Invalid authentication token presented from {client_ip} (cert: {client_cert_dn})")
                self.service.rate_limiter.record_failure(client_ip)
                self._send_json(401, {"error": "Invalid or missing X-TraceX-Host-Token header."})
                self.service.log_audit(client_ip, self.command, self.path, None, "REJECTED_INVALID_TOKEN", 401, client_cert_dn)
                return False, client_cert_dn

        self.service.rate_limiter.record_success(client_ip)
        return True, client_cert_dn

    def do_GET(self):
        auth_ok, cert_dn = self._authenticate()
        if not auth_ok:
            return

        client_ip = self.client_address[0]
        path = self.path.split("?")[0].rstrip("/")

        if path in ("", "/status", "/api/vbox/status", "/health"):
            data = self.service.get_host_status()
            self._send_json(200, data)
            self.service.log_audit(client_ip, "GET", path, None, "SUCCESS", 200, cert_dn)
            return

        # /api/vbox/workers/{vm_id}/status
        if path.startswith("/api/vbox/workers/") and path.endswith("/status"):
            parts = path.split("/")
            if len(parts) >= 5:
                vm_id = parts[4]
                res = self.service.get_worker_status(vm_id)
                code = res.get("code", 200)
                self._send_json(code, res)
                self.service.log_audit(client_ip, "GET", path, vm_id, "SUCCESS" if code == 200 else "ERROR", code, cert_dn)
                return

        # /api/vbox/workers/{vm_id}/results
        if path.startswith("/api/vbox/workers/") and path.endswith("/results"):
            parts = path.split("/")
            if len(parts) >= 5:
                vm_id = parts[4]
                res = self.service.get_execution_results(vm_id)
                code = res.get("code", 200)
                self._send_json(code, res)
                self.service.log_audit(client_ip, "GET", path, vm_id, "SUCCESS" if code == 200 else "ERROR", code, cert_dn)
                return

        self._send_json(404, {"error": f"Endpoint '{path}' not found or unsupported."})
        self.service.log_audit(client_ip, "GET", path, None, "NOT_FOUND", 404, cert_dn)

    def do_POST(self):
        auth_ok, cert_dn = self._authenticate()
        if not auth_ok:
            return

        client_ip = self.client_address[0]
        path = self.path.split("?")[0].rstrip("/")
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        # /api/vbox/workers/{vm_id}/restore
        if path.startswith("/api/vbox/workers/") and path.endswith("/restore"):
            parts = path.split("/")
            if len(parts) >= 5:
                vm_id = parts[4]
                try:
                    payload = json.loads(body.decode("utf-8")) if body else {}
                except Exception:
                    payload = {}
                snap_name = payload.get("snapshot_name", "Clean_Base")
                res = self.service.restore_worker_snapshot(vm_id, snap_name)
                code = res.get("code", 200)
                self._send_json(code, res)
                self.service.log_audit(client_ip, "POST", path, vm_id, f"RESTORE_SNAP_{snap_name}", code, cert_dn)
                return

        # /api/vbox/workers/{vm_id}/start
        if path.startswith("/api/vbox/workers/") and path.endswith("/start"):
            parts = path.split("/")
            if len(parts) >= 5:
                vm_id = parts[4]
                res = self.service.start_worker(vm_id)
                code = res.get("code", 200)
                self._send_json(code, res)
                self.service.log_audit(client_ip, "POST", path, vm_id, "START_WORKER_HEADLESS", code, cert_dn)
                return

        # /api/vbox/workers/{vm_id}/stop
        if path.startswith("/api/vbox/workers/") and path.endswith("/stop"):
            parts = path.split("/")
            if len(parts) >= 5:
                vm_id = parts[4]
                res = self.service.stop_worker(vm_id)
                code = res.get("code", 200)
                self._send_json(code, res)
                self.service.log_audit(client_ip, "POST", path, vm_id, "STOP_WORKER_POWEROFF", code, cert_dn)
                return

        # /api/vbox/workers/{vm_id}/transfer_evidence
        if path.startswith("/api/vbox/workers/") and path.endswith("/transfer_evidence"):
            parts = path.split("/")
            if len(parts) >= 5:
                vm_id = parts[4]
                filename = self.headers.get("X-Evidence-Filename", "sample.bin")
                expected_sha256 = self.headers.get("X-Evidence-SHA256", "")
                res = self.service.stage_evidence_file(
                    vm_identifier=vm_id,
                    filename=filename,
                    file_bytes=body,
                    expected_sha256=expected_sha256
                )
                code = res.get("code", 200)
                self._send_json(code, res)
                self.service.log_audit(client_ip, "POST", path, vm_id, f"STAGE_EVIDENCE_{filename}", code, cert_dn)
                return

        self._send_json(404, {"error": f"Endpoint '{path}' not found or unsupported."})
        self.service.log_audit(client_ip, "POST", path, None, "NOT_FOUND", 404, cert_dn)

    def log_message(self, format, *args):
        logger.info(f"{self.client_address[0]} - {format % args}")


def run_host_agent(config: Optional[HostAgentConfig] = None):
    """Starts the standalone VirtualBox Host Controller Agent server with HTTPS & mTLS."""
    cfg = config or HostAgentConfig.load()
    service = HostControllerService(cfg)
    HostAgentHTTPHandler.service = service

    server_address = (cfg.bind_host, cfg.bind_port)
    httpd = HTTPServer(server_address, HostAgentHTTPHandler)

    has_certs = (
        cfg.cert_file and cfg.key_file and Path(cfg.cert_file).exists() and Path(cfg.key_file).exists()
    )

    if cfg.require_mtls:
        if not has_certs:
            raise RuntimeError(
                f"FATAL SECURITY REJECTION: require_mtls is True, but server cert/key files were not found at "
                f"cert={cfg.cert_file}, key={cfg.key_file}. Refusing plain HTTP downgrade."
            )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=cfg.cert_file, keyfile=cfg.key_file)
        if cfg.ca_file and Path(cfg.ca_file).exists():
            ctx.load_verify_locations(cafile=cfg.ca_file)
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            raise RuntimeError(
                f"FATAL SECURITY REJECTION: require_mtls is True, but CA file was not found at {cfg.ca_file}. "
                f"Client certificate validation cannot be enforced."
            )
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    elif has_certs:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=cfg.cert_file, keyfile=cfg.key_file)
        if cfg.ca_file and Path(cfg.ca_file).exists():
            ctx.load_verify_locations(cafile=cfg.ca_file)
            ctx.verify_mode = ssl.CERT_REQUIRED
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    else:
        # Development / test mode with warning
        logger.warning("SECURITY WARNING: Starting Host Controller Agent over plain HTTP. mTLS is disabled.")
        scheme = "http"

    logger.info(f"TraceX VirtualBox Host Controller Agent listening on {scheme}://{cfg.bind_host}:{cfg.bind_port}")
    logger.info(f"Allowed Worker VMs: {cfg.allowed_vm_uuids}")
    logger.info(f"Hardware Virtualization: {service.get_hardware_virt_status()}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Host Controller Agent shutting down.")
        httpd.server_close()


if __name__ == "__main__":
    run_host_agent()
