"""
TraceX Proxmox VE Hypervisor Provider
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Manages isolated analysis worker VMs hosted on Proxmox Virtual Environment (PVE)
clusters using the authenticated Proxmox REST API v2.
"""

import os
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from backend.app.config import settings
from backend.app.core.models import DynamicSandboxRun
from backend.app.analyzers.dynamic.sandbox_registry import ISandboxProvider
from backend.app.analyzers.dynamic.worker_auth import worker_auth_manager

logger = logging.getLogger(__name__)


class ProxmoxProvider(ISandboxProvider):
    """
    Controls disposable Proxmox VE worker VMs via Proxmox REST API.
    """

    def __init__(self):
        self._host = getattr(settings, "PROXMOX_HOST", "") or os.getenv("PROXMOX_HOST", "")
        self._node = getattr(settings, "PROXMOX_NODE", "pve") or os.getenv("PROXMOX_NODE", "pve")
        self._vmid = getattr(settings, "PROXMOX_VMID", "100") or os.getenv("PROXMOX_VMID", "100")
        self._snapshot = getattr(settings, "PROXMOX_SNAPSHOT", "Clean_Base")
        self._api_token = getattr(settings, "PROXMOX_API_TOKEN", "") or os.getenv("PROXMOX_API_TOKEN", "")

    @property
    def provider_id(self) -> str:
        return "proxmox"

    @property
    def name(self) -> str:
        return "Proxmox VE Cluster Worker"

    @property
    def os_family(self) -> str:
        return "windows"

    @property
    def deployment_mode(self) -> str:
        return "MODE_A_EXTERNAL"

    def preflight(self) -> Dict[str, Any]:
        """Validates Proxmox API configuration and cluster reachability."""
        if not self._host or not self._api_token:
            return {
                "ready": False,
                "status": "NOT_CONFIGURED",
                "details": {
                    "message": "Proxmox VE API endpoint or API token is not configured.",
                    "hint": "Configure PROXMOX_HOST, PROXMOX_NODE, PROXMOX_VMID, and PROXMOX_API_TOKEN in Settings."
                }
            }

        import httpx
        url = f"https://{self._host}:8006/api2/json/nodes/{self._node}/qemu/{self._vmid}/status/current"
        headers = {"Authorization": f"PVEAPIToken={self._api_token}"}
        try:
            with httpx.Client(verify=False, timeout=5.0) as client:
                res = client.get(url, headers=headers)
                if res.status_code == 200:
                    data = res.json().get("data", {})
                    return {
                        "ready": True,
                        "status": "INSTALLED_AND_READY",
                        "details": {
                            "message": f"Connected to Proxmox VE. Worker VM {self._vmid} status: {data.get('status')}.",
                            "vmid": self._vmid,
                            "node": self._node,
                            "snapshot": self._snapshot
                        }
                    }
                return {
                    "ready": False,
                    "status": "NOT_CONFIGURED",
                    "details": {"message": f"Proxmox API returned HTTP {res.status_code}: {res.text[:200]}"}
                }
        except Exception as e:
            return {"ready": False, "status": "ERROR", "details": {"message": f"Connection error: {e}"}}

    def provision(self, run: DynamicSandboxRun, staged_file: Path) -> Dict[str, Any]:
        """Rolls back Proxmox VM to clean snapshot and powers on."""
        pre = self.preflight()
        if not pre.get("ready"):
            raise RuntimeError(f"Proxmox preflight failed: {pre.get('details', {}).get('message')}")

        import httpx
        headers = {"Authorization": f"PVEAPIToken={self._api_token}"}
        rollback_url = f"https://{self._host}:8006/api2/json/nodes/{self._node}/qemu/{self._vmid}/snapshot/{self._snapshot}/rollback"
        start_url = f"https://{self._host}:8006/api2/json/nodes/{self._node}/qemu/{self._vmid}/status/start"

        with httpx.Client(verify=False, timeout=30.0) as client:
            run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Rolling back Proxmox VM {self._vmid} to '{self._snapshot}'...")
            client.post(rollback_url, headers=headers)
            run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Starting Proxmox VM {self._vmid}...")
            client.post(start_url, headers=headers)

        token = worker_auth_manager.generate_worker_token(
            run_id=run.id,
            target_binary=run.target_binary,
            expected_sha256=getattr(run, "target_sha256", ""),
            expires_in_seconds=getattr(run, "timeout_seconds", 120) + 120,
            worker_type="windows"
        )
        return {"status": "PROVISIONED", "vmid": self._vmid, "worker_token": token}

    def execute(self, run: DynamicSandboxRun, timeout_seconds: int) -> Dict[str, Any]:
        return {"status": "EXECUTING", "timeout_seconds": timeout_seconds}

    def collect_telemetry(self, run: DynamicSandboxRun) -> Dict[str, Any]:
        session = worker_auth_manager.get_session(run.id) or {}
        return {"telemetry_received": session.get("telemetry_received", False)}

    def terminate(self, run: DynamicSandboxRun) -> None:
        import httpx
        if self._host and self._api_token:
            stop_url = f"https://{self._host}:8006/api2/json/nodes/{self._node}/qemu/{self._vmid}/status/stop"
            headers = {"Authorization": f"PVEAPIToken={self._api_token}"}
            try:
                with httpx.Client(verify=False, timeout=10.0) as client:
                    client.post(stop_url, headers=headers)
            except Exception:
                pass

    def restore_and_cleanup(self, run: DynamicSandboxRun) -> None:
        self.terminate(run)
        import httpx
        if self._host and self._api_token:
            rollback_url = f"https://{self._host}:8006/api2/json/nodes/{self._node}/qemu/{self._vmid}/snapshot/{self._snapshot}/rollback"
            headers = {"Authorization": f"PVEAPIToken={self._api_token}"}
            try:
                with httpx.Client(verify=False, timeout=30.0) as client:
                    client.post(rollback_url, headers=headers)
            except Exception:
                pass
        worker_auth_manager.revoke_worker_session(run.id)


proxmox_provider = ProxmoxProvider()

