"""
TraceX VMware Hypervisor Provider
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Manages isolated analysis worker VMs hosted on VMware Workstation / Player / ESXi
via vmrun CLI or vSphere management interface.

Supports:
- Mode A: External VMware Management (TraceX Manager controls sibling worker VM)
- Mode B: Nested Virtualization (Worker VM running inside VMware host)
"""

import os
import shutil
import subprocess
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from backend.app.config import settings
from backend.app.core.models import DynamicSandboxRun
from backend.app.analyzers.dynamic.sandbox_registry import ISandboxProvider
from backend.app.analyzers.dynamic.worker_auth import worker_auth_manager

logger = logging.getLogger(__name__)


class VMwareProvider(ISandboxProvider):
    """
    Controls disposable VMware worker VMs for Windows PE and Android dynamic analysis.
    """

    def __init__(self):
        self._vmrun_path: Optional[str] = self._find_vmrun()
        self._default_vmx = getattr(settings, "VMWARE_WORKER_VMX", "C:\\VMs\\TraceX-Worker-Win10\\TraceX-Worker-Win10.vmx")
        self._default_snapshot = getattr(settings, "VMWARE_WORKER_SNAPSHOT", "Clean_Base")

    @property
    def provider_id(self) -> str:
        return "vmware"

    @property
    def name(self) -> str:
        return "VMware Workstation / ESXi Worker"

    @property
    def os_family(self) -> str:
        return "windows"

    @property
    def deployment_mode(self) -> str:
        return "MODE_A_EXTERNAL"

    def _find_vmrun(self) -> Optional[str]:
        candidates = [
            shutil.which("vmrun"),
            "C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrun.exe",
            "C:\\Program Files (x86)\\VMware\\VMware VIX\\vmrun.exe",
            "C:\\Program Files\\VMware\\VMware Workstation\\vmrun.exe",
            "/usr/bin/vmrun"
        ]
        for c in candidates:
            if c and Path(c).exists():
                return str(c)
        return None

    def preflight(self) -> Dict[str, Any]:
        """Inspects VMware vmrun availability and target VMX image."""
        vmrun = self._find_vmrun()
        if not vmrun:
            return {
                "ready": False,
                "status": "NOT_CONFIGURED",
                "details": {
                    "message": "VMware management tool (vmrun.exe) is not installed or not in PATH.",
                    "hint": "Install VMware Workstation Pro / Player or VMware VIX SDK."
                }
            }

        # Check target VMX file
        vmx_path = Path(self._default_vmx)
        if not vmx_path.exists():
            return {
                "ready": False,
                "status": "NOT_CONFIGURED",
                "details": {
                    "message": f"VMware CLI found, but target worker VM image was not found at '{self._default_vmx}'.",
                    "hint": f"Create a worker VM and configure VMWARE_WORKER_VMX in Settings."
                }
            }

        # Check for clean baseline snapshot
        has_snapshot = False
        try:
            res = subprocess.run([vmrun, "listSnapshots", str(vmx_path)], capture_output=True, text=True, timeout=5.0)
            if res.returncode == 0 and self._default_snapshot in res.stdout:
                has_snapshot = True
        except Exception:
            pass

        if not has_snapshot:
            return {
                "ready": False,
                "status": "PARTIALLY_CONFIGURED",
                "details": {
                    "message": f"VMware VM found, but baseline snapshot '{self._default_snapshot}' is missing.",
                    "hint": f"Take a clean snapshot named '{self._default_snapshot}' on VM '{vmx_path.name}'."
                }
            }

        return {
            "ready": True,
            "status": "INSTALLED_AND_READY",
            "details": {
                "message": f"VMware worker VM '{vmx_path.name}' ready with snapshot '{self._default_snapshot}'.",
                "vmx_path": str(vmx_path),
                "snapshot_name": self._default_snapshot
            }
        }

    def provision(self, run: DynamicSandboxRun, staged_file: Path) -> Dict[str, Any]:
        """Reverts VMware worker to clean snapshot and powers on."""
        pre = self.preflight()
        if not pre.get("ready"):
            raise RuntimeError(f"VMware preflight failed: {pre.get('details', {}).get('message')}")

        vmrun = self._vmrun_path
        vmx = self._default_vmx
        snap = self._default_snapshot

        run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Reverting VMware VM to clean snapshot '{snap}'...")
        res = subprocess.run([vmrun, "revertToSnapshot", vmx, snap], capture_output=True, text=True, timeout=30.0)
        if res.returncode != 0:
            raise RuntimeError(f"VMware revert failed: {res.stderr.strip()}")

        run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Powering on VMware worker (nogui)...")
        res = subprocess.run([vmrun, "start", vmx, "nogui"], capture_output=True, text=True, timeout=30.0)
        if res.returncode != 0 and "already running" not in res.stderr.lower():
            raise RuntimeError(f"VMware start failed: {res.stderr.strip()}")

        token = worker_auth_manager.generate_worker_token(
            run_id=run.id,
            target_binary=run.target_binary,
            expected_sha256=getattr(run, "target_sha256", ""),
            expires_in_seconds=getattr(run, "timeout_seconds", 120) + 120,
            worker_type="windows"
        )

        return {
            "status": "PROVISIONED",
            "vmx_path": vmx,
            "worker_token": token
        }

    def execute(self, run: DynamicSandboxRun, timeout_seconds: int) -> Dict[str, Any]:
        run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Dispatching execution signal to VMware worker...")
        return {"status": "EXECUTING", "timeout_seconds": timeout_seconds}

    def collect_telemetry(self, run: DynamicSandboxRun) -> Dict[str, Any]:
        session = worker_auth_manager.get_session(run.id) or {}
        return {
            "worker_ip": session.get("worker_ip"),
            "heartbeat_count": session.get("heartbeat_count", 0),
            "telemetry_received": session.get("telemetry_received", False)
        }

    def terminate(self, run: DynamicSandboxRun) -> None:
        vmrun = self._vmrun_path
        if vmrun:
            try:
                subprocess.run([vmrun, "stop", self._default_vmx, "hard"], capture_output=True, text=True, timeout=10.0)
                run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] VMware worker powered off.")
            except Exception as e:
                logger.warning(f"Error stopping VMware VM: {e}")

    def restore_and_cleanup(self, run: DynamicSandboxRun) -> None:
        self.terminate(run)
        vmrun = self._vmrun_path
        if vmrun:
            try:
                subprocess.run([vmrun, "revertToSnapshot", self._default_vmx, self._default_snapshot], capture_output=True, text=True, timeout=30.0)
                run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] VMware worker reverted to '{self._default_snapshot}'.")
            except Exception as e:
                logger.warning(f"Error reverting VMware VM: {e}")
        worker_auth_manager.revoke_worker_session(run.id)


vmware_provider = VMwareProvider()

