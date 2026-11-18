"""
TraceX KVM / Libvirt Hypervisor Provider
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Manages isolated analysis worker VMs hosted on KVM/QEMU hypervisors using virsh CLI
or the libvirt management interface.
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


class KVMProvider(ISandboxProvider):
    """
    Controls disposable KVM/QEMU worker VMs for isolated forensic detonation.
    """

    def __init__(self):
        self._virsh_path: Optional[str] = shutil.which("virsh")
        self._default_domain = getattr(settings, "KVM_WORKER_DOMAIN", "TraceX-Worker-Win10")
        self._default_snapshot = getattr(settings, "KVM_WORKER_SNAPSHOT", "Clean_Base")

    @property
    def provider_id(self) -> str:
        return "kvm"

    @property
    def name(self) -> str:
        return "KVM / QEMU Disposable Worker"

    @property
    def os_family(self) -> str:
        return "windows"

    @property
    def deployment_mode(self) -> str:
        return "MODE_A_EXTERNAL"

    def preflight(self) -> Dict[str, Any]:
        virsh = self._virsh_path or shutil.which("virsh")
        if not virsh:
            return {
                "ready": False,
                "status": "NOT_CONFIGURED",
                "details": {
                    "message": "Libvirt / virsh command line tool is not detected in PATH.",
                    "hint": "Install libvirt-clients and ensure virsh is accessible."
                }
            }

        # Check domain existence
        try:
            res = subprocess.run([virsh, "dominfo", self._default_domain], capture_output=True, text=True, timeout=4.0)
            if res.returncode != 0:
                return {
                    "ready": False,
                    "status": "NOT_CONFIGURED",
                    "details": {
                        "message": f"KVM domain '{self._default_domain}' was not found.",
                        "hint": f"Create a KVM domain named '{self._default_domain}' with snapshot '{self._default_snapshot}'."
                    }
                }
        except Exception as e:
            return {"ready": False, "status": "ERROR", "details": {"message": str(e)}}

        return {
            "ready": True,
            "status": "INSTALLED_AND_READY",
            "details": {
                "message": f"KVM worker domain '{self._default_domain}' is ready.",
                "domain": self._default_domain,
                "snapshot": self._default_snapshot
            }
        }

    def provision(self, run: DynamicSandboxRun, staged_file: Path) -> Dict[str, Any]:
        virsh = self._virsh_path or "virsh"
        dom = self._default_domain
        snap = self._default_snapshot

        run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Reverting KVM domain '{dom}' to snapshot '{snap}'...")
        res = subprocess.run([virsh, "snapshot-revert", dom, snap], capture_output=True, text=True, timeout=30.0)
        if res.returncode != 0:
            raise RuntimeError(f"KVM snapshot-revert failed: {res.stderr.strip()}")

        run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Starting KVM domain '{dom}'...")
        subprocess.run([virsh, "start", dom], capture_output=True, text=True, timeout=20.0)

        token = worker_auth_manager.generate_worker_token(
            run_id=run.id,
            target_binary=run.target_binary,
            expected_sha256=getattr(run, "target_sha256", ""),
            expires_in_seconds=getattr(run, "timeout_seconds", 120) + 120,
            worker_type="windows"
        )
        return {"status": "PROVISIONED", "domain": dom, "worker_token": token}

    def execute(self, run: DynamicSandboxRun, timeout_seconds: int) -> Dict[str, Any]:
        return {"status": "EXECUTING", "timeout_seconds": timeout_seconds}

    def collect_telemetry(self, run: DynamicSandboxRun) -> Dict[str, Any]:
        session = worker_auth_manager.get_session(run.id) or {}
        return {"telemetry_received": session.get("telemetry_received", False)}

    def terminate(self, run: DynamicSandboxRun) -> None:
        virsh = self._virsh_path or "virsh"
        try:
            subprocess.run([virsh, "destroy", self._default_domain], capture_output=True, text=True, timeout=10.0)
            run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] KVM domain '{self._default_domain}' halted.")
        except Exception:
            pass

    def restore_and_cleanup(self, run: DynamicSandboxRun) -> None:
        self.terminate(run)
        virsh = self._virsh_path or "virsh"
        try:
            subprocess.run([virsh, "snapshot-revert", self._default_domain, self._default_snapshot], capture_output=True, text=True, timeout=30.0)
            run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] KVM worker reverted to '{self._default_snapshot}'.")
        except Exception:
            pass
        worker_auth_manager.revoke_worker_session(run.id)


kvm_provider = KVMProvider()

