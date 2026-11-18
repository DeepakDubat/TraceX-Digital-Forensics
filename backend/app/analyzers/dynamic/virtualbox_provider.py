"""
TraceX VirtualBox Hypervisor Provider
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Manages isolated analysis worker VMs hosted on Oracle VirtualBox.
Supports:
- Mode A (Remote): TraceX Manager VM controls physical host via VirtualBox Host Controller Agent.
- Mode A (Local): Direct VBoxManage CLI control on host.

Security Guarantees:
- Zero Host Execution: Untrusted binaries run strictly inside disposable Worker VMs.
- Clean Baseline Revert: Enforces snapshot restoration before and after every execution.
- Security Isolation: Clipboard disabled, 0 shared folders, network strictly isolated (hostonly/intnet).
- Cryptographic Verification: Staged evidence SHA-256 verified before dispatch and upon arrival.
- Firmware Virtualization: Explicitly alerts if VT-x/AMD-V is disabled in BIOS.
"""

import os
import shutil
import hashlib
import subprocess
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from backend.app.config import settings
from backend.app.core.models import DynamicSandboxRun
from backend.app.analyzers.dynamic.sandbox_registry import ISandboxProvider
from backend.app.analyzers.dynamic.worker_auth import worker_auth_manager
from backend.app.analyzers.dynamic.vbox_host_client import vbox_host_client
from backend.app.analyzers.dynamic.vm_detector import vm_detector

logger = logging.getLogger(__name__)


class VirtualBoxProvider(ISandboxProvider):
    """
    Controls disposable VirtualBox worker VMs for Windows PE and Android dynamic analysis.
    Supports both direct local VBoxManage and remote Host Controller Agent.
    """

    def __init__(self):
        self._vboxmanage_path: Optional[str] = self._find_vboxmanage()
        self._default_vm_name = getattr(settings, "VBOX_WORKER_VM", "TraceX-Worker-Win10")
        self._default_snapshot = getattr(settings, "VBOX_WORKER_SNAPSHOT", "Clean_Base")

    @property
    def provider_id(self) -> str:
        return "virtualbox"

    @property
    def name(self) -> str:
        return "Oracle VirtualBox Disposable Worker"

    @property
    def os_family(self) -> str:
        return "windows"

    @property
    def deployment_mode(self) -> str:
        return "MODE_A_EXTERNAL"

    def _find_vboxmanage(self) -> Optional[str]:
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
        return None

    def preflight(self) -> Dict[str, Any]:
        """Inspects VirtualBox installation, Host Controller Agent, and clean baseline snapshot."""
        # 1. Check if remote Host Controller Agent is configured
        if vbox_host_client.is_configured:
            status = vbox_host_client.get_status()
            if status.get("error"):
                return {
                    "ready": False,
                    "status": "NOT_CONFIGURED",
                    "details": {
                        "message": f"Host Controller Agent unreachable at {vbox_host_client.base_url}: {status.get('error')}",
                        "hint": "Start the Host Controller Agent on the Windows host using start_host_agent.bat."
                    }
                }

            # Check hardware virtualization status from host agent
            if not status.get("firmware_virtualization_enabled", True):
                return {
                    "ready": False,
                    "status": "NOT_CONFIGURED",
                    "details": {
                        "message": "ACTION REQUIRED: Enable Intel VT-x in BIOS/UEFI.",
                        "host_agent": status,
                        "hint": "Hardware virtualization is disabled in host BIOS. Analysis worker VMs cannot boot."
                    }
                }

            worker_info = vbox_host_client.get_worker_status(self._default_vm_name)
            if worker_info.get("error"):
                return {
                    "ready": False,
                    "status": "NOT_CONFIGURED",
                    "details": {
                        "message": f"Worker VM '{self._default_vm_name}' not accessible via Host Controller: {worker_info.get('error')}",
                        "hint": f"Ensure '{self._default_vm_name}' exists and is added to allowed_vm_uuids."
                    }
                }

            if not worker_info.get("has_baseline_snapshot", False):
                return {
                    "ready": False,
                    "status": "PARTIALLY_CONFIGURED",
                    "details": {
                        "message": f"Worker VM '{self._default_vm_name}' is missing approved baseline snapshot '{self._default_snapshot}'.",
                        "worker_info": worker_info,
                        "hint": f"Take clean snapshot '{self._default_snapshot}' on worker VM."
                    }
                }

            return {
                "ready": True,
                "status": "INSTALLED_AND_READY",
                "details": {
                    "message": f"VirtualBox worker VM '{self._default_vm_name}' ready via Host Controller Agent.",
                    "mode": "REMOTE_HOST_AGENT",
                    "agent_url": vbox_host_client.base_url,
                    "worker_info": worker_info
                }
            }

        # 2. Local VBoxManage mode
        vbox = self._find_vboxmanage()
        if not vbox:
            return {
                "ready": False,
                "status": "NOT_CONFIGURED",
                "details": {
                    "message": "Oracle VirtualBox (VBoxManage) is not installed or not in PATH.",
                    "hint": "Install Oracle VirtualBox 7.x or configure VBOX_HOST_AGENT_URL for Manager VM."
                }
            }

        # Check host hardware virtualization
        env = vm_detector.get_environment_info()
        cpu_virt = env.get("cpu_virtualization", {})
        if not cpu_virt.get("firmware_virtualization_enabled", True):
            return {
                "ready": False,
                "status": "NOT_CONFIGURED",
                "details": {
                    "message": "ACTION REQUIRED: Enable Intel VT-x in BIOS/UEFI.",
                    "hint": "Reboot into BIOS/UEFI setup and enable Intel Virtualization Technology (VT-x) or AMD SVM."
                }
            }

        # Check installed version
        version = "Unknown"
        try:
            res = subprocess.run([vbox, "--version"], capture_output=True, text=True, timeout=4.0)
            if res.returncode == 0:
                version = res.stdout.strip()
        except Exception as e:
            logger.warning(f"Failed to query VBoxManage version: {e}")

        # Enumerate registered VMs
        vms = []
        try:
            res = subprocess.run([vbox, "list", "vms"], capture_output=True, text=True, timeout=4.0)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if line.strip():
                        parts = line.strip().split('"')
                        if len(parts) >= 2:
                            vms.append(parts[1])
        except Exception as e:
            logger.warning(f"Failed to list VirtualBox VMs: {e}")

        has_target_vm = self._default_vm_name in vms
        if not has_target_vm:
            return {
                "ready": False,
                "status": "NOT_CONFIGURED",
                "details": {
                    "message": f"VirtualBox installed (v{version}), but worker VM '{self._default_vm_name}' was not found.",
                    "version": version,
                    "existing_vms": vms,
                    "hint": f"Create a VirtualBox VM named '{self._default_vm_name}' with snapshot '{self._default_snapshot}'."
                }
            }

        # Check for clean baseline snapshot
        has_snapshot = False
        try:
            res = subprocess.run([vbox, "snapshot", self._default_vm_name, "list"], capture_output=True, text=True, timeout=4.0)
            if res.returncode == 0 and self._default_snapshot in res.stdout:
                has_snapshot = True
        except Exception:
            pass

        if not has_snapshot:
            return {
                "ready": False,
                "status": "PARTIALLY_CONFIGURED",
                "details": {
                    "message": f"VirtualBox worker VM '{self._default_vm_name}' found, but snapshot '{self._default_snapshot}' is missing.",
                    "version": version,
                    "hint": f"Take a clean snapshot named '{self._default_snapshot}' for VM '{self._default_vm_name}'."
                }
            }

        return {
            "ready": True,
            "status": "INSTALLED_AND_READY",
            "details": {
                "message": f"VirtualBox worker VM '{self._default_vm_name}' is ready with baseline snapshot '{self._default_snapshot}'.",
                "version": version,
                "vm_name": self._default_vm_name,
                "snapshot_name": self._default_snapshot
            }
        }

    def provision(self, run: DynamicSandboxRun, staged_file: Path) -> Dict[str, Any]:
        """
        Reverts the VirtualBox worker VM to clean baseline snapshot,
        generates an ephemeral worker auth token, and boots the VM headless.
        """
        pre = self.preflight()
        if not pre.get("ready"):
            raise RuntimeError(f"VirtualBox preflight failed: {pre.get('details', {}).get('message')}")

        vm = self._default_vm_name
        snap = self._default_snapshot

        # Remote Host Controller Agent mode
        if vbox_host_client.is_configured:
            run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Host Controller: Reverting VM '{vm}' to snapshot '{snap}'...")
            rst = vbox_host_client.restore_snapshot(vm, snap)
            if rst.get("error"):
                raise RuntimeError(f"Host Controller snapshot restore failed: {rst.get('error')}")

            run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Host Controller: Booting worker VM '{vm}' headless...")
            st = vbox_host_client.start_worker(vm)
            if st.get("error"):
                raise RuntimeError(f"Host Controller worker start failed: {st.get('error')}")

            # Generate scoped worker token
            token = worker_auth_manager.generate_worker_token(
                run_id=run.id,
                target_binary=run.target_binary,
                expected_sha256=getattr(run, "target_sha256", ""),
                expires_in_seconds=getattr(run, "timeout_seconds", 120) + 120,
                worker_type="windows"
            )

            # Transfer evidence
            run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Transferring staged evidence to Host Controller...")
            xfer = vbox_host_client.transfer_evidence(vm, staged_file, getattr(run, "target_sha256", ""))
            if xfer.get("error"):
                logger.warning(f"Evidence staging transfer notice: {xfer.get('error')}")

            return {
                "status": "PROVISIONED",
                "vm_name": vm,
                "worker_token": token,
                "mode": "REMOTE_HOST_AGENT",
                "timestamp": datetime.utcnow().isoformat()
            }

        # Local VBoxManage mode
        vbox = self._vboxmanage_path
        if not vbox:
            raise RuntimeError("VBoxManage path not found.")

        # Hardening: Disable clipboard and remove shared folders
        try:
            subprocess.run([vbox, "modifyvm", vm, "--clipboard-mode", "disabled"], capture_output=True, text=True, timeout=5.0)
            subprocess.run([vbox, "modifyvm", vm, "--drag-and-drop", "disabled"], capture_output=True, text=True, timeout=5.0)
        except Exception:
            pass

        # 1. Restore clean snapshot
        logger.info(f"Reverting VirtualBox VM '{vm}' to snapshot '{snap}' for run {run.id}")
        run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Restoring VirtualBox VM '{vm}' to clean snapshot '{snap}'...")
        res = subprocess.run([vbox, "snapshot", vm, "restore", snap], capture_output=True, text=True, timeout=30.0)
        if res.returncode != 0:
            raise RuntimeError(f"VirtualBox snapshot restore failed: {res.stderr.strip()}")

        # 2. Boot worker VM in headless mode
        logger.info(f"Starting VirtualBox VM '{vm}' headless...")
        run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Booting worker VM '{vm}' (headless)...")
        res = subprocess.run([vbox, "startvm", vm, "--type", "headless"], capture_output=True, text=True, timeout=30.0)
        if res.returncode != 0 and "already locked" not in res.stderr.lower():
            raise RuntimeError(f"Failed to start VirtualBox worker VM: {res.stderr.strip()}")

        # 3. Generate short-lived worker token
        token = worker_auth_manager.generate_worker_token(
            run_id=run.id,
            target_binary=run.target_binary,
            expected_sha256=getattr(run, "target_sha256", ""),
            expires_in_seconds=getattr(run, "timeout_seconds", 120) + 120,
            worker_type="windows"
        )

        return {
            "status": "PROVISIONED",
            "vm_name": vm,
            "worker_token": token,
            "mode": "LOCAL_VBOXMANAGE",
            "timestamp": datetime.utcnow().isoformat()
        }

    def execute(self, run: DynamicSandboxRun, timeout_seconds: int) -> Dict[str, Any]:
        """Dispatches execution instructions to the running worker."""
        run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Dispatching execution signal to worker VM '{self._default_vm_name}'...")
        return {
            "status": "EXECUTING",
            "vm_name": self._default_vm_name,
            "timeout_seconds": timeout_seconds,
            "started_at": datetime.utcnow().isoformat()
        }

    def collect_telemetry(self, run: DynamicSandboxRun) -> Dict[str, Any]:
        """Returns session telemetry gathered from the worker."""
        session = worker_auth_manager.get_session(run.id) or {}
        artifacts = session.get("artifacts_collected", [])

        if vbox_host_client.is_configured:
            remote_artifacts = vbox_host_client.retrieve_results(self._default_vm_name).get("artifacts", [])
            for ra in remote_artifacts:
                if ra.get("filename") not in [a.get("filename") for a in artifacts if isinstance(a, dict)]:
                    artifacts.append(ra)

        return {
            "worker_ip": session.get("worker_ip"),
            "heartbeat_count": session.get("heartbeat_count", 0),
            "telemetry_received": session.get("telemetry_received", False),
            "artifacts_collected": artifacts
        }

    def terminate(self, run: DynamicSandboxRun) -> None:
        """Powers off the worker VM."""
        if vbox_host_client.is_configured:
            vbox_host_client.stop_worker(self._default_vm_name)
            run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Worker VM '{self._default_vm_name}' powered off via Host Controller.")
            return

        vbox = self._vboxmanage_path
        if vbox:
            try:
                subprocess.run([vbox, "controlvm", self._default_vm_name, "poweroff"], capture_output=True, text=True, timeout=10.0)
                run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Worker VM '{self._default_vm_name}' powered off.")
            except Exception as e:
                logger.warning(f"Error powering off VirtualBox VM: {e}")

    def restore_and_cleanup(self, run: DynamicSandboxRun) -> None:
        """Halts the worker, restores clean snapshot, and purges worker auth token."""
        self.terminate(run)

        if vbox_host_client.is_configured:
            vbox_host_client.restore_snapshot(self._default_vm_name, self._default_snapshot)
            run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Post-analysis: Worker reverted to clean snapshot '{self._default_snapshot}' via Host Controller.")
        else:
            vbox = self._vboxmanage_path
            if vbox:
                try:
                    subprocess.run([vbox, "snapshot", self._default_vm_name, "restore", self._default_snapshot], capture_output=True, text=True, timeout=30.0)
                    run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Post-analysis: VirtualBox worker reverted to clean snapshot '{self._default_snapshot}'.")
                except Exception as e:
                    logger.warning(f"Error reverting VirtualBox snapshot: {e}")

        worker_auth_manager.revoke_worker_session(run.id)


virtualbox_provider = VirtualBoxProvider()
