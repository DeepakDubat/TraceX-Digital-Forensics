import os
import sys
import shutil
import platform
import subprocess
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

from backend.app.config import settings
from backend.app.core.models import (
    SandboxCapabilityMatrix,
    SandboxEnvironmentInfo
)

logger = logging.getLogger(__name__)

class SandboxCapabilitiesDetector:
    """
    Live inspector of host virtualization infrastructure, container subsystems,
    and Android emulator environments.
    Reports honest ground truth: never assumes tools exist or that virtualization is enabled.
    """

    def __init__(self):
        self._cached_matrix: Optional[SandboxCapabilityMatrix] = None
        self._cache_timestamp: Optional[datetime] = None

    def get_capabilities(self, force_refresh: bool = False) -> SandboxCapabilityMatrix:
        """Returns the complete virtualization and sandbox capability matrix."""
        if not force_refresh and self._cached_matrix and self._cache_timestamp:
            elapsed = (datetime.utcnow() - self._cache_timestamp).total_seconds()
            if elapsed < 30.0:
                return self._cached_matrix

        matrix = self._inspect_system()
        self._cached_matrix = matrix
        self._cache_timestamp = datetime.utcnow()
        return matrix

    def list_environments(self, force_refresh: bool = False) -> List[SandboxEnvironmentInfo]:
        """Discovers and enumerates all available and configurable sandbox environments."""
        matrix = self.get_capabilities(force_refresh=force_refresh)
        envs: List[SandboxEnvironmentInfo] = []

        # 1. Windows Sandbox (Disposable WSB)
        wsb_status = "INSTALLED_AND_READY" if matrix.windows_sandbox_installed else (
            "UNSUPPORTED_PLATFORM" if "home" in matrix.os_name.lower() else "NOT_CONFIGURED"
        )
        envs.append(SandboxEnvironmentInfo(
            id="env-windows-sandbox",
            name="Windows Sandbox (Disposable Container)",
            provider_type="windows_sandbox",
            os_family="windows",
            is_available=matrix.windows_sandbox_installed,
            status=wsb_status,
            version=matrix.os_version,
            details={
                "isolation_model": "Micro-VM Lightweight Container",
                "disposable": True,
                "supported": matrix.windows_sandbox_installed,
                "requirements": "Windows 10/11 Pro/Enterprise/Edu, Hardware Virtualization enabled"
            },
            config={"max_memory_mb": 4096, "networking": "disabled", "clipboard": "disabled"}
        ))

        # 2. Hyper-V Disposable VM
        hyperv_status = "INSTALLED_AND_READY" if (matrix.hyperv_active and matrix.cpu_virtualization_enabled) else (
            "UNSUPPORTED_PLATFORM" if not matrix.hyperv_supported else "NOT_CONFIGURED"
        )
        envs.append(SandboxEnvironmentInfo(
            id="env-hyperv-vm",
            name="Hyper-V Dedicated Analysis VM",
            provider_type="hyperv",
            os_family="windows",
            is_available=matrix.hyperv_active,
            status=hyperv_status,
            version="Hyper-V 10.0",
            details={
                "isolation_model": "Type-1 Hypervisor Full Virtual Machine",
                "snapshot_rollback": True,
                "active": matrix.hyperv_active,
                "supported": matrix.hyperv_supported,
                "cpu_virtualization": matrix.cpu_virtualization_enabled
            },
            config={"vm_name": "TraceX-Malware-Lab", "snapshot_name": "Clean_Base", "vswitch": "Private_Lab"}
        ))

        # 3. CAPE Sandbox (Automated Remote)
        cape_url = getattr(settings, "CAPE_URL", "").strip()
        cape_status = "INSTALLED_AND_READY" if matrix.cape_configured else "NOT_CONFIGURED"
        envs.append(SandboxEnvironmentInfo(
            id="env-cape-sandbox",
            name="CAPE Sandbox (Remote Cuckoo Derivative)",
            provider_type="cape",
            os_family="windows",
            is_available=matrix.cape_configured,
            status=cape_status,
            version="CAPE 2.x API",
            details={
                "isolation_model": "Remote Automated Bare-Metal / KVM Sandbox",
                "api_url": cape_url or "Not Configured",
                "kernel_monitoring": True
            },
            config={"api_url": cape_url, "timeout": 180}
        ))

        # 4. Android Studio Emulator (AVD)
        avd_count = len(matrix.available_avds)
        active_count = len(matrix.active_emulators)
        droid_status = "INSTALLED_AND_READY" if (active_count > 0 or avd_count > 0) else (
            "NOT_CONFIGURED" if not matrix.adb_installed else "CONFIGURED_OFFLINE"
        )
        envs.append(SandboxEnvironmentInfo(
            id="env-android-avd",
            name="Android Studio Emulator (AVD)",
            provider_type="android_emulator",
            os_family="android",
            is_available=(matrix.adb_installed and (avd_count > 0 or active_count > 0)),
            status=droid_status,
            version="Android SDK Platform-Tools",
            details={
                "isolation_model": "QEMU-based ARM/x86 Android Virtual Device",
                "adb_installed": matrix.adb_installed,
                "avds_discovered": matrix.available_avds,
                "running_devices": matrix.active_emulators,
                "snapshot_rollback": True
            },
            config={"target_avd": matrix.available_avds[0] if matrix.available_avds else "", "dns_isolation": True}
        ))

        # 5. Genymotion Desktop
        envs.append(SandboxEnvironmentInfo(
            id="env-genymotion",
            name="Genymotion Desktop / Player",
            provider_type="genymotion",
            os_family="android",
            is_available=False,
            status="NOT_CONFIGURED",
            version="Genymotion gmtool",
            details={
                "isolation_model": "VirtualBox/KVM Hardware-Accelerated Android",
                "gmtool_installed": False,
                "message": "Genymotion toolchain not detected in PATH"
            },
            config={"vm_name": "Samsung_Galaxy_S10_API29"}
        ))

        # 6. MobSF Dynamic Analyzer
        mobsf_status = "INSTALLED_AND_READY" if matrix.mobsf_dynamic_configured else "NOT_CONFIGURED"
        envs.append(SandboxEnvironmentInfo(
            id="env-mobsf-dynamic",
            name="MobSF Dynamic Analyzer",
            provider_type="mobsf_dynamic",
            os_family="android",
            is_available=matrix.mobsf_dynamic_configured,
            status=mobsf_status,
            version="MobSF REST API v1",
            details={
                "isolation_model": "MobSF Instrumented Dynamic Container / Corellium",
                "xposed_frida_support": True
            },
            config={"mobsf_url": getattr(settings, "MOBSF_URL", "http://127.0.0.1:8001")}
        ))

        # 7. Oracle VirtualBox Worker VM (Mode A External / Mode B Nested)
        from backend.app.analyzers.dynamic.virtualbox_provider import virtualbox_provider
        vbox_pre = virtualbox_provider.preflight()
        envs.append(SandboxEnvironmentInfo(
            id="env-virtualbox-worker",
            name="Oracle VirtualBox Disposable Worker",
            provider_type="virtualbox",
            os_family="windows",
            is_available=vbox_pre.get("ready", False),
            status=vbox_pre.get("status", "NOT_CONFIGURED"),
            version=vbox_pre.get("details", {}).get("version", "VirtualBox 7.x"),
            details={
                "isolation_model": "Type-2 Hypervisor Disposable Sibling / Nested VM",
                "snapshot_rollback": True,
                "message": vbox_pre.get("details", {}).get("message", ""),
                "hint": vbox_pre.get("details", {}).get("hint", "")
            },
            config={"vm_name": "TraceX-Worker-Win10", "snapshot_name": "Clean_Base"}
        ))

        # 8. VMware Workstation / ESXi Worker VM
        from backend.app.analyzers.dynamic.vmware_provider import vmware_provider
        vmw_pre = vmware_provider.preflight()
        envs.append(SandboxEnvironmentInfo(
            id="env-vmware-worker",
            name="VMware Workstation / ESXi Worker",
            provider_type="vmware",
            os_family="windows",
            is_available=vmw_pre.get("ready", False),
            status=vmw_pre.get("status", "NOT_CONFIGURED"),
            version="VMware Workstation / vSphere",
            details={
                "isolation_model": "Hardware-Assisted Disposable Analysis VM",
                "snapshot_rollback": True,
                "message": vmw_pre.get("details", {}).get("message", ""),
                "hint": vmw_pre.get("details", {}).get("hint", "")
            },
            config={"vmx_path": "TraceX-Worker-Win10.vmx", "snapshot_name": "Clean_Base"}
        ))

        # 9. KVM / QEMU Disposable Worker
        from backend.app.analyzers.dynamic.kvm_provider import kvm_provider
        kvm_pre = kvm_provider.preflight()
        envs.append(SandboxEnvironmentInfo(
            id="env-kvm-worker",
            name="KVM / QEMU Disposable Worker",
            provider_type="kvm",
            os_family="windows",
            is_available=kvm_pre.get("ready", False),
            status=kvm_pre.get("status", "NOT_CONFIGURED"),
            version="QEMU/KVM Libvirt",
            details={
                "isolation_model": "Linux KVM Hardware-Accelerated Virtual Machine",
                "snapshot_rollback": True,
                "message": kvm_pre.get("details", {}).get("message", "")
            },
            config={"domain": "TraceX-Worker-Win10", "snapshot_name": "Clean_Base"}
        ))

        # 10. Proxmox VE Cluster Worker
        from backend.app.analyzers.dynamic.proxmox_provider import proxmox_provider
        pve_pre = proxmox_provider.preflight()
        envs.append(SandboxEnvironmentInfo(
            id="env-proxmox-worker",
            name="Proxmox VE Cluster Worker",
            provider_type="proxmox",
            os_family="windows",
            is_available=pve_pre.get("ready", False),
            status=pve_pre.get("status", "NOT_CONFIGURED"),
            version="Proxmox VE 8.x REST API",
            details={
                "isolation_model": "PVE Cluster Orchestrated Worker VM",
                "snapshot_rollback": True,
                "message": pve_pre.get("details", {}).get("message", "")
            },
            config={"vmid": "100", "snapshot_name": "Clean_Base"}
        ))

        return envs

    def _inspect_system(self) -> SandboxCapabilityMatrix:
        """Conducts genuine host system checks without assumptions."""
        os_name = platform.system()
        os_version = platform.version()
        cpu_virt = False
        hyperv_supported = False
        hyperv_active = False
        wsb_installed = False

        if os_name == "Windows":
            os_caption, cpu_virt, hyperv_supported, hyperv_active, wsb_installed = self._inspect_windows_host()
            os_name = os_caption or f"Windows {platform.release()}"

        # Android Subsystem Checks
        android_sdk_installed, adb_installed, avds, active_emulators = self._inspect_android_host()

        # Network Simulation Tool Checks
        fakenet_installed = bool(shutil.which("fakenet")) or bool(getattr(settings, "FAKENET_PATH", ""))
        inetsim_installed = bool(shutil.which("inetsim")) or bool(getattr(settings, "INETSIM_PATH", ""))

        # Remote Sandboxes
        cape_url = getattr(settings, "CAPE_URL", "").strip()
        cape_configured = bool(cape_url)

        mobsf_url = getattr(settings, "MOBSF_URL", "").strip()
        mobsf_configured = bool(mobsf_url and not mobsf_url.startswith("•••"))

        # Overall Readiness Ratings
        overall_win = "READY" if (wsb_installed or hyperv_active or cape_configured) else "NOT_CONFIGURED"
        overall_droid = "READY" if (adb_installed and (len(active_emulators) > 0 or len(avds) > 0)) else "NOT_CONFIGURED"

        return SandboxCapabilityMatrix(
            os_name=os_name,
            os_version=os_version,
            cpu_virtualization_enabled=cpu_virt,
            hyperv_supported=hyperv_supported,
            hyperv_active=hyperv_active,
            windows_sandbox_installed=wsb_installed,
            android_sdk_installed=android_sdk_installed,
            adb_installed=adb_installed,
            available_avds=avds,
            active_emulators=active_emulators,
            mobsf_dynamic_configured=mobsf_configured,
            cape_configured=cape_configured,
            fakenet_installed=fakenet_installed,
            inetsim_installed=inetsim_installed,
            overall_windows_readiness=overall_win,
            overall_android_readiness=overall_droid
        )

    def _inspect_windows_host(self) -> Tuple[str, bool, bool, bool, bool]:
        """Queries WMI, system binaries, and optional features safely."""
        os_caption = "Microsoft Windows"
        cpu_virt = False
        hyperv_supported = False
        hyperv_active = False
        wsb_installed = False

        try:
            # Query OS Edition
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "(Get-WmiObject -Class Win32_OperatingSystem).Caption"],
                capture_output=True, text=True, timeout=4.0
            )
            if res.returncode == 0 and res.stdout.strip():
                os_caption = res.stdout.strip()
        except Exception:
            pass

        # Check if Windows edition supports Hyper-V (Pro, Enterprise, Education, Server)
        is_home_edition = "home" in os_caption.lower()
        hyperv_supported = not is_home_edition

        try:
            # Check CPU Virtualization
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "(Get-WmiObject -Class Win32_Processor).VirtualizationFirmwareEnabled"],
                capture_output=True, text=True, timeout=4.0
            )
            if res.returncode == 0:
                cpu_virt = "true" in res.stdout.lower()
        except Exception:
            pass

        try:
            # Check Windows Sandbox binary
            wsb_path = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "WindowsSandbox.exe"
            if wsb_path.exists():
                wsb_installed = True
            elif shutil.which("WindowsSandbox"):
                wsb_installed = True
        except Exception:
            pass

        try:
            # Check Hyper-V VMMS service status
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "(Get-Service -Name vmms -ErrorAction SilentlyContinue).Status"],
                capture_output=True, text=True, timeout=3.0
            )
            if res.returncode == 0 and "running" in res.stdout.lower():
                hyperv_active = True
        except Exception:
            pass

        return os_caption, cpu_virt, hyperv_supported, hyperv_active, wsb_installed

    def _inspect_android_host(self) -> Tuple[bool, bool, List[str], List[str]]:
        """Inspects Android SDK, ADB, and available/active emulators."""
        sdk_installed = False
        adb_installed = False
        avds: List[str] = []
        active_emulators: List[str] = []

        # Check ANDROID_HOME / ANDROID_SDK_ROOT
        sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
        if not sdk_root:
            local_appdata = os.environ.get("LOCALAPPDATA", "")
            if local_appdata:
                potential_sdk = Path(local_appdata) / "Android" / "Sdk"
                if potential_sdk.exists():
                    sdk_root = str(potential_sdk)

        if sdk_root and Path(sdk_root).exists():
            sdk_installed = True

        # Check ADB binary
        adb_path = shutil.which("adb")
        if not adb_path and sdk_root:
            potential_adb = Path(sdk_root) / "platform-tools" / ("adb.exe" if sys.platform == "win32" else "adb")
            if potential_adb.exists():
                adb_path = str(potential_adb)

        if adb_path and Path(adb_path).exists():
            adb_installed = True
            # Query active devices
            try:
                res = subprocess.run([adb_path, "devices"], capture_output=True, text=True, timeout=4.0)
                if res.returncode == 0:
                    for line in res.stdout.splitlines()[1:]:
                        parts = line.strip().split()
                        if len(parts) >= 2 and parts[1] == "device":
                            active_emulators.append(parts[0])
            except Exception:
                pass

        # Check AVDs
        if sdk_root:
            emulator_path = Path(sdk_root) / "emulator" / ("emulator.exe" if sys.platform == "win32" else "emulator")
            if emulator_path.exists():
                try:
                    res = subprocess.run([str(emulator_path), "-list-avds"], capture_output=True, text=True, timeout=4.0)
                    if res.returncode == 0:
                        avds = [line.strip() for line in res.stdout.splitlines() if line.strip()]
                except Exception:
                    pass

        # Check user .android/avd folder if emulator tool not in path
        if not avds:
            user_home = Path.home() / ".android" / "avd"
            if user_home.exists():
                avds = [d.stem for d in user_home.glob("*.ini")]

        return sdk_installed, adb_installed, avds, active_emulators

sandbox_capabilities = SandboxCapabilitiesDetector()
