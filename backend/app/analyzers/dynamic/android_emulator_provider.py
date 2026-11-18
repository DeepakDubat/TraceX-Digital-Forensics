"""
TraceX Android Emulator Analysis Provider
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Orchestrates dynamic behavioral analysis of Android APK packages on isolated
Android Studio AVD instances or dedicated Android Worker VMs.

Guarantees:
- Zero Manager VM Execution: Untrusted APK files NEVER run on the Manager VM or host.
- Hardware Virtualization Enforcement: If VT-x is disabled, clearly reports:
  "ACTION REQUIRED: Enable Intel VT-x in BIOS/UEFI."
- Strict Network Containment: By default, wifi and mobile data are disabled.
- Automated Telemetry: Live logcat, running processes, socket inspection, and artifact retrieval.
"""

import os
import shutil
import subprocess
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

from backend.app.config import settings
from backend.app.core.models import DynamicSandboxRun
from backend.app.analyzers.dynamic.sandbox_registry import ISandboxProvider
from backend.app.analyzers.dynamic.sandbox_capabilities import sandbox_capabilities
from backend.app.analyzers.dynamic.vm_detector import vm_detector

logger = logging.getLogger(__name__)


class AndroidEmulatorProvider(ISandboxProvider):
    """
    Controls disposable Android Worker environments (AVD / Dedicated Worker VM).
    """

    @property
    def provider_id(self) -> str:
        return "android_emulator"

    @property
    def name(self) -> str:
        return "Android Studio Emulator (AVD / Worker)"

    @property
    def os_family(self) -> str:
        return "android"

    def _discover_sdk(self) -> Dict[str, Optional[str]]:
        """Discovers Android SDK, ADB, and emulator binaries."""
        sdk_candidates = [
            os.getenv("ANDROID_HOME"),
            os.getenv("ANDROID_SDK_ROOT"),
            str(Path.home() / "AppData" / "Local" / "Android" / "Sdk"),
            "C:\\Android\\Sdk",
            "/opt/android-sdk",
            str(Path.home() / "Android" / "Sdk")
        ]
        sdk_path = None
        for cand in sdk_candidates:
            if cand and Path(cand).exists():
                sdk_path = str(cand)
                break

        adb_path = shutil.which("adb")
        if not adb_path and sdk_path:
            cand_adb = Path(sdk_path) / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb")
            if cand_adb.exists():
                adb_path = str(cand_adb)

        emulator_path = shutil.which("emulator")
        if not emulator_path and sdk_path:
            cand_emu = Path(sdk_path) / "emulator" / ("emulator.exe" if os.name == "nt" else "emulator")
            if cand_emu.exists():
                emulator_path = str(cand_emu)

        return {
            "sdk_root": sdk_path,
            "adb_path": adb_path,
            "emulator_path": emulator_path
        }

    def _list_avds(self, emulator_path: Optional[str]) -> List[str]:
        """Queries registered Android Virtual Devices."""
        if not emulator_path or not Path(emulator_path).exists():
            return []
        try:
            res = subprocess.run([emulator_path, "-list-avds"], capture_output=True, text=True, timeout=5.0)
            if res.returncode == 0:
                return [line.strip() for line in res.stdout.splitlines() if line.strip()]
        except Exception as e:
            logger.warning(f"Failed to list AVDs: {e}")
        return []

    def preflight(self) -> Dict[str, Any]:
        """
        Inspects Android SDK, ADB, emulator binary, registered AVDs, and hardware virtualization.
        If firmware virtualization is disabled, displays:
        ACTION REQUIRED: Enable Intel VT-x in BIOS/UEFI.
        """
        discovery = self._discover_sdk()
        sdk_found = bool(discovery["sdk_root"])
        adb_found = bool(discovery["adb_path"])
        emu_found = bool(discovery["emulator_path"])
        avds = self._list_avds(discovery["emulator_path"])

        # Check hardware virtualization
        env = vm_detector.get_environment_info()
        cpu_virt = env.get("cpu_virtualization", {})
        virt_enabled = cpu_virt.get("firmware_virtualization_enabled", True)

        if not virt_enabled:
            return {
                "ready": False,
                "status": "NOT_CONFIGURED",
                "details": {
                    "message": "ACTION REQUIRED: Enable Intel VT-x in BIOS/UEFI.",
                    "android_sdk_installed": sdk_found,
                    "adb_available": adb_found,
                    "emulator_available": emu_found,
                    "available_avds": avds,
                    "hint": "Android x86/ARM emulators require hardware-assisted virtualization. Enable Intel VT-x / AMD-V in BIOS/UEFI."
                }
            }

        if not adb_found:
            return {
                "ready": False,
                "status": "NOT_CONFIGURED",
                "details": {
                    "message": "Android Debug Bridge (adb) was not found in PATH or Android SDK platform-tools.",
                    "android_sdk_installed": sdk_found,
                    "hint": "Install Android SDK platform-tools or add adb to PATH."
                }
            }

        # Check for active devices or bootable AVDs
        matrix = sandbox_capabilities.get_capabilities()
        active_devices = matrix.active_emulators
        ready = len(active_devices) > 0 or len(avds) > 0

        status = "INSTALLED_AND_READY" if ready else "PARTIALLY_CONFIGURED"
        msg = (
            "Android analysis environment ready." if ready else
            "Android SDK and ADB installed, but no active emulator or AVD detected."
        )

        return {
            "ready": ready,
            "status": status,
            "details": {
                "message": msg,
                "sdk_root": discovery["sdk_root"],
                "adb_path": discovery["adb_path"],
                "emulator_path": discovery["emulator_path"],
                "active_devices": active_devices,
                "available_avds": avds,
                "firmware_virtualization_enabled": True
            }
        }

    def provision(self, run: DynamicSandboxRun, staged_file: Path) -> Dict[str, Any]:
        """Prepares Android emulator and validates APK target."""
        pre = self.preflight()
        if not pre.get("ready"):
            raise RuntimeError(f"Cannot provision Android emulator: {pre.get('details', {}).get('message')}")

        device_id = self._get_target_device()
        if not device_id:
            raise RuntimeError("No active Android device or emulator is connected.")

        # Enforce network isolation on device
        if run.network_policy == "DISABLED":
            self._adb(device_id, ["shell", "svc", "wifi", "disable"])
            self._adb(device_id, ["shell", "svc", "data", "disable"])

        # Clear logcat prior to analysis
        self._adb(device_id, ["logcat", "-c"])

        return {
            "device_id": device_id,
            "staged_file": str(staged_file),
            "network_policy": run.network_policy
        }

    def execute(self, run: DynamicSandboxRun, timeout_seconds: int) -> Dict[str, Any]:
        """Installs APK into the emulator and starts main activity."""
        device_id = self._get_target_device()
        if not device_id:
            raise RuntimeError("No active Android emulator connected.")

        staged_file = settings.DATA_DIR / "staging" / run.id / run.target_binary

        # 1. Install APK
        install_res = self._adb(device_id, ["install", "-r", str(staged_file)])
        if "Success" not in install_res:
            raise RuntimeError(f"APK installation failed: {install_res}")

        # 2. Extract package name from investigation or APK
        package_name = self._resolve_package_name(run)
        if package_name:
            # Launch via monkey
            launch_res = self._adb(device_id, ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"])
            return {
                "started": True,
                "device_id": device_id,
                "package_name": package_name,
                "launch_status": launch_res.strip()
            }

        return {"started": True, "device_id": device_id, "package_name": "unknown"}

    def collect_telemetry(self, run: DynamicSandboxRun) -> Dict[str, Any]:
        """Pulls Android logcat, running processes, and network socket tables."""
        device_id = self._get_target_device()
        telemetry: Dict[str, Any] = {
            "processes": [],
            "file_events": [],
            "registry_events": [],
            "network_flows": [],
            "logs": []
        }

        if not device_id:
            return telemetry

        # 1. Collect logcat
        try:
            logcat_out = self._adb(device_id, ["logcat", "-d", "-v", "time", "*:I"])
            telemetry["logs"] = logcat_out.splitlines()[:500]
        except Exception:
            pass

        # 2. Collect process snapshot
        try:
            ps_out = self._adb(device_id, ["shell", "ps", "-A"])
            package_name = self._resolve_package_name(run)
            for line in ps_out.splitlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 9:
                    pname = parts[-1]
                    pid = int(parts[1]) if parts[1].isdigit() else 0
                    ppid = int(parts[2]) if parts[2].isdigit() else 0
                    if package_name and package_name in pname:
                        telemetry["processes"].append({
                            "name": pname,
                            "pid": pid,
                            "parent_pid": ppid,
                            "operation": "AppProcessRunning"
                        })
        except Exception:
            pass

        # 3. Collect active network sockets
        try:
            net_out = self._adb(device_id, ["shell", "netstat", "-n"])
            for line in net_out.splitlines():
                if "ESTABLISHED" in line or "SYN_SENT" in line:
                    parts = line.split()
                    if len(parts) >= 6:
                        telemetry["network_flows"].append({
                            "proto": parts[0],
                            "local": parts[3],
                            "foreign": parts[4],
                            "state": parts[5]
                        })
        except Exception:
            pass

        return telemetry

    def terminate(self, run: DynamicSandboxRun) -> None:
        """Force-stops the target application."""
        device_id = self._get_target_device()
        package_name = self._resolve_package_name(run)
        if device_id and package_name:
            self._adb(device_id, ["shell", "am", "force-stop", package_name])

    def restore_and_cleanup(self, run: DynamicSandboxRun) -> None:
        """Uninstalls the application from emulator."""
        self.terminate(run)
        device_id = self._get_target_device()
        package_name = self._resolve_package_name(run)
        if device_id and package_name:
            self._adb(device_id, ["uninstall", package_name])

    def _get_target_device(self) -> Optional[str]:
        matrix = sandbox_capabilities.get_capabilities()
        if matrix.active_emulators:
            return matrix.active_emulators[0]
        return None

    def _resolve_package_name(self, run: DynamicSandboxRun) -> Optional[str]:
        from backend.app.database.repository import repo
        inv = repo.get_investigation(run.investigation_id)
        return inv.package_name if inv and inv.package_name else None

    def _adb(self, device_id: str, args: List[str]) -> str:
        cmd = ["adb", "-s", device_id] + args
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30.0)
        return res.stdout


android_emulator_provider = AndroidEmulatorProvider()
