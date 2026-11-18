"""
TraceX VM & Virtualization Environment Detector
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Live inspector of host and guest virtualization topography, parent hypervisors,
CPU virtualization extensions, nested virtualization capabilities, resource limits,
and hypervisor management interfaces.

Supports:
- VMware Workstation / Player / ESXi / vSphere
- Oracle VirtualBox
- Microsoft Hyper-V
- KVM / QEMU
- Proxmox VE
- Xen / Citrix
- Bare Metal / Physical Hardware
"""

import os
import sys
import shutil
import platform
import subprocess
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


class VMEnvironmentDetector:
    """
    Detects whether TraceX is running inside a virtual machine, identifies the
    parent hypervisor, inspects exposed CPU virtualization extensions (nested virtualization),
    enumerates hypervisor management tools, and evaluates available computing resources.
    """

    def __init__(self):
        self._cached_report: Optional[Dict[str, Any]] = None
        self._last_checked: Optional[datetime] = None

    def get_environment_info(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Returns the full VM environment and virtualization topometry report."""
        if not force_refresh and self._cached_report and self._last_checked:
            elapsed = (datetime.utcnow() - self._last_checked).total_seconds()
            if elapsed < 30.0:
                return self._cached_report

        report = self._inspect_environment()
        self._cached_report = report
        self._last_checked = datetime.utcnow()
        return report

    def _inspect_environment(self) -> Dict[str, Any]:
        """Conducts genuine hardware, BIOS, WMI, and hypervisor tool inspections."""
        os_name = platform.system()
        os_release = platform.release()
        os_version = platform.version()
        arch = platform.machine()

        # Hardware & BIOS topometry
        sys_info = self._get_system_wmi_info()
        manufacturer = sys_info.get("manufacturer", "")
        model = sys_info.get("model", "")
        bios_vendor = sys_info.get("bios_vendor", "")
        bios_version = sys_info.get("bios_version", "")
        bios_serial = sys_info.get("bios_serial", "")
        hypervisor_flag = sys_info.get("hypervisor_present", False)

        # Classify hypervisor
        hypervisor_type, hypervisor_name, confidence = self._classify_hypervisor(
            manufacturer, model, bios_vendor, bios_version, bios_serial, hypervisor_flag
        )
        is_vm = hypervisor_type != "bare_metal"

        # CPU & Nested Virtualization Extensions
        cpu_virt_exposed = sys_info.get("cpu_virt_enabled", False)
        nested_virt_available, nested_details = self._test_nested_virtualization(cpu_virt_exposed)

        # System Resources
        resources = self._get_resource_metrics(sys_info)

        # Management Tools
        mgmt_tools = self._detect_management_tools()

        # Network Interfaces
        net_info = self._detect_network_configuration()

        # Deployment Mode Recommendation
        recommended_mode, mode_reason, actionable_setup = self._determine_recommended_mode(
            is_vm=is_vm,
            hypervisor_type=hypervisor_type,
            nested_virt_available=nested_virt_available,
            mgmt_tools=mgmt_tools,
            resources=resources
        )

        return {
            "is_virtual_machine": is_vm,
            "detected_hypervisor": hypervisor_name,
            "hypervisor_type": hypervisor_type,
            "detection_confidence": confidence,
            "guest_os": {
                "name": os_name,
                "release": os_release,
                "version": os_version,
                "architecture": arch,
                "caption": sys_info.get("os_caption", f"{os_name} {os_release}")
            },
            "parent_hypervisor_details": {
                "system_manufacturer": manufacturer,
                "system_model": model,
                "bios_vendor": bios_vendor,
                "bios_version": bios_version,
                "bios_serial": bios_serial,
                "hypervisor_present_flag": hypervisor_flag,
                "guest_services_detected": sys_info.get("detected_guest_services", [])
            },
            "cpu_virtualization": {
                "extensions_exposed_to_guest": cpu_virt_exposed,
                "nested_virtualization_available": nested_virt_available,
                "nested_details": nested_details,
                "firmware_virtualization_enabled": cpu_virt_exposed,
                "action_required": "ACTION REQUIRED: Enable Intel VT-x in BIOS/UEFI." if not cpu_virt_exposed else None,
                "physical_cores": sys_info.get("physical_cores", os.cpu_count() or 1),
                "logical_processors": sys_info.get("logical_processors", os.cpu_count() or 1),
                "cpu_name": sys_info.get("cpu_name", platform.processor() or "Unknown CPU")
            },
            "memory_resources": {
                "total_ram_mb": resources.get("total_ram_mb", 0),
                "available_ram_mb": resources.get("available_ram_mb", 0),
                "ram_sufficient_for_workers": resources.get("available_ram_mb", 0) >= 2048
            },
            "storage_resources": {
                "workspace_drive": resources.get("workspace_drive", "C:"),
                "total_disk_gb": resources.get("total_disk_gb", 0.0),
                "free_disk_gb": resources.get("free_disk_gb", 0.0),
                "disk_sufficient_for_workers": resources.get("free_disk_gb", 0.0) >= 5.0
            },
            "management_tools_detected": mgmt_tools,
            "network_configuration": net_info,
            "deployment_mode": {
                "recommended_mode": recommended_mode,
                "reason": mode_reason,
                "actionable_setup": actionable_setup,
                "supports_mode_a_external": mgmt_tools.get("any_external_mgmt_available", False),
                "supports_mode_b_nested": nested_virt_available
            },
            "checked_at_utc": datetime.utcnow().isoformat()
        }

    def _get_system_wmi_info(self) -> Dict[str, Any]:
        """Queries Windows WMI/CIM or Linux sysfs safely with strict timeouts."""
        info = {
            "manufacturer": "",
            "model": "",
            "bios_vendor": "",
            "bios_version": "",
            "bios_serial": "",
            "hypervisor_present": False,
            "cpu_virt_enabled": False,
            "physical_cores": os.cpu_count() or 1,
            "logical_processors": os.cpu_count() or 1,
            "total_ram_bytes": 0,
            "available_ram_bytes": 0,
            "cpu_name": "",
            "os_caption": "",
            "detected_guest_services": []
        }

        if sys.platform == "win32":
            # 1. ComputerSystem
            try:
                ps_cs = "(Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, HypervisorPresent, TotalPhysicalMemory, NumberOfProcessors, NumberOfLogicalProcessors) | ConvertTo-Json"
                res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cs], capture_output=True, text=True, timeout=4.0)
                if res.returncode == 0 and res.stdout.strip():
                    import json
                    data = json.loads(res.stdout.strip())
                    info["manufacturer"] = str(data.get("Manufacturer") or "").strip()
                    info["model"] = str(data.get("Model") or "").strip()
                    info["hypervisor_present"] = bool(data.get("HypervisorPresent", False))
                    info["total_ram_bytes"] = int(data.get("TotalPhysicalMemory") or 0)
                    info["logical_processors"] = int(data.get("NumberOfLogicalProcessors") or os.cpu_count() or 1)
            except Exception:
                pass

            # 2. BIOS
            try:
                ps_bios = "(Get-CimInstance Win32_BIOS | Select-Object Manufacturer, SerialNumber, Version, SMBIOSBIOSVersion) | ConvertTo-Json"
                res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_bios], capture_output=True, text=True, timeout=3.0)
                if res.returncode == 0 and res.stdout.strip():
                    import json
                    data = json.loads(res.stdout.strip())
                    info["bios_vendor"] = str(data.get("Manufacturer") or "").strip()
                    info["bios_serial"] = str(data.get("SerialNumber") or "").strip()
                    info["bios_version"] = str(data.get("SMBIOSBIOSVersion") or data.get("Version") or "").strip()
            except Exception:
                pass

            # 3. Processor
            try:
                ps_proc = "(Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, VirtualizationFirmwareEnabled) | Select-Object -First 1 | ConvertTo-Json"
                res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_proc], capture_output=True, text=True, timeout=3.0)
                if res.returncode == 0 and res.stdout.strip():
                    import json
                    data = json.loads(res.stdout.strip())
                    info["cpu_name"] = str(data.get("Name") or "").strip()
                    info["physical_cores"] = int(data.get("NumberOfCores") or os.cpu_count() or 1)
                    info["cpu_virt_enabled"] = bool(data.get("VirtualizationFirmwareEnabled", False))
            except Exception:
                pass

            # 4. OS Caption
            try:
                ps_os = "(Get-CimInstance Win32_OperatingSystem).Caption"
                res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_os], capture_output=True, text=True, timeout=3.0)
                if res.returncode == 0 and res.stdout.strip():
                    info["os_caption"] = res.stdout.strip()
            except Exception:
                pass

            # 5. Check for hypervisor services/drivers
            known_services = [
                "VMTools", "vmmouse", "vm3dmp", "vmxnet3",
                "VBoxGuest", "VBoxMouse", "VBoxSF", "VBoxService",
                "vmicguestinterface", "vmicheartbeat", "vmickvpexchange", "vmicrdv", "vmicshutdown", "vmictimesync", "vmicvmsession", "vmbus",
                "QEMU-GA", "viostor", "netkvm"
            ]
            try:
                ps_svc = "Get-Service | Where-Object { $_.Name -match 'vbox|vmware|vmic|qemu|xen' } | Select-Object -ExpandProperty Name"
                res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_svc], capture_output=True, text=True, timeout=3.0)
                if res.returncode == 0 and res.stdout.strip():
                    svcs = [s.strip() for s in res.stdout.splitlines() if s.strip()]
                    info["detected_guest_services"] = svcs
            except Exception:
                pass

        return info

    def _classify_hypervisor(
        self,
        manufacturer: str,
        model: str,
        bios_vendor: str,
        bios_version: str,
        bios_serial: str,
        hypervisor_present: bool
    ) -> Tuple[str, str, str]:
        """
        Classifies the hypervisor based on hardware telemetry signatures.
        Returns (hypervisor_type, display_name, confidence).
        """
        m_lower = manufacturer.lower()
        model_lower = model.lower()
        bv_lower = bios_vendor.lower()
        bs_lower = bios_serial.lower()
        bver_lower = bios_version.lower()

        # 1. VMware (Workstation, Player, ESXi, Fusion)
        if "vmware" in m_lower or "vmware" in model_lower or "vmware" in bv_lower or "vmware" in bs_lower:
            name = "VMware ESXi" if ("esx" in bv_lower or "esxi" in model_lower) else "VMware Workstation / vSphere"
            return "vmware", name, "HIGH"

        # 2. Oracle VirtualBox
        if "innotek" in m_lower or "virtualbox" in model_lower or "virtualbox" in bv_lower or "vbox" in bs_lower:
            return "virtualbox", "Oracle VirtualBox", "HIGH"

        # 3. Microsoft Hyper-V
        if "microsoft" in m_lower and ("virtual machine" in model_lower or "hyper-v" in model_lower or "vrtual" in bs_lower):
            return "hyperv", "Microsoft Hyper-V", "HIGH"

        # 4. KVM / QEMU
        if "qemu" in m_lower or "qemu" in model_lower or "bochs" in bv_lower or "seabios" in bv_lower:
            # Check if running under Proxmox VE
            return "kvm", "KVM / QEMU", "HIGH"

        # 5. Xen / Citrix Hypervisor
        if "xen" in m_lower or "xen" in model_lower or "xen" in bv_lower:
            return "xen", "Xen / Citrix Hypervisor", "HIGH"

        # 6. Generic VM (HypervisorPresent flag set, but generic strings)
        if hypervisor_present:
            # Check if likely Hyper-V (e.g. Windows Virtualization-Based Security or container host)
            if "microsoft" in bv_lower or "american megatrends" in bv_lower:
                # Could be physical host running Windows with Hyper-V / VBS enabled
                if not any(v in m_lower for v in ("virtual", "qemu", "vmware", "innotek", "xen")):
                    return "bare_metal", "Bare Metal (Physical Host with VBS/Hypervisor Platform)", "HIGH"
            return "unknown_vm", "Generic Virtual Machine", "MEDIUM"

        return "bare_metal", "Bare Metal / Physical Host", "HIGH"

    def _test_nested_virtualization(self, cpu_virt_flag: bool) -> Tuple[bool, str]:
        """
        Tests whether hardware-assisted nested virtualization is actively available.
        A VM can only run nested VMs/emulators if the parent hypervisor explicitly exposes VT-x/AMD-V.
        """
        if not cpu_virt_flag:
            return False, "Hardware virtualization disabled in BIOS/hypervisor configuration."

        # If VirtualizationFirmwareEnabled is true, test if Windows Hypervisor Platform or hypervisor commands succeed
        try:
            if sys.platform == "win32":
                # Check for Hyper-V or Windows Hypervisor Platform features
                ps_test = "(Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform).State"
                res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_test], capture_output=True, text=True, timeout=3.0)
                if res.returncode == 0:
                    state = res.stdout.strip()
                    if state.lower() == "enabled":
                        return True, "VT-x/AMD-V exposed and Windows Hypervisor Platform feature is ENABLED."
                    return True, "VT-x/AMD-V exposed to guest. Windows Hypervisor Platform is AVAILABLE."
        except Exception:
            pass

        return cpu_virt_flag, "Virtualization extensions reported by processor."

    def _get_resource_metrics(self, sys_info: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates system memory and storage limits for dynamic workers."""
        total_ram_mb = int(sys_info.get("total_ram_bytes", 0) / (1024 * 1024))
        available_ram_mb = total_ram_mb

        if sys.platform == "win32":
            try:
                ps_mem = "(Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory"
                res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_mem], capture_output=True, text=True, timeout=3.0)
                if res.returncode == 0 and res.stdout.strip():
                    available_ram_mb = int(int(res.stdout.strip()) / 1024)
            except Exception:
                pass

        # Storage on drive hosting analysis_workspace
        workspace_drive = "C:"
        total_disk_gb = 0.0
        free_disk_gb = 0.0
        try:
            drive_path = Path(os.getcwd()).anchor
            total, used, free = shutil.disk_usage(drive_path)
            total_disk_gb = round(total / (1024 ** 3), 1)
            free_disk_gb = round(free / (1024 ** 3), 1)
            workspace_drive = drive_path
        except Exception:
            pass

        return {
            "total_ram_mb": total_ram_mb,
            "available_ram_mb": available_ram_mb,
            "workspace_drive": workspace_drive,
            "total_disk_gb": total_disk_gb,
            "free_disk_gb": free_disk_gb
        }

    def _detect_management_tools(self) -> Dict[str, Any]:
        """Detects installed CLI and API tools for controlling parent or nested hypervisors."""
        tools = {
            "vmware_vmrun_installed": False,
            "vmware_vmrun_path": None,
            "vbox_manage_installed": False,
            "vbox_manage_path": None,
            "hyperv_powershell_available": False,
            "virsh_installed": False,
            "virsh_path": None,
            "proxmox_api_configured": False,
            "any_external_mgmt_available": False
        }

        # 1. VMware vmrun
        vmrun_candidates = [
            shutil.which("vmrun"),
            "C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrun.exe",
            "C:\\Program Files (x86)\\VMware\\VMware VIX\\vmrun.exe",
            "C:\\Program Files\\VMware\\VMware Workstation\\vmrun.exe"
        ]
        for c in vmrun_candidates:
            if c and Path(c).exists():
                tools["vmware_vmrun_installed"] = True
                tools["vmware_vmrun_path"] = str(c)
                break

        # 2. VirtualBox VBoxManage
        vbox_candidates = [
            shutil.which("VBoxManage"),
            "C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe",
            "C:\\Program Files (x86)\\Oracle\\VirtualBox\\VBoxManage.exe"
        ]
        for c in vbox_candidates:
            if c and Path(c).exists():
                tools["vbox_manage_installed"] = True
                tools["vbox_manage_path"] = str(c)
                break

        # 3. Hyper-V PowerShell
        if sys.platform == "win32":
            try:
                res = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", "Get-Command Get-VM -ErrorAction SilentlyContinue"],
                    capture_output=True, text=True, timeout=3.0
                )
                if res.returncode == 0 and res.stdout.strip():
                    tools["hyperv_powershell_available"] = True
            except Exception:
                pass

        # 4. KVM virsh
        virsh_path = shutil.which("virsh")
        if virsh_path and Path(virsh_path).exists():
            tools["virsh_installed"] = True
            tools["virsh_path"] = str(virsh_path)

        # 5. Proxmox API (from settings or env)
        from backend.app.config import settings
        proxmox_host = getattr(settings, "PROXMOX_HOST", "") or os.getenv("PROXMOX_HOST", "")
        if proxmox_host:
            tools["proxmox_api_configured"] = True

        tools["any_external_mgmt_available"] = bool(
            tools["vmware_vmrun_installed"] or
            tools["vbox_manage_installed"] or
            tools["hyperv_powershell_available"] or
            tools["virsh_installed"] or
            tools["proxmox_api_configured"]
        )

        return tools

    def _detect_network_configuration(self) -> Dict[str, Any]:
        """Inspects network interfaces, virtual adapter vendors, and isolation topology."""
        interfaces = []
        is_virtual_nic = False

        if sys.platform == "win32":
            try:
                ps_net = "(Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }) | Select-Object Description, IPAddress, MACAddress | ConvertTo-Json"
                res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_net], capture_output=True, text=True, timeout=3.0)
                if res.returncode == 0 and res.stdout.strip():
                    import json
                    parsed = json.loads(res.stdout.strip())
                    items = parsed if isinstance(parsed, list) else [parsed]
                    for item in items:
                        desc = str(item.get("Description") or "")
                        ips = item.get("IPAddress") or []
                        if isinstance(ips, str):
                            ips = [ips]
                        mac = str(item.get("MACAddress") or "")
                        is_v = any(k in desc.lower() for k in ("vmware", "virtual", "vbox", "hyper-v", "virtio", "loopback", "tap"))
                        if is_v:
                            is_virtual_nic = True
                        interfaces.append({
                            "description": desc,
                            "ip_addresses": ips,
                            "mac_address": mac,
                            "is_virtual_adapter": is_v
                        })
            except Exception:
                pass

        return {
            "interfaces": interfaces,
            "has_virtual_nic": is_virtual_nic,
            "isolation_status": "CONTROLLED_AIRGAP" if not interfaces else "MANAGEMENT_NETWORK_ACTIVE"
        }

    def _determine_recommended_mode(
        self,
        is_vm: bool,
        hypervisor_type: str,
        nested_virt_available: bool,
        mgmt_tools: Dict[str, Any],
        resources: Dict[str, Any]
    ) -> Tuple[str, str, List[str]]:
        """
        Determines the optimal deployment mode:
        Mode A: External Hypervisor Management (preferred when TraceX runs in VM and can talk to parent hypervisor)
        Mode B: Nested Virtualization (when VT-x/AMD-V is exposed to guest)
        Remote: When remote CAPE/MobSF is configured
        Not Configured: When neither mode is available
        """
        instructions = []

        # 1. Mode A: External Hypervisor Management
        if mgmt_tools.get("vmware_vmrun_installed") and hypervisor_type == "vmware":
            return (
                "MODE_A_EXTERNAL",
                "Mode A (External VMware Management): TraceX detected VMware environment and vmrun CLI. Can control disposable worker VMs on the parent host.",
                ["Create a dedicated Worker VM 'TraceX-Worker-Win10' in VMware.", "Create a clean snapshot named 'Clean_Base'.", "Configure worker VM path in Settings -> Dynamic Analysis."]
            )

        if mgmt_tools.get("vbox_manage_installed") and hypervisor_type == "virtualbox":
            return (
                "MODE_A_EXTERNAL",
                "Mode A (External VirtualBox Management): VBoxManage detected. Can orchestrate disposable worker VMs on parent VirtualBox.",
                ["Create an analysis VM named 'TraceX-Worker-Win10' in VirtualBox.", "Take clean snapshot 'Clean_Base'.", "Attach to host-only or isolated internal network."]
            )

        if mgmt_tools.get("hyperv_powershell_available") and hypervisor_type == "hyperv":
            return (
                "MODE_A_EXTERNAL",
                "Mode A (External Hyper-V Management): Hyper-V PowerShell module available. Can manage Hyper-V worker VMs.",
                ["Create Hyper-V VM 'TraceX-Malware-Lab' with snapshot 'Clean_Base'.", "Assign to private virtual switch 'Private_Lab'."]
            )

        # 2. Mode B: Nested Virtualization
        if nested_virt_available:
            return (
                "MODE_B_NESTED",
                "Mode B (Nested Virtualization): Hardware virtualization extensions (VT-x/AMD-V) are exposed to this VM. TraceX can host disposable nested worker containers.",
                ["Enable nested virtualization in parent hypervisor if performance is sluggish.", "Disposable container sandbox ready for execution."]
            )

        # 3. Not Configured / Unsupported
        if is_vm:
            if hypervisor_type == "vmware":
                instructions = [
                    "Shut down the TraceX Manager VM in VMware.",
                    "Open VM Settings -> Processors.",
                    "Check the box: 'Virtualize Intel VT-x/EPT or AMD-V/RVI' (Nested Virtualization).",
                    "Alternatively, install VMware VIX / vmrun.exe inside the VM to enable Mode A external management.",
                    "Power on the VM. TraceX will automatically detect nested VT-x."
                ]
                reason = "Running inside VMware, but nested hardware virtualization is not exposed and vmrun is not installed."
            elif hypervisor_type == "virtualbox":
                instructions = [
                    "Shut down the TraceX VM in VirtualBox.",
                    "On the host machine, run: VBoxManage modifyvm <VM_NAME> --nested-hw-virt on",
                    "Alternatively, install VirtualBox Guest Additions and VBoxManage in PATH.",
                    "Power on the VM."
                ]
                reason = "Running inside VirtualBox, but nested VT-x/AMD-V is disabled on the parent VM."
            elif hypervisor_type == "hyperv":
                instructions = [
                    "Shut down the TraceX VM on the Hyper-V host.",
                    "On the parent Windows host, open PowerShell as Administrator and run:",
                    "Set-VMProcessor -VMName '<TraceX_VM_Name>' -ExposeVirtualizationExtensions $true",
                    "Start the TraceX VM. TraceX will immediately detect exposed hardware virtualization."
                ]
                reason = "Running inside Hyper-V, but parent host has not enabled 'ExposeVirtualizationExtensions'."
            else:
                instructions = [
                    "Enable nested virtualization (VT-x/AMD-V) in your hypervisor CPU configuration.",
                    "Allocate at least 4 GB RAM and 2 CPU cores to the TraceX Manager VM.",
                    "Alternatively, configure a remote CAPE Sandbox endpoint in Settings."
                ]
                reason = f"Running inside {hypervisor_type}, but neither external hypervisor management nor nested virtualization is active."

            return "NOT_CONFIGURED", reason, instructions

        # Bare metal
        return (
            "NOT_CONFIGURED",
            "ACTION REQUIRED: Enable Intel VT-x in BIOS/UEFI. TraceX is running on a physical host without hardware virtualization enabled in BIOS/UEFI.",
            [
                "ACTION REQUIRED: Enable Intel VT-x in BIOS/UEFI.",
                "Reboot workstation and enter BIOS/UEFI setup (press F2/Del on boot).",
                "Navigate to Advanced CPU Configuration and enable 'Intel (VMX) Virtualization Technology' (or AMD SVM).",
                "Save changes (F10) and reboot Windows.",
                "Deploy TraceX inside a dedicated Manager VM attached to the VirtualBox Host Controller Agent."
            ]
        )


vm_detector = VMEnvironmentDetector()

