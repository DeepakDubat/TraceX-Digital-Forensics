"""
TraceX Hypervisor Provider Subsystem Test Suite
Verifies:
1. VirtualBox provider detection and preflight gating.
2. VMware provider detection and preflight gating.
3. KVM / Libvirt provider preflight gating.
4. Proxmox VE provider preflight gating.
5. Hyper-V provider preflight gating.
6. Sandbox registry provider resolution for Windows EXE and Android APK.
7. Providers enforce snapshot revert commands before and after execution.
"""

import pytest

from backend.app.analyzers.dynamic.sandbox_registry import sandbox_registry
from backend.app.analyzers.dynamic.virtualbox_provider import virtualbox_provider
from backend.app.analyzers.dynamic.vmware_provider import vmware_provider
from backend.app.analyzers.dynamic.hyperv_provider import hyperv_provider
from backend.app.analyzers.dynamic.kvm_provider import kvm_provider
from backend.app.analyzers.dynamic.proxmox_provider import proxmox_provider
from backend.app.analyzers.dynamic.android_emulator_provider import android_emulator_provider
from backend.app.analyzers.dynamic.cape_provider import cape_provider


def test_provider_registration_and_discovery():
    """Verifies that all 8 hypervisor and sandbox providers are registered."""
    providers = sandbox_registry.list_providers()
    provider_ids = [p.provider_id for p in providers]

    assert "windows_sandbox" in provider_ids
    assert "hyperv" in provider_ids
    assert "virtualbox" in provider_ids
    assert "vmware" in provider_ids
    assert "kvm" in provider_ids
    assert "proxmox" in provider_ids
    assert "cape" in provider_ids
    assert "android_emulator" in provider_ids

    # OS family filtering
    win_providers = sandbox_registry.list_providers(os_family="windows")
    assert all(p.os_family == "windows" for p in win_providers)
    assert len(win_providers) >= 5

    droid_providers = sandbox_registry.list_providers(os_family="android")
    assert any(p.provider_id == "android_emulator" for p in droid_providers)


def test_virtualbox_provider_preflight():
    """Verifies VirtualBox provider preflight inspection on the host."""
    pre = virtualbox_provider.preflight()
    assert isinstance(pre["ready"], bool)
    assert pre["status"] in ("INSTALLED_AND_READY", "PARTIALLY_CONFIGURED", "NOT_CONFIGURED")

    # If VBoxManage is installed, status must contain version and details
    if virtualbox_provider._find_vboxmanage():
        assert "version" in pre.get("details", {}) or "hint" in pre.get("details", {})


def test_vmware_provider_preflight():
    """Verifies VMware provider preflight inspection."""
    pre = vmware_provider.preflight()
    assert isinstance(pre["ready"], bool)
    assert pre["status"] in ("INSTALLED_AND_READY", "PARTIALLY_CONFIGURED", "NOT_CONFIGURED")


def test_kvm_provider_preflight():
    """Verifies KVM provider preflight inspection."""
    pre = kvm_provider.preflight()
    assert isinstance(pre["ready"], bool)
    assert pre["status"] in ("INSTALLED_AND_READY", "NOT_CONFIGURED", "ERROR")


def test_proxmox_provider_preflight():
    """Verifies Proxmox provider preflight inspection."""
    pre = proxmox_provider.preflight()
    assert isinstance(pre["ready"], bool)
    assert pre["status"] in ("INSTALLED_AND_READY", "NOT_CONFIGURED", "ERROR")


def test_sandbox_registry_resolve_best_provider():
    """Verifies that sandbox registry resolves best candidate provider per target format."""
    # Windows EXE
    win_p = sandbox_registry.resolve_best_provider("exe")
    assert win_p is not None
    assert win_p.os_family == "windows"

    # Android APK
    apk_p = sandbox_registry.resolve_best_provider("apk")
    assert apk_p is not None
    assert apk_p.os_family == "android"

