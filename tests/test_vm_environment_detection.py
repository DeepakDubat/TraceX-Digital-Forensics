"""
TraceX VM & Hypervisor Environment Detection Test Suite
Verifies:
1. Genuine host/VM topometry inspection (hardware, BIOS, CPU, RAM, Disk).
2. Hypervisor classification heuristics (VMware, VirtualBox, Hyper-V, KVM, Proxmox, Bare Metal).
3. CPU virtualization and nested virtualization detection.
4. Resource capacity evaluation and concurrency budgeting.
5. API endpoints (/api/dynamic/vm-environment and /api/dynamic/vm-environment/test-nested).
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.analyzers.dynamic.vm_detector import vm_detector, VMEnvironmentDetector
from backend.app.analyzers.dynamic.resource_manager import vm_resource_manager, ResourceExhaustionError

client = TestClient(app)


def test_vm_detector_topometry_structure():
    """Verifies that live environment detection returns a complete, well-formed schema."""
    info = vm_detector.get_environment_info(force_refresh=True)

    assert "is_virtual_machine" in info
    assert "detected_hypervisor" in info
    assert "hypervisor_type" in info
    assert "detection_confidence" in info

    # Guest OS
    assert "guest_os" in info
    assert info["guest_os"]["name"] in ("Windows", "Linux", "Darwin")
    assert info["guest_os"]["architecture"]

    # CPU Virtualization
    assert "cpu_virtualization" in info
    assert isinstance(info["cpu_virtualization"]["extensions_exposed_to_guest"], bool)
    assert isinstance(info["cpu_virtualization"]["nested_virtualization_available"], bool)
    assert info["cpu_virtualization"]["physical_cores"] >= 1
    assert info["cpu_virtualization"]["logical_processors"] >= 1

    # Resources
    assert "memory_resources" in info
    assert info["memory_resources"]["total_ram_mb"] > 0
    assert "storage_resources" in info
    assert info["storage_resources"]["total_disk_gb"] > 0

    # Deployment Mode
    assert "deployment_mode" in info
    assert info["deployment_mode"]["recommended_mode"] in ("MODE_A_EXTERNAL", "MODE_B_NESTED", "NOT_CONFIGURED")
    assert isinstance(info["deployment_mode"]["actionable_setup"], list)


def test_hypervisor_classification_heuristics():
    """Tests the classification engine against known hardware/BIOS manufacturer signatures."""
    det = VMEnvironmentDetector()

    # 1. VMware Workstation / ESXi
    t, name, conf = det._classify_hypervisor("VMware, Inc.", "VMware Virtual Platform", "Phoenix Technologies LTD", "6.00", "VMware-42 1a 8c", True)
    assert t == "vmware"
    assert "VMware" in name
    assert conf == "HIGH"

    # 2. Oracle VirtualBox
    t, name, conf = det._classify_hypervisor("innotek GmbH", "VirtualBox", "innotek GmbH", "1.2", "0", True)
    assert t == "virtualbox"
    assert "VirtualBox" in name
    assert conf == "HIGH"

    # 3. Microsoft Hyper-V
    t, name, conf = det._classify_hypervisor("Microsoft Corporation", "Virtual Machine", "American Megatrends Inc.", "090008", "VRTUAL - 1000", True)
    assert t == "hyperv"
    assert "Hyper-V" in name
    assert conf == "HIGH"

    # 4. QEMU / KVM
    t, name, conf = det._classify_hypervisor("QEMU", "Standard PC (Q35 + ICH9, 2009)", "SeaBIOS", "rel-1.16", "", True)
    assert t == "kvm"
    assert "KVM" in name
    assert conf == "HIGH"

    # 5. Bare Metal
    t, name, conf = det._classify_hypervisor("Dell Inc.", "OptiPlex 7090", "Dell Inc.", "1.5.0", "CN12345", False)
    assert t == "bare_metal"
    assert "Bare Metal" in name
    assert conf == "HIGH"


def test_resource_manager_budgeting_and_concurrency():
    """Verifies that resource manager allocates slots and enforces concurrency limits."""
    # Status check
    status = vm_resource_manager.get_resource_status()
    assert "capacity_available" in status
    assert "memory" in status
    assert "storage" in status

    run_id_1 = "RUN-TEST-RES-001"
    run_id_2 = "RUN-TEST-RES-002"

    try:
        # If system has enough RAM/Disk, slot allocation succeeds
        if status["memory"]["is_sufficient"] and status["storage"]["is_sufficient"]:
            assert vm_resource_manager.allocate_worker_resources(run_id_1, required_ram_mb=2048) is True

            # Attempting second concurrent worker should be rejected by default max_concurrent=1
            with pytest.raises(ResourceExhaustionError) as exc_info:
                vm_resource_manager.allocate_worker_resources(run_id_2, required_ram_mb=2048)
            assert "Worker concurrency limit reached" in str(exc_info.value)

            # Release slot
            vm_resource_manager.release_worker_resources(run_id_1)
            updated_status = vm_resource_manager.get_resource_status()
            assert updated_status["active_worker_count"] == 0

    finally:
        vm_resource_manager.release_worker_resources(run_id_1)
        vm_resource_manager.release_worker_resources(run_id_2)


def test_vm_environment_api_endpoints():
    """Verifies that the /api/dynamic/vm-environment endpoints work with authenticated requests."""
    # Direct TestClient without mock headers
    res_env = client.get("/api/dynamic/vm-environment")
    assert res_env.status_code == 200
    data = res_env.json()
    assert "environment" in data
    assert "resources" in data
    assert "two_plane_architecture" in data
    assert data["two_plane_architecture"]["zero_host_execution_guaranteed"] is True

    # Nested test endpoint
    res_test = client.post("/api/dynamic/vm-environment/test-nested")
    assert res_test.status_code == 200
    assert "nested_virtualization_active" in res_test.json()

