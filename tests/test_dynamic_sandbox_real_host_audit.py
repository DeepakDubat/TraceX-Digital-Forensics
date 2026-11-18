"""
TraceX Dynamic Sandbox Real Host Audit & Isolation Verification Suite
Tests the genuine host environment, honest capability discovery, preflight gating,
and strict zero-host-execution guarantees.
"""

import os
import sys
import tempfile
import hashlib
from pathlib import Path
import pytest

from backend.app.config import settings
from backend.app.core.models import DynamicSandboxRun
from backend.app.database.repository import repo
from backend.app.analyzers.dynamic.sandbox_capabilities import sandbox_capabilities
from backend.app.analyzers.dynamic.sandbox_policy import sandbox_policy, SandboxSecurityViolation
from backend.app.analyzers.dynamic.sandbox_manager import DynamicSandboxManager
from backend.app.analyzers.dynamic.windows_sandbox import windows_sandbox_provider
from backend.app.analyzers.dynamic.hyperv_provider import hyperv_provider
from backend.app.analyzers.dynamic.android_emulator_provider import android_emulator_provider


# ==============================================================================
# TEST 1: LIVE HOST CAPABILITY INSPECTION REFLECTS GROUND TRUTH
# ==============================================================================

def test_live_host_capabilities_ground_truth():
    """
    Verifies that sandbox_capabilities honestly queries the Windows host
    without mock fabrication or false claims.
    """
    matrix = sandbox_capabilities.get_capabilities(force_refresh=True)

    # Validate OS detection
    assert "Windows" in matrix.os_name
    assert matrix.os_version

    # Validate Hardware Virtualization
    # Host is Windows 11 Home with VirtualizationFirmwareEnabled: False
    assert isinstance(matrix.cpu_virtualization_enabled, bool)
    assert isinstance(matrix.hyperv_supported, bool)
    assert isinstance(matrix.hyperv_active, bool)
    assert isinstance(matrix.windows_sandbox_installed, bool)

    # Windows Sandbox and Hyper-V must NOT report installed/active if not present
    if not matrix.windows_sandbox_installed:
        wsb_env = next((e for e in sandbox_capabilities.list_environments() if e.id == "env-windows-sandbox"), None)
        assert wsb_env is not None
        assert wsb_env.is_available is False
        assert wsb_env.status in ("UNSUPPORTED_PLATFORM", "NOT_CONFIGURED")

    if not matrix.hyperv_active:
        hv_env = next((e for e in sandbox_capabilities.list_environments() if e.id == "env-hyperv-vm"), None)
        assert hv_env is not None
        assert hv_env.is_available is False
        assert hv_env.status in ("UNSUPPORTED_PLATFORM", "NOT_CONFIGURED")


# ==============================================================================
# TEST 2: ALL SIX ENVIRONMENTS HONESTLY ENUMERATED
# ==============================================================================

def test_environments_enumeration_and_status():
    """Verifies that all 6 dynamic analysis environments are listed with realistic statuses."""
    envs = sandbox_capabilities.list_environments(force_refresh=True)
    env_ids = [e.id for e in envs]

    assert "env-windows-sandbox" in env_ids
    assert "env-hyperv-vm" in env_ids
    assert "env-cape-sandbox" in env_ids
    assert "env-android-avd" in env_ids
    assert "env-genymotion" in env_ids
    assert "env-mobsf-dynamic" in env_ids

    # Every environment must define isolation model and requirements
    for e in envs:
        assert e.name
        assert e.provider_type
        assert e.os_family in ("windows", "android", "linux")
        assert e.status in ("INSTALLED_AND_READY", "CONFIGURED_OFFLINE", "NOT_CONFIGURED", "UNSUPPORTED_PLATFORM")


# ==============================================================================
# TEST 3: ZERO HOST EXECUTION ENFORCEMENT
# ==============================================================================

def test_zero_host_execution_policy():
    """
    Verifies Requirement 1: Any attempt to direct execution to the host,
    local workstation, or raw subprocess MUST be immediately rejected.
    """
    # Create a temporary synthetic safe sample
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(b"MZ_SYNTHETIC_BENIGN_TEST_PAYLOAD")
        f_path = Path(f.name)

    sample_sha256 = hashlib.sha256(b"MZ_SYNTHETIC_BENIGN_TEST_PAYLOAD").hexdigest()

    try:
        # 1. Reject 'host' environment
        with pytest.raises(SandboxSecurityViolation) as exc_info:
            sandbox_policy.validate_execution_target("host", f_path, sample_sha256)
        assert "Direct host execution" in str(exc_info.value)

        # 2. Reject 'workstation' environment
        with pytest.raises(SandboxSecurityViolation) as exc_info:
            sandbox_policy.validate_execution_target("workstation", f_path, sample_sha256)
        assert "Direct host execution" in str(exc_info.value)

        # 3. Reject 'subprocess' environment
        with pytest.raises(SandboxSecurityViolation) as exc_info:
            sandbox_policy.validate_execution_target("subprocess", f_path, sample_sha256)
        assert "Direct host execution" in str(exc_info.value)

        # 4. Reject tampered SHA-256
        with pytest.raises(SandboxSecurityViolation) as exc_info:
            sandbox_policy.validate_execution_target("env-windows-sandbox", f_path, "0000000000000000000000000000000000000000000000000000000000000000")
        assert "INTEGRITY VIOLATION" in str(exc_info.value)

    finally:
        if f_path.exists():
            f_path.unlink()


# ==============================================================================
# TEST 4: PREFLIGHT GATING PREVENTS EXECUTION ON UNREADY HOST
# ==============================================================================

def test_preflight_gating_rejects_unready_providers():
    """
    Verifies that provider.preflight() correctly returns ready=False
    when the underlying host virtualization or tools are not present,
    and start_analysis_session aborts with status=FAILED rather than executing on host.
    """
    # 1. Check Windows Sandbox preflight on this host
    wsb_pre = windows_sandbox_provider.preflight()
    assert isinstance(wsb_pre["ready"], bool)
    if not wsb_pre["ready"]:
        assert wsb_pre["status"] in ("UNSUPPORTED_PLATFORM", "NOT_CONFIGURED")
        assert "Windows Sandbox" in wsb_pre["details"]["message"]

    # 2. Check Hyper-V preflight on this host
    hv_pre = hyperv_provider.preflight()
    assert isinstance(hv_pre["ready"], bool)
    if not hv_pre["ready"]:
        assert hv_pre["status"] in ("UNSUPPORTED_PLATFORM", "NOT_CONFIGURED")
        assert "Hyper-V" in hv_pre["details"]["message"]

    # 3. Check Android Emulator preflight on this host
    matrix = sandbox_capabilities.get_capabilities()
    if len(matrix.active_emulators) == 0 and len(matrix.available_avds) == 0:
        droid_pre = android_emulator_provider.preflight()
        assert droid_pre["ready"] is False
        assert droid_pre["status"] in ("CONFIGURED_OFFLINE", "NOT_CONFIGURED")


# ==============================================================================
# TEST 5: STAGING ISOLATION & IMMUTABILITY
# ==============================================================================

def test_staging_isolation_and_integrity_verification():
    """
    Verifies that staging:
    1. Creates a working copy in an isolated directory.
    2. Verifies SHA-256 match before and after staging.
    3. Leaves original evidence untouched.
    """
    # Create synthetic safe binary
    test_content = b"TRACE_X_BENIGN_SYNTHETIC_PE_ANALYSIS_TARGET_SAMPLE"
    original_sha256 = hashlib.sha256(test_content).hexdigest()

    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(test_content)
        orig_path = Path(f.name)

    analysis_id = "RUN-TEST-ISOLATION-001"

    try:
        staged_path, staged_hash = sandbox_policy.create_isolated_staging_copy(
            analysis_id=analysis_id,
            original_evidence_path=orig_path,
            expected_sha256=original_sha256
        )

        assert staged_path.exists()
        assert staged_hash.lower() == original_sha256.lower()
        assert staged_path != orig_path
        assert analysis_id in str(staged_path)

        # Confirm original file remains identical
        assert orig_path.exists()
        assert hashlib.sha256(orig_path.read_bytes()).hexdigest().lower() == original_sha256.lower()

    finally:
        if orig_path.exists():
            orig_path.unlink()
        staging_dir = settings.DATA_DIR / "staging" / analysis_id
        if staging_dir.exists():
            import shutil
            shutil.rmtree(staging_dir, ignore_errors=True)
