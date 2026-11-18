"""
TraceX VirtualBox Host Controller Agent & Worker VM Tests
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Comprehensive Security Tests:
1. Wildcard 0.0.0.0 Binding Rejection
2. Worker VM Allowlist (Kali VM explicitly excluded) & Snapshot Whitelist
3. Rate Limiter Brute-Force Protection
4. Audit Logging Validation
5. PKI Certificate Generation & mTLS Key Management
6. Client Rejection of Plain HTTP Downgrade
7. Live HTTPS mTLS Handshake & Valid Request
8. Rejection of Untrusted Rogue Certificates
9. Rejection of Expired Client Certificates
10. Staged Evidence Transfer & SHA-256 Verification
11. Path Traversal Defense & Filesystem Isolation
12. Firmware Virtualization Warning (Enable Intel VT-x in BIOS/UEFI)
13. Real vs Mocked Execution Labeling Invariant
"""

import os
import json
import ssl
import shutil
import hashlib
import tempfile
import threading
from pathlib import Path
from http.server import HTTPServer
import pytest
from unittest.mock import patch, MagicMock

from backend.app.analyzers.dynamic.vbox_host_agent import (
    HostAgentConfig,
    HostControllerService,
    HostAgentHTTPHandler,
    AuthRateLimiter
)
from backend.app.analyzers.dynamic.vbox_host_client import VirtualBoxHostClient
from backend.app.analyzers.dynamic.pki_manager import pki_manager


@pytest.fixture
def temp_host_env():
    """Provides an isolated temporary directory for host agent staging, certs, and config."""
    temp_dir = Path(tempfile.mkdtemp(prefix="tracex_host_agent_test_"))
    staging_dir = temp_dir / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    certs_dir = temp_dir / "certs"
    certs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir = temp_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Generate test PKI bundle
    bundle = pki_manager.generate_full_pki_bundle(certs_dir)

    config = HostAgentConfig(
        bind_host="127.0.0.1",
        bind_port=9443,
        auth_token="tracex_hc_test_token_secret_12345",
        allowed_vm_uuids=["TraceX-Worker-Win10", "TraceX-Worker-Android"],
        allowed_snapshots=["Clean_Base", "Baseline"],
        vboxmanage_path="C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe",
        staging_root=staging_dir,
        allowed_client_subnets=["127.0.0.1/32", "192.168.56.0/24"],
        require_mtls=True,
        cert_file=str(bundle["server_cert"]),
        key_file=str(bundle["server_key"]),
        ca_file=str(bundle["ca_cert"]),
        audit_log_path=logs_dir / "test_audit.log"
    )
    service = HostControllerService(config)

    yield {
        "temp_dir": temp_dir,
        "staging_dir": staging_dir,
        "certs_dir": certs_dir,
        "logs_dir": logs_dir,
        "bundle": bundle,
        "config": config,
        "service": service
    }

    shutil.rmtree(temp_dir, ignore_errors=True)


def test_wildcard_binding_rejection():
    """Verifies that HostAgentConfig strictly rejects 0.0.0.0 or wildcard bindings."""
    with pytest.raises(ValueError, match="CRITICAL SECURITY REJECTION"):
        HostAgentConfig(bind_host="0.0.0.0")

    with pytest.raises(ValueError, match="CRITICAL SECURITY REJECTION"):
        HostAgentConfig(bind_host="")

    with pytest.raises(ValueError, match="CRITICAL SECURITY REJECTION"):
        HostAgentConfig(bind_host="::")


def test_kali_vm_removed_from_allowlist(temp_host_env):
    """Verifies that the Kali VM has been stripped from allowed worker VMs."""
    service = temp_host_env["service"]
    assert service.is_vm_allowed("TraceX-Worker-Win10") is True
    assert service.is_vm_allowed("TraceX-Worker-Android") is True
    assert service.is_vm_allowed("kali-linux-2026.1-virtualbox-amd64") is False
    assert service.is_vm_allowed("Arbitrary-VM") is False


def test_rate_limiter_blocks_brute_force():
    """Verifies that AuthRateLimiter locks out client IP after 5 consecutive failures."""
    limiter = AuthRateLimiter(max_failures=5, window_seconds=60.0, lockout_seconds=300.0)
    test_ip = "192.168.56.50"

    assert limiter.is_blocked(test_ip) is False
    for i in range(4):
        limiter.record_failure(test_ip)
        assert limiter.is_blocked(test_ip) is False

    # 5th failure triggers lockout
    locked = limiter.record_failure(test_ip)
    assert locked is True
    assert limiter.is_blocked(test_ip) is True

    # Other IPs are not locked out
    assert limiter.is_blocked("192.168.56.51") is False


def test_audit_logging(temp_host_env):
    """Verifies that security events are recorded in the audit log."""
    service = temp_host_env["service"]
    log_file = temp_host_env["config"].audit_log_path

    service.log_audit("192.168.56.10", "POST", "/api/vbox/workers/TraceX-Worker-Win10/start", "TraceX-Worker-Win10", "SUCCESS", 200, "tracex-manager-vm")
    assert log_file.exists()

    content = log_file.read_text(encoding="utf-8")
    assert "192.168.56.10" in content
    assert "TraceX-Worker-Win10" in content
    assert "tracex-manager-vm" in content
    assert "SUCCESS" in content


def test_client_refuses_plain_http_downgrade():
    """Verifies that VirtualBoxHostClient strictly forbids plain http:// unless explicitly allowed."""
    with pytest.raises(ValueError, match="SECURITY REJECTION: Plain HTTP to Host Controller Agent"):
        VirtualBoxHostClient(base_url="http://192.168.56.1:9443")


def test_live_https_mtls_valid_request(temp_host_env):
    """
    Tests live HTTPS server with mTLS authentication, verifying that:
    1. Server presents cert signed by CA
    2. Client presents cert signed by CA
    3. HMAC token is verified
    4. Successful JSON response is returned
    """
    cfg = temp_host_env["config"]
    bundle = temp_host_env["bundle"]
    service = temp_host_env["service"]
    HostAgentHTTPHandler.service = service

    # Pick a free port for test server
    test_port = 19443
    server_address = ("127.0.0.1", test_port)
    httpd = HTTPServer(server_address, HostAgentHTTPHandler)

    # Server TLS Context
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(bundle["server_cert"]), keyfile=str(bundle["server_key"]))
    ctx.load_verify_locations(cafile=str(bundle["ca_cert"]))
    ctx.verify_mode = ssl.CERT_REQUIRED
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    try:
        # Client configured with valid client cert and CA
        client = VirtualBoxHostClient(
            base_url=f"https://127.0.0.1:{test_port}",
            auth_token=cfg.auth_token,
            ca_file=str(bundle["ca_cert"]),
            client_cert=str(bundle["client_cert"]),
            client_key=str(bundle["client_key"]),
            timeout=5.0
        )

        status = client.get_status()
        assert status.get("status") == "ONLINE"
        assert status.get("protocol") == "HTTPS"
        assert status.get("mtls_enabled") is True
        assert "TraceX-Worker-Win10" in status.get("allowed_vm_uuids", [])
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_mtls_rejection_of_untrusted_client_cert(temp_host_env):
    """Verifies that a client presenting a certificate from an untrusted rogue CA is rejected."""
    bundle = temp_host_env["bundle"]
    service = temp_host_env["service"]
    HostAgentHTTPHandler.service = service

    test_port = 19444
    httpd = HTTPServer(("127.0.0.1", test_port), HostAgentHTTPHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(bundle["server_cert"]), keyfile=str(bundle["server_key"]))
    ctx.load_verify_locations(cafile=str(bundle["ca_cert"]))
    ctx.verify_mode = ssl.CERT_REQUIRED
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    try:
        # Create rogue CA and rogue client cert
        rogue_dir = temp_host_env["temp_dir"] / "rogue"
        rogue_dir.mkdir(parents=True, exist_ok=True)
        rogue_ca_cert, rogue_ca_key = pki_manager.create_ca(common_name="Rogue Evil CA")
        rogue_client_cert, rogue_client_key = pki_manager.create_client_certificate(rogue_ca_cert, rogue_ca_key)

        rogue_cert_file = rogue_dir / "rogue_client.pem"
        rogue_key_file = rogue_dir / "rogue_client.key"
        rogue_cert_file.write_text(pki_manager.serialize_cert_pem(rogue_client_cert), encoding="utf-8")
        rogue_key_file.write_text(pki_manager.serialize_key_pem(rogue_client_key), encoding="utf-8")

        # Attempt connection with rogue cert
        rogue_client = VirtualBoxHostClient(
            base_url=f"https://127.0.0.1:{test_port}",
            auth_token=temp_host_env["config"].auth_token,
            ca_file=str(bundle["ca_cert"]),
            client_cert=str(rogue_cert_file),
            client_key=str(rogue_key_file),
            timeout=5.0
        )

        resp = rogue_client.get_status()
        assert resp.get("code") in (495, 504)
        assert "failed" in resp.get("error", "").lower() or "rejected" in resp.get("error", "").lower()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_mtls_rejection_of_expired_client_cert(temp_host_env):
    """Verifies that an expired client certificate is strictly rejected during TLS handshake."""
    bundle = temp_host_env["bundle"]
    service = temp_host_env["service"]
    HostAgentHTTPHandler.service = service

    test_port = 19445
    httpd = HTTPServer(("127.0.0.1", test_port), HostAgentHTTPHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(bundle["server_cert"]), keyfile=str(bundle["server_key"]))
    ctx.load_verify_locations(cafile=str(bundle["ca_cert"]))
    ctx.verify_mode = ssl.CERT_REQUIRED
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    try:
        # Load real CA key and cert to issue an expired client cert
        ca_cert_obj = pki_manager.create_ca()[0]  # Just need builder
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        real_ca_cert = x509.load_pem_x509_certificate(bundle["ca_cert"].read_bytes())
        real_ca_key = serialization.load_pem_private_key(bundle["ca_key"].read_bytes(), password=None)

        exp_cert, exp_key = pki_manager.create_client_certificate(
            real_ca_cert, real_ca_key, common_name="tracex-manager-vm", expired=True
        )

        exp_dir = temp_host_env["temp_dir"] / "expired"
        exp_dir.mkdir(parents=True, exist_ok=True)
        exp_cert_file = exp_dir / "expired_client.pem"
        exp_key_file = exp_dir / "expired_client.key"
        exp_cert_file.write_text(pki_manager.serialize_cert_pem(exp_cert), encoding="utf-8")
        exp_key_file.write_text(pki_manager.serialize_key_pem(exp_key), encoding="utf-8")

        expired_client = VirtualBoxHostClient(
            base_url=f"https://127.0.0.1:{test_port}",
            auth_token=temp_host_env["config"].auth_token,
            ca_file=str(bundle["ca_cert"]),
            client_cert=str(exp_cert_file),
            client_key=str(exp_key_file),
            timeout=5.0
        )

        resp = expired_client.get_status()
        assert resp.get("code") in (495, 504)
        assert "failed" in resp.get("error", "").lower() or "rejected" in resp.get("error", "").lower()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_host_agent_evidence_transfer_and_hash_verification(temp_host_env):
    """Verifies that evidence transfer validates SHA-256 and stages into isolated directory."""
    service = temp_host_env["service"]

    # Harmless synthetic binary
    synthetic_payload = b"MZ\x90\x00\x03\x00\x00\x00TraceX-Synthetic-Harmless-Test-Sample-12345"
    expected_sha256 = hashlib.sha256(synthetic_payload).hexdigest()

    # 1. Valid transfer
    res = service.stage_evidence_file(
        vm_identifier="TraceX-Worker-Win10",
        filename="synthetic_test.exe",
        file_bytes=synthetic_payload,
        expected_sha256=expected_sha256
    )

    assert res.get("success") is True
    assert res.get("sha256") == expected_sha256.lower()
    assert Path(res["staged_path"]).exists()
    assert Path(res["staged_path"]).read_bytes() == synthetic_payload

    # 2. Hash mismatch rejection
    bad_res = service.stage_evidence_file(
        vm_identifier="TraceX-Worker-Win10",
        filename="tampered.exe",
        file_bytes=synthetic_payload,
        expected_sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    assert bad_res.get("code") == 400
    assert "Evidence hash mismatch" in bad_res.get("error", "")


def test_path_traversal_neutralization(temp_host_env):
    """Verifies that path traversal attacks in filenames are neutralized."""
    service = temp_host_env["service"]
    synthetic_payload = b"BENIGN_TEST_BYTES"
    sha = hashlib.sha256(synthetic_payload).hexdigest()

    res = service.stage_evidence_file(
        vm_identifier="TraceX-Worker-Win10",
        filename="../../Windows/System32/evil.exe",
        file_bytes=synthetic_payload,
        expected_sha256=sha
    )

    assert res.get("success") is True
    staged_path = Path(res["staged_path"])
    assert staged_path.name == "evil.exe"
    assert str(staged_path).startswith(str(temp_host_env["staging_dir"]))


def test_firmware_virtualization_alert_reporting(temp_host_env):
    """Verifies that if hardware virtualization is disabled, the exact action message is reported."""
    service = temp_host_env["service"]

    with patch.object(service, "get_hardware_virt_status", return_value={
        "firmware_virtualization_enabled": False,
        "action_required": "ACTION REQUIRED: Enable Intel VT-x in BIOS/UEFI."
    }):
        status = service.get_host_status()
        assert status["firmware_virtualization_enabled"] is False
        assert status["action_required"] == "ACTION REQUIRED: Enable Intel VT-x in BIOS/UEFI."


def test_synthetic_pe_and_apk_lifecycle(temp_host_env):
    """Validates staging and verification lifecycle for harmless synthetic PE and APK samples."""
    service = temp_host_env["service"]

    # Synthetic PE
    pe_bytes = b"MZ\x90\x00" + b"\x00" * 56 + b"\x80\x00\x00\x00"
    pe_sha256 = hashlib.sha256(pe_bytes).hexdigest()

    pe_stage = service.stage_evidence_file(
        vm_identifier="TraceX-Worker-Win10",
        filename="benign_sample.exe",
        file_bytes=pe_bytes,
        expected_sha256=pe_sha256
    )
    assert pe_stage["success"] is True
    assert pe_stage["sha256"] == pe_sha256

    # Synthetic APK
    apk_bytes = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"TraceX-Synthetic-Harmless-APK-Manifest-Mock"
    apk_sha256 = hashlib.sha256(apk_bytes).hexdigest()

    apk_stage = service.stage_evidence_file(
        vm_identifier="TraceX-Worker-Android",
        filename="benign_sample.apk",
        file_bytes=apk_bytes,
        expected_sha256=apk_sha256
    )
    assert apk_stage["success"] is True
    assert apk_stage["sha256"] == apk_sha256


def test_real_vs_mocked_execution_labeling():
    """Guarantees that without genuine guest execution logs, execution is NEVER marked VERIFIED."""
    from backend.app.analyzers.dynamic.sandbox_capabilities import sandbox_capabilities
    envs = sandbox_capabilities.list_environments()

    vbox_env = next((e for e in envs if e.id == "env-virtualbox-worker"), None)
    assert vbox_env is not None
    assert vbox_env.status in ("NOT_CONFIGURED", "PARTIALLY_CONFIGURED", "CONFIGURED_OFFLINE", "UNSUPPORTED_PLATFORM")
    assert vbox_env.status != "INSTALLED_AND_READY"


def test_vbox_host_client_unconfigured():
    """Verifies that VirtualBoxHostClient returns clean 503 error when not configured."""
    client = VirtualBoxHostClient(base_url="", auth_token="", allow_http_downgrade=True)
    assert client.is_configured is False
    res = client.get_status()
    assert res.get("code") == 503
    assert "not configured" in res.get("error", "").lower()
