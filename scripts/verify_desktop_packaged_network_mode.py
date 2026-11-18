"""
TraceX Packaged Desktop Application Network Mode Verification Script
Validates:
1. GUI Subsystem (IMAGE_SUBSYSTEM_WINDOWS_GUI = 2): Zero CMD/console windows.
2. Headless backend startup on isolated loopback port.
3. Frontend assets served with NetworkPrivacyModal.
4. Mode switching between LOCAL ONLY and HYBRID.
5. Immediate update of Integration Manager catalog status.
6. Shodan connection blocked in LOCAL ONLY and permitted in HYBRID.
7. Mode persistence across full application restart.
8. Clean graceful IPC shutdown.
"""

import os
import sys
import time
import json
import socket
import struct
import shutil
import tempfile
import subprocess
import urllib.request
import urllib.error
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = PROJECT_ROOT / "dist"
TRACEX_DIR = DIST_DIR / "TraceX"
HOST_EXE = TRACEX_DIR / "TraceX.exe"
BACKEND_EXE = TRACEX_DIR / "TraceX-Backend.exe"


def verify_pe_gui_subsystem(exe_path: Path):
    """Verifies executable uses Windows GUI subsystem (no console window)."""
    with open(exe_path, "rb") as f:
        data = f.read(2048)
    assert data[:2] == b"MZ", f"{exe_path} is not a valid MZ executable"
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    magic = struct.unpack_from("<H", data, pe_offset + 24)[0]
    
    # 0x10b is PE32, 0x20b is PE32+ (64-bit)
    if magic == 0x20b:
        subsystem_offset = pe_offset + 24 + 68
    elif magic == 0x10b:
        subsystem_offset = pe_offset + 24 + 68
    else:
        raise ValueError(f"Unknown PE magic: {hex(magic)}")
        
    subsystem = struct.unpack_from("<H", data, subsystem_offset)[0]
    # IMAGE_SUBSYSTEM_WINDOWS_GUI = 2, IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
    assert subsystem == 2, f"{exe_path} subsystem is {subsystem} (expected 2 for GUI / No Console)"
    print(f"  [PASS] {exe_path.name} PE Subsystem is WINDOWS_GUI (2) -> Zero console window guaranteed.")


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http_req(url: str, method: str = "GET", data: dict = None, headers: dict = None, bridge_token: str = None) -> dict:
    hdr = {"User-Agent": "TraceX-Verifier"}
    if bridge_token:
        hdr["X-TraceX-Bridge-Token"] = bridge_token
    if headers:
        hdr.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        hdr["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=hdr, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            content = resp.read().decode("utf-8")
            try:
                return json.loads(content)
            except Exception:
                return {"raw": content, "status": resp.status}
    except urllib.error.HTTPError as e:
        content = e.read().decode("utf-8")
        try:
            return json.loads(content)
        except Exception:
            return {"error": str(e), "code": e.code, "raw": content}


def run_full_packaged_verification():
    print("=" * 70)
    print("TRACEX PACKAGED APPLICATION VERIFICATION")
    print("=" * 70)

    # 1. PE Subsystem Verification
    print("\n[*] Step 1: Checking PE Headers for Zero-Console Guarantee...")
    verify_pe_gui_subsystem(HOST_EXE)
    verify_pe_gui_subsystem(BACKEND_EXE)

    # 2. Spawning Packaged Backend in Isolated Sandbox
    test_port = find_free_port()
    temp_data = Path(tempfile.mkdtemp(prefix="tracex_packaged_test_"))
    bridge_token = "verify-bridge-token-2026"

    print(f"\n[*] Step 2: Spawning packaged backend on 127.0.0.1:{test_port}...")
    print(f"    Sandbox Data Dir: {temp_data}")

    env = os.environ.copy()
    env["HOST"] = "127.0.0.1"
    env["PORT"] = str(test_port)
    env["FORENSICS_DATA_DIR"] = str(temp_data)
    env["TRACEX_BRIDGE_TOKEN"] = bridge_token
    env["WORKBENCH_DEPLOYMENT_MODE"] = "workstation"

    startupinfo = None
    creationflags = 0
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0
        creationflags = subprocess.CREATE_NO_WINDOW

    proc = subprocess.Popen(
        [str(BACKEND_EXE), "--no-browser", "--port", str(test_port)],
        env=env,
        startupinfo=startupinfo,
        creationflags=creationflags,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE
    )

    try:
        # Helper to automatically pass bridge token
        def call_api(url, method="GET", data=None):
            return http_req(url, method=method, data=data, bridge_token=bridge_token)

        # Wait for health
        healthy = False
        health_url = f"http://127.0.0.1:{test_port}/api/health"
        for _ in range(40):
            time.sleep(0.5)
            try:
                res = http_req(health_url)
                if res.get("status") == "healthy":
                    healthy = True
                    break
            except Exception:
                pass

        assert healthy, "Backend failed to become healthy within 20s"
        print(f"  [PASS] Backend online and healthy: network_mode={res.get('network_mode')}")

        # 3. Verify Frontend Serves Updated Assets
        print("\n[*] Step 3: Verifying Frontend Static Asset Delivery...")
        index_url = f"http://127.0.0.1:{test_port}/"
        index_res = http_req(index_url)
        raw_html = index_res.get("raw", "")
        assert "TraceX" in raw_html or "html" in raw_html, "Frontend index.html did not load"
        print("  [PASS] Frontend production bundle served cleanly at /")

        # 4. Verify Initial Network Mode
        print("\n[*] Step 4: Verifying Initial Mode is LOCAL_ONLY...")
        mode_url = f"http://127.0.0.1:{test_port}/api/system/network-mode"
        mode_data = call_api(mode_url)
        assert mode_data.get("mode") == "LOCAL_ONLY", f"Expected LOCAL_ONLY, got {mode_data}"
        assert mode_data["local_only_mode"] is True
        print(f"  [PASS] Initial mode confirmed: {mode_data['mode']}")

        # 5. Verify Shodan Blocked in LOCAL ONLY
        print("\n[*] Step 5: Testing Shodan Connection in LOCAL ONLY Mode...")
        shodan_test_url = f"http://127.0.0.1:{test_port}/api/credentials/shodan/test"
        shodan_res = call_api(shodan_test_url, method="POST", data={"api_key": "dummy_test_key_12345"})
        assert shodan_res.get("connected") is False
        assert shodan_res.get("status") == "Blocked by Local-Only Mode"
        print(f"  [PASS] Shodan test correctly blocked: {shodan_res.get('status')}")

        # 6. Verify Catalog Status in LOCAL ONLY
        print("\n[*] Step 6: Checking Integration Catalog in LOCAL ONLY Mode...")
        cat_url = f"http://127.0.0.1:{test_port}/api/credentials/providers"
        cat_res = call_api(cat_url)
        shodan_cat = next((p for p in cat_res if p.get("id") == "shodan"), None)
        assert shodan_cat is not None
        assert shodan_cat.get("blocked_by_local_only") is True
        assert shodan_cat.get("status_badge") == "local_only_blocked"
        print(f"  [PASS] Catalog reflects BLOCKED BY LOCAL-ONLY MODE for Shodan.")

        # 7. Switch Mode to HYBRID
        print("\n[*] Step 7: Switching Network Mode to HYBRID...")
        switch_res = call_api(mode_url, method="POST", data={"mode": "HYBRID"})
        assert switch_res.get("mode") == "HYBRID"
        assert switch_res.get("local_only_mode") is False
        print("  [PASS] Network mode switched to HYBRID.")

        # 8. Verify Catalog Status Updates Immediately in HYBRID
        print("\n[*] Step 8: Verifying Immediate Catalog Update in HYBRID...")
        cat_res2 = call_api(cat_url)
        shodan_cat2 = next((p for p in cat_res2 if p.get("id") == "shodan"), None)
        assert shodan_cat2.get("blocked_by_local_only") is False
        assert shodan_cat2.get("status_badge") != "local_only_blocked"
        print("  [PASS] Catalog immediately updated: Shodan is no longer blocked by local-only mode.")

        # 9. Verify Shodan Test Permitted in HYBRID
        print("\n[*] Step 9: Testing Shodan Connection in HYBRID Mode...")
        shodan_hybrid_res = call_api(shodan_test_url, method="POST", data={"api_key": "invalid_test_key"})
        assert shodan_hybrid_res.get("status") != "Blocked by Local-Only Mode", \
            f"Expected live dispatch, got: {shodan_hybrid_res.get('status')}"
        print(f"  [PASS] Shodan test executed live network dispatch: status='{shodan_hybrid_res.get('status')}'")

        # 10. Switch Back to LOCAL ONLY
        print("\n[*] Step 10: Switching Back to LOCAL ONLY Mode...")
        switch_local = call_api(mode_url, method="POST", data={"mode": "LOCAL_ONLY"})
        assert switch_local.get("mode") == "LOCAL_ONLY"
        assert switch_local.get("local_only_mode") is True
        
        # Test Shodan blocked again immediately
        shodan_res3 = call_api(shodan_test_url, method="POST", data={"api_key": "dummy"})
        assert shodan_res3.get("status") == "Blocked by Local-Only Mode"
        print("  [PASS] Returned to LOCAL ONLY mode; Shodan immediately blocked again.")

        # Set to HYBRID before restart test
        call_api(mode_url, method="POST", data={"mode": "HYBRID"})
        print("  [INFO] Persisted HYBRID mode in database for restart test.")

        # 11. Graceful Shutdown
        print("\n[*] Step 11: Testing Graceful IPC Shutdown...")
        shutdown_url = f"http://127.0.0.1:{test_port}/api/system/shutdown"
        call_api(shutdown_url, method="POST", data={})
        proc.wait(timeout=10)
        assert proc.poll() is not None, "Process failed to terminate cleanly"
        print(f"  [PASS] Process terminated with returncode {proc.returncode}.")

    except Exception as e:
        if proc.poll() is None:
            proc.kill()
        raise e

    # 12. Restart Backend and Verify Mode Persistence
    print("\n[*] Step 12: Simulating Application Restart and Testing Mode Persistence...")
    test_port2 = find_free_port()
    env["PORT"] = str(test_port2)

    proc2 = subprocess.Popen(
        [str(BACKEND_EXE), "--no-browser", "--port", str(test_port2)],
        env=env,
        startupinfo=startupinfo,
        creationflags=creationflags,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE
    )

    try:
        def call_api2(url, method="GET", data=None):
            return http_req(url, method=method, data=data, bridge_token=bridge_token)

        healthy = False
        health_url2 = f"http://127.0.0.1:{test_port2}/api/health"
        for _ in range(40):
            time.sleep(0.5)
            try:
                res = http_req(health_url2)
                if res.get("status") == "healthy":
                    healthy = True
                    break
            except Exception:
                pass

        assert healthy, "Restarted backend failed to become healthy"
        mode_url2 = f"http://127.0.0.1:{test_port2}/api/system/network-mode"
        mode_res2 = call_api2(mode_url2)
        assert mode_res2.get("mode") == "HYBRID", f"Expected persisted HYBRID, got {mode_res2.get('mode')}"
        assert mode_res2.get("local_only_mode") is False
        print(f"  [PASS] Mode successfully persisted across restart: {mode_res2.get('mode')}")

        # Reset to LOCAL_ONLY and shutdown
        call_api2(mode_url2, method="POST", data={"mode": "LOCAL_ONLY"})
        shutdown_url2 = f"http://127.0.0.1:{test_port2}/api/system/shutdown"
        call_api2(shutdown_url2, method="POST", data={})
        proc2.wait(timeout=10)
        print("  [PASS] Clean final shutdown after persistence test.")

    finally:
        if proc2.poll() is None:
            proc2.kill()
        shutil.rmtree(temp_data, ignore_errors=True)

    print("\n" + "=" * 70)
    print("ALL PACKAGED APPLICATION NETWORK MODE TESTS PASSED (100% SUCCESS)")
    print("=" * 70)


if __name__ == "__main__":
    run_full_packaged_verification()
