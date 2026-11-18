import os
import sys
import time
import zipfile
import shutil
import tempfile
import urllib.request
import json
import subprocess
from pathlib import Path

def run_clean_test():
    test_dir = Path(tempfile.gettempdir()) / "clean_portable_test"
    if test_dir.exists():
        shutil.rmtree(test_dir, ignore_errors=True)
    test_dir.mkdir(parents=True, exist_ok=True)

    zip_path = Path("dist/ForensicsWorkbench-Portable.zip").resolve()
    print(f"[*] Extracting {zip_path.name} to temporary test directory...")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(test_dir)

    exe_path = test_dir / "ForensicsWorkbench.exe"
    assert exe_path.exists(), f"Executable not found at {exe_path}"

    # Pre-launch check: verify clean data directory
    data_dir = test_dir / "data"
    assert not (data_dir / "workbench.db").exists(), "Historical workbench.db found in package!"
    assert not (data_dir / ".master.key").exists(), "Master key found in package!"
    print("[+] Pre-launch Check: Zero historical database, cases, or credentials exist.")

    # Launch the portable executable in isolated environment on port 8990
    port = 8990
    print(f"[*] Launching ForensicsWorkbench.exe on port {port}...")
    proc = subprocess.Popen(
        [str(exe_path), "--headless", "--port", str(port)],
        cwd=str(test_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    )

    try:
        # Wait for health
        healthy = False
        for i in range(30):
            time.sleep(1)
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{port}/api/health")
                with urllib.request.urlopen(req, timeout=2) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        if data.get("status") == "healthy":
                            healthy = True
                            print(f"[+] Application healthy after {i+1}s!")
                            break
            except Exception:
                pass

        assert healthy, "Application failed to start or reach healthy status within 30s"

        # 1. Verify unauthenticated access returns HTTP 401
        try:
            req_unauth = urllib.request.Request(f"http://127.0.0.1:{port}/api/credentials/providers")
            urllib.request.urlopen(req_unauth, timeout=2)
            assert False, "Unauthenticated request to /api/credentials/providers should have failed with HTTP 401"
        except urllib.error.HTTPError as e:
            assert e.code == 401, f"Expected HTTP 401, got {e.code}"
            print("[+] Verified unauthenticated request strictly rejected with HTTP 401")

        # 2. Verify Initial Administrator Setup is Required
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/auth/setup-status")
        with urllib.request.urlopen(req, timeout=2) as resp:
            setup_status = json.loads(resp.read().decode("utf-8"))
            print(f"[*] Clean setup status: setup_required={setup_status.get('setup_required')}, mode={setup_status.get('deployment_mode')}")
            assert setup_status.get("setup_required") is True, "Clean installation must require initial setup"
            assert setup_status.get("deployment_mode") == "workstation"

        # 3. Perform Initial Setup
        setup_payload = json.dumps({
            "username": "portable_admin",
            "password": "PortableAdminPass2026!#$",
            "email": "portable@forensics.local"
        }).encode("utf-8")
        setup_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/auth/initial-setup",
            data=setup_payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(setup_req, timeout=3) as resp:
            setup_data = json.loads(resp.read().decode("utf-8"))
            token = setup_data.get("token")
            csrf_token = setup_data.get("csrf_token")
            assert token, "Session token missing from initial-setup response"
            print(f"[+] Initial Administrator provisioned: {setup_data.get('user', {}).get('username')}")

        auth_headers = {
            "Authorization": f"Bearer {token}",
            "x-csrf-token": csrf_token,
            "Content-Type": "application/json"
        }

        # 4. Verify setup endpoint is now permanently locked
        try:
            lock_req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/auth/initial-setup",
                data=setup_payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            urllib.request.urlopen(lock_req, timeout=2)
            assert False, "Subsequent setup request should have returned HTTP 403"
        except urllib.error.HTTPError as e:
            assert e.code == 403
            print("[+] Verified initial-setup endpoint locked after provisioning (HTTP 403)")

        # 5. Verify dashboard stats: total_investigations MUST BE 0
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/dashboard/stats", headers=auth_headers)
        with urllib.request.urlopen(req, timeout=2) as resp:
            stats = json.loads(resp.read().decode("utf-8"))
            tot = stats.get("total_investigations")
            print(f"[*] Clean Dashboard stats: total_investigations = {tot}")
            assert tot == 0, f"Expected 0 investigations in clean installation, got {tot}"

        # 6. Verify credentials catalog initially shows NOT CONFIGURED
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/credentials/providers", headers=auth_headers)
        with urllib.request.urlopen(req, timeout=2) as resp:
            providers = json.loads(resp.read().decode("utf-8"))
            configured_count = sum(1 for p in providers if p.get("is_configured"))
            print(f"[*] Configured providers in clean installation: {configured_count} (out of {len(providers)})")
            assert configured_count == 0, "Found pre-configured credentials in clean installation!"

        # 7. Verify Master Key Status
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/credentials/master-key/status", headers=auth_headers)
        with urllib.request.urlopen(req, timeout=2) as resp:
            key_status = json.loads(resp.read().decode("utf-8"))
            print(f"[*] Master key status: {key_status.get('status')}, source: {key_status.get('key_source')}")
            assert key_status.get("status") == "active"
            assert key_status.get("key_source") == "secure_local_store"

        # 8. Verify AI Providers endpoint
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/opencode/providers", headers=auth_headers)
        with urllib.request.urlopen(req, timeout=2) as resp:
            ai_providers = json.loads(resp.read().decode("utf-8"))
            print(f"[*] AI Providers available: {len(ai_providers)}")
            p_ids = [p["id"] for p in ai_providers]
            assert "opencode" in p_ids
            assert "openai" in p_ids
            assert "anthropic" in p_ids
            assert "gemini" in p_ids
            assert "groq" in p_ids

        # 9. Save a user BYOK API key and verify encryption
        save_payload = json.dumps({"data": {"api_key": "sk-proj-testbyokcleaninstallationkey998877"}}).encode("utf-8")
        save_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/credentials/openai",
            data=save_payload,
            headers=auth_headers,
            method="POST"
        )
        with urllib.request.urlopen(save_req, timeout=2) as resp:
            save_resp = json.loads(resp.read().decode("utf-8"))
            print(f"[*] Saved BYOK key status: {save_resp.get('status')}")
            assert save_resp.get("status") == "success"

        # Verify provider now reports is_configured = True with masked key
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/credentials/openai", headers=auth_headers)
        with urllib.request.urlopen(req, timeout=2) as resp:
            openai_p = json.loads(resp.read().decode("utf-8"))
            assert openai_p["is_configured"] is True
            assert "masked_values" in openai_p
            masked = openai_p["masked_values"].get("api_key", "")
            print(f"[+] Masked key reported: {masked}")
            assert "8877" in masked
            assert "sk-proj-testbyok" not in masked

        # 5. Verify local .master.key was generated in isolated data/ directory
        assert (data_dir / ".master.key").exists(), "Master key was not created in clean data directory!"
        assert (data_dir / "workbench.db").exists(), "workbench.db was not initialized!"
        print(f"[+] Isolated Master Key created: {(data_dir / '.master.key').stat().st_size} bytes")
        print(f"[+] Isolated Database created: {(data_dir / 'workbench.db').stat().st_size} bytes")

        print("\n==============================================================================")
        print("    CLEAN PORTABLE APPLICATION ACCEPTANCE TEST: 100% VERIFIED AND PASSED!")
        print("==============================================================================")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        time.sleep(1)
        shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == "__main__":
    run_clean_test()
