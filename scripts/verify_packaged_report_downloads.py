"""
TraceX Packaged Application End-to-End Download & Filesystem Verification Script
Universal Digital Forensics & Cyber Investigation Suite v2.0.0

Tests:
1. Spawns packaged TraceX-Backend.exe in isolated subprocess.
2. Authenticates using ephemeral desktop bridge token.
3. Requests on-disk report compilation for PDF, HTML, TXT, JSON, and ZIP Bundle.
4. Verifies actual filesystem existence in %USERPROFILE%\\Documents\\TraceX\\Reports\\<ID>\\
5. Validates non-zero byte size on real Windows storage.
6. Verifies PDF document parsing with PyMuPDF.
7. Confirms saved report listing endpoint returns all generated files.
8. Tests path traversal security protections.
9. Simulates restart and confirms reports persist across sessions.
"""

import os
import sys
import json
import time
import struct
import shutil
import urllib.request
import urllib.error
import subprocess
from pathlib import Path

# PyMuPDF
import fitz

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = PROJECT_ROOT / "dist"
TRACEX_DIR = DIST_DIR / "TraceX"
BACKEND_EXE = TRACEX_DIR / "TraceX-Backend.exe"
HOST_EXE = TRACEX_DIR / "TraceX.exe"

USER_PROFILE = os.environ.get("USERPROFILE") or str(Path.home())
REPORTS_ROOT = Path(USER_PROFILE) / "Documents" / "TraceX" / "Reports"

def main():
    print("=" * 72)
    print("TRACEX PACKAGED APPLICATION REPORT DOWNLOAD & FILESYSTEM VERIFICATION")
    print("=" * 72)
    print(f"[*] Packaged Backend : {BACKEND_EXE}")
    print(f"[*] Reports Root     : {REPORTS_ROOT}")

    assert BACKEND_EXE.exists(), f"Backend executable not found at {BACKEND_EXE}"
    assert HOST_EXE.exists(), f"Host executable not found at {HOST_EXE}"

    # Step 1: Start packaged backend on test port
    test_port = 54890
    bridge_token = "tracex-verify-token-xyz123"
    env = os.environ.copy()
    env["TRACEX_BRIDGE_TOKEN"] = bridge_token
    env["DB_PATH"] = "analysis_workspace/workbench.db"

    creationflags = 0x08000000 # CREATE_NO_WINDOW
    proc = subprocess.Popen(
        [str(BACKEND_EXE), "--port", str(test_port), "--no-browser"],
        env=env,
        creationflags=creationflags
    )

    try:
        # Wait for backend health
        print(f"[*] Waiting for packaged backend on port {test_port}...")
        healthy = False
        health_url = f"http://127.0.0.1:{test_port}/api/health"
        for _ in range(40):
            try:
                with urllib.request.urlopen(health_url, timeout=1.0) as resp:
                    if resp.status == 200:
                        healthy = True
                        break
            except Exception:
                time.sleep(0.5)

        assert healthy, "Packaged backend failed to come online."
        print("[PASS] Packaged backend online and healthy.")

        # Common headers
        headers = {
            "Content-Type": "application/json",
            "Origin": f"http://127.0.0.1:{test_port}",
            "X-TraceX-Bridge-Token": bridge_token
        }

        # Step 2: Fetch available investigations
        inv_url = f"http://127.0.0.1:{test_port}/api/investigations"
        req = urllib.request.Request(inv_url, headers=headers)
        with urllib.request.urlopen(req) as resp:
            invs = json.loads(resp.read().decode("utf-8"))

        assert len(invs) > 0, "No investigations found in database."
        target_inv_id = invs[0]["id"]
        print(f"[+] Using target investigation for download test: {target_inv_id}")

        inv_reports_dir = REPORTS_ROOT / target_inv_id
        inv_reports_dir.mkdir(parents=True, exist_ok=True)

        # Step 3: Test PDF Report Download & Disk Save
        print("\n[*] Testing PDF Report Compilation & Disk Save...")
        save_url = f"http://127.0.0.1:{test_port}/api/investigations/{target_inv_id}/report/save"
        pdf_payload = json.dumps({"format": "pdf", "overwrite": True}).encode("utf-8")
        req_pdf = urllib.request.Request(save_url, data=pdf_payload, headers=headers)
        with urllib.request.urlopen(req_pdf) as resp:
            pdf_data = json.loads(resp.read().decode("utf-8"))

        assert pdf_data["status"] == "success", f"PDF save failed: {pdf_data}"
        pdf_path = Path(pdf_data["filepath"])
        print(f"    Saved PDF Path : {pdf_path}")
        print(f"    Saved PDF Size : {pdf_data['file_size_formatted']} ({pdf_data['file_size']} bytes)")

        assert pdf_path.exists(), f"PDF does not exist on disk at {pdf_path}"
        assert pdf_path.stat().st_size > 0, "PDF size on disk is 0 bytes"
        assert pdf_path.stat().st_size == pdf_data["file_size"], "Filesize mismatch"

        # PyMuPDF Verification
        doc = fitz.open(str(pdf_path))
        page_count = len(doc)
        print(f"    [PyMuPDF] Valid PDF with {page_count} pages.")
        assert page_count >= 1, "PDF has 0 pages"
        p1_text = doc[0].get_text()
        assert "TRACEX" in p1_text.upper() or "DIGITAL FORENSICS" in p1_text.upper()
        doc.close()
        print("[PASS] PDF Report verified on real Windows filesystem.")

        # Step 4: Test HTML Report Download & Disk Save
        print("\n[*] Testing HTML Report Compilation & Disk Save...")
        html_payload = json.dumps({"format": "html", "overwrite": True}).encode("utf-8")
        req_html = urllib.request.Request(save_url, data=html_payload, headers=headers)
        with urllib.request.urlopen(req_html) as resp:
            html_data = json.loads(resp.read().decode("utf-8"))

        html_path = Path(html_data["filepath"])
        print(f"    Saved HTML Path: {html_path}")
        print(f"    Saved HTML Size: {html_data['file_size_formatted']} ({html_data['file_size']} bytes)")
        assert html_path.exists()
        assert html_path.stat().st_size > 0
        html_content = html_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html_content or "<html" in html_content
        print("[PASS] HTML Report verified on real Windows filesystem.")

        # Step 5: Test JSON Evidence Export & Disk Save
        print("\n[*] Testing JSON Evidence Export & Disk Save...")
        json_payload = json.dumps({"format": "json", "overwrite": True}).encode("utf-8")
        req_json = urllib.request.Request(save_url, data=json_payload, headers=headers)
        with urllib.request.urlopen(req_json) as resp:
            j_data = json.loads(resp.read().decode("utf-8"))

        j_path = Path(j_data["filepath"])
        print(f"    Saved JSON Path: {j_path}")
        print(f"    Saved JSON Size: {j_data['file_size_formatted']} ({j_data['file_size']} bytes)")
        assert j_path.exists()
        assert j_path.stat().st_size > 0
        parsed_json = json.loads(j_path.read_text(encoding="utf-8"))
        assert "record" in parsed_json
        print("[PASS] JSON Report verified on real Windows filesystem.")

        # Step 6: Test TXT and ZIP Bundle
        print("\n[*] Testing TXT Report & ZIP Bundle Exports...")
        txt_payload = json.dumps({"format": "txt", "overwrite": True}).encode("utf-8")
        req_txt = urllib.request.Request(save_url, data=txt_payload, headers=headers)
        with urllib.request.urlopen(req_txt) as resp:
            t_data = json.loads(resp.read().decode("utf-8"))
        assert Path(t_data["filepath"]).stat().st_size > 0
        print(f"    Saved TXT Size : {t_data['file_size_formatted']}")

        bundle_payload = json.dumps({"format": "bundle", "overwrite": True}).encode("utf-8")
        req_bundle = urllib.request.Request(save_url, data=bundle_payload, headers=headers)
        with urllib.request.urlopen(req_bundle) as resp:
            b_data = json.loads(resp.read().decode("utf-8"))
        assert Path(b_data["filepath"]).stat().st_size > 0
        print(f"    Saved ZIP Size : {b_data['file_size_formatted']}")
        print("[PASS] TXT and ZIP Bundle reports verified on real Windows filesystem.")

        # Step 7: Test Saved Files Listing API
        print("\n[*] Testing Saved Files Listing API...")
        list_url = f"http://127.0.0.1:{test_port}/api/investigations/{target_inv_id}/report/saved-files"
        req_list = urllib.request.Request(list_url, headers=headers)
        with urllib.request.urlopen(req_list) as resp:
            saved_list = json.loads(resp.read().decode("utf-8"))

        print(f"    Retrieved {len(saved_list)} saved report files from backend.")
        assert len(saved_list) >= 4
        formats_found = {f["format"] for f in saved_list}
        assert "pdf" in formats_found
        assert "html" in formats_found
        assert "json" in formats_found
        print("[PASS] Saved reports listing endpoint verified.")

        # Step 8: Test Path Traversal Security
        print("\n[*] Testing Path Traversal Protection...")
        open_url = f"http://127.0.0.1:{test_port}/api/reports/open-file"
        traversal_payload = json.dumps({"filepath": "C:\\Windows\\System32\\cmd.exe"}).encode("utf-8")
        req_trav = urllib.request.Request(open_url, data=traversal_payload, headers=headers)
        try:
            with urllib.request.urlopen(req_trav) as resp:
                assert False, "Path traversal should have been rejected with 403"
        except urllib.error.HTTPError as e:
            assert e.code == 403, f"Expected 403 Forbidden, got {e.code}"
            print(f"    Path traversal correctly blocked: {e.code} Forbidden.")
        print("[PASS] Path traversal protection verified.")

    finally:
        # Terminate packaged backend
        proc.kill()
        proc.wait()

    # Step 9: Verify persistence across simulated application restart
    print("\n[*] Verifying Reports Persistence Across Application Restarts...")
    persisted_files = list(inv_reports_dir.iterdir())
    assert len(persisted_files) >= 4, "Reports did not persist on disk after backend shutdown!"
    for pf in persisted_files:
        assert pf.stat().st_size > 0, f"Persisted file {pf.name} is empty!"
        print(f"    [PERSISTED] {pf.name} ({pf.stat().st_size} bytes)")
    print("[PASS] All reports safely persisted in %USERPROFILE%\\Documents\\TraceX\\Reports.")

    print("\n" + "=" * 72)
    print("ALL PACKAGED DOWNLOAD & FILESYSTEM VERIFICATION CHECKS PASSED (100% SUCCESS)")
    print("=" * 72)

if __name__ == "__main__":
    main()
