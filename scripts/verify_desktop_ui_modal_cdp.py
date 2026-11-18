"""
CDP Browser Automation Test for Packaged TraceX Network Privacy Modal
Launches headless Chrome, navigates to the packaged backend frontend,
and tests:
1. Top-right Network Mode button click -> Opens 'NETWORK PRIVACY & CONNECTION SETTINGS' modal.
2. Modal displays LOCAL ONLY and HYBRID MODE cards with feature descriptions.
3. Clicking 'ENABLE HYBRID MODE' triggers confirmation dialog.
4. Confirming switches mode to HYBRID and header reflects 'HYBRID MODE'.
5. Switching back to 'ENABLE LOCAL ONLY' updates header immediately.
6. Saves screenshot for verification.
"""

import os
import asyncio
import json
import base64
import time
import socket
import subprocess
import tempfile
import shutil
from pathlib import Path
import websockets
import urllib.request

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = PROJECT_ROOT / "dist"
BACKEND_EXE = DIST_DIR / "TraceX" / "TraceX-Backend.exe"
CHROME_EXE = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
SCREENSHOT_DIR = PROJECT_ROOT / "reports" / "screenshots"
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)


class CDPClient:
    def __init__(self, ws_url):
        self.ws_url = ws_url
        self.ws = None
        self.msg_id = 0
        self.pending = {}

    async def connect(self):
        self.ws = await websockets.connect(self.ws_url, max_size=50 * 1024 * 1024)
        asyncio.create_task(self._listen())

    async def _listen(self):
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                if "id" in msg:
                    fut = self.pending.pop(msg["id"], None)
                    if fut and not fut.done():
                        fut.set_result(msg)
        except Exception:
            pass

    async def send(self, method: str, params: dict = None):
        self.msg_id += 1
        mid = self.msg_id
        fut = asyncio.get_event_loop().create_future()
        self.pending[mid] = fut
        await self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        res = await asyncio.wait_for(fut, timeout=15)
        return res.get("result", {})

    async def evaluate(self, expr: str):
        res = await self.send("Runtime.evaluate", {"expression": expr, "returnByValue": True, "awaitPromise": True})
        return res.get("result", {}).get("value")

    async def screenshot(self, path: Path):
        res = await self.send("Page.captureScreenshot", {"format": "png"})
        data = base64.b64decode(res["data"])
        path.write_bytes(data)
        print(f"  [+] Screenshot captured: {path}")


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def run_cdp_verification():
    print("=" * 70)
    print("CDP BROWSER AUTOMATION: NETWORK PRIVACY MODAL VERIFICATION")
    print("=" * 70)

    test_port = find_free_port()
    cdp_port = find_free_port()
    temp_data = Path(tempfile.mkdtemp(prefix="tracex_cdp_test_"))

    env = os.environ.copy()
    env["HOST"] = "127.0.0.1"
    env["PORT"] = str(test_port)
    env["FORENSICS_DATA_DIR"] = str(temp_data)
    env["WORKBENCH_DEPLOYMENT_MODE"] = "workstation"
    env.pop("TRACEX_BRIDGE_TOKEN", None)

    startupinfo = None
    creationflags = 0
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0
        creationflags = subprocess.CREATE_NO_WINDOW

    print(f"[*] Starting packaged backend on port {test_port}...")
    backend_proc = subprocess.Popen(
        [str(BACKEND_EXE), "--no-browser", "--port", str(test_port)],
        env=env,
        startupinfo=startupinfo,
        creationflags=creationflags,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE
    )

    chrome_proc = None
    try:
        # Wait for backend health
        for _ in range(30):
            time.sleep(0.5)
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{test_port}/api/health")
                with urllib.request.urlopen(req, timeout=1.0) as resp:
                    if resp.status == 200:
                        break
            except Exception:
                pass

        print(f"[*] Launching headless Chrome on CDP port {cdp_port}...")
        chrome_user_data = Path(tempfile.mkdtemp(prefix="chrome_cdp_profile_"))
        chrome_args = [
            CHROME_EXE,
            "--headless=new",
            f"--remote-debugging-port={cdp_port}",
            f"--user-data-dir={chrome_user_data}",
            "--window-size=1400,1050",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "about:blank"
        ]
        chrome_proc = subprocess.Popen(chrome_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Get WebSocket debugger URL
        ws_url = None
        for _ in range(20):
            time.sleep(0.5)
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{cdp_port}/json", timeout=1.0) as resp:
                    tabs = json.loads(resp.read().decode("utf-8"))
                    if tabs:
                        ws_url = tabs[0].get("webSocketDebuggerUrl")
                        if ws_url:
                            break
            except Exception:
                pass

        assert ws_url, "Failed to connect to Chrome CDP WebSocket"
        print(f"[*] Connected to Chrome CDP: {ws_url}")

        client = CDPClient(ws_url)
        await client.connect()
        await client.send("Page.enable")
        await client.send("Runtime.enable")
        await client.send("Network.enable")
        
        target_url = f"http://127.0.0.1:{test_port}"
        print(f"[*] Navigating to {target_url}...")
        await client.send("Page.navigate", {"url": target_url})
        await asyncio.sleep(3)

        # Wait for React app hydration
        print("[*] Waiting for frontend app hydration...")
        ready = False
        for _ in range(20):
            has_app = await client.evaluate("Boolean(document.querySelector('header') && document.body.innerText.includes('TraceX'))")
            if has_app:
                ready = True
                break
            await asyncio.sleep(0.5)

        assert ready, "Frontend React app failed to mount"
        print("  [PASS] Frontend UI mounted cleanly.")

        # Test Step 1: Find the Network Mode Header Button
        print("\n[*] Step 1: Locating top-right Network Mode button in header...")
        btn_text = await client.evaluate("""
            (() => {
                const btn = document.querySelector('header button[title*=\"Network Privacy\"]');
                return btn ? btn.innerText.replace(/\\s+/g, ' ').trim() : null;
            })()
        """)
        print(f"  [+] Current header button text: '{btn_text}'")
        assert "LOCAL ONLY" in btn_text, f"Expected button to show LOCAL ONLY, got: {btn_text}"

        # Test Step 2: Click Header Button to Open Modal
        print("\n[*] Step 2: Clicking header button to open Network Privacy modal...")
        clicked = await client.evaluate("""
            (() => {
                const btn = document.querySelector('header button[title*=\"Network Privacy\"]');
                if (btn) { btn.click(); return true; }
                return false;
            })()
        """)
        assert clicked, "Could not click Network Privacy header button"
        await asyncio.sleep(1)

        # Test Step 3: Verify Modal is Open and Displays Contents
        print("\n[*] Step 3: Verifying Modal content...")
        modal_info = await client.evaluate("""
            (() => {
                const titleEl = document.querySelector('h2');
                const hasModal = document.body.innerText.includes('NETWORK PRIVACY & CONNECTION SETTINGS');
                const hasLocalCard = document.body.innerText.includes('All forensic processing stays on the local computer.');
                const hasHybridCard = document.body.innerText.includes('Use local forensic processing together with explicitly configured online integrations.');
                const hasEnableLocalBtn = Array.from(document.querySelectorAll('button')).some(b => b.innerText.includes('ENABLE LOCAL ONLY'));
                const hasEnableHybridBtn = Array.from(document.querySelectorAll('button')).some(b => b.innerText.includes('ENABLE HYBRID MODE'));
                return {
                    hasModal,
                    hasLocalCard,
                    hasHybridCard,
                    hasEnableLocalBtn,
                    hasEnableHybridBtn
                };
            })()
        """)
        print("  [+] Modal DOM verification:", modal_info)
        assert modal_info["hasModal"], "Modal header 'NETWORK PRIVACY & CONNECTION SETTINGS' not found!"
        assert modal_info["hasLocalCard"], "LOCAL ONLY card not found!"
        assert modal_info["hasHybridCard"], "HYBRID MODE card not found!"
        assert modal_info["hasEnableHybridBtn"], "ENABLE HYBRID MODE button not found!"
        print("  [PASS] Network Privacy & Connection Settings modal rendered with both options.")

        # Capture Screenshot of Modal
        await client.screenshot(SCREENSHOT_DIR / "network_privacy_modal_open.png")

        # Test Step 4: Click ENABLE HYBRID MODE to trigger confirmation safety dialog
        print("\n[*] Step 4: Clicking 'ENABLE HYBRID MODE' to test confirmation prompt...")
        await client.evaluate("""
            (() => {
                const btns = Array.from(document.querySelectorAll('button'));
                const hybridBtn = btns.find(b => b.innerText.includes('ENABLE HYBRID MODE'));
                if (hybridBtn) hybridBtn.click();
            })()
        """)
        await asyncio.sleep(1)

        # Test Step 5: Verify Confirmation Safety Dialog
        print("\n[*] Step 5: Verifying Confirmation Safety Dialog...")
        confirm_info = await client.evaluate("""
            (() => {
                const text = document.body.innerText;
                const hasWarning = text.includes('Hybrid Mode allows configured integrations to communicate with their external service providers');
                const hasLocalGuarantee = text.includes('Original evidence files remain local unless you explicitly approve an upload');
                const hasCancel = Array.from(document.querySelectorAll('button')).some(b => b.innerText.includes('CANCEL'));
                return { hasWarning, hasLocalGuarantee, hasCancel };
            })()
        """)
        print("  [+] Confirmation prompt verification:", confirm_info)
        assert confirm_info["hasWarning"], "Confirmation warning text missing!"
        assert confirm_info["hasLocalGuarantee"], "Evidence stays local guarantee missing!"
        print("  [PASS] Confirmation dialog safety prompt verified.")

        # Capture Screenshot of Confirmation Dialog
        await client.screenshot(SCREENSHOT_DIR / "network_privacy_modal_confirmation.png")

        # Test Step 6: Confirm Enable Hybrid Mode
        print("\n[*] Step 6: Confirming HYBRID mode activation...")
        await client.evaluate("""
            (() => {
                const btns = Array.from(document.querySelectorAll('button'));
                // Click the confirm button in the dialog
                const confirmBtn = btns.filter(b => b.innerText.includes('ENABLE HYBRID MODE')).pop();
                if (confirmBtn) confirmBtn.click();
            })()
        """)
        await asyncio.sleep(1.5)

        # Test Step 7: Verify Header Button Switched to HYBRID MODE
        print("\n[*] Step 7: Verifying Header Button switched to HYBRID MODE...")
        new_btn_text = await client.evaluate("""
            (() => {
                const btn = document.querySelector('header button[title*=\"Network Privacy\"]');
                return btn ? btn.innerText.replace(/\\s+/g, ' ').trim() : null;
            })()
        """)
        print(f"  [+] New header button text: '{new_btn_text}'")
        assert "HYBRID" in new_btn_text, f"Expected button to show HYBRID, got: {new_btn_text}"
        print("  [PASS] Header button immediately updated to HYBRID MODE.")

        # Test Step 8: Reopen modal and switch back to LOCAL ONLY
        print("\n[*] Step 8: Reopening modal and returning to LOCAL ONLY...")
        await client.evaluate("""
            (() => {
                const btn = document.querySelector('header button[title*=\"Network Privacy\"]');
                if (btn) btn.click();
            })()
        """)
        await asyncio.sleep(1)

        await client.evaluate("""
            (() => {
                const btns = Array.from(document.querySelectorAll('button'));
                const localBtn = btns.find(b => b.innerText.includes('ENABLE LOCAL ONLY'));
                if (localBtn) localBtn.click();
            })()
        """)
        await asyncio.sleep(1.5)

        restored_btn_text = await client.evaluate("""
            (() => {
                const btn = document.querySelector('header button[title*=\"Network Privacy\"]');
                return btn ? btn.innerText.replace(/\\s+/g, ' ').trim() : null;
            })()
        """)
        print(f"  [+] Restored header button text: '{restored_btn_text}'")
        assert "LOCAL ONLY" in restored_btn_text, f"Expected button to show LOCAL ONLY, got: {restored_btn_text}"
        print("  [PASS] Returned to LOCAL ONLY mode immediately without unnecessary prompts.")

        print("\n" + "=" * 70)
        print("CDP BROWSER AUTOMATION: ALL MODAL & BUTTON TESTS PASSED (100% SUCCESS)")
        print("=" * 70)

    finally:
        if chrome_proc and chrome_proc.poll() is None:
            chrome_proc.kill()
        if backend_proc and backend_proc.poll() is None:
            backend_proc.kill()
        shutil.rmtree(temp_data, ignore_errors=True)
        if 'chrome_user_data' in locals():
            shutil.rmtree(chrome_user_data, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(run_cdp_verification())
