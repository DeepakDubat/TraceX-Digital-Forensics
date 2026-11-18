import asyncio
import json
import base64
import time
import subprocess
import urllib.request
import sqlite3
from pathlib import Path
import websockets

CHROME_EXE = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
SCREENSHOTS_DIR = Path("reports/screenshots/startup_validation")
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path("analysis_workspace/workbench.db")

class CDPClient:
    def __init__(self, ws_url):
        self.ws_url = ws_url
        self.ws = None
        self.msg_id = 0
        self.pending = {}
        self.console_logs = []
        self.failed_requests = []
        self.api_requests = []

    async def connect(self):
        self.ws = await websockets.connect(self.ws_url, max_size=50*1024*1024)
        asyncio.create_task(self._listen())

    async def _listen(self):
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                if "id" in msg:
                    fut = self.pending.pop(msg["id"], None)
                    if fut and not fut.done():
                        fut.set_result(msg)
                else:
                    method = msg.get("method", "")
                    params = msg.get("params", {})
                    if method == "Runtime.consoleAPICalled":
                        text = " ".join([arg.get("value", "") if isinstance(arg.get("value"), str) else json.dumps(arg.get("value", "")) for arg in params.get("args", [])])
                        log_type = params.get('type', 'log').upper()
                        self.console_logs.append(f"[{log_type}] {text}")
                    elif method == "Network.requestWillBeSent":
                        req = params.get("request", {})
                        url = req.get("url", "")
                        if "/api/" in url:
                            self.api_requests.append((url, req.get("method", "GET")))
                    elif method == "Network.responseReceived":
                        resp = params.get("response", {})
                        status = resp.get("status", 0)
                        url = resp.get("url", "")
                        if status >= 400:
                            self.failed_requests.append((url, status))
        except Exception:
            pass

    async def send(self, method, params=None):
        self.msg_id += 1
        curr_id = self.msg_id
        fut = asyncio.get_event_loop().create_future()
        self.pending[curr_id] = fut
        payload = {"id": curr_id, "method": method, "params": params or {}}
        await self.ws.send(json.dumps(payload))
        res = await asyncio.wait_for(fut, timeout=25.0)
        return res.get("result", {})

    async def evaluate(self, expr):
        res = await self.send("Runtime.evaluate", {"expression": expr, "returnByValue": True, "awaitPromise": True})
        return res.get("result", {}).get("value")

    async def screenshot(self, file_path):
        res = await self.send("Page.captureScreenshot", {"format": "png"})
        data = base64.b64decode(res["data"])
        with open(file_path, "wb") as f:
            f.write(data)
        print(f"  [+] Screenshot saved: {file_path}")

async def run_full_application_lifecycle():
    print("=" * 70)
    print("EXECUTING APPLICATION LIFECYCLE & STARTUP PERSISTENCE VALIDATION")
    print("=" * 70)

    # 1. Database Integrity Verification
    print("\n[1] Verifying SQLite Database Integrity & Preserved Investigations...")
    assert DB_PATH.exists(), f"Database not found at {DB_PATH}"
    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()
    cur.execute("PRAGMA integrity_check;")
    integrity = cur.fetchone()[0]
    assert integrity.lower() == "ok", f"Integrity check failed: {integrity}"

    cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table';")
    table_count = cur.fetchone()[0]

    cur.execute("SELECT count(*) FROM investigations;")
    investigations_count = cur.fetchone()[0]

    cur.execute("SELECT count(*) FROM evidence_items;")
    evidence_count = cur.fetchone()[0]

    cur.execute("PRAGMA journal_mode;")
    journal_mode = cur.fetchone()[0]
    conn.close()

    print(f"    - Database Path        : {DB_PATH}")
    print(f"    - PRAGMA integrity     : {integrity}")
    print(f"    - Journal Mode         : {journal_mode.upper()}")
    print(f"    - Table Count          : {table_count}")
    print(f"    - Investigations Stored: {investigations_count}")
    print(f"    - Evidence Records     : {evidence_count}")
    assert investigations_count > 0, "Investigations count should not be zero!"
    assert table_count >= 30, f"Expected >= 30 tables, got {table_count}"

    # 2. Chrome Headless CDP Browser Session
    print("\n[2] Launching Google Chrome for Live User Interaction Testing...")
    profile_dir = Path(tempfile.gettempdir()) / "chrome_startup_validation"
    profile_dir.mkdir(parents=True, exist_ok=True)
    chrome_proc = subprocess.Popen([
        CHROME_EXE,
        "--headless=new",
        "--remote-debugging-port=9222",
        f"--user-data-dir={profile_dir}",
        "--window-size=1400,1050",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "about:blank"
    ])

    await asyncio.sleep(2)

    try:
        with urllib.request.urlopen("http://127.0.0.1:9222/json") as resp:
            tabs = json.loads(resp.read().decode())
        ws_url = tabs[0]["webSocketDebuggerUrl"]

        client = CDPClient(ws_url)
        await client.connect()

        await client.send("Page.enable")
        await client.send("DOM.enable")
        await client.send("Runtime.enable")
        await client.send("Network.enable")

        # Test A: Reverse Proxy URL (Original Bug URL)
        proxy_url = "http://127.0.0.1:9000/http://127.0.0.1:8000/"
        print(f"\n[3] Testing Original Reverse Proxy URL: {proxy_url} ...")
        await client.send("Page.navigate", {"url": proxy_url})
        await asyncio.sleep(3)

        title = await client.evaluate("document.title")
        print(f"    - Document Title: {title}")

        # Verify Overview Dashboard
        print("\n[4] Verifying Overview Dashboard...")
        dashboard_check = await client.evaluate("""
            (() => {
                const text = document.body.innerText;
                const hasStats = text.includes('TOTAL INVESTIGATIONS') || text.includes('CONFIRMED C2') || text.includes('Overview Dashboard');
                return {
                    rendered: hasStats,
                    textSnippet: text.slice(0, 150)
                };
            })()
        """)
        print(f"    - Dashboard Render Status: {dashboard_check['rendered']}")
        print(f"    - Dashboard Text Snippet: {dashboard_check['textSnippet']}")
        assert dashboard_check["rendered"] is True, "Overview Dashboard failed to render!"
        await client.screenshot(str(SCREENSHOTS_DIR / "01_overview_dashboard.png"))

        # Verify New Investigation Page
        print("\n[5] Navigating to 'New Investigation'...")
        await client.evaluate("""
            (() => {
                const buttons = Array.from(document.querySelectorAll('button'));
                const btn = buttons.find(b => b.textContent && b.textContent.includes('New Investigation'));
                if (btn) btn.click();
            })()
        """)
        await asyncio.sleep(2)

        new_inv_check = await client.evaluate("""
            (() => {
                const text = document.body.innerText;
                const hasUpload = text.includes('New Forensic Investigation') || text.includes('STAGE & ANALYZE') || text.includes('SCIENTIFIC DIGITAL EVIDENCE');
                return {
                    rendered: hasUpload,
                    textSnippet: text.slice(0, 150)
                };
            })()
        """)
        print(f"    - New Investigation Render Status: {new_inv_check['rendered']}")
        assert new_inv_check["rendered"] is True, "New Investigation page failed to render!"
        await client.screenshot(str(SCREENSHOTS_DIR / "02_new_investigation.png"))

        # Verify Tools & API Config Page
        print("\n[6] Navigating to 'Tools & API Config'...")
        await client.evaluate("""
            (() => {
                const buttons = Array.from(document.querySelectorAll('button'));
                const btn = buttons.find(b => b.textContent && b.textContent.includes('Tools & API Config'));
                if (btn) btn.click();
            })()
        """)
        await asyncio.sleep(3)

        tools_check = await client.evaluate("""
            (() => {
                const text = document.body.innerText;
                const hasSpinner = text.includes('Inspecting local binaries and configurations...');
                const hasBackend = text.includes('FastAPI Backend Service');
                const hasDb = text.includes('SQLite Forensics Database');
                const hasJadx = text.includes('JADX Decompiler');
                const hasMobSF = text.includes('MobSF REST Service');
                const hasYara = text.includes('YARA');
                const hasAndroguard = text.includes('Androguard');
                return {
                    hasSpinner: hasSpinner,
                    hasBackend: hasBackend,
                    hasDb: hasDb,
                    hasJadx: hasJadx,
                    hasMobSF: hasMobSF,
                    hasYara: hasYara,
                    hasAndroguard: hasAndroguard,
                    totalLength: text.length
                };
            })()
        """)
        print(f"    - Tools Page State: {tools_check}")
        assert tools_check["hasSpinner"] is False, "Infinite loading spinner occurred!"
        assert tools_check["hasBackend"] is True, "Backend card missing!"
        assert tools_check["hasDb"] is True, "Database card missing!"
        assert tools_check["hasJadx"] is True, "JADX card missing!"
        assert tools_check["hasMobSF"] is True, "MobSF card missing!"
        await client.screenshot(str(SCREENSHOTS_DIR / "03_tools_api_config.png"))

        # Verify Investigation History
        print("\n[7] Navigating to 'Investigation History'...")
        await client.evaluate("""
            (() => {
                const buttons = Array.from(document.querySelectorAll('button'));
                const btn = buttons.find(b => b.textContent && b.textContent.includes('Investigation History'));
                if (btn) btn.click();
            })()
        """)
        await asyncio.sleep(2)

        history_check = await client.evaluate("""
            (() => {
                const text = document.body.innerText;
                const hasTable = text.includes('Historical Investigation Registry') || text.includes('CASES LOGGED') || text.includes('Target File');
                return {
                    rendered: hasTable,
                    contentLength: text.length
                };
            })()
        """)
        print(f"    - History Render Status: {history_check['rendered']}")
        assert history_check["rendered"] is True, "Investigation History failed to render!"
        await client.screenshot(str(SCREENSHOTS_DIR / "04_investigation_history.png"))

        print("\n" + "=" * 70)
        print("LIFECYCLE & PERSISTENCE VALIDATION COMPLETED: ALL CHECKS PASSED")
        print(f"Console Logs: {len(client.console_logs)}")
        print(f"Failed API Requests: {len(client.failed_requests)}")
        print("=" * 70)

        return {
            "success": True,
            "database": {
                "path": str(DB_PATH),
                "integrity": integrity,
                "tables": table_count,
                "investigations": investigations_count,
                "evidence_records": evidence_count,
                "journal_mode": journal_mode
            },
            "dashboard_rendered": dashboard_check["rendered"],
            "new_investigation_rendered": new_inv_check["rendered"],
            "tools_config_rendered": tools_check["hasBackend"] and not tools_check["hasSpinner"],
            "history_rendered": history_check["rendered"],
            "failed_requests": client.failed_requests,
            "console_logs": client.console_logs
        }

    finally:
        chrome_proc.terminate()

if __name__ == "__main__":
    res = asyncio.run(run_full_application_lifecycle())
    with open("reports/startup_persistence_results.json", "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    print("\nResults successfully saved to reports/startup_persistence_results.json")
