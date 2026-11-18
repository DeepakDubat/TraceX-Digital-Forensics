import asyncio
import json
import base64
import time
import subprocess
import urllib.request
from pathlib import Path
import websockets

CHROME_EXE = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
SCREENSHOTS_DIR = Path("reports/screenshots")
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

class CDPClient:
    def __init__(self, ws_url):
        self.ws_url = ws_url
        self.ws = None
        self.msg_id = 0
        self.pending = {}
        self.console_logs = []
        self.network_events = []
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
                        log_entry = f"[{log_type}] {text}"
                        self.console_logs.append(log_entry)
                        print(f"  [Console {log_type}] {text}")
                    elif method == "Log.entryAdded":
                        entry = params.get("entry", {})
                        log_entry = f"[{entry.get('level', 'log').upper()}] {entry.get('text', '')}"
                        self.console_logs.append(log_entry)
                        print(f"  [Log] {log_entry}")
                    elif method == "Network.requestWillBeSent":
                        req = params.get("request", {})
                        url = req.get("url", "")
                        if "/api/" in url:
                            self.api_requests.append((url, req.get("method", "GET")))
                            print(f"  [Network -> API Request] {req.get('method', 'GET')} {url}")
                    elif method == "Network.responseReceived":
                        resp = params.get("response", {})
                        status = resp.get("status", 0)
                        url = resp.get("url", "")
                        self.network_events.append((url, status))
                        if "/api/" in url:
                            print(f"  [Network <- API Response {status}] {url}")
                        if status >= 400:
                            self.failed_requests.append((url, status))
                            print(f"  [Network Error {status}] {url}")
                    elif method == "Network.loadingFailed":
                        url = params.get("requestId", "")
                        error = params.get("errorText", "")
                        self.failed_requests.append((url, error))
                        print(f"  [Network Failed] {url} -> {error}")
        except Exception as e:
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
        print(f"[*] Screenshot saved: {file_path}")

async def verify_url(client, target_url, screenshot_prefix):
    print("\n" + "=" * 70)
    print(f"TESTING TARGET URL: {target_url}")
    print("=" * 70)

    client.console_logs.clear()
    client.failed_requests.clear()
    client.api_requests.clear()

    # 1. Navigate
    print(f"[*] Navigating to {target_url}...")
    await client.send("Page.navigate", {"url": target_url})
    await asyncio.sleep(3)

    title = await client.evaluate("document.title")
    print(f"[*] Document Title: {title}")

    # 2. Click sidebar to Tools & API Config
    print("[*] Clicking sidebar 'Tools & API Config'...")
    clicked = await client.evaluate("""
        (() => {
            const buttons = Array.from(document.querySelectorAll('button'));
            const btn = buttons.find(b => b.textContent && b.textContent.includes('Tools & API Config'));
            if (btn) {
                btn.click();
                return true;
            }
            return false;
        })()
    """)
    print(f"[*] Sidebar button click status: {clicked}")
    await asyncio.sleep(3)

    # 3. Check for infinite loading vs rendered content
    page_state = await client.evaluate("""
        (() => {
            const text = document.body.innerText;
            const hasSpinner = text.includes('Inspecting local binaries and configurations...');
            const hasHeader = text.includes('Tools & API Configuration') || text.includes('Tool Adapters & API Configuration');
            const hasBackendCard = text.includes('FastAPI Backend Service');
            const hasDbCard = text.includes('SQLite Forensics Database');
            const hasToolsGrid = text.includes('DETECTED FORENSICS TOOLS') || text.includes('DETECTED SYSTEM TOOLS');
            return {
                hasSpinner: hasSpinner,
                hasHeader: hasHeader,
                hasBackendCard: hasBackendCard,
                hasDbCard: hasDbCard,
                hasToolsGrid: hasToolsGrid,
                contentLength: text.length
            };
        })()
    """)
    print(f"[*] Page State Check: {page_state}")
    assert page_state["hasHeader"] is True, "Page Header not found!"
    assert page_state["hasBackendCard"] is True, "FastAPI Backend Service card not found!"
    assert page_state["hasDbCard"] is True, "SQLite Database card not found!"
    assert page_state["hasToolsGrid"] is True, "Detected Tools Grid not found!"
    assert page_state["hasSpinner"] is False, "Infinite loading spinner detected!"

    # 4. Extract all rendered cards and statuses
    cards = await client.evaluate("""
        (() => {
            const cards = Array.from(document.querySelectorAll('.bg-surface.border.border-app'));
            return cards.map(c => {
                const titleEl = c.querySelector('.font-bold.font-mono');
                const badgeEl = c.querySelector('span.font-bold');
                const diagEl = c.querySelector('.font-sans p.break-words');
                return {
                    name: titleEl ? titleEl.textContent.trim() : 'Unknown',
                    badge: badgeEl ? badgeEl.textContent.trim() : 'Unknown',
                    diagnostic: diagEl ? diagEl.textContent.trim() : ''
                };
            }).filter(c => c.name !== 'Unknown');
        })()
    """)
    print(f"\n[*] Visible Status Cards ({len(cards)} found):")
    for c in cards:
        print(f"    - [{c['badge']}] {c['name']}")
        if c['diagnostic']:
            print(f"        Diagnostic: {c['diagnostic'][:90]}...")

    # 5. Capture Initial Page Screenshot
    shot_init = SCREENSHOTS_DIR / f"{screenshot_prefix}_initial.png"
    await client.screenshot(str(shot_init))

    # 6. Test Individual Retry Button: SQLite Database
    print("\n[*] Testing SQLite Database individual check...")
    db_test = await client.evaluate("""
        (() => {
            const buttons = Array.from(document.querySelectorAll('button'));
            const btn = buttons.find(b => b.textContent && b.textContent.includes('Verify Database'));
            if (btn) {
                btn.click();
                return true;
            }
            return false;
        })()
    """)
    print(f"[*] Clicked 'Verify Database': {db_test}")
    await asyncio.sleep(2)

    # 7. Test Individual Test Execution: JADX Decompiler
    print("[*] Testing JADX Decompiler individual test...")
    jadx_test = await client.evaluate("""
        (() => {
            const cards = Array.from(document.querySelectorAll('.bg-surface.border.border-app'));
            const card = cards.find(c => c.textContent && c.textContent.includes('JADX Decompiler'));
            if (card) {
                const btn = card.querySelector('button');
                if (btn) {
                    btn.click();
                    return true;
                }
            }
            return false;
        })()
    """)
    print(f"[*] Clicked JADX Test button: {jadx_test}")
    await asyncio.sleep(3)

    # 8. Test Individual Test Execution: MobSF REST Service (offline test)
    print("[*] Testing MobSF REST Service offline test...")
    mobsf_test = await client.evaluate("""
        (() => {
            const cards = Array.from(document.querySelectorAll('.bg-surface.border.border-app'));
            const card = cards.find(c => c.textContent && c.textContent.includes('MobSF REST Service'));
            if (card) {
                const btn = card.querySelector('button');
                if (btn) {
                    btn.click();
                    return true;
                }
            }
            return false;
        })()
    """)
    print(f"[*] Clicked MobSF Test button: {mobsf_test}")
    await asyncio.sleep(3)

    # 9. Verify MobSF status shows SERVICE UNREACHABLE / TIMEOUT with no hang
    mobsf_status = await client.evaluate("""
        (() => {
            const cards = Array.from(document.querySelectorAll('.bg-surface.border.border-app'));
            const card = cards.find(c => c.textContent && c.textContent.includes('MobSF REST Service'));
            if (card) {
                return card.textContent;
            }
            return '';
        })()
    """)
    print(f"[*] MobSF Card Status Text: {mobsf_status[:120]}...")
    assert "SERVICE UNREACHABLE" in mobsf_status or "TIMEOUT" in mobsf_status or "FAILED" in mobsf_status, "MobSF did not report offline status correctly!"

    # 10. Navigate Away and Return
    print("\n[*] Navigating to another view (History)...")
    await client.evaluate("""
        (() => {
            const buttons = Array.from(document.querySelectorAll('button'));
            const btn = buttons.find(b => b.textContent && b.textContent.includes('Investigation History'));
            if (btn) btn.click();
        })()
    """)
    await asyncio.sleep(2)

    print("[*] Returning to 'Tools & API Config'...")
    await client.evaluate("""
        (() => {
            const buttons = Array.from(document.querySelectorAll('button'));
            const btn = buttons.find(b => b.textContent && b.textContent.includes('Tools & API Config'));
            if (btn) btn.click();
        })()
    """)
    await asyncio.sleep(2)

    return_state = await client.evaluate("""
        (() => {
            const text = document.body.innerText;
            const hasSpinner = text.includes('Inspecting local binaries and configurations...');
            const hasBackendCard = text.includes('FastAPI Backend Service');
            return {
                hasSpinner: hasSpinner,
                hasBackendCard: hasBackendCard
            };
        })()
    """)
    print(f"[*] Return Navigation State: {return_state}")
    assert return_state["hasBackendCard"] is True, "Cards failed to render after returning!"
    assert return_state["hasSpinner"] is False, "Infinite loading spinner occurred on return!"

    # 11. Final Screenshot
    shot_final = SCREENSHOTS_DIR / f"{screenshot_prefix}_final.png"
    await client.screenshot(str(shot_final))

    # 12. Check API Requests and Console Errors
    print(f"\n[*] Total API requests observed: {len(client.api_requests)}")
    for req_url, method in client.api_requests[:8]:
        print(f"    - {method} {req_url}")

    print(f"[*] Failed Network Requests (status >= 400): {len(client.failed_requests)}")
    print(f"[*] Console Log Entries: {len(client.console_logs)}")

    return {
        "url": target_url,
        "success": True,
        "cards": cards,
        "initial_screenshot": str(shot_init),
        "final_screenshot": str(shot_final),
        "api_requests": client.api_requests,
        "failed_requests": client.failed_requests,
        "console_logs": client.console_logs
    }

async def main():
    profile_dir = Path(tempfile.gettempdir()) / "chrome_full_runtime_profile"
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
        await client.send("Log.enable")

        # Test 1: Vite Dev Server URL
        res_dev = await verify_url(client, "http://127.0.0.1:5173", "vite_dev")

        # Test 2: Reverse Proxy URL (The exact URL from user report)
        res_proxy = await verify_url(client, "http://127.0.0.1:9000/http://127.0.0.1:8000/", "reverse_proxy_9000")

        # Test 3: Direct Backend SPA URL
        res_backend = await verify_url(client, "http://127.0.0.1:8000/", "backend_spa")

        print("\n" + "=" * 70)
        print("ALL 3 RUNTIME BROWSER SCENARIOS VERIFIED SUCCESSFULLY!")
        print("=" * 70)

        with open("reports/verification_results.json", "w", encoding="utf-8") as f:
            json.dump({
                "dev_server": res_dev,
                "reverse_proxy": res_proxy,
                "backend_spa": res_backend
            }, f, indent=2)

    finally:
        chrome_proc.terminate()

if __name__ == "__main__":
    asyncio.run(main())
