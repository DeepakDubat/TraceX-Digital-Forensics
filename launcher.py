import os
import sys

# In PyInstaller windowed mode (console=False), sys.stdout and sys.stderr are None.
# Redirect them to os.devnull to prevent AttributeError in print() and logging.
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")

import time
import socket
import urllib.request
import json
import webbrowser
import threading
from pathlib import Path

# Ensure application and bundle roots are in sys.path
if getattr(sys, "frozen", False):
    app_dir = Path(sys.executable).resolve().parent
    bundle_dir = Path(getattr(sys, "_MEIPASS", app_dir))
    for p in (str(bundle_dir), str(app_dir)):
        if p not in sys.path:
            sys.path.insert(0, p)
else:
    app_dir = Path(__file__).resolve().parent
    if str(app_dir) not in sys.path:
        sys.path.insert(0, str(app_dir))

def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0

def check_workbench_health(port: int, host: str = "127.0.0.1") -> bool:
    try:
        url = f"http://{host}:{port}/api/health"
        req = urllib.request.Request(url, headers={"User-Agent": "ForensicsWorkbenchLauncher"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("status") == "healthy"
    except Exception:
        return False
    return False

def find_available_port(preferred_port: int = 8000, host: str = "127.0.0.1") -> int:
    if not is_port_in_use(preferred_port, host):
        return preferred_port
    if check_workbench_health(preferred_port, host):
        return preferred_port
    for p in range(preferred_port + 1, preferred_port + 25):
        if not is_port_in_use(p, host):
            return p
    return preferred_port

def wait_and_open_browser(url: str, port: int, host: str = "127.0.0.1"):
    for _ in range(60):
        time.sleep(0.5)
        if check_workbench_health(port, host):
            print(f"[+] Workbench backend healthy. Opening user browser at {url}")
            webbrowser.open(url)
            return
    print("[!] Backend startup health check timed out. Please check console logs.")

def main():
    args = sys.argv[1:]
    host = "127.0.0.1"
    preferred_port = int(os.environ.get("PORT", "8000"))
    # Standalone desktop mode: NEVER open external browser by default unless explicitly requested
    no_browser = "--open-browser" not in args

    for i, arg in enumerate(args):
        if arg in ("--port", "-p") and i + 1 < len(args):
            try:
                preferred_port = int(args[i + 1])
            except ValueError:
                pass

    # Check for existing running instance
    if check_workbench_health(preferred_port, host):
        target_url = f"http://{host}:{preferred_port}"
        print(f"[*] Detected active Forensics Workbench on {target_url}.")
        if not no_browser:
            print("[*] Bringing up application interface in default browser...")
            webbrowser.open(target_url)
        sys.exit(0)

    # Resolve port conflicts safely without terminating third-party processes
    active_port = find_available_port(preferred_port, host)
    if active_port != preferred_port:
        print(f"[!] Preferred port {preferred_port} is in use by another process. Assigned port {active_port}.")

    os.environ["HOST"] = host
    os.environ["PORT"] = str(active_port)
    if "TRACEX_BRIDGE_TOKEN" not in os.environ:
        os.environ["TRACEX_BRIDGE_TOKEN"] = "tracex-workstation-desktop-token"

    from backend.app.config import settings
    settings.HOST = host
    settings.PORT = active_port

    target_url = f"http://{host}:{active_port}"

    print("=" * 72)
    print("        TRACEX FORENSICS & CYBER INVESTIGATION SUITE")
    print("=" * 72)
    print(f"[*] Version          : {settings.VERSION}")
    print(f"[*] Local Binding    : {target_url} (loopback only)")
    print(f"[*] Storage Root     : {settings.DATA_ROOT}")
    print(f"[*] Portable Mode    : {settings.IS_PORTABLE}")
    print(f"[*] Local-Only Mode  : {settings.LOCAL_ONLY_MODE}")
    print("=" * 72)
    print("Press Ctrl+C to safely stop the workbench server.")
    print("")

    if not no_browser:
        browser_thread = threading.Thread(
            target=wait_and_open_browser,
            args=(target_url, active_port, host),
            daemon=True
        )
        browser_thread.start()

    from backend.app.main import app
    import uvicorn
    uvicorn.run(
        app,
        host=host,
        port=active_port,
        reload=False,
        log_level="info",
        log_config=None
    )

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        log_file = (Path(sys.executable).resolve().parent / "backend_crash.log") if getattr(sys, "frozen", False) else Path("backend_crash.log")
        try:
            log_file.write_text(traceback.format_exc(), encoding="utf-8")
        except Exception:
            pass
        raise
