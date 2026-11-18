"""
TraceX – Digital Forensics & Cyber Investigation Suite
Desktop Host Application (Tier 1 Process)

Responsibilities:
1. Single-Instance Mutex ('TraceX_SingleInstance_Mutex')
2. Dynamic loopback port assignment
3. Ephemeral 256-bit IPC Bridge Token generation ('X-TraceX-Bridge-Token')
4. Headless child process supervision ('TraceX-Backend.exe' with CREATE_NO_WINDOW)
5. Microsoft Edge WebView2 Evergreen desktop window management
6. Graceful child termination on window close
"""

import os
import sys
import time
import socket
import secrets
import urllib.request
import json
import subprocess
import threading
import collections
from pathlib import Path

# Resolve base directories
if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).resolve().parent
    BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", APP_DIR))
else:
    APP_DIR = Path(__file__).resolve().parent.parent
    BUNDLE_DIR = APP_DIR

MUTEX_NAME = "TraceX_SingleInstance_Mutex"
WINDOW_TITLE = "TraceX – Digital Forensics & Cyber Investigation Suite"

# ==============================================================================
# WINDOWS SINGLE INSTANCE MUTEX
# ==============================================================================

def acquire_single_instance_mutex():
    """Ensures only a single instance of TraceX runs simultaneously on Windows."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32
        ERROR_ALREADY_EXISTS = 183

        mutex = kernel32.CreateMutexW(None, False, MUTEX_NAME)
        last_error = kernel32.GetLastError()
        if last_error == ERROR_ALREADY_EXISTS:
            # Find and restore existing window
            hwnd = user32.FindWindowW(None, WINDOW_TITLE)
            if hwnd:
                user32.ShowWindow(hwnd, 9) # SW_RESTORE
                user32.SetForegroundWindow(hwnd)
            sys.exit(0)
        return mutex
    except Exception:
        return None

# ==============================================================================
# PORT & LOOPBACK MANAGEMENT
# ==============================================================================

def find_available_loopback_port(preferred: int = 8000) -> int:
    """Finds an available local TCP port on 127.0.0.1 without conflicts."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            pass

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def wait_for_backend_health(port: int, timeout_sec: int = 35) -> bool:
    """Polls backend health endpoint until online."""
    url = f"http://127.0.0.1:{port}/api/health"
    start = time.time()
    while time.time() - start < timeout_sec:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "TraceX-Host"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    if data.get("status") == "healthy":
                        return True
        except Exception:
            pass
        time.sleep(0.3)
    return False

# ==============================================================================
# CHILD PROCESS SUPERVISION
# ==============================================================================

class BackendSupervisor:
    """Spawns and supervises the headless backend process with no visible window."""

    def __init__(self, port: int, bridge_token: str):
        self.port = port
        self.bridge_token = bridge_token
        self.process: subprocess.Popen = None
        self._shutdown_event = threading.Event()
        self._stderr_buffer = collections.deque(maxlen=300)

    def _drain_stderr(self):
        """Continuously drains child stderr to prevent OS pipe buffer saturation deadlock."""
        if not self.process or not self.process.stderr:
            return
        try:
            for line in iter(self.process.stderr.readline, b''):
                if not line:
                    break
                decoded = line.decode("utf-8", errors="ignore").rstrip()
                self._stderr_buffer.append(decoded)
        except Exception:
            pass

    def get_recent_stderr(self, lines: int = 50) -> str:
        return "\n".join(list(self._stderr_buffer)[-lines:])

    def start(self):
        env = os.environ.copy()
        env["HOST"] = "127.0.0.1"
        env["PORT"] = str(self.port)
        env["TRACEX_BRIDGE_TOKEN"] = self.bridge_token
        env["WORKBENCH_DEPLOYMENT_MODE"] = "workstation"

        # Check for portable mode
        if (APP_DIR / ".portable").exists() or os.getenv("FORENSICS_PORTABLE_MODE") in ("true", "1"):
            env["FORENSICS_PORTABLE_MODE"] = "true"
            env["FORENSICS_DATA_DIR"] = str(APP_DIR / "UserData")

        # Configure bundled tool environments (Java, Tesseract) if present in tools directory
        java_home = APP_DIR / "tools" / "java"
        if java_home.is_dir():
            env["JAVA_HOME"] = str(java_home.resolve())
            env["PATH"] = f"{java_home.resolve() / 'bin'};{env.get('PATH', '')}"

        tessdata_dir = APP_DIR / "tools" / "tesseract" / "tessdata"
        if tessdata_dir.is_dir():
            env["TESSDATA_PREFIX"] = str(tessdata_dir.resolve())
            tess_dir = APP_DIR / "tools" / "tesseract"
            env["PATH"] = f"{tess_dir.resolve()};{env.get('PATH', '')}"

        # Hide window flags on Windows
        startupinfo = None
        creationflags = 0
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0 # SW_HIDE
            creationflags = subprocess.CREATE_NO_WINDOW

        # Determine target binary
        backend_exe = APP_DIR / "TraceX-Backend.exe"
        if getattr(sys, "frozen", False) and backend_exe.exists():
            cmd = [str(backend_exe), "--port", str(self.port), "--no-browser"]
        else:
            # Development mode: launch Python launcher with --no-browser
            py_exe = sys.executable
            launcher_py = APP_DIR / "launcher.py"
            cmd = [py_exe, str(launcher_py), "--no-browser", "--port", str(self.port)]

        self.process = subprocess.Popen(
            cmd,
            env=env,
            startupinfo=startupinfo,
            creationflags=creationflags,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE
        )

        # Non-blocking continuous drain thread prevents pipe saturation deadlock
        threading.Thread(target=self._drain_stderr, daemon=True).start()

        # Monitor child health in background thread
        threading.Thread(target=self._monitor_lifecycle, daemon=True).start()

    def _monitor_lifecycle(self):
        if not self.process:
            return
        code = self.process.wait()
        if code != 0 and not self._shutdown_event.is_set():
            recent_err = "\n".join(list(self._stderr_buffer)[-50:])
            log_dir = (APP_DIR / "UserData" / "logs") if (APP_DIR / ".portable").exists() else (Path(os.environ.get("LOCALAPPDATA", str(APP_DIR))) / "TraceX" / "logs")
            try:
                log_dir.mkdir(parents=True, exist_ok=True)
                (log_dir / "backend_crash.log").write_text(recent_err, encoding="utf-8")
            except Exception:
                pass
            import logging
            logging.error(f"TraceX Backend child process exited unexpectedly with code {code}: {recent_err}")

    def stop(self):
        self._shutdown_event.set()
        if self.process:
            pid = self.process.pid
            # 1. Attempt graceful IPC shutdown via loopback bridge API
            try:
                url = f"http://127.0.0.1:{self.port}/api/system/shutdown"
                req = urllib.request.Request(
                    url,
                    data=b"{}",
                    headers={
                        "Content-Type": "application/json",
                        "X-TraceX-Bridge-Token": self.bridge_token,
                        "User-Agent": "TraceX-DesktopHost"
                    }
                )
                with urllib.request.urlopen(req, timeout=1.5) as resp:
                    pass
            except Exception:
                pass

            # 2. Wait up to 3.0 seconds for graceful backend exit
            try:
                self.process.wait(timeout=3.0)
                return
            except Exception:
                pass

            # 3. Fallback to process hierarchy termination if hung
            try:
                if os.name == "nt":
                    si = subprocess.STARTUPINFO()
                    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    si.wShowWindow = 0  # SW_HIDE
                    subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(pid)],
                        capture_output=True,
                        timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        startupinfo=si
                    )
                else:
                    self.process.terminate()
                    self.process.wait(timeout=2)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass

# ==============================================================================
# MAIN DESKTOP HOST ENTRYPOINT
# ==============================================================================

def get_app_icon() -> str:
    candidates = [
        APP_DIR / "installer" / "installer_assets" / "app_icon.ico",
        BUNDLE_DIR / "installer" / "installer_assets" / "app_icon.ico",
        APP_DIR / "app_icon.ico",
        BUNDLE_DIR / "app_icon.ico",
    ]
    for c in candidates:
        if c.is_file():
            return str(c.resolve())
    return None

def main():
    mutex = acquire_single_instance_mutex()

    port = find_available_loopback_port(preferred=8000)
    bridge_token = secrets.token_urlsafe(32)

    supervisor = BackendSupervisor(port=port, bridge_token=bridge_token)
    supervisor.start()

    # Wait for backend readiness
    healthy = wait_for_backend_health(port, timeout_sec=35)
    if not healthy:
        recent_err = supervisor.get_recent_stderr(lines=20)
        supervisor.stop()
        if os.name == "nt":
            import ctypes
            msg = (
                "TraceX Forensics Suite failed to initialize backend services within the allotted timeout.\n"
                "Please verify that no other service is locking the required loopback port and check logs."
            )
            if recent_err:
                msg += f"\n\nBackend stderr diagnostics:\n{recent_err}"
            ctypes.windll.user32.MessageBoxW(
                0,
                msg,
                "TraceX Initialization Error",
                0x10 # MB_ICONERROR
            )
        sys.exit(1)

    app_url = f"http://127.0.0.1:{port}"
    icon_path = get_app_icon()

    import webview

    # Enable downloads in WebView2 and configure central destination
    webview.settings['ALLOW_DOWNLOADS'] = True

    try:
        import webview.platforms.edgechromium as ec
        original_on_download = getattr(ec.EdgeChrome, "on_download_starting", None)

        def custom_on_download_starting(self, sender, args):
            try:
                user_profile = os.environ.get("USERPROFILE") or str(Path.home())
                base_dir = Path(user_profile) / "Documents" / "TraceX" / "Reports"
                base_dir.mkdir(parents=True, exist_ok=True)

                raw_name = os.path.basename(getattr(args, "ResultFilePath", "") or "TraceX_Report.dat")
                if not raw_name or raw_name == ".":
                    raw_name = "TraceX_Report.dat"

                target = base_dir / raw_name
                stem = target.stem
                ext = target.suffix
                counter = 1
                while target.exists():
                    target = base_dir / f"{stem} ({counter}){ext}"
                    counter += 1

                args.ResultFilePath = str(target.resolve())
                args.Handled = True
                args.Cancel = False
            except Exception:
                if original_on_download:
                    original_on_download(self, sender, args)
                else:
                    args.Cancel = False

        ec.EdgeChrome.on_download_starting = custom_on_download_starting
    except Exception:
        pass

    # JavaScript initialization snippet injecting non-enumerable token & API base
    init_script = f"""
    try {{
        Object.defineProperty(window, '__TRACEX_BRIDGE_TOKEN__', {{
            value: "{bridge_token}",
            writable: false,
            configurable: false,
            enumerable: false
        }});
    }} catch (e) {{
        window.__TRACEX_BRIDGE_TOKEN__ = "{bridge_token}";
    }}
    window.__API_BASE__ = "http://127.0.0.1:{port}/api";
    """

    window = webview.create_window(
        title=WINDOW_TITLE,
        url=app_url,
        width=1440,
        height=900,
        min_size=(1100, 700),
        resizable=True,
        fullscreen=False,
        text_select=True,
    )

    def on_loaded():
        try:
            window.evaluate_js(init_script)
        except Exception:
            pass

    def on_closed():
        supervisor.stop()

    window.events.loaded += on_loaded
    window.events.closed += on_closed

    try:
        webview.start(gui="edgechromium", debug=False)
    finally:
        supervisor.stop()

if __name__ == "__main__":
    main()

