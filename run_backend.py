import sys
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

try:
    import uvicorn
except ModuleNotFoundError:
    # If the user executed `python run_backend.py` using Python 3.12 or an unconfigured interpreter,
    # automatically try re-launching with Python 3.11 where the workbench dependencies are installed.
    import subprocess
    try:
        check = subprocess.run(["py", "-3.11", "-c", "import uvicorn"], capture_output=True)
        if check.returncode == 0:
            print("[*] Detected Python 3.11 with workbench dependencies. Re-launching backend...")
            sys.exit(subprocess.call(["py", "-3.11", str(Path(__file__).resolve())] + sys.argv[1:]))
    except Exception:
        pass

    print("=" * 80)
    print(" [ERROR] Required module 'uvicorn' is not installed in this Python environment.")
    print(f" Current interpreter : {sys.executable}")
    print(f" Current version     : {sys.version.split()[0]}")
    print(" To launch with the correct environment, run:")
    print("   py -3.11 run_backend.py")
    print("=" * 80)
    raise

from backend.app.config import settings

if __name__ == "__main__":
    print("=" * 80)
    print(" APK FORENSICS & THREAT INTELLIGENCE WORKBENCH ")
    print("=" * 80)
    print(f"[*] Starting Backend on http://{settings.HOST}:{settings.PORT}")
    print(f"[*] Analysis Workspace : {settings.DATA_DIR}")
    print(f"[*] Local-Only Policy  : {settings.LOCAL_ONLY_MODE}")
    print("=" * 80)
    uvicorn.run(
        "backend.app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=False
    )
