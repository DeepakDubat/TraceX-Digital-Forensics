#!/usr/bin/env bash
# ==============================================================================
# TRACEX - DIGITAL FORENSICS & CYBER INVESTIGATION SUITE
# Linux & Kali Linux Developer Workbench Launcher
# ==============================================================================
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "=============================================================================="
echo "       TRACEX - DIGITAL FORENSICS & CYBER INVESTIGATION SUITE"
echo "                     Developer Workbench Launcher"
echo "=============================================================================="

# Ensure .env exists
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    cp .env.example .env
fi

# Locate Python
PYTHON_BIN=""
for cmd in python3.11 python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON_BIN="$cmd"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "[-] Python is not installed. Please run ./install.sh first."
    exit 1
fi

# Start Backend in background
echo "[*] Starting FastAPI Backend on http://127.0.0.1:8000 ..."
"$PYTHON_BIN" run_backend.py &
BACKEND_PID=$!

# Start Reverse Proxy
echo "[*] Starting Reverse Proxy on http://127.0.0.1:9000 ..."
"$PYTHON_BIN" run_proxy.py &
PROXY_PID=$!

# Start Frontend
echo "[*] Starting Vite Frontend on http://localhost:5173 ..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd "$ROOT_DIR"

echo "[+] TraceX Workbench active!"
echo "    UI (Dev Server) : http://localhost:5173"
echo "    Backend API     : http://127.0.0.1:8000"
echo "    Web Preview URL : http://127.0.0.1:9000/http://127.0.0.1:8000/"
echo "Press Ctrl+C to stop all services."

trap "kill $BACKEND_PID $PROXY_PID $FRONTEND_PID 2>/dev/null; exit" SIGINT SIGTERM
wait
