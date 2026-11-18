#!/usr/bin/env bash
# ==============================================================================
# APK FORENSICS & THREAT INTELLIGENCE WORKBENCH
# Linux & Kali Linux Launcher
# ==============================================================================
set -e

echo "=============================================================================="
echo "          APK FORENSICS & THREAT INTELLIGENCE WORKBENCH"
echo "=============================================================================="

# Check Python environment
if ! command -v python3 &> /dev/null; then
    echo "[-] Python3 is not installed. Please install python3 and pip."
    exit 1
fi

# Start Backend in background
echo "[*] Starting FastAPI Backend on http://127.0.0.1:8000 ..."
python3 run_backend.py &
BACKEND_PID=$!

# Start Reverse Proxy
echo "[*] Starting Reverse Proxy on http://127.0.0.1:9000 ..."
python3 run_proxy.py &
PROXY_PID=$!

# Start Frontend
echo "[*] Starting Vite Frontend on http://localhost:5173 ..."
cd frontend
npm run dev &
FRONTEND_PID=$!

echo "[+] Workbench active!"
echo "    UI (Dev Server) : http://localhost:5173"
echo "    Backend API     : http://127.0.0.1:8000"
echo "    Web Preview URL : http://127.0.0.1:9000/http://127.0.0.1:8000/"
echo "Press Ctrl+C to stop all services."

trap "kill $BACKEND_PID $PROXY_PID $FRONTEND_PID 2>/dev/null; exit" SIGINT SIGTERM
wait
