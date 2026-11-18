#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "=============================================================================="
echo "       TRACEX - DIGITAL FORENSICS & CYBER INVESTIGATION SUITE"
echo "                      Discover. Analyze. Investigate."
echo "=============================================================================="
echo ""

# 1. Initialize .env
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    cp .env.example .env
fi

# 2. Python environment
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
    PYCMD="python"
else
    for cmd in python3.11 python3 python; do
        if command -v "$cmd" &>/dev/null; then
            PYCMD="$cmd"
            break
        fi
    done
fi

if [ -z "$PYCMD" ]; then
    echo "[X] ERROR: Python was not found. Please run ./install.sh first."
    exit 1
fi

# 3. Check frontend bundle
if [ ! -f "frontend/dist/index.html" ] && command -v npm &>/dev/null; then
    echo "[*] Building frontend bundle..."
    cd frontend
    npm run build
    cd ..
fi

echo "[*] Launching TraceX Forensic Engine on http://127.0.0.1:8000 ..."
"$PYCMD" launcher.py --open-browser
