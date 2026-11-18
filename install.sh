#!/usr/bin/env bash
set -e

echo "=============================================================================="
echo "       TRACEX - DIGITAL FORENSICS & CYBER INVESTIGATION SUITE"
echo "                     Automated Setup & Installer"
echo "=============================================================================="
echo ""

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# 1. Check Python
PYTHON_BIN=""
for cmd in python3.11 python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON_BIN="$cmd"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "[X] ERROR: Python 3.10+ or 3.11 is required but was not found."
    echo "    Please install Python from https://www.python.org/ or via your package manager."
    exit 1
fi

echo "[*] Using Python: $($PYTHON_BIN --version)"

# 2. Virtual Environment
if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment (.venv)..."
    "$PYTHON_BIN" -m venv .venv
fi

if [ -f ".venv/bin/activate" ]; then
    echo "[*] Activating virtual environment..."
    source .venv/bin/activate
    ACTIVE_PY="python"
else
    ACTIVE_PY="$PYTHON_BIN"
fi

# 3. Python Dependencies
echo "[*] Installing Python backend dependencies from requirements.txt..."
"$ACTIVE_PY" -m pip install --upgrade pip
"$ACTIVE_PY" -m pip install -r requirements.txt

# 4. Frontend Build
if command -v npm &>/dev/null; then
    echo "[*] Installing frontend dependencies & building production bundle..."
    cd frontend
    npm install
    npm run build
    cd ..
    echo "[+] Frontend bundle built successfully."
else
    echo "[!] npm not found. Ensure Node.js is installed if frontend needs rebuilding."
fi

# 5. Configuration File
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    echo "[*] Copying .env.example to .env..."
    cp .env.example .env
fi

echo ""
echo "=============================================================================="
echo "                     TRACEX SETUP COMPLETE!"
echo "=============================================================================="
echo " To start TraceX:"
echo "   ./run_tracex.sh   (or ./start.sh)"
echo ""
echo " Application will open at: http://127.0.0.1:8000"
echo "=============================================================================="
